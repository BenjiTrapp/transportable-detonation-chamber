"""YAML rules over network events.

The parsers turn a pcap into events; an analyst who sees a new campaign wants to
say "this pattern means something" without touching Python. This module loads
rules from YAML, checks every one when the file is read, and matches them
against the events of a capture. The rule language follows what
``rules/sigma/*.yml`` already looks like (``field|operator: value``, a list means
"any of", strings compare without regard to case), so whoever reads those does
not learn a second notation. Several things are easy to get wrong:

  * A broken rule breaks the file. Rules come from people, so a bad regex, a
    mistyped field or a ``requires`` on a rule that does not exist is the normal
    case. Everything is checked at load time (regexes are compiled once, lists
    resolved once, field names checked against what the parsers emit, ``requires``
    held against the known ids once) and a rule that does not hold goes into
    ``errors`` with its reason and is left out; the others run. Matching itself
    cannot raise: an odd field value (None, bytes, a list where text was
    expected) is "no match", never an exception.
  * A rule that cannot fire loads cleanly. A misspelt field matches nothing
    forever, and an unknown list name quietly read as empty does the same, so
    both are errors. ``password`` is not a field at all: ``net_mail_ftp`` keeps
    it as a ``Secret`` so that nothing copies it, and a rule that could read it
    would make the engine the first thing that does.
  * A regex is harmless. ``(a+)+$`` against forty characters runs for hours, and
    ``^/(\\w+/?){1,5}\\.php$`` against two hundred for longer than anyone waits,
    in one event of a capture the malware chose, and the standard ``re`` cannot be
    interrupted. So rule patterns run on the ``regex`` module with a timeout on
    every call (``REGEX_TIMEOUT_S``), which holds whatever the pattern is. A
    pattern that times out is not "no match": see the next point. If ``regex``
    cannot be imported, ``re`` is used and nothing bounds a call except the
    checks below, so the subject is then cut to ``MAX_SUBJECT_UNGUARDED``
    characters instead of ``MAX_SUBJECT``; the guest always has ``regex``
    (``requirements.txt``).
    Independent of the engine, a pattern is checked when the rule loads, as an
    early warning with a reason and not as the guarantee: shapes that are
    exponential (a repeat that holds a repeat or an optional part it cannot tell
    from what follows, alternatives that start alike inside a repeat,
    conditional groups) are refused, and a worst-case step estimate on
    ``PRICE_LEN`` characters over ``MAX_REGEX_STEPS`` is refused. The estimate has
    known gaps (the cost of a lookahead inside a repeat's body is not priced) and
    is not the thing to rely on. A list field is shown to a regex only up to its
    first ``MAX_REGEX_ELEMENTS`` elements (a longer list with no match among them
    is unknown, reason ``cut``, like a field longer than the cut), and one ``evaluate`` may spend only
    ``REGEX_BUDGET_S`` seconds in regexes, shared by all rules. The other string
    operators are linear and see the whole field.
  * A regex that was not run is "could not tell", not "no". A timeout, a spent
    budget, or a field longer than the cut in which nothing decisive was found
    (padding a field must not choose the answer) makes the condition unknown. Unknown is never true and never false:
    ``not: {path|re: ...}`` over an unknown is unknown, so an attacker who exhausts
    the budget does not make every negated rule fire. An ``all`` is false if any
    member is false, an ``any`` true if any member is true, and unknown
    otherwise. A rule that is unknown for an event is skipped for that event and
    named in ``Hits.unevaluated``; its hits from the events it could decide are
    real, and for a rule listed there the absence of a hit is not an answer. A
    correlation whose required rules are unevaluated and which did not fire is
    listed too, but only if it fired for no process at all.
  * Every rule against every event. Rules are filed under the event types they
    name, and a rule whose match has a plain equality or ``in`` condition is
    additionally filed under that field's values, so an event is tried on the
    rules that can possibly match it and not on all of them.
  * One hit per matching event. A thousand requests of one kind are one finding
    with ``count`` 1000 and the first ``MAX_HIT_EVENTS`` events, grouped by
    process, which is also what a correlation needs.
  * The weight of a finding comes from the rule. It does not: a rule may name
    an evidence ``kind``, and the evidence model decides what that kind weighs.
    There is no weight key, and one is rejected. The kind must be one of the
    network kinds of ``memory_evidence`` (``NETWORK_KINDS``): a misspelt kind
    would load and score nothing forever, and a host-side kind such as
    ``thread_start_private`` would let a rule reach a weight no capture can
    support.
  * ``True == 1``. A flag is not a number: ``nxdomain: true`` does not match
    ``1`` and ``port: 1`` does not match ``True``.
  * A destination is a fact. ``dest`` is what the sample says it talks to (a Host
    header, a server name), so ``known_good`` hiding by destination lets malware
    pick its own invisibility: ``Host: www.msftconnecttest.com`` on a connection
    to its own address. ``download``, ``upload`` and ``decoded`` events state that
    something crossed the wire, which is not a claim about a name, and are never
    hidden (``ALWAYS_VISIBLE``). Every other event with a known-good destination
    is still hidden, and for those the name is as trustworthy as the sample's
    own header or SNI; requiring a DNS answer for it in the capture would close
    that and belongs to a later phase.
  * Events carry a credential. A hit names its events (index, type, time,
    destination, port) and copies nothing else, so a hit on an ``ftp`` event
    serializes, and the password cannot reach a report through it.

A correlation rule has no ``event``: ``requires: [[a, b], [c]]`` is met by a
process for which one of ``a``/``b`` and ``c`` all hit. The order in time is not
looked at, only that the same process did all of it, and a capture that knows
no process is one process, ``""``.
"""

import math
import operator
import os
import re
import threading
import time
import warnings

import yaml

try:
    import regex as _regex_module
except ImportError:                      # re is used, see the docstring
    _regex_module = None

import memory_evidence
import net_events

try:                                     # Python 3.11 and later
    from re import _constants as sre_constants
    from re import _parser as sre_parse
except ImportError:                      # 3.9, 3.10
    import sre_constants
    import sre_parse

MAX_SUBJECT = 2048          # characters of a field that a regex is shown, with a timeout
MAX_SUBJECT_UNGUARDED = 256 # the same with plain ``re``, which cannot be interrupted
PRICE_LEN = 256             # the length the load-time cost estimate is made for
REGEX_TIMEOUT_S = 0.02      # one regex call on one field; a normal one takes microseconds
MAX_PATTERN = 500           # characters of a regex
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 6               # any / all / not inside each other
MAX_NODES = 400             # conditions and blocks of one rule
MAX_HIT_EVENTS = 20         # events named by one hit; ``count`` is exact
MAX_REGEX_ELEMENTS = 16     # elements of a list field a regex is tried on
REGEX_BUDGET_S = 20.0       # seconds of regex matching one ``evaluate`` may spend
ALWAYS_VISIBLE = frozenset(("download", "upload", "decoded"))   # never hidden by known_good
MAX_REGEX_STEPS = 20000000  # estimated worst case of one regex on PRICE_LEN characters

SEVERITIES = ("info", "low", "medium", "high", "critical")
KNOWN_GOOD = "known_good"

# --- fields -----------------------------------------------------------------------
# What the parsers put into events, per type: the fields a rule may name. A field
# a parser sets only sometimes is listed too. ``test_net_rules`` compares this
# table with real parser output, so a parser that gains a field must gain it here.

COMMON = frozenset(("type", "ts", "process", "pid", "dest", "port", "dest_is_ip", "in_tree"))

# Fields that exist but that a rule may not name: the credential, and nested
# structures (headers, WebSocket messages, stream gaps) that no operator reads.
UNMATCHABLE = frozenset(("password", "headers", "resp_headers", "messages", "stream_gaps"))

_SESSION = ("user", "password_captured", "auth_attempts", "auth_ok", "starttls", "encrypted",
            "truncated", "stream_capped")

FIELDS = {
    "dns": COMMON | {"server", "query", "query_type", "answers", "rcode", "nxdomain"},
    "conn": COMMON,
    "conn_failed": COMMON,
    "udp": COMMON,
    "tls": COMMON | {"sni", "cert_subject", "cert_issuer", "cert_not_after", "self_signed",
                     "stream_capped", "version", "ciphers", "extensions", "alpn", "ja3",
                     "ja3_hash", "ja4", "hello_incomplete"},
    "http": COMMON | {"method", "url", "path", "query", "ua", "header_order", "body_text",
                      "body_bytes", "body_capped", "body_decode_failed", "request_encoding",
                      "form_names", "status", "resp_text", "resp_bytes", "resp_capped",
                      "resp_decode_failed", "content_type", "content_encoding",
                      "request_truncated", "response_truncated", "stream_capped"},
    "raw": COMMON | {"proto", "direction", "framing", "delimiter", "message_sizes",
                     "message_count", "entropy", "printable_ratio", "heartbeat", "interval",
                     "stream_bytes", "stream_capped", "client_guessed"},
    "ftp": COMMON | {"commands", "files", "uploaded", "capped"} | set(_SESSION),
    "smtp": COMMON | {"mail_from", "rcpt_to", "subject", "body_bytes", "attachments",
                      "data_complete", "auth", "capped"} | set(_SESSION),
    "websocket": COMMON | {"url", "path", "messages_capped", "truncated", "stream_capped"},
    "download": COMMON | {"url", "path", "kind", "content_type", "content_encoding", "truncated",
                          "sha256", "size", "inflate_capped", "inflate_failed", "wire_sha256",
                          "wire_size"},
    "upload": COMMON | {"method", "url", "path", "size", "sha256", "kind", "content_type",
                        "content_encoding", "truncated"},
    "decoded": COMMON | {"source", "field", "name", "scheme", "layers", "kind", "charset",
                         "text", "text_capped", "size", "sha256", "preview", "credential",
                         "encoded", "encoded_len", "truncated"},
    "beacon": COMMON | {"interval", "jitter", "cov", "on_rhythm", "periodic", "unmeasured",
                        "connections", "first_ts", "last_ts", "via", "addresses"},
    "retry": COMMON | {"attempts", "first_ts", "last_ts", "via", "addresses"},
    "fanout": COMMON | {"path", "hosts", "dests", "nxdomain", "window_s"},
}
FIELDS = {etype: frozenset(names) for etype, names in FIELDS.items()}

RULE_KEYS = frozenset(("id", "name", "description", "event", "match", "severity", "role",
                       "behavior", "attack", "family", "kind", "count_gte",
                       "include_known_good", "requires"))
_CORRELATION_FORBIDDEN = ("event", "match", "count_gte", "include_known_good")
_TEXT_KEYS = ("description", "role", "behavior", "family", "kind")


_run = threading.local()        # the regex budget of the evaluate() running in this thread


def subject_limit():
    """How many characters of a field a regex is shown, with the engine in use."""
    return MAX_SUBJECT if _regex_module is not None else MAX_SUBJECT_UNGUARDED


class _Unknown(Exception):
    """A condition that could not be decided (a regex timed out or the budget is
    spent). Raised out of the condition, and handled by ``all``/``any``/``not``,
    which never turn it into true or false."""

    def __init__(self, *reasons):
        super().__init__(", ".join(reasons))
        self.reasons = frozenset(reasons)


class RuleError(ValueError):
    """A rule that cannot be used; the message is the reason shown to the analyst."""


# --- comparing values ---------------------------------------------------------------

def _key(value):
    """The hashable form two values are equal by, or None for a value that is no scalar.

    A string compares without regard to case; a bool is not a number, so a flag
    never equals 1; None is a value of its own, which is also what a missing
    field is.
    """
    if value is None:
        return ("z",)
    if isinstance(value, bool):
        return ("b", value)
    if isinstance(value, (int, float)):
        return ("n", value)
    if isinstance(value, str):
        return ("s", value.lower())
    return None


def _scalars(value):
    """The values a field offers: its elements when it is a list, else itself."""
    if isinstance(value, (list, tuple)):
        return value
    return (value,)


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    return value


def _is_scalar(value):
    return value is None or isinstance(value, (str, int, float, bool))


def _plain(value):
    return value if value is None or isinstance(value, (str, int, float, bool)) else None


# --- regex safety -------------------------------------------------------------------
# ``re`` backtracks and cannot be interrupted. What blows up is ambiguity: more than one
# way to divide a string among repeats. This reads the parsed pattern and refuses the
# shapes that are ambiguous. It is an early warning with a reason; the guarantee is the
# timeout on every call (``_Compiled``).

_OPEN = 16          # a repeat that can run more often than this is open-ended

# The characters a pattern can consume, as sets over a small alphabet: ASCII as itself
# and four stand-ins for what is not ASCII, so that negated classes can be complemented
# (``[^/]`` and ``/`` are disjoint, ``\S`` and ``\s`` too).
_NON_ASCII = (128, 129, 130, 131)       # word character, digit, whitespace, anything else
_UNIVERSE = frozenset(range(132))
_DIGITS = frozenset(range(48, 58)) | {129}
_SPACES = frozenset((9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 130))
_WORD = (frozenset(range(48, 58)) | frozenset(range(65, 91)) | frozenset(range(97, 123))
         | {95, 128, 129})
_CATEGORIES = {
    "CATEGORY_DIGIT": _DIGITS, "CATEGORY_NOT_DIGIT": _UNIVERSE - _DIGITS,
    "CATEGORY_SPACE": _SPACES, "CATEGORY_NOT_SPACE": _UNIVERSE - _SPACES,
    "CATEGORY_WORD": _WORD, "CATEGORY_NOT_WORD": _UNIVERSE - _WORD,
}


def _names_in(*names):
    return tuple(getattr(sre_constants, n) for n in names if hasattr(sre_constants, n))


_REPEATS = _names_in("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
_ZERO_WIDTH = _names_in("AT", "ASSERT", "ASSERT_NOT")
_ASSERTS = _names_in("ASSERT", "ASSERT_NOT")
_ATOMIC = _names_in("ATOMIC_GROUP")             # Python 3.11 and later
_CONDITIONAL = sre_constants.GROUPREF_EXISTS


def _symbol(code):
    if code < 128:
        return code
    char = chr(code)
    if char.isspace():
        return 130
    if char.isdecimal():
        return 129
    return 128 if char.isalnum() else 131


def _fold(chars, fold):
    if not fold:
        return chars
    return chars | {ord(chr(c).swapcase()) for c in chars if 65 <= c <= 122 and chr(c).isalpha()}


def _in_set(av, fold):
    exact, loose, negate = set(), set(), False
    for op, arg in av:
        if op == sre_constants.NEGATE:
            negate = True
        elif op == sre_constants.LITERAL:
            (exact if arg < 128 else loose).add(_symbol(arg))
        elif op == sre_constants.RANGE:
            low, high = arg
            exact.update(range(low, min(high, 127) + 1))
            if high > 127:
                loose.update(_NON_ASCII)
        elif op == sre_constants.CATEGORY:
            exact |= _CATEGORIES.get(str(arg), _UNIVERSE)
        else:
            return _UNIVERSE
    exact = _fold(frozenset(exact), fold)
    # a negated class keeps every non-ASCII stand-in it did not name as a whole category
    return _UNIVERSE - exact if negate else exact | loose


def _single(op, av, fold):
    """The characters one LITERAL/IN/ANY ... consumes, or None if ``op`` is not one."""
    if op == sre_constants.LITERAL:
        return _fold(frozenset((_symbol(av),)), fold)
    if op == sre_constants.NOT_LITERAL:
        return _UNIVERSE - _fold(frozenset((av,)), fold) if av < 128 else _UNIVERSE
    if op == sre_constants.ANY:
        return _UNIVERSE - {10}
    if op == sre_constants.IN:
        return _in_set(av, fold)
    if op == sre_constants.CATEGORY:
        return _CATEGORIES.get(str(av), _UNIVERSE)
    return None


def _subitems(op, av):
    """The item lists nested in one element, whatever its kind."""
    if op == sre_constants.SUBPATTERN:
        return [av[-1]]
    if op in _REPEATS:
        return [av[2]]
    if op == sre_constants.BRANCH:
        return list(av[1])
    if op in _ASSERTS:
        return [av[1]]
    if op in _ATOMIC:
        return [av]
    if op == _CONDITIONAL:
        return [part for part in av[1:] if part is not None]
    return []


def _everything(items):
    """Every element at any depth."""
    for op, av in items:
        yield op, av
        for sub in _subitems(op, av):
            for found in _everything(sub):
                yield found


def _has_repeat(items):
    return any(op in _REPEATS for op, av in _everything(items))


def _has_open(items):
    return any(op in _REPEATS and _is_open(av) for op, av in _everything(items))


def _is_open(av):
    return av[1] == sre_constants.MAXREPEAT or av[1] > _OPEN


def _chars(items, fold):
    """Every character the items can consume."""
    total = frozenset()
    for op, av in items:
        one = _single(op, av, fold)
        if one is not None:
            total |= one
        elif op in _ZERO_WIDTH:
            continue
        elif op in _REPEATS or op == sre_constants.SUBPATTERN or op in _ATOMIC:
            total |= _chars(_subitems(op, av)[0], fold)
        elif op == sre_constants.BRANCH:
            for alt in av[1]:
                total |= _chars(alt, fold)
        else:
            return _UNIVERSE                # a group reference, a conditional ...
    return total


def _nullable(op, av):
    if op in _ZERO_WIDTH:
        return True
    if op in _REPEATS:
        return av[0] == 0
    if op == sre_constants.SUBPATTERN:
        return all(_nullable(o, a) for o, a in av[-1])
    if op == sre_constants.BRANCH:
        return any(all(_nullable(o, a) for o, a in alt) for alt in av[1])
    return False


def _first(items, fold):
    """(characters a match of ``items`` can start with, whether it can be empty)."""
    start = frozenset()
    for op, av in items:
        if op in _ZERO_WIDTH:
            continue
        if op in _REPEATS or op == sre_constants.SUBPATTERN or op in _ATOMIC:
            start |= _first(_subitems(op, av)[0], fold)[0]
        elif op == sre_constants.BRANCH:
            for alt in av[1]:
                start |= _first(alt, fold)[0]
        else:
            start |= _chars([(op, av)], fold)
        if not _nullable(op, av):
            return start, False
    return start, True


def _empty():
    return RuleError("a repeated or optional part that can match nothing "
                     "((?:a*)?, (?:\\s{0,2})*) can do so in more than one way")


def _sequence(items):
    """``(op, av, optional)`` of one level: groups opened up, and the contents of
    an optional group that holds an open repeat counted as optional elements of the
    level, so ``(?:\\d+)?(?:\\d+)?`` is seen as the two adjacent repeats it is."""
    out = []
    for op, av in items:
        if op == sre_constants.SUBPATTERN:
            out.extend(_sequence(av[-1]))
        elif op in _REPEATS and av[0] == 0 and av[1] == 1 and _has_open(av[2]):
            if _first(av[2], False)[1]:
                raise _empty()
            out.extend((o, a, True) for o, a, _ in _sequence(av[2]))
        else:
            out.append((op, av, False))
    return out


class _Risk:
    """Walks a parsed pattern, refuses the shapes that are exponential, and estimates
    the work of the rest as a number of steps on a ``PRICE_LEN`` field.

    A repeat is *ambiguous* when it can swallow a character that may follow it, so
    that where it ends is a choice; each choice multiplies the work of everything
    after it. A repeat that cannot swallow its follower is *deterministic* and only
    adds its own run. So ``\\d+\\d+x`` is the product of two lengths (and a third
    for the start position), ``\\w+@\\w+\\.\\w+`` the sum of three.
    """

    def __init__(self, fold):
        self.fold = fold

    def work(self, items, inside=False):
        flat = _sequence(items)
        rest = 0
        for i in range(len(flat) - 1, -1, -1):
            rest = self.element(flat, i, inside, rest)
        return rest

    def follow(self, flat, i):
        found = frozenset()
        for op, av, optional in flat[i + 1:]:
            if op in _ZERO_WIDTH:
                continue
            found |= _first([(op, av)], self.fold)[0]
            if not (optional or _nullable(op, av)):
                break
        return found

    def element(self, flat, i, inside, rest):
        """The work of ``flat[i:]`` given the work of ``flat[i + 1:]``."""
        op, av, optional = flat[i]
        if op in _REPEATS:
            lo, hi, body = av
            if _first(body, self.fold)[1]:
                raise _empty()
            if hi > 1 and _has_repeat(body):
                self.delimited(body)
            self.work(body, inside or hi > 1)
            run = PRICE_LEN if _is_open(av) else hi
            if (hi > 1 or lo == 0 or optional) and (
                    _chars(body, self.fold) & self.follow(flat, i)):
                return (run if hi > 1 else 2) * (1 + rest)
            # the last element of a pattern cannot fail after it matched: it costs nothing more
            last = i == len(flat) - 1
            return (1 if last else run if hi > 1 else 1) + rest
        if op == sre_constants.BRANCH:
            if inside:
                self.alternatives(av[1])
            works = [self.work(alt, inside) for alt in av[1]]
            starts = [_first(alt, self.fold)[0] for alt in av[1]]
            overlapping = sum(len(x) for x in starts) > len(frozenset().union(*starts))
            if overlapping:
                return len(av[1]) * (1 + max(works) + rest)
            return max(works) + rest
        if op == _CONDITIONAL:
            raise RuleError("a conditional group (?(1)..|..) is not supported")
        if op in _ZERO_WIDTH:
            return sum(self.work(sub, inside) for sub in _subitems(op, av)) + rest
        if op in _ATOMIC:
            return self.work(av, inside) + rest
        return 1 + rest

    def delimited(self, body):
        """The body of a repeat may only hold a repeat or an optional part if the
        characters that follow it (inside the body, or the start of the next
        round) are ones it cannot match, so that where it ends is never a choice.
        ``(?:[a-z]+\\.)+`` and ``(?:ab?)+`` are fine; ``(a+)+``, ``(\\w+/?)+`` and
        ``(?:[ab][a-z]?)*`` are not."""
        flat = _sequence(body)
        start = _first(body, self.fold)[0]
        for i, (op, av, optional) in enumerate(flat):
            if op in _REPEATS and (av[1] > 1 or av[0] == 0) or optional:
                follow = frozenset()
                for later, args, later_optional in flat[i + 1:]:
                    if later in _ZERO_WIDTH:
                        continue
                    follow |= _first([(later, args)], self.fold)[0]
                    if not (later_optional or _nullable(later, args)):
                        break
                else:
                    follow |= start
                if _chars([(op, av)], self.fold) & follow:
                    raise RuleError("a part of a repeated group can match what comes after "
                                    "it, so where it ends is a choice that multiplies: "
                                    "(?:[a-z]+\\.)+ is fine, (a+)+ and (\\w+/?)+ are not")
            elif op not in _REPEATS and op not in _ZERO_WIDTH and _has_repeat([(op, av)]):
                raise RuleError("alternatives that hold repeats cannot sit inside a repeat")

    def alternatives(self, alts):
        seen = frozenset()
        for alt in alts:
            first, empty = _first(alt, self.fold)
            if empty or first & seen:
                raise RuleError("alternatives that can start alike inside a repetition "
                                "backtrack exponentially")
            seen |= first


def _starts(parsed, fold):
    """How many positions of a ``PRICE_LEN`` field a search can start a real attempt at.

    One when the pattern is anchored. When it opens with literal characters, an
    attempt needs those, and the most starts they allow is the length divided by
    how soon the literal can overlap itself (``cmd`` 3, ``aa`` 1). Otherwise all.
    """
    flat = _sequence(parsed)
    if flat and flat[0][0] == sre_constants.AT and str(flat[0][1]) in (
            "AT_BEGINNING", "AT_BEGINNING_STRING"):
        return 1
    prefix = []
    for op, av, _optional in flat:
        if op != sre_constants.LITERAL:
            break
        prefix.append(chr(av).lower() if fold else chr(av))
    if not prefix:
        return PRICE_LEN
    border = [0] * len(prefix)             # longest proper prefix that is also a suffix
    for i in range(1, len(prefix)):
        k = border[i - 1]
        while k and prefix[i] != prefix[k]:
            k = border[k - 1]
        border[i] = k + (prefix[i] == prefix[k])
    period = len(prefix) - border[-1]
    return -(-PRICE_LEN // period)


def _compile_regex(pattern):
    if len(pattern) > MAX_PATTERN:
        raise RuleError("regex longer than %d characters" % MAX_PATTERN)
    if "[[:" in pattern:
        raise RuleError("a POSIX class like [[:digit:]] means different things in re and in "
                        "regex; write \\d or [0-9]")
    try:
        with warnings.catch_warnings():
            # "possible nested set" / "possible set difference": the two engines disagree
            warnings.simplefilter("error", FutureWarning)
            compiled = re.compile(pattern)
        if compiled.flags & (re.ASCII | re.LOCALE):
            raise RuleError("the ASCII and LOCALE flags are not supported")
        parsed = sre_parse.parse(pattern)
        fold = bool(compiled.flags & re.IGNORECASE)
        steps = _Risk(fold).work(parsed) * _starts(parsed, fold)
        if steps > MAX_REGEX_STEPS:
            raise RuleError("its worst case on a %d-character field is about %d steps "
                            "(limit %d): too many repeats that can swallow what follows "
                            "them" % (PRICE_LEN, steps, MAX_REGEX_STEPS))
    except RuleError as exc:
        raise RuleError("regex %r refused: %s" % (pattern, exc))
    except FutureWarning as exc:
        raise RuleError("regex %r refused: %s (re and regex read this differently; "
                        "escape the bracket or the operator)" % (pattern, exc))
    except (re.error, RecursionError, OverflowError) as exc:
        raise RuleError("invalid regex %r: %s" % (pattern, exc))
    return _Compiled(pattern)


class _Compiled:
    """A rule regex on the engine in use; ``search`` raises ``_Unknown`` on a timeout."""

    def __init__(self, pattern):
        self.guarded = _regex_module is not None
        self.limit = subject_limit()
        self._pattern = (_regex_module or re).compile(pattern)

    def search(self, text):
        if not self.guarded:
            return self._pattern.search(text)
        try:
            return self._pattern.search(text, timeout=REGEX_TIMEOUT_S)
        except TimeoutError:
            raise _Unknown("timeout")


# --- compiling a rule ---------------------------------------------------------------

_COMPARE = {"gte": operator.ge, "lte": operator.le, "gt": operator.gt, "lt": operator.lt}
_FLAGS = frozenset((("b", True), ("b", False), ("z",)))     # too common to index by
_SCALAR_OPS = ("", "re", "contains", "startswith", "endswith", "in", "gte", "lte", "gt", "lt")
_WHOLE_OPS = ("count_gte", "has_all")


def _names(allowed):
    return ", ".join(sorted(allowed))


def _merge(unknown, new):
    return new if unknown is None else _Unknown(*(unknown.reasons | new.reasons))


def _all(tests):
    """False if any member is false, unknown if none is false and one is unknown."""
    def run(event):
        unknown = None
        for test in tests:
            try:
                if not test(event):
                    return False
            except _Unknown as exc:
                unknown = _merge(unknown, exc)
        if unknown is not None:
            raise unknown
        return True
    return run


def _any(tests):
    """True if any member is true, unknown if none is true and one is unknown."""
    def run(event):
        unknown = None
        for test in tests:
            try:
                if test(event):
                    return True
            except _Unknown as exc:
                unknown = _merge(unknown, exc)
        if unknown is not None:
            raise unknown
        return False
    return run


def _not(test):
    return lambda event: not test(event)          # an unknown passes through unchanged


class _Compiler:
    """Turns the ``match`` of one rule into a function of an event."""

    def __init__(self, lists, types):
        self.lists = lists
        self.types = types
        self.fields = frozenset().union(*(FIELDS[t] for t in types)) if types else frozenset()
        self.nodes = 0

    def tick(self):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise RuleError("match has more than %d conditions and blocks" % MAX_NODES)

    def resolve(self, value):
        """A ``$name`` becomes a copy of the list; ``$$x`` is the text ``$x``."""
        if isinstance(value, str) and value.startswith("$"):
            if value.startswith("$$"):
                return value[1:]
            name = value[1:]
            if name not in self.lists:
                raise RuleError("unknown list %r" % value)
            return list(self.lists[name])
        return value

    def element(self, text, item):
        """An item written inside a list: ``$name`` there would be silently literal."""
        if isinstance(item, str) and item.startswith("$"):
            if item.startswith("$$"):
                return item[1:]
            raise RuleError("%s: %r inside a list is text, not a list name; use $$ for a "
                            "literal $, or give the list name alone as the value"
                            % (text, item))
        return item

    def values(self, text, value, scalar_ok=True, kind=None):
        if isinstance(value, list):
            value = [self.element(text, item) for item in value]
        else:
            value = self.resolve(value)
        if isinstance(value, list):
            if not value:
                raise RuleError("%s: the list is empty" % text)
            items = value
        elif scalar_ok:
            items = [value]
        else:
            raise RuleError("%s needs a list" % text)
        for item in items:
            if not _is_scalar(item) or (kind is str and not isinstance(item, str)):
                raise RuleError("%s: %r is not a %s" % (text, item, "string" if kind is str
                                                         else "plain value"))
        return items

    def mapping(self, node, depth, top=False):
        """``(conditions, index)``: a list of (cost, test) and, at the top, an index key."""
        if not isinstance(node, dict):
            raise RuleError("a match must be a mapping of conditions")
        _no_duplicates(node, "a match")
        tests, index = [], None
        for key, value in node.items():
            self.tick()
            if not isinstance(key, str):
                raise RuleError("%r is not a field name" % (key,))
            if key in ("any", "all", "not"):
                tests.append(self.block(key, value, depth))
                continue
            cost, test, keys = self.condition(key, value)
            tests.append((cost, test))
            if top and keys and index is None:
                index = (key.partition("|")[0], keys)
        tests.sort(key=lambda t: t[0])
        return tests, index

    def conjunction(self, node, depth):
        tests = [t for _cost, t in self.mapping(node, depth)[0]]
        if not tests:
            return lambda event: True
        return tests[0] if len(tests) == 1 else _all(tests)

    def block(self, name, value, depth):
        if depth + 1 > MAX_DEPTH:
            raise RuleError("blocks nested more than %d deep" % MAX_DEPTH)
        if name == "not" and isinstance(value, dict):
            return 3, _not(self.conjunction(value, depth + 1))
        if not isinstance(value, list) or not value:
            raise RuleError("%r needs a non-empty list of mappings" % name)
        members = [self.conjunction(v, depth + 1) for v in value]
        if name == "all":
            return 3, _all(members)
        if name == "any":
            return 3, _any(members)
        return 3, _not(_any(members))

    def condition(self, key, value):
        field, _bar, op = key.partition("|")
        if "|" in op or op not in _SCALAR_OPS + _WHOLE_OPS:
            raise RuleError("unknown operator %r in %r (known: %s)"
                            % (op, key, _names(("equality",) + _SCALAR_OPS[1:] + _WHOLE_OPS)))
        if field == "password":
            raise RuleError("'password' cannot be matched: it is a credential "
                            "(use password_captured)")
        if field in UNMATCHABLE:
            raise RuleError("%r is a nested structure and cannot be matched" % field)
        if field not in self.fields:
            raise RuleError("%r is not a field of %s events" % (field, "/".join(self.types)))
        if op in _WHOLE_OPS:
            return self.whole(field, op, value)
        return self.scalar(field, op, value)

    def whole(self, field, op, value):
        if op == "count_gte":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuleError("%s|count_gte needs a whole number, not %r" % (field, value))

            def count_gte(event):
                found = event.get(field)
                return isinstance(found, (str, list, tuple, dict, set)) and len(found) >= value
            return 1, count_gte, None
        wanted = frozenset(_key(v) for v in self.values(field + "|has_all", value, False))

        def has_all(event):
            found = event.get(field)
            if not isinstance(found, (list, tuple, set)):
                return False
            return wanted <= frozenset(_key(v) for v in found)
        return 1, has_all, None

    def scalar(self, field, op, value):
        text = field + ("|" + op if op else "")
        keys = None
        if op in ("", "in"):
            items = self.values(text, value, scalar_ok=op == "")
            wanted = frozenset(_key(v) for v in items)
            cost = 0
            if not wanted <= _FLAGS:
                keys = wanted

            def check(item):
                key = _key(item)
                return key is not None and key in wanted
        elif op in ("contains", "startswith", "endswith"):
            needles = tuple(v.lower() for v in self.values(text, value, kind=str))
            if "" in needles:
                raise RuleError("%s: an empty string matches everything" % text)
            cost = 1

            def check(item):
                if not isinstance(item, str):
                    return False
                lowered = item.lower()
                if op == "contains":
                    return any(n in lowered for n in needles)
                if op == "startswith":
                    return lowered.startswith(needles)
                return lowered.endswith(needles)
        elif op == "re":
            patterns = [_compile_regex(p) for p in self.values(text, value, kind=str)]
            cost = 2

            def check(item):
                if not isinstance(item, str):
                    return False
                left = getattr(_run, "left", None)
                if left is not None and left <= 0:
                    _run.spent = True
                    raise _Unknown("budget")
                started = time.perf_counter()
                unknown = None
                try:
                    for pattern in patterns:
                        head = item[:pattern.limit]
                        cut = len(item) > pattern.limit
                        try:
                            m = pattern.search(head)
                        except _Unknown as exc:
                            unknown = _merge(unknown, exc)
                            continue
                        # a match that reaches the cut might have been anchored there
                        # or have run on, so it counts for nothing
                        if m and not (cut and m.end() == len(head)):
                            return True
                        if cut:
                            # nothing decisive in the part that was looked at, and
                            # the rest was not: "no" would be the padder's answer
                            unknown = _merge(unknown, _Unknown("cut"))
                finally:
                    if left is not None:
                        _run.left = left - (time.perf_counter() - started)
                        if _run.left <= 0:
                            _run.spent = True
                if unknown is not None:
                    raise unknown
                return False
        else:
            number = _number(self.resolve(value))
            if number is None:
                raise RuleError("%s needs a number, not %r" % (text, value))
            cost = 1
            compare = _COMPARE[op]

            def check(item):
                n = _number(item)
                return n is not None and compare(n, number)

        if op != "re":
            def test(event):
                found = event.get(field)
                if isinstance(found, (list, tuple)):
                    return any(check(item) for item in found)
                return check(found)
            return cost, test, keys

        def test_regex(event):
            found = event.get(field)
            if not isinstance(found, (list, tuple)):
                return check(found)
            unknown = None
            for item in found[:MAX_REGEX_ELEMENTS]:
                try:
                    if check(item):
                        return True
                except _Unknown as exc:
                    unknown = _merge(unknown, exc)
            if len(found) > MAX_REGEX_ELEMENTS:
                # elements nobody looked at: padding the list must not choose "no"
                unknown = _merge(unknown, _Unknown("cut"))
            if unknown is not None:
                raise unknown
            return False
        return cost, test_regex, keys


# --- the rule and the hit -------------------------------------------------------------

class Rule(dict):
    """One rule: a plain dict of the YAML keys (so it serializes), plus what was
    compiled from them, which is not part of the dict."""

    def __init__(self, spec, match=None, index=None):
        super().__init__(spec)
        self._match = match
        self._index = index
        self._sees_known = bool(spec["include_known_good"])
        self._position = 0


class RuleHit(dict):
    """A rule that matched, for one process.

    Plain dict for the same reason. ``events`` names where it matched (``index`` is
    the position in the list given to ``evaluate``) without copying the events.
    """

    def __init__(self, rule, process, count, events, via=()):
        super().__init__()
        self["rule_id"] = rule["id"]
        for key in ("name", "description", "severity", "role", "behavior", "attack",
                    "family", "kind"):
            self[key] = list(rule[key]) if key == "attack" else rule[key]
        self["process"] = process
        self["count"] = count
        self["events"] = events
        self["via"] = list(via)


def _reference(index, event):
    return {"index": index, "type": event["type"], "ts": _plain(event.get("ts")),
            "dest": _plain(event.get("dest")), "port": _plain(event.get("port"))}


class Hits(list):
    """The result of ``evaluate``: a list of ``RuleHit``, plus what it could not decide.

    ``unevaluated`` lists the rules that could not be decided for some events,
    because a regex timed out or the regex time budget was spent: each entry is
    ``{"rule_id", "events", "reasons"}`` (``events`` is how many events were
    skipped; ``reasons`` are ``timeout``, ``budget`` or ``requires <id>``).

    For a rule that is not listed, no hit means no match. For a rule that is
    listed, its hits come from the events it could decide and are real, but the
    absence of a hit is not an answer: it may be "could not tell". A condition that
    could not be decided never counts as true or as false, in a ``not`` either.
    ``budget_spent`` is True when the regex time ran out during the call, whether
    or not a later condition was then skipped.

    A regex is decided on the first ``subject_limit()`` characters of a field: a
    match there is a match, but when nothing decisive is found and the field was
    longer, the answer is "could not tell" (reason ``cut``) and never "no". So a
    regex rule on a long body that does not match in its head is listed here.

    Limits of the listing: a correlation is listed only when it fired for no
    process at all (the rule it needed is listed either way); and the regex time
    budget is shared by all rules, so one slow rule can leave every regex rule
    undecided for the rest of the call (``budget_spent``, reason ``budget``).
    ``regex_engine`` is ``"regex"`` (every call has a timeout) or ``"re"`` (the
    fallback: nothing bounds a call but the load-time checks, so a pattern they
    miss, such as a lookahead inside a repeated group, can run for hours).
    """

    def __init__(self):
        super().__init__()
        self.unevaluated = []
        self.budget_spent = False
        self.regex_engine = "regex"


class KnownGood:
    """The ``known_good`` names of a rule set: ``a.b`` is that name, ``*.a.b``
    is ``a.b`` and every name under it, compared without case or a final dot.
    ``net_evidence`` hides by the same list as the rules do."""

    def __init__(self, names):
        self.exact, self.suffixes = set(), set()
        for name in names:
            name = str(name).lower().rstrip(".")
            if name.startswith("*."):
                self.suffixes.add(name[2:])
                self.exact.add(name[2:])
            elif name:
                self.exact.add(name)

    def __bool__(self):
        return bool(self.exact)

    def hides(self, event):
        dest = event.get("dest")
        if not isinstance(dest, str) or not dest:
            return False
        dest = dest.lower().rstrip(".")
        if dest in self.exact:
            return True
        while "." in dest:
            dest = dest.partition(".")[2]
            if dest in self.suffixes:
                return True
        return False


class RuleSet:
    """The rules of one or more files, ready to match.

    ``rules`` holds the rules that loaded, ``errors`` one text per thing that did
    not (with the rule and the reason), ``lists`` the named lists, ``known_good``
    among them. ``notes`` says what an operator should know about how the rules
    will run (the unguarded ``re`` fallback), ``regex_engine`` which one it is.
    """

    def __init__(self, rules, errors, lists):
        self.rules = rules
        self.errors = errors
        self.lists = lists
        self.regex_engine = "regex" if _regex_module is not None else "re"
        self.notes = [] if _regex_module is not None else [
            "the regex module is not installed: regexes run on re with no timeout and "
            "are cut at %d characters; only the load-time checks guard them" % MAX_SUBJECT_UNGUARDED]
        self._known = KnownGood(lists.get(KNOWN_GOOD, ()))
        self._scan = {}         # event type -> rules to try on every event of it
        self._indexed = {}      # event type -> field -> key -> rules
        self._chains = []
        for position, rule in enumerate(rules):
            rule._position = position
            if rule["requires"]:
                self._chains.append(rule)
                continue
            for etype in rule["event"]:
                if rule._index is None:
                    self._scan.setdefault(etype, []).append(rule)
                else:
                    field, keys = rule._index
                    by_key = self._indexed.setdefault(etype, {}).setdefault(field, {})
                    for key in keys:
                        by_key.setdefault(key, []).append(rule)

    def _candidates(self, event, etype):
        scan = self._scan.get(etype, ())
        by_field = self._indexed.get(etype)
        if not by_field:
            return scan
        extra = {}
        for field, by_key in by_field.items():
            for item in _scalars(event.get(field)):
                key = _key(item)
                if key is not None:
                    for rule in by_key.get(key, ()):
                        extra[rule._position] = rule
        return list(scan) + list(extra.values()) if extra else scan

    def evaluate(self, events):
        """The hits of every rule over ``events``, rules in the order they were
        loaded, then the correlations. The events are not changed."""
        seen = {}               # rule position -> process -> [count, event references]
        hidden = self._known.hides if self._known else None
        unknown = {}            # rule position -> [events skipped, reasons]
        _run.left, _run.spent = REGEX_BUDGET_S, False
        try:
            self._scan_events(events, seen, hidden, unknown)
            spent = _run.spent
        finally:
            _run.left = None
        hits, by_rule = Hits(), {}
        for position in sorted(seen):
            rule = self.rules[position]
            for process, (count, refs) in seen[position].items():
                if count >= rule["count_gte"]:
                    hit = RuleHit(rule, process, count, refs)
                    hits.append(hit)
                    by_rule.setdefault(rule["id"], {})[process] = hit
        hits.extend(self._correlate(by_rule))
        hits.budget_spent = spent
        hits.regex_engine = self.regex_engine
        hits.unevaluated = self._unevaluated(unknown, by_rule, hits)
        return hits

    def _unevaluated(self, unknown, by_rule, hits):
        out = {self.rules[p]["id"]: [n, set(reasons)] for p, (n, reasons) in unknown.items()}
        fired = {h["rule_id"] for h in hits}
        for rule in self._chains:
            missing = [i for group in rule["requires"] for i in group if i in out]
            if missing and rule["id"] not in fired:
                out[rule["id"]] = [0, {"requires " + i for i in sorted(set(missing))}]
        return [{"rule_id": rid, "events": n, "reasons": sorted(reasons)}
                for rid, (n, reasons) in sorted(out.items())]

    def _scan_events(self, events, seen, hidden, unknown):
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                continue
            etype = event.get("type")
            if not isinstance(etype, str):
                continue
            invisible = (hidden is not None and etype not in ALWAYS_VISIBLE
                         and hidden(event))
            for rule in self._candidates(event, etype):
                if invisible and not rule._sees_known:
                    continue
                try:
                    matched = rule._match(event)
                except _Unknown as exc:
                    skipped = unknown.setdefault(rule._position, [0, set()])
                    skipped[0] += 1
                    skipped[1] |= exc.reasons
                    continue
                if matched:
                    process = event.get("process")
                    entry = seen.setdefault(rule._position, {}).setdefault(
                        process if isinstance(process, str) else "", [0, []])
                    entry[0] += 1
                    if len(entry[1]) < MAX_HIT_EVENTS:
                        entry[1].append(_reference(index, event))

    def _correlate(self, by_rule):
        chains = []
        for rule in self._chains:
            processes = []
            for process in dict.fromkeys(p for per in by_rule.values() for p in per):
                parts = [[by_rule[i][process] for i in group
                          if i in by_rule and process in by_rule[i]]
                         for group in rule["requires"]]
                if all(parts):
                    processes.append((process, [h for group in parts for h in group]))
            for process, members in processes:
                refs = [e for h in members for e in h["events"]][:MAX_HIT_EVENTS]
                chains.append(RuleHit(rule, process, sum(h["count"] for h in members), refs,
                                      via=[h["rule_id"] for h in members]))
        return chains


# --- loading ------------------------------------------------------------------------------

class _Mapping(dict):
    """A YAML mapping that remembers the keys it was given twice.

    YAML lets the later one win silently, which turns ``path|contains: a`` followed
    by ``path|contains: b`` into a rule that tests only ``b``.
    """

    duplicates = ()


try:
    _SafeLoader = yaml.CSafeLoader
except AttributeError:
    _SafeLoader = yaml.SafeLoader


class _Loader(_SafeLoader):
    def construct_yaml_map(self, node):
        data = _Mapping()
        yield data
        data.update(self.construct_mapping(node))
        seen, twice = set(), []
        for key_node, _value in node.value:
            try:
                key = self.construct_object(key_node)
                if key in seen and key not in twice:
                    twice.append(key)
                seen.add(key)
            except TypeError:                   # an unhashable key; construct_mapping refuses it
                continue
        data.duplicates = twice


_Loader.add_constructor("tag:yaml.org,2002:map", _Loader.construct_yaml_map)


def _no_duplicates(mapping, what):
    twice = getattr(mapping, "duplicates", ())
    if twice:
        raise RuleError("%s has the key %s twice; the second would silently replace the first"
                        % (what, ", ".join(repr(k) for k in twice)))


def _one_line(text):
    return " ".join(str(text).split())


def _read(path, errors):
    """The parsed YAML of one file, or None after reporting why not."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            errors.append("%s: larger than %d bytes, not read" % (path, MAX_FILE_BYTES))
            return None
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8")
        return yaml.load(text, Loader=_Loader)
    except (OSError, ValueError, TypeError, OverflowError, yaml.YAMLError, RecursionError) as exc:
        errors.append("%s: cannot read the rule file: %s" % (path, _one_line(exc)))
        return None


def _files(paths):
    if isinstance(paths, (str, bytes, os.PathLike)):
        paths = [paths]
    out = []
    for path in paths:
        path = os.fspath(path)
        if os.path.isdir(path):
            out.extend(sorted(os.path.join(path, name) for name in os.listdir(path)
                              if name.lower().endswith((".yaml", ".yml"))))
        else:
            out.append(path)
    return out


def _read_lists(raw, path, lists, errors):
    if not isinstance(raw, dict):
        errors.append("%s: 'lists' must be a mapping of name to list" % path)
        return
    for name in getattr(raw, "duplicates", ()):
        errors.append("%s: list %r is defined twice in one 'lists'; the first is ignored"
                      % (path, name))
    for name, items in raw.items():
        if (not isinstance(name, str) or not isinstance(items, list)
                or not all(isinstance(i, (str, int, float)) and not isinstance(i, bool)
                           for i in items)):
            errors.append("%s: list %r must be a list of strings or numbers" % (path, name))
            continue
        lists.setdefault(name, []).extend(items)


def _text(spec, key):
    value = spec.get(key, "")
    if not isinstance(value, str):
        raise RuleError("%r must be text" % key)
    return value


def _event_rule(spec, lists):
    event = spec.get("event")
    if event is None:
        raise RuleError("needs an event (one of: %s)" % ", ".join(net_events.EVENT_TYPES))
    types = [event] if isinstance(event, str) else event
    if (not isinstance(types, list) or not types
            or not all(isinstance(t, str) for t in types)):
        raise RuleError("'event' must be an event type or a list of them")
    for etype in types:
        if etype not in net_events.EVENT_TYPES:
            raise RuleError("unknown event type %r (known: %s)"
                            % (etype, ", ".join(net_events.EVENT_TYPES)))
    types = list(dict.fromkeys(types))
    compiler = _Compiler(lists, types)
    tests, index = compiler.mapping(spec.get("match", {}), 0, top=True)
    parts = [t for _cost, t in tests]
    match = _all(parts) if parts else (lambda event: True)
    count = spec.get("count_gte", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise RuleError("'count_gte' must be a whole number of at least 1")
    include = spec.get("include_known_good", False)
    if not isinstance(include, bool):
        raise RuleError("'include_known_good' must be true or false")
    return types, match, index, count, include


def _build(spec, lists):
    """A ``Rule`` from one raw YAML rule, or RuleError saying what is wrong."""
    if not isinstance(spec, dict):
        raise RuleError("a rule must be a mapping")
    _no_duplicates(spec, "the rule")
    for key in spec:
        if key not in RULE_KEYS:
            raise RuleError("unknown key %r (known: %s)" % (key, _names(RULE_KEYS)))
    severity = spec.get("severity", "info")
    if severity not in SEVERITIES:
        raise RuleError("severity must be one of %s, not %r" % (", ".join(SEVERITIES), severity))
    attack = spec.get("attack", [])
    attack = [attack] if isinstance(attack, str) else attack
    if not isinstance(attack, list) or not all(isinstance(a, str) for a in attack):
        raise RuleError("'attack' must be a technique or a list of them")
    out = {"id": spec["id"], "name": spec["name"], "severity": severity, "attack": attack}
    for key in _TEXT_KEYS:
        out[key] = _text(spec, key)
    if out["kind"] and out["kind"] not in memory_evidence.NETWORK_KINDS:
        raise RuleError("unknown evidence kind %r (known: %s)"
                        % (out["kind"], ", ".join(memory_evidence.NETWORK_KINDS)))
    if "requires" in spec:
        for key in _CORRELATION_FORBIDDEN:
            if key in spec:
                raise RuleError("a correlation rule (with 'requires') takes no %r" % key)
        groups = spec["requires"]
        if (not isinstance(groups, list) or not groups
                or not all(isinstance(g, list) and g and all(isinstance(i, str) for i in g)
                           for g in groups)):
            raise RuleError("'requires' must be a list of non-empty lists of rule ids, "
                            "like [[a, b], [c]]")
        out.update(event=[], match={}, count_gte=1, include_known_good=False,
                   requires=[list(g) for g in groups])
        return Rule(out)
    types, match, index, count, include = _event_rule(spec, lists)
    out.update(event=types, match=spec.get("match", {}), count_gte=count,
               include_known_good=include, requires=[])
    return Rule(out, match, index)


def _check_requires(rules, errors):
    """Drop the correlations that name something that is not an event rule."""
    plain = {r["id"] for r in rules if not r["requires"]}
    chains = {r["id"] for r in rules if r["requires"]}
    kept = []
    for rule in rules:
        problem = None
        for group in rule["requires"]:
            for name in group:
                if name in chains:
                    problem = "requires %r, which is a correlation rule itself" % name
                elif name not in plain:
                    problem = "requires %r, which is not a rule that loaded" % name
        if problem:
            errors.append("rule %r: %s" % (rule["id"], problem))
        else:
            kept.append(rule)
    return kept


def load_rules(paths):
    """Load rule files (or the ``.yaml``/``.yml`` files of directories) into a ``RuleSet``.

    Nothing raises. A file that cannot be read, a list that is malformed and a
    rule that does not hold are each one entry in ``errors``, and everything else
    is used. ``known_good`` exists even when no file defines it; lists of the
    same name in several files are joined.
    """
    errors, lists, raw_rules = [], {KNOWN_GOOD: []}, []
    for path in _files(paths):
        data = _read(path, errors)
        if data is None:
            continue
        if not isinstance(data, dict):
            errors.append("%s: a rule file is a mapping with 'lists' and 'rules'" % path)
            continue
        for key in getattr(data, "duplicates", ()):
            errors.append("%s: %r appears twice at the top; the first is ignored" % (path, key))
        for key in data:
            if key not in ("lists", "rules"):
                errors.append("%s: unknown top-level key %r (known: lists, rules)" % (path, key))
        if "lists" in data:
            _read_lists(data["lists"], path, lists, errors)
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            errors.append("%s: 'rules' must be a list" % path)
            continue
        raw_rules += [(path, number, spec) for number, spec in enumerate(rules, 1)]
    built, seen = [], set()
    for path, number, spec in raw_rules:
        rule_id = spec.get("id") if isinstance(spec, dict) else None
        label = "%s: rule %s" % (path, repr(rule_id) if isinstance(rule_id, str) and rule_id
                                 else "#%d" % number)
        try:
            if not isinstance(spec, dict):
                raise RuleError("a rule must be a mapping")
            for key in ("id", "name"):
                if not isinstance(spec.get(key), str) or not spec[key]:
                    raise RuleError("%r must be a non-empty string" % key)
            if rule_id in seen:
                raise RuleError("duplicate id (an earlier rule has it)")
            seen.add(rule_id)
            built.append(_build(spec, lists))
        except RuleError as exc:
            errors.append("%s: %s" % (label, exc))
    return RuleSet(_check_requires(built, errors), errors, lists)
