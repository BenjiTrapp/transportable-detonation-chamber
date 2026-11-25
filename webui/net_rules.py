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
    ``\\d+\\d+\\d+x`` against a thousand for longer than anyone waits, in one
    event of a capture the malware chose. ``re`` cannot be interrupted, so the
    defence is refusal at load time of the shapes that make it blow up (nested
    repetition, overlapping alternatives under a repetition, adjacent
    overlapping repeats, more than two ambiguous repeats) and a bound on what a
    regex is shown: the first ``MAX_SUBJECT`` characters of a field. The other
    string operators are linear and see the whole field.
  * Every rule against every event. Rules are filed under the event types they
    name, and a rule whose match has a plain equality or ``in`` condition is
    additionally filed under that field's values, so an event is tried on the
    rules that can possibly match it and not on all of them.
  * One hit per matching event. A thousand requests of one kind are one finding
    with ``count`` 1000 and the first ``MAX_HIT_EVENTS`` events, grouped by
    process, which is also what a correlation needs.
  * The weight of a finding comes from the rule. It does not: a rule may name
    an evidence ``kind``, and the evidence model decides what that kind weighs.
    There is no weight key, and one is rejected.
  * ``True == 1``. A flag is not a number: ``nxdomain: true`` does not match
    ``1`` and ``port: 1`` does not match ``True``.
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

import yaml

import net_events

try:                                     # Python 3.11 and later
    from re import _constants as sre_constants
    from re import _parser as sre_parse
except ImportError:                      # 3.9, 3.10
    import sre_constants
    import sre_parse

MAX_SUBJECT = 1024          # characters of a field that a regex is shown
MAX_PATTERN = 500           # characters of a regex
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 6               # any / all / not inside each other
MAX_NODES = 400             # conditions and blocks of one rule
MAX_HIT_EVENTS = 20         # events named by one hit; ``count`` is exact
MAX_AMBIGUOUS_REPEATS = 2   # unbounded repeats that can swallow what follows them

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

_HEAVY = 5          # a repeat that can run more often than this multiplies what is inside
_OPEN = 16          # a repeat that can run more often than this is open-ended
_ASCII_SETS = {
    "CATEGORY_DIGIT": frozenset(range(48, 58)),
    "CATEGORY_SPACE": frozenset((9, 10, 11, 12, 13, 32)),
    "CATEGORY_WORD": frozenset(list(range(48, 58)) + list(range(65, 91))
                               + list(range(97, 123)) + [95]),
}
_REPEATS = tuple(getattr(sre_constants, name) for name in
                 ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(sre_constants, name))
_ZERO_WIDTH = tuple(getattr(sre_constants, name) for name in ("AT", "ASSERT", "ASSERT_NOT"))


def _flatten(items):
    out = []
    for op, av in items:
        if op == sre_constants.SUBPATTERN:
            out.extend(_flatten(av[-1]))
        else:
            out.append((op, av))
    return out


def _fold(chars, fold):
    if not fold or chars is None:
        return chars
    return frozenset(chars | {ord(chr(c).swapcase()) for c in chars if c < 0x110000
                              and len(chr(c).swapcase()) == 1})


def _in_set(av, fold):
    chars = set()
    for op, arg in av:
        if op == sre_constants.LITERAL:
            chars.add(arg)
        elif op == sre_constants.RANGE and arg[1] - arg[0] < 256:
            chars.update(range(arg[0], arg[1] + 1))
        elif op == sre_constants.CATEGORY and str(arg) in _ASCII_SETS:
            chars |= _ASCII_SETS[str(arg)]
        else:
            return None                     # a negation, a wide range, a non-ASCII category
    return _fold(frozenset(chars), fold)


def _union(a, b):
    return None if a is None or b is None else a | b


def _chars(items, fold):
    """Every character the items can consume; None when that is too broad to say."""
    total = frozenset()
    for op, av in _flatten(items):
        if op == sre_constants.LITERAL:
            part = _fold(frozenset((av,)), fold)
        elif op == sre_constants.IN:
            part = _in_set(av, fold)
        elif op in _REPEATS:
            part = _chars(av[2], fold)
        elif op == sre_constants.BRANCH:
            part = frozenset()
            for alt in av[1]:
                part = _union(part, _chars(alt, fold))
        elif op in _ZERO_WIDTH:
            part = frozenset()
        else:
            part = None                     # ANY, NOT_LITERAL, a group reference ...
        total = _union(total, part)
        if total is None:
            return None
    return total


def _nullable(op, av):
    if op in _ZERO_WIDTH:
        return True
    if op in _REPEATS:
        return av[0] == 0
    if op == sre_constants.BRANCH:
        return any(all(_nullable(o, a) for o, a in _flatten(alt)) for alt in av[1])
    return False


def _first(items, fold):
    """(characters a match of ``items`` can start with, whether it can be empty)."""
    start = frozenset()
    for op, av in _flatten(items):
        if op in _ZERO_WIDTH:
            continue
        if op in _REPEATS:
            part = _first(av[2], fold)[0]
        elif op == sre_constants.BRANCH:
            part = frozenset()
            for alt in av[1]:
                part = _union(part, _first(alt, fold)[0])
        else:
            part = _chars([(op, av)], fold)
        start = _union(start, part)
        if not _nullable(op, av):
            return start, False
    return start, True


def _overlap(a, b):
    if a is not None and not a or b is not None and not b:
        return False
    return a is None or b is None or bool(a & b)


def _is_open(av):
    return av[1] == sre_constants.MAXREPEAT or av[1] > _OPEN


class _Risk:
    def __init__(self, fold):
        self.fold = fold
        self.ambiguous = 0

    def walk(self, items, heavy):
        flat = _flatten(items)
        for i, (op, av) in enumerate(flat):
            if op in _REPEATS:
                lo, hi, body = av
                if heavy and hi > 1:
                    raise RuleError("a repetition inside a repetition backtracks exponentially")
                if _is_open(av):
                    self.open_repeat(flat, i, body)
                self.walk(body, heavy or hi > _HEAVY)
            elif op == sre_constants.BRANCH:
                if heavy:
                    self.alternatives(av[1])
                for alt in av[1]:
                    self.walk(alt, heavy)
            elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
                self.walk(av[1], heavy)

    def alternatives(self, alts):
        seen = frozenset()
        for alt in alts:
            first, empty = _first(alt, self.fold)
            if empty or first is None or first & seen:
                raise RuleError("alternatives that can start alike inside a repetition "
                                "backtrack exponentially")
            seen |= first

    def open_repeat(self, flat, i, body):
        swallows = _chars(body, self.fold)
        follow = frozenset()
        for op, av in flat[i + 1:]:
            if op in _ZERO_WIDTH:
                continue
            if op in _REPEATS and _is_open(av) and _overlap(swallows, _chars(av[2], self.fold)):
                raise RuleError("adjacent repeats that can match the same characters "
                                "backtrack in a product of their lengths")
            follow = _union(follow, _first([(op, av)], self.fold)[0])
            if not _nullable(op, av):
                break
        if _overlap(swallows, follow):
            self.ambiguous += 1
            if self.ambiguous > MAX_AMBIGUOUS_REPEATS:
                raise RuleError("more than %d unbounded repeats that can swallow what "
                                "follows them backtrack in a power of the length"
                                % MAX_AMBIGUOUS_REPEATS)


def _compile_regex(pattern):
    if len(pattern) > MAX_PATTERN:
        raise RuleError("regex longer than %d characters" % MAX_PATTERN)
    try:
        compiled = re.compile(pattern)
        parsed = sre_parse.parse(pattern)
        _Risk(bool(compiled.flags & re.IGNORECASE)).walk(parsed, False)
    except RuleError as exc:
        raise RuleError("regex %r refused: %s" % (pattern, exc))
    except (re.error, RecursionError, OverflowError) as exc:
        raise RuleError("invalid regex %r: %s" % (pattern, exc))
    return compiled


# --- compiling a rule ---------------------------------------------------------------

_COMPARE = {"gte": operator.ge, "lte": operator.le, "gt": operator.gt, "lt": operator.lt}
_FLAGS = frozenset((("b", True), ("b", False), ("z",)))     # too common to index by
_SCALAR_OPS = ("", "re", "contains", "startswith", "endswith", "in", "gte", "lte", "gt", "lt")
_WHOLE_OPS = ("count_gte", "has_all")


def _names(allowed):
    return ", ".join(sorted(allowed))


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

    def values(self, text, value, scalar_ok=True, kind=None):
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
        if len(tests) == 1:
            return tests[0]
        return lambda event: all(t(event) for t in tests)

    def block(self, name, value, depth):
        if depth + 1 > MAX_DEPTH:
            raise RuleError("blocks nested more than %d deep" % MAX_DEPTH)
        if name == "not" and isinstance(value, dict):
            inner = self.conjunction(value, depth + 1)
            return 3, lambda event: not inner(event)
        if not isinstance(value, list) or not value:
            raise RuleError("%r needs a non-empty list of mappings" % name)
        members = [self.conjunction(v, depth + 1) for v in value]
        if name == "all":
            return 3, lambda event: all(m(event) for m in members)
        if name == "any":
            return 3, lambda event: any(m(event) for m in members)
        return 3, lambda event: not any(m(event) for m in members)

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
                head = item[:MAX_SUBJECT]
                cut = len(item) > MAX_SUBJECT
                for pattern in patterns:
                    m = pattern.search(head)
                    # a match that reaches the cut might have been anchored there or
                    # have run on, so it counts for nothing
                    if m and not (cut and m.end() == len(head)):
                        return True
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

        def test(event):
            found = event.get(field)
            if isinstance(found, (list, tuple)):
                return any(check(item) for item in found)
            return check(found)
        return cost, test, keys


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


class _KnownGood:
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
    among them.
    """

    def __init__(self, rules, errors, lists):
        self.rules = rules
        self.errors = errors
        self.lists = lists
        self._known = _KnownGood(lists.get(KNOWN_GOOD, ()))
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
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                continue
            etype = event.get("type")
            if not isinstance(etype, str):
                continue
            invisible = hidden is not None and hidden(event)
            for rule in self._candidates(event, etype):
                if invisible and not rule._sees_known:
                    continue
                if rule._match(event):
                    process = event.get("process")
                    entry = seen.setdefault(rule._position, {}).setdefault(
                        process if isinstance(process, str) else "", [0, []])
                    entry[0] += 1
                    if len(entry[1]) < MAX_HIT_EVENTS:
                        entry[1].append(_reference(index, event))
        hits, by_rule = [], {}
        for position in sorted(seen):
            rule = self.rules[position]
            for process, (count, refs) in seen[position].items():
                if count >= rule["count_gte"]:
                    hit = RuleHit(rule, process, count, refs)
                    hits.append(hit)
                    by_rule.setdefault(rule["id"], {})[process] = hit
        return hits + self._correlate(by_rule)

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
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as exc:
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

    def match(event):
        for part in parts:
            if not part(event):
                return False
        return True
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
