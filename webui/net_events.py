"""Network event schema.

Everything TDC learns from a pcap - DNS lookups, connections, TLS handshakes,
HTTP requests, decoded payloads, beacon candidates - has to reach one rule
engine and one UI. Each protocol parser would otherwise invent its own shape,
and every consumer would grow a branch per parser. This module fixes the shape:
one event class, one list of types, built through a constructor that enforces
it.

Several assumptions would quietly corrupt the result:

  * A destination is a hostname. Malware often connects to a bare IP, which is
    itself a signal ("no DNS lookup came first"). The event therefore records
    whether the destination is an IP, rather than leaving every rule to guess
    from the string.
  * A pcap knows which process sent a packet. It does not: it holds packets,
    not processes. "in_tree" (is the process part of the sample's process
    tree) is always False in this phase and must not be derived from
    anything. The field exists because a later phase fills it, so rules and UI
    can already refer to it.
  * Events arrive in time order. They arrive per parser, so merging them
    needs an explicit sort, and events with the same timestamp must keep
    their order or the same pcap yields different timelines between runs.
  * Any string is a valid event type. A misspelt type silently matches no
    rule, so unknown types are rejected where the event is created.

Event timestamps are Unix seconds as float. Parser-specific data goes into
extra keyword fields; the mandatory ones are always present.
"""

import codecs
import ipaddress
import unicodedata

EVENT_TYPES = (
    "dns", "conn", "conn_failed", "tls", "http", "udp", "raw", "ftp", "smtp",
    "websocket", "download", "upload", "decoded", "beacon", "retry", "fanout",
)


def render_bytes(raw, escape=b""):
    """Bytes as readable text in which no two different byte strings look alike.

    Anything a capture hands over as bytes (a DNS label, a delimiter, a server
    name) may hold a NUL, a newline or a byte above 0x7F, and none of those can
    be left raw in a report or an API response. The text is written as a zone
    file writes a name: a printable ASCII byte (``!`` to ``~``) stands for
    itself, a backslash is ``\\\\``, any byte listed in ``escape`` is preceded
    by a backslash, and every other byte (control characters, space, bytes
    above 0x7E) is ``\\DDD`` with its decimal value, three digits. A backslash
    always starts an escape, so the text can be read back and two different
    inputs never give the same text: ``a.b`` and ``a\\.b`` stay apart when
    ``escape`` holds ``.``. DNS names pass ``escape=b"."`` so that a dot inside
    a label is not mistaken for the dot between labels; text where a dot is
    ordinary (a server name) does not. ``escape`` may only name printable,
    non-digit ASCII bytes: a digit after a backslash would read as the start of
    ``\\DDD``.
    """
    for byte in escape:
        if not 0x21 <= byte <= 0x7E or 0x30 <= byte <= 0x39:
            raise ValueError("cannot escape byte %d: not printable non-digit ASCII" % byte)
    out = []
    for byte in raw:
        if byte == 0x5C or byte in escape:
            out.append("\\" + chr(byte))
        elif 0x21 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append("\\%03d" % byte)
    return "".join(out)


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


class NetEvent(dict):
    """One network event.

    A dict subclass built through a constructor that enforces the schema. The
    mandatory fields and the fields of every parser except one are plain JSON
    values, so such an event goes through ``json.dumps`` as it is. The
    exception is deliberate: ``net_mail_ftp`` stores a captured password as a
    ``Secret``, which is not JSON-serializable and makes ``json.dumps`` (and
    pickling) raise ``TypeError``. Events that may hold one (``ftp``, ``smtp``)
    are serialized through ``net_mail_ftp.masked(...)``, which accepts one
    event, a list of them or any nesting and returns plain dicts. Using it on
    every event is always safe.
    """

    def __init__(self, type, ts, process="", pid=None, dest="", **fields):
        if type not in EVENT_TYPES:
            raise ValueError("unknown network event type: %r" % (type,))
        super().__init__()
        self["type"] = type
        self["ts"] = float(ts)
        self["process"] = process
        self["pid"] = pid
        self["dest"] = dest
        self["port"] = None
        self.update(fields)
        # Derived last so that a caller's keyword cannot override them.
        self["dest_is_ip"] = _is_ip(dest) if isinstance(dest, str) else False
        self["in_tree"] = False


def sort_events(events):
    """Return a new list in time order; equal timestamps keep insertion order."""
    # list.sort is stable, which provides the tie rule.
    return sorted(events, key=lambda e: e["ts"])


def event_summary(events):
    """Count of events per type."""
    counts = {}
    for e in events:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    return counts


# --- readable text -----------------------------------------------------------
# Shared by ``net_decode`` (is a decoded value text or bytes?) and ``net_http``
# (is a body that starts with a printable magic such as ``MZ`` a file or a
# sentence?). ``net_decode`` reads the events ``net_http`` makes, so neither can
# import the other's judgement without the layering running backwards; it lives
# with the schema, like ``render_bytes``.

MIN_TEXT = 5            # characters of decoded text
TEXT_SHARE = 0.95       # printable share of a text; the slack is a stray control byte or a cut
MIN_ALNUM_SHARE = 0.25  # a text of dashes, dots and spaces is filler, not content
SHORT_TEXT = 16         # a text shorter than this may use only plain characters (see _plain)
TEXT_SAMPLE = 64 * 1024     # characters judged; the rest of a long text is taken as it comes
_BOM8 = b"\xef\xbb\xbf"
_PLAIN_PUNCTUATION = " \t\r\n_-.:/\\@=&,;|"
_ONE_SCRIPT = {"HIRAGANA": "CJK", "KATAKANA": "CJK", "BOPOMOFO": "CJK",
               "HALFWIDTH": "CJK", "FULLWIDTH": "CJK"}


def _scripts(sample):
    """Scripts of the non-ASCII letters of a text, Japanese counted as one."""
    found = set()
    for c in sample:
        if c > "\x7f" and c.isalpha():
            word = unicodedata.name(c, "?").split()[0]
            found.add(_ONE_SCRIPT.get(word, word))
    return found


def _plain(sample):
    """Letters, digits, whitespace and the punctuation of paths, addresses and
    key=value pairs (and any non-ASCII punctuation). Random printable bytes
    use quotes, brackets and symbols about a quarter of the time; a short text
    must not."""
    return all(c.isalnum() or c in _PLAIN_PUNCTUATION
               or (c > "\x7f" and unicodedata.category(c).startswith("P")) for c in sample)


def _texty(text):
    """Is this decoded text, as opposed to bytes that happen to decode?"""
    text = text.rstrip("\x00")
    if len(text) < MIN_TEXT:
        return None
    sample = text[:TEXT_SAMPLE]
    printable = sum(1 for c in sample if (c.isprintable() and c != "\ufffd") or c in "\t\r\n")
    if printable < TEXT_SHARE * len(sample):
        return None
    if sum(1 for c in sample if c.isalnum()) < MIN_ALNUM_SHARE * len(sample):
        return None
    if len(_scripts(sample)) > 1:
        return None
    if len(text) < SHORT_TEXT and not _plain(text):
        return None
    return text


def _utf16_like(raw):
    pairs = len(raw) // 2
    if pairs < MIN_TEXT:
        return False
    highs = raw[1:2 * pairs:2].count(0)
    lows = raw[0:2 * pairs:2].count(0)
    return highs * 10 >= pairs * 9 and lows * 10 <= pairs


def _decode_with(raw, charset, cut):
    try:
        return codecs.getincrementaldecoder(charset)().decode(raw, final=not cut)
    except UnicodeDecodeError:
        return None


def read_text(raw, cut=False):
    """``(text, charset)`` if ``raw`` is readable text, else None.

    ``cut`` says the bytes are the start of something longer, so a character
    split at the end is not an error.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        charset = "utf-16-le" if raw[:2] == b"\xff\xfe" else "utf-16-be"
        body = raw[2:]
        text = _decode_with(body[:len(body) & ~1], charset, cut)
        text = _texty(text) if text is not None else None
        return (text, charset) if text is not None else None
    if _utf16_like(raw):
        text = _decode_with(raw[:len(raw) & ~1], "utf-16-le", cut)
        text = _texty(text) if text is not None else None
        return (text, "utf-16-le") if text is not None else None
    body = (raw[3:] if raw.startswith(_BOM8) else raw).rstrip(b"\x00")
    text = _decode_with(body, "utf-8", cut)
    if text is not None:
        text = _texty(text)
        return (text, "utf-8") if text is not None else None
    sample = body[:TEXT_SAMPLE]
    plain = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if plain < TEXT_SHARE * len(sample):
        return None
    text = _texty(body.decode("cp1252", "replace"))
    return (text, "cp1252") if text is not None else None


def is_readable_text(raw, cut=True):
    """Is ``raw`` readable text (the start of a longer body when ``cut``)?"""
    return read_text(raw[:TEXT_SAMPLE], cut) is not None
