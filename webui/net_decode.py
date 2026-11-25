"""Encoded values in network events, decoded only when the result means something.

Malware wraps what it sends: a stealer's harvest is base64 in a POST field, a
C2's instruction is hex in a query parameter, a bot's report is a percent-
escaped form value, and a blob is often compressed first. Undoing that is where
the content of an infection becomes readable. The hard part is not decoding, it
is deciding when not to. These assumptions would turn the report into noise:

  * A string in the base64 alphabet is base64. Hashes, UUIDs, session ids, JWT
    signatures, long identifiers and file paths are all valid base64 or hex,
    and decoding them yields random bytes. A result is therefore reported only
    if it is text (mostly printable, with real letters or digits, in UTF-8,
    UTF-16LE or an ANSI code page) or begins with the signature of a file type
    that matters (PE, ELF, archives, documents, images, SQLite). The input
    must also be long enough that random bytes are unlikely to pass, and a
    short result is held to a stricter standard (plain characters only), because
    a decimal number such as an id is valid hex and decodes to printable
    bytes about one time in a hundred.
  * A result that is not text is worthless. A PE hidden in base64 is the best
    finding there is; it is reported by kind, with size, hash and a preview,
    never as garbled text.
  * One layer is all there is. Base64 of gzip, base64 of base64 and a
    percent-escaped base64 value are routine, so layers are followed, but only
    to ``MAX_LAYERS`` and only while each step is itself plausible; inflating
    never produces more than ``MAX_INFLATED`` bytes and an event has a total
    inflate budget, so a compression bomb costs a bounded amount of time.
  * URL encoding is always a finding. ``%20`` and ``%2F`` in a query are
    ordinary; escaping is reported only when it is dense (half the value or
    more: obfuscation or non-ASCII text) or escapes a letter or digit, which
    nobody does by accident, or as a layer on the way to something else.
  * A form value is read the way a browser sends it. ``+`` is kept as ``+``
    (a space would corrupt base64), and only the named text fields of an
    event are read; an event is never copied wholesale, so a ``Secret`` that
    ``net_mail_ftp`` keeps unserializable stays that way.
  * Input is text. A field may hold bytes that are not UTF-8, a lone surrogate
    or something that is not a string at all; ``decode`` takes ``str`` or
    bytes-like values and returns None for anything it cannot make sense of.

A ``Decoded`` keeps the raw bytes. The ``decoded`` event derived from it does
not: bytes are described by kind, size, SHA-256 and a ``render_bytes`` preview
so the event is plain JSON.
"""

import binascii
import codecs
import hashlib
import ipaddress
import json
import re
import unicodedata
import zlib
from collections import namedtuple
from urllib.parse import unquote_to_bytes

from net_events import NetEvent, render_bytes

MAX_INPUT = 256 * 1024          # characters of one value examined; bodies are capped at this upstream
MAX_LAYERS = 4                  # url + base64 + gzip + base64 is the deepest chain met in practice
MAX_INFLATED = 1024 * 1024      # bytes one inflate step may produce
MAX_EVENT_INFLATE = 4 * 1024 * 1024    # bytes all inflate steps of one event may produce together
MAX_EVENT_CHARS = 1024 * 1024   # characters of field text scanned per event
MAX_VALUES_PER_FIELD = 64       # candidate values examined in one field
MAX_SEGMENTS = 8                # dot-separated segments of a header token read (a JWT has 3)
MAX_DECODED_PER_EVENT = 200     # decoded events one event may yield
MAX_EVENT_TEXT = 64 * 1024      # characters of decoded text kept in an event
PREVIEW_BYTES = 32              # bytes of a binary result shown in an event
ENCODED_SHOWN = 80              # characters of the encoded value shown in an event

MIN_BASIC = 4       # one base64 quantum: "a:b". Only for a Basic credential, see _decode_basic
MIN_BASE64 = 12     # 9 bytes; random ones read as text about 0.006 % (8 chars: 0.14 %, too loose)
MIN_HEX = 10        # 5 bytes, the shortest word worth reading ("hello")
MIN_URL_ESCAPES = 2     # one escape is a space or a quote; two is a pattern
MIN_URL_SHARE = 0.5     # share of the value that is escapes; prose and URLs stay below
MIN_TEXT = 5            # characters of decoded text
TEXT_SHARE = 0.95       # printable share of a text; the slack is a stray control byte or a cut
MIN_ALNUM_SHARE = 0.25  # a text of dashes, dots and spaces is filler, not content
SHORT_TEXT = 16         # a text shorter than this may use only plain characters (see _plain)
TEXT_SAMPLE = 64 * 1024     # characters judged; the rest of a long text is taken as it comes
_MIN_VALUE = 3 * MIN_URL_ESCAPES    # a value shorter than this cannot decode by any scheme

_SIGNATURES = (
    # kind, magic, shortest plausible file
    ("pe", b"MZ", 64),
    ("elf", b"\x7fELF", 16),
    ("macho", b"\xfe\xed\xfa\xce", 16), ("macho", b"\xfe\xed\xfa\xcf", 16),
    ("macho", b"\xce\xfa\xed\xfe", 16), ("macho", b"\xcf\xfa\xed\xfe", 16),
    ("zip", b"PK\x03\x04", 22),
    ("gzip", b"\x1f\x8b\x08", 18),
    ("rar", b"Rar!\x1a\x07", 8),
    ("7z", b"7z\xbc\xaf\x27\x1c", 8),
    ("cab", b"MSCF\x00\x00\x00\x00", 8),
    ("pdf", b"%PDF-", 8),
    ("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8),
    ("png", b"\x89PNG\r\n\x1a\n", 16),
    ("jpeg", b"\xff\xd8\xff", 8),
    ("gif", b"GIF87a", 10), ("gif", b"GIF89a", 10),
    ("sqlite", b"SQLite format 3\x00", 16),
)
# Kinds whose magic is printable ASCII: ``MZ-Berlin weekly report`` and
# ``GIF89a is the format`` start the same way. They count as files only when the
# bytes are not readable text; a real PE, GIF or RAR never is.
_PRINTABLE_MAGIC = frozenset(("pe", "pdf", "gif", "rar"))

_HEX = re.compile(rb"[0-9A-Fa-f]+")
_B64 = re.compile(rb"[A-Za-z0-9+/]*")
_B64URL = re.compile(rb"[A-Za-z0-9_-]*")
_UNNEEDED_ESCAPE = re.compile(rb"%(?:4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|3[0-9])")
_WHITESPACE = re.compile(r"\s")
_COOKIE_PIECE = re.compile(r";|, ")
_JSON_PAIR = re.compile(r'"([^"\\\n]{1,64})"\s*:\s*"((?:[^"\\]|\\.)*)"')
_BLANK_LINE = re.compile(r"\r?\n\r?\n")
_PART_NAME = re.compile(r'name="([^"]{0,128})"')
_AUTH_VALUE = re.compile(r"([A-Za-z][A-Za-z0-9_-]*)[ \t]+(\S+)")
_CREDENTIAL_HEADERS = ("headers.authorization", "headers.proxy-authorization")
MAX_CREDENTIAL_LINES = 200  # lines of a decoded text checked for credential shapes
MAX_CREDENTIAL_CHARS = 64 * 1024    # characters of a decoded text checked
_SECRET_NAME = re.compile(r"pass|pwd|secret|token|key|auth|cred", re.I)
_SECRET_PAIR = re.compile(
    r"(?:pass|pwd|secret|token|key|auth|cred)[A-Za-z0-9_.-]{0,32}[\"']?[ \t]*[=:][ \t]*[\"']?\S", re.I)
_URL_SCHEME = r"[A-Za-z][A-Za-z0-9+.-]{0,20}://"
_URL_USERINFO = re.compile(_URL_SCHEME + r"[^/\s:@]{1,64}:[^/\s@]{1,128}@")
_URL_TOKEN = re.compile(_URL_SCHEME + r"\S*")
_COLON_PAIR = re.compile(r"([^\s:]{1,64}):[ \t]*(\S{0,8})")
_URL_FIELD = re.compile("(?:" + _URL_SCHEME + r"|www\.)\S+")
_RECORD_DELIMITERS = ("|", "\t", ";", ",")
_BOM8 = b"\xef\xbb\xbf"
_PLAIN_PUNCTUATION = " \t\r\n_-.:/\\@=&,;|"
_ONE_SCRIPT = {"HIRAGANA": "CJK", "KATAKANA": "CJK", "BOPOMOFO": "CJK",
               "HALFWIDTH": "CJK", "FULLWIDTH": "CJK"}

_Verdict = namedtuple("_Verdict", "kind text charset final cont")


class Decoded:
    """What an encoded value turned out to hold.

    ``scheme`` is the layers undone, outermost first, joined with ``+``
    (``base64``, ``base64+gzip``, ``url+base64``); ``layers`` is the same as a
    tuple. ``bytes`` is the result. ``kind`` is ``text`` for readable text (then
    ``text`` is set and ``charset`` names how it was read) and otherwise the
    file type found (``pe``, ``zip``, ``pdf``...), with ``text`` None.
    ``truncated`` is True when the result is only the start of the real one:
    the value was longer than ``MAX_INPUT`` or an inflate step hit its ceiling
    or ran out of input.
    """

    __slots__ = ("scheme", "layers", "bytes", "text", "kind", "charset", "truncated")

    def __init__(self, layers, data, verdict, truncated):
        self.layers = tuple(layers)
        self.scheme = "+".join(layers)
        self.bytes = data
        self.text = verdict.text
        self.kind = verdict.kind
        self.charset = verdict.charset
        self.truncated = truncated

    def __repr__(self):
        return "Decoded(%s, %s, %d bytes)" % (self.scheme, self.kind, len(self.bytes))


class _Work:
    """What one decode (or one event's worth of decodes) has spent."""

    def __init__(self):
        self.inflate_left = MAX_EVENT_INFLATE
        self.chars_left = MAX_EVENT_CHARS
        self.truncated = False


# --- reading bytes as text -----------------------------------------------------

def _sniff(raw):
    for kind, magic, shortest in _SIGNATURES:
        if raw.startswith(magic) and len(raw) >= shortest:
            return kind
    return ""


def _is_zlib(raw):
    return (len(raw) >= 6 and raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA))


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


def _read_text(raw, cut):
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


def _verdict(raw, work):
    kind = _sniff(raw)
    if kind and kind not in _PRINTABLE_MAGIC:
        return _Verdict(kind, None, None, True, kind == "gzip")
    read = _read_text(raw, work.truncated)
    if read is not None:
        return _Verdict("text", read[0], read[1], True, True)
    if kind:
        return _Verdict(kind, None, None, True, False)
    return _Verdict("", None, None, False, _is_zlib(raw))


# --- the schemes ---------------------------------------------------------------

def _hex(token, lenient):
    if lenient:
        token = token[:len(token) & ~1]
    if len(token) < MIN_HEX or len(token) % 2 or not _HEX.fullmatch(token):
        return None
    return binascii.unhexlify(token)


def _join_lines(token):
    """One value from a base64 blob wrapped in equal lines (MIME, PEM)."""
    lines = [line.strip() for line in token.splitlines() if line.strip()]
    if len(lines) < 2 or len(lines[0]) < MIN_BASE64:
        return None
    width = len(lines[0])
    if any(len(line) != width for line in lines[:-1]) or len(lines[-1]) > width:
        return None
    return b"".join(lines)


def _base64(token, lenient, minimum=MIN_BASE64):
    if b"\n" in token or b"\r" in token:
        token = _join_lines(token)
        if token is None:
            return None
    if lenient:
        token = token[:len(token) & ~3]
    body = token.rstrip(b"=")
    pad = len(token) - len(body)
    if len(token) < minimum or pad > 2 or (pad and len(token) % 4) or len(body) % 4 == 1:
        return None
    if _B64.fullmatch(body):
        data = body
    elif _B64URL.fullmatch(body):
        data = body.translate(bytes.maketrans(b"-_", b"+/"))
    else:
        return None
    try:
        return binascii.a2b_base64(data + b"=" * (-len(data) % 4))
    except binascii.Error:
        return None


def _url(token):
    """``(bytes, qualifies)``: ``qualifies`` says the escaping is itself a finding."""
    out = unquote_to_bytes(token)
    escapes = (len(token) - len(out)) // 2
    if not escapes:
        return None
    deliberate = _UNNEEDED_ESCAPE.search(token) is not None
    dense = 3 * escapes >= MIN_URL_SHARE * len(token)
    return out, escapes >= MIN_URL_ESCAPES and (dense or deliberate)


def _inflate(raw, wbits, work):
    """The start of the inflated data, at most ``MAX_INFLATED`` bytes, or None."""
    limit = min(MAX_INFLATED, work.inflate_left)
    if limit <= 0:
        work.truncated = True
        return None
    decoder = zlib.decompressobj(wbits)
    try:
        out = decoder.decompress(raw, limit)
    except zlib.error:
        return None
    work.inflate_left -= len(out)
    if not decoder.eof:
        work.truncated = True
    return out or None


def _next_layer(data, inside, work):
    """``(layer, bytes, verdict)`` of the next layer, or None.

    ``inside`` is False for the outermost layer, which is never compressed
    data (a compressed body is undone upstream). A step is taken only if its
    result is final (text or a known file) or can be continued (compressed
    data, readable text that may itself be encoded).
    """
    if inside:
        if data[:3] == b"\x1f\x8b\x08":
            name, wbits = "gzip", 31
        elif _is_zlib(data):
            name, wbits = "zlib", 15
        else:
            name = None
        if name:
            out = _inflate(data, wbits, work)
            if out is None:
                return None
            verdict = _verdict(out, work)
            return (name, out, verdict) if verdict.final or verdict.cont else None
    token = data.strip()
    lenient = False
    if len(token) > MAX_INPUT:
        token, lenient, work.truncated = token[:MAX_INPUT], True, True
    if len(token) < _MIN_VALUE:
        return None
    candidates = []
    if b"%" in token:
        found = _url(token)
        if found is not None:
            candidates.append(("url", found[0], found[1]))
    out = _hex(token, lenient)
    if out is not None:
        candidates.append(("hex", out, True))
    out = _base64(token, lenient)
    if out is not None:
        candidates.append(("base64", out, True))
    carry = None
    for name, out, qualifies in candidates:
        verdict = _verdict(out, work)
        if verdict.final and qualifies:
            return name, out, verdict
        if carry is None and (verdict.final or verdict.cont):
            carry = (name, out, verdict._replace(final=False))
    return carry


def _as_bytes(value):
    if isinstance(value, str):
        value = value[:MAX_INPUT + 1]
        try:
            return value.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            return value.encode("utf-8", "replace")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value[:MAX_INPUT + 1])
    return None


def _decode(raw, work):
    work.truncated = False
    layers, best, current = [], None, raw
    for step in range(MAX_LAYERS):
        taken = _next_layer(current, step > 0, work)
        if taken is None:
            break
        name, current, verdict = taken
        layers.append(name)
        if verdict.final:
            best = (tuple(layers), current, verdict, work.truncated)
    return Decoded(*best) if best is not None else None


def decode(value):
    """``Decoded`` for an encoded ``str`` or bytes-like value, else None.

    None is the answer for anything that is not clearly an encoding of text or
    of a known file type: too short, not in any scheme's alphabet, or decoding
    to noise. It is also the answer for input that is not a string at all.
    """
    raw = _as_bytes(value)
    if raw is None:
        return None
    return _decode(raw, _Work())


# --- events --------------------------------------------------------------------

def _form_pairs(text):
    if not text or _WHITESPACE.search(text):
        return []
    pairs = []
    for segment in text.split("&"):
        if not segment:
            continue
        key, equals, value = segment.partition("=")
        if not equals or not key or len(key) > 128 or value.startswith("="):
            return []
        if len(value) >= _MIN_VALUE:
            pairs.append((key, value))
            if len(pairs) == MAX_VALUES_PER_FIELD:
                break
    return pairs


def _json_pairs(text):
    pairs = []
    for match in _JSON_PAIR.finditer(text):
        key, value = match.groups()
        if len(value) < _MIN_VALUE:
            continue
        if "\\" in value:
            try:
                value = json.loads('"%s"' % value)
            except ValueError:
                pass
        pairs.append((key, value))
        if len(pairs) == MAX_VALUES_PER_FIELD:
            break
    return pairs


def _multipart_pairs(text):
    boundary = text.partition("\n")[0].strip()
    if not 4 <= len(boundary) <= 200:
        return []
    pairs = []
    for part in text.split(boundary)[1:]:
        blank = _BLANK_LINE.search(part)
        if not blank:
            continue
        found = _PART_NAME.search(part[:min(blank.start(), 2048)])
        value = part[blank.end():].strip()
        if found and len(value) >= _MIN_VALUE:
            pairs.append((found.group(1), value))
            if len(pairs) == MAX_VALUES_PER_FIELD:
                break
    return pairs


def _lines(text):
    """The lines of a body that is a list of encoded records."""
    pairs = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if len(line) >= _MIN_VALUE:
            pairs.append(("line %d" % number, line))
            if len(pairs) == MAX_VALUES_PER_FIELD:
                break
    return pairs


def _decode_text(text, work):
    """``(name, value, Decoded)`` for each encoded value in a field's text.

    The values of a form, JSON object or multipart body are tried one by one.
    Any other text is tried whole first, and only when it is not itself
    encoded are its lines.
    """
    text = text.strip()
    if text.startswith(("{", "[")):
        pairs = _json_pairs(text)
    elif text.startswith("--"):
        pairs = _multipart_pairs(text)
    else:
        pairs = _form_pairs(text)
    if not pairs:
        whole = _decode(_as_bytes(text), work)
        if whole is not None:
            return [("", text, whole)]
        pairs = _lines(text) if len(text.splitlines()) > 1 else []
    found = []
    for name, value in pairs:
        decoded = _decode(_as_bytes(value), work)
        if decoded is not None:
            found.append((name, value, decoded))
    return found


def _decode_basic(token):
    """``Decoded`` for the token of ``Basic <token>``, else None.

    The scheme says what the token is: base64 of ``user:password``. That is
    evidence the general rule has to get from length and content, so it may be
    short ("user:pass" is 12 characters) and is accepted when it is printable
    text with a colon after a non-empty user name.
    """
    raw = _base64(token.encode("ascii", "replace"), False, MIN_BASIC)
    if raw is None:
        return None
    for charset in ("utf-8", "latin-1"):
        try:
            text = raw.decode(charset)
        except UnicodeDecodeError:
            continue
        if text.isprintable() and text.find(":") > 0:
            return Decoded(("base64",), raw, _Verdict("text", text, charset, True, False), False)
    return None


def _cookie_pairs(text):
    """``(name, value)`` of each ``name=value`` piece of a Cookie or Set-Cookie
    value; ``[]`` when the text is not one (a bare base64 value ends in ``=``)."""
    pairs = []
    # Repeated Set-Cookie headers arrive joined by ", "; so does an Expires date,
    # whose pieces have no "=" and are skipped.
    for piece in _COOKIE_PIECE.split(text):
        key, equals, value = piece.strip().partition("=")
        if not equals or not key or len(key) > 128 or _WHITESPACE.search(key) or value.startswith("="):
            continue
        value = value.strip('"')
        if len(value) >= _MIN_VALUE:
            pairs.append((key, value))
            if len(pairs) == MAX_VALUES_PER_FIELD:
                break
    return pairs


def _decode_header(text, work):
    """``(name, value, Decoded)`` for each encoded value of a header value.

    A header is read whatever its name, since malware names its own. Its
    value is an authorization (``Scheme token``), a cookie (``a=b; c=d``) or
    one bare value; a token with dots is also read segment by segment, which
    is how a JWT carries its header and payload.
    """
    text = text.strip()
    found = []
    auth = _AUTH_VALUE.fullmatch(text)
    if auth:
        scheme, token = auth.groups()
        if scheme.lower() == "basic":
            decoded = _decode_basic(token)
            if decoded is not None:
                return [(scheme, token, decoded)]
        pairs = [(scheme, token)]
    else:
        pairs = _cookie_pairs(text) or [("", text)]
    for name, value in pairs:
        decoded = _decode(_as_bytes(value), work)
        if decoded is not None:
            found.append((name, value, decoded))
            continue
        if "." not in value or _WHITESPACE.search(value):
            continue
        for index, segment in enumerate(value.split(".", MAX_SEGMENTS)[:MAX_SEGMENTS]):
            decoded = _decode(_as_bytes(segment), work) if len(segment) >= _MIN_VALUE else None
            if decoded is not None:
                found.append(("%s[%d]" % (name, index), segment, decoded))
    return found


def _is_credential(field, name, decoded):
    """Is a decoded value (or might it be) a credential?

    True when any of these holds:
      * it came from an ``Authorization`` or ``Proxy-Authorization`` header;
      * the name it was found under (form key, cookie, header) says secret:
        ``pass``, ``pwd``, ``secret``, ``token``, ``key``, ``auth`` or ``cred``;
      * any line of the text has ``name:value`` shape, the value running to the
        end of the line (spaces allowed), or ``name=value`` / a JSON pair whose
        key says secret, or URL userinfo (``scheme://user:pw@host``);
      * any line is a delimited record (``|``, tab, ``;``, ``,``) with a URL
        field and at least two other fields: the line format of a browser
        credential dump, ``Chrome|https://bank.com|bob|Passw0rd!``.

    **This errs towards True, on purpose.** The flag exists so that a later
    layer can mask what it names: a false mark costs a reader one ``***``, a
    missed mark leaves a password in a report for good. So ``hostname: PC01``
    and ``stolen credentials: admin / hunter2`` are marked as well. What is
    left unmarked is text with no such shape: ``address:port``, a drive path, a
    URL without userinfo, a clock time, JSON without a secret key, prose.
    """
    if field in _CREDENTIAL_HEADERS:
        return True
    header = field.partition(".")[2] if field.startswith(("headers.", "resp_headers.")) else ""
    if _SECRET_NAME.search(name) or _SECRET_NAME.search(header):
        return True
    text = (decoded.text or "")[:MAX_CREDENTIAL_CHARS]
    if _SECRET_PAIR.search(text) or _URL_USERINFO.search(text):
        return True
    for line in text.splitlines()[:MAX_CREDENTIAL_LINES]:
        if _colon_pair(line) or _credential_record(line):
            return True
    return False


def _colon_pair(line):
    """Does a line hold ``name:value`` with something after the colon?

    URLs are cut out first (their colons are not pairs; userinfo is looked for
    separately), as are drive letters, ``ip:port`` and clock times.
    """
    for match in _COLON_PAIR.finditer(_URL_TOKEN.sub(" ", line)):
        left, head = match.groups()
        if not head or not (left[-1].isalnum() or left[-1] in "._-@!$#"):
            continue
        if head.startswith(("\\", "/")) and len(left) == 1:
            continue
        if left.isdigit() and len(left) <= 2 and head[:2].isdigit():
            continue
        if head.isdigit() and len(head) <= 5:
            try:
                ipaddress.ip_address(left)
                continue
            except ValueError:
                pass
        return True
    return False


def _credential_record(line):
    """A delimited line with a URL field and at least two other fields."""
    if "://" not in line and "www." not in line:
        return False
    for delimiter in _RECORD_DELIMITERS:
        fields = [field.strip() for field in line.split(delimiter)]
        if len(fields) < 3:
            continue
        urls = [field for field in fields if _URL_FIELD.fullmatch(field)]
        if urls and sum(1 for field in fields if field) - len(urls) >= 2:
            return True
    return False


def _field_text(value):
    if isinstance(value, str):
        return value[:MAX_INPUT]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_INPUT]).decode("latin-1")
    return None


def _header_fields(prefix, headers):
    if isinstance(headers, dict):
        for name, value in headers.items():
            if isinstance(name, str):
                for one in value if isinstance(value, (list, tuple)) else (value,):
                    yield "%s.%s" % (prefix, name.lower()), one, True


def _fields(event):
    """``(field, value, is_header)`` for each field of an event worth reading."""
    kind = event.get("type")
    if kind == "http":
        yield "query", event.get("query"), False
        yield from _header_fields("headers", event.get("headers"))
        yield "body_text", event.get("body_text"), False
        yield from _header_fields("resp_headers", event.get("resp_headers"))
        yield "resp_text", event.get("resp_text"), False
    elif kind == "websocket":
        messages = event.get("messages")
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                if isinstance(message, dict):
                    yield "messages[%d].text" % index, message.get("text"), False


def _decoded_event(source, field, name, value, decoded):
    text = decoded.text
    return NetEvent(
        "decoded", source.get("ts", 0.0), process=source.get("process", ""),
        pid=source.get("pid"), dest=source.get("dest", ""), port=source.get("port"),
        source=source.get("type"), field=field, name=name,
        scheme=decoded.scheme, layers=list(decoded.layers), kind=decoded.kind,
        charset=decoded.charset,
        text=text[:MAX_EVENT_TEXT] if text is not None else None,
        text_capped=text is not None and len(text) > MAX_EVENT_TEXT,
        size=len(decoded.bytes), sha256=hashlib.sha256(decoded.bytes).hexdigest(),
        preview=render_bytes(decoded.bytes[:PREVIEW_BYTES]) if text is None else "",
        credential=_is_credential(field, name, decoded),
        encoded=value[:ENCODED_SHOWN], encoded_len=len(value), truncated=decoded.truncated)


def decode_event_fields(event):
    """``decoded`` events for the encoded values in an ``http`` or ``websocket``
    event (query, headers, body, response; or WebSocket messages), in field order; an empty list when there is nothing worth reporting.

    Only the text fields named here are read and nothing of the event is
    copied beyond where it came from (time, process, destination), so the
    source event is not changed and no ``Secret`` can travel into the result.
    The walk is bounded: ``MAX_EVENT_CHARS`` of field text, ``MAX_VALUES_PER_FIELD``
    values per field, ``MAX_EVENT_INFLATE`` inflated bytes and
    ``MAX_DECODED_PER_EVENT`` results.
    """
    work = _Work()
    found = []
    for field, raw, is_header in _fields(event):
        text = _field_text(raw)
        if text is None or not text.strip():
            continue
        if work.chars_left <= 0:
            break
        work.chars_left -= len(text)
        for name, value, decoded in (_decode_header if is_header else _decode_text)(text, work):
            found.append(_decoded_event(event, field, name, value, decoded))
            if len(found) == MAX_DECODED_PER_EVENT:
                return found
    return found
