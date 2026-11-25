"""HTTP streams to ``http``, ``download``, ``upload`` and ``websocket`` events.

HTTP is where most malware talks to its operator: the gate URL, the beacon
that repeats every thirty seconds, the form fields of a stolen-credential
POST, the second-stage download. Later phases read these events for beacon
intervals (``ts`` of each request), rules (``method``, ``path``, ``body_text``,
``form_names``), the decoder (``body_text``) and the client fingerprint
(``header_order``, ``ua``). The assumptions this module refuses to make:

  * A stream from a pcap is a whole conversation. It is routinely cut: a lost
    segment ends the stream at the hole, a capture can stop mid-transfer, and
    the retention cap shortens a long one. ``http.client`` and ``email.parser``
    (and dpkt) assume well-formed, complete input and raise or silently invent
    an ending, so the messages are split here, and a damaged stream gives the
    events read before the damage. What is cut is never presented as complete:
    ``request_truncated`` / ``response_truncated`` are True when the message's
    headers or body ended before their declared end (a Content-Length not
    reached, a missing last chunk, a body that runs to the end of a stream
    that was itself cut); ``stream_gaps`` (sizes of the holes) and
    ``stream_capped`` say why, and tell a reader that messages after the
    last one may be missing, which no per-message flag can.
  * A flow is one request. A keep-alive connection carries many, and each
    event takes the time of the packet its request began in (found by
    matching the packets back onto the reassembled stream, so segments
    captured out of order still get the right time). One timestamp per flow
    would make every beacon interval zero.
  * The first sender is the client. A capture that begins with the server's
    response makes the reader guess wrongly (``Flow.client_guessed``); when it
    is a guess, the content decides, and the server address is taken from the
    side that sent the response.
  * Header names have one case. ``header_order`` lists the names as sent, in
    order, duplicates included, because it feeds a fingerprint in which case
    and order are the signal. ``headers`` is keyed by lower-cased name (so it
    survives a round trip through JSON) and answers any case.
  * A body is text. ``body_text`` / ``resp_text`` are set when the retained
    bytes decode as UTF-8 or Latin-1 and look like text; Latin-1 accepts every
    byte, so a body with NULs or many control characters is binary and gets
    None with its size in ``body_bytes`` / ``resp_bytes``. An empty body is
    "" (not None), so the two cases differ.
  * A body fits in memory. Text is retained up to ``MAX_BODY_TEXT`` and
    ``body_capped`` / ``resp_capped`` say when more existed. The sizes are
    always the real ones. Working memory is bounded by the stream cap of
    ``net_flows`` (4 MiB per direction); a download larger than that is
    reported with ``truncated`` and the hash of what was kept.
  * An upgrade is a request. After ``101`` both directions carry WebSocket
    frames, not HTTP. Client frames are masked, lengths may use 16 or 64 bits,
    a message may be fragmented with control frames between its parts, and the
    two directions interleave in time, so messages are listed by when they
    began. A request that asks for an upgrade and was answered with anything
    but 101 is only an HTTP event.
  * A body is what is on the wire. ``Content-Encoding`` gzip, x-gzip and
    deflate (and stacks of them) are undone before the text is decided, with
    the framings servers mislabel (gzip, zlib-wrapped and raw deflate) all
    accepted. A compressed body is a decompression bomb waiting for a tool
    that opens untrusted captures, so inflating stops at ``MAX_INFLATED``, set
    to the text cap because nothing past it would be kept; the decompressor
    itself refuses to produce more, so the output is never allocated, and
    ``body_capped`` / ``resp_capped`` say it was cut. Corrupt or cut
    compressed data is normal in a pcap: the event is kept, the text is
    whatever inflated before the break (None if nothing did),
    ``body_bytes`` / ``resp_bytes`` stay the bytes on the wire, and
    ``body_decode_failed`` / ``resp_decode_failed`` are True. An encoding that
    is not understood (br, zstd) leaves the body as it is; the encoding
    applied or seen is in ``content_encoding`` (response) and
    ``request_encoding``. A ``download`` is the file as the
    receiving application sees it: when an encoding was undone, ``kind``,
    ``sha256`` and ``size`` are those of the inflated bytes and the wire
    bytes' are ``wire_sha256`` / ``wire_size`` (present only when they
    differ); if inflating failed, or no encoding applies, the wire bytes are
    the payload. When inflating stopped at the ceiling only a prefix exists
    and a hash of a prefix identifies nothing, so ``sha256`` and ``size`` are
    None and ``inflate_capped`` is True. An ``upload`` still describes the
    wire bytes.
  * Bytes from a capture are inert. Nothing is executed or opened as a file;
    a download is hashed and its first bytes name its kind.

Only the ``Upgrade``/``101`` exchange is a WebSocket; ``permessage-deflate``
frames are not inflated, so such a message has ``text`` None.

``dest`` is the Host header's name (lower case, no port) and falls back to the
server address; ``port`` is the TCP port. ``content_type`` and
``content_encoding`` are the response's (the response decides whether a
download happened); the request's are ``headers["content-type"]`` and
``request_encoding``.
"""

import codecs
import hashlib
import heapq
import re
import zlib
from bisect import bisect_right
from urllib.parse import parse_qsl, urlsplit

from net_events import NetEvent

MAX_BODY_TEXT = 256 * 1024       # text kept per body or message; the size is still exact
MAX_INFLATED = MAX_BODY_TEXT     # output of one inflate step; nothing past it is kept anyway
MAX_HEAD = 256 * 1024            # a header section longer than this is not read
UPLOAD_MIN = 512                 # a request body above this many bytes is an upload
MAX_WS_FRAMES = 20000            # frames read per direction
MAX_WS_MESSAGES = 5000           # messages kept per event

_MATCH_BUDGET = 256              # searches allowed to place out-of-order segments

_METHODS = frozenset(
    "GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH PROPFIND PROPPATCH "
    "MKCOL COPY MOVE LOCK UNLOCK REPORT SEARCH".split())
_REQUEST_LINE = re.compile(r"([A-Z][A-Z-]*) +(\S+)(?: +HTTP/(\d\.\d))?[ \t]*$")
_STATUS_LINE = re.compile(r"HTTP/(\d\.\d) +(\d{3})(?: +(.*))?$")
_HEAD_END = re.compile(rb"\r?\n\r?\n")
_HEX = re.compile(rb"[0-9a-fA-F]+$")
_DIGITS = re.compile(rb"[0-9]{1,18}$")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_BOUNDARY = re.compile(r'boundary="?([^";]+)"?', re.I)
_PART_NAME = re.compile(rb'(?:^|[;\s])name="([^"]*)"', re.I)

_CODINGS = frozenset(("gzip", "x-gzip", "deflate", "identity"))

_WS_DATA = (0, 1, 2)
_WS_CONTROL = (8, 9, 10)


class Headers(dict):
    """Header values keyed by lower-cased name, readable under any case."""

    def __getitem__(self, name):
        return super().__getitem__(name.lower())

    def get(self, name, default=None):
        return super().get(name.lower() if isinstance(name, str) else name, default)

    def __contains__(self, name):
        return isinstance(name, str) and super().__contains__(name.lower())


def _decode(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _first_line(stream):
    head = bytes(stream[:4096]).split(b"\n", 1)[0].rstrip(b"\r")
    return head.decode("latin-1")


def _request_line(line):
    """``(method, target, version)`` or None. An unknown method needs a version."""
    m = _REQUEST_LINE.match(line)
    if m is None or (m.group(1) not in _METHODS and m.group(3) is None):
        return None
    return m.group(1), m.group(2), m.group(3) or ""


def _is_request(stream):
    return _request_line(_first_line(stream)) is not None


def _is_response(stream):
    return _STATUS_LINE.match(_first_line(stream)) is not None


def looks_like_http(stream):
    """True when the stream begins like an HTTP request or response."""
    return _is_request(stream) or _is_response(stream)


# --- messages -----------------------------------------------------------------

class _Message:
    """One request or response read from a stream."""

    def __init__(self, start):
        self.start = start          # offset of the first byte, for the timestamp
        self.end = start            # offset after the message
        self.method = ""
        self.target = ""
        self.status = None
        self.headers = []           # [(name, value)] in order, original case
        self.body = b""
        self.truncated = False


def _read_head(stream, pos, request):
    """The message whose header section starts at ``pos``, or None if there is none."""
    end = _HEAD_END.search(stream, pos, pos + MAX_HEAD)
    if end is not None:
        raw, body_start, complete = stream[pos:end.start()], end.end(), True
    else:
        raw, body_start, complete = stream[pos:pos + MAX_HEAD], len(stream), False
    lines = raw.split(b"\n")
    if not complete and len(lines) > 1:
        lines.pop()                 # the last line may be cut mid-way
    first = lines[0].rstrip(b"\r").decode("latin-1")
    msg = _Message(pos)
    if request:
        parsed = _request_line(first)
        if parsed is None:
            return None
        msg.method, msg.target = parsed[0], parsed[1]
    else:
        m = _STATUS_LINE.match(first)
        if m is None:
            return None
        msg.status = int(m.group(2))
    for line in lines[1:]:
        line = line.rstrip(b"\r")
        if not line:
            continue
        if line[:1] in (b" ", b"\t") and msg.headers:
            name, value = msg.headers[-1]
            msg.headers[-1] = (name, value + " " + _decode(line).strip())
            continue
        name, sep, value = line.partition(b":")
        name = name.strip()
        if sep and name:
            msg.headers.append((_decode(name), _decode(value).strip()))
    msg.end = body_start
    msg.truncated = not complete
    return msg


def _lookup(headers, name):
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _read_chunked(stream, pos):
    """``(body, position after it, truncated)``. A broken size ends the body."""
    out = []
    size_of = len(stream)
    while True:
        eol = stream.find(b"\n", pos)
        if eol < 0:
            return b"".join(out), size_of, True
        size_text = stream[pos:eol].split(b";")[0].strip()
        if not _HEX.match(size_text):
            return b"".join(out), size_of, True
        size = int(size_text, 16)
        pos = eol + 1
        if size == 0:
            while True:                         # trailers, up to the blank line
                eol = stream.find(b"\n", pos)
                if eol < 0:
                    return b"".join(out), size_of, True
                line = stream[pos:eol].rstrip(b"\r")
                pos = eol + 1
                if not line:
                    return b"".join(out), pos, False
        chunk = stream[pos:pos + size]
        out.append(chunk)
        if len(chunk) < size:
            return b"".join(out), size_of, True
        pos += size
        if stream[pos:pos + 2] == b"\r\n":
            pos += 2
        elif stream[pos:pos + 1] == b"\n":
            pos += 1
        else:       # the stream ended after the chunk, or the chunk is not followed by a line end
            return b"".join(out), size_of, True


def _read_body(stream, pos, msg, no_body, until_close, cut):
    """``(body, position after it, truncated)``."""
    if no_body:
        return b"", pos, False
    encoding = (_lookup(msg.headers, "transfer-encoding") or "").lower()
    if "chunked" in encoding:
        return _read_chunked(stream, pos)
    length = (_lookup(msg.headers, "content-length") or "").encode("latin-1", "replace")
    if _DIGITS.match(length):
        want = int(length)
        body = stream[pos:pos + want]
        return body, pos + len(body), len(body) < want
    if until_close:
        return stream[pos:], len(stream), cut
    return b"", pos, False


def _read_messages(stream, request, cut, methods=()):
    """The messages of one direction, in order, up to the first unreadable byte.

    ``methods`` are the methods of the requests, for a response stream: a
    response to HEAD has no body whatever its headers say. ``cut`` is True when
    the stream itself ended early, so a body that runs to its end is cut too.
    """
    messages = []
    pos = 0
    final = 0
    while True:
        while stream[pos:pos + 1] in (b"\r", b"\n"):
            pos += 1
        if pos >= len(stream):
            break
        msg = _read_head(stream, pos, request)
        if msg is None:
            break
        pos = msg.end
        if msg.truncated:
            if request or not 100 <= msg.status < 200 or msg.status == 101:
                messages.append(msg)
            break
        if request:
            body, pos, msg.truncated = _read_body(stream, pos, msg, False, False, cut)
        else:
            sent = methods[final] if final < len(methods) else ""
            interim = 100 <= msg.status < 200 and msg.status != 101
            tunnel = sent == "CONNECT" and 200 <= msg.status < 300
            no_body = (interim or msg.status in (204, 304) or sent == "HEAD"
                       or tunnel or msg.status == 101)
            body, pos, msg.truncated = _read_body(stream, pos, msg, no_body, True, cut)
            if interim:
                continue
            final += 1
        msg.body, msg.end = body, pos
        messages.append(msg)
        if msg.truncated:
            break
        if request and msg.method == "CONNECT":
            break
        if not request and (msg.status == 101 or tunnel):
            break
    return messages


# --- time ---------------------------------------------------------------------

def _offsets(packets, direction, stream):
    """``(starts, times)``: where each captured segment begins in the stream.

    The segments of ``Flow.packets`` are in arrival order and the stream is in
    sequence order. They agree unless something arrived out of order, was
    repeated or lies beyond a hole; those segments are found in the stream by
    their content (a limited number of searches), and a segment that is not
    in it contributes nothing.
    """
    found = []
    used = set()
    cursor = 0
    budget = _MATCH_BUDGET
    for ts, d, payload in packets:
        n = len(payload)
        if d != direction or not n:
            continue
        pos = cursor if stream[cursor:cursor + n] == payload else -1
        if pos < 0 and budget > 0:
            budget -= 1
            pos = stream.find(payload)
            while pos in used:
                pos = stream.find(payload, pos + 1)
        if pos < 0:
            continue
        used.add(pos)
        found.append((pos, ts))
        cursor = max(cursor, pos + n)
    found.sort(key=lambda item: item[0])
    return [p for p, _t in found], [t for _p, t in found]


def _time_at(index, offset, default):
    starts, times = index
    i = bisect_right(starts, offset) - 1
    return times[i] if i >= 0 else default


# --- bodies -------------------------------------------------------------------

def _text(body):
    """``(text or None, capped)`` for a body; "" when empty, None when binary."""
    if not body:
        return "", False
    capped = len(body) > MAX_BODY_TEXT
    chunk = body[:MAX_BODY_TEXT]
    try:
        # a character cut by the cap is not an error
        text = codecs.getincrementaldecoder("utf-8")().decode(chunk, final=not capped)
    except UnicodeDecodeError:
        text = chunk.decode("latin-1")
    if "\x00" in text or len(_CONTROL.findall(text)) * 20 > len(text):
        return None, capped
    return text, capped


def _inflate_stream(data, wbits, limit):
    """``(output, capped, failed)`` for one attempt at one framing of ``data``.

    The output ceiling is enforced by the decompressor itself (``max_length``),
    so a bomb never allocates more than ``limit`` + 1 bytes. A stream that ends
    before its end marker, or breaks, is ``failed`` and keeps what it produced.
    """
    out = []
    total = 0
    members = 0
    while data:
        decoder = zlib.decompressobj(wbits)
        try:
            chunk = decoder.decompress(data, limit + 1 - total)
        except zlib.error:
            # garbage after a complete member (padding) is not a failure
            return b"".join(out), False, members == 0
        out.append(chunk)
        total += len(chunk)
        if total > limit:
            return b"".join(out)[:limit], True, False
        if not decoder.eof:
            return b"".join(out), False, True
        members += 1
        data = decoder.unused_data if wbits > 0 else b""
    return b"".join(out), False, False


def _inflate(data, limit):
    """Undo one gzip or deflate layer: ``(output, capped, failed)``.

    Servers label gzip, zlib-wrapped deflate and raw deflate with each other's
    names, so the zlib/gzip header is detected, and raw deflate is tried when
    that yields nothing.
    """
    if not data:
        return b"", False, False
    out, capped, failed = _inflate_stream(data, zlib.MAX_WBITS | 32, limit)
    if failed and not out:
        out, capped, failed = _inflate_stream(data, -zlib.MAX_WBITS, limit)
    return out, capped, failed


def _decoded(body, encoding):
    """``(data, capped, failed, applied)``: the body with its content encoding undone.

    ``applied`` is True when an inflate was attempted. ``capped`` means more output existed than ``MAX_INFLATED``; ``failed`` that
    a supported encoding could not be undone completely, in which case ``data``
    is what came out before it broke. An encoding that is not understood leaves
    the body as it is.
    """
    codings = [c.strip() for c in encoding.split(",") if c.strip()]
    if not body or not codings or any(c not in _CODINGS for c in codings):
        return body, False, False, False
    data, capped, failed, applied = body, False, False, False
    for coding in reversed(codings):
        if coding == "identity":
            continue
        applied = True
        data, capped, failed = _inflate(data, MAX_INFLATED)
        if capped or failed:
            break
    return data, capped, failed, applied


def _body_text(body, encoding):
    """``(text or None, capped, decode_failed, decoded)`` of a message body.

    ``decoded`` is what ``_decoded`` returned. A body that could not be decoded
    at all has no text, however empty its remains are.
    """
    decoded = _decoded(body, encoding)
    data, inflate_capped, failed, _applied = decoded
    text, capped = _text(data)
    if failed and not data:
        text = None
    return text, capped or inflate_capped, failed, decoded


def _payload(wire, decoded):
    """``(kind, fields)`` of a downloaded body, as the receiving application sees it.

    When an encoding was undone completely the file is the inflated bytes, and
    the wire bytes' hash and size are added beside it. When inflating stopped
    at the ceiling only a prefix of the file exists, and a hash of a prefix
    identifies nothing, so ``sha256`` and ``size`` are None (the kind, read
    from the start, is still known) and ``inflate_capped`` says why. When
    inflating failed, or no encoding applies, the wire bytes are the payload.
    """
    data, capped, failed, applied = decoded
    wire_sha = hashlib.sha256(wire).hexdigest()
    if not applied or failed:
        return _kind(wire), {"sha256": wire_sha, "size": len(wire), "inflate_capped": False}
    kind = _kind(data)
    if capped:
        return kind, {"sha256": None, "size": None, "inflate_capped": True,
                      "wire_sha256": wire_sha, "wire_size": len(wire)}
    fields = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
              "inflate_capped": False}
    if fields["sha256"] != wire_sha:
        fields["wire_sha256"] = wire_sha
    if fields["size"] != len(wire):
        fields["wire_size"] = len(wire)
    return kind, fields


def _kind(body):
    if body[:2] == b"MZ":
        return "pe"
    if body[:4] == b"\x7fELF":
        return "elf"
    if body[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if body[:4] == b"%PDF":
        return "pdf"
    return ""


def _form_names(content_type, body):
    ctype = content_type.lower()
    names = []
    if "application/x-www-form-urlencoded" in ctype:
        text = _text(body)[0]
        if text:
            names = [k for k, _v in parse_qsl(text, keep_blank_values=True) if k]
    elif "multipart/form-data" in ctype:
        m = _BOUNDARY.search(content_type)
        if m:
            marker = b"--" + m.group(1).encode("latin-1", "replace")
            for part in body[:MAX_BODY_TEXT].split(marker)[1:]:
                head = re.split(rb"\r?\n\r?\n", part, 1)[0]
                found = _PART_NAME.search(head)
                if found:
                    names.append(_decode(found.group(1)))
    return list(dict.fromkeys(names))


# --- request fields -----------------------------------------------------------

def _headers_of(pairs):
    headers = Headers()
    order = []
    for name, value in pairs:
        order.append(name)
        key = name.lower()
        old = dict.get(headers, key)
        headers[key] = value if old is None else old + ", " + value
    return headers, order


def _host_of(authority):
    """The name in a Host header: lower case, no port, no brackets."""
    if authority.startswith("["):
        return authority[1:].split("]", 1)[0].lower()
    name, sep, port = authority.rpartition(":")
    return (name if sep and port.isdigit() else authority).lower()


def _split_target(target):
    """``(path, query, absolute)`` of a request target."""
    if target.startswith("/"):
        path, _q, query = target.partition("?")
        return path, query, False
    if "://" in target[:12]:
        try:
            parts = urlsplit(target)
        except ValueError:
            return target, "", False
        return parts.path or "/", parts.query, True
    return target, "", False


class _Context:
    """What is known about the flow as a whole, in client/server terms."""

    def __init__(self, flow, swapped):
        if swapped:
            self.server, self.port = flow.src, flow.sport
            self.client_dir, self.server_dir = "s", "c"
            client_gaps, server_gaps = flow.server_gaps, flow.client_gaps
            self.client_stream, self.server_stream = flow.server_stream(), flow.client_stream()
        else:
            self.server, self.port = flow.dst, flow.dport
            self.client_dir, self.server_dir = "c", "s"
            client_gaps, server_gaps = flow.client_gaps, flow.server_gaps
            self.client_stream, self.server_stream = flow.client_stream(), flow.server_stream()
        self.gaps = list(client_gaps) + list(server_gaps)
        self.capped = bool(flow.capped)
        self.client_cut = bool(client_gaps) or self.capped
        self.server_cut = bool(server_gaps) or self.capped
        self.first_ts = flow.first_ts
        self.client_time = _offsets(flow.packets, self.client_dir, self.client_stream)
        self.server_time = _offsets(flow.packets, self.server_dir, self.server_stream)


class _Origin:
    """Where a request went: the fields every event of one exchange shares."""

    def __init__(self, ctx, req):
        self.method = req.method if req else ""
        self.headers, self.order = _headers_of(req.headers if req else ())
        target = req.target if req else ""
        self.path, self.query, absolute = _split_target(target) if req else ("", "", False)
        authority = self.headers.get("host", "").lower()
        name = _host_of(authority) if authority else ""
        if not name and absolute:
            try:
                name = (urlsplit(target).hostname or "").lower()
            except ValueError:
                name = ""
        self.dest = name or ctx.server
        if not req:
            self.url = ""
        elif absolute:
            self.url = target
        elif target.startswith("/"):
            self.url = "http://" + (authority or ctx.server) + target
        else:
            self.url = target
        self.port = ctx.port


# --- websocket ----------------------------------------------------------------

def _unmask(data, key):
    n = len(data)
    if not n:
        return b""
    stream_key = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream_key, "big")).to_bytes(n, "big")


def _ws_parse(stream, limit, base=0):
    """``(frames, capped, truncated)`` for a stream that starts at a frame."""
    frames = []
    pos = 0
    total = len(stream)
    while pos < total:
        if len(frames) >= limit:
            return frames, True, False
        if total - pos < 2:
            return frames, False, True
        b0, b1 = stream[pos], stream[pos + 1]
        opcode = b0 & 0x0F
        if opcode not in _WS_DATA and opcode not in _WS_CONTROL:
            return frames, False, True          # reserved opcode: not frames
        size = b1 & 0x7F
        head = 2
        if size == 126:
            head = 4
        elif size == 127:
            head = 10
        if total - pos < head:
            return frames, False, True
        if head == 4:
            size = int.from_bytes(stream[pos + 2:pos + 4], "big")
        elif head == 10:
            size = int.from_bytes(stream[pos + 2:pos + 10], "big")
            if size >> 63:
                return frames, False, True
        masked = bool(b1 & 0x80)
        key = b""
        if masked:
            if total - pos < head + 4:
                return frames, False, True
            key = stream[pos + head:pos + head + 4]
            head += 4
        data = stream[pos + head:pos + head + size]
        cut = len(data) < size
        data = data[:MAX_BODY_TEXT]
        frames.append({
            "opcode": opcode, "fin": bool(b0 & 0x80),
            "payload": _unmask(data, key) if masked else bytes(data),
            "size": size, "truncated": cut, "offset": base + pos,
        })
        if cut:
            return frames, False, True
        pos += head + size
    return frames, False, False


def ws_frames(stream):
    """The WebSocket frames of a stream that begins at a frame boundary.

    Each frame is a dict: ``opcode``, ``fin``, ``payload`` (unmasked, at most
    ``MAX_BODY_TEXT`` bytes), ``size`` (the length the frame declares),
    ``truncated`` (the stream ended inside it) and ``offset`` (where it begins
    in ``stream``). Reading stops at the first thing that is not a frame.
    """
    return _ws_parse(stream, MAX_WS_FRAMES)[0]


def _ws_messages(frames, direction, index, default):
    """Data messages of one direction; control frames and fragments are folded."""
    messages = []
    cur = None
    for f in frames:
        if f["opcode"] in _WS_CONTROL:
            continue
        if f["opcode"] == 0 and cur is not None:
            if len(cur["data"]) < MAX_BODY_TEXT:
                cur["data"] += f["payload"][:MAX_BODY_TEXT - len(cur["data"])]
            cur["size"] += f["size"]
            cur["truncated"] = cur["truncated"] or f["truncated"]
        else:
            cur = {"data": bytearray(f["payload"]), "size": f["size"],
                   "truncated": f["truncated"], "ts": _time_at(index, f["offset"], default)}
        if f["fin"] or f["truncated"]:
            messages.append(cur)
            cur = None
    if cur is not None:
        cur["truncated"] = True
        messages.append(cur)
    return [{"direction": direction, "text": _text(bytes(m["data"]))[0], "size": m["size"],
             "ts": m["ts"], "truncated": m["truncated"]} for m in messages]


def _websocket_event(ctx, origin, req, resp, ts):
    cframes, ccapped, ctrunc = _ws_parse(ctx.client_stream[req.end:], MAX_WS_FRAMES, req.end)
    sframes, scapped, strunc = _ws_parse(ctx.server_stream[resp.end:], MAX_WS_FRAMES, resp.end)
    mine = _ws_messages(cframes, "c", ctx.client_time, ts)
    theirs = _ws_messages(sframes, "s", ctx.server_time, ts)
    merged = list(heapq.merge(mine, theirs, key=lambda m: m["ts"]))
    capped = ccapped or scapped or len(merged) > MAX_WS_MESSAGES
    return NetEvent(
        "websocket", ts, dest=origin.dest, port=origin.port, url=origin.url,
        path=origin.path, messages=merged[:MAX_WS_MESSAGES], messages_capped=capped,
        truncated=ctrunc or strunc or ctx.client_cut or ctx.server_cut,
        stream_gaps=list(ctx.gaps), stream_capped=ctx.capped)


# --- events -------------------------------------------------------------------

def _is_upgrade(req):
    return "websocket" in (_lookup(req.headers, "upgrade") or "").lower()


def _exchange_events(ctx, req, resp):
    origin = _Origin(ctx, req)
    req_ts = _time_at(ctx.client_time, req.start, ctx.first_ts) if req else None
    resp_ts = _time_at(ctx.server_time, resp.start, ctx.first_ts) if resp else None
    ts = req_ts if req else resp_ts
    resp_headers = _headers_of(resp.headers if resp else ())[0]
    body = req.body if req else b""
    reply = resp.body if resp else b""
    ctype = resp_headers.get("content-type", "")
    request_encoding = origin.headers.get("content-encoding", "").strip().lower()
    response_encoding = resp_headers.get("content-encoding", "").strip().lower()
    body_text, body_capped, body_failed, decoded = _body_text(body, request_encoding)
    data = decoded[0]
    resp_text, resp_capped, resp_failed, resp_decoded = _body_text(reply, response_encoding)
    http = NetEvent(
        "http", ts, dest=origin.dest, port=origin.port,
        method=origin.method, url=origin.url, path=origin.path, query=origin.query,
        ua=origin.headers.get("user-agent", ""), headers=origin.headers,
        header_order=origin.order,
        body_text=body_text, body_bytes=len(body), body_capped=body_capped,
        body_decode_failed=body_failed, request_encoding=request_encoding,
        form_names=_form_names(origin.headers.get("content-type", ""), data) if req else [],
        status=resp.status if resp else None,
        resp_text=resp_text, resp_bytes=len(reply), resp_capped=resp_capped,
        resp_decode_failed=resp_failed, content_type=ctype,
        content_encoding=response_encoding,
        request_truncated=bool(req and req.truncated),
        response_truncated=bool(resp and resp.truncated),
        stream_gaps=list(ctx.gaps), stream_capped=ctx.capped)
    events = [http]
    if len(body) > UPLOAD_MIN:
        events.append(NetEvent(
            "upload", req_ts, dest=origin.dest, port=origin.port, method=origin.method,
            url=origin.url, path=origin.path, size=len(body),
            sha256=hashlib.sha256(body).hexdigest(), kind=_kind(body),
            content_type=origin.headers.get("content-type", ""), truncated=req.truncated))
    if reply:
        kind, identity = _payload(reply, resp_decoded)
        if kind:
            events.append(NetEvent(
                "download", resp_ts, dest=origin.dest, port=origin.port, url=origin.url,
                path=origin.path, kind=kind, content_type=ctype,
                content_encoding=response_encoding, truncated=resp.truncated, **identity))
    if req and resp and resp.status == 101 and _is_upgrade(req):
        events.append(_websocket_event(ctx, origin, req, resp, req_ts))
    return events


def _reversed(client, server):
    """Is the stream taken for the client's really the server's?"""
    return not _is_request(client) and (_is_response(client) or _is_request(server))


def events_from_flow(flow):
    """``http`` events of a TCP flow, with ``download``, ``upload`` and
    ``websocket`` events beside the exchange they belong to. A flow that does
    not carry HTTP gives an empty list."""
    if flow.proto != "tcp":
        return []
    client, server = flow.client_stream(), flow.server_stream()
    if not looks_like_http(client) and not looks_like_http(server):
        return []
    ctx = _Context(flow, bool(flow.client_guessed) and _reversed(client, server))
    requests = _read_messages(ctx.client_stream, True, ctx.client_cut)
    responses = _read_messages(ctx.server_stream, False, ctx.server_cut,
                               [r.method for r in requests])
    events = []
    for i in range(max(len(requests), len(responses))):
        req = requests[i] if i < len(requests) else None
        resp = responses[i] if i < len(responses) else None
        exchange = _exchange_events(ctx, req, resp)
        events.extend(exchange)
        if exchange[-1]["type"] == "websocket":
            break           # what follows an upgrade is not HTTP
    return events
