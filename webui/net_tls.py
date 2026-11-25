"""TLS handshakes to ``tls`` events, with JA3 and JA4 fingerprints.

When a client refuses the analysis environment's certificate or pins its own,
nothing after the handshake is readable, and the server name it asked for and
the shape of its ClientHello are all that is left of the connection. A later
phase builds a fingerprint database on ``ja3`` / ``ja4`` to recognise a sample
as behaving like an earlier run, and rules read ``dest``. So these strings have
to come out the same every time the same client is seen. The assumptions this
module refuses to make:

  * A handshake is well-formed and whole. It is read from a capture: a hello
    may be cut by a lost segment or the end of the capture, split over several
    TLS records, or hostile. ``dpkt`` assumes complete input and raises or
    mangles otherwise, so the records and the hello are read here, by hand.
    Every length in the file (a record, a handshake message, a cipher list, an
    extension, a name) is checked against the bytes that are actually there
    before it is used, every loop consumes at least one byte, and the amount
    read is capped (``MAX_RECORDS``, ``MAX_HANDSHAKE``, ``MAX_HELLO``), so a
    field that claims megabytes costs nothing and a record chain that never
    ends is cut short. A hello that is cut or inconsistent gives no event at
    all: a fingerprint of half a hello is not the client's, and would put the
    same client into two database entries.
  * Two sightings of one client have the same fields. Chrome and others put
    GREASE values (``0x0a0a``, ``0x1a1a`` ... ``0xfafa``) at random places in
    the cipher, extension and group lists, so a fingerprint that kept them
    would change at every run. They are removed before anything is counted,
    hashed or reported (``ciphers`` and ``extensions`` are listed without
    them). Clients that shuffle their extension order (recent Chrome) still
    change their JA3; JA4 sorts exactly for that reason.
  * The TLS version is the number in the record. JA3 uses the version of the
    ClientHello message, which stays 1.2 for a TLS 1.3 client; JA4 uses the
    highest version in ``supported_versions`` and falls back to the message's.
    ``version`` in the event is the second reading, as text.
  * There is always a server name. A client that connects to an address (or
    sends no SNI) has none: ``sni`` is "" and ``dest`` is the server's
    address, as for HTTP without a Host. JA4 says it too (``i`` instead of
    ``d``). When there is one, ``dest`` is that name, not the address, like
    the queried name rather than the resolver in the DNS events.
  * The certificate is in the stream. For TLS 1.2 and older the server sends
    it in clear and the leaf is read with ``cryptography.x509``; with TLS 1.3
    it is encrypted, and a chain in a capture is often incomplete or damaged.
    A missing or unreadable certificate leaves the event intact with the
    ``cert_*`` fields empty and ``self_signed`` False; ``stream_gaps`` and
    ``stream_capped`` say when it is missing because the capture was cut.
    ``self_signed`` is "subject equals issuer", the sign that matters here; no
    signature is verified.
  * The first sender is the client. A capture that starts with the server's
    flight makes the reader guess wrongly (``Flow.client_guessed``); then the
    side that actually begins with a ClientHello is the client.
  * A flow is one handshake. The first ClientHello is the event; the second
    one after a HelloRetryRequest is the same connection.

Only a TCP stream that begins with a TLS handshake record is read: SSLv2
hellos, DTLS, QUIC and STARTTLS upgrades inside another protocol are not.
Nothing from a capture is executed or opened as a file; a certificate is only
parsed.
"""

import hashlib
from datetime import timezone

from cryptography import x509

from net_events import NetEvent

MAX_RECORD = 1 << 14            # TLS plaintext record limit; a longer one is not TLS
MAX_RECORDS = 256               # records read per direction
MAX_HANDSHAKE = 256 * 1024      # handshake bytes gathered per direction
MAX_HELLO = 64 * 1024           # a ClientHello larger than this is not read
MAX_NAME = 255                  # longest server name kept

_HANDSHAKE = 22
_CLIENT_HELLO = 1
_CERTIFICATE = 11

_EXT_SNI = 0
_EXT_GROUPS = 10
_EXT_POINTS = 11
_EXT_SIGNATURES = 13
_EXT_ALPN = 16
_EXT_VERSIONS = 43

_VERSION_NAMES = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1",
                  0x0301: "TLS 1.0", 0x0300: "SSL 3.0"}
_JA4_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                 0x0300: "s3", 0x0002: "s2"}

_NO_HASH = "000000000000"


class _Malformed(Exception):
    """A length in the hello does not agree with the bytes that are there."""


def is_grease(value):
    """``0x?a?a`` with both bytes equal: the values a client adds to stay compatible."""
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def _without_grease(values):
    return [v for v in values if not is_grease(v)]


# --- records ------------------------------------------------------------------

def _handshake_bytes(stream):
    """The handshake messages' bytes from the TLS records at the start of ``stream``.

    Records are read while they are handshake records; the first record of any
    other kind (change cipher spec, application data) ends the readable part,
    because what follows is encrypted. A last record cut by the end of the
    stream contributes the bytes that exist.
    """
    out = bytearray()
    pos = 0
    total = len(stream)
    for _ in range(MAX_RECORDS):
        if pos + 5 > total:
            break
        kind, major, minor = stream[pos], stream[pos + 1], stream[pos + 2]
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        if kind != _HANDSHAKE or major != 3 or minor > 4 or length > MAX_RECORD:
            break
        room = MAX_HANDSHAKE - len(out)
        if room <= 0:
            break
        body = stream[pos + 5:pos + 5 + length]
        out += body[:room]
        if len(body) < length:
            break
        pos += 5 + length
    return bytes(out)


def _messages(data):
    """``(type, body)`` of each complete handshake message in ``data``."""
    pos = 0
    while pos + 4 <= len(data):
        size = int.from_bytes(data[pos + 1:pos + 4], "big")
        end = pos + 4 + size
        if end > len(data):
            return
        yield data[pos], data[pos + 4:end]
        pos = end


# --- the ClientHello ----------------------------------------------------------

class _Cursor:
    """Sequential reads that cannot run past the end of the data."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        end = self.pos + n
        if end > len(self.data):
            raise _Malformed()
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def number(self, n):
        return int.from_bytes(self.take(n), "big")

    @property
    def left(self):
        return len(self.data) - self.pos


def _numbers(data, prefix, width):
    """The ``width``-byte numbers of a length-prefixed list.

    A prefix that claims more than there is reads what there is, and a
    trailing partial number is ignored, so the answer depends only on the bytes.
    """
    if len(data) < prefix:
        return []
    size = min(int.from_bytes(data[:prefix], "big"), len(data) - prefix)
    body = data[prefix:prefix + size]
    return [int.from_bytes(body[i:i + width], "big")
            for i in range(0, len(body) - width + 1, width)]


def _name(data):
    """The first host name of a server_name extension, or None."""
    if len(data) < 2:
        return None
    body = data[2:2 + int.from_bytes(data[:2], "big")]
    pos = 0
    while pos + 3 <= len(body):
        kind = body[pos]
        size = int.from_bytes(body[pos + 1:pos + 3], "big")
        value = body[pos + 3:pos + 3 + size]
        if kind == 0:
            return value[:MAX_NAME].decode("ascii", "backslashreplace").lower()
        pos += 3 + size
    return None


def _protocols(data):
    """The protocol names of an ALPN extension."""
    if len(data) < 2:
        return []
    body = data[2:2 + int.from_bytes(data[:2], "big")]
    names = []
    pos = 0
    while pos < len(body):
        size = body[pos]
        names.append(body[pos + 1:pos + 1 + size])
        pos += 1 + size
    return [n.decode("latin-1") for n in names]


class ClientHello:
    """The fields of a ClientHello that a fingerprint or a rule reads.

    Lists are in the order the client sent them and still hold GREASE values;
    ``ja3``, ``ja4`` and the event drop them.
    """

    def __init__(self):
        self.version = 0
        self.ciphers = []
        self.extensions = []
        self.groups = []
        self.point_formats = []
        self.signatures = []
        self.versions = []
        self.alpn = []
        self.sni = None             # None: no server_name extension

    @property
    def effective_version(self):
        """The highest version offered, as ``supported_versions`` says if it is there."""
        offered = _without_grease(self.versions)
        return max(offered) if offered else self.version


def _read_hello(body):
    cur = _Cursor(body)
    hello = ClientHello()
    hello.version = cur.number(2)
    cur.take(32)                                    # random
    cur.take(cur.number(1))                         # session id
    suites = cur.take(cur.number(2))
    if len(suites) % 2:
        raise _Malformed()
    hello.ciphers = [int.from_bytes(suites[i:i + 2], "big") for i in range(0, len(suites), 2)]
    cur.take(cur.number(1))                         # compression methods
    if not cur.left:
        return hello                                # a hello without extensions
    block = _Cursor(cur.take(cur.number(2)))
    seen = set()
    while block.left:
        kind = block.number(2)
        data = block.take(block.number(2))
        hello.extensions.append(kind)
        if kind in seen:
            continue
        seen.add(kind)
        if kind == _EXT_SNI:
            hello.sni = _name(data) or ""
        elif kind == _EXT_GROUPS:
            hello.groups = _numbers(data, 2, 2)
        elif kind == _EXT_POINTS:
            hello.point_formats = _numbers(data, 1, 1)
        elif kind == _EXT_SIGNATURES:
            hello.signatures = _numbers(data, 2, 2)
        elif kind == _EXT_VERSIONS:
            hello.versions = _numbers(data, 1, 2)
        elif kind == _EXT_ALPN:
            hello.alpn = _protocols(data)
    return hello


def parse_client_hello(stream):
    """The first ClientHello at the start of ``stream``, or None.

    None means there is no complete, consistent hello: the stream is not TLS,
    the hello is cut (or spread over a hole), or one of its lengths contradicts
    the bytes around it.
    """
    for kind, body in _messages(_handshake_bytes(stream)):
        if kind != _CLIENT_HELLO or len(body) > MAX_HELLO:
            return None
        try:
            return _read_hello(body)
        except _Malformed:
            return None
    return None


# --- fingerprints -------------------------------------------------------------

def ja3(hello):
    """The JA3 string: ``version,ciphers,extensions,groups,point formats``.

    Values are decimal and joined with ``-``, GREASE is removed, and an empty
    field stays empty. Its MD5 is the ``ja3_hash`` of the event.
    """
    fields = [
        [hello.version],
        _without_grease(hello.ciphers),
        _without_grease(hello.extensions),
        _without_grease(hello.groups),
        hello.point_formats,
    ]
    return ",".join("-".join(str(v) for v in field) for field in fields)


def ja3_hash(hello):
    return hashlib.md5(ja3(hello).encode("ascii"), usedforsecurity=False).hexdigest()


def _digest12(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _alpn_code(protocols):
    """First and last character of the first protocol, as JA4 writes it."""
    first = protocols[0].encode("latin-1") if protocols else b""
    if not first:
        return "00"
    if all(b < 128 and chr(b).isalnum() for b in (first[0], first[-1])):
        return chr(first[0]) + chr(first[-1])
    hexed = first.hex()
    return hexed[0] + hexed[-1]


def ja4(hello):
    """The JA4 string ``t<ver><sni><nciphers><nextensions><alpn>_<hash>_<hash>``.

    ``sni`` is ``d`` when the hello has a server_name extension and ``i`` when
    it has none. The counts are two digits, at most 99, GREASE excluded and
    SNI and ALPN included. The first hash is over the sorted cipher list; the
    second over the sorted extension types without SNI and ALPN, followed by
    the signature algorithms in the order sent. Sorting makes both
    independent of the order a client shuffles its lists into.
    """
    ciphers = _without_grease(hello.ciphers)
    extensions = _without_grease(hello.extensions)
    signatures = _without_grease(hello.signatures)
    version = _JA4_VERSIONS.get(hello.effective_version, "00")
    head = "t%s%s%02d%02d%s" % (
        version, "i" if hello.sni is None else "d",
        min(len(ciphers), 99), min(len(extensions), 99), _alpn_code(hello.alpn))
    cipher_part = (_digest12(",".join("%04x" % c for c in sorted(ciphers)))
                   if ciphers else _NO_HASH)
    kept = sorted(e for e in extensions if e not in (_EXT_SNI, _EXT_ALPN))
    text = ",".join("%04x" % e for e in kept)
    if signatures:
        text += "_" + ",".join("%04x" % s for s in signatures)
    extension_part = _digest12(text) if kept else _NO_HASH
    return "%s_%s_%s" % (head, cipher_part, extension_part)


# --- the server's certificate -------------------------------------------------

def _leaf_der(body):
    """The first certificate of a Certificate message, or b""."""
    cur = _Cursor(body)
    try:
        cur.take(3)                                 # length of the whole list
        return cur.take(cur.number(3))
    except _Malformed:
        return b""


def _certificate(server_stream):
    """``(subject, issuer, not_after, self_signed)``; empty when there is no readable leaf."""
    empty = ("", "", "", False)
    for kind, body in _messages(_handshake_bytes(server_stream)):
        if kind != _CERTIFICATE:
            continue
        der = _leaf_der(body)
        if not der:
            return empty
        try:
            cert = x509.load_der_x509_certificate(der)
            ends = getattr(cert, "not_valid_after_utc", None)
            if ends is None:
                ends = cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_after = ends.astimezone(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            return (cert.subject.rfc4514_string(), cert.issuer.rfc4514_string(),
                    not_after, cert.subject == cert.issuer)
        except Exception:
            # a certificate from a capture is untrusted and often damaged;
            # whatever way it fails, the handshake is still reported
            return empty
    return empty


# --- events -------------------------------------------------------------------

def _first_time(flow, direction, default):
    for ts, d, payload in flow.packets:
        if d == direction and payload:
            return ts
    return default


def events_from_flow(flow):
    """The ``tls`` event of a TCP flow, as a list; empty when the flow holds no
    complete ClientHello."""
    if flow.proto != "tcp":
        return []
    client, server = flow.client_stream(), flow.server_stream()
    hello = parse_client_hello(client)
    swapped = False
    if hello is None and flow.client_guessed:
        hello = parse_client_hello(server)
        swapped = hello is not None
    if hello is None:
        return []
    if swapped:
        client_dir, address, port = "s", flow.src, flow.sport
        gaps = list(flow.server_gaps) + list(flow.client_gaps)
        reply = client
    else:
        client_dir, address, port = "c", flow.dst, flow.dport
        gaps = list(flow.client_gaps) + list(flow.server_gaps)
        reply = server
    subject, issuer, not_after, self_signed = _certificate(reply)
    sni = hello.sni or ""
    return [NetEvent(
        "tls", _first_time(flow, client_dir, flow.first_ts), dest=sni or address, port=port,
        sni=sni, version=_VERSION_NAMES.get(hello.effective_version,
                                            "0x%04x" % hello.effective_version),
        ciphers=_without_grease(hello.ciphers), extensions=_without_grease(hello.extensions),
        alpn=list(hello.alpn), ja3=ja3(hello), ja3_hash=ja3_hash(hello), ja4=ja4(hello),
        cert_subject=subject, cert_issuer=issuer, cert_not_after=not_after,
        self_signed=self_signed, stream_gaps=gaps, stream_capped=bool(flow.capped))]
