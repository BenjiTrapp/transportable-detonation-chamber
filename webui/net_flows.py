"""Read a pcap into flows and reassembled TCP streams.

Every network parser downstream (DNS, HTTP, TLS, FTP/SMTP, raw) consumes the
flows built here, so a mistake in this module corrupts all of them. The
assumptions this module refuses to make:

  * Packets do not arrive in stream order and do not arrive once. Segments are
    placed by sequence number, a repeated segment is dropped, and an overlap
    contributes only the bytes that are new. Sequence numbers are compared
    modulo 2**32, because a stream that crosses the wrap would otherwise be
    ordered backwards.
  * A missing segment is not zeros and not a reason to jump ahead. Bytes that
    were never captured are never invented: the stream ends at the first gap
    and the size of every hole is recorded in ``gaps``. A parser that sees a
    short stream knows it is short; a parser fed padding believes it.
  * The first packet seen is not always the client. A capture that starts after
    the SYN begins with a SYN/ACK or with data, and a source port reused after
    a close is a new connection, not more of the old one.
  * IP fragments are not TCP segments. Only the first fragment carries a
    transport header, and joining the rest is a separate job, so none are used.
  * A pcap is not trustworthy input. A cut file, a file that is not a pcap and
    a malformed frame all come back as a ``PcapResult`` with a reason in
    ``note``; nothing a capture contains raises out of ``read_pcap``, and none
    of its bytes is executed or opened as a file.
  * A capture is not small. Retained payload is bounded per direction, per
    capture and in flow count; whatever is dropped is flagged (``Flow.capped``,
    ``PcapResult.note``) instead of silently shortening a stream.

Both classic pcap (either byte order, microsecond or nanosecond timestamps) and
pcapng are read, told apart by the file's magic bytes rather than its name.
pcapng gets its own block reader instead of dpkt's: dpkt's reads the link type
and timestamp resolution of the first interface only, applies them to every
packet, and cannot tell a cut block from a short one, so a capture with a
second interface would be decoded with the wrong clock or the wrong link layer.
Here each packet carries the link type and resolution of its own interface.

Two inherent guesses are visible in the output rather than hidden. A capture
that starts mid-connection has no SYN, so the first sender is taken as the
client (``Flow.client_guessed``). UDP has no connection at all and the same rule
applies, so a UDP flow is always a guess.
"""

import struct

import dpkt

# Retention limits. A 4 MiB direction holds the headers, handshakes and
# commands every parser needs and the opening of a payload transfer; the
# assembled stream and the per-message list share the payload bytes, so the
# worst case for a whole capture is roughly twice MAX_TOTAL_BYTES.
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_SEGMENTS = 50000
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FLOWS = 50000

_MAX_RECORD = 1 << 24           # larger than any real frame: the header is corrupt
_MASK32 = 0xFFFFFFFF

_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 10 ** 6),
    b"\xa1\xb2\xc3\xd4": (">", 10 ** 6),
    b"\x4d\x3c\xb2\xa1": ("<", 10 ** 9),
    b"\xa1\xb2\x3c\x4d": (">", 10 ** 9),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"       # the section header block's type
_NG_BOM = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}
_NG_IDB, _NG_EPB = 1, 6
_NG_OPT_TSRESOL, _NG_OPT_TSOFFSET = 9, 14
_MAX_BLOCK = _MAX_RECORD + 4096

_LINK_ETHERNET = 1
_LINK_SLL = 113
_LINK_NULL = 0
_LINK_RAW = (12, 101, 228, 229)
_LINKS = (_LINK_ETHERNET, _LINK_SLL, _LINK_NULL) + _LINK_RAW


class PcapResult:
    """What a capture contained. ``note`` is empty when nothing needs saying.

    ``format`` is "pcap" or "pcapng" (decided by the file's magic bytes), or ""
    when the file is neither.
    """

    def __init__(self):
        self.format = ""
        self.flows = []
        self.truncated = False
        self.note = ""
        self.packet_count = 0


class _Half:
    """One direction of a flow while packets are still arriving."""

    def __init__(self):
        self.isn = None         # sequence number of the SYN, if it was captured
        self.first_seq = None   # first data seq stored; the origin without a SYN
        self.fin = None         # sequence number just past the FIN
        self.segs = {}          # TCP: seq -> payload
        self.chunks = []        # UDP: payloads in arrival order
        self.kept = 0


class Flow:
    """One conversation between a client and a server.

    ``client_bytes`` / ``server_bytes`` count payload seen, retransmissions
    excluded, including payload that was not retained because of a limit.
    ``packets`` lists ``(ts, direction, payload)`` per message in capture
    order, ``direction`` being "c" (client to server) or "s". ``gaps`` are the
    sizes in bytes of holes in the TCP streams (client holes first); the
    streams end at their first hole. For UDP a stream is the datagrams joined
    in arrival order, so message-oriented protocols should read ``packets``.

    ``client_guessed`` is True when nothing in the capture says who the client
    is: a TCP capture that starts after the SYN (the first sender is taken as
    the client) and every UDP flow (there is no handshake). A parser that
    depends on the direction should treat such a flow with care.
    """

    def __init__(self, proto, client, server, ts, client_guessed):
        self.proto = proto
        self.client_guessed = client_guessed
        self.src, self.sport = client
        self.dst, self.dport = server
        self.first_ts = ts
        self.last_ts = ts
        self.client_bytes = 0
        self.server_bytes = 0
        self.client_gaps = []
        self.server_gaps = []
        self.packets = []
        self.capped = False
        self._half = {"c": _Half(), "s": _Half()}
        self._streams = {"c": b"", "s": b""}

    @property
    def gaps(self):
        return self.client_gaps + self.server_gaps

    def client_stream(self):
        return self._streams["c"]

    def server_stream(self):
        return self._streams["s"]

    def _direction(self, ip, port):
        return "c" if (ip, port) == (self.src, self.sport) else "s"

    def _touch(self, ts):
        if ts < self.first_ts:
            self.first_ts = ts
        if ts > self.last_ts:
            self.last_ts = ts

    def _count(self, direction, n):
        if direction == "c":
            self.client_bytes += n
        else:
            self.server_bytes += n

    def _finish(self):
        for d in ("c", "s"):
            half = self._half[d]
            if half.chunks:
                self._streams[d] = b"".join(half.chunks)
            else:
                data, gaps = _assemble(half, self.capped)
                self._streams[d] = data
                (self.client_gaps if d == "c" else self.server_gaps).extend(gaps)
        self._half = None


def _signed32(value):
    value &= _MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def _assemble(half, capped):
    """Join the stored segments in sequence order, stopping at the first hole.

    Returns ``(stream, gap_sizes)``. Every hole is listed, but only the data
    before the first one goes into the stream.
    """
    pivot = half.isn + 1 if half.isn is not None else half.first_seq
    if pivot is None or not half.segs:
        return b"", []
    placed = sorted((_signed32(seq - pivot), payload)
                    for seq, payload in half.segs.items())
    cursor = 0 if half.isn is not None else placed[0][0]
    out = []
    gaps = []
    for rel, payload in placed:
        end = rel + len(payload)
        if half.isn is not None and rel < 0:    # before the first byte: not stream data
            if end <= 0:
                continue
            payload, rel = payload[-rel:], 0
        if end <= cursor:
            continue
        if rel > cursor:
            gaps.append(rel - cursor)
            cursor = rel
        elif rel < cursor:
            payload = payload[cursor - rel:]
        if not gaps:
            out.append(payload)
        cursor = end
    if half.fin is not None and not capped:
        fin_rel = _signed32(half.fin - pivot)
        if fin_rel > cursor:
            gaps.append(fin_rel - cursor)
    return b"".join(out), gaps


class _Reader:
    """State of one read_pcap call."""

    def __init__(self):
        self.result = PcapResult()
        self.active = {}
        self.total_kept = 0
        self.fragments = 0
        self.undecodable = 0
        self.bad_links = set()
        self.flows_refused = 0
        self.any_capped = False

    def add_packet(self, ts, ip):
        if isinstance(ip, dpkt.ip.IP) and (ip.mf or ip.offset):
            self.fragments += 1
            return
        l4 = ip.data
        src = dpkt.utils.inet_to_str(ip.src)
        dst = dpkt.utils.inet_to_str(ip.dst)
        if isinstance(l4, dpkt.tcp.TCP):
            self._tcp(ts, src, dst, l4)
        elif isinstance(l4, dpkt.udp.UDP):
            self._udp(ts, src, dst, l4)

    def _flow_for(self, key, proto, client, server, ts, client_guessed):
        if len(self.result.flows) >= MAX_FLOWS:
            self.flows_refused += 1
            return None
        flow = Flow(proto, client, server, ts, client_guessed)
        self.active[key] = flow
        self.result.flows.append(flow)
        return flow

    @staticmethod
    def _key(proto, a, b):
        a, b = sorted((a, b))
        return (a[0], a[1], b[0], b[1], proto)

    def _admit(self, flow, half, n, held):
        """True when n more bytes may be retained; otherwise flag the flow."""
        if (half.kept + n > MAX_STREAM_BYTES or held >= MAX_SEGMENTS
                or self.total_kept + n > MAX_TOTAL_BYTES):
            flow.capped = True
            self.any_capped = True
            return False
        half.kept += n
        self.total_kept += n
        return True

    def _udp(self, ts, src, dst, dgram):
        a, b = (src, dgram.sport), (dst, dgram.dport)
        key = self._key("udp", a, b)
        flow = self.active.get(key) or self._flow_for(key, "udp", a, b, ts, True)
        if flow is None:
            return
        flow._touch(ts)
        payload = bytes(dgram.data)
        if not payload:
            return
        d = flow._direction(src, dgram.sport)
        half = flow._half[d]
        flow._count(d, len(payload))
        if self._admit(flow, half, len(payload), len(half.chunks)):
            half.chunks.append(payload)
            flow.packets.append((ts, d, payload))

    def _tcp(self, ts, src, dst, seg):
        a, b = (src, seg.sport), (dst, seg.dport)
        key = self._key("tcp", a, b)
        syn = bool(seg.flags & dpkt.tcp.TH_SYN)
        ack = bool(seg.flags & dpkt.tcp.TH_ACK)
        flow = self.active.get(key)
        if flow is not None and syn and _is_new_connection(flow, a, ack, seg.seq):
            flow = None
        if flow is None:
            # A SYN names its sender the client and a SYN/ACK names its receiver
            # the client. Without either, the capture began mid-connection and
            # the first sender is only a guess; client_guessed says so.
            client, server = (b, a) if syn and ack else (a, b)
            flow = self._flow_for(key, "tcp", client, server, ts, not syn)
            if flow is None:
                return
        flow._touch(ts)
        d = flow._direction(src, seg.sport)
        half = flow._half[d]
        seq = seg.seq & _MASK32
        if syn and half.isn is None:
            half.isn = seq
        data_seq = (seq + (1 if syn else 0)) & _MASK32
        payload = bytes(seg.data)
        if payload:
            self._tcp_payload(flow, half, d, ts, data_seq, payload)
        if seg.flags & dpkt.tcp.TH_FIN:
            half.fin = (data_seq + len(payload)) & _MASK32

    def _tcp_payload(self, flow, half, d, ts, seq, payload):
        old = half.segs.get(seq)
        if old is not None and len(old) >= len(payload):
            return                              # retransmission
        added = len(payload) - (len(old) if old is not None else 0)
        flow._count(d, added)
        if not self._admit(flow, half, added, len(half.segs)):
            return
        if half.first_seq is None:
            half.first_seq = seq
        half.segs[seq] = payload
        flow.packets.append((ts, d, payload))


def _is_new_connection(flow, sender, ack, seq):
    """Does this SYN or SYN/ACK start a different connection on a known 4-tuple?"""
    seq &= _MASK32
    d = flow._direction(*sender)
    if not ack:
        if d == "s":
            return True
        isn = flow._half["c"].isn
        return isn is None or isn != seq
    if d == "c":
        return True
    isn = flow._half["s"].isn
    if isn is not None:
        return isn != seq
    return flow._half["c"].isn is None


def _ip_from_frame(buf, linktype):
    """The IP packet inside a link-layer frame, or None when it carries none."""
    if linktype == _LINK_ETHERNET:
        inner = dpkt.ethernet.Ethernet(buf).data
    elif linktype == _LINK_SLL:
        inner = dpkt.sll.SLL(buf).data
    elif linktype == _LINK_NULL:
        inner = dpkt.loopback.Loopback(buf).data
    else:
        version = buf[0] >> 4
        if version == 4:
            inner = dpkt.ip.IP(buf)
        elif version == 6:
            inner = dpkt.ip6.IP6(buf)
        else:
            return None
    if isinstance(inner, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return inner
    return None


def _records(fh, endian, divisor, linktype, result):
    """Yield ``(ts, frame, linktype)`` per complete record of a classic pcap.

    A cut or corrupt tail sets ``result.truncated`` and ends the iteration.
    """
    hdr = struct.Struct(endian + "IIII")
    while True:
        raw = fh.read(hdr.size)
        if not raw:
            return
        if len(raw) < hdr.size:
            result.truncated = True
            result.note = "pcap is truncated: the last record header is incomplete"
            return
        sec, frac, incl, _orig = hdr.unpack(raw)
        if incl > _MAX_RECORD:
            result.truncated = True
            result.note = "pcap is corrupt: a record claims %d bytes" % incl
            return
        frame = fh.read(incl)
        if len(frame) < incl:
            result.truncated = True
            result.note = "pcap is truncated: the last record is incomplete"
            return
        yield sec + frac / divisor, frame, linktype


def _ng_options(buf, endian):
    """``(code, value)`` pairs of a pcapng option list; stops at the end option."""
    pos = 0
    while pos + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, pos)
        if code == 0:
            return
        yield code, buf[pos + 4:pos + 4 + length]
        pos += 4 + ((length + 3) & ~3)


def _ng_interface(body, endian):
    """``(linktype, ticks_per_second, offset_seconds)`` from an interface block."""
    linktype = struct.unpack_from(endian + "H", body, 0)[0] if len(body) >= 2 else -1
    divisor, offset = 10 ** 6, 0
    for code, value in _ng_options(body[8:], endian):
        if code == _NG_OPT_TSRESOL and len(value) == 1:
            raw = value[0]
            divisor = (2 if raw & 0x80 else 10) ** (raw & 0x7F)
        elif code == _NG_OPT_TSOFFSET and len(value) == 8:
            offset = struct.unpack(endian + "q", value)[0]
    return linktype, divisor, offset


def _ng_records(fh, result):
    """Yield ``(ts, frame, linktype)`` per packet block of a pcapng file.

    Link type and clock come from the packet's own interface, and a new section
    header starts a new interface list (and may change byte order). A frame of
    None marks a packet block that could not be used. A cut or corrupt block
    sets ``result.truncated`` and ends the iteration.
    """
    endian = None
    interfaces = []
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            result.truncated = True
            result.note = "pcapng is truncated: the last block header is incomplete"
            return
        prefix = b""
        if head[:4] == _PCAPNG_MAGIC:
            prefix = fh.read(4)
            if prefix not in _NG_BOM:
                if result.packet_count or interfaces:
                    result.truncated = True
                    result.note = "pcapng is corrupt: bad section header"
                else:
                    result.note = "not a valid pcapng file: bad section header"
                return
            endian = _NG_BOM[prefix]
            btype = 0x0A0D0D0A
            length = struct.unpack(endian + "I", head[4:])[0]
        elif endian is None:
            result.note = "not a valid pcapng file: no section header"
            return
        else:
            btype, length = struct.unpack(endian + "II", head)
        if length < 12 + len(prefix) or length % 4 or length > _MAX_BLOCK:
            result.truncated = True
            result.note = "pcapng is corrupt: a block claims %d bytes" % length
            return
        want = length - 8 - len(prefix)
        rest = fh.read(want)
        if len(rest) < want:
            result.truncated = True
            result.note = "pcapng is truncated: the last block is incomplete"
            return
        body = (prefix + rest)[:-4]            # drop the trailing length field
        if btype == 0x0A0D0D0A:
            interfaces = []
        elif btype == _NG_IDB:
            interfaces.append(_ng_interface(body, endian))
        elif btype == _NG_EPB:
            if len(body) < 20:
                yield 0.0, None, None
                continue
            iface, hi, lo, caplen, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface >= len(interfaces) or caplen > len(body) - 20:
                yield 0.0, None, None
                continue
            linktype, divisor, offset = interfaces[iface]
            ts = offset + ((hi << 32) | lo) / divisor
            yield ts, body[20:20 + caplen], linktype


def read_pcap(path):
    """Read a classic pcap into a PcapResult. Never raises on bad input."""
    reader = _Reader()
    result = reader.result
    try:
        with open(path, "rb") as fh:
            head = fh.read(24)
            if head[:4] == _PCAPNG_MAGIC:
                result.format = "pcapng"
                fh.seek(0)
                records = _ng_records(fh, result)
            elif len(head) >= 24 and head[:4] in _MAGICS:
                result.format = "pcap"
                endian, divisor = _MAGICS[head[:4]]
                linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
                records = _records(fh, endian, divisor, linktype, result)
            else:
                result.note = "not a pcap or pcapng file: unrecognised header"
                return result
            for ts, frame, linktype in records:
                result.packet_count += 1
                if frame is None:
                    reader.undecodable += 1
                    continue
                if linktype not in _LINKS:
                    reader.bad_links.add(linktype)
                    continue
                try:
                    ip = _ip_from_frame(frame, linktype)
                    if ip is not None:
                        reader.add_packet(ts, ip)
                except Exception:
                    # a frame from a capture is untrusted; one that dpkt cannot
                    # decode is skipped and counted, whatever way it fails
                    reader.undecodable += 1
    except OSError as exc:
        result.note = "could not read pcap file: %s" % exc.strerror
        return result
    for flow in result.flows:
        flow._finish()
    _write_note(reader)
    return result


def _write_note(reader):
    result = reader.result
    parts = [result.note] if result.note else []
    if reader.fragments:
        parts.append("%d IP fragment(s) skipped" % reader.fragments)
    if reader.bad_links:
        parts.append("frames with unsupported link type %s skipped"
                     % ", ".join(str(n) for n in sorted(reader.bad_links)))
    if reader.undecodable:
        parts.append("%d undecodable frame(s) skipped" % reader.undecodable)
    if reader.flows_refused:
        parts.append("flow limit of %d reached, %d packet(s) of later flows dropped"
                     % (MAX_FLOWS, reader.flows_refused))
    if reader.any_capped:
        parts.append("payload retention limit reached, streams of some flows are cut")
    result.note = "; ".join(parts)
