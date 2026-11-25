"""pcap reading, flows and TCP stream reassembly.

Regressions covered:
  * out-of-order segments were joined in arrival order, so a parser saw the
    second half of a request first
  * a retransmitted segment appeared twice in the stream
  * a lost segment was papered over (zero fill or skip-ahead), so a parser read
    bytes that were never on the wire; the stream must end at the gap
  * sequence numbers were compared as plain integers, so a stream crossing the
    2**32 wrap came out in the wrong order
  * a capture started mid-connection (no SYN) with its first segment arriving
    out of order lost the data that preceded it
  * a capture that begins with the SYN/ACK took the server for the client
  * a reused source port after a closed connection merged two connections
    into one stream
  * IP fragments were decoded as if they started with a TCP header
  * a half-written pcap or a file that is not a pcap raised instead of
    reporting what was readable
  * a large capture was held in memory without bound
  * per-message timestamps were thrown away, so heartbeat intervals could not
    be measured
  * pcapng, the format Wireshark and tshark write by default, was refused, so
    importing a foreign capture failed in practice
  * a pcapng with more than one interface was decoded with the first
    interface's link type and clock
  * a cut pcapng block was taken for a short packet instead of a truncation
  * growing retransmits at one sequence number were each charged only for
    their extra bytes yet kept in full, so the retention caps could be beaten
    by a crafted capture, and one message appeared as several in ``packets``
  * a capture that begins mid-connection looked as certain about who the
    client is as one that begins with the SYN
"""

import socket
import struct

import dpkt
import pytest

import net_flows

CLIENT = "192.0.2.10"
SERVER = "198.51.100.7"
CPORT = 49152
SPORT = 80

SYN, ACK, FIN, RST = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST
PSH = dpkt.tcp.TH_PUSH


def _ip(addr):
    return socket.inet_pton(socket.AF_INET6 if ":" in addr else socket.AF_INET, addr)


def _l3(src, dst, proto, transport):
    if ":" in src:
        return dpkt.ip6.IP6(src=_ip(src), dst=_ip(dst), nxt=proto, hlim=64,
                            data=transport)
    return dpkt.ip.IP(src=_ip(src), dst=_ip(dst), p=proto, ttl=64, data=transport)


def _frame(ip):
    eth_type = dpkt.ethernet.ETH_TYPE_IP6 if isinstance(ip, dpkt.ip6.IP6) \
        else dpkt.ethernet.ETH_TYPE_IP
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=eth_type, data=ip))


def _tcp(ts, src, sport, dst, dport, seq, flags, payload=b"", ack=0, raw_ip=False):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF,
                       ack=ack & 0xFFFFFFFF, flags=flags, win=8192, data=payload)
    ip = _l3(src, dst, dpkt.ip.IP_PROTO_TCP, seg)
    return (ts, bytes(ip) if raw_ip else _frame(ip))


def _udp_packet(dport, payload, ts=1.0, src=CLIENT, sport=40000, dst=SERVER):
    dgram = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    dgram.ulen = 8 + len(payload)
    return [(ts, _frame(_l3(src, dst, dpkt.ip.IP_PROTO_UDP, dgram)))]


def _tcp_exchange(request, response, client_ts=1.0, server_ts=2.0, cport=CPORT,
                  isn_c=1000, isn_s=5000, close=True):
    """SYN, SYN/ACK, ACK, request, response, ACK and an orderly close."""
    c = (CLIENT, cport, SERVER, SPORT)
    s = (SERVER, SPORT, CLIENT, cport)
    t = client_ts
    pk = [
        _tcp(t - 0.3, *c, isn_c, SYN),
        _tcp(t - 0.2, *s, isn_s, SYN | ACK, ack=isn_c + 1),
        _tcp(t - 0.1, *c, isn_c + 1, ACK, ack=isn_s + 1),
        _tcp(client_ts, *c, isn_c + 1, ACK | PSH, request, ack=isn_s + 1),
        _tcp(server_ts, *s, isn_s + 1, ACK | PSH, response,
             ack=isn_c + 1 + len(request)),
    ]
    if close:
        end_c = isn_c + 1 + len(request)
        end_s = isn_s + 1 + len(response)
        pk += [
            _tcp(server_ts + 0.1, *c, end_c, ACK | FIN, ack=end_s),
            _tcp(server_ts + 0.2, *s, end_s, ACK | FIN, ack=end_c + 1),
        ]
    return pk


def _tcp_segments(segments, isn=1000, syn=True, raw_ip=False, src=CLIENT, dst=SERVER):
    """Client-to-server segments in the order given.

    ``segments`` is a list of ``(slot, payload)``. Slot n starts at byte
    (n - 1) * W of the stream, W being the length of the longest payload, so a
    skipped slot leaves a hole of known size and equal slots are retransmissions.
    """
    width = max(len(p) for _, p in segments)
    c = (src, CPORT, dst, SPORT)
    pk = [_tcp(0.5, *c, isn, SYN, raw_ip=raw_ip)] if syn else []
    for i, (slot, payload) in enumerate(segments):
        pk.append(_tcp(1.0 + i * 0.1, *c, isn + 1 + (slot - 1) * width,
                       ACK | PSH, payload, raw_ip=raw_ip))
    return pk


def _pcap(tmp_path, packets, linktype=dpkt.pcap.DLT_EN10MB, name="t.pcap"):
    path = tmp_path / name
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=linktype)
        for ts, buf in packets:
            w.writepkt(buf, ts)
    return str(path)


def _pcapng(tmp_path, packets, linktype=dpkt.pcap.DLT_EN10MB, name="t.pcapng"):
    path = tmp_path / name
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f, linktype=linktype)
        for ts, buf in packets:
            w.writepkt(buf, ts)
    return str(path)


def _ng_block(endian, btype, body):
    total = 12 + len(body)
    return struct.pack(endian + "II", btype, total) + body + struct.pack(endian + "I", total)


def _ng_file(endian, interfaces, packets):
    """A hand-built pcapng. interfaces: [(linktype, tsresol or None)];
    packets: [(interface, ts_ticks, frame)]."""
    bom = struct.pack(endian + "I", 0x1A2B3C4D)
    out = _ng_block(endian, 0x0A0D0D0A,
                    bom + struct.pack(endian + "HHq", 1, 0, -1))
    for linktype, tsresol in interfaces:
        opts = b""
        if tsresol is not None:
            opts = struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\0\0\0"
            opts += struct.pack(endian + "HH", 0, 0)
        out += _ng_block(endian, 1, struct.pack(endian + "HHI", linktype, 0, 65535) + opts)
    for iface, ticks, frame in packets:
        pad = b"\0" * (-len(frame) % 4)
        body = struct.pack(endian + "IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF,
                           len(frame), len(frame)) + frame + pad
        out += _ng_block(endian, 6, body)
    return out


def _flow_view(flow):
    return (flow.proto, flow.src, flow.sport, flow.dst, flow.dport,
            flow.first_ts, flow.last_ts, flow.client_bytes, flow.server_bytes,
            flow.gaps, flow.client_stream(), flow.server_stream(),
            [(ts, d, bytes(pl)) for ts, d, pl in flow.packets])


# --- the brief's behaviours -------------------------------------------------

def test_a_tcp_conversation_becomes_one_flow_per_direction(tmp_path):
    p = _pcap(tmp_path, _tcp_exchange(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"))
    r = net_flows.read_pcap(p)
    assert len(r.flows) == 1
    f = r.flows[0]
    assert f.dport == 80 and f.proto == "tcp"
    assert f.client_stream().startswith(b"GET /")
    assert f.server_stream().startswith(b"HTTP/1.1 200")


def test_out_of_order_segments_are_reassembled_in_sequence(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(2, b"world"), (1, b"hello ")]))
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"hello world"


def test_a_retransmitted_segment_is_not_duplicated(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"abc"), (1, b"abc"), (2, b"def")]))
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"abcdef"


def test_a_missing_segment_leaves_a_recorded_gap(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"aaa"), (3, b"ccc")]))
    f = net_flows.read_pcap(p).flows[0]
    assert f.gaps and f.client_stream() == b"aaa"


def test_a_truncated_pcap_yields_what_was_readable(tmp_path):
    full = _pcap(tmp_path, _tcp_exchange(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"))
    cut = tmp_path / "cut.pcap"
    with open(full, "rb") as f:
        cut.write_bytes(f.read()[:-12])
    r = net_flows.read_pcap(str(cut))
    assert r.truncated is True and r.note
    assert r.packet_count >= 1


def test_a_file_that_is_not_a_pcap_is_refused_with_a_reason(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"this is not a capture")
    r = net_flows.read_pcap(str(bad))
    assert r.flows == [] and "pcap" in r.note.lower()


def test_udp_packets_become_flows_too(tmp_path):
    p = _pcap(tmp_path, _udp_packet(53, b"\x00\x01"))
    assert net_flows.read_pcap(p).flows[0].proto == "udp"


def test_each_message_keeps_its_timestamp_and_direction(tmp_path):
    p = _pcap(tmp_path, _tcp_exchange(b"ping", b"pong", client_ts=10.0, server_ts=11.5))
    pk = net_flows.read_pcap(p).flows[0].packets
    assert [(d, bytes(pl)) for _, d, pl in pk] == [("c", b"ping"), ("s", b"pong")]
    assert [ts for ts, _, _ in pk] == [10.0, 11.5]


# --- reassembly details -----------------------------------------------------

def test_the_stream_stops_at_a_gap_and_does_not_skip_ahead(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"aaa"), (3, b"ccc"), (4, b"ddd")]))
    f = net_flows.read_pcap(p).flows[0]
    assert f.client_stream() == b"aaa"
    assert f.gaps == [3]


def test_data_missing_before_the_close_is_a_gap_too(tmp_path):
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN),
          _tcp(1.0, *c, 1001, ACK | PSH, b"abc"),
          _tcp(1.1, *c, 1001 + 3 + 4, ACK | FIN)]
    f = net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0]
    assert f.client_stream() == b"abc" and f.gaps == [4]


def test_sequence_numbers_that_wrap_past_2_to_the_32_stay_in_order(tmp_path):
    segs = [(3, b"again!"), (2, b"world "), (1, b"hello ")]
    p = _pcap(tmp_path, _tcp_segments(segs, isn=0xFFFFFFFC))
    f = net_flows.read_pcap(p).flows[0]
    assert f.client_stream() == b"hello world again!"
    assert f.gaps == []


def test_a_capture_that_starts_mid_connection_still_orders_its_segments(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(2, b"world"), (1, b"hello ")], syn=False))
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"hello world"


def test_a_midstream_capture_wrapping_the_sequence_space_stays_in_order(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(2, b"world"), (1, b"hello ")],
                                      isn=0xFFFFFFFD, syn=False))
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"hello world"


def test_a_retransmission_with_more_data_keeps_the_longer_segment(tmp_path):
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN),
          _tcp(1.0, *c, 1001, ACK, b"ab"),
          _tcp(1.1, *c, 1001, ACK, b"abcd"),
          _tcp(1.2, *c, 1005, ACK, b"ef")]
    assert net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0].client_stream() == b"abcdef"


def test_a_segment_overlapping_earlier_data_adds_only_the_new_bytes(tmp_path):
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN),
          _tcp(1.0, *c, 1001, ACK, b"abcd"),
          _tcp(1.1, *c, 1003, ACK, b"cdef")]
    assert net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0].client_stream() == b"abcdef"


def test_retransmissions_do_not_appear_as_extra_messages(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"abc"), (1, b"abc"), (2, b"def")]))
    pk = net_flows.read_pcap(p).flows[0].packets
    assert [bytes(pl) for _, _, pl in pk] == [b"abc", b"def"]


def test_a_longer_retransmission_is_one_message_not_two(tmp_path):
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN),
          _tcp(1.0, *c, 1001, ACK, b"ab"),
          _tcp(1.7, *c, 1001, ACK, b"abcd"),
          _tcp(2.0, *c, 1005, ACK, b"ef")]
    f = net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0]
    assert [(ts, d, bytes(pl)) for ts, d, pl in f.packets] == [
        (1.0, "c", b"abcd"), (2.0, "c", b"ef")]
    assert f.client_bytes == 6


def test_byte_counts_cover_each_direction(tmp_path):
    p = _pcap(tmp_path, _tcp_exchange(b"ping", b"pong!"))
    f = net_flows.read_pcap(p).flows[0]
    assert (f.client_bytes, f.server_bytes) == (4, 5)
    assert f.first_ts < f.last_ts


# --- flows ------------------------------------------------------------------

def test_a_capture_beginning_with_the_syn_ack_still_finds_the_client(tmp_path):
    pk = _tcp_exchange(b"ping", b"pong")[1:]
    f = net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0]
    assert (f.src, f.dst, f.dport) == (CLIENT, SERVER, 80)
    assert f.client_stream() == b"ping" and f.server_stream() == b"pong"


def test_a_reused_source_port_after_a_close_is_a_new_flow(tmp_path):
    pk = (_tcp_exchange(b"first", b"one", client_ts=5.0, server_ts=6.0, isn_c=1000)
          + _tcp_exchange(b"second", b"two", client_ts=50.0, server_ts=51.0, isn_c=777000))
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert [f.client_stream() for f in r.flows] == [b"first", b"second"]


def test_a_retransmitted_syn_does_not_split_the_flow(tmp_path):
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN), _tcp(1.0, *c, 1000, SYN),
          _tcp(1.5, *c, 1001, ACK, b"abc")]
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert len(r.flows) == 1 and r.flows[0].client_stream() == b"abc"


def test_two_connections_are_two_flows(tmp_path):
    pk = (_tcp_exchange(b"a", b"b", cport=40001, client_ts=1.0, server_ts=1.5)
          + _tcp_exchange(b"c", b"d", cport=40002, client_ts=2.0, server_ts=2.5))
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert sorted(f.sport for f in r.flows) == [40001, 40002]


def test_udp_flow_keeps_every_datagram_with_its_direction(tmp_path):
    pk = _udp_packet(53, b"query", ts=1.0)
    resp = dpkt.udp.UDP(sport=53, dport=40000, data=b"answer")
    resp.ulen = 8 + 6
    pk.append((1.2, _frame(_l3(SERVER, CLIENT, dpkt.ip.IP_PROTO_UDP, resp))))
    f = net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0]
    assert f.dport == 53
    assert [(ts, d, bytes(pl)) for ts, d, pl in f.packets] == [
        (1.0, "c", b"query"), (1.2, "s", b"answer")]


def test_ipv6_traffic_is_read(tmp_path):
    c6, s6 = "2001:db8::10", "2001:db8::7"
    pk = _udp_packet(53, b"v6", src=c6, dst=s6)
    f = net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0]
    assert (f.src, f.dst) == (c6, s6) and f.client_stream() == b"v6"


def test_raw_ip_captures_without_ethernet_are_read(tmp_path):
    pk = _tcp_segments([(2, b"world"), (1, b"hello ")], raw_ip=True)
    p = _pcap(tmp_path, pk, linktype=dpkt.pcap.DLT_RAW)
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"hello world"


def test_ip_fragments_are_not_read_as_tcp(tmp_path):
    frag = dpkt.ip.IP(src=_ip(CLIENT), dst=_ip(SERVER), p=dpkt.ip.IP_PROTO_TCP,
                      offset=185, data=b"\x00" * 40)
    r = net_flows.read_pcap(_pcap(tmp_path, [(1.0, _frame(frag))]))
    assert r.flows == [] and "fragment" in r.note.lower()


def test_non_tcp_udp_traffic_is_counted_but_makes_no_flow(tmp_path):
    ping = dpkt.ip.IP(src=_ip(CLIENT), dst=_ip(SERVER), p=dpkt.ip.IP_PROTO_ICMP,
                      data=dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1)))
    r = net_flows.read_pcap(_pcap(tmp_path, [(1.0, _frame(ping))]))
    assert r.flows == [] and r.packet_count == 1


# --- file level -------------------------------------------------------------

def test_an_empty_capture_has_no_flows_and_is_not_an_error(tmp_path):
    r = net_flows.read_pcap(_pcap(tmp_path, []))
    assert r.flows == [] and r.truncated is False and r.packet_count == 0


def test_a_missing_file_is_reported_not_raised(tmp_path):
    r = net_flows.read_pcap(str(tmp_path / "nope.pcap"))
    assert r.flows == [] and r.note


def test_a_cut_inside_the_global_header_is_not_a_pcap(tmp_path):
    p = _pcap(tmp_path, _udp_packet(53, b"x"))
    with open(p, "rb") as f:
        head = f.read()[:10]
    (tmp_path / "h.pcap").write_bytes(head)
    r = net_flows.read_pcap(str(tmp_path / "h.pcap"))
    assert r.flows == [] and "pcap" in r.note.lower()


def test_the_flows_before_a_truncation_are_kept(tmp_path):
    pk = _udp_packet(53, b"one", ts=1.0) + _udp_packet(53, b"two", ts=2.0, sport=40001)
    with open(_pcap(tmp_path, pk), "rb") as f:
        data = f.read()
    (tmp_path / "c.pcap").write_bytes(data[:-5])
    r = net_flows.read_pcap(str(tmp_path / "c.pcap"))
    assert r.truncated and len(r.flows) == 1 and r.flows[0].client_stream() == b"one"


@pytest.mark.parametrize("endian,magic,divisor", [
    ("<", 0xA1B2C3D4, 10**6), (">", 0xA1B2C3D4, 10**6),
    ("<", 0xA1B23C4D, 10**9), (">", 0xA1B23C4D, 10**9),
])
def test_byte_order_and_nanosecond_pcaps_give_the_same_timestamps(
        tmp_path, endian, magic, divisor):
    frame = _udp_packet(53, b"hi")[0][1]
    ts_frac = 250 * divisor // 1000
    blob = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    blob += struct.pack(endian + "IIII", 7, ts_frac, len(frame), len(frame)) + frame
    path = tmp_path / "e.pcap"
    path.write_bytes(blob)
    f = net_flows.read_pcap(str(path)).flows[0]
    assert f.first_ts == 7.25


def test_an_unsupported_link_type_is_reported(tmp_path):
    p = _pcap(tmp_path, _udp_packet(53, b"x"), linktype=147)
    r = net_flows.read_pcap(p)
    assert r.flows == [] and "link type" in r.note.lower()
    assert r.packet_count == 1


def test_garbage_frames_are_skipped_not_fatal(tmp_path):
    pk = [(1.0, b"\xff" * 5)] + _udp_packet(53, b"ok", ts=2.0)
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert len(r.flows) == 1 and r.packet_count == 2


# --- memory bound -----------------------------------------------------------

def test_retained_payload_per_direction_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(net_flows, "MAX_STREAM_BYTES", 10)
    p = _pcap(tmp_path, _tcp_segments([(1, b"aaaaaa"), (2, b"bbbbbb"), (3, b"cccccc")]))
    r = net_flows.read_pcap(p)
    f = r.flows[0]
    assert f.client_stream() == b"aaaaaa"
    assert f.capped is True and "limit" in r.note.lower()
    assert f.client_bytes == 18


def test_growing_retransmits_at_one_seq_cannot_beat_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(net_flows, "MAX_STREAM_BYTES", 1000)
    monkeypatch.setattr(net_flows, "MAX_TOTAL_BYTES", 1000)
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN)]
    pk += [_tcp(1.0 + n / 1000.0, *c, 1001, ACK, b"x" * n) for n in range(1, 301, 3)]
    pk += [_tcp(3.0, *c, 1001, ACK, b"x" * 3000)]
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    f = r.flows[0]
    assert f.capped is True and "limit" in r.note.lower()
    assert sum(len(pl) for _, _, pl in f.packets) <= 1000
    assert len(f.client_stream()) <= 1000
    assert len(f.packets) == 1


def test_growing_retransmits_do_not_exhaust_the_segment_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(net_flows, "MAX_SEGMENTS", 1)
    c = (CLIENT, CPORT, SERVER, SPORT)
    pk = [_tcp(0.5, *c, 1000, SYN)]
    pk += [_tcp(1.0 + n / 100.0, *c, 1001, ACK, b"x" * n) for n in range(1, 40)]
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert r.flows[0].client_stream() == b"x" * 39 and not r.flows[0].capped


def test_the_cap_does_not_mark_a_normal_flow(tmp_path):
    f = net_flows.read_pcap(_pcap(tmp_path, _tcp_exchange(b"a", b"b"))).flows[0]
    assert f.capped is False


def test_total_retained_payload_across_flows_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(net_flows, "MAX_TOTAL_BYTES", 8)
    pk = (_udp_packet(53, b"aaaaaa", ts=1.0, sport=1111)
          + _udp_packet(53, b"bbbbbb", ts=2.0, sport=2222))
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert len(r.flows) == 2 and r.flows[1].capped and "limit" in r.note.lower()


def test_the_number_of_flows_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(net_flows, "MAX_FLOWS", 2)
    pk = []
    for i in range(4):
        pk += _udp_packet(53, b"x", ts=1.0 + i, sport=3000 + i)
    r = net_flows.read_pcap(_pcap(tmp_path, pk))
    assert len(r.flows) == 2 and r.packet_count == 4 and "limit" in r.note.lower()


# --- pcapng -----------------------------------------------------------------

def test_a_pcapng_yields_the_same_flows_as_the_equivalent_pcap(tmp_path):
    pk = (_tcp_exchange(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n",
                        client_ts=10.0, server_ts=11.5)
          + _tcp_segments([(2, b"world"), (1, b"hello ")], isn=7000)
          + _udp_packet(53, b"q", ts=20.0))
    classic = net_flows.read_pcap(_pcap(tmp_path, pk))
    ng = net_flows.read_pcap(_pcapng(tmp_path, pk))
    assert len(ng.flows) == len(classic.flows) == 3
    assert [_flow_view(f) for f in ng.flows] == [_flow_view(f) for f in classic.flows]
    assert ng.packet_count == classic.packet_count == len(pk)
    assert ng.truncated is False and ng.note == ""


def test_the_result_says_which_format_it_read(tmp_path):
    pk = _udp_packet(53, b"x")
    assert net_flows.read_pcap(_pcap(tmp_path, pk)).format == "pcap"
    assert net_flows.read_pcap(_pcapng(tmp_path, pk)).format == "pcapng"
    bad = tmp_path / "x.bin"
    bad.write_bytes(b"this is not a capture")
    assert net_flows.read_pcap(str(bad)).format == ""


def test_the_format_comes_from_the_magic_not_the_file_name(tmp_path):
    p = _pcapng(tmp_path, _udp_packet(53, b"x"), name="named-like-a-pcap.pcap")
    r = net_flows.read_pcap(p)
    assert r.format == "pcapng" and len(r.flows) == 1


def test_a_truncated_pcapng_yields_what_was_readable(tmp_path):
    full = _pcapng(tmp_path, _tcp_exchange(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"))
    with open(full, "rb") as f:
        (tmp_path / "cut.pcapng").write_bytes(f.read()[:-12])
    r = net_flows.read_pcap(str(tmp_path / "cut.pcapng"))
    assert r.truncated is True and r.note
    assert r.packet_count >= 1 and r.flows


@pytest.mark.parametrize("make", [_pcap, _pcapng])
def test_a_capture_cut_at_any_byte_never_raises(tmp_path, make):
    packets = _tcp_exchange(b"ping", b"pong")
    with open(make(tmp_path, packets), "rb") as f:
        data = f.read()
    counts = []
    clean_cuts = 0
    for n in range(len(data) + 1):
        (tmp_path / "c.bin").write_bytes(data[:n])
        r = net_flows.read_pcap(str(tmp_path / "c.bin"))
        counts.append(r.packet_count)
        if r.packet_count and not r.truncated:
            clean_cuts += 1
    assert counts == sorted(counts) and counts[-1] == len(packets)
    # only a cut on a record boundary may look clean; any other cut must say so
    assert clean_cuts <= len(packets)


def test_a_pcapng_that_is_cut_inside_a_section_header_is_not_a_capture(tmp_path):
    p = _pcapng(tmp_path, _udp_packet(53, b"x"))
    with open(p, "rb") as f:
        (tmp_path / "h.pcapng").write_bytes(f.read()[:10])
    r = net_flows.read_pcap(str(tmp_path / "h.pcapng"))
    assert r.flows == [] and "pcap" in r.note.lower()


def test_pcapng_magic_followed_by_nonsense_is_refused_with_a_reason(tmp_path):
    bad = tmp_path / "n.pcapng"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00" + b"\xde\xad\xbe\xef" * 8)
    r = net_flows.read_pcap(str(bad))
    assert r.flows == [] and "pcap" in r.note.lower()


def test_a_pcapng_block_with_an_absurd_length_is_not_allocated(tmp_path):
    good = _ng_file("<", [(1, None)], [])
    blob = good + struct.pack("<II", 6, 0x7FFFFFF0) + b"\0" * 16
    bad = tmp_path / "big.pcapng"
    bad.write_bytes(blob)
    r = net_flows.read_pcap(str(bad))
    assert r.truncated is True and "corrupt" in r.note.lower()


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_in_either_byte_order_is_read(tmp_path, endian):
    frame = _udp_packet(53, b"hi")[0][1]
    blob = _ng_file(endian, [(1, None)], [(0, 7 * 10**6 + 250000, frame)])
    path = tmp_path / "e.pcapng"
    path.write_bytes(blob)
    f = net_flows.read_pcap(str(path)).flows[0]
    assert f.first_ts == 7.25 and f.client_stream() == b"hi"


def test_pcapng_honours_each_interfaces_timestamp_resolution(tmp_path):
    frame = _udp_packet(53, b"hi")[0][1]
    blob = _ng_file("<", [(1, 9)], [(0, 7 * 10**9 + 250000000, frame)])
    path = tmp_path / "ns.pcapng"
    path.write_bytes(blob)
    assert net_flows.read_pcap(str(path)).flows[0].first_ts == 7.25


def test_pcapng_interfaces_keep_their_own_link_type_and_clock(tmp_path):
    eth = _udp_packet(53, b"eth", sport=1111)[0][1]
    raw = bytes(dpkt.ethernet.Ethernet(_udp_packet(53, b"raw", sport=2222)[0][1]).data)
    blob = _ng_file("<", [(1, None), (101, 9)],
                    [(0, 2 * 10**6, eth), (1, 3 * 10**9, raw)])
    path = tmp_path / "multi.pcapng"
    path.write_bytes(blob)
    flows = net_flows.read_pcap(str(path)).flows
    assert sorted((f.sport, f.first_ts) for f in flows) == [(1111, 2.0), (2222, 3.0)]


def test_a_pcapng_with_several_sections_resets_its_interfaces(tmp_path):
    frame = _udp_packet(53, b"hi")[0][1]
    one = _ng_file("<", [(147, None)], [])
    two = _ng_file(">", [(1, None)], [(0, 2 * 10**6, frame)])
    path = tmp_path / "sections.pcapng"
    path.write_bytes(one + two)
    r = net_flows.read_pcap(str(path))
    assert [ts for ts, _, _ in r.flows[0].packets] == [2.0] and not r.note


def test_a_pcapng_packet_naming_an_unknown_interface_is_skipped(tmp_path):
    frame = _udp_packet(53, b"hi")[0][1]
    path = tmp_path / "noif.pcapng"
    path.write_bytes(_ng_file("<", [(1, None)], [(5, 10**6, frame), (0, 2 * 10**6, frame)]))
    r = net_flows.read_pcap(str(path))
    assert r.packet_count == 2 and len(r.flows) == 1 and "undecodable" in r.note


def test_a_pcapng_interface_with_an_unsupported_link_type_is_reported(tmp_path):
    frame = _udp_packet(53, b"hi")[0][1]
    path = tmp_path / "lt.pcapng"
    path.write_bytes(_ng_file("<", [(147, None)], [(0, 10**6, frame)]))
    r = net_flows.read_pcap(str(path))
    assert r.flows == [] and "link type" in r.note.lower()


# --- who is the client ------------------------------------------------------

def test_a_flow_that_began_with_a_syn_is_not_a_guess(tmp_path):
    f = net_flows.read_pcap(_pcap(tmp_path, _tcp_exchange(b"a", b"b"))).flows[0]
    assert f.client_guessed is False


def test_a_capture_that_began_mid_connection_marks_the_client_as_a_guess(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"abc")], syn=False))
    assert net_flows.read_pcap(p).flows[0].client_guessed is True


def test_a_syn_ack_first_capture_is_not_a_guess(tmp_path):
    pk = _tcp_exchange(b"ping", b"pong")[1:]
    assert net_flows.read_pcap(_pcap(tmp_path, pk)).flows[0].client_guessed is False


def test_a_udp_flow_always_has_a_guessed_client(tmp_path):
    f = net_flows.read_pcap(_pcap(tmp_path, _udp_packet(53, b"x"))).flows[0]
    assert f.client_guessed is True
