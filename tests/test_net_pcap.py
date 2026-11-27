"""The capture writer (webui/net_pcap.py): what the fake servers recorded, written so Phase 1 reads it back.

The first test is the whole architecture: the analysis that already ships, ``net_analyze.analyze_pcap``, is given a file
the writer made and has to find the exchange in it without knowing who answered. The others hold the writer to what
that needs (sequence numbers that advance with the payload, a close, a file that parses when it was cut off) and to
what a session needs of it (it never raises into a server, it is thread-safe, it is bounded).
"""

import math
import os
import threading

import dpkt
import pytest

import net_analyze
import net_flows
import net_pcap

GUEST = "10.0.2.15"
T0 = 1795000000.0
GET = b"GET /gate.php HTTP/1.1\r\nHost: c2.evil\r\n\r\n"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


_OPEN = []


@pytest.fixture(autouse=True)
def _close_what_a_test_left_open():
    yield
    while _OPEN:
        _OPEN.pop().close()


def _writer(tmp_path, name="capture.pcap"):
    path = str(tmp_path / name)
    w = net_pcap.CaptureWriter(path, GUEST)
    _OPEN.append(w)
    return w, path


def _flows(path):
    return net_flows.read_pcap(path).flows


def _dns(name, qid=0x1234, address=None):
    msg = dpkt.dns.DNS(id=qid, qr=dpkt.dns.DNS_R if address else dpkt.dns.DNS_Q, opcode=dpkt.dns.DNS_QUERY,
                       rd=1, ra=1 if address else 0)
    msg.qd = [dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    if address:
        raw = bytes(int(part) for part in address.split("."))
        msg.an = [dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN, ttl=60, rlen=4,
                                  rdata=raw, ip=raw)]
    return bytes(msg)


def _packets(path):
    with open(path, "rb") as fh:
        return [(ts, dpkt.ethernet.Ethernet(buf)) for ts, buf in dpkt.pcap.Reader(fh)]


# --- the seam -------------------------------------------------------------------------------------------------------


def test_what_was_written_is_what_analyze_pcap_reads_back(tmp_path):
    path = str(tmp_path / "capture.pcap")
    w = net_pcap.CaptureWriter(path, "10.0.2.15")
    w.exchange(1795000000.0, "203.0.113.5", 80, 49200,
               b"GET /gate.php HTTP/1.1\r\nHost: c2.evil\r\n\r\n",
               b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    w.close()
    report = net_analyze.analyze_pcap(path)
    assert report["event_summary"].get("http") == 1
    http = [e for e in report["events"] if e["type"] == "http"][0]
    assert (http["dest"], http["path"]) == ("c2.evil", "/gate.php")


def test_a_datagram_round_trip_is_read_back_as_a_dns_event(tmp_path):
    w, path = _writer(tmp_path)
    w.datagram(T0, "10.0.2.3", 53, 51000, _dns("c2.evil"))
    w.datagram(T0 + 0.02, "10.0.2.3", 53, 51000, _dns("c2.evil", address="198.18.0.7"), inbound=True)
    w.close()
    report = net_analyze.analyze_pcap(path)
    dns = [e for e in report["events"] if e["type"] == "dns"]
    assert len(dns) == 1
    assert dns[0]["dest"] == "c2.evil"
    assert dns[0]["answers"] == ["198.18.0.7"]
    assert report["errors"] == []


def test_a_writer_closed_twice_does_not_raise(tmp_path):
    w, _ = _writer(tmp_path)
    w.close()
    w.close()


def test_an_isolated_run_reads_the_same_capture_without_a_second_path(tmp_path):
    w, path = _writer(tmp_path)
    body = b"user=admin&pass=hunter2"
    w.exchange(T0, "198.18.0.9", 80, 49300,
               b"POST /login HTTP/1.1\r\nHost: c2.evil\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               b"Content-Length: %d\r\n\r\n" % len(body) + body, OK)
    w.close()
    report = net_analyze.analyze_pcap(path, mode="isolated")
    assert report["errors"] == []
    assert any(e["type"] in ("http", "upload") and e.get("path") == "/login" for e in report["events"])


# --- what reassembly needs ------------------------------------------------------------------------------------------


def test_the_numbers_advance_with_the_payload_so_both_streams_come_back_whole(tmp_path):
    w, path = _writer(tmp_path)
    request = b"POST /up HTTP/1.1\r\nHost: c2.evil\r\nContent-Length: 20000\r\n\r\n" + bytes(range(256)) * 78
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 300000\r\n\r\n" + b"\xa5" * 300000
    w.exchange(T0, "203.0.113.5", 80, 49200, request, response)
    w.close()
    flows = _flows(path)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.client_stream() == request
    assert flow.server_stream() == response
    assert flow.gaps == []
    assert not flow.client_guessed
    assert (flow.src, flow.sport, flow.dst, flow.dport) == (GUEST, 49200, "203.0.113.5", 80)


def test_no_packet_carries_more_than_a_frame_can(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, b"x" * 50000, b"y" * 50000)
    w.close()
    assert max(len(bytes(eth)) for _, eth in _packets(path)) <= 1514


def test_a_conversation_is_a_handshake_data_and_a_close(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.close()
    tcp = [eth.data.data for _, eth in _packets(path)]
    flags = [t.flags for t in tcp]
    assert flags[0] == dpkt.tcp.TH_SYN
    assert flags[1] == dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
    assert sum(1 for f in flags if f & dpkt.tcp.TH_FIN) == 2
    assert not any(f & dpkt.tcp.TH_RST for f in flags)
    flow = _flows(path)[0]
    assert flow.answered and not flow.server_reset


def test_a_conversation_with_nothing_said_is_still_a_flow(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 4444, 49200, b"", b"")
    w.close()
    flow = _flows(path)[0]
    assert flow.packets == [] and flow.answered and flow.gaps == []


def test_a_stream_that_crosses_the_wrap_of_the_sequence_numbers_is_whole(tmp_path):
    w, path = _writer(tmp_path)
    w._isn = lambda *args: 0xFFFFFF00
    w.exchange(T0, "203.0.113.5", 80, 49200, GET * 20, OK * 20)
    w.close()
    flow = _flows(path)[0]
    assert flow.client_stream() == GET * 20 and flow.server_stream() == OK * 20 and flow.gaps == []


def test_the_same_port_used_again_is_a_second_connection_not_more_of_the_first(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.exchange(T0 + 60, "203.0.113.5", 80, 49200, GET, OK)
    w.close()
    flows = _flows(path)
    assert len(flows) == 2
    assert all(f.client_stream() == GET and f.server_stream() == OK for f in flows)


def test_exchanges_to_different_places_are_different_flows(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.exchange(T0 + 1, "203.0.113.6", 80, 49201, GET, OK)
    w.close()
    assert sorted(f.dst for f in _flows(path)) == ["203.0.113.5", "203.0.113.6"]


def test_the_time_given_is_the_time_the_connection_began_and_time_does_not_go_back(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET * 40, OK * 40)
    w.close()
    stamps = [ts for ts, _ in _packets(path)]
    assert stamps[0] == pytest.approx(T0, abs=1e-6)
    assert stamps == sorted(stamps)
    assert stamps[-1] - T0 < 1.0


def test_the_checksums_are_ones_a_real_analyser_accepts(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.datagram(T0, "10.0.2.3", 53, 51000, _dns("a.b"))
    w.close()
    for _, eth in _packets(path):
        ip = eth.data
        assert dpkt.in_cksum(bytes(ip)[:20]) == 0
        l4 = ip.data
        pseudo = dpkt.struct.pack(">4s4sxBH", ip.src, ip.dst, ip.p, len(bytes(l4)))
        assert dpkt.in_cksum(pseudo + bytes(l4)) == 0


# --- UDP ------------------------------------------------------------------------------------------------------------


def test_a_udp_exchange_is_a_request_and_an_answer_in_one_flow(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "198.18.0.9", 9999, 40000, b"hello", b"world", proto="udp")
    w.close()
    flow = _flows(path)[0]
    assert flow.proto == "udp"
    assert [(d, p) for _, d, p in flow.packets] == [("c", b"hello"), ("s", b"world")]
    assert (flow.src, flow.dst, flow.dport) == (GUEST, "198.18.0.9", 9999)


def test_an_unknown_transport_is_refused(tmp_path):
    w, _ = _writer(tmp_path)
    with pytest.raises(ValueError):
        w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK, proto="icmp")


# --- a capture that was cut off -------------------------------------------------------------------------------------


def test_what_is_written_is_on_disk_before_the_writer_is_closed(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    report = net_analyze.analyze_pcap(path)             # the process could be killed here; the file is what it is
    assert report["event_summary"].get("http") == 1
    w.close()


def test_a_file_cut_in_the_middle_of_a_packet_still_gives_the_exchange_before_it(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.exchange(T0 + 1, "203.0.113.5", 80, 49201, GET, OK)
    w.close()
    size = os.path.getsize(path)
    with open(path, "r+b") as fh:
        fh.truncate(size - 20)
    report = net_analyze.analyze_pcap(path)
    assert report["event_summary"].get("http") == 2
    assert report["errors"] == []


def test_a_file_cut_before_the_close_still_has_its_request_and_answer(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.close()
    packets = _packets(path)
    keep = len(packets) - 3                              # the close is gone
    out = str(tmp_path / "cut.pcap")
    with open(out, "wb") as fh:
        pw = dpkt.pcap.Writer(fh)
        for ts, eth in packets[:keep]:
            pw.writepkt(bytes(eth), ts=ts)
    assert net_analyze.analyze_pcap(out)["event_summary"].get("http") == 1


# --- conversations that are not one request and one answer --------------------------------------------------------


def _wire(path):
    flow = _flows(path)[0]
    return [(d, p) for _t, d, p in flow.packets]


def test_a_server_that_speaks_first_is_written_server_first(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 25, 49200, [
        ("s", b"220 mail.example ESMTP\r\n"),
        ("c", b"EHLO host\r\n"),
        ("s", b"250 ok\r\n"),
        ("c", b"QUIT\r\n"),
        ("s", b"221 bye\r\n"),
    ])
    w.close()
    assert [d for d, _p in _wire(path)] == ["s", "c", "s", "c", "s"]
    flow = _flows(path)[0]
    assert not flow.client_guessed
    assert flow.client_stream() == b"EHLO host\r\nQUIT\r\n"
    assert flow.server_stream() == b"220 mail.example ESMTP\r\n250 ok\r\n221 bye\r\n"
    assert flow.gaps == []


def test_a_banner_first_protocol_is_read_back_as_smtp(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 25, 49200, [
        ("s", b"220 mail.example ESMTP\r\n"),
        ("c", b"EHLO host\r\n"),
        ("s", b"250 ok\r\n"),
        ("c", b"MAIL FROM:<a@b.example>\r\n"),
        ("s", b"250 ok\r\n"),
        ("c", b"QUIT\r\n"),
        ("s", b"221 bye\r\n"),
    ])
    w.close()
    report = net_analyze.analyze_pcap(path)
    assert report["errors"] == []
    assert report["event_summary"].get("smtp", 0) >= 1


def test_a_handshake_and_what_was_inside_it_are_one_connection(tmp_path):
    hello = b"\x16\x03\x01\x00\x05hello"
    reply = b"\x16\x03\x03\x00\x05reply"
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 443, 49200, [("c", hello), ("s", reply), ("c", GET), ("s", OK)])
    w.close()
    flows = _flows(path)
    assert len(flows) == 1
    assert _wire(path) == [("c", hello), ("s", reply), ("c", GET), ("s", OK)]
    assert flows[0].client_stream() == hello + GET and flows[0].server_stream() == reply + OK
    assert flows[0].gaps == []


def test_a_conversation_is_one_conn_for_the_analysis_however_many_turns_it_had(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 80, 49200, [("c", GET), ("s", OK), ("c", GET), ("s", OK)])
    w.close()
    report = net_analyze.analyze_pcap(path)
    assert report["event_summary"].get("conn") == 1
    assert report["event_summary"].get("http") == 2


def test_the_acknowledgement_after_a_change_of_speaker_covers_what_the_other_said(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 80, 49200, [("s", b"A" * 3000), ("c", b"B" * 10)])
    w.close()
    tcp = [eth.data.data for _, eth in _packets(path)]
    data = [t for t in tcp if t.data]
    first_server, last_server = [t for t in data if t.sport == 80][0], [t for t in data if t.sport == 80][-1]
    client = [t for t in data if t.sport == 49200][0]
    assert client.ack == last_server.seq + len(last_server.data)
    assert client.seq == first_server.ack


def test_turns_of_one_direction_in_a_row_are_one_run_of_bytes(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 80, 49200, [("c", b"GET / HT"), ("c", b"TP/1.1\r\n\r\n"), ("s", b""), ("s", OK)])
    w.close()
    flow = _flows(path)[0]
    assert flow.client_stream() == b"GET / HTTP/1.1\r\n\r\n" and flow.server_stream() == OK
    assert flow.gaps == []


def test_a_conversation_with_no_turns_is_a_handshake_and_a_close(tmp_path):
    w, path = _writer(tmp_path)
    assert w.conversation(T0, "198.18.0.9", 4444, 49200, [])
    w.close()
    flow = _flows(path)[0]
    assert flow.packets == [] and flow.answered and flow.gaps == []


def test_turns_may_be_given_as_a_generator(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 80, 49200, (t for t in [("c", GET), ("s", OK)]))
    w.close()
    assert _wire(path) == [("c", GET), ("s", OK)]


@pytest.mark.parametrize("turns", [[("x", b"a")], [("c",)], ["cs"], [("c", "text")], 5])
def test_turns_that_are_not_turns_are_refused(tmp_path, turns):
    w, _ = _writer(tmp_path)
    with pytest.raises((ValueError, TypeError)):
        w.conversation(T0, "198.18.0.9", 80, 49200, turns)
    assert w.exchanges == 0


def test_the_cut_of_one_direction_leaves_the_other_whole(tmp_path, monkeypatch):
    monkeypatch.setattr(net_pcap, "MAX_STREAM_BYTES", 100)
    monkeypatch.setattr(net_pcap, "MSS", 50)
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 80, 49200, [("s", b"s" * 300), ("c", b"hello"), ("s", b"more"), ("c", b"bye")])
    w.close()
    assert w.truncated == 1
    flow = _flows(path)[0]
    assert flow.client_stream() == b"hellobye"


def test_an_exchange_is_the_same_bytes_as_the_conversation_of_its_two_turns(tmp_path):
    a, pa = _writer(tmp_path, "a.pcap")
    b, pb = _writer(tmp_path, "b.pcap")
    a.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    b.conversation(T0, "203.0.113.5", 80, 49200, [("c", GET), ("s", OK)])
    a.close()
    b.close()
    with open(pa, "rb") as fa, open(pb, "rb") as fb:
        assert fa.read() == fb.read()


def test_a_request_that_was_never_answered_is_in_the_capture(tmp_path):
    # a session stopped while a server waited: the server records what it has, with nothing as the answer
    w, path = _writer(tmp_path)
    assert w.exchange(T0, "203.0.113.5", 80, 49200, GET, b"")
    w.close()
    flow = _flows(path)[0]
    assert flow.client_stream() == GET and flow.server_stream() == b"" and flow.gaps == []
    report = net_analyze.analyze_pcap(path)
    http = [e for e in report["events"] if e["type"] == "http"]
    assert [(e["dest"], e["path"]) for e in http] == [("c2.evil", "/gate.php")]
    assert report["errors"] == []


def test_a_conversation_that_ends_with_the_guest_is_acknowledged_by_the_server(tmp_path):
    w, path = _writer(tmp_path)
    w.conversation(T0, "198.18.0.9", 80, 49200, [("s", b"banner\r\n"), ("c", b"hello\r\n")])
    w.close()
    tcp = [eth.data.data for _, eth in _packets(path)]
    last_client = [t for t in tcp if t.sport == 49200 and t.data][-1]
    acks = [t for t in tcp if t.sport == 80 and not t.data and t.flags == dpkt.tcp.TH_ACK
            and t.ack == last_client.seq + len(last_client.data)]
    assert acks


def test_what_a_conversation_is_made_of_does_not_depend_on_which_thread_came_first(tmp_path):
    calls = [(T0 + n, "203.0.113.%d" % (n + 1), 80, 40000 + n, GET + b"x" * n, OK) for n in range(6)]

    def written(order, name):
        w, path = _writer(tmp_path, name)
        for n in order:
            w.exchange(*calls[n])
        w.close()
        with open(path, "rb") as fh:
            return sorted(buf for _ts, buf in dpkt.pcap.Reader(fh))

    assert written(range(6), "a.pcap") == written(reversed(range(6)), "b.pcap")


def test_a_port_that_comes_round_again_gets_numbers_of_its_own(tmp_path):
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.close()
    syns = [eth.data.data.seq for _, eth in _packets(path) if eth.data.data.flags == dpkt.tcp.TH_SYN]
    assert len(syns) == 2 and syns[0] != syns[1]


# --- what a server may rely on --------------------------------------------------------------------------------------


def test_a_write_after_close_is_dropped_and_counted_not_raised(tmp_path):
    w, path = _writer(tmp_path)
    w.close()
    assert w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK) is False
    assert w.datagram(T0, "10.0.2.3", 53, 51000, b"x") is False
    assert (w.exchanges, w.datagrams, w.dropped) == (0, 0, 2)
    assert net_flows.read_pcap(path).flows == []


def test_counters_say_what_was_written(tmp_path):
    w, _ = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)
    w.exchange(T0, "198.18.0.9", 9999, 40000, b"a", b"b", proto="udp")
    w.datagram(T0, "10.0.2.3", 53, 51000, b"q")
    w.datagram(T0, "10.0.2.3", 53, 51000, b"a", inbound=True)
    w.close()
    assert w.exchanges == 2
    assert w.datagrams == 4                              # the udp exchange's two and these two
    assert w.packets > 10
    assert w.payload_bytes == len(GET) + len(OK) + 2 + 2
    assert w.dropped == 0 and w.truncated == 0


def test_several_servers_writing_at_once_leave_every_conversation_whole(tmp_path):
    w, path = _writer(tmp_path)

    def serve(n):
        for i in range(25):
            request = b"GET /%d/%d HTTP/1.1\r\nHost: c2.evil\r\n\r\n" % (n, i) + b"." * 3000
            w.exchange(T0 + n + i, "203.0.113.5", 80, 40000 + n * 100 + i, request, OK + b"z" * 3000)

    threads = [threading.Thread(target=serve, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    w.close()
    flows = _flows(path)
    assert len(flows) == 200
    assert all(f.gaps == [] and f.server_bytes == len(OK) + 3000 for f in flows)


@pytest.mark.parametrize("args", [
    ("not-an-address", 80, 49200),
    ("2001:db8::1", 80, 49200),
    ("203.0.113.5", 0, 49200),
    ("203.0.113.5", 70000, 49200),
    ("203.0.113.5", 80, -1),
    ("203.0.113.5", 80, 70000),
])
def test_an_address_or_port_that_cannot_be_written_is_refused(tmp_path, args):
    w, _ = _writer(tmp_path)
    with pytest.raises(ValueError):
        w.exchange(T0, args[0], args[1], args[2], GET, OK)
    assert w.exchanges == 0


@pytest.mark.parametrize("ts", [float("nan"), float("inf"), -1.0, "now", None])
def test_a_timestamp_that_is_not_a_time_is_refused(tmp_path, ts):
    w, _ = _writer(tmp_path)
    with pytest.raises((ValueError, TypeError)):
        w.exchange(ts, "203.0.113.5", 80, 49200, GET, OK)
    assert w.exchanges == 0


def test_text_is_not_a_payload(tmp_path):
    w, _ = _writer(tmp_path)
    with pytest.raises(TypeError):
        w.exchange(T0, "203.0.113.5", 80, 49200, "GET / HTTP/1.1", OK)


def test_a_datagram_too_large_for_udp_is_refused(tmp_path):
    w, _ = _writer(tmp_path)
    with pytest.raises(ValueError):
        w.datagram(T0, "10.0.2.3", 53, 51000, b"x" * 70000)


def test_the_guest_address_is_checked_when_the_writer_is_made(tmp_path):
    with pytest.raises(ValueError):
        net_pcap.CaptureWriter(str(tmp_path / "x.pcap"), "guest")
    assert not os.path.exists(str(tmp_path / "x.pcap"))


def test_a_path_that_cannot_be_written_fails_at_the_start_not_at_the_end(tmp_path):
    with pytest.raises(OSError):
        net_pcap.CaptureWriter(str(tmp_path / "no-such-dir" / "x.pcap"), GUEST)


def test_a_failing_disk_stops_the_capture_and_does_not_reach_the_server(tmp_path):
    w, _ = _writer(tmp_path)
    real = w._out

    class Full:
        def write(self, data):
            raise OSError(28, "No space left on device")

        def flush(self):
            pass

        def close(self):
            pass

    w._out = Full()
    assert w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK) is False
    assert "No space" in w.error
    assert w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK) is False
    assert w.dropped == 2
    w.close()
    real.close()


# --- bounds ---------------------------------------------------------------------------------------------------------


def test_a_payload_longer_than_a_reader_keeps_is_cut_one_byte_past_it_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(net_pcap, "MAX_STREAM_BYTES", 1000)
    monkeypatch.setattr(net_pcap, "MSS", 100)
    w, path = _writer(tmp_path)
    monkeypatch.setattr(net_flows, "MAX_STREAM_BYTES", 1000)
    w.exchange(T0, "203.0.113.5", 80, 49200, b"a" * 5000, b"b" * 1500)
    w.close()
    flow = _flows(path)[0]
    assert flow.client_stream() == b"a" * 1000 and flow.server_stream() == b"b" * 1000
    assert flow.capped and flow.gaps == []
    assert w.truncated == 2
    assert w.payload_bytes == 2 * 1001


def test_a_cut_is_in_the_file_for_a_reader_that_never_saw_the_writer(tmp_path):
    # no content-length, no framing: a download of 5 MiB that says nothing about its own size
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, GET, b"\xa5" * (5 * 1024 * 1024))
    w.close()
    result = net_flows.read_pcap(path)
    flow = result.flows[0]
    assert flow.capped
    assert "retention limit" in result.note
    assert len(flow.server_stream()) <= net_flows.MAX_STREAM_BYTES
    assert flow.gaps == []
    assert w.truncated == 1


def test_a_payload_that_just_fits_is_not_reported_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(net_pcap, "MAX_STREAM_BYTES", 1000)
    monkeypatch.setattr(net_pcap, "MSS", 100)
    monkeypatch.setattr(net_flows, "MAX_STREAM_BYTES", 1000)
    w, path = _writer(tmp_path)
    w.exchange(T0, "203.0.113.5", 80, 49200, b"a" * 1000, b"b")
    w.close()
    assert not _flows(path)[0].capped
    assert w.truncated == 0


def test_a_session_of_connections_that_carry_nothing_is_bounded_by_the_flows_the_reader_keeps(tmp_path,
                                                                                              monkeypatch):
    monkeypatch.setattr(net_pcap, "MAX_FLOWS", 5)
    w, path = _writer(tmp_path)
    results = [w.exchange(T0 + i, "203.0.113.5", 445, 40000 + i, b"", b"") for i in range(8)]
    w.close()
    assert results == [True] * 5 + [False] * 3
    assert (w.flows, w.dropped, w.exchanges) == (5, 3, 5)
    assert len(_flows(path)) == 5


def test_a_new_udp_four_tuple_counts_as_a_flow_and_a_known_one_does_not(tmp_path, monkeypatch):
    monkeypatch.setattr(net_pcap, "MAX_FLOWS", 2)
    w, path = _writer(tmp_path)
    assert w.datagram(T0, "10.0.2.3", 53, 51000, b"q1")
    assert w.datagram(T0, "10.0.2.3", 53, 51000, b"a1", inbound=True)      # the same flow
    assert w.datagram(T0, "10.0.2.3", 53, 51001, b"q2")
    assert not w.datagram(T0, "10.0.2.3", 53, 51002, b"q3")                 # a third
    assert w.datagram(T0, "10.0.2.3", 53, 51001, b"q2 again")              # but a known one still goes
    assert not w.exchange(T0, "203.0.113.5", 80, 49200, GET, OK)            # and a TCP one is a new flow
    w.close()
    assert (w.flows, w.dropped) == (2, 2)
    assert len(_flows(path)) == 2


def test_the_limits_of_the_budget_are_the_readers(tmp_path):
    assert net_pcap.MAX_STREAM_BYTES == net_flows.MAX_STREAM_BYTES
    assert net_pcap.MAX_TOTAL_BYTES == net_flows.MAX_TOTAL_BYTES
    assert net_pcap.MAX_FLOWS == net_flows.MAX_FLOWS


def test_a_capture_that_has_reached_its_budget_drops_what_comes_after_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(net_pcap, "MAX_TOTAL_BYTES", 100)
    w, path = _writer(tmp_path)
    assert w.exchange(T0, "203.0.113.5", 80, 49200, b"a" * 60, b"b" * 30) is True
    assert w.exchange(T0 + 1, "203.0.113.5", 80, 49201, b"a" * 60, b"b" * 30) is False
    assert w.datagram(T0 + 2, "10.0.2.3", 53, 51000, b"c" * 20) is False
    assert w.datagram(T0 + 2, "10.0.2.3", 53, 51000, b"c" * 10) is True
    w.close()
    assert w.dropped == 2
    assert len(_flows(path)) == 2


# --- the context every server is given ------------------------------------------------------------------------------


def test_a_context_holds_what_it_was_given_and_does_nothing_else():
    d, ca, w, ops, rec = object(), object(), object(), object(), object()
    ctx = net_pcap.SessionContext(diverter=d, ca=ca, writer=w, ops=ops, recorder=rec,
                                  passthrough=["teamserver.mine"], mode="isolated+passthrough", guest_ip=GUEST)
    assert (ctx.diverter, ctx.ca, ctx.writer, ctx.ops, ctx.recorder) == (d, ca, w, ops, rec)
    assert ctx.passthrough == ["teamserver.mine"]
    assert (ctx.mode, ctx.guest_ip) == ("isolated+passthrough", GUEST)


def test_a_context_made_with_nothing_has_no_services_and_an_empty_allowlist():
    ctx = net_pcap.SessionContext()
    assert (ctx.diverter, ctx.ca, ctx.writer, ctx.ops, ctx.recorder) == (None, None, None, None, None)
    assert list(ctx.passthrough) == []
    assert ctx.mode == "isolated"


def test_two_contexts_do_not_share_an_allowlist():
    a, b = net_pcap.SessionContext(), net_pcap.SessionContext()
    a.passthrough.append("x.mine")
    assert list(b.passthrough) == []
