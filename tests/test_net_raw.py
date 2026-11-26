"""Unknown protocols profiled into ``raw`` events.

Regressions covered:
  * a later phase builds a fingerprint from these values, so a framing that is
    guessed groups unrelated implants together; every detector answers
    "unknown" unless the bytes prove its claim: a length chain must end exactly
    at the end of the stream with no empty message and at least two messages and
    every reading that fits must cut the same messages, a delimiter must end
    the stream, repeat at least three times (six for a non-text byte, which
    must also be far more frequent than a byte of random data is) and two
    detectors that both fit a stream cancel each other out
  * random (encrypted) data ends in a non-printable byte most of the time and
    contains some byte of every kind, so "the last byte is the delimiter" and
    "this prefix happens to fit" claimed framing for every encrypted stream
  * a length read from the capture is attacker-controlled: one that is zero,
    larger than the rest of the stream, 2**32-1, or a chain cut inside its last
    message is contained (no exception, no read past the data, no "framing")
  * a million tiny messages are not a million loop turns or a million-entry
    event: the chain walk and the reported size list are both capped, and
    ``message_count`` says how many were seen
  * TCP segments are not messages (Nagle joins sends, the MSS cuts them), so
    "fixed" is only said for small equal segments that account for the whole
    stream; a bulk transfer cut at the MSS is not fixed-size records
  * integer arrays and zero-padded fixed records are an extremely common shape
    for custom protocols and are not delimited messages: u16/u32 little-endian
    ints and 16-byte records padded with NULs end in 0x00, hold many of them
    and have NUL as the commonest control byte, so they were reported as NUL
    delimited with sizes like [1, 1, 1] or [9, 0, 0, 0, 0, 0, 0, 9]; a
    non-text delimiter now needs messages that are never empty, are not all
    the same size (that is a fixed-width layout) and average at least three
    bytes, and two unrelated implants that both pad with NULs are
    not filed as one shape
  * the entropy of one repeated byte was ``-0.0``, which ``json.dumps`` writes
    as a different text from ``0.0`` and would split one fingerprint in two
  * a UDP datagram is a message, so its sizes are reported as they are
  * a heartbeat is judged from the capture time of each send (``Flow.packets``),
    with the thresholds of ``memory_evidence.beaconing_from_connections`` (the
    same four-beat minimum, robust coefficient of variation of at most 0.5 and
    half the intervals on rhythm), so both feed one evidence model that decides
    the same way; one slow gap does not hide a rhythm, a retransmitted segment
    is not an extra beat, the segments of one send count as one beat, and large
    sends or a steady stream are not a heartbeat
  * the two directions of a conversation have different shapes (a request and
    a reply), so each non-empty direction gets its own event, the client's
    first, and nothing is averaged over both
  * entropy of a few bytes is low however random they are; ``stream_bytes``
    travels with it so a consumer can tell
  * the delimiter was a ``bytes`` value, so ``json.dumps`` of a ``raw`` event
    raised at the report and API boundary; it is text now, written by
    ``net_events.render_bytes``, as DNS names are (a printable byte as itself,
    any other as ``\\DDD`` with its decimal value, so a newline is ``\\010``),
    and every event of every framing kind goes through ``json.dumps``
  * an empty stream, or one whose first segment was lost, produces no event
"""

import json
import os
import random
import socket
import struct
import tempfile

import dpkt
import pytest

import memory_evidence
import net_flows
import net_raw

CLIENT = "192.0.2.10"
SERVER = "198.51.100.7"
CPORT = 49152
SPORT = 4444

_SYN, _ACK, _PSH = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH
_SEGMENT = 60000


# --- building flows -----------------------------------------------------------

def _tcp_frame(src, sport, dst, dport, seq, ack, flags, payload=b""):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF,
                       ack=ack & 0xFFFFFFFF, flags=flags, win=8192, data=payload)
    return _eth(src, dst, dpkt.ip.IP_PROTO_TCP, seg)


def _udp_frame(src, sport, dst, dport, payload):
    dgram = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    dgram.ulen = len(dgram)
    return _eth(src, dst, dpkt.ip.IP_PROTO_UDP, dgram)


def _eth(src, dst, proto, l4):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=proto, ttl=64, data=l4)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _read(packets):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "raw.pcap")
        with open(path, "wb") as fh:
            w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
            for ts, buf in sorted(packets, key=lambda p: p[0]):
                w.writepkt(buf, ts)
        result = net_flows.read_pcap(path)
    assert len(result.flows) == 1, result.note
    return result.flows[0]


def _tcp_packets(segments, drop=()):
    """Frames for ``(ts, "c" | "s", payload)`` sends, with a handshake before them.

    Each send is its own segment (cut at ``_SEGMENT``); ``drop`` lists send
    indices that are never captured, which leaves a hole in the stream.
    """
    ends = {"c": (CLIENT, CPORT, SERVER, SPORT), "s": (SERVER, SPORT, CLIENT, CPORT)}
    isn = {"c": 1000, "s": 5000}
    nxt = {"c": isn["c"] + 1, "s": isn["s"] + 1}
    # the handshake is a second before the first send, or at time 0 (a pcap
    # holds no negative times); _read keeps equal times in the order written
    t0 = max(min(ts for ts, _d, _p in segments) - 1.0, 0.0)
    packets = [
        (t0, _tcp_frame(*ends["c"], isn["c"], 0, _SYN)),
        (t0, _tcp_frame(*ends["s"], isn["s"], isn["c"] + 1, _SYN | _ACK)),
        (t0, _tcp_frame(*ends["c"], isn["c"] + 1, isn["s"] + 1, _ACK)),
    ]
    for index, (ts, direction, payload) in enumerate(segments):
        other = "s" if direction == "c" else "c"
        for i in range(0, len(payload), _SEGMENT):
            part = payload[i:i + _SEGMENT]
            if index not in drop:
                packets.append((ts, _tcp_frame(*ends[direction], nxt[direction],
                                               nxt[other], _ACK | _PSH, part)))
            nxt[direction] += len(part)
    return packets


def _raw_flow(data):
    """A TCP flow where the client sends ``data`` once; empty data sends nothing."""
    return _read(_tcp_packets([(2.0, "c", data)]))


def _raw_flow_timed(items):
    """A TCP flow where the client sends ``(ts, payload)`` at those times."""
    return _read(_tcp_packets([(ts, "c", payload) for ts, payload in items]))


def _flow(segments, **kw):
    return _read(_tcp_packets(segments, **kw))


def _udp_flow(datagrams):
    """A UDP flow of ``(ts, "c" | "s", payload)`` datagrams."""
    ends = {"c": (CLIENT, CPORT, SERVER, SPORT), "s": (SERVER, SPORT, CLIENT, CPORT)}
    return _read([(ts, _udp_frame(*ends[d], payload)) for ts, d, payload in datagrams])


def _noise(n, seed=1):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def _profile(data, **kw):
    events = net_raw.events_from_flow(_flow([(2.0, "c", data)], **kw))
    assert len(events) == 1
    return events[0]


def _beats(times, payload=b"\x01"):
    return _raw_flow_timed([(t, payload) for t in times])


def _event(flow):
    events = net_raw.events_from_flow(flow)
    assert len(events) == 1
    return events[0]


# --- the brief's cases --------------------------------------------------------

def test_a_length_prefixed_stream_is_recognized():
    e = net_raw.events_from_flow(_raw_flow(b"\x00\x03abc\x00\x04defg"))[0]
    assert e["framing"] == "length-prefixed" and e["message_sizes"] == [3, 4]


def test_a_newline_delimited_stream_is_recognized():
    e = net_raw.events_from_flow(_raw_flow(b"one\ntwo\nthree\n"))[0]
    assert e["framing"] == "delimited" and e["delimiter"] == "\\010"


def test_high_entropy_is_reported():
    e = net_raw.events_from_flow(_raw_flow(os.urandom(4096)))[0]
    assert e["entropy"] > 7.5 and e["printable_ratio"] < 0.5


def test_text_traffic_reports_low_entropy_and_high_printability():
    e = net_raw.events_from_flow(_raw_flow(b"hello world " * 200))[0]
    assert e["entropy"] < 5.0 and e["printable_ratio"] > 0.9


def test_regular_small_messages_count_as_a_heartbeat():
    e = net_raw.events_from_flow(_raw_flow_timed([(t * 30.0, b"\x01") for t in range(6)]))[0]
    assert e["heartbeat"] is True and abs(e["interval"] - 30.0) < 1.0


def test_an_empty_stream_produces_no_event():
    assert net_raw.events_from_flow(_raw_flow(b"")) == []


# --- the event ----------------------------------------------------------------

def test_the_event_is_a_raw_event_about_the_server_the_client_talked_to():
    e = _profile(b"\x00\x03abc\x00\x04defg")
    assert e["type"] == "raw" and e["direction"] == "c" and e["proto"] == "tcp"
    assert e["dest"] == SERVER and e["dest_is_ip"] is True and e["port"] == SPORT
    assert e["in_tree"] is False and e["stream_bytes"] == 11
    assert e["message_count"] == 2 and e["client_guessed"] is False


def test_the_event_time_is_the_first_send_of_that_direction():
    e = _event(_flow([(7.5, "c", b"abc"), (9.0, "c", b"def")]))
    assert e["ts"] == 7.5


def test_both_directions_get_an_event_the_clients_first():
    events = net_raw.events_from_flow(_flow([
        (2.0, "c", b"\x00\x03abc\x00\x04defg"),
        (3.0, "s", b"ok\nok\nok\n")]))
    assert [e["direction"] for e in events] == ["c", "s"]
    assert events[0]["framing"] == "length-prefixed"
    assert events[1]["framing"] == "delimited"


def test_a_server_only_stream_gives_one_server_event():
    events = net_raw.events_from_flow(_flow([(3.0, "s", b"ok\nok\nok\n")]))
    assert [e["direction"] for e in events] == ["s"]


def test_a_flow_cut_at_a_hole_reports_the_gap_and_still_profiles_what_came_first():
    e = _event(_flow([(2.0, "c", b"one\ntwo\nthree\n"), (3.0, "c", b"x" * 40),
                      (4.0, "c", b"y" * 40)], drop=(1,)))
    assert e["stream_gaps"] == [40] and e["stream_capped"] is False
    assert e["stream_bytes"] == 14 and e["framing"] == "delimited"


# --- entropy and printable ratio ----------------------------------------------

def test_entropy_is_shannon_bits_per_byte():
    assert _profile(b"\x41" * 100)["entropy"] == 0.0
    assert str(_profile(b"\x41" * 100)["entropy"]) == "0.0"
    assert _profile(bytes(range(256)))["entropy"] == 8.0
    assert _profile(b"ab" * 50)["entropy"] == 1.0


def test_printable_ratio_counts_text_bytes_and_ordinary_whitespace():
    e = _profile(b"abcd\t\r\n" + b"\x00\x01\x02\xff" * 2 + b"\x7f")
    assert e["printable_ratio"] == pytest.approx(7 / 16, abs=1e-3)


def test_entropy_of_a_short_stream_comes_with_its_size():
    e = _profile(_noise(20))
    assert e["entropy"] < 4.4 and e["stream_bytes"] == 20


# --- length-prefixed ----------------------------------------------------------

def test_a_four_byte_big_endian_prefix_is_recognized():
    data = b"\x00\x00\x00\x05hello\x00\x00\x00\x02hi"
    e = _profile(data)
    assert e["framing"] == "length-prefixed" and e["message_sizes"] == [5, 2]


def test_a_little_endian_prefix_is_recognized():
    e = _profile(b"\x03\x00\x00\x00abc\x04\x00\x00\x00defg\x01\x00\x00\x00z")
    assert e["framing"] == "length-prefixed" and e["message_sizes"] == [3, 4, 1]
    e = _profile(b"\x03\x00abc\x04\x00defg")
    assert e["framing"] == "length-prefixed" and e["message_sizes"] == [3, 4]


def test_one_message_is_not_enough_to_call_a_stream_length_prefixed():
    assert _profile(b"\x00\x03abc")["framing"] == "unknown"


def test_a_chain_that_does_not_end_at_the_end_of_the_stream_is_not_framing():
    assert _profile(b"\x00\x03abc\x00\x04def")["framing"] == "unknown"
    assert _profile(b"\x00\x03abc\x00\x04defgX")["framing"] == "unknown"


@pytest.mark.parametrize("data", [
    b"\x00\x00\x00\x00\x00\x00",                    # empty messages
    b"\x00\x03abc\x00\x00\x00\x03abc",              # one of them empty
    b"\xff\xff\xff\xff" + b"a" * 64,                # 2**32 - 1
    b"\xff\xff" + b"a" * 64,                        # 65535 against 64 bytes
    b"\x00\x00\xff\xff" + b"a" * 64,
    b"\x7f\xff\xff\xff" + b"a" * 64,
])
def test_a_length_that_does_not_fit_the_stream_gives_no_framing(data):
    e = _profile(data)
    assert e["framing"] == "unknown" and e["message_sizes"] == []


def test_random_data_is_never_called_length_prefixed_or_delimited():
    for seed in range(200):
        e = _profile(_noise(64 + seed, seed))
        assert e["framing"] in ("unknown", "fixed"), seed
    for seed in range(50):
        assert _profile(_noise(4096, seed))["framing"] == "unknown", seed


def test_a_huge_chain_is_walked_to_a_bound_and_reported_to_a_bound():
    data = b"\x00\x01a" * 100000
    e = _profile(data)
    assert e["framing"] == "length-prefixed"
    assert len(e["message_sizes"]) == net_raw.MAX_REPORTED
    assert e["message_count"] == net_raw.MAX_CHAIN
    assert e["stream_bytes"] == 300000


def test_two_prefix_readings_that_cut_different_messages_are_unknown():
    # fits as 2-byte little endian [3, 7] and as 4-byte little endian [3, 3]
    data = b"\x03\x00\x00\x00\x00\x07\x00\x03\x00\x00\x00\x03\x05\x03"
    assert _profile(data)["framing"] == "unknown"


def test_two_byte_orders_that_cut_the_same_messages_are_not_a_conflict():
    data = (b"\x01\x01" + b"a" * 257) * 2
    e = _profile(data)
    assert e["framing"] == "length-prefixed" and e["message_sizes"] == [257, 257]


def test_a_stream_two_detectors_both_fit_is_unknown():
    # a 2-byte little endian chain of "abcdef\x00" bodies ([7, 7, 7]), and also
    # \x00 delimited into "\x07", "abcdef", "\x07", "abcdef", ...
    data = b"\x07\x00abcdef\x00" * 3
    assert net_raw._length_prefixed(data) == ([7, 7, 7], 3)
    e = _profile(data)
    assert e["framing"] == "unknown" and e["delimiter"] is None


# --- delimited ----------------------------------------------------------------

def test_crlf_lines_report_a_crlf_delimiter():
    e = _profile(b"USER bob\r\nPASS x\r\nQUIT\r\n")
    assert e["framing"] == "delimited" and e["delimiter"] == "\\013\\010"
    assert e["message_sizes"] == [8, 6, 4] and e["message_count"] == 3


def test_a_lone_newline_inside_crlf_text_keeps_newline_as_the_delimiter():
    e = _profile(b"a\r\nb\nc\n")
    assert e["delimiter"] == "\\010" and e["message_sizes"] == [2, 1, 1]


def test_long_text_lines_are_delimited_whatever_their_length():
    e = _profile((b"{" + b'"k": "v", ' * 40 + b"}\n") * 4)
    assert e["framing"] == "delimited" and e["delimiter"] == "\\010"
    assert e["message_count"] == 4


def test_a_null_terminated_message_stream_is_delimited():
    e = _profile(b"\x01ab\x00\x02cde\x00\x03f\x00" * 2)
    assert e["framing"] == "delimited" and e["delimiter"] == "\\000"
    assert e["message_sizes"] == [3, 4, 2, 3, 4, 2]


def test_a_binary_delimiter_needs_six_occurrences_and_text_lines_three():
    assert _profile(b"\x01ab\x00\x02cde\x00\x03f\x00")["framing"] == "unknown"


def test_integer_arrays_are_not_nul_delimited_messages():
    for pack in ("<H", "<I", ">H", ">I", "<Q"):
        for n in (2, 6, 39, 200):
            data = b"".join(struct.pack(pack, i) for i in range(1, n))
            assert _profile(data)["framing"] != "delimited", (pack, n)
    e = _profile(b"".join(struct.pack("<H", i) for i in range(1, 40)))
    assert e["framing"] == "unknown" and e["delimiter"] is None and e["message_sizes"] == []


def test_nul_padded_fixed_records_are_not_nul_delimited_messages():
    record = b"id:\x07abcde" + b"\x00" * 7
    assert len(record) == 16
    for n in (2, 6, 40):
        e = _profile(record * n)
        assert e["framing"] == "unknown" and e["delimiter"] is None, n


def test_equal_sized_fields_ending_in_a_control_byte_are_not_delimited_messages():
    # u32 little endian values below 2**24: three bytes and a NUL, every time
    data = b"".join(struct.pack("<I", 0x112233 + i * 0x010101) for i in range(10))
    assert _profile(data)["framing"] == "unknown"
    assert _profile(b"abcd\x00" * 7)["framing"] == "unknown"
    assert _profile(b"abcd\x00" * 6 + b"abcde\x00")["framing"] == "delimited"


def test_a_binary_delimiter_needs_messages_that_are_never_empty():
    two = b"abcd\x00abcde\x00"
    assert _profile(two * 4)["delimiter"] == "\\000"
    assert _profile(two * 3 + b"\x00" + two * 3)["framing"] == "unknown"
    assert _profile(b"\x00" + two * 4)["framing"] == "unknown"


def test_a_binary_delimiter_needs_messages_of_three_bytes_on_average():
    assert _profile(b"ab\x00abc\x00" * 7)["framing"] == "unknown"
    assert _profile(b"abc\x00abcd\x00" * 7)["framing"] == "delimited"
    assert _profile(b"a\x00" * 7 + b"abcdefghijklmnopq\x00" * 2 + b"b\x00" * 7)["framing"] == "delimited"


def test_text_lines_may_still_include_blank_lines():
    e = _profile(b"HELO a\n\nMAIL b\n\nQUIT\n")
    assert e["framing"] == "delimited" and e["message_sizes"] == [6, 0, 6, 0, 4]


def test_a_run_of_delimiters_is_padding_not_messages():
    assert _profile(b"\x00" * 6)["framing"] == "unknown"
    assert _profile(b"\n" * 10)["framing"] == "unknown"


def test_a_delimiter_must_end_the_stream_and_repeat_three_times():
    assert _profile(b"one\ntwo\nthree")["framing"] == "unknown"
    assert _profile(b"one\ntwo\n")["framing"] == "unknown"
    assert _profile(b"hello world " * 200)["framing"] == "unknown"


def test_random_data_that_happens_to_end_in_a_control_byte_is_not_delimited():
    for last in (b"\x00", b"\n", b"\x03", b"\xff"):
        assert _profile(_noise(4096, 3) + last)["framing"] == "unknown"


def test_a_control_byte_that_is_not_the_most_common_one_is_not_the_delimiter():
    assert _profile(b"\x01" * 10 + b"abc\x03" * 6)["framing"] == "unknown"
    assert _profile(b"\x01" * 5 + b"abc\x03" * 6)["framing"] == "delimited"


def test_the_delimiter_scan_and_the_report_are_bounded():
    e = _profile(b"a\n" * 200000)
    assert e["framing"] == "delimited" and e["message_count"] == 200000
    assert len(e["message_sizes"]) == net_raw.MAX_REPORTED


# --- fixed --------------------------------------------------------------------

def test_equal_small_sends_are_fixed_size_records():
    e = _event(_flow([(t, "c", _noise(16, t)) for t in (2.0, 3.0, 4.0, 5.0)]))
    assert e["framing"] == "fixed" and e["message_sizes"] == [16, 16, 16, 16]
    assert e["delimiter"] is None and e["message_count"] == 4


def test_two_equal_sends_are_not_enough():
    e = _event(_flow([(2.0, "c", _noise(16, 2)), (3.0, "c", _noise(16, 3))]))
    assert e["framing"] == "unknown"


def test_sends_of_different_size_are_not_fixed():
    e = _event(_flow([(2.0, "c", _noise(16, 2)), (3.0, "c", _noise(16, 3)),
                      (4.0, "c", _noise(17, 4))]))
    assert e["framing"] == "unknown" and e["message_sizes"] == []


def test_equal_mss_sized_segments_of_a_bulk_transfer_are_not_fixed_records():
    e = _event(_flow([(t, "c", _noise(1460, t)) for t in (2.0, 3.0, 4.0, 5.0)]))
    assert e["framing"] == "unknown"


def test_fixed_is_not_claimed_when_the_segments_do_not_account_for_the_stream():
    e = _event(_flow([(t, "c", _noise(16, t)) for t in (2.0, 3.0, 4.0, 5.0)], drop=(1,)))
    assert e["framing"] == "unknown"


# --- UDP ----------------------------------------------------------------------

def test_udp_datagrams_are_the_messages():
    e = _event(_udp_flow([(2.0, "c", b"\x01abc"), (3.0, "c", b"\x02de"),
                          (4.0, "c", b"\x03fghi")]))
    assert e["proto"] == "udp" and e["client_guessed"] is True
    assert e["framing"] == "unknown" and e["message_sizes"] == [4, 3, 5]
    assert e["message_count"] == 3 and e["stream_bytes"] == 12


def test_equal_udp_datagrams_are_fixed_and_a_beacon_of_them_is_a_heartbeat():
    e = _event(_udp_flow([(t * 20.0, "c", _noise(24, t)) for t in range(5)]))
    assert e["framing"] == "fixed" and e["message_sizes"] == [24] * 5
    assert e["heartbeat"] is True and abs(e["interval"] - 20.0) < 0.1


# --- heartbeat ----------------------------------------------------------------

def test_a_jittery_rhythm_is_still_a_heartbeat():
    e = _event(_beats([0, 30, 61, 88, 121, 150]))
    assert e["heartbeat"] is True and 29.0 <= e["interval"] <= 31.0


def test_irregular_traffic_is_not_a_heartbeat():
    e = _event(_beats([0, 1, 10, 11, 60, 200, 201]))
    assert e["heartbeat"] is False and e["interval"] is None


def test_three_beats_are_too_few_for_a_rhythm():
    assert _event(_beats([0, 30, 60]))["heartbeat"] is False


def test_beats_that_are_mostly_off_the_rhythm_are_not_a_heartbeat():
    # intervals 7 7 7 13 13 13 10: robust CoV 0.44 passes, but only one of
    # seven is within 25% of the median of 10
    times = [0, 7, 14, 21, 34, 47, 60, 70]
    e = _event(_beats(times))
    assert e["heartbeat"] is False and e["interval"] is None
    assert memory_evidence.beaconing_from_connections(
        [(t, SERVER, SPORT) for t in times]) == []


def test_one_slow_gap_does_not_hide_the_rhythm():
    e = _event(_beats([0, 30, 60, 90, 120, 420, 450, 480]))
    assert e["heartbeat"] is True and e["interval"] == 30.0


def test_the_segments_of_one_send_are_one_beat():
    flow = _raw_flow_timed([(t, b"\x01") for ts in range(0, 150, 30)
                            for t in (ts, ts + 0.05)])
    e = _event(flow)
    assert e["heartbeat"] is True and e["interval"] == 30.0


def test_one_burst_is_not_a_rhythm():
    e = _event(_beats([i * 0.1 for i in range(12)]))
    assert e["heartbeat"] is False


def test_a_steady_stream_of_close_packets_is_not_a_heartbeat():
    e = _event(_beats([i * 0.3 for i in range(200)]))
    assert e["heartbeat"] is False


def test_large_regular_sends_are_not_a_heartbeat():
    e = _event(_beats([t * 30.0 for t in range(6)], payload=b"x" * 2000))
    assert e["heartbeat"] is False and e["interval"] is None


def test_a_retransmitted_segment_is_not_an_extra_beat():
    packets = _tcp_packets([(t, "c", b"\x01" + bytes([i])) for i, t in
                            enumerate([0.0, 100.0, 107.0, 200.0, 300.0, 400.0])])
    # repeat the segment sent at 100.0 at 107.0 as a retransmission: it
    # would be an interval of 7s if the flow counted it as a message
    seg = [p for p in packets if p[0] == 100.0][0]
    packets.append((107.0, seg[1]))
    e = _event(_read(packets))
    assert e["heartbeat"] is True and e["interval"] == 100.0


@pytest.mark.parametrize("times", [
    [0, 30, 60, 90, 120, 150],
    [0, 30, 61, 88, 121, 150],
    [0, 30, 60, 90, 120, 420, 450, 480],
    [0, 1, 10, 11, 60, 200, 201],
    [0, 30, 60],
    [0, 10, 40, 41, 100, 400, 410],
    [0, 60, 125, 180, 250, 300, 370, 420],
    [0, 5, 100, 105, 200, 205, 300, 305],
    [0, 7, 14, 21, 34, 47, 60, 70],
])
def test_the_rhythm_verdict_matches_the_projects_beaconing_judgement(times):
    expected = bool(memory_evidence.beaconing_from_connections(
        [(t, SERVER, SPORT) for t in times]))
    assert _event(_beats(times))["heartbeat"] is expected


def test_the_thresholds_are_the_ones_of_the_beaconing_judgement():
    assert net_raw.BEACON_MIN_CONNECTIONS == memory_evidence.BEACON_MIN_CONNECTIONS
    assert net_raw.BEACON_MAX_COV == memory_evidence.BEACON_MAX_COV
    assert net_raw.BEACON_MIN_INTERVAL_S == memory_evidence.BEACON_MIN_INTERVAL_S


# --- the event is JSON --------------------------------------------------------

def test_the_delimiter_is_written_by_the_shared_byte_rendering():
    assert _profile(b"a\nb\nc\n")["delimiter"] == "\\010"
    assert _profile(b"a\r\nb\r\nc\r\n")["delimiter"] == "\\013\\010"
    assert _profile(b"\x01ab\xff\x01abc\xff" * 4)["delimiter"] == "\\255"


_EVERY_FRAMING = {
    # name: (flow, framing of the first event)
    "length-prefixed": (lambda: _flow([(2.0, "c", b"\x00\x03abc\x00\x04defg")]), "length-prefixed"),
    "delimited": (lambda: _flow([(2.0, "c", b"one\ntwo\nthree\n")]), "delimited"),
    "delimited-binary": (lambda: _flow([(2.0, "c", b"\x01ab\x00\x02cde\x00\x03f\x00" * 2)]),
                         "delimited"),
    "fixed": (lambda: _flow([(t, "c", _noise(16, t)) for t in (2.0, 3.0, 4.0)]), "fixed"),
    "unknown": (lambda: _flow([(2.0, "c", _noise(512)), (3.0, "s", b"\x00\xff")]), "unknown"),
    "udp": (lambda: _udp_flow([(2.0, "c", b"\x01abc"), (3.0, "s", b"\x02de")]), "unknown"),
    "heartbeat": (lambda: _beats([0, 30, 60, 90, 120]), "fixed"),
}


@pytest.mark.parametrize("kind", sorted(_EVERY_FRAMING))
def test_a_complete_raw_event_of_every_framing_kind_goes_through_json_dumps(kind):
    make, framing = _EVERY_FRAMING[kind]
    events = net_raw.events_from_flow(make())
    assert events and events[0]["framing"] == framing
    for e in events:
        assert json.loads(json.dumps(e))["type"] == "raw"
        assert not any(isinstance(v, (bytes, bytearray)) for v in e.values())
