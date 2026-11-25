"""HTTP streams to ``http``, ``download``, ``upload`` and ``websocket`` events.

Regressions covered:
  * a stream out of a pcap is routinely incomplete, and a parser written for
    whole messages raised on it; here a cut request, a cut response and garbage
    after a good message each leave the earlier events intact
  * a body that ran out because a segment was lost (or the capture ended, or
    the retention cap cut the stream) was reported as a complete short body, so
    a reader could not tell "empty" from "missing"; ``request_truncated`` /
    ``response_truncated`` say so, ``stream_gaps`` / ``stream_capped`` give the
    cause, and a download cut short is flagged and not presented as the file
  * every request on a keep-alive connection carried the flow's first
    timestamp, so beacon intervals measured from the events came out as zero;
    each event takes the time of the packet its request began in, also when
    segments were captured out of order
  * header names were folded to one case (or lookups were case sensitive), so
    the header order that feeds the fingerprint lost its case, or
    ``headers["User-Agent"]`` and ``headers["user-agent"]`` disagreed
  * duplicate headers vanished from ``header_order``
  * the first sender was trusted as the client: a capture that begins with the
    server's response made the server look like the requester
  * a HEAD response (or 204, 304, 1xx) was read as having a body and swallowed
    the next response on the connection
  * a response to a CONNECT was parsed as HTTP although a tunnel follows
  * a body was kept whole, so one 2 GB download became one 2 GB string; the
    text is capped and ``body_capped`` / ``resp_capped`` say it was
  * binary bodies were decoded as Latin-1 (which accepts every byte) and
    delivered as text to the rules and the decoder
  * a UTF-8 character cut by the text cap turned the whole body into binary
  * a masked WebSocket frame was read unmasked, a 16/64-bit length as 7-bit, a
    fragmented message as several, and a refused upgrade as a WebSocket
  * messages of the two directions were listed one direction after the other
    instead of in the order they happened
  * a download hash was taken over a body that the stream cap had cut and
    looked like the hash of the real file
  * a gzip or deflate body (most of the real web, and malware too) had no
    text, so what the C2 sent back stayed unreadable; the raw-deflate and
    zlib-wrapped forms servers mislabel in both directions are read as well
  * a decompression bomb (a few hundred bytes that expand to gigabytes) was
    allowed to allocate its output; inflating stops at ``MAX_INFLATED`` and
    the body says it was cut
  * a compressed body cut by the capture, or corrupt, took the event down or
    passed for an empty one; the event is kept with the raw size and
    ``body_decode_failed`` / ``resp_decode_failed``
  * text cut by the inflate ceiling (or by a stream that broke) split a
    multi-byte character, and the whole body was then decoded as Latin-1 and
    delivered garbled ("aÃ©", "ä¸­"); the cut is not an error, whichever cap
    made it
  * a gzipped PE that the capture held only part of produced no ``download``
    event at all, so the one fact a later phase needs (a PE was fetched from
    this URL) was lost; it is reported with its kind and no hash
  * an encoding the module cannot undo (br, zstd) was treated as if it had
    been undone, or the body was dropped, instead of being left as it was
  * many small decompression bombs in one capture each inflated into the
    hash up to ``MAX_HASHED``, so the parser hashed about a thousand times
    the bytes the capture retained; a ``HashBudget`` passed in by the caller
    bounds the total over every flow it is given to, and a download past it
    says so (``hash_budget_spent``) instead of carrying a hash
  * a Host header was decoded as UTF-8 or else Latin-1, so the same name
    reached ``net_analyze`` as different characters depending on its other
    bytes and got another spelling than in DNS and TLS; ``dest`` and ``url``
    keep the bytes (``surrogateescape``) for the central rendering
"""

import gzip
import hashlib
import os
import random
import socket
import tempfile
import tracemalloc
import zlib

import dpkt
import pytest

import net_events
import net_flows
import net_http

CLIENT = "192.0.2.10"
SERVER = "198.51.100.7"
CPORT = 49152
SPORT = 80

_SYN, _ACK, _PSH = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH
_SEGMENT = 60000


def _frame(src, sport, dst, dport, seq, ack, flags, payload=b""):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF,
                       ack=ack & 0xFFFFFFFF, flags=flags, win=8192, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=seg)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _flow_from(segments, syn=True, drop=(), order=None, cport=CPORT):
    """Write the segments to a pcap, read it back, return the single flow.

    ``segments`` is a list of ``(ts, "c" | "s", payload)``, each one message of
    the stream in logical order. ``drop`` lists indices of segments that are
    never captured (their sequence space is still used, which leaves a hole),
    ``order`` the indices in the order they are written (out-of-order capture),
    ``syn=False`` a capture that begins mid-connection. Going through
    ``read_pcap`` means the parser is fed what the real reader produces.
    """
    ends = {"c": (CLIENT, cport, SERVER, SPORT), "s": (SERVER, SPORT, CLIENT, cport)}
    isn = {"c": 1000, "s": 5000}
    nxt = {"c": isn["c"] + 1, "s": isn["s"] + 1}
    built = []
    for ts, direction, payload in segments:
        frames = []
        for i in range(0, len(payload), _SEGMENT):
            part = payload[i:i + _SEGMENT]
            other = "s" if direction == "c" else "c"
            frames.append((ts, _frame(*ends[direction], nxt[direction], nxt[other],
                                      _ACK | _PSH, part)))
            nxt[direction] += len(part)
        built.append(frames)
    packets = []
    if syn:
        t0 = min(ts for ts, _d, _p in segments) - 1.0 if segments else 0.0
        packets += [
            (t0, _frame(*ends["c"], isn["c"], 0, _SYN)),
            (t0 + 0.1, _frame(*ends["s"], isn["s"], isn["c"] + 1, _SYN | _ACK)),
            (t0 + 0.2, _frame(*ends["c"], isn["c"] + 1, isn["s"] + 1, _ACK)),
        ]
    for index in (order if order is not None else range(len(built))):
        if index not in drop:
            packets += built[index]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "http.pcap")
        with open(path, "wb") as fh:
            w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
            for ts, buf in packets:
                w.writepkt(buf, ts)
        result = net_flows.read_pcap(path)
    assert len(result.flows) == 1, result.note
    return result.flows[0]


def _http_flow(request, response, **kw):
    segments = []
    if request:
        segments.append((1.0, "c", request))
    if response:
        segments.append((2.0, "s", response))
    return _flow_from(segments, **kw)


def _ws_frame(payload, opcode=1, masked=False, fin=True):
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    mbit = 0x80 if masked else 0
    if n < 126:
        head += bytes([mbit | n])
    elif n < 65536:
        head += bytes([mbit | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([mbit | 127]) + n.to_bytes(8, "big")
    if masked:
        key = b"\x01\x02\x03\x04"
        head += key
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return head + payload


def _events(request, response, kind="http", **kw):
    evs = net_http.events_from_flow(_http_flow(request, response, **kw))
    return [e for e in evs if e["type"] == kind]


def _get(path=b"/", host=b"x.top", extra=b""):
    return b"GET " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n" + extra + b"\r\n"


def _ok(body=b"", extra=b""):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\n" + extra + b"\r\n" + body)


# --- the contract from the brief --------------------------------------------

def test_a_get_becomes_an_event_with_path_and_user_agent():
    e = net_http.events_from_flow(_http_flow(
        b"GET /gate.php?id=7 HTTP/1.1\r\nHost: evil.top\r\nUser-Agent: curl/8\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))[0]
    assert e["method"] == "GET" and e["path"] == "/gate.php"
    assert e["query"] == "id=7" and e["ua"] == "curl/8"
    assert e["dest"] == "evil.top" and e["status"] == 200


def test_header_order_is_preserved():
    e = net_http.events_from_flow(_http_flow(
        b"GET / HTTP/1.1\r\nHost: a.top\r\nAccept: */*\r\nUser-Agent: x\r\n\r\n", b""))[0]
    assert e["header_order"] == ["Host", "Accept", "User-Agent"]


def test_a_post_form_exposes_its_field_names():
    e = net_http.events_from_flow(_http_flow(
        b"POST /api HTTP/1.1\r\nHost: evil.top\r\nContent-Length: 15\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\nhwid=A1&os=win",
        b"HTTP/1.1 200 OK\r\n\r\n"))[0]
    assert sorted(e["form_names"]) == ["hwid", "os"]


def test_two_requests_on_one_keep_alive_connection_become_two_events():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /a HTTP/1.1\r\nHost: x.top\r\n\r\nGET /b HTTP/1.1\r\nHost: x.top\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
    assert [e["path"] for e in evs if e["type"] == "http"] == ["/a", "/b"]
    assert [e["status"] for e in evs if e["type"] == "http"] == [200, 404]


def test_a_chunked_response_body_is_joined():
    e = net_http.events_from_flow(_http_flow(
        b"GET / HTTP/1.1\r\nHost: x.top\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n"))[0]
    assert e["resp_text"] == "abcdefg"


def test_an_executable_response_becomes_a_download_event():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /s.dll HTTP/1.1\r\nHost: evil.top\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMZ\x90\x00"))
    d = [e for e in evs if e["type"] == "download"][0]
    assert d["kind"] == "pe" and d["size"] == 4 and len(d["sha256"]) == 64


def test_a_large_request_body_becomes_an_upload_event():
    evs = net_http.events_from_flow(_http_flow(
        b"POST /up HTTP/1.1\r\nHost: evil.top\r\nContent-Length: 600\r\n\r\n" + b"x" * 600,
        b"HTTP/1.1 200 OK\r\n\r\n"))
    assert [e["type"] for e in evs if e["type"] == "upload"] == ["upload"]


def test_a_response_without_a_request_is_still_reported():
    evs = net_http.events_from_flow(_http_flow(b"", b"HTTP/1.1 200 OK\r\n\r\nhi"))
    assert evs and evs[0]["method"] == ""


def test_a_websocket_upgrade_and_its_frames_become_websocket_events():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n\r\n"
        + _ws_frame(b"ping"),
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        + _ws_frame(b"pong")))
    ws = [e for e in evs if e["type"] == "websocket"]
    assert ws and ws[0]["dest"] == "c2.top"
    assert [m["text"] for m in ws[0]["messages"]] == ["ping", "pong"]


def test_a_websocket_frame_with_binary_payload_is_kept_as_bytes():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n\r\n"
        + _ws_frame(b"\xff\x00\xfe", opcode=2),
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n"))
    m = [e for e in evs if e["type"] == "websocket"][0]["messages"][0]
    assert m["text"] is None and m["size"] == 3


# --- the event shape ---------------------------------------------------------

def test_events_are_net_events_and_carry_the_whole_http_shape():
    e = _events(_get(b"/a?b=1"), _ok(b"hi", b"Content-Type: text/plain\r\n"))[0]
    assert isinstance(e, net_events.NetEvent)
    assert e["in_tree"] is False and e["dest_is_ip"] is False and e["port"] == SPORT
    assert e["url"] == "http://x.top/a?b=1"
    assert (e["body_text"], e["body_bytes"], e["form_names"]) == ("", 0, [])
    assert (e["resp_text"], e["resp_bytes"], e["content_type"]) == ("hi", 2, "text/plain")


def test_header_lookups_are_case_insensitive_and_order_keeps_the_original_case():
    e = _events(_get(extra=b"uSeR-aGeNt: abc\r\nX-Token: 1\r\n"), b"")[0]
    assert e["header_order"] == ["Host", "uSeR-aGeNt", "X-Token"]
    assert e["headers"]["User-Agent"] == "abc" == e["headers"]["user-agent"]
    assert "USER-AGENT" in e["headers"] and e["headers"].get("X-TOKEN") == "1"
    assert e["headers"].get("missing") is None and "missing" not in e["headers"]
    assert e["ua"] == "abc"


def test_a_repeated_header_stays_in_the_order_twice_and_its_values_join():
    e = _events(_get(extra=b"Cookie: a=1\r\nAccept: x\r\nCookie: b=2\r\n"), b"")[0]
    assert e["header_order"] == ["Host", "Cookie", "Accept", "Cookie"]
    assert e["headers"]["cookie"] == "a=1, b=2"


def test_response_headers_are_on_the_event_like_the_request_headers():
    e = _events(_get(), _ok(b"x", b"sEt-CoOkIe: sid=1\r\nSet-Cookie: t=2\r\nX-Token: abc\r\n"))[0]
    assert e["resp_headers"]["Set-Cookie"] == "sid=1, t=2" == e["resp_headers"]["set-cookie"]
    assert e["resp_headers"].get("X-TOKEN") == "abc" and "x-token" in e["resp_headers"]
    assert e["resp_headers"]["content-length"] == "1"
    assert e["headers"]["host"] == "x.top" and "set-cookie" not in e["headers"]
    assert _events(_get(), b"")[0]["resp_headers"] == {}


def test_a_folded_header_line_continues_the_previous_header():
    e = _events(_get(extra=b"X-Long: first\r\n  second\r\n"), b"")[0]
    assert e["headers"]["x-long"] == "first second"
    assert e["header_order"] == ["Host", "X-Long"]


def test_bare_line_feeds_are_accepted():
    e = _events(b"GET /lf HTTP/1.1\nHost: x.top\n\n", b"HTTP/1.1 200 OK\nContent-Length: 1\n\nz")[0]
    assert e["path"] == "/lf" and e["resp_text"] == "z"


def test_the_destination_is_the_host_header_without_port_and_in_lower_case():
    e = _events(_get(host=b"Evil.TOP:8080"), b"")[0]
    assert e["dest"] == "evil.top" and e["dest_is_ip"] is False and e["port"] == SPORT
    assert e["url"] == "http://evil.top:8080/"


def test_without_a_host_header_the_destination_is_the_server_address():
    e = _events(b"GET / HTTP/1.0\r\n\r\n", b"")[0]
    assert e["dest"] == SERVER and e["dest_is_ip"] is True


def test_a_bare_ip_host_is_flagged_as_an_ip():
    e = _events(_get(host=b"203.0.113.9"), b"")[0]
    assert e["dest"] == "203.0.113.9" and e["dest_is_ip"] is True


def test_an_absolute_form_request_target_gives_the_path_and_query():
    e = _events(b"GET http://proxy.top/p/q?z=1 HTTP/1.1\r\nHost: proxy.top\r\n\r\n", b"")[0]
    assert (e["path"], e["query"], e["url"]) == ("/p/q", "z=1", "http://proxy.top/p/q?z=1")


def test_a_custom_method_with_a_version_is_still_http():
    e = _events(b"BEACON /x HTTP/1.1\r\nHost: x.top\r\n\r\n", b"")[0]
    assert e["method"] == "BEACON"


def test_a_request_without_a_response_has_no_status():
    e = _events(_get(), b"")[0]
    assert e["status"] is None and e["resp_text"] == "" and e["resp_bytes"] == 0
    assert e["content_type"] == "" and e["response_truncated"] is False


# --- time ---------------------------------------------------------------------

def test_each_request_takes_the_time_of_its_own_packet():
    flow = _flow_from([(10.0, "c", _get(b"/a")), (10.1, "s", _ok()),
                       (40.0, "c", _get(b"/b")), (40.1, "s", _ok()),
                       (70.0, "c", _get(b"/c")), (70.1, "s", _ok())])
    evs = net_http.events_from_flow(flow)
    assert [e["ts"] for e in evs] == [10.0, 40.0, 70.0]


def test_the_time_is_right_when_segments_were_captured_out_of_order():
    flow = _flow_from([(10.0, "c", _get(b"/a")), (40.0, "c", _get(b"/b")),
                       (41.0, "s", _ok() + _ok())], order=[1, 0, 2])
    assert [(e["path"], e["ts"]) for e in net_http.events_from_flow(flow)] \
        == [("/a", 10.0), ("/b", 40.0)]


def test_a_request_split_over_segments_takes_the_time_of_its_first():
    flow = _flow_from([(5.0, "c", b"GET /split HTTP/1.1\r\nHo"),
                       (6.0, "c", b"st: x.top\r\n\r\n")])
    e = net_http.events_from_flow(flow)[0]
    assert e["path"] == "/split" and e["ts"] == 5.0


# --- truncation is visible ----------------------------------------------------

def test_a_complete_exchange_is_not_flagged():
    e = _events(_get(), _ok(b"abc"))[0]
    assert e["request_truncated"] is False and e["response_truncated"] is False
    assert e["stream_gaps"] == [] and e["stream_capped"] is False


def test_a_response_body_cut_by_a_lost_segment_is_flagged_not_short():
    body = b"B" * 100
    response = _ok(body)
    head = len(response) - 100
    flow = _flow_from([(1.0, "c", _get()), (2.0, "s", response[:head + 40]),
                       (2.1, "s", response[head + 40:head + 70]),
                       (2.2, "s", response[head + 70:])], drop=[2])
    e = net_http.events_from_flow(flow)[0]
    assert e["resp_bytes"] == 40 and e["resp_text"] == "B" * 40
    assert e["response_truncated"] is True and e["request_truncated"] is False
    assert e["stream_gaps"] == [30]


def test_a_request_body_cut_by_a_lost_segment_is_flagged():
    request = (b"POST /p HTTP/1.1\r\nHost: x.top\r\nContent-Length: 100\r\n\r\n" + b"R" * 100)
    head = len(request) - 100
    flow = _flow_from([(1.0, "c", request[:head + 40]), (1.1, "c", request[head + 40:head + 70]),
                       (1.2, "c", request[head + 70:])], drop=[1])
    e = net_http.events_from_flow(flow)[0]
    assert e["body_bytes"] == 40 and e["request_truncated"] is True
    assert e["stream_gaps"] == [30]


def test_a_body_that_runs_to_the_end_of_the_connection_is_flagged_only_if_data_is_missing():
    whole = net_http.events_from_flow(_http_flow(_get(), b"HTTP/1.0 200 OK\r\n\r\n" + b"z" * 50))[0]
    assert whole["resp_bytes"] == 50 and whole["response_truncated"] is False
    flow = _flow_from([(1.0, "c", _get()), (2.0, "s", b"HTTP/1.0 200 OK\r\n\r\n" + b"z" * 20),
                       (2.1, "s", b"z" * 10), (2.2, "s", b"z" * 20)], drop=[2])
    cut = net_http.events_from_flow(flow)[0]
    assert cut["resp_bytes"] == 20 and cut["response_truncated"] is True
    assert cut["stream_gaps"] == [10]


def test_a_stream_that_ends_inside_the_body_is_flagged_without_any_gap():
    e = _events(_get(), b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"q" * 10)[0]
    assert e["resp_bytes"] == 10 and e["response_truncated"] is True
    assert e["stream_gaps"] == []


def test_a_chunked_body_without_its_last_chunk_is_flagged():
    e = _events(_get(), b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"4\r\nabcd\r\n3\r\nef")[0]
    assert e["resp_text"] == "abcdef" and e["response_truncated"] is True


def test_a_request_cut_inside_its_headers_is_still_an_event_and_flagged():
    e = _events(b"GET /cut?a=1 HTTP/1.1\r\nHost: x.top\r\nUser-Ag", b"")[0]
    assert e["path"] == "/cut" and e["dest"] == "x.top"
    assert e["request_truncated"] is True and e["header_order"] == ["Host"]


def test_a_response_cut_inside_its_headers_is_flagged():
    e = _events(_get(), b"HTTP/1.1 200 OK\r\nContent-Ty")[0]
    assert e["status"] == 200 and e["response_truncated"] is True


def test_a_download_cut_short_is_flagged_and_sized_by_what_was_seen():
    body = b"MZ" + b"\x90" * 98
    response = _ok(body)
    flow = _flow_from([(1.0, "c", _get(b"/a.exe")), (2.0, "s", response[:len(response) - 60])])
    d = [e for e in net_http.events_from_flow(flow) if e["type"] == "download"][0]
    assert d["truncated"] is True and d["size"] == 40
    assert d["sha256"] == hashlib.sha256(body[:40]).hexdigest()


def test_a_complete_download_is_not_flagged_and_hashes_the_body():
    body = b"\x7fELF" + bytes(range(60))
    d = _events(_get(b"/a"), _ok(body), kind="download")[0]
    assert d["truncated"] is False and d["kind"] == "elf" and d["size"] == len(body)
    assert d["sha256"] == hashlib.sha256(body).hexdigest()
    assert d["dest"] == "x.top" and d["url"] == "http://x.top/a"


# --- caps ---------------------------------------------------------------------

def test_a_long_text_body_is_kept_only_to_the_cap_and_says_so():
    n = net_http.MAX_BODY_TEXT + 5000
    e = _events(_get(), _ok(b"a" * n))[0]
    assert e["resp_bytes"] == n and len(e["resp_text"]) == net_http.MAX_BODY_TEXT
    assert e["resp_capped"] is True and e["response_truncated"] is False


def test_a_text_body_under_the_cap_is_not_flagged():
    e = _events(_get(), _ok(b"a" * 100))[0]
    assert e["resp_capped"] is False and e["body_capped"] is False


def test_a_character_cut_by_the_text_cap_does_not_make_the_body_binary():
    # the leading byte puts the cut in the middle of a two-byte character
    text = ("a" + "\u00e9" * (net_http.MAX_BODY_TEXT // 2 + 10)).encode("utf-8")
    e = _events(_get(), _ok(text))[0]
    assert e["resp_capped"] is True and e["resp_text"] == "a" + "\u00e9" * (net_http.MAX_BODY_TEXT // 2 - 1)


def test_a_request_body_over_the_cap_is_capped_too():
    n = net_http.MAX_BODY_TEXT + 1
    e = _events(b"POST /p HTTP/1.1\r\nHost: x.top\r\nContent-Length: %d\r\n\r\n" % n
                + b"k" * n, b"")[0]
    assert e["body_bytes"] == n and e["body_capped"] is True
    assert len(e["body_text"]) == net_http.MAX_BODY_TEXT


def test_a_download_larger_than_the_stream_cap_is_flagged_and_the_event_stays_small():
    size = net_flows.MAX_STREAM_BYTES + 100000
    body = b"MZ" + b"\x00" * (size - 2)
    evs = net_http.events_from_flow(_http_flow(_get(b"/big"), _ok(body)))
    http = [e for e in evs if e["type"] == "http"][0]
    d = [e for e in evs if e["type"] == "download"][0]
    assert http["stream_capped"] is True and http["response_truncated"] is True
    assert d["truncated"] is True and d["size"] < size
    assert d["sha256"] != hashlib.sha256(body).hexdigest()
    assert http["resp_text"] is None and http["resp_bytes"] == d["size"]


# --- bodies as text -----------------------------------------------------------

def test_a_binary_body_has_no_text_but_a_size():
    e = _events(_get(), _ok(b"\xff\x00\xfe\x01\x02\x03"))[0]
    assert e["resp_text"] is None and e["resp_bytes"] == 6


def test_a_utf8_body_is_text_and_a_latin1_body_is_text():
    assert _events(_get(), _ok("caf\u00e9".encode("utf-8")))[0]["resp_text"] == "caf\u00e9"
    assert _events(_get(), _ok(b"caf\xe9"))[0]["resp_text"] == "caf\u00e9"


def test_random_bytes_are_not_delivered_as_latin1_text():
    blob = random.Random(7).getrandbits(8 * 400).to_bytes(400, "little")
    assert _events(_get(), _ok(blob))[0]["resp_text"] is None


def test_a_request_body_is_text_for_the_decoder():
    e = _events(b"POST /p HTTP/1.1\r\nHost: x.top\r\nContent-Length: 12\r\n\r\ndGVzdC1ib2R5", b"")[0]
    assert e["body_text"] == "dGVzdC1ib2R5" and e["body_bytes"] == 12


# --- forms ---------------------------------------------------------------------

def test_form_names_are_decoded_unique_and_kept_in_order():
    body = b"a%5B0%5D=1&b=&a%5B0%5D=2&c+d=3"
    e = _events(b"POST /f HTTP/1.1\r\nHost: x.top\r\nContent-Type: Application/X-WWW-Form-Urlencoded"
                b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body, b"")[0]
    assert e["form_names"] == ["a[0]", "b", "c d"]


def test_multipart_field_names_are_listed_and_filenames_are_not_taken_for_names():
    body = (b'--XyZ\r\nContent-Disposition: form-data; name="hwid"\r\n\r\nA1\r\n'
            b'--XyZ\r\nContent-Disposition: form-data; name="doc"; filename="n.txt"\r\n'
            b'Content-Type: text/plain\r\n\r\nhello\r\n--XyZ--\r\n')
    e = _events(b"POST /m HTTP/1.1\r\nHost: x.top\r\nContent-Type: multipart/form-data; boundary=XyZ"
                b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body, b"")[0]
    assert e["form_names"] == ["hwid", "doc"]


def test_a_json_body_has_no_form_names():
    body = b'{"a=b": 1}'
    e = _events(b"POST /j HTTP/1.1\r\nHost: x.top\r\nContent-Type: application/json"
                b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body, b"")[0]
    assert e["form_names"] == [] and e["body_text"] == '{"a=b": 1}'


# --- framing ------------------------------------------------------------------

def test_chunk_extensions_and_trailers_are_skipped():
    e = _events(_get(), b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"4;ext=1\r\nabcd\r\nA\r\n0123456789\r\n0\r\nX-Trailer: 1\r\n\r\n")[0]
    assert e["resp_text"] == "abcd0123456789" and e["response_truncated"] is False


def test_a_response_after_a_chunked_one_is_still_paired():
    evs = _events(_get(b"/1") + _get(b"/2"),
                  b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                  + _ok(b"second"))
    assert [(e["path"], e["resp_text"]) for e in evs] == [("/1", "abc"), ("/2", "second")]


def test_a_malformed_chunk_size_ends_the_message_and_is_flagged():
    e = _events(_get(), b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"3\r\nabc\r\nzz\r\nrest")[0]
    assert e["resp_text"] == "abc" and e["response_truncated"] is True


def test_a_head_response_has_no_body_and_does_not_swallow_the_next_response():
    evs = _events(b"HEAD /h HTTP/1.1\r\nHost: x.top\r\n\r\n" + _get(b"/n"),
                  b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n" + _ok(b"next"))
    assert [(e["method"], e["status"], e["resp_bytes"]) for e in evs] \
        == [("HEAD", 200, 0), ("GET", 200, 4)]


def test_204_and_304_have_no_body_even_with_a_length():
    evs = _events(_get(b"/1") + _get(b"/2") + _get(b"/3"),
                  b"HTTP/1.1 204 No Content\r\n\r\n"
                  b"HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n" + _ok(b"end"))
    assert [(e["status"], e["resp_bytes"]) for e in evs] == [(204, 0), (304, 0), (200, 3)]


def test_an_interim_100_continue_is_not_the_final_response():
    evs = _events(b"POST /p HTTP/1.1\r\nHost: x.top\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi",
                  b"HTTP/1.1 100 Continue\r\n\r\n" + _ok(b"done"))
    assert len(evs) == 1 and evs[0]["status"] == 200 and evs[0]["resp_text"] == "done"


def test_extra_responses_without_requests_are_reported_with_an_empty_method():
    evs = _events(_get(b"/a"), _ok(b"1") + _ok(b"2"))
    assert [(e["method"], e["resp_text"]) for e in evs] == [("GET", "1"), ("", "2")]


def test_a_connect_request_ends_http_parsing_because_a_tunnel_follows():
    evs = net_http.events_from_flow(_http_flow(
        b"CONNECT evil.top:443 HTTP/1.1\r\nHost: evil.top:443\r\n\r\n\x16\x03\x01\x02\x00GET / HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x03\x00\x50"))
    assert [(e["type"], e["method"], e["status"]) for e in evs] == [("http", "CONNECT", 200)]


def test_a_content_length_that_is_not_a_number_is_ignored():
    e = _events(b"POST /p HTTP/1.1\r\nHost: x.top\r\nContent-Length: abc\r\n\r\n" + _get(b"/n"), b"")
    assert [x["path"] for x in e] == ["/p", "/n"]


# --- not http, and damaged streams --------------------------------------------

def test_a_flow_that_is_not_http_gives_no_events():
    assert net_http.events_from_flow(_http_flow(b"\x16\x03\x01\x00\xa5\x01\x00", b"\x16\x03\x03\x00\x30")) == []


def test_a_udp_flow_gives_no_events():
    class Udp:
        proto = "udp"
    assert net_http.events_from_flow(Udp()) == []


def test_garbage_after_a_good_exchange_keeps_the_good_events():
    evs = _events(_get(b"/ok") + b"\x00\x01\x02 not http at all", _ok(b"fine"))
    assert [(e["path"], e["resp_text"]) for e in evs] == [("/ok", "fine")]


def test_a_capture_that_begins_with_the_response_does_not_make_the_server_the_client():
    flow = _flow_from([(2.0, "s", b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")], syn=False)
    # the reader can only guess: the first sender is taken for the client
    assert flow.client_guessed and flow.src == SERVER
    e = net_http.events_from_flow(flow)[0]
    assert e["method"] == "" and e["resp_text"] == "abc"
    assert e["dest"] == SERVER and e["port"] == SPORT


def test_events_survive_arbitrary_bytes_after_a_valid_start():
    rnd = random.Random(1234)
    heads = [b"GET /x HTTP/1.1\r\nHost: a.top\r\n", b"HTTP/1.1 200 OK\r\n",
             b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
             b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"]
    for i in range(60):
        junk = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 300)))
        request = heads[i % 4] + junk
        response = (b"HTTP/1.1 101 Switching Protocols\r\n\r\n" if i % 4 == 3
                    else b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") + junk
        for ev in net_http.events_from_flow(_http_flow(request, response)):
            assert ev["type"] in net_events.EVENT_TYPES


# --- looks_like_http ----------------------------------------------------------

def test_looks_like_http_accepts_requests_and_responses():
    for stream in (b"GET / HTTP/1.1\r\n", b"POST /a HTTP/1.0\r\n", b"HTTP/1.1 200 OK\r\n",
                   b"HTTP/1.0 404 Not Found", b"GET /cut", b"BEACON /x HTTP/1.1\r\n"):
        assert net_http.looks_like_http(stream), stream


def test_looks_like_http_rejects_everything_else():
    for stream in (b"", b"\x16\x03\x01\x00\xa5", b"get / HTTP/1.1\r\n",
                   b"SSH-2.0-OpenSSH_9\r\n", b"HTTP/", b"HTTPX/1.1 200 OK", b"\x00GET / HTTP/1.1",
                   b"220 smtp.example.com ESMTP\r\n", b"BEACON /x"):
        assert not net_http.looks_like_http(stream), stream


# --- downloads and uploads ----------------------------------------------------

def test_file_kinds_are_told_by_their_first_bytes():
    cases = [(b"MZ\x90\x00\x03", "pe"), (b"\x7fELF\x02\x01", "elf"),
             (b"PK\x03\x04\x14\x00", "zip"), (b"%PDF-1.7\n", "pdf")]
    for body, kind in cases:
        d = _events(_get(), _ok(body), kind="download")
        assert [x["kind"] for x in d] == [kind], body


def test_an_ordinary_response_is_not_a_download():
    for body in (b"", b"<html>MZ</html>", b"PKI is not a zip", b"just text", b"\x89PNG\r\n"):
        assert _events(_get(), _ok(body), kind="download") == [], body


def test_a_sentence_that_begins_like_a_pe_or_a_pdf_is_not_a_download():
    # "MZ" and "%PDF" are printable: text may start with them. net_decode already
    # refuses them as files when the bytes read as text; the download event must too.
    for body in (b"MZ-Berlin weekly report: the numbers for the week are in the sheet",
                 b"MZ is how a DOS executable begins, and this page explains the header",
                 b"%PDF is the first word of a PDF, and this is a note about the format"):
        assert _events(_get(), _ok(body), kind="download") == [], body


def test_a_pe_or_a_pdf_with_binary_content_is_still_a_download():
    pe = b"MZ\x90\x00\x03\x00\x00\x00\x04" + bytes(range(256)) * 4
    pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n" + bytes(range(256)) * 4
    for body, kind in ((pe, "pe"), (pdf, "pdf")):
        assert [x["kind"] for x in _events(_get(), _ok(body), kind="download")] == [kind]


def _plain_pe(lfanew, pad=0):
    """A PE written in bytes below 0x80 (an ASCII stub, an ASCII "code" section)."""
    head = bytearray(b"MZ" + b"A" * 0x3A)
    head[0x3C:0x40] = lfanew.to_bytes(4, "little")
    return (bytes(head) + b"A" * (lfanew - 0x40) + b"PE\x00\x00" + b"L\x01\x02\x00" + b"B" * 200
            + b"A" * pad)


def test_a_pe_cannot_hide_as_text_by_being_written_in_plain_bytes():
    far = _plain_pe(0x10000)                 # e_lfanew beyond the 64 KiB the text check reads
    padded = _plain_pe(0x80, pad=70000)      # header right, then 64 KiB of letters
    for body in (far, padded):
        assert net_events.is_readable_text(body)          # it does read as text...
        assert [x["kind"] for x in _events(_get(), _ok(body), kind="download")] == ["pe"]


def test_text_beginning_mz_is_not_made_a_pe_by_the_header_check():
    sentence = b"MZ-Berlin weekly report: the numbers for the week are in the sheet."
    utf16 = b"MZ" + "Wochenbericht: die Zahlen der Woche stehen im Blatt".encode("utf-16-le")
    lying = bytearray(sentence * 4)            # a plausible e_lfanew with no PE\0\0 behind it
    lying[0x3C:0x40] = (0x40).to_bytes(4, "little")
    for body in (sentence, utf16, sentence * 3, bytes(lying)):
        assert _events(_get(), _ok(body), kind="download") == [], body


def test_an_ordinary_pe_is_still_a_pe():
    pe = bytearray(b"MZ\x90\x00" + bytes(range(256)) * 4)
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\x00\x00"
    assert [x["kind"] for x in _events(_get(), _ok(bytes(pe)), kind="download")] == ["pe"]
    assert net_http._kind(b"MZ\x90\x00\x03") == "pe"          # a stub with no header at all


def test_a_pdf_written_in_ascii_is_still_a_pdf_and_a_paragraph_about_one_is_not():
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
           b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n"
           b"trailer\n<< /Root 1 0 R >>\n%%EOF\n")
    cut = pdf[:pdf.index(b"endobj")]                       # capture ended inside an object
    tail_only = b"%PDF-1.4\n" + b"x" * 3000 + b"\n%%EOF\n"
    for body in (pdf, cut, tail_only):
        assert [x["kind"] for x in _events(_get(), _ok(body), kind="download")] == ["pdf"], body
    prose = b"%PDF is the header of a PDF; an object is introduced by a pair of numbers."
    assert _events(_get(), _ok(prose), kind="download") == []


def test_an_upload_that_begins_like_a_sentence_has_no_file_kind():
    body = b"MZ-Berlin weekly report: " + b"the numbers for the week are in the sheet. " * 20
    up = _events(b"POST /u HTTP/1.1\r\nHost: x.top\r\nContent-Length: %d\r\n\r\n" % len(body) + body,
                 _ok(b"ok"), kind="upload")
    assert [u["kind"] for u in up] == [""]


def test_a_download_event_names_its_origin_and_type():
    d = _events(_get(b"/s.dll"), _ok(b"MZ\x90\x00", b"Content-Type: application/octet-stream\r\n"),
                kind="download")[0]
    assert d["content_type"] == "application/octet-stream" and d["path"] == "/s.dll"
    assert d["ts"] == 2.0 and d["port"] == SPORT


def test_a_download_after_a_head_request_comes_from_the_right_response():
    evs = _events(b"HEAD /h HTTP/1.1\r\nHost: x.top\r\n\r\n" + _get(b"/f"),
                  b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" + _ok(b"MZ\x90\x00"),
                  kind="download")
    assert len(evs) == 1 and evs[0]["path"] == "/f"


def test_the_upload_threshold_is_above_512_bytes():
    def uploads(n):
        return _events(b"POST /u HTTP/1.1\r\nHost: x.top\r\nContent-Length: %d\r\n\r\n" % n
                       + b"u" * n, b"", kind="upload")
    assert uploads(512) == [] and len(uploads(513)) == 1


def test_an_upload_event_describes_the_request_body():
    body = b"PK\x03\x04" + b"z" * 600
    u = _events(b"POST /u?x=1 HTTP/1.1\r\nHost: x.top\r\nContent-Type: application/zip"
                b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body, b"", kind="upload")[0]
    assert u["size"] == len(body) and u["sha256"] == hashlib.sha256(body).hexdigest()
    assert u["kind"] == "zip" and u["truncated"] is False and u["method"] == "POST"
    assert u["url"] == "http://x.top/u?x=1" and u["dest"] == "x.top" and u["ts"] == 1.0


def test_a_transfer_names_the_address_it_was_sent_to_whatever_its_host_header_says():
    """The Host header is the sample's claim; the connection is where the bytes went.

    Regressions covered: an upload with ``Host: ocsp.digicert.com`` to a C2
    address carried only the claimed name, so nothing about the C2 address
    (Sysmon's beacon to it) could ever be matched to it.
    """
    body = b"u" * 600
    u = _events(b"POST /u HTTP/1.1\r\nHost: ocsp.digicert.com\r\nContent-Length: %d\r\n\r\n"
                % len(body) + body, b"", kind="upload")[0]
    assert u["dest"] == "ocsp.digicert.com" and u["addresses"] == [SERVER]
    pe = b"MZ\x90\x00\x03\x00\x00\x00\x04" + bytes(range(256)) * 4
    d = _events(_get(host=b"ocsp.digicert.com"), _ok(pe), kind="download")[0]
    assert d["dest"] == "ocsp.digicert.com" and d["addresses"] == [SERVER]


def test_an_upload_cut_short_is_still_reported_and_flagged():
    request = b"POST /u HTTP/1.1\r\nHost: x.top\r\nContent-Length: 900\r\n\r\n" + b"u" * 700
    u = _events(request, b"", kind="upload")[0]
    assert u["truncated"] is True and u["size"] == 700


# --- websocket ----------------------------------------------------------------

_UPGRADE = (b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: k\r\n\r\n")
_SWITCH = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"


def _ws_events(client_frames, server_frames, **kw):
    evs = net_http.events_from_flow(_http_flow(_UPGRADE + client_frames, _SWITCH + server_frames, **kw))
    return [e for e in evs if e["type"] == "websocket"]


def test_the_upgrade_request_is_also_an_http_event():
    evs = net_http.events_from_flow(_http_flow(_UPGRADE + _ws_frame(b"a"), _SWITCH + _ws_frame(b"b")))
    http = [e for e in evs if e["type"] == "http"]
    assert [(e["path"], e["status"]) for e in http] == [("/ws", 101)]


def test_client_frames_are_unmasked_and_directions_are_named():
    ws = _ws_events(_ws_frame(b"secret", masked=True), _ws_frame(b"reply"))[0]
    assert [(m["direction"], m["text"], m["size"]) for m in ws["messages"]] \
        == [("c", "secret", 6), ("s", "reply", 5)]


def test_long_frames_use_their_extended_lengths():
    mid, big = b"m" * 300, b"b" * 70000
    ws = _ws_events(_ws_frame(mid, masked=True), _ws_frame(big))[0]
    assert [m["size"] for m in ws["messages"]] == [300, 70000]
    assert ws["messages"][0]["text"] == "m" * 300


def test_a_fragmented_message_is_one_message_and_control_frames_are_not_messages():
    ws = _ws_events(
        _ws_frame(b"hel", opcode=1, fin=False) + _ws_frame(b"", opcode=9)
        + _ws_frame(b"lo ", opcode=0, fin=False) + _ws_frame(b"wor", opcode=0, fin=True)
        + _ws_frame(b"", opcode=8),
        b"")[0]
    assert [(m["text"], m["size"]) for m in ws["messages"]] == [("hello wor", 9)]


def test_messages_are_listed_in_the_order_they_happened():
    flow = _flow_from([
        (1.0, "c", _UPGRADE), (1.1, "s", _SWITCH),
        (2.0, "c", _ws_frame(b"q1")), (2.5, "s", _ws_frame(b"a1")),
        (3.0, "c", _ws_frame(b"q2")), (3.5, "s", _ws_frame(b"a2"))])
    ws = [e for e in net_http.events_from_flow(flow) if e["type"] == "websocket"][0]
    assert [(m["text"], m["ts"]) for m in ws["messages"]] \
        == [("q1", 2.0), ("a1", 2.5), ("q2", 3.0), ("a2", 3.5)]


def test_the_websocket_event_names_the_upgrade():
    ws = _ws_events(_ws_frame(b"a"), b"")[0]
    assert ws["url"] == "http://c2.top/ws" and ws["path"] == "/ws" and ws["port"] == SPORT
    assert ws["ts"] == 1.0 and ws["truncated"] is False and ws["messages_capped"] is False


def test_a_refused_upgrade_is_not_a_websocket():
    evs = net_http.events_from_flow(_http_flow(
        _UPGRADE, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno"))
    assert [e["type"] for e in evs] == ["http"]
    assert evs[0]["status"] == 200 and evs[0]["resp_text"] == "no"


def test_an_upgrade_that_was_never_answered_is_only_an_http_event():
    evs = net_http.events_from_flow(_http_flow(_UPGRADE + _ws_frame(b"x", masked=True), b""))
    assert [e["type"] for e in evs] == ["http"]


def test_a_cut_websocket_frame_is_flagged():
    cut = _ws_frame(b"abcdefgh")[:-5]
    ws = _ws_events(b"", _ws_frame(b"ok") + cut)[0]
    assert ws["truncated"] is True
    assert [m["text"] for m in ws["messages"]] == ["ok", "abc"]
    assert ws["messages"][1]["truncated"] is True and ws["messages"][1]["size"] == 8


def test_websocket_messages_are_capped_and_say_so():
    n = net_http.MAX_WS_MESSAGES + 3
    ws = _ws_events(b"", b"".join(_ws_frame(b"m") for _ in range(n)))[0]
    assert len(ws["messages"]) == net_http.MAX_WS_MESSAGES and ws["messages_capped"] is True


def test_ws_frames_reads_frames_from_a_bare_stream():
    stream = _ws_frame(b"one", masked=True) + _ws_frame(b"\x00\x01", opcode=2) + _ws_frame(b"", opcode=8)
    frames = net_http.ws_frames(stream)
    assert [(f["opcode"], f["fin"], f["payload"], f["size"]) for f in frames] \
        == [(1, True, b"one", 3), (2, True, b"\x00\x01", 2), (8, True, b"", 0)]
    assert [f["truncated"] for f in frames] == [False, False, False]


def test_ws_frames_stops_at_a_reserved_opcode_and_at_nonsense():
    good = _ws_frame(b"ok")
    assert [f["payload"] for f in net_http.ws_frames(good + b"\x85\x00" + good)] == [b"ok"]
    assert net_http.ws_frames(b"") == [] and net_http.ws_frames(b"\x81") == []
    assert net_http.ws_frames(b"\x81\x7f" + b"\xff" * 8 + b"x") == []


# --- content encoding ---------------------------------------------------------

_TEXT = b'{"cmd": "sleep", "arg": 30, "pad": "' + b"abcdefgh" * 40 + b'"}'


def _raw_deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


def _encoded(body, coding):
    return _ok(body, b"Content-Encoding: " + coding + b"\r\n")


def test_a_gzipped_response_is_read_as_text():
    wire = gzip.compress(_TEXT)
    for coding in (b"gzip", b"x-gzip", b"GZIP"):
        e = _events(_get(), _encoded(wire, coding))[0]
        assert e["resp_text"] == _TEXT.decode(), coding
        assert e["resp_bytes"] == len(wire) and e["resp_capped"] is False
        assert e["resp_decode_failed"] is False and e["content_encoding"] == coding.decode().lower()


def test_a_zlib_wrapped_deflate_response_is_read_as_text():
    e = _events(_get(), _encoded(zlib.compress(_TEXT), b"deflate"))[0]
    assert e["resp_text"] == _TEXT.decode() and e["resp_decode_failed"] is False


def test_a_raw_deflate_response_without_the_zlib_header_is_read_as_text():
    e = _events(_get(), _encoded(_raw_deflate(_TEXT), b"deflate"))[0]
    assert e["resp_text"] == _TEXT.decode() and e["resp_decode_failed"] is False


def test_a_mislabelled_encoding_is_still_read():
    assert _events(_get(), _encoded(zlib.compress(_TEXT), b"gzip"))[0]["resp_text"] == _TEXT.decode()
    assert _events(_get(), _encoded(_raw_deflate(_TEXT), b"gzip"))[0]["resp_text"] == _TEXT.decode()
    assert _events(_get(), _encoded(gzip.compress(_TEXT), b"deflate"))[0]["resp_text"] == _TEXT.decode()


def test_a_gzipped_request_body_is_read_for_text_and_form_names():
    wire = gzip.compress(b"hwid=A1&os=win")
    e = _events(b"POST /f HTTP/1.1\r\nHost: x.top\r\nContent-Encoding: gzip\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n"
                % len(wire) + wire, b"")[0]
    assert e["body_text"] == "hwid=A1&os=win" and e["form_names"] == ["hwid", "os"]
    assert e["body_bytes"] == len(wire) and e["request_encoding"] == "gzip"
    assert e["body_decode_failed"] is False and e["content_encoding"] == ""


def test_stacked_encodings_are_undone_in_reverse_order():
    wire = gzip.compress(zlib.compress(_TEXT))
    e = _events(_get(), _encoded(wire, b"deflate, gzip"))[0]
    assert e["resp_text"] == _TEXT.decode() and e["content_encoding"] == "deflate, gzip"


def test_a_gzip_stream_of_several_members_and_trailing_padding_is_one_body():
    wire = gzip.compress(b"first ") + gzip.compress(b"second") + b"\x00" * 8
    e = _events(_get(), _encoded(wire, b"gzip"))[0]
    assert e["resp_text"] == "first second" and e["resp_decode_failed"] is False


def test_a_decompression_bomb_stops_at_the_ceiling_and_never_allocates_the_output():
    bomb = gzip.compress(b"\x00" * (64 * 1024 * 1024), 9)
    assert len(bomb) < 100000
    flow = _http_flow(_get(), _encoded(bomb, b"gzip"))
    tracemalloc.start()
    try:
        e = net_http.events_from_flow(flow)[0]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024
    assert e["resp_capped"] is True and e["resp_decode_failed"] is False
    assert e["resp_bytes"] == len(bomb)
    text = _events(_get(), _encoded(gzip.compress(b"t" * (net_http.MAX_INFLATED + 10)), b"gzip"))[0]
    assert len(text["resp_text"]) == net_http.MAX_INFLATED and text["resp_capped"] is True


def test_a_bomb_in_a_request_body_is_stopped_too():
    bomb = zlib.compress(b"\x00" * (32 * 1024 * 1024), 9)
    e = _events(b"POST /b HTTP/1.1\r\nHost: x.top\r\nContent-Encoding: deflate\r\n"
                b"Content-Length: %d\r\n\r\n" % len(bomb) + bomb, b"")[0]
    assert e["body_capped"] is True and e["body_bytes"] == len(bomb)


def test_a_body_below_the_ceiling_that_inflates_completely_is_not_flagged():
    text = b"y" * (net_http.MAX_INFLATED)
    e = _events(_get(), _encoded(gzip.compress(text), b"gzip"))[0]
    assert e["resp_capped"] is False and len(e["resp_text"]) == len(text)


def test_a_truncated_gzip_body_keeps_the_event_and_marks_decoding_failed():
    original = b"".join(b"record %d: value %d\n" % (i, i * i) for i in range(400))
    wire = gzip.compress(original)[:120]
    e = _events(_get(), _encoded(wire, b"gzip"))[0]
    assert e["status"] == 200 and e["resp_bytes"] == 120
    assert e["resp_decode_failed"] is True and e["response_truncated"] is False
    assert e["resp_text"] and original.decode().startswith(e["resp_text"])


def test_corrupt_compressed_data_gives_no_text_and_marks_decoding_failed():
    wire = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + bytes(range(7, 200))
    e = _events(_get(), _encoded(wire, b"gzip"))[0]
    assert e["resp_decode_failed"] is True and e["resp_text"] is None
    assert e["resp_bytes"] == len(wire)
    e = _events(_get(), _encoded(b"this is not deflate at all", b"deflate"))[0]
    assert e["resp_decode_failed"] is True and e["resp_text"] is None


def test_a_wire_cut_compressed_body_is_flagged_on_both_counts():
    wire = gzip.compress(b"z" * 5000 + b"tail")
    e = _events(_get(), b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n"
                % len(wire) + wire[:30])[0]
    assert e["response_truncated"] is True and e["resp_decode_failed"] is True
    assert e["resp_bytes"] == 30


def test_an_unknown_content_encoding_leaves_the_body_as_it_is():
    e = _events(_get(), _encoded(b"plain words", b"br"))[0]
    assert e["resp_text"] == "plain words" and e["resp_decode_failed"] is False
    assert e["content_encoding"] == "br"
    e = _events(_get(), _encoded(gzip.compress(_TEXT), b"gzip, br"))[0]
    assert e["resp_text"] is None and e["resp_decode_failed"] is False


def test_identity_and_missing_encodings_change_nothing():
    for extra in (b"Content-Encoding: identity\r\n", b""):
        e = _events(_get(), _ok(b"hello", extra))[0]
        assert e["resp_text"] == "hello" and e["resp_decode_failed"] is False
    assert e["content_encoding"] == "" and e["request_encoding"] == ""


def test_an_empty_body_with_an_encoding_is_empty_not_failed():
    e = _events(b"HEAD /h HTTP/1.1\r\nHost: x.top\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 40\r\n\r\n")[0]
    assert e["resp_text"] == "" and e["resp_decode_failed"] is False and e["content_encoding"] == "gzip"


# --- downloads of encoded bodies ----------------------------------------------

_PE = b"MZ\x90\x00\x03" + bytes(range(256)) * 8


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def test_a_gzipped_pe_is_a_pe_download_hashed_as_the_file():
    wire = gzip.compress(_PE)
    d = _events(_get(b"/stage2"), _encoded(wire, b"gzip"), kind="download")[0]
    assert d["kind"] == "pe" and d["sha256"] == _sha(_PE) and d["size"] == len(_PE)
    assert d["wire_sha256"] == _sha(wire) != d["sha256"]
    assert d["wire_size"] == len(wire) != d["size"]
    assert d["inflate_capped"] is False and d["content_encoding"] == "gzip"
    assert d["truncated"] is False and d["path"] == "/stage2"


def test_the_same_payload_with_and_without_gzip_has_the_same_file_hash():
    plain = _events(_get(), _ok(_PE), kind="download")[0]
    for coding, wire in ((b"gzip", gzip.compress(_PE)), (b"deflate", zlib.compress(_PE)),
                         (b"deflate", _raw_deflate(_PE)), (b"deflate, gzip", gzip.compress(zlib.compress(_PE)))):
        d = _events(_get(), _encoded(wire, coding), kind="download")[0]
        assert d["sha256"] == plain["sha256"] and d["size"] == plain["size"], coding


def test_an_uncompressed_download_has_no_wire_fields():
    d = _events(_get(), _ok(_PE), kind="download")[0]
    assert d["sha256"] == _sha(_PE) and d["size"] == len(_PE) and d["kind"] == "pe"
    assert "wire_sha256" not in d and "wire_size" not in d
    assert d["inflate_capped"] is False and d["content_encoding"] == ""


_MIB = 1024 * 1024


def test_a_gzipped_payload_above_the_text_ceiling_still_gets_its_file_hash():
    big = b"MZ" + b"\x00" * (4 * _MIB)
    wire = gzip.compress(big)
    d = _events(_get(), _encoded(wire, b"gzip"), kind="download")[0]
    assert d["kind"] == "pe" and d["sha256"] == _sha(big) and d["size"] == len(big)
    assert d["inflate_capped"] is False
    assert d["wire_sha256"] == _sha(wire) and d["wire_size"] == len(wire)


def test_the_retained_text_keeps_its_own_smaller_cap_beside_the_big_hash():
    # a zip: its magic is not printable text, so the readable body below does not
    # turn it into a sentence (a body that begins "%PDF" and reads as text is not a PDF)
    big = b"PK\x03\x04" + b"a" * (3 * _MIB)
    wire = gzip.compress(big)
    evs = net_http.events_from_flow(_http_flow(_get(), _encoded(wire, b"gzip")))
    http = [e for e in evs if e["type"] == "http"][0]
    d = [e for e in evs if e["type"] == "download"][0]
    assert len(http["resp_text"]) == net_http.MAX_BODY_TEXT and http["resp_capped"] is True
    assert http["resp_bytes"] == len(wire) and http["resp_decode_failed"] is False
    assert d["kind"] == "zip" and d["sha256"] == _sha(big) and d["size"] == len(big)


def test_a_stacked_encoding_hashes_the_whole_file_too():
    big = b"MZ" + b"\x00" * (3 * _MIB)
    d = _events(_get(), _encoded(gzip.compress(zlib.compress(big)), b"deflate, gzip"),
                kind="download")[0]
    assert d["sha256"] == _sha(big) and d["size"] == len(big)


def test_a_payload_above_the_hashing_ceiling_has_no_hash_and_says_so(monkeypatch):
    monkeypatch.setattr(net_http, "MAX_HASHED", 2 * _MIB)
    big = b"MZ" + b"\x00" * (3 * _MIB)
    wire = gzip.compress(big)
    d = _events(_get(), _encoded(wire, b"gzip"), kind="download")[0]
    assert d["kind"] == "pe" and d["inflate_capped"] is True
    assert d["sha256"] is None and d["size"] is None
    assert d["wire_sha256"] == _sha(wire) and d["wire_size"] == len(wire)
    just_fits = b"MZ" + b"\x00" * (2 * _MIB - 2)
    d = _events(_get(), _encoded(gzip.compress(just_fits), b"gzip"), kind="download")[0]
    assert d["sha256"] == _sha(just_fits) and d["size"] == 2 * _MIB


def test_the_hashing_ceiling_is_in_the_tens_of_megabytes_and_above_the_text_ceiling():
    assert 16 * _MIB <= net_http.MAX_HASHED <= 256 * _MIB
    assert net_http.MAX_HASHED > 8 * net_http.MAX_INFLATED


def test_a_big_gzipped_pe_that_breaks_after_the_text_ceiling_is_reported_without_a_hash():
    wire = gzip.compress(b"MZ" + b"\x00" * (3 * _MIB))
    cut = wire[:len(wire) // 2]
    d = _events(_get(), _encoded(cut, b"gzip"), kind="download")[0]
    assert d["kind"] == "pe" and d["sha256"] is None and d["size"] is None
    assert d["inflate_failed"] is True and d["inflate_capped"] is False
    assert d["wire_sha256"] == _sha(cut)


def test_the_flags_that_explain_a_missing_hash_are_false_when_there_is_one():
    for d in (_events(_get(), _ok(_PE), kind="download")[0],
              _events(_get(), _encoded(gzip.compress(_PE), b"gzip"), kind="download")[0],
              _events(_get(), _encoded(_PE, b"gzip"), kind="download")[0]):
        assert d["inflate_failed"] is False and d["inflate_capped"] is False
        assert d["sha256"] is not None and d["size"] is not None


def test_a_failed_inflate_falls_back_to_the_wire_bytes_for_kind_and_hash():
    d = _events(_get(), _encoded(_PE, b"gzip"), kind="download")[0]
    assert d["kind"] == "pe" and d["sha256"] == _sha(_PE) and d["size"] == len(_PE)
    assert "wire_sha256" not in d and d["inflate_capped"] is False
    e = _events(_get(), _encoded(_PE, b"gzip"))[0]
    assert e["resp_decode_failed"] is True


def test_a_gzipped_pe_cut_mid_stream_is_still_reported_as_a_download_without_a_hash():
    wire = gzip.compress(_PE)
    for cut in (len(wire) - 20, len(wire) - 5):
        evs = net_http.events_from_flow(_http_flow(_get(b"/s2"), _encoded(wire[:cut], b"gzip")))
        d = [e for e in evs if e["type"] == "download"][0]
        assert d["kind"] == "pe" and d["path"] == "/s2"
        assert d["sha256"] is None and d["size"] is None
        assert d["inflate_failed"] is True and d["inflate_capped"] is False
        assert d["wire_sha256"] == _sha(wire[:cut]) and d["wire_size"] == cut
        http = [e for e in evs if e["type"] == "http"][0]
        assert http["resp_decode_failed"] is True


def test_a_cut_stream_with_nothing_inflated_yet_has_no_kind_and_no_download():
    evs = net_http.events_from_flow(_http_flow(_get(), _encoded(gzip.compress(_PE)[:12], b"gzip")))
    assert [e["type"] for e in evs] == ["http"]


def test_an_encoding_that_is_not_understood_is_hashed_as_it_arrived():
    d = _events(_get(), _encoded(_PE, b"br"), kind="download")[0]
    assert d["kind"] == "pe" and d["sha256"] == _sha(_PE) and "wire_sha256" not in d
    assert d["content_encoding"] == "br"


def test_a_gzipped_response_that_is_not_a_file_is_not_a_download():
    assert _events(_get(), _encoded(gzip.compress(_TEXT), b"gzip"), kind="download") == []
    assert _events(_get(), _encoded(gzip.compress(b""), b"gzip"), kind="download") == []


# --- text cut by an inflate cap or a break ------------------------------------

def test_utf8_text_cut_by_the_inflate_ceiling_is_not_garbled():
    two = ("a" + "\u00e9" * (net_http.MAX_INFLATED // 2 + 100)).encode("utf-8")
    e = _events(_get(), _encoded(gzip.compress(two), b"gzip"))[0]
    assert e["resp_capped"] is True and e["resp_decode_failed"] is False
    assert e["resp_text"] == "a" + "\u00e9" * ((net_http.MAX_INFLATED - 1) // 2)
    three = ("\u4e2d" * (net_http.MAX_INFLATED // 3 + 100)).encode("utf-8")
    e = _events(_get(), _encoded(zlib.compress(three), b"deflate"))[0]
    assert e["resp_capped"] is True
    assert e["resp_text"] == "\u4e2d" * (net_http.MAX_INFLATED // 3)


def test_a_gzipped_request_body_cut_by_the_ceiling_is_not_garbled_either():
    wire = gzip.compress(("\u4e2d" * (net_http.MAX_INFLATED // 3 + 100)).encode("utf-8"))
    e = _events(b"POST /p HTTP/1.1\r\nHost: x.top\r\nContent-Encoding: gzip\r\n"
                b"Content-Length: %d\r\n\r\n" % len(wire) + wire, b"")[0]
    assert e["body_capped"] is True and set(e["body_text"]) == {"\u4e2d"}


def test_utf8_text_from_a_stream_that_broke_mid_character_is_not_garbled():
    original = "".join("\u00e9\u4e2d %d " % i for i in range(300))
    wire = gzip.compress(original.encode("utf-8"))
    seen = 0
    for cut in range(30, len(wire) - 8, 5):
        e = _events(_get(), _encoded(wire[:cut], b"gzip"))[0]
        assert e["resp_decode_failed"] is True
        if e["resp_text"]:
            seen += 1
            assert original.startswith(e["resp_text"]), cut
    assert seen > 10


# --- upload encoding ----------------------------------------------------------

def test_an_upload_names_the_encoding_of_the_body_its_hash_describes():
    wire = gzip.compress(b"exfil " * 400)
    assert len(wire) < 600
    body = wire + b"\x00" * (600 - len(wire))
    u = _events(b"POST /u HTTP/1.1\r\nHost: x.top\r\nContent-Encoding: GZIP\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body) + body, b"", kind="upload")[0]
    assert u["content_encoding"] == "gzip" and u["sha256"] == _sha(body)
    plain = _events(b"POST /u HTTP/1.1\r\nHost: x.top\r\nContent-Length: 600\r\n\r\n" + b"u" * 600,
                    b"", kind="upload")[0]
    assert plain["content_encoding"] == ""


def test_a_websocket_message_cut_by_the_text_cap_is_not_garbled():
    text = ("a" + "\u00e9" * (net_http.MAX_BODY_TEXT // 2 + 100)).encode("utf-8")
    ws = _ws_events(b"", _ws_frame(text))[0]
    m = ws["messages"][0]
    assert m["size"] == len(text) and m["text"] == "a" + "\u00e9" * ((net_http.MAX_BODY_TEXT - 1) // 2)


# --- a hashing budget shared by the flows of a capture ---------------------------------

class _CountingSha:
    """hashlib.sha256 that counts the bytes streamed into it with update(), and
    all bytes it was given (``total``)."""

    streamed = 0
    total = 0

    def __init__(self, data=b""):
        _CountingSha.total += len(data)
        self._h = hashlib.sha256(data)

    def update(self, chunk):
        _CountingSha.streamed += len(chunk)
        _CountingSha.total += len(chunk)
        self._h.update(chunk)

    def hexdigest(self):
        return self._h.hexdigest()


class _Hashlib:
    sha256 = _CountingSha


def _bomb_downloads(monkeypatch, n, size=_MIB, **kw):
    """``n`` downloads of one gzipped PE; above the text ceiling it is streamed
    into the hash, below it hashed from memory."""
    monkeypatch.setattr(net_http, "hashlib", _Hashlib)
    _CountingSha.streamed = _CountingSha.total = 0
    payload = b"MZ" + b"\x00" * size
    flow = _http_flow(_get(), _encoded(gzip.compress(payload, 9), b"gzip"))
    downloads = []
    for _ in range(n):
        downloads += [e for e in net_http.events_from_flow(flow, **kw) if e["type"] == "download"]
    return payload, downloads


def test_without_a_budget_every_download_is_hashed_as_before(monkeypatch):
    payload, downloads = _bomb_downloads(monkeypatch, 6)
    assert [d["sha256"] for d in downloads] == [_sha(payload)] * 6
    assert all("hash_budget_spent" not in d for d in downloads)
    assert _CountingSha.streamed == 6 * len(payload)


def test_a_hashing_budget_bounds_the_total_over_many_flows(monkeypatch):
    budget = net_http.HashBudget(3 * _MIB)
    payload, downloads = _bomb_downloads(monkeypatch, 20, hash_budget=budget)
    assert _CountingSha.streamed <= 3 * _MIB and budget.spent == _CountingSha.streamed
    hashed = [d for d in downloads if d["sha256"] is not None]
    assert [d["sha256"] for d in hashed] == [_sha(payload)] * 2
    rest = downloads[len(hashed):]
    assert len(rest) == 18 and all(d["hash_budget_spent"] is True and d["kind"] == "pe"
                                   and d["size"] is None and d["inflate_capped"] is True
                                   for d in rest)
    assert all(d["wire_sha256"] for d in rest)


def test_a_spent_budget_costs_no_more_inflating(monkeypatch):
    budget = net_http.HashBudget(0)
    calls = []
    real = net_http._chunks

    def counted(data, wbits, run):
        for chunk in real(data, wbits, run):
            calls.append(len(chunk))
            yield chunk

    monkeypatch.setattr(net_http, "_chunks", counted)
    _payload, downloads = _bomb_downloads(monkeypatch, 5, hash_budget=budget)
    assert all(d["hash_budget_spent"] for d in downloads)
    # the text inflate stops at its ceiling; the hash adds nothing once the budget is gone
    assert sum(calls) <= 5 * (net_http.MAX_INFLATED + net_http._CHUNK)


def test_the_budget_covers_small_bombs_hashed_from_memory_too(monkeypatch):
    budget = net_http.HashBudget(_MIB)
    payload, downloads = _bomb_downloads(monkeypatch, 20, size=200 * 1024, hash_budget=budget)
    assert len(payload) < net_http.MAX_INFLATED
    wire = len(gzip.compress(payload, 9))
    assert budget.spent <= _MIB and _CountingSha.total <= _MIB + 20 * wire
    assert sum(1 for d in downloads if d["sha256"]) == _MIB // len(payload) == 5
    assert all(d["hash_budget_spent"] and d["kind"] == "pe" for d in downloads[5:])


# --- names keep their bytes ---------------------------------------------------------------

def _wire(text):
    return text.encode("ascii", "surrogateescape")


@pytest.mark.parametrize("raw", [b"Ev\x1bil\x00x.T\xe9p", b"caf\xc3\xa9.top"])
def test_the_host_keeps_its_bytes_for_the_caller_to_render(raw):
    e = _events(_get(host=raw), b"")[0]
    assert _wire(e["dest"]) == raw.lower()
    assert _wire(e["url"]) == b"http://" + raw.lower() + b"/"


def test_an_absolute_target_keeps_its_bytes_too():
    e = _events(b"GET http://a\xe9\x01.top/x HTTP/1.1\r\n\r\n", b"")[0]
    assert _wire(e["dest"]) == b"a\xe9\x01.top" and _wire(e["url"]) == b"http://a\xe9\x01.top/x"
