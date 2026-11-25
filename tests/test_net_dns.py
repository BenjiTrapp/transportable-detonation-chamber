"""DNS messages to ``dns`` events.

Regressions covered:
  * a client that reuses its source port puts many DNS messages into one UDP
    flow; reading the joined stream merged them into one and every event
    carried the flow's first timestamp instead of its own packet's
  * a response was paired with whatever query came before it instead of the
    query with the same transaction ID, so out-of-order answers landed on the
    wrong name
  * a reused transaction ID paired an answer with a query for another name
  * a query nobody answered vanished instead of being an event with no answers
  * direction was trusted: UDP has no handshake, so a capture that begins with
    a response makes the resolver look like the client; the resolver address
    and the queried name must not depend on that guess
  * a response with no query in the capture was dropped, and a duplicated
    response was counted as a second lookup
  * NXDOMAIN was visible only as a code number, so an NXDOMAIN burst could not
    be counted; SERVFAIL must not be mistaken for it
  * a malformed or looping message raised, or took the good messages next to
    it down with it
  * the same name in different letter case was two different destinations
"""

import os
import socket
import tempfile

import dpkt

import net_dns
import net_events
import net_flows

CLIENT = "192.0.2.10"
RESOLVER = "198.51.100.53"

_QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}


def _frame(src, sport, dst, dport, payload):
    dgram = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    dgram.ulen = 8 + len(payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=dgram)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _rr(name, qtype, value):
    kind = _QTYPES.get(qtype, qtype)
    if kind == 1:
        return dpkt.dns.DNS.RR(name=name, type=1, ttl=60, ip=socket.inet_aton(value))
    if kind == 28:
        return dpkt.dns.DNS.RR(name=name, type=28, ttl=60,
                               ip6=socket.inet_pton(socket.AF_INET6, value))
    if kind == 5:
        return dpkt.dns.DNS.RR(name=name, type=5, ttl=60, cname=value)
    if kind == 16:
        raw = value.encode()
        return dpkt.dns.DNS.RR(name=name, type=16, ttl=60,
                               rdata=bytes([len(raw)]) + raw)
    raise AssertionError("helper does not build %r" % (qtype,))


def _message(name, qtype, answers=None, rcode=0, txid=0x1234, response=True):
    """Real DNS wire bytes. ``answers`` are (rr_type, value) pairs or plain values."""
    kind = _QTYPES.get(qtype, qtype)
    msg = dpkt.dns.DNS(id=txid, qr=dpkt.dns.DNS_R if response else dpkt.dns.DNS_Q,
                       opcode=dpkt.dns.DNS_QUERY, rcode=rcode,
                       qd=[dpkt.dns.DNS.Q(name=name, type=kind, cls=1)])
    if answers:
        msg.an = [_rr(name, *(a if isinstance(a, tuple) else (qtype, a)))
                  for a in answers]
    return bytes(msg)


def _flow_from(datagrams, cport=40000, sport=53):
    """Write the datagrams to a pcap, read it back, return the single flow.

    ``datagrams`` is a list of ``(ts, "c" | "s", payload)``; "c" travels from
    the client port to the resolver. Going through ``read_pcap`` means the
    parser is fed what the real reader produces, including the grouping of
    every message of a reused 4-tuple into one flow.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "dns.pcap")
        with open(path, "wb") as fh:
            w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
            for ts, direction, payload in datagrams:
                if direction == "c":
                    buf = _frame(CLIENT, cport, RESOLVER, sport, payload)
                else:
                    buf = _frame(RESOLVER, sport, CLIENT, cport, payload)
                w.writepkt(buf, ts)
        result = net_flows.read_pcap(path)
    assert len(result.flows) == 1, result.note
    return result.flows[0]


def _dns_flow(name, qtype, answers, rcode=0, txid=0x1234):
    """One lookup. ``answers`` None means the query was never answered."""
    datagrams = [(10.0, "c", _message(name, qtype, response=False, txid=txid))]
    if answers is not None:
        datagrams.append((10.2, "s", _message(name, qtype, answers, rcode=rcode,
                                              txid=txid)))
    return _flow_from(datagrams)


def _raw_udp_flow(port, payload):
    return _flow_from([(1.0, "c", payload)], sport=port)


# --- the contract from the brief --------------------------------------------

def test_a_query_and_its_answer_become_one_event():
    events = net_dns.events_from_flow(_dns_flow("evil.top", "A", ["203.0.113.9"]))
    assert len(events) == 1
    e = events[0]
    assert e["type"] == "dns" and e["query"] == "evil.top"
    assert e["answers"] == ["203.0.113.9"] and e["nxdomain"] is False
    assert e["rcode"] == "NOERROR" and e["query_type"] == "A"


def test_nxdomain_is_marked():
    e = net_dns.events_from_flow(_dns_flow("gone.top", "A", [], rcode=3))[0]
    assert e["nxdomain"] is True and e["rcode"] == "NXDOMAIN"
    assert e["answers"] == []


def test_servfail_is_not_nxdomain():
    e = net_dns.events_from_flow(_dns_flow("broken.top", "A", [], rcode=2))[0]
    assert e["rcode"] == "SERVFAIL" and e["nxdomain"] is False


def test_a_txt_answer_keeps_its_text():
    e = net_dns.events_from_flow(_dns_flow("c2.top", "TXT", ["cm0="]))[0]
    assert e["answers"] == ["cm0="] and e["query_type"] == "TXT"


def test_a_query_without_an_answer_is_still_an_event():
    events = net_dns.events_from_flow(_dns_flow("slow.top", "A", None))
    assert len(events) == 1
    e = events[0]
    assert e["answers"] == [] and e["nxdomain"] is False and e["rcode"] == ""


def test_a_malformed_dns_payload_is_skipped_without_raising():
    assert net_dns.events_from_flow(_raw_udp_flow(53, b"\xff\xff\xff")) == []


# --- event shape --------------------------------------------------------------

def test_the_event_is_a_net_event_named_after_the_looked_up_name():
    e = net_dns.events_from_flow(_dns_flow("evil.top", "A", ["203.0.113.9"]))[0]
    assert isinstance(e, net_events.NetEvent)
    assert e["dest"] == "evil.top" and e["dest_is_ip"] is False
    assert e["server"] == RESOLVER and e["port"] == 53
    assert e["in_tree"] is False
    assert e["ts"] == 10.0


def test_names_are_compared_in_lower_case_without_the_root_dot():
    e = net_dns.events_from_flow(_dns_flow("Evil.TOP.", "A", ["203.0.113.9"]))[0]
    assert e["query"] == "evil.top" and e["dest"] == "evil.top"


def test_every_answer_record_is_listed_in_order():
    answers = [("CNAME", "edge.cdn.example"), ("A", "203.0.113.9"),
               ("AAAA", "2001:db8::1")]
    e = net_dns.events_from_flow(_dns_flow("www.evil.top", "A", answers))[0]
    assert e["answers"] == ["edge.cdn.example", "203.0.113.9", "2001:db8::1"]


def test_an_unknown_query_type_is_named_by_its_number():
    flow = _flow_from([(1.0, "c", _message("x.top", 65000, response=False))])
    assert net_dns.events_from_flow(flow)[0]["query_type"] == "TYPE65000"


# --- many messages in one flow -----------------------------------------------

def test_each_lookup_of_a_reused_source_port_is_its_own_event_with_its_own_time():
    datagrams = []
    for i, name in enumerate(["a.top", "b.top", "c.top"]):
        t = 100.0 + i * 5
        datagrams.append((t, "c", _message(name, "A", response=False, txid=i + 1)))
        datagrams.append((t + 0.1, "s", _message(name, "A", ["203.0.113.%d" % (i + 1)],
                                                 txid=i + 1)))
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert [e["query"] for e in events] == ["a.top", "b.top", "c.top"]
    assert [e["ts"] for e in events] == [100.0, 105.0, 110.0]
    assert [e["answers"] for e in events] == [["203.0.113.1"], ["203.0.113.2"],
                                              ["203.0.113.3"]]


def test_answers_that_arrive_out_of_order_go_to_the_query_with_their_id():
    datagrams = [
        (1.0, "c", _message("first.top", "A", response=False, txid=11)),
        (1.1, "c", _message("second.top", "A", response=False, txid=22)),
        (1.2, "s", _message("second.top", "A", ["203.0.113.2"], txid=22)),
        (1.3, "s", _message("first.top", "A", ["203.0.113.1"], txid=11)),
    ]
    first, second = net_dns.events_from_flow(_flow_from(datagrams))
    assert (first["query"], first["answers"]) == ("first.top", ["203.0.113.1"])
    assert (second["query"], second["answers"]) == ("second.top", ["203.0.113.2"])


def test_a_reused_transaction_id_does_not_answer_a_query_for_another_name():
    datagrams = [
        (1.0, "c", _message("asked.top", "A", response=False, txid=5)),
        (2.0, "s", _message("other.top", "A", ["203.0.113.7"], txid=5)),
    ]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    asked = [e for e in events if e["query"] == "asked.top"]
    assert len(asked) == 1 and asked[0]["answers"] == []
    other = [e for e in events if e["query"] == "other.top"]
    assert len(other) == 1 and other[0]["answers"] == ["203.0.113.7"]


def test_a_repeated_query_and_its_one_answer_are_two_events_and_one_answer():
    q = _message("slow.top", "A", response=False, txid=9)
    datagrams = [(1.0, "c", q), (3.0, "c", q),
                 (3.1, "s", _message("slow.top", "A", ["203.0.113.5"], txid=9))]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert [e["ts"] for e in events] == [1.0, 3.0]
    assert [e["answers"] for e in events] == [[], ["203.0.113.5"]]


# --- direction is a guess ----------------------------------------------------

def test_a_capture_that_starts_with_a_response_still_yields_the_lookup():
    datagrams = [(1.0, "s", _message("late.top", "A", ["203.0.113.4"], txid=3))]
    flow = _flow_from(datagrams)
    assert flow.client_guessed and flow.src == RESOLVER    # the reader took the resolver for the client
    e = net_dns.events_from_flow(flow)[0]
    assert e["query"] == "late.top" and e["answers"] == ["203.0.113.4"]
    assert e["server"] == RESOLVER and e["ts"] == 1.0


def test_a_duplicated_response_is_not_a_second_lookup():
    answer = _message("dup.top", "A", ["203.0.113.4"], txid=3)
    datagrams = [(1.0, "c", _message("dup.top", "A", response=False, txid=3)),
                 (1.1, "s", answer), (1.2, "s", answer)]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert len(events) == 1 and events[0]["answers"] == ["203.0.113.4"]


# --- bad input ----------------------------------------------------------------

def test_a_bad_message_does_not_cost_the_good_ones_next_to_it():
    datagrams = [
        (1.0, "c", _message("good.top", "A", response=False, txid=1)),
        (1.1, "c", b"\xff\xff\xff"),
        (1.2, "s", _message("good.top", "A", ["203.0.113.1"], txid=1)),
        (1.3, "c", _message("also.top", "A", response=False, txid=2)),
    ]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert [e["query"] for e in events] == ["good.top", "also.top"]
    assert events[0]["answers"] == ["203.0.113.1"]


def test_a_compression_pointer_that_points_at_itself_is_skipped():
    header = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    looping = header + b"\xc0\x0c\x00\x01\x00\x01"
    assert net_dns.events_from_flow(_raw_udp_flow(53, looping)) == []


def test_a_message_with_no_question_is_skipped():
    empty = bytes(dpkt.dns.DNS(id=1, qr=dpkt.dns.DNS_Q))
    assert net_dns.events_from_flow(_raw_udp_flow(53, empty)) == []


def test_a_response_cut_short_leaves_the_query_unanswered_without_raising():
    cut = _message("c2.top", "TXT", ["abcdef"], txid=4)[:-14]
    datagrams = [(1.0, "c", _message("c2.top", "TXT", response=False, txid=4)),
                 (1.1, "s", cut)]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert len(events) == 1 and events[0]["answers"] == []


# --- is_dns -------------------------------------------------------------------

def test_udp_port_53_is_dns_in_either_direction():
    assert net_dns.is_dns(_dns_flow("evil.top", "A", ["203.0.113.9"])) is True
    flow = _flow_from([(1.0, "s", _message("x.top", "A", ["203.0.113.9"]))])
    assert net_dns.is_dns(flow) is True


def test_other_udp_ports_are_not_dns():
    assert net_dns.is_dns(_raw_udp_flow(5000, b"hello")) is False


def test_a_tcp_flow_is_not_claimed():
    flow = _raw_udp_flow(53, b"x")
    flow.proto = "tcp"
    assert net_dns.is_dns(flow) is False


def test_a_record_cut_inside_its_data_keeps_the_bytes_that_exist():
    cut = _message("c2.top", "TXT", ["abcdef"], txid=4)[:-3]
    datagrams = [(1.0, "c", _message("c2.top", "TXT", response=False, txid=4)),
                 (1.1, "s", cut)]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert len(events) == 1 and events[0]["answers"] == ["abc"]
