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
  * a label with bytes that are not UTF-8 (DNS allows any byte, tunnelling and
    C2 lookups use it) made the whole message unreadable, so the lookup the
    tool exists to catch produced no event
  * a dot inside a label rendered the same as a label separator, so two
    different names became one destination
  * many queries sharing one transaction ID, answered in order, were matched by
    scanning every waiting query again for each answer
  * a wall-clock bound (3 s) on matching 20,000 lookups with one transaction
    ID failed on a loaded machine; the test counts the entries popped instead
    (final review M3)
  * compression pointers let 56 KB of reply hold 4000 answers of 253
    characters: sixty such replies were 61 MB of report and 12 s; a message
    keeps ``MAX_ANSWERS`` records and ``answers_capped`` says more existed
    (follow-up F1)
"""

import os
import random
import socket
import struct
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


def test_a_response_cut_inside_a_record_keeps_the_complete_records_before_it():
    full = _message("c2.top", "A", ["203.0.113.1", "203.0.113.2"], txid=4)
    datagrams = [(1.0, "c", _message("c2.top", "A", response=False, txid=4)),
                 (1.1, "s", full[:-3])]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert len(events) == 1
    assert events[0]["answers"] == ["203.0.113.1"] and events[0]["rcode"] == "NOERROR"


def test_a_response_cut_inside_its_question_does_not_answer_and_does_not_raise():
    full = _message("c2.top", "A", ["203.0.113.1"], txid=4)
    datagrams = [(1.0, "c", _message("c2.top", "A", response=False, txid=4)),
                 (1.1, "s", full[:16])]
    events = net_dns.events_from_flow(_flow_from(datagrams))
    assert len(events) == 1 and events[0]["answers"] == [] and events[0]["rcode"] == ""


def test_random_damage_to_a_message_never_raises():
    rng = random.Random(53)
    good = _message("www.evil.top", "A", [("CNAME", "edge.cdn.example"),
                                          ("A", "203.0.113.9")], txid=8)
    damaged = []
    for i in range(3000):
        data = bytearray(good)
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            del data[rng.randrange(len(data)):]
        damaged.append((1.0 + i * 1e-3, "c" if i % 2 else "s", bytes(data)))
    assert isinstance(net_dns.events_from_flow(_flow_from(damaged)), list)


# --- names that are not text --------------------------------------------------

def _wire_name(*labels):
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def _raw_query(txid, *labels, qtype=1):
    return (struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0)
            + _wire_name(*labels) + struct.pack("!HH", qtype, 1))


def _raw_response(txid, rcode, labels, rdata=b"\x01\x02\x03\x04", qtype=1):
    """A response whose one answer names its owner by pointer to the question."""
    head = struct.pack("!6H", txid, 0x8180 | rcode, 1, 1, 0, 0)
    question = _wire_name(*labels) + struct.pack("!HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return head + question + answer


def test_a_label_that_is_not_utf8_still_yields_the_lookup():
    flow = _flow_from([(1.0, "c", _raw_query(1, b"\xff\xfe\xfd", b"top"))])
    e = net_dns.events_from_flow(flow)[0]
    assert e["query"] == "\\255\\254\\253.top" and e["dest"] == e["query"]


def test_a_binary_lookup_and_its_answer_are_paired():
    labels = (b"\x00\x80tunnel", b"top")
    flow = _flow_from([(1.0, "c", _raw_query(2, *labels)),
                       (1.1, "s", _raw_response(2, 0, labels))])
    events = net_dns.events_from_flow(flow)
    assert len(events) == 1
    assert events[0]["dest"] == "\\000\\128tunnel.top"
    assert events[0]["answers"] == ["1.2.3.4"]


def test_a_dot_inside_a_label_is_not_a_label_separator():
    one = net_dns.events_from_flow(_flow_from([(1.0, "c", _raw_query(1, b"a.b", b"top"))]))
    two = net_dns.events_from_flow(_flow_from([(1.0, "c", _raw_query(1, b"a", b"b", b"top"))]))
    assert one[0]["dest"] == "a\\.b.top" and two[0]["dest"] == "a.b.top"


def test_a_backslash_in_a_label_is_escaped_so_the_rendering_is_unambiguous():
    flow = _flow_from([(1.0, "c", _raw_query(1, b"a\\b", b"top"))])
    assert net_dns.events_from_flow(flow)[0]["dest"] == "a\\\\b.top"


def test_a_space_or_control_byte_in_a_label_is_written_as_its_number():
    flow = _flow_from([(1.0, "c", _raw_query(1, b"a b\x01", b"top"))])
    assert net_dns.events_from_flow(flow)[0]["dest"] == "a\\032b\\001.top"


def test_a_response_with_no_question_still_answers_the_waiting_query():
    refused = struct.pack("!6H", 6, 0x8100 | 1, 0, 0, 0, 0)       # FORMERR, qdcount 0
    flow = _flow_from([(1.0, "c", _raw_query(6, b"odd", b"top")), (1.1, "s", refused)])
    events = net_dns.events_from_flow(flow)
    assert len(events) == 1 and events[0]["rcode"] == "FORMERR"


# --- many lookups sharing a transaction ID ------------------------------------

def test_many_queries_with_one_transaction_id_are_matched_without_rescanning(monkeypatch):
    n = 20000
    datagrams = [(1.0 + i * 1e-4, "c",
                  _message("h%d.top" % i, "A", response=False, txid=77))
                 for i in range(n)]
    datagrams += [(20.0 + i * 1e-4, "s",
                   _message("h%d.top" % i, "A", ["10.%d.%d.1" % (i // 256, i % 256)],
                            txid=77))
                  for i in range(n)]
    flow = _flow_from(datagrams)
    # work, not wall-clock time (a loaded machine made a 3 s bound flaky): each
    # lookup sits on two stacks and is popped from each at most once
    looked_at = []
    take = net_dns._take

    def counted(stack):
        before = len(stack)
        found = take(stack)
        looked_at.append(before - len(stack))
        return found
    monkeypatch.setattr(net_dns, "_take", counted)
    events = net_dns.events_from_flow(flow)
    assert len(events) == n
    assert events[1234]["answers"] == ["10.4.210.1"]
    assert all(e["answers"] for e in events)
    assert len(looked_at) == n and sum(looked_at) <= 2 * n


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


# --- a bound on the answers of one message (follow-up F1) ----------------------

def _pointer_reply(count):
    """A reply whose ``count`` CNAME answers all point back at the question name."""
    name = b"".join(bytes([63]) + b"a" * 63 for _ in range(3)) + bytes([60]) + b"b" * 60 + b"\x00"
    question = name + struct.pack("!HH", 1, 1)
    answers = (b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c") * count
    ask = struct.pack("!6H", 7, 0x0100, 1, 0, 0, 0) + question
    reply = struct.pack("!6H", 7, 0x8180, 1, count, 0, 0) + question + answers
    return ask, reply


def test_a_reply_keeps_at_most_max_answers_and_says_it_was_cut():
    ask, reply = _pointer_reply(4000)
    e = net_dns.events_from_flow(_flow_from([(1.0, "c", ask), (1.1, "s", reply)]))[0]
    assert len(e["answers"]) == net_dns.MAX_ANSWERS and e["answers_capped"] is True
    assert net_dns.MAX_ANSWERS <= 100


def test_a_reply_within_the_bound_is_not_marked_cut():
    ask, reply = _pointer_reply(net_dns.MAX_ANSWERS)
    e = net_dns.events_from_flow(_flow_from([(1.0, "c", ask), (1.1, "s", reply)]))[0]
    assert len(e["answers"]) == net_dns.MAX_ANSWERS and e["answers_capped"] is False
    plain = net_dns.events_from_flow(_dns_flow("evil.top", "A", ["203.0.113.9"]))[0]
    assert plain["answers_capped"] is False
