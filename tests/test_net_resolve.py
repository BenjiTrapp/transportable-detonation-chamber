"""The DNS server (webui/net_resolve.py): where a faked name gets its address.

The address a name is given here is what every fake server later reads back out of a connection's destination, so the
tests hold the answer to what a resolver on the guest will accept (the id, the question as asked, NOERROR with no
records rather than NXDOMAIN for what is not an A) and to what the report needs of the server (what it did not
answer, and which of the names were housekeeping). The last test is the seam: the capture the server writes is read
by the analysis that ships, as any capture is.
"""

import pathlib
import socket
import tempfile
import threading

import dpkt
import pytest

import net_analyze
import net_divert
import net_pcap
import net_resolve
import net_system

GUEST = "10.0.2.15"
SHARED = "10.0.0.5"             # the address FakeSystemOps reads as the adapter's own, which is a shared address too
T0 = 1795000000.0

_OPEN = []


@pytest.fixture(autouse=True)
def _close_what_a_test_left_open():
    yield
    while _OPEN:
        _OPEN.pop().close()


def _server(tmp_path=None, passthrough=None, writer=True, ops=None, **kw):
    ops = ops or net_system.FakeSystemOps()
    diverter = net_divert.GuestDiverter(ops, 7, shared=SHARED, **kw)
    diverter.start()
    w = None
    if writer:
        path = str((tmp_path or _tmp()) / "capture.pcap")
        w = net_pcap.CaptureWriter(path, GUEST)
        _OPEN.append(w)
    ctx = net_pcap.SessionContext(diverter=diverter, writer=w, ops=ops, passthrough=passthrough, guest_ip=GUEST)
    server = net_resolve.DnsServer(ctx)
    server.ctx = ctx
    return server, diverter


def _tmp():
    return pathlib.Path(tempfile.mkdtemp(prefix="tdc-resolve-"))


def _query(name, qtype="A", qid=0x1234, rd=1, cls=dpkt.dns.DNS_IN, opcode=dpkt.dns.DNS_QUERY, qr=dpkt.dns.DNS_Q):
    code = {"A": dpkt.dns.DNS_A, "AAAA": dpkt.dns.DNS_AAAA, "TXT": dpkt.dns.DNS_TXT, "MX": dpkt.dns.DNS_MX}[qtype]
    msg = dpkt.dns.DNS(id=qid, qr=qr, opcode=opcode, rd=rd)
    msg.qd = [dpkt.dns.DNS.Q(name=name, type=code, cls=cls)]
    return bytes(msg)


def _answers(reply):
    return [socket.inet_ntoa(rr.rdata) for rr in dpkt.dns.DNS(reply).an if rr.type == dpkt.dns.DNS_A]


def _rcode(reply):
    return dpkt.dns.DNS(reply).rcode


def _pcap_packets(path):
    with open(path, "rb") as fh:
        return [(ts, dpkt.ethernet.Ethernet(buf)) for ts, buf in dpkt.pcap.Reader(fh)]


# --- what the brief asked for ---------------------------------------------------------------------------------------


def test_an_a_query_is_answered_with_the_address_the_diverter_assigned():
    s, d = _server()
    reply = s.answer(_query("c2.evil", "A"))
    assert _answers(reply) == [d.address_for("c2.evil")]
    assert _answers(reply)[0].startswith("198.18.")


def test_the_same_name_asked_twice_gets_the_same_address():
    s, _ = _server()
    assert _answers(s.answer(_query("c2.evil", "A"))) == _answers(s.answer(_query("c2.evil", "A")))


def test_an_address_is_assigned_only_when_the_name_is_asked_for():
    s, d = _server()
    assert len(d.state()["names"]) == 0
    s.answer(_query("c2.evil", "A"))
    assert len(d.state()["names"]) == 1


def test_a_name_on_the_passthrough_allowlist_is_not_faked():
    s, d = _server(passthrough=["teamserver.mine"])
    assert s.answer(_query("teamserver.mine", "A")) is None
    assert d.state()["names"] == {}


def test_an_aaaa_query_is_answered_with_no_records_not_with_nxdomain():
    # NXDOMAIN on AAAA makes some clients give up on the name entirely
    reply = _server()[0].answer(_query("c2.evil", "AAAA"))
    assert _rcode(reply) == 0 and _answers(reply) == [] and dpkt.dns.DNS(reply).an == []


def test_a_txt_query_gets_an_empty_answer_so_a_dns_tunnel_keeps_talking():
    reply = _server()[0].answer(_query("x.tunnel.evil", "TXT"))
    assert _rcode(reply) == 0
    assert dpkt.dns.DNS(reply).an == []


def test_a_malformed_query_is_not_answered_and_does_not_raise():
    assert _server()[0].answer(b"\xff\xff\xff") is None


def test_the_query_and_its_answer_are_both_written_to_the_capture():
    s, _ = _server()
    s.answer(_query("c2.evil", "A"))
    assert s.ctx.writer.datagrams >= 2


# --- the wire -------------------------------------------------------------------------------------------------------


def test_the_reply_is_a_response_to_that_query_with_its_id_and_rd():
    s, _ = _server()
    for rd in (0, 1):
        reply = dpkt.dns.DNS(s.answer(_query("c2.evil", "A", qid=0xBEEF, rd=rd)))
        assert reply.id == 0xBEEF and reply.rd == rd
        assert reply.qr == dpkt.dns.DNS_R and reply.opcode == dpkt.dns.DNS_QUERY
        assert reply.ra == 1 and reply.aa == 1 and reply.rcode == 0
        assert [(q.name, q.type) for q in reply.qd] == [("c2.evil", dpkt.dns.DNS_A)]


def test_the_a_record_is_one_record_with_the_ttl_of_the_server():
    s, d = _server()
    reply = dpkt.dns.DNS(s.answer(_query("c2.evil", "A")))
    assert len(reply.an) == 1
    rr = reply.an[0]
    assert (rr.type, rr.cls, rr.ttl) == (dpkt.dns.DNS_A, dpkt.dns.DNS_IN, 60)
    assert net_resolve.DnsServer.TTL == 60
    assert rr.name == "c2.evil"


def test_the_question_is_echoed_as_asked_and_the_diverter_gets_the_normalised_name():
    s, d = _server()
    asked = _query("C2.eViL", "A")
    reply = s.answer(asked)
    assert reply[12:12 + len(asked) - 12] == asked[12:]         # 0x20: a resolver checks the case came back
    assert list(d.state()["names"]) == ["c2.evil"]
    assert _answers(reply) == [d.address_for("c2.evil")]


def test_two_spellings_in_different_case_are_one_name_with_one_address():
    s, d = _server()
    assert _answers(s.answer(_query("c2.EVIL", "A"))) == _answers(s.answer(_query("C2.evil", "A")))
    assert len(d.state()["names"]) == 1


@pytest.mark.parametrize("make", [
    lambda: _query("c2.evil", "A", qr=dpkt.dns.DNS_R),
    lambda: _query("c2.evil", "A", opcode=dpkt.dns.DNS_IQUERY),
    lambda: _query("c2.evil", "A", opcode=dpkt.dns.DNS_STATUS),
    lambda: _query("c2.evil", "A", cls=3),
])
def test_only_a_standard_query_in_class_in_is_answered(make):
    s, d = _server()
    assert s.answer(make()) is None
    assert d.state()["names"] == {}
    assert s.summary()["unsupported"] == 1


def test_a_query_with_two_questions_or_none_is_not_answered():
    s, _ = _server()
    two = dpkt.dns.DNS(id=1, rd=1)
    two.qd = [dpkt.dns.DNS.Q(name="a.evil", type=1, cls=1), dpkt.dns.DNS.Q(name="b.evil", type=1, cls=1)]
    none = dpkt.dns.DNS(id=1, rd=1)
    assert s.answer(bytes(two)) is None and s.answer(bytes(none)) is None
    assert s.summary()["unsupported"] == 2


def test_a_query_that_brings_an_edns_record_is_still_answered():
    s, _ = _server()
    msg = dpkt.dns.DNS(_query("c2.evil", "A"))
    msg.ar = [dpkt.dns.DNS.RR(name="", type=41, cls=4096, ttl=0, rlen=0, rdata=b"")]
    assert _answers(s.answer(bytes(msg))) != []


def test_a_diverter_that_raises_gives_no_answer_and_no_exception():
    s, d = _server()
    d.stop()                                    # address_for raises RuntimeError once stopped
    assert s.answer(_query("c2.evil", "A")) is None
    assert s.summary()["failed"] == 1


def test_the_root_name_is_no_name_and_is_not_answered():
    s, _ = _server()
    assert s.answer(_query("", "A")) is None
    assert s.summary()["failed"] == 1


# --- passthrough and housekeeping -----------------------------------------------------------------------------------


def test_passthrough_matches_the_exact_name_after_normalisation_and_not_its_subdomains():
    s, _ = _server(passthrough=["TeamServer.Mine.", "ops.mine:8443"])
    assert s.answer(_query("teamserver.mine", "A")) is None
    assert s.answer(_query("ops.mine", "A")) is None
    assert s.answer(_query("sub.teamserver.mine", "A")) is not None
    assert s.answer(_query("evilteamserver.mine", "A")) is not None
    assert s.summary()["passthrough"] == ["teamserver.mine", "ops.mine"]


def test_a_housekeeping_name_is_answered_like_any_other_and_listed():
    s, d = _server()
    reply = s.answer(_query("www.msftconnecttest.com", "A"))
    assert _answers(reply) == [d.address_for("www.msftconnecttest.com")]
    s.answer(_query("c2.evil", "A"))
    assert s.summary()["housekeeping"] == ["www.msftconnecttest.com"]


def test_housekeeping_matches_on_label_boundaries():
    s, _ = _server()
    s.answer(_query("msftncsi.com", "A"))
    s.answer(_query("dns.msftncsi.com", "A"))
    s.answer(_query("evilmsftncsi.com", "A"))
    s.answer(_query("msftncsi.com.evil.top", "A"))
    assert s.summary()["housekeeping"] == ["msftncsi.com", "dns.msftncsi.com"]


def test_what_a_clean_windows_asks_for_is_housekeeping():
    for name in ("www.msftconnecttest.com", "dns.msftncsi.com", "ctldl.windowsupdate.com", "time.windows.com",
                 "settings-win.data.microsoft.com", "wdcp.microsoft.com"):
        assert net_resolve.is_housekeeping(name), name
    assert not net_resolve.is_housekeeping("c2.evil")


# --- what the report needs ------------------------------------------------------------------------------------------


def test_the_summary_counts_what_was_asked_by_type_and_what_was_not_answered():
    s, _ = _server()
    s.answer(_query("a.evil", "A"))
    s.answer(_query("a.evil", "A"))
    s.answer(_query("a.evil", "AAAA"))
    s.answer(_query("a.evil", "TXT"))
    s.answer(_query("a.evil", "MX"))
    s.answer(b"\xff\xff\xff")
    out = s.summary()
    assert out["queries"] == {"A": 2, "AAAA": 1, "TXT": 1, "MX": 1}
    assert out["malformed"] == 1 and out["unsupported"] == 0 and out["failed"] == 0


def test_the_summary_is_a_copy_and_has_the_keys_the_runner_reads():
    s, _ = _server(passthrough=["x.mine"])
    s.answer(_query("www.msftconnecttest.com", "A"))
    out = s.summary()
    assert set(out) >= {"housekeeping", "passthrough", "unaddressed", "malformed", "unsupported", "failed",
                        "queries", "capture_errors", "housekeeping_more", "unaddressed_more"}
    out["housekeeping"].append("x")
    out["queries"]["A"] = 99
    assert s.summary()["housekeeping"] == ["www.msftconnecttest.com"]
    assert s.summary()["queries"] == {"A": 1}


def test_a_name_that_got_no_address_is_listed_as_unaddressed_though_it_was_answered():
    ops = net_system.FakeSystemOps()
    d = net_divert.GuestDiverter(ops, 7)            # the default shared address is ours to add, and so is refused
    d.start()
    ops.fail["add_address"] = net_system.SystemOpsError("netsh add address failed (1): The pool is full")
    s = net_resolve.DnsServer(net_pcap.SessionContext(diverter=d, ops=ops))
    reply = s.answer(_query("c2.evil", "A"))
    assert _answers(reply) == [d.shared]            # still an answer: the sample tries, and the attempt is seen
    assert d.state()["unaddressed_names"] == ["c2.evil"]
    assert s.summary()["unaddressed"] == [{"name": "c2.evil", "reason": net_divert.UNADDRESSED_REASON}]


def test_a_name_served_from_the_shared_address_that_works_is_not_unaddressed():
    ops = net_system.FakeSystemOps()
    d = net_divert.GuestDiverter(ops, 7, shared=SHARED)
    d.start()
    ops.fail["add_address"] = net_system.SystemOpsError("The pool is full")
    s = net_resolve.DnsServer(net_pcap.SessionContext(diverter=d, ops=ops))
    assert _answers(s.answer(_query("c2.evil", "A"))) == [SHARED]
    assert d.state()["shared_names"] == ["c2.evil"]
    assert s.summary()["unaddressed"] == []


def test_the_diverter_state_is_not_read_for_a_name_that_has_its_own_address():
    s, d = _server()
    calls = []
    real = d.state
    d.state = lambda: calls.append(1) or real()
    for _ in range(5):
        s.answer(_query("c2.evil", "A"))
    assert calls == []


def test_the_names_the_summary_lists_are_bounded():
    s, _ = _server()
    for i in range(net_resolve.MAX_LISTED + 25):
        s.answer(_query("h%d.msftncsi.com" % i, "A"))
    out = s.summary()
    assert len(out["housekeeping"]) == net_resolve.MAX_LISTED and out["housekeeping_more"] == 25


# --- the capture ----------------------------------------------------------------------------------------------------


def test_the_capture_gets_the_query_and_the_reply_as_the_same_conversation(tmp_path):
    s, d = _server(tmp_path)
    s.answer(_query("c2.evil", "A"), local_addr=("10.0.2.3", 53), peer_addr=(GUEST, 51234), ts=T0)
    s.ctx.writer.close()
    packets = _pcap_packets(str(tmp_path / "capture.pcap"))
    assert len(packets) == 2
    (t1, q), (t2, a) = packets
    assert socket.inet_ntoa(q.data.dst) == "10.0.2.3" and q.data.data.dport == 53 and q.data.data.sport == 51234
    assert socket.inet_ntoa(a.data.src) == "10.0.2.3" and a.data.data.sport == 53 and a.data.data.dport == 51234
    assert t1 == T0 and t2 > t1


def test_without_addresses_the_query_goes_to_the_diverters_dns_address_from_a_default_port(tmp_path):
    s, d = _server(tmp_path, dns_address="127.0.0.2")
    s.answer(_query("c2.evil", "A"), ts=T0)
    s.ctx.writer.close()
    (_, q), _ = _pcap_packets(str(tmp_path / "capture.pcap"))
    assert socket.inet_ntoa(q.data.dst) == "127.0.0.2" and q.data.data.dport == 53
    assert q.data.data.sport == net_resolve.DEFAULT_PEER_PORT


def test_a_passthrough_query_is_in_the_capture_without_an_answer(tmp_path):
    s, _ = _server(tmp_path, passthrough=["teamserver.mine"])
    s.answer(_query("teamserver.mine", "A"))
    assert s.ctx.writer.datagrams == 1


def test_a_server_with_no_writer_still_answers():
    s, _ = _server(writer=False)
    assert _answers(s.answer(_query("c2.evil", "A"))) != []


def test_a_capture_that_cannot_take_the_datagram_does_not_stop_the_answer_and_is_counted():
    s, _ = _server()
    reply = s.answer(_query("c2.evil", "A"), peer_addr=(GUEST, 70000))   # a port the writer refuses
    assert _answers(reply) != []
    assert s.summary()["capture_errors"] == 2


def test_no_dns_event_is_put_in_the_recorder_because_the_capture_carries_it():
    class Recorder:
        def __init__(self):
            self.touched = []

        def __getattr__(self, name):
            self.touched.append(name)
            return lambda *a, **k: None
    s, _ = _server()
    s.ctx.recorder = Recorder()
    s.answer(_query("c2.evil", "A"))
    s.answer(b"\xff\xff\xff")
    assert s.ctx.recorder.touched == []


def test_the_summary_can_be_read_while_threads_answer():
    s, _ = _server()
    errors = []

    def work(i):
        try:
            for j in range(40):
                s.answer(_query("h%d-%d.msftncsi.com" % (i, j), "A"))
                s.summary()
        except Exception as e:      # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert s.summary()["queries"] == {"A": 240}


# --- the seam -------------------------------------------------------------------------------------------------------


def test_what_the_server_wrote_is_read_back_by_analyze_pcap_as_a_dns_event(tmp_path):
    s, d = _server(tmp_path)
    s.answer(_query("c2.evil", "A"), peer_addr=(GUEST, 51234), ts=T0)
    s.ctx.writer.close()
    report = net_analyze.analyze_pcap(str(tmp_path / "capture.pcap"))
    dns = [e for e in report["events"] if e["type"] == "dns"]
    assert len(dns) == 1
    assert dns[0]["dest"] == "c2.evil"
    assert dns[0]["answers"] == [d.address_for("c2.evil")]
    assert dns[0]["answers"][0].startswith("198.18.")
    assert report["errors"] == []
