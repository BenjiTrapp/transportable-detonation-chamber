"""Network findings in the shared evidence model (``webui/net_evidence.py``).

Regressions covered:
  * a beacon seen as an event and as a rule hit reported twice, so one
    phenomenon scored twice
  * an evidence ``kind`` misspelt in a rule file loaded cleanly and scored
    nothing, forever
  * data our own server accepted in the isolated mode counted as if a real C2
    had received it
  * a finding derived from an FTP or SMTP login carried the password, or the
    ``Secret`` that refuses JSON, into the verdict
  * a short or loose rhythm (four random contacts are measured as periodic in
    about one series in ten) given the full weight of a check-in
  * Windows housekeeping (connectivity checks, OCSP, wpad) turned into C2
    evidence because the findings ignored ``known_good``
  * an OCSP POST of the idle machine, visible as an upload, was corroborated by
    an unrelated reflective PE in the same process: 3.0 SUSPICIOUS became 7.0
    MALICIOUS
"""

import json

import pytest

import memory_evidence
import net_behavior
import net_evidence
import net_events
import net_mail_ftp
import net_rules

from test_net_default_rules import EVIDENCE_ARTS, Capture, _benign_capture, _pe, _rules, _session


def _hit(rule_id, kind=None, process="", dests=("c2.top",), etype="beacon"):
    rule = {"id": rule_id, "name": rule_id, "description": "", "severity": "medium",
            "role": "c2", "behavior": "", "attack": ["T1071"], "family": "", "kind": kind}
    refs = [{"index": i, "type": etype, "ts": 1.0 + i, "dest": d, "port": None}
            for i, d in enumerate(dests)]
    return net_rules.RuleHit(rule, process, len(refs), refs)


def _beacon(dest="c2.top", connections=8, cov=0.05, on_rhythm=0.9, interval=60.0,
            via=("http",), process="a.exe", pid=None, **extra):
    return net_events.NetEvent("beacon", 1.0, process=process, pid=pid, dest=dest,
                               interval=interval,
                               jitter=cov, cov=cov, on_rhythm=on_rhythm, periodic=True,
                               unmeasured=None, connections=connections, via=list(via),
                               **extra)


def _kinds(findings):
    return [f["kind"] for f in findings]


# --- the contract from the brief -------------------------------------------------------

def test_a_rule_hit_with_a_kind_becomes_a_finding():
    hits = [_hit("x", kind="exfil_upload", process="a.exe")]
    f = net_evidence.findings_from([], hits, process="a.exe", known_good=())[0]
    assert f["kind"] == "exfil_upload" and f["source"] == "network"


def test_a_rule_hit_without_a_kind_produces_no_finding():
    assert net_evidence.findings_from([], [_hit("x", kind=None)], known_good=()) == []
    assert net_evidence.findings_from([], [_hit("x", kind="")], known_good=()) == []


def test_a_beacon_event_becomes_a_checkin_finding():
    evs = [net_events.NetEvent("beacon", 1.0, process="a.exe", dest="c2.top", interval=60.0)]
    kinds = [f["kind"] for f in net_evidence.findings_from(evs, [], process="a.exe", known_good=())]
    assert "c2_checkin" in kinds


def test_an_isolated_run_marks_its_findings_as_partly_observed():
    evs = [net_events.NetEvent("upload", 1.0, process="a.exe", dest="c2.top", body_bytes=4096)]
    f = net_evidence.findings_from(evs, [], process="a.exe", observed_fully=False, known_good=())[0]
    assert f["observation"] < 1.0


def test_the_same_phenomenon_is_not_reported_twice():
    evs = [net_events.NetEvent("beacon", 1.0, process="a.exe", dest="c2.top", interval=60.0)]
    hits = [_hit("beaconing", kind="c2_checkin", process="a.exe")]
    out = net_evidence.findings_from(evs, hits, process="a.exe", known_good=())
    assert len([f for f in out if f["kind"] == "c2_checkin"]) == 1


# --- the kinds ---------------------------------------------------------------------------

def test_the_network_kinds_are_the_arts_the_rules_may_name():
    assert set(net_evidence.NETWORK_KINDS) == EVIDENCE_ARTS
    assert set(net_evidence.NETWORK_KINDS) <= set(memory_evidence.KINDS)


def test_the_kinds_the_starter_rules_use_exist_with_the_weights_of_the_spec():
    weights = {"payload_staging": 4.0, "c2_checkin": 4.0, "dga_pattern": 2.0,
               "recon_service": 1.0, "credential_in_transit": 4.5}
    rs = _rules()
    assert rs.errors == []
    assert {r["kind"] for r in rs.rules if r["kind"]} == set(weights)
    for kind, weight in weights.items():
        assert memory_evidence.KINDS[kind]["weight"] == weight


def test_a_rule_naming_an_unknown_kind_is_refused_when_it_loads(tmp_path):
    path = tmp_path / "r.yaml"
    path.write_text("rules:\n"
                    "  - {id: typo, name: typo, event: upload, kind: exfil_uplaod}\n"
                    "  - {id: ok, name: ok, event: upload, kind: exfil_upload}\n")
    rs = net_rules.load_rules([str(path)])
    assert [r["id"] for r in rs.rules] == ["ok"]
    assert len(rs.errors) == 1 and "exfil_uplaod" in rs.errors[0] and "typo" in rs.errors[0]


def test_a_rule_may_not_name_a_kind_that_is_not_a_network_kind(tmp_path):
    # thread_start_private weighs 6.0 on its own; a rule must not reach it.
    path = tmp_path / "r.yaml"
    path.write_text("rules:\n  - {id: x, name: x, event: http, kind: thread_start_private}\n")
    rs = net_rules.load_rules([str(path)])
    assert rs.rules == [] and "thread_start_private" in rs.errors[0]


def test_a_correlation_naming_an_unknown_kind_is_refused(tmp_path):
    path = tmp_path / "r.yaml"
    path.write_text("rules:\n  - {id: a, name: a, event: http}\n"
                    "  - {id: c, name: c, requires: [[a]], kind: nope}\n")
    rs = net_rules.load_rules([str(path)])
    assert [r["id"] for r in rs.rules] == ["a"] and "nope" in rs.errors[0]


def test_a_hit_with_a_kind_the_model_does_not_know_is_an_error():
    with pytest.raises(ValueError, match="nope"):
        net_evidence.findings_from([], [_hit("x", kind="nope")], known_good=())


# --- events with one meaning -----------------------------------------------------------------

def test_a_tight_beacon_of_a_known_process_is_a_full_checkin():
    f = net_evidence.findings_from([_beacon(pid=4242)], [], known_good=())[0]
    assert f["kind"] == "c2_checkin" and f["base_weight"] == 4.0
    assert f["needs_corroboration"] is False and f["pid"] == 4242
    assert f["dest"] == "c2.top" and f["interval_s"] == 60.0


def test_a_tight_beacon_without_a_process_needs_a_second_signal():
    # A pcap knows no process: any periodic service on the machine is "the sample".
    f = net_evidence.findings_from([_beacon()], [], known_good=())[0]
    assert f["base_weight"] == 4.0 and f["needs_corroboration"] is True and f["pid"] is None


def test_two_unlisted_periodic_services_are_not_a_verdict_on_their_own():
    evs = [_beacon(dest="poller-a.example"), _beacon(dest="poller-b.example")]
    assert memory_evidence.score(net_evidence.findings_from(evs, [], known_good=()))["score"] \
        < memory_evidence.VERDICT_SUSPICIOUS * 2


def test_uploads_without_a_process_need_a_second_signal():
    evs = [net_events.NetEvent("upload", float(i), dest="t%d.example" % i, size=2000)
           for i in range(2)]
    out = memory_evidence.score(net_evidence.findings_from(evs, [], known_good=()))
    assert all(f["needs_corroboration"] for f in out["findings"])
    assert out["label"] == "SUSPICIOUS" and out["score"] < memory_evidence.VERDICT_MALICIOUS


def test_an_upload_of_a_known_process_stands_alone_until_one_without_joins_it():
    with_pid = net_events.NetEvent("upload", 1.0, pid=7, dest="c2.top", size=2000)
    without = net_events.NetEvent("upload", 2.0, dest="c2.top", size=2000)
    alone = net_evidence.findings_from([with_pid], [], known_good=())[0]
    assert alone["needs_corroboration"] is False
    mixed = net_evidence.findings_from([with_pid, without], [], known_good=())[0]
    assert mixed["needs_corroboration"] is True and mixed["pid"] is None


@pytest.mark.parametrize("connections, cov, on_rhythm", [(4, 0.0, 1.0), (5, 0.0, 1.0),
                                                         (8, 0.3, 0.9), (8, 0.1, 0.6)])
def test_a_short_or_loose_beacon_weighs_what_a_loose_sysmon_beacon_weighs(connections, cov,
                                                                         on_rhythm):
    f = net_evidence.findings_from([_beacon(connections=connections, cov=cov,
                                            on_rhythm=on_rhythm)], [], known_good=())[0]
    loose = memory_evidence.KINDS["c2_beaconing"]["weight"] * memory_evidence.BEACON_LOOSE_FACTOR
    assert f["base_weight"] == pytest.approx(loose) and f["needs_corroboration"] is True


def test_short_beacons_to_many_hosts_stay_below_suspicious():
    # Four contacts to a host are measured periodic by chance about one time in ten;
    # a capture with many such hosts must not add up to a verdict on its own.
    evs = [_beacon(dest="h%d.example" % i, connections=4, cov=0.0, on_rhythm=1.0)
           for i in range(30)]
    assert memory_evidence.score(net_evidence.findings_from(evs, [], known_good=()))["label"] == "CLEAN"


def test_a_beacon_without_a_measurement_is_no_checkin():
    ev = _beacon(interval=None, cov=None, on_rhythm=None)
    ev["periodic"], ev["unmeasured"] = False, net_behavior.UNMEASURED_SCALES
    assert net_evidence.findings_from([ev], [], known_good=()) == []


def test_a_rhythm_of_failed_connections_is_not_a_checkin():
    assert net_evidence.findings_from([_beacon(via=("conn_failed",))], [], known_good=()) == []
    assert _kinds(net_evidence.findings_from([_beacon(via=("conn", "conn_failed"))], [], known_good=())) \
        == ["c2_checkin"]


def test_an_upload_is_exfiltration_with_its_size_and_destination():
    ev = net_events.NetEvent("upload", 1.0, dest="c2.top", size=9000, sha256="ab" * 32,
                             kind="zip", method="POST", path="/up")
    f = net_evidence.findings_from([ev], [], process="a.exe", known_good=())[0]
    assert (f["kind"], f["process"], f["dest"], f["size"], f["sha256"]) == \
        ("exfil_upload", "a.exe", "c2.top", 9000, "ab" * 32)
    assert f["observation"] == 1.0


def test_uploads_to_one_host_are_one_finding():
    evs = [net_events.NetEvent("upload", float(i), dest="c2.top", size=1000 + i) for i in range(5)]
    out = net_evidence.findings_from(evs, [], known_good=())
    assert _kinds(out) == ["exfil_upload"] and out[0]["count"] == 5 and out[0]["size"] == 5010


def test_an_executable_download_is_staging_and_another_file_is_not():
    evs = [net_events.NetEvent("download", 1.0, dest="e.top", kind="pe", sha256="cd" * 32),
           net_events.NetEvent("download", 2.0, dest="e.top", kind="pdf")]
    out = net_evidence.findings_from(evs, [], known_good=())
    assert _kinds(out) == ["payload_staging"] and out[0]["sha256"] == "cd" * 32


def test_retries_to_a_dead_host_are_dead_c2_retry():
    ev = net_events.NetEvent("retry", 1.0, dest="dead.top", attempts=7)
    assert _kinds(net_evidence.findings_from([ev], [], known_good=())) == ["dead_c2_retry"]


def test_retries_to_an_ipv6_address_are_not_taken_for_a_single_label_name():
    ev = net_events.NetEvent("retry", 1.0, dest="2001:db8::5", attempts=7)
    assert _kinds(net_evidence.findings_from([ev], [], known_good=())) == ["dead_c2_retry"]


@pytest.mark.parametrize("name", ["wpad", "wpad.corp.example.com", "isatap",
                                  "12.2.0.192.in-addr.arpa", "fileserver.corp.local"])
def test_retries_of_a_name_the_resolver_asks_for_on_its_own_are_no_finding(name):
    ev = net_events.NetEvent("retry", 1.0, dest=name, attempts=7)
    assert net_evidence.findings_from([ev], [], known_good=()) == []


def test_a_path_on_many_hosts_is_fallback_rotation_and_a_burst_of_nxdomain_is_dga():
    evs = [net_events.NetEvent("fanout", 1.0, path="/gate.php", hosts=6,
                               dests=["a%d.top" % i for i in range(6)]),
           net_events.NetEvent("fanout", 2.0, hosts=12, nxdomain=True, window_s=60.0,
                               dests=["x%d.top" % i for i in range(12)])]
    assert _kinds(net_evidence.findings_from(evs, [], known_good=())) == ["fallback_rotation", "dga_pattern"]


def test_events_of_other_types_give_nothing():
    evs = [net_events.NetEvent(t, 1.0, dest="x.top") for t in
           ("dns", "conn", "conn_failed", "tls", "http", "udp", "raw", "ftp", "smtp",
            "websocket", "decoded")]
    assert net_evidence.findings_from(evs, [], known_good=()) == []


# --- process, observation, deduplication ---------------------------------------------------

def test_the_process_of_the_event_wins_over_the_default():
    out = net_evidence.findings_from([_beacon(process="b.exe")], [], process="a.exe", known_good=())
    assert out[0]["process"] == "b.exe"
    assert net_evidence.findings_from([_beacon(process="")], [], process="a.exe", known_good=())[0]["process"] \
        == "a.exe"


def test_isolated_mode_lowers_only_what_our_server_accepted():
    evs = [_beacon(), net_events.NetEvent("upload", 1.0, dest="c2.top", size=4096),
           net_events.NetEvent("download", 1.0, dest="c2.top", kind="pe")]
    hits = [_hit("ftp", kind="credential_in_transit", dests=("203.0.113.5",), etype="ftp")]
    out = {f["kind"]: f for f in net_evidence.findings_from(evs, hits, observed_fully=False, known_good=())}
    assert out["exfil_upload"]["observation"] == net_evidence.OBSERVATION_ISOLATED
    assert out["credential_in_transit"]["observation"] == net_evidence.OBSERVATION_ISOLATED
    assert out["c2_checkin"]["observation"] == 1.0
    assert out["payload_staging"]["observation"] == 1.0


def test_an_attempted_upload_of_a_known_process_alone_is_still_suspicious():
    ev = net_events.NetEvent("upload", 1.0, pid=7, dest="c2.top", size=4096)
    out = memory_evidence.score(net_evidence.findings_from([ev], [], observed_fully=False,
                                                           known_good=()))
    assert out["label"] == "SUSPICIOUS"


def test_a_hit_on_the_same_host_adds_its_rule_to_the_event_finding():
    hits = [_hit("net.periodic_checkin", kind="c2_checkin", process="a.exe")]
    out = net_evidence.findings_from([_beacon()], hits, process="a.exe", known_good=())
    assert len(out) == 1 and out[0]["rules"] == ["net.periodic_checkin"]
    assert out[0]["base_weight"] == 4.0          # the measured finding, not the bare hit


def test_a_hit_on_another_host_is_its_own_finding():
    hits = [_hit("r", kind="c2_checkin", dests=("other.top",), etype="http")]
    out = net_evidence.findings_from([_beacon()], hits, process="a.exe", known_good=())
    assert sorted(f["dest"] for f in out) == ["c2.top", "other.top"]


def test_a_hit_is_one_finding_per_destination():
    hits = [_hit("net.ip_lookup", kind="recon_service",
                 dests=("api.ipify.org", "api.ipify.org", "ip-api.com"), etype="dns")]
    out = net_evidence.findings_from([], hits, known_good=())
    assert sorted(f["dest"] for f in out) == ["api.ipify.org", "ip-api.com"]


def test_a_hit_and_an_event_without_a_process_are_the_sample_s():
    hits = [_hit("r", kind="c2_checkin", process="")]
    out = net_evidence.findings_from([_beacon(process="")], hits, process="a.exe", known_good=())
    assert len(out) == 1 and out[0]["process"] == "a.exe"


def test_network_findings_supersede_the_sysmon_beacon_of_the_same_loop():
    conns = [(1000.0 + 60.0 * i, "203.0.113.7", 443) for i in range(8)]
    sysmon = memory_evidence.beaconing_from_connections(conns, process=r"C:\x\a.exe")
    net = net_evidence.findings_from([_beacon(process="", addresses=["203.0.113.7"])], [],
                                     process="a.exe", known_good=())
    out = memory_evidence.score(sysmon + net)
    assert _kinds(out["findings"]) == ["c2_checkin"] and out["score"] == 4.0


def test_the_findings_are_plain_json():
    evs = [_beacon(), net_events.NetEvent("upload", 1.0, dest="c2.top", size=4096)]
    out = net_evidence.findings_from(evs, [_hit("r", kind="recon_service", dests=("x.top",))], known_good=())
    assert json.loads(json.dumps(out)) == out


# --- credentials ------------------------------------------------------------------------------

def test_a_credential_finding_carries_neither_the_password_nor_the_secret():
    cap = Capture()
    _session(cap, 5.0, "203.0.113.20", 21,
             b"USER stealer\r\nPASS Tr0ub4dor&3\r\nSTOR harvest.zip\r\n",
             b"220 ok\r\n331 ok\r\n230 ok\r\n150 ok\r\n")
    events = cap.read()
    ftp = [e for e in events if e["type"] == "ftp"][0]
    assert isinstance(ftp["password"], net_mail_ftp.Secret)
    with pytest.raises(TypeError):
        json.dumps(ftp)
    hits = _rules().evaluate(events)
    out = net_evidence.findings_from(events, hits, process="a.exe", known_good=())
    assert _kinds(out) == ["credential_in_transit"]
    text = json.dumps(out)
    assert "Tr0ub4dor" not in text and "stealer" not in text
    assert out[0]["dest"] == "203.0.113.20"


def test_a_hit_with_extra_fields_does_not_carry_them_into_the_finding():
    hit = _hit("ftp", kind="credential_in_transit", dests=("203.0.113.5",), etype="ftp")
    hit["events"][0]["password"] = net_mail_ftp.Secret("hunter2")
    hit["password"] = net_mail_ftp.Secret("hunter2")
    out = net_evidence.findings_from([], [hit], known_good=())
    assert "hunter2" not in json.dumps(out)


# --- known_good and ordinary traffic -----------------------------------------------------------

def test_known_good_hides_event_findings_but_never_a_transfer():
    # As in the rules (net_rules.ALWAYS_VISIBLE): a download or an upload is not
    # hidden by the name it claims.
    kg = ["*.windowsupdate.com", "ocsp.digicert.com"]
    evs = [_beacon(dest="ctldl.windowsupdate.com"),
           net_events.NetEvent("upload", 1.0, dest="ocsp.digicert.com", size=600),
           net_events.NetEvent("retry", 1.0, dest="x.windowsupdate.com", attempts=6),
           net_events.NetEvent("download", 1.0, dest="download.windowsupdate.com", kind="pe")]
    assert _kinds(net_evidence.findings_from(evs, [], known_good=kg)) == \
        ["exfil_upload", "payload_staging"]


def test_what_known_good_hides_is_exactly_what_the_rules_hide(tmp_path):
    path = tmp_path / "r.yaml"
    path.write_text("lists:\n  known_good: [ocsp.digicert.com, ctl.example]\n"
                    "rules:\n"
                    "  - {id: up, name: up, event: upload}\n"
                    "  - {id: bc, name: bc, event: beacon}\n")
    rs = net_rules.load_rules([str(path)])
    evs = [net_events.NetEvent("upload", 1.0, dest="ocsp.digicert.com", size=600),
           _beacon(dest="ctl.example")]
    fired = {h["rule_id"] for h in rs.evaluate(evs)}
    kinds = set(_kinds(net_evidence.findings_from(evs, [], known_good=rs)))
    assert ("up" in fired) == ("exfil_upload" in kinds) is True
    assert ("bc" in fired) == ("c2_checkin" in kinds) is False


def test_the_lists_of_a_rule_set_are_read_for_their_known_good():
    rs = _rules()
    events = _benign_capture()
    via_lists = net_evidence.findings_from(events, [], known_good=rs.lists)
    assert via_lists == net_evidence.findings_from(events, [], known_good=rs)
    with pytest.raises(TypeError):
        net_evidence.findings_from(events, [], known_good={"other": ["x"]})


def test_known_good_hides_a_fanout_only_when_every_host_is_known():
    kg = ["*.example.com"]
    known = net_events.NetEvent("fanout", 1.0, path="/x", hosts=5,
                                dests=["h%d.example.com" % i for i in range(5)])
    mixed = net_events.NetEvent("fanout", 1.0, path="/y", hosts=5,
                                dests=["h1.example.com", "evil.top"] + ["h%d.example.com" % i
                                                                         for i in range(3)])
    assert _kinds(net_evidence.findings_from([known, mixed], [], known_good=kg)) == \
        ["fallback_rotation"]


def test_an_hour_of_ordinary_windows_traffic_is_clean():
    rs = _rules()
    events = _benign_capture()
    hits = rs.evaluate(events)
    findings = net_evidence.findings_from(events, hits, process="a.exe",
                                          known_good=rs.lists["known_good"])
    # The OCSP POSTs are an upload to a claimed name, which is never hidden:
    # one host, no process, so it waits for a second signal.
    assert [(f["kind"], f["dest"], f["needs_corroboration"]) for f in findings] == \
        [("exfil_upload", "ocsp.digicert.com", True)]
    assert memory_evidence.score(findings)["label"] == "CLEAN"


def test_a_loader_capture_through_the_real_parsers_is_scored():
    cap = Capture()
    cap.get(5.0, "stage.top", "/a.bin", _pe(), "application/octet-stream")
    for i in range(8):
        cap.get(100.0 + 60.0 * i, "c2.top", "/t", b"ok")
    events = cap.read()
    rs = _rules()
    out = net_evidence.findings_from(events, rs.evaluate(events), process="a.exe",
                                     known_good=rs.lists["known_good"])
    assert sorted(_kinds(out)) == ["c2_checkin", "payload_staging"]
    # No process in a pcap: the check-in waits for a second signal, the staging does not.
    assert memory_evidence.score(out)["label"] == "SUSPICIOUS"
    sysmon = memory_evidence.beaconing_from_connections(
        [(100.0 + 60.0 * i, cap.server("c2.top"), 80) for i in range(8)], process="a.exe")
    both = memory_evidence.score(out + sysmon)
    assert both["label"] == "MALICIOUS" and both["superseded_count"] == 1


# --- known_good is not optional ---------------------------------------------------------

def test_known_good_has_no_default():
    with pytest.raises(TypeError):
        net_evidence.findings_from([_beacon()], [])
    with pytest.raises(TypeError):
        net_evidence.findings_from([_beacon()], [], known_good=None)


def test_the_rule_set_itself_can_be_passed_as_known_good():
    rs = _rules()
    events = _benign_capture()
    out = net_evidence.findings_from(events, rs.evaluate(events), process="a.exe",
                                     known_good=rs)
    assert _kinds(out) == ["exfil_upload"] and memory_evidence.score(out)["label"] == "CLEAN"


# --- a rule hit is held to what the event is held to --------------------------------------

def _failed_rhythm():
    return [_beacon(via=("conn_failed",), addresses=["203.0.113.7"])]


def test_a_rule_cannot_make_a_checkin_of_failed_connections():
    rs = _rules()
    events = _failed_rhythm()
    hits = rs.evaluate(events)
    assert [h["rule_id"] for h in hits] == ["net.periodic_checkin"]
    assert net_evidence.findings_from(events, hits, process="a.exe", known_good=rs) == []


def test_a_checkin_hit_whose_beacon_cannot_be_looked_up_is_dropped():
    rs = _rules()
    events = [_beacon()]
    hits = rs.evaluate(events)
    assert net_evidence.findings_from([], hits, process="a.exe", known_good=rs) == []


def test_a_checkin_from_a_rule_carries_the_addresses_and_supersedes_sysmon():
    rs = _rules()
    events = [_beacon(process="", addresses=["203.0.113.7"])]
    hits = rs.evaluate(events)
    net = net_evidence.findings_from(events, hits, process="a.exe", known_good=rs)
    assert len(net) == 1 and net[0]["addresses"] == ["203.0.113.7"]
    assert net[0]["rules"] == ["net.periodic_checkin"]
    sysmon = memory_evidence.beaconing_from_connections(
        [(1000.0 + 60.0 * i, "203.0.113.7", 443) for i in range(8)], process="a.exe")
    out = memory_evidence.score(sysmon + net)
    assert out["score"] == 4.0 and out["superseded_count"] == 1


def test_a_checkin_rule_on_a_request_without_an_answer_gives_nothing(tmp_path):
    path = tmp_path / "r.yaml"
    path.write_text("rules:\n  - {id: gate, name: gate, event: http, kind: c2_checkin}\n")
    rs = net_rules.load_rules([str(path)])
    unanswered = [net_events.NetEvent("http", 1.0, dest="c2.top", status=None)]
    answered = [net_events.NetEvent("http", 1.0, dest="c2.top", status=200)]
    assert net_evidence.findings_from(unanswered, rs.evaluate(unanswered), known_good=rs) == []
    assert _kinds(net_evidence.findings_from(answered, rs.evaluate(answered),
                                             known_good=rs)) == ["c2_checkin"]


# --- a known-good transfer is about its endpoint only -------------------------------------

def test_the_idle_machine_s_ocsp_posts_do_not_turn_a_host_finding_malicious():
    rs = _rules()
    events = _benign_capture()
    net = net_evidence.findings_from(events, rs.evaluate(events), process="a.exe", known_good=rs)
    pe = memory_evidence.MemoryFinding("aether", "reflective_pe", "a.exe")
    alone = memory_evidence.score([pe])
    both = memory_evidence.score([pe] + net)
    assert (alone["score"], alone["label"]) == (3.0, "SUSPICIOUS")
    assert both["label"] == "SUSPICIOUS" and both["score"] == 3.0 + 1.6
    upload = [f for f in both["findings"] if f["kind"] == "exfil_upload"][0]
    assert upload["known_good"] is True and upload["factors"]["corroboration"] == 0.4


def test_a_known_good_upload_does_not_vouch_for_an_unrelated_host_finding():
    up = net_evidence.findings_from(
        [net_events.NetEvent("upload", 1.0, dest="ocsp.digicert.com", size=600)], [],
        known_good=["ocsp.digicert.com"])
    heap = memory_evidence.MemoryFinding("aether", "heap_api_table", "")
    out = memory_evidence.score([heap] + up)
    assert [f for f in out["findings"] if f["kind"] == "heap_api_table"][0][
        "factors"]["corroboration"] == memory_evidence.UNCORROBORATED


def test_a_known_good_upload_is_corroborated_by_a_finding_about_the_same_endpoint():
    up = net_evidence.findings_from(
        [net_events.NetEvent("upload", 1.0, dest="ocsp.digicert.com", size=600)], [],
        known_good=["ocsp.digicert.com"])
    other = memory_evidence.MemoryFinding("sysmon-network", "c2_beaconing", "",
                                          extra={"dest": "ocsp.digicert.com"})
    out = memory_evidence.score(up + [other])
    upload = [f for f in out["findings"] if f["kind"] == "exfil_upload"][0]
    assert upload["factors"]["corroboration"] == 1.0
    assert upload["corroborated_by"] == ["sysmon-network"]


def test_an_upload_to_an_unlisted_host_is_corroborated_as_before():
    up = net_evidence.findings_from(
        [net_events.NetEvent("upload", 1.0, dest="c2.top", size=600)], [], process="a.exe",
        known_good=["ocsp.digicert.com"])
    pe = memory_evidence.MemoryFinding("aether", "reflective_pe", "a.exe")
    assert "known_good" not in up[0]
    assert memory_evidence.score([pe] + up)["score"] == 7.0
