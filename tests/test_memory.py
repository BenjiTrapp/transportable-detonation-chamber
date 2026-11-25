"""Live-memory results, scanner output parsing and the evidence model.

Regressions covered:
  * results lived only in RAM and were lost on every restart
  * a PID entry of an earlier sample answered for a later one
  * BeaconEye called with arguments it does not accept; both parsers keyed on
    words that never occur in the real output, so nothing was ever found
  * baseline keyed by image name: a sample named svchost.exe inherited
    svchost's baseline
  * one beacon loop counted twice: Sysmon's c2_beaconing (3.0) and the
    network check-in (4.0) together crossed the malicious threshold from a
    single phenomenon
  * a new confidence factor shifting the verdicts of findings that do not
    carry it
  * two notions of "regular": memory_evidence measured a 60 s beacon with a
    follow-up request as 59.7 s where net_behavior measured 60.0 s
"""

import json

import pytest


# --- Result store ----------------------------------------------------------

def test_results_survive_a_restart(tdc, tmp_path):
    d = str(tmp_path / "store")
    store = tdc._ResultStore(d)
    store.put("aether", {"score": 6.5}, pid=4072, sha256="aa" * 32)
    reloaded = tdc._ResultStore(d)
    assert reloaded.lookup("aether", pid=4072) == {"score": 6.5}
    assert reloaded.lookup("aether", sha256="aa" * 32) == {"score": 6.5}


def test_pid_entry_of_another_sample_is_ignored(tdc, tmp_path):
    store = tdc._ResultStore(str(tmp_path / "s"))
    store.put("aether", {"sample": "old"}, pid=4072, sha256="11" * 32)
    assert store.lookup("aether", pid=4072, sha256="22" * 32) is None
    assert store.lookup("aether", pid=4072, sha256="11" * 32) == {"sample": "old"}


def test_old_pid_only_entries_expire(tdc, tmp_path, monkeypatch):
    store = tdc._ResultStore(str(tmp_path / "s"))
    store.put("hsb", {"x": 1}, pid=10)
    assert store.lookup("hsb", pid=10) == {"x": 1}
    real_time = tdc.time.time
    monkeypatch.setattr(tdc.time, "time", lambda: real_time() + 7 * 3600)
    assert store.lookup("hsb", pid=10) is None


def test_store_is_bounded(tdc, tmp_path):
    store = tdc._ResultStore(str(tmp_path / "s"), limit=5)
    for i in range(1, 13):
        store.put("aether", {"i": i}, pid=i)
    files = list((tmp_path / "s").glob("*.json"))
    assert len(files) == 5
    assert store.lookup("aether", pid=12) == {"i": 12}
    assert store.lookup("aether", pid=1) is None          # oldest evicted, also on disk
    assert tdc._ResultStore(str(tmp_path / "s"), limit=5).lookup("aether", pid=1) is None


# --- Hunt-Sleeping-Beacons / BeaconEye ---------------------------------------

HSB_OUTPUT = (
    " _   _    _____   ______\n"
    "Hunt-Sleeping-Beacons | @thefLinkk\n\n"
    "\x1b[36m* Detections for: rustinel.exe (6508) C:\\tools\\rustinel.exe run\x1b[0m\n"
    "\t! Thread 4908 | \x1b[31mBlocking Timer detected\x1b[0m | \x1b[31mThread's blocking state "
    "triggered by ntdll!RtlpTpTimerCallback\x1b[0m | Severity: \x1b[31mHIGH\x1b[0m\n"
    "\t! Thread 5000 | Return address spoofing | jmp gadget | Severity: MID\n\n"
    "* Scanned: 140 processes and 1076 threads in 1.721 seconds\n"
)

BEACONEYE_OUTPUT = (
    "BeconEye by @_EthicalChaos_\n"
    "[+] Scanning for beacon processess...\n"
    "  rundll32.exe (4242), Keys Found:True, Configuration Address: 0x1F2A0000 \n"
    "\tBeaconType: HTTPS\n\tPort: 443\n\tC2Server: evil.example,/jquery.min.js\n\tWatermark: 1359593325\n"
    "  other.exe (77), Keys Found:False, Configuration Address: 0x10 \n"
    "\tBeaconType: SMB\n"
    "[+] Scanned 143 processes in 00:00:00.5\n[+] Found 2 beacon processes\n"
)


def test_hsb_parser_reads_the_real_format(tdc):
    f = tdc._parse_hsb_output(HSB_OUTPUT)
    assert len(f) == 1
    assert (f[0]["process"], f[0]["pid"], f[0]["severity"]) == ("rustinel.exe", 6508, "high")
    assert [d["title"] for d in f[0]["detections"]] == ["Blocking Timer detected", "Return address spoofing"]
    assert "\x1b" not in json.dumps(f)


def test_hsb_parser_without_detections(tdc):
    assert tdc._parse_hsb_output("* Scanned: 1 processes and 42 threads in 0.07 seconds\n") == []


def test_beaconeye_parser_reads_the_real_format(tdc):
    f = tdc._parse_beaconeye_output(BEACONEYE_OUTPUT)
    assert [(x["process"], x["pid"]) for x in f] == [("rundll32.exe", 4242), ("other.exe", 77)]
    assert f[0]["config"]["C2Server"] == "evil.example,/jquery.min.js"
    assert f[0]["config"]["c2"] == f[0]["config"]["C2Server"]
    assert f[0]["keys_found"] is True and f[1]["keys_found"] is False
    assert f[1]["config"] == {"BeaconType": "SMB"}


class _Proc:
    def __init__(self, out):
        self.stdout, self.stderr, self.returncode = out, "", 0


def test_beaconeye_is_called_without_pid_arguments_and_filtered(tdc, monkeypatch, tmp_path):
    exe = tmp_path / "BeaconEye.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(tdc, "BEACONEYE_EXE", str(exe))
    monkeypatch.setattr(tdc, "_cross_arch_note", lambda pid: None)
    calls = []
    monkeypatch.setattr(tdc, "_run_cmd", lambda args, **kw: calls.append(args) or _Proc(BEACONEYE_OUTPUT))
    result, err = tdc._run_beaconeye(4242)
    assert err is None
    assert calls == [[str(exe)]]          # BeaconEye has no PID option; "scan --pid" was rejected
    assert [f["pid"] for f in result["findings"]] == [4242]


def test_hsb_cross_arch_limitation_is_reported(tdc, monkeypatch, tmp_path):
    exe = tmp_path / "Hunt-Sleeping-Beacons.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(tdc, "HUNT_SLEEPING_BEACONS_EXE", str(exe))
    monkeypatch.setattr(tdc, "_run_cmd", lambda args, **kw: _Proc(HSB_OUTPUT))
    monkeypatch.setattr(tdc, "_process_machine", lambda pid: "ARM64")
    monkeypatch.setattr(tdc.platform, "machine", lambda: "ARM64")
    result, _ = tdc._run_hsb(6508)
    assert "ARM64" in result["limitation"]


def test_scan_endpoint_rejects_non_numeric_pid(client):
    assert client.post("/api/scan/beacons", json={"pid": "1; calc"}).status_code == 400


# --- Evidence model --------------------------------------------------------

def test_baseline_keys_use_the_full_image_path(tdc):
    me = tdc.memory_evidence
    finding = lambda proc: me.MemoryFinding("aether", "heap_api_table", proc,  # noqa: E731
                                            identity=(4096, "kernel32.dll"))
    real = finding(r"C:\Windows\System32\svchost.exe")
    fake = finding(r"C:\Users\Public\Downloads\svchost.exe")
    assert real["process"] == fake["process"] == "svchost.exe"
    assert real["key"] != fake["key"]
    baseline = me.MemoryBaseline(str(tdc._memory_baseline.path))
    baseline.add([real])
    ev = me.score([fake], baseline=baseline)
    assert ev["suppressed_count"] == 0


def test_baseline_from_an_older_key_scheme_is_ignored(tdc, tmp_path):
    me = tdc.memory_evidence
    path = tmp_path / "old.json"
    f = me.MemoryFinding("aether", "heap_api_table", "explorer.exe", identity=(1,))
    path.write_text(json.dumps({"created": "x", "updated": "x", "keys": {f["key"]: {"kind": "k"}}}))
    b = me.MemoryBaseline(str(path))
    assert b.stats()["stale"] is True
    assert not b.knows(f["key"])
    b.add([f])
    assert b.stats()["key_version"] == me.KEY_VERSION and b.knows(f["key"])


def test_cross_arch_scanner_findings_count_less(tdc):
    me = tdc.memory_evidence
    findings = tdc._parse_hsb_output(HSB_OUTPUT)
    full = me.score(me.from_hsb({"findings": findings}, "x.exe"))
    limited = me.score(me.from_hsb({"findings": findings, "limitation": "native ARM64"}, "x.exe"))
    assert limited["score"] < full["score"]
    assert limited["label"] == "CLEAN"


def test_decoded_beacon_config_is_malicious_evidence(tdc):
    me = tdc.memory_evidence
    findings = me.from_beaconeye({"findings": tdc._parse_beaconeye_output(BEACONEYE_OUTPUT)[:1]}, "r.exe")
    findings += me.from_hsb({"findings": tdc._parse_hsb_output(HSB_OUTPUT)}, "r.exe")
    assert me.score(findings)["label"] == "MALICIOUS"


@pytest.mark.parametrize("interval, expected", [(2.0, 1), (None, 0)])
def test_beaconing_needs_a_regular_rhythm(tdc, interval, expected):
    import random
    rnd = random.Random(7)
    t, conns = 0.0, []
    for _ in range(8):
        t += interval if interval else rnd.uniform(0.5, 60)
        conns.append((t, "10.0.0.1", 443))
    assert len(tdc.memory_evidence.beaconing_from_connections(conns, "b.exe")) == expected


# --- Observation factor and supersede ----------------------------------------

def test_existing_findings_keep_their_score_without_an_observation_factor(tdc):
    f = tdc.memory_evidence.MemoryFinding("aether", "reflective_pe", "a.exe")
    assert tdc.memory_evidence.score([f])["findings"][0]["factors"]["observation"] == 1.0


def test_an_observation_factor_below_one_lowers_the_contribution(tdc):
    me = tdc.memory_evidence
    full = me.score([me.MemoryFinding("net", "exfil_upload", "a.exe")])["score"]
    half = me.score([me.MemoryFinding("net", "exfil_upload", "a.exe",
                                      extra={"observation": 0.5})])["score"]
    assert half < full
    assert half == pytest.approx(full * 0.5)


@pytest.mark.parametrize("value, factor", [(1.7, 1.0), (-0.2, 0.0), ("x", 1.0), (None, 1.0),
                                           (float("nan"), 1.0), (True, 1.0)])
def test_an_observation_outside_zero_to_one_is_held_to_it(tdc, value, factor):
    me = tdc.memory_evidence
    f = me.MemoryFinding("net", "exfil_upload", "a.exe", extra={"observation": value})
    assert me.score([f])["findings"][0]["factors"]["observation"] == factor


def test_a_checkin_supersedes_beaconing_for_the_same_process_and_host(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe", extra={"dest": "c2.top"})
    ck = me.MemoryFinding("net", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    out = me.score([bc, ck])
    assert [f["kind"] for f in out["findings"]] == ["c2_checkin"]
    assert out["suppressed"][0]["superseded_by"] == "c2_checkin"


def test_beaconing_to_another_host_is_not_superseded(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe", extra={"dest": "other.top"})
    ck = me.MemoryFinding("net", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    assert len(me.score([bc, ck])["findings"]) == 2


def test_one_beacon_seen_by_sysmon_and_on_the_wire_is_not_malicious_by_itself(tdc):
    # The case the spec names: 3.0 + 4.0 from one loop would be 7.0 >= 6.0.
    me = tdc.memory_evidence
    conns = [(1000.0 + 60.0 * i, "203.0.113.7", 443) for i in range(8)]
    bc = me.beaconing_from_connections(conns, process="a.exe")
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe",
                          extra={"dest": "c2.top", "addresses": ["203.0.113.7"]})
    out = me.score(bc + [ck])
    assert out["score"] == 4.0 and out["label"] == "SUSPICIOUS"
    assert out["suppressed"][0]["kind"] == "c2_beaconing"


def test_sysmon_beaconing_matches_a_checkin_by_one_of_its_addresses(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "A.EXE", extra={"dest": "2001:db8::0001"})
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe",
                          extra={"dest": "c2.top", "addresses": ["2001:db8::1"]})
    assert [f["kind"] for f in me.score([bc, ck])["findings"]] == ["c2_checkin"]


def test_a_superseded_finding_still_corroborates_the_one_that_absorbed_it(tdc):
    # "Die Beobachtung aus Sysmon bleibt als Bestaetigung stehen".
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon-network", "c2_beaconing", "a.exe", extra={"dest": "c2.top"})
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", weight=3.5,
                          extra={"dest": "c2.top", "needs_corroboration": True})
    alone = me.score([ck])["findings"][0]
    together = me.score([bc, ck])["findings"][0]
    assert alone["factors"]["corroboration"] == me.UNCORROBORATED
    assert together["factors"]["corroboration"] == 1.0
    assert together["corroborated_by"] == ["sysmon-network"]
    assert together["absorbed"] == [{"kind": "c2_beaconing", "source": "sysmon-network"}]


def test_a_superseded_finding_still_corroborates_other_kinds_as_before(tdc):
    me = tdc.memory_evidence
    mem = me.MemoryFinding("aether", "heap_api_table", "a.exe")
    bc = me.MemoryFinding("sysmon-network", "c2_beaconing", "a.exe", extra={"dest": "c2.top"})
    before = me.score([mem, bc])
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    after = me.score([mem, bc, ck])
    heap = [f for f in after["findings"] if f["kind"] == "heap_api_table"][0]
    assert heap["factors"] == [f for f in before["findings"]
                               if f["kind"] == "heap_api_table"][0]["factors"]


def test_a_checkin_the_baseline_knows_supersedes_nothing(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe", extra={"dest": "c2.top"})
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", identity=("c2.top",),
                          extra={"dest": "c2.top"})
    baseline = me.MemoryBaseline(str(tdc._memory_baseline.path))
    baseline.add([ck])
    out = me.score([bc, ck], baseline=baseline)
    assert [f["kind"] for f in out["findings"]] == ["c2_beaconing"]


def test_superseded_findings_are_not_counted_as_suppressed_by_the_baseline(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe", extra={"dest": "c2.top"})
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    out = me.score([bc, ck])
    assert out["suppressed_count"] == 0 and out["superseded_count"] == 1
    assert out["suppressed"][0]["score"] == 0.0 and "baseline" not in out["suppressed"][0]


def test_a_finding_without_a_destination_is_not_superseded(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe")
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", extra={"dest": ""})
    assert len(me.score([bc, ck])["findings"]) == 2


def test_supersede_needs_the_same_process(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "b.exe", extra={"dest": "c2.top"})
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    assert len(me.score([bc, ck])["findings"]) == 2


def test_every_superseded_kind_is_a_kind(tdc):
    kinds = tdc.memory_evidence.KINDS
    assert kinds["c2_checkin"]["supersedes"] == ("c2_beaconing",)
    for spec in kinds.values():
        assert set(spec.get("supersedes", ())) <= set(kinds)


@pytest.mark.parametrize("kinds", [
    {"a": {"supersedes": ("b",)}, "b": {"supersedes": ("a",)}},
    {"a": {"supersedes": ("a",)}},
    {"a": {"supersedes": ("b",)}, "b": {"supersedes": ("c",)}, "c": {"supersedes": ("a",)}},
])
def test_kinds_that_supersede_each_other_are_refused(tdc, kinds):
    with pytest.raises(ValueError, match="cycle"):
        tdc.memory_evidence._check_kinds(kinds)


def test_a_chain_of_supersedes_is_not_a_cycle(tdc):
    me = tdc.memory_evidence
    kinds = {"a": {"supersedes": ("b", "c")}, "b": {"supersedes": ("c",)}, "c": {}}
    kinds.update({k: {} for k in me.NETWORK_KINDS})
    me._check_kinds(kinds)


# --- Supersede never lowers the score ----------------------------------------------

def _sysmon_tight(me, dest="203.0.113.7"):
    conns = [(1000.0 + 60.0 * i, dest, 443) for i in range(8)]
    found = me.beaconing_from_connections(conns, process="a.exe")
    assert found[0]["base_weight"] == 3.0 and found[0]["needs_corroboration"] is False
    return found


def test_a_loose_checkin_does_not_take_the_place_of_a_stronger_sysmon_beacon(tdc):
    me = tdc.memory_evidence
    loose = me.MemoryFinding("network", "c2_checkin", "a.exe", weight=2.1,
                             extra={"dest": "203.0.113.7", "needs_corroboration": True})
    out = me.score(_sysmon_tight(me) + [loose])
    assert out["score"] == 3.0
    assert [f["kind"] for f in out["findings"]] == ["c2_beaconing"]
    assert out["suppressed"][0]["kind"] == "c2_checkin"
    assert out["suppressed"][0]["superseded_by"] == "c2_beaconing"


def test_more_evidence_on_the_process_does_not_lower_the_score(tdc):
    me = tdc.memory_evidence
    heap = me.MemoryFinding("aether", "heap_api_table", "a.exe")
    loose = me.MemoryFinding("network", "c2_checkin", "a.exe", weight=2.1,
                             extra={"dest": "203.0.113.7", "needs_corroboration": True})
    before = me.score(_sysmon_tight(me) + [heap])["score"]
    assert before == 4.5
    assert me.score(_sysmon_tight(me) + [heap, loose])["score"] >= before


@pytest.mark.parametrize("extra", [
    {"needs_corroboration": True},                 # nobody else on the process
    {"observation": 0.3},
    {"samples": 4, "seen_in": 1},
])
def test_a_weakly_weighed_checkin_leaves_the_sysmon_beacon_standing(tdc, extra):
    me = tdc.memory_evidence
    sysmon = me.beaconing_from_connections(
        [(1000.0 + 60.0 * i, "203.0.113.7", 443) for i in range(8)], process="a.exe")
    sysmon[0]["source"] = "network"          # same source: no corroboration
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe",
                          extra=dict({"dest": "203.0.113.7"}, **extra))
    alone = me.score(sysmon)["score"]
    assert me.score(sysmon + [ck])["score"] >= alone == 3.0


def test_a_checkin_takes_the_place_of_two_beacons_only_if_it_counts_more(tdc):
    # Two Sysmon beacons to one address on two ports, 3.0 each: one check-in
    # of 4.0 is one phenomenon, but taking out 6.0 for 4.0 would lower the score.
    me = tdc.memory_evidence
    conns = [(1000.0 + 60.0 * i, "203.0.113.7", port) for i in range(8) for port in (443, 8443)]
    sysmon = me.beaconing_from_connections(conns, process="a.exe")
    ck = me.MemoryFinding("network", "c2_checkin", "a.exe", extra={"dest": "203.0.113.7"})
    assert me.score(sysmon)["score"] == 6.0
    out = me.score(sysmon + [ck])
    assert out["score"] == 6.0 and out["superseded_count"] == 1
    assert out["suppressed"][0]["kind"] == "c2_checkin"


def test_adding_any_finding_never_lowers_the_score(tdc):
    import random
    me = tdc.memory_evidence
    rng = random.Random(3)

    def one():
        kind = rng.choice(["c2_beaconing", "c2_checkin", "c2_checkin", "heap_api_table",
                           "reflective_pe", "pipe_cross_process"])
        extra = {"dest": rng.choice(["203.0.113.7", "c2.top", "other.top"])}
        if kind == "c2_checkin" and rng.random() < 0.5:
            extra["addresses"] = ["203.0.113.7"]
        if rng.random() < 0.5:
            extra["needs_corroboration"] = rng.random() < 0.5
        if rng.random() < 0.3:
            extra["observation"] = rng.choice([0.2, 0.6, 1.0])
        if rng.random() < 0.2:
            extra.update(samples=4, seen_in=rng.randint(1, 4))
        return me.MemoryFinding(rng.choice(["sysmon-network", "network", "aether"]), kind,
                                rng.choice(["a.exe", "A.exe", "b.exe"]),
                                identity=(rng.random(),),
                                weight=rng.choice([None, 0.84, 2.1, 3.0, 4.0]), extra=extra)

    for _ in range(3000):
        base = [one() for _ in range(rng.randint(0, 6))]
        before = me.score(base)["score"]
        after = me.score(base + [one()])["score"]
        assert after >= before, (base, after, before)


@pytest.mark.parametrize("kind, weight, evidence", [
    ("c2_checkin", 4.0, "structural"), ("exfil_upload", 4.0, "structural"),
    ("credential_in_transit", 4.5, "structural"), ("fallback_rotation", 3.0, "behavioral"),
    ("dead_c2_retry", 2.0, "behavioral"), ("recon_service", 1.0, "behavioral"),
    ("tls_ja3_known", 2.5, "structural"), ("dga_pattern", 2.0, "behavioral"),
    ("payload_staging", 4.0, "structural"),
])
def test_the_network_kinds_carry_the_weights_of_the_spec(tdc, kind, weight, evidence):
    spec = tdc.memory_evidence.KINDS[kind]
    assert (spec["weight"], spec["evidence"]) == (weight, evidence)


# --- Periodicity: one definition, in net_behavior ------------------------------

def test_a_follow_up_request_does_not_shorten_the_interval(tdc):
    # A connection 0.3 s after each check-in is part of it. Dropping only the
    # short interval measured 59.7 s; net_behavior measures 60.0 s.
    conns = []
    for i in range(8):
        conns += [(60.0 * i, "10.0.0.1", 443), (60.0 * i + 0.3, "10.0.0.1", 443)]
    f = tdc.memory_evidence.beaconing_from_connections(conns, "b.exe")[0]
    assert f["mean_interval_s"] == 60.0 and "every 60.0s" in f["detail"]
    assert f["connections"] == 16


def test_beaconing_and_net_behavior_report_the_same_numbers(tdc):
    import net_behavior
    times = [0.0, 61.0, 118.0, 181.0, 240.0, 302.0, 359.0]
    p = net_behavior.periodicity(times)
    f = tdc.memory_evidence.beaconing_from_connections([(t, "10.0.0.1", 443) for t in times])[0]
    assert (f["mean_interval_s"], f["cov"], f["on_rhythm"]) == (p["interval"], p["cov"], p["on_rhythm"])


def test_a_series_with_two_time_scales_is_not_a_sysmon_beacon(tdc):
    # GET plus POST three seconds later on every check-in: net_behavior
    # withholds the number, so there is no finding with a wrong one.
    times = []
    for i in range(8):
        times += [60.0 * i, 60.0 * i + 3.0]
    assert tdc.memory_evidence.beaconing_from_connections([(t, "10.0.0.1", 443) for t in times]) == []


def test_sysmon_beaconing_names_its_destination(tdc):
    conns = [(60.0 * i, "10.0.0.1", 443) for i in range(8)]
    f = tdc.memory_evidence.beaconing_from_connections(conns, "b.exe")[0]
    assert f["dest"] == "10.0.0.1" and f["endpoint"] == "10.0.0.1:443"
