"""Live-memory results, scanner output parsing and the evidence model.

Regressions covered:
  * results lived only in RAM and were lost on every restart
  * a PID entry of an earlier sample answered for a later one
  * BeaconEye called with arguments it does not accept; both parsers keyed on
    words that never occur in the real output, so nothing was ever found
  * baseline keyed by image name: a sample named svchost.exe inherited
    svchost's baseline
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
