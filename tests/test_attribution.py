"""Which alerts and processes belong to a detonation, and the verdict built from them.

Regressions covered:
  * months-old alerts of another process with the same PID drove a sample's verdict
  * Fibratus marked the process of every alert as "detonated"
  * memory evidence below the suspicious threshold still added a point
  * mixed-timezone timestamps compared as strings; 7 fractional digits not parsed
"""

import pytest

from conftest import make_alert


def utc(local_naive):
    """A local wall-clock time (as submissions record it) as an ISO UTC string.

    Submissions store naive local time, alerts carry UTC; computing the
    alert times from local time keeps the tests independent of the
    machine's time zone (CI runs in UTC).
    """
    import datetime
    dt = datetime.datetime.fromisoformat(local_naive).astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


SUB = {"agent_pid": 4242, "timestamp": "2026-10-20T10:00:00", "filename": "evil.exe",
       "file_path": r"C:\Users\Public\Downloads\evil.exe", "sha256": "ab" * 32}


@pytest.mark.parametrize("ts, expected", [
    ("2026-10-20T09:49:24.5826903+02:00", 1792482564.58269),  # Rustinel: 7 digits
    ("2026-09-14T07:55:51Z", 1789372551.0),
    ("2026-10-20T07:49:24.582Z", 1792482564.582),
    ("x", None),
    ("", None),
    (None, None),
])
def test_to_epoch(tdc, ts, expected):
    got = tdc._to_epoch(ts)
    assert (got is None) if expected is None else got == pytest.approx(expected, abs=1e-3)


def test_naive_timestamps_are_local_time(tdc):
    import datetime
    local = datetime.datetime(2026, 10, 20, 10, 0, 0).astimezone()
    assert tdc._to_epoch("2026-10-20T10:00:00") == pytest.approx(local.timestamp())


def test_agent_attribution_needs_time_window_and_image(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [SUB, {
        "agent_pid": 5000, "timestamp": "2026-10-20T10:00:00", "filename": "x.dll"}])
    idx = tdc._agent_detonation_index()
    at = lambda local: tdc._to_epoch(local)  # noqa: E731
    sample = r"C:\Users\Public\Downloads\evil.exe"
    assert tdc._is_agent_detonation(idx, 4242, at("2026-10-20T10:00:05"), sample)
    assert not tdc._is_agent_detonation(idx, 4242, at("2026-10-21T09:00:00"), r"C:\x\svchost.exe")
    assert not tdc._is_agent_detonation(idx, 4242, at("2026-10-20T10:01:00"), r"C:\x\notepad.exe")
    # DLLs run under a host process: the image is not compared.
    assert tdc._is_agent_detonation(idx, 5000, at("2026-10-20T10:00:10"), r"C:\x\rundll32.exe")
    assert not tdc._is_agent_detonation(idx, 5000, at("2026-10-19T10:00:10"), r"C:\x\rundll32.exe")


def test_fibratus_alerts_do_not_mark_processes_detonated(tdc):
    alert = tdc.parse_fibratus_alert({
        "id": "f1", "title": ".NET assembly loaded", "severity": "high",
        "events": [{"timestamp": "2026-10-20T10:00:00Z", "category": "image",
                    "proc": {"pid": 1564, "name": "BeaconEye.exe", "exe": r"C:\tools\BeaconEye\BeaconEye.exe"}}],
    })
    assert alert["detonated"] is False
    procs = tdc.build_process_tree([alert])
    assert not any(p.get("detonated") for p in procs.values())


def test_sample_and_its_children_are_detonated(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [SUB])
    procs = tdc.build_process_tree([
        make_alert(1, 4242, utc("2026-10-20T10:00:05"), SUB["file_path"]),
        make_alert(2, 4300, utc("2026-10-20T10:00:09"), r"C:\x\cmd.exe", 4242, "evil.exe"),
        make_alert(3, 4242, utc("2026-10-21T10:00:00"), r"C:\x\svchost.exe"),   # reused PID
    ])
    det = sorted(p["name"] for p in procs.values() if p.get("detonated"))
    assert det == ["cmd.exe", "evil.exe"]
    flagged = [a["id"] for p in procs.values() for a in p["alerts"] if a.get("detonated")]
    assert sorted(flagged) == ["a1", "a2"]


def test_detonation_results_ignore_alerts_of_earlier_pid_holders(tdc, client, monkeypatch):
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [SUB])
    monkeypatch.setattr(tdc, "_fetch_many", lambda specs: {})
    monkeypatch.setattr(tdc, "_litterbox_online", lambda: False)
    monkeypatch.setattr(tdc, "_is_fibratus_running", lambda: False)
    monkeypatch.setattr(tdc, "_is_rustinel_running", lambda: False)
    monkeypatch.setattr(tdc, "_network_beaconing_for_pid", lambda pid: {"available": False})
    old = make_alert(1, 4242, "2026-09-14T07:55:51Z", r"C:\x\powershell.exe")
    new = make_alert(2, 4242, utc("2026-10-20T10:00:05"), SUB["file_path"])
    tdc._store_alerts([old, new])
    d = client.get(f"/api/detonation/results?pid=4242&sha256={SUB['sha256']}").get_json()
    assert [a["id"] for a in d["fibratus_alerts"]] == ["a2"]


def test_weak_memory_evidence_does_not_raise_the_verdict(tdc, monkeypatch):
    weak = {"label": "CLEAN", "score": 0.3, "reasons": ["noise"], "suppressed_count": 0,
            "findings": [], "thresholds": {"suspicious": 2.0, "malicious": 6.0}}
    monkeypatch.setattr(tdc.memory_evidence, "score", lambda findings, baseline=None: dict(weak))
    v = tdc._compute_verdict({"aether": {"report": {}}}, [])
    assert v["label"] == "CLEAN" and v["score"] == 0
    strong = dict(weak, label="MALICIOUS", score=6.5)
    monkeypatch.setattr(tdc.memory_evidence, "score", lambda findings, baseline=None: dict(strong))
    assert tdc._compute_verdict({"aether": {"report": {}}}, [])["label"] == "MALICIOUS"


def test_alerts_since_and_limit(tdc, client):
    tdc._store_alerts([
        make_alert(1, 1, "2026-10-20T09:00:00+02:00", r"C:\a.exe"),   # 07:00 UTC
        make_alert(2, 2, "2026-10-20T08:30:00Z", r"C:\b.exe"),
        make_alert(3, 3, "2026-10-20T07:30:00.1234567Z", r"C:\c.exe"),
    ])
    since = client.get("/api/alerts?since=2026-10-20T07:15:00Z").get_json()
    assert sorted(a["id"] for a in since) == ["a2", "a3"]
    newest = client.get("/api/alerts?limit=2").get_json()
    assert [a["id"] for a in newest] == ["a2", "a3"]
    assert client.get("/api/alerts?since=kaputt").status_code == 400
