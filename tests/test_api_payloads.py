"""API payloads: size, shape and the data they report.

Regressions covered:
  * /api/alerts carried ~79 MB of duplicated raw fields per poll
  * /api/sessions returned every alert in one session (78 MB)
  * submissions recorded a sample path that never existed
  * the graph landing page listed memory scans ("PID 4072") as samples
  * Sysmon XPath without time bounds / parent filter
  * ETW events parsed from wevtutil RenderedXml
"""

import gzip
import json

from conftest import make_alert


def _big_alert(i):
    cmd = "powershell -enc " + "A" * 2000
    return make_alert(i, 100 + i, f"2026-10-20T08:{i % 60:02d}:00Z", r"C:\x\powershell.exe",
                      command_line=cmd, rule_description="desc " * 50,
                      raw={"process.command_line": cmd, "rule.description": "desc " * 50,
                           "edr.match": {"summary": "matched", "sigma": {"big": "x" * 3000}},
                           "event.action": "process-start"})


def test_alert_list_is_slim_and_compressed(client, tdc):
    tdc._store_alerts([_big_alert(i) for i in range(50)])
    full = len(json.dumps(tdc.events_store["alerts"]))
    r = client.get("/api/alerts", headers={"Accept-Encoding": "gzip"})
    assert r.headers["Content-Encoding"] == "gzip"
    body = json.loads(gzip.decompress(r.data))
    assert len(r.data) < full / 20
    a = body[0]
    assert a["raw_trimmed"] is True
    assert "process.command_line" not in a["raw"]
    assert a["raw"]["edr.match"] == {"summary": "matched"}
    assert a["raw"]["event.action"] == "process-start"
    # Unchanged list -> 304 without a body.
    again = client.get("/api/alerts", headers={"If-None-Match": r.headers["ETag"]})
    assert again.status_code == 304 and not again.data


def test_alert_detail_has_the_full_raw_event(client, tdc):
    tdc._store_alerts([_big_alert(1)])
    d = client.get("/api/alerts/a1").get_json()
    assert d["raw"]["edr.match"]["sigma"]["big"].startswith("x")
    assert client.get("/api/alerts/nope").status_code == 404


def test_sessions_are_summaries(client, tdc):
    alerts = [make_alert(i, 7, f"2026-10-20T08:00:{i:02d}Z", r"C:\x\a.exe") for i in range(5)]
    alerts += [make_alert(10 + i, 8, f"2026-10-20T12:00:{i:02d}Z", r"C:\x\b.exe") for i in range(3)]
    tdc._store_alerts(alerts)
    d = client.get("/api/sessions?gap=600").get_json()
    assert d["total_sessions"] == 2
    newest = d["sessions"][0]
    assert newest["count"] == 3 and newest["processes"][0]["name"] == "b.exe"
    assert "alerts" not in newest and len(newest["alert_ids"]) == 3


def test_submission_path_points_at_an_existing_file(tdc, client, monkeypatch, tmp_path):
    drop = tmp_path / "Downloads"
    drop.mkdir()
    (drop / "evil.exe").write_bytes(b"MZ")
    real_join = tdc.os.path.join
    monkeypatch.setattr(tdc.os.path, "join",
                        lambda a, *rest: real_join(str(drop), *rest) if a == r"C:\Users\Public\Downloads"
                        else real_join(a, *rest))
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [
        {"filename": "evil.exe", "file_path": r"C:\Users\vagrant\Desktop\infected\evil.exe"}])
    subs = client.get("/api/submissions").get_json()
    assert subs[0]["file_path"] == str(drop / "evil.exe")
    assert "vagrant" not in json.dumps(subs)


def test_graph_samples_exclude_process_scans(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_load_scan_history", lambda: [
        {"tool": "Aether", "filename": "PID 4072", "verdict": "clean"},
        {"tool": "Exit Capture", "filename": "PID 4072", "verdict": "detected", "score": 6.54},
        {"tool": "EMBER2024", "filename": "a.exe", "sha256": "cd" * 32, "verdict": "benign", "score": 0.3},
    ])
    samples = tdc._build_samples({}, {}, {})
    assert [s["filename"] for s in samples] == ["a.exe"]


def test_sysmon_xpath_filters(tdc):
    q = tdc._sysmon_xpath([1, 3], since="2026-10-20T08:00:00Z", until="2026-10-20T09:00:00Z",
                          pid=12, parent_pid=34)
    assert "EventID=1 or EventID=3" in q
    assert "@SystemTime>='2026-10-20T08:00:00.000Z'" in q
    assert "@SystemTime<'2026-10-20T09:00:00.000Z'" in q
    assert "Data[@Name='ProcessId']='12'" in q and "Data[@Name='ParentProcessId']='34'" in q
    assert tdc._sysmon_xpath(None) == "*"


ETW_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID>
<TimeCreated SystemTime='2026-10-20T08:54:06.1234567Z'/></System><EventData>
<Data Name='TargetUserName'>TDC</Data><Data Name='LogonType'>3</Data></EventData>
<RenderingInfo Culture='de-DE'><Level>Informationen</Level>
<Message>Ein Konto wurde erfolgreich angemeldet.&#13;&#10;Details</Message></RenderingInfo></Event>"""


class _Completed:
    def __init__(self, xml):
        self.stdout = b"\xff\xfe" + xml.encode("utf-16-le")
        self.stderr, self.returncode = b"", 0


def test_etw_events_from_rendered_xml(tdc, client, monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen["args"] = args
        return _Completed(ETW_XML)

    monkeypatch.setattr(tdc.subprocess, "run", fake_run)
    d = client.get("/api/etw/events?channel=security&max=5&event_id=4624").get_json()
    assert seen["args"][:3] == ["wevtutil", "qe", "Security"]
    assert "/q:*[System[EventID=4624]]" in seen["args"]
    ev = d["events"][0]
    assert (ev["event_id"], ev["level"], ev["provider"]) == (4624, "Informationen", "Microsoft-Windows-Security-Auditing")
    assert ev["message"] == "Ein Konto wurde erfolgreich angemeldet."
    assert ev["data"] == {"TargetUserName": "TDC", "LogonType": "3"}
    assert client.get("/api/etw/events?channel=security&since=nope").status_code == 400
