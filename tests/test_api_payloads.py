"""API payloads: size, shape and the data they report.

Regressions covered:
  * /api/alerts carried ~79 MB of duplicated raw fields per poll
  * /api/sessions returned every alert in one session (78 MB)
  * submissions recorded a sample path that never existed
  * the graph landing page listed memory scans ("PID 4072") as samples
  * Sysmon XPath without time bounds / parent filter
  * ETW events parsed from wevtutil RenderedXml
  * the verdict of a detonation computed on every view and never kept, so
    the history of the Submit tab could not show it; kept on another sample's
    or another run's submission, or written again on every poll; kept on the
    newest run of the sample when it was computed for none of its runs (a
    PID none of them had, no PID for a sample that always ran with one)
  * a kept verdict rebuilding the process tree and changing the ETag of the
    alert list (every open page loading tens of MB again)
  * the tests writing the submissions.json of the repository
  * a write of submissions.json that failed halfway (a full disk) leaving
    the history empty, without a word in the log; a file another program
    held for a moment failing the write; readers of the file that did not
    wait for a write to end
"""

import ast
import gzip
import json
import os
import threading

import pytest

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


# --- The verdict kept on the submission (VERDICT HISTORY of the Submit tab) ------

SHA_A, SHA_B = "a1" * 32, "b2" * 32


def _submissions_on_disk(tdc, monkeypatch, subs):
    """submissions.json with these entries (newest first, as the server keeps
    them), read back as the server reads it: a fresh copy on every load."""
    with open(tdc.SUBMISSIONS_FILE, "w") as f:
        json.dump(subs, f)

    def load():
        with open(tdc.SUBMISSIONS_FILE) as f:
            return json.load(f)

    monkeypatch.setattr(tdc, "_load_submissions", load)
    return load


def _results_without_the_vm(tdc, monkeypatch):
    """/api/detonation/results with LitterBox, the agent, the EDRs and Sysmon away."""
    monkeypatch.setattr(tdc, "_fetch_many", lambda specs: {})
    monkeypatch.setattr(tdc, "_litterbox_online", lambda: False)
    monkeypatch.setattr(tdc, "_is_fibratus_running", lambda: False)
    monkeypatch.setattr(tdc, "_is_rustinel_running", lambda: False)
    monkeypatch.setattr(tdc, "_network_beaconing_for_pid", lambda pid: {"available": False})
    monkeypatch.setattr(tdc, "_pipe_activity_for", lambda pid, sha256=None, at=None: {"available": False})


def test_the_tests_keep_away_from_the_submissions_of_the_repository(tdc, tmp_path):
    """webui/submissions.json is in the repository: a test that stores a
    verdict must write a file of its own."""
    assert os.path.dirname(tdc.SUBMISSIONS_FILE) == str(tmp_path)


def test_detonation_results_store_the_verdict_on_the_submission(tdc, client, monkeypatch):
    """The verdict /api/detonation/results computes is kept, as its label and
    score, on the submission of the run it was computed for: the one of the
    sample with this PID; without a PID the one of the sample that ran
    without (LitterBox only). It is written under the submissions lock and
    only when it changed. A PID none of the sample's submissions ran as, no
    PID for a sample that always ran with one (tdc_detonation_results with a
    hash only), a sample without a submission, or a PID alone (PIDs are
    reused) keep it nowhere: it was computed for no run of the history."""
    load = _submissions_on_disk(tdc, monkeypatch, [
        {"id": "new", "sha256": SHA_A, "agent_pid": 5000, "timestamp": "2026-11-05T11:37:11", "filename": "evil.exe",
         "verdict": None},
        {"id": "old", "sha256": SHA_A, "agent_pid": 4242, "timestamp": "2026-11-05T10:00:00", "filename": "evil.exe",
         "verdict": None},
        {"id": "other", "sha256": SHA_B, "agent_pid": 4242, "timestamp": "2026-11-04T10:00:00", "filename": "b.exe",
         "verdict": None},
        {"id": "lb", "sha256": SHA_A, "agent_pid": None, "timestamp": "2026-11-03T10:00:00", "filename": "evil.exe",
         "verdict": None},
        {"id": "nosha", "agent_pid": 4242, "timestamp": "2026-11-02T10:00:00", "filename": "old.exe", "verdict": None},
    ])
    real_save, saves = tdc._save_submissions, []

    def save(subs):
        saves.append(tdc.submissions_lock.locked())
        real_save(subs)

    monkeypatch.setattr(tdc, "_save_submissions", save)
    _results_without_the_vm(tdc, monkeypatch)
    computed = {"label": "MALICIOUS", "score": 4, "reasons": ["1 critical EDR alert(s)", "LitterBox score 8/10"]}
    monkeypatch.setattr(tdc, "_compute_verdict", lambda results, alerts: dict(computed))

    def verdict_of(query):
        r = client.get("/api/detonation/results?" + query)
        assert r.status_code == 200
        return r.get_json()["verdict"]

    def kept():
        return {sub["id"]: sub["verdict"] for sub in load()}

    malicious, suspicious, clean = ({"label": "MALICIOUS", "score": 4}, {"label": "SUSPICIOUS", "score": 2},
                                    {"label": "CLEAN", "score": 0})
    assert verdict_of(f"sha256={SHA_A}&pid=4242&filename=evil.exe") == computed
    assert kept() == {"new": None, "old": malicious, "other": None, "lb": None, "nosha": None}, "kept on another submission"
    assert saves == [True], "not written once, under the submissions lock"
    verdict_of(f"sha256={SHA_A}&pid=4242&filename=evil.exe")
    assert len(saves) == 1, "an unchanged verdict was written again"
    computed.update(label="SUSPICIOUS", score=2, reasons=[])
    verdict_of(f"sha256={SHA_A}&pid=4242")
    assert kept()["old"] == suspicious and len(saves) == 2, "a new verdict did not replace the kept one"
    # The newest run of the sample, the hash in any case
    verdict_of(f"sha256={SHA_A.upper()}&pid=5000")
    assert kept() == {"new": suspicious, "old": suspicious, "other": None, "lb": None, "nosha": None} and len(saves) == 3
    # A PID no submission of the sample ran as: no run of the history, kept nowhere (not on the newest run)
    computed.update(label="MALICIOUS", score=4)
    verdict_of(f"sha256={SHA_A}&pid=9999")
    assert kept() == {"new": suspicious, "old": suspicious, "other": None, "lb": None, "nosha": None} and len(saves) == 3, \
        "a verdict computed for a PID no run had was kept on a run of the sample"
    # Without a PID: the submission of the sample that ran without one (LitterBox only)
    computed.update(label="CLEAN", score=0)
    verdict_of(f"sha256={SHA_A}")
    assert kept() == {"new": suspicious, "old": suspicious, "other": None, "lb": clean, "nosha": None} and len(saves) == 4
    # Without a PID for a sample that only ran with one (tdc_detonation_results with a hash only): kept nowhere
    verdict_of(f"sha256={SHA_B}")
    assert kept()["other"] is None and len(saves) == 4, "a verdict computed without a PID was kept on a run with one"
    # Nothing to keep it on: an unknown sample, or a PID without a sample (not even a submission without a hash)
    verdict_of(f"sha256={'c3' * 32}&pid=4242")
    verdict_of("pid=4242")
    assert len(saves) == 4 and kept()["other"] is None and kept()["nosha"] is None, \
        "a verdict was kept on a submission of another sample"


def _disk_full_while_writing(tdc, monkeypatch):
    """A write of submissions.json fails halfway, as on a full disk: part of
    the list is written, then json.dump fails."""
    def dump(obj, f, **kw):
        f.write('[\n  {\n    "id": "')
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tdc.json, "dump", dump)


def _left_beside(tdc):
    """What a write of submissions.json left next to it."""
    folder = os.path.dirname(tdc.SUBMISSIONS_FILE)
    return sorted(name for name in os.listdir(folder) if name.startswith("submissions") and name != "submissions.json")


def test_detonation_results_survive_a_verdict_that_cannot_be_kept(tdc, client, monkeypatch, capsys):
    """Keeping the verdict is a side effect: a submissions file that cannot be
    written (the disk full halfway through the write) or read leaves the
    results as they are and the file as it was, and says so in the log."""
    _results_without_the_vm(tdc, monkeypatch)
    load = _submissions_on_disk(tdc, monkeypatch, [
        {"id": "s", "sha256": SHA_A, "agent_pid": 4242, "timestamp": "2026-11-05T10:00:00", "verdict": None}])
    with open(tdc.SUBMISSIONS_FILE, "rb") as f:
        before = f.read()
    _disk_full_while_writing(tdc, monkeypatch)
    r = client.get(f"/api/detonation/results?sha256={SHA_A}&pid=4242")
    assert r.status_code == 200 and r.get_json()["verdict"]["label"] == "CLEAN"
    out = capsys.readouterr().out
    assert "[submissions]" in out and "No space left on device" in out, out
    assert "No space left on device" not in r.get_data(as_text=True)
    with open(tdc.SUBMISSIONS_FILE, "rb") as f:
        assert f.read() == before, "a verdict that could not be kept emptied the submissions"
    assert [sub["id"] for sub in load()] == ["s"] and _left_beside(tdc) == []

    def unreadable():
        raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(tdc, "_load_submissions", unreadable)
    r = client.get(f"/api/detonation/results?sha256={SHA_A}&pid=4242")
    assert r.status_code == 200 and r.get_json()["verdict"]["label"] == "CLEAN"
    assert "[submissions]" in capsys.readouterr().out


def test_a_submission_that_cannot_be_recorded_keeps_the_others(tdc, monkeypatch, capsys):
    """A new submission whose write fails halfway (a full disk) keeps the
    history as it was: the file is written beside it and put in its place
    only once it is complete. The submit still answers with its entry; the
    log says what failed."""
    load = _submissions_on_disk(tdc, monkeypatch, [
        {"id": "s", "sha256": SHA_A, "agent_pid": 4242, "timestamp": "2026-11-05T10:00:00", "verdict": None},
        {"id": "t", "sha256": SHA_B, "agent_pid": 5000, "timestamp": "2026-11-04T10:00:00", "verdict": None}])
    with open(tdc.SUBMISSIONS_FILE, "rb") as f:
        before = f.read()
    real_dump = tdc.json.dump
    _disk_full_while_writing(tdc, monkeypatch)
    entry = tdc._record_submission("new.exe", "c3" * 32, 10, "agent", {})
    assert entry["sha256"] == "c3" * 32 and entry["filename"] == "new.exe"
    out = capsys.readouterr().out
    assert "[submissions]" in out and "No space left on device" in out, out
    with open(tdc.SUBMISSIONS_FILE, "rb") as f:
        assert f.read() == before, "a submission that could not be recorded took the others with it"
    assert [sub["id"] for sub in load()] == ["s", "t"] and _left_beside(tdc) == []
    # The disk has room again: the next submission joins the others
    monkeypatch.setattr(tdc.json, "dump", real_dump)
    tdc._record_submission("next.exe", "d4" * 32, 10, "agent", {})
    assert [sub.get("filename") for sub in load()] == ["next.exe", None, None] and _left_beside(tdc) == []


def test_a_submissions_file_another_program_holds_is_replaced_after_a_moment(tdc, monkeypatch):
    """On Windows another program (the virus scanner, an indexer) holding
    submissions.json for a moment fails putting the new file in its place
    with PermissionError: the write tries again shortly. When the file stays
    held it gives up: the error goes to its caller, the file stays as it
    was, and nothing is left beside it."""
    load = _submissions_on_disk(tdc, monkeypatch, [{"id": "s", "sha256": SHA_A, "verdict": None}])
    real_replace, attempts, pauses = os.replace, [], []

    def held(times):
        def replace(src, dst):
            attempts.append((os.path.basename(src), os.path.basename(dst)))
            if len(attempts) <= times:
                raise PermissionError(13, "The process cannot access the file because it is being used by another process")
            real_replace(src, dst)
        return replace

    monkeypatch.setattr(tdc.time, "sleep", pauses.append)
    monkeypatch.setattr(tdc.os, "replace", held(2))
    tdc._save_submissions([{"id": "n"}])
    assert [sub["id"] for sub in load()] == ["n"] and len(attempts) == 3 and len(pauses) == 2, (attempts, pauses)
    assert set(attempts) == {("submissions.json.tmp", "submissions.json")} and _left_beside(tdc) == []
    attempts.clear()
    pauses.clear()
    monkeypatch.setattr(tdc.os, "replace", held(10 ** 6))
    with pytest.raises(PermissionError):
        tdc._save_submissions([{"id": "m"}])
    assert [sub["id"] for sub in load()] == ["n"] and _left_beside(tdc) == []
    assert 3 <= len(attempts) <= 20 and 0 < sum(pauses) <= 2, (len(attempts), pauses)


def test_the_readers_of_the_submissions_wait_for_a_write(tdc, monkeypatch):
    """A write of submissions.json holds the submissions lock from reading the
    list to putting the new file in its place; every reader takes it as
    well: the samples of the graph, the detonation windows of the process
    tree (which stays cached), the start of a submission for its pipes."""
    seen = []

    def load():
        seen.append(tdc.submissions_lock.locked())
        return [{"id": "s", "sha256": SHA_A, "agent_pid": 4242, "timestamp": "2026-11-05T10:00:00", "filename": "evil.exe"}]

    monkeypatch.setattr(tdc, "_load_submissions", load)
    tdc._build_samples({}, {}, {})
    tdc.build_process_tree([])
    tdc._pipe_submission_start("4242", SHA_A)
    assert seen == [True, True, True], "a reader of the submissions does not wait for a write to end"
    # The lock is not re-entrant: building the tree (which reads the file twice) does not wait for itself
    with open(tdc.SUBMISSIONS_FILE, "w") as f:
        json.dump(load(), f)
    done = threading.Event()

    def build():
        tdc._store_alerts([make_alert(1, 4242, "2026-11-05T09:00:05Z", r"C:\x\evil.exe")])
        done.set()

    threading.Thread(target=build, daemon=True).start()
    if not done.wait(10):
        tdc.submissions_lock.release()
        pytest.fail("building the process tree waits for the submissions lock it holds itself")


def test_nothing_takes_the_submissions_lock_while_holding_it(app_module):
    """submissions_lock is not re-entrant: nothing app.py calls while it holds
    the lock takes it again (itself or through the functions it calls)."""
    with open(app_module.__file__, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    def locked(node):
        return isinstance(node, ast.With) and any(
            isinstance(item.context_expr, ast.Name) and item.context_expr.id == "submissions_lock" for item in node.items)

    def calls(nodes):
        return {n.func.id for node in nodes for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}

    takers = {name for name, fn in functions.items() if any(locked(n) for n in ast.walk(fn))}
    while True:
        more = {name for name, fn in functions.items() if name not in takers and calls([fn]) & takers}
        if not more:
            break
        takers |= more
    assert {"_build_samples", "_agent_detonation_index", "_pipe_submission_start", "build_process_tree",
            "_record_submission", "_store_submission_verdict"} <= takers
    nested = {name: sorted(calls(block.body) & takers) for name, fn in functions.items()
              for block in ast.walk(fn) if locked(block) and calls(block.body) & takers}
    assert not nested, f"called while holding the submissions lock, and taking it: {nested}"


def test_a_kept_verdict_leaves_the_process_tree_and_the_alert_list_as_they_were(tdc, client, monkeypatch):
    """The process tree takes only when and as which PID and file each sample
    ran from submissions.json: a verdict kept there neither builds the tree
    again nor changes the ETag of the alert list (every open page would load
    the whole list again). A new submission does both."""
    load = _submissions_on_disk(tdc, monkeypatch, [
        {"id": "s", "sha256": SHA_A, "agent_pid": 4242, "timestamp": "2026-10-20T10:00:00", "filename": "evil.exe",
         "file_path": r"C:\Users\Public\Downloads\evil.exe", "verdict": None}])
    builds = []
    real_build = tdc.build_process_tree
    monkeypatch.setattr(tdc, "build_process_tree", lambda alerts: builds.append(len(alerts)) or real_build(alerts))
    alerts = [make_alert(1, 4242, "2026-10-20T08:00:05Z", r"C:\Users\Public\Downloads\evil.exe")]
    stamp = [os.path.getmtime(tdc.SUBMISSIONS_FILE)]

    def touched():
        # A new modification time, as a write a second later gives it on any file system
        stamp[0] += 10
        os.utime(tdc.SUBMISSIONS_FILE, (stamp[0], stamp[0]))

    def etag():
        return client.get("/api/alerts").headers["ETag"]

    tdc._store_alerts(alerts)
    first = etag()
    assert builds == [1]
    tdc._store_submission_verdict(SHA_A, "4242", {"label": "MALICIOUS", "score": 4, "reasons": ["x"]})
    assert load()[0]["verdict"] == {"label": "MALICIOUS", "score": 4}
    touched()
    tdc._store_alerts(alerts)
    assert builds == [1] and etag() == first, "a kept verdict built the process tree again or changed the alert list's ETag"
    # Another detonation: its window changes the tree
    subs = load()
    subs.insert(0, {"id": "t", "sha256": SHA_B, "agent_pid": 5000, "timestamp": "2026-10-21T10:00:00",
                    "filename": "b.exe", "verdict": None})
    with open(tdc.SUBMISSIONS_FILE, "w") as f:
        json.dump(subs, f)
    touched()
    tdc._store_alerts(alerts)
    assert builds == [1, 1] and etag() != first, "a new submission did not build the process tree again"
    tdc._store_alerts(alerts)
    assert builds == [1, 1], "an unchanged file built the tree again"
