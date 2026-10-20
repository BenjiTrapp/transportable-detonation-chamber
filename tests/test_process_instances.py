"""Process instances: Windows reuses PIDs, so a PID alone never identifies a process.

Regressions covered:
  * a later holder of a PID merged with an earlier one (PID 1112 showed a
    September PowerShell with its children under today's aether.exe)
  * children attached to the wrong holder of their parent's PID
  * events of one holder attributed to another
  * Sysmon's "-" for an unknown parent became a nameless stub
"""

from conftest import make_alert


SEPT = "2026-09-14T08:01:01Z"
OCT = "2026-10-20T12:00:12Z"


def _by_name(procs):
    """name -> (key, process) for real processes (stub parents excluded)."""
    return {p["name"]: (k, p) for k, p in procs.items() if not p.get("is_stub")}


def test_reused_pid_creates_separate_instances(tdc):
    procs = tdc.build_process_tree([
        make_alert(1, 1112, SEPT, r"C:\Windows\System32\powershell.exe", 12452, "cmd.exe"),
        make_alert(2, 1112, OCT, r"C:\tools\Aether\Aether.exe", 7000, "python.exe"),
        make_alert(3, 1112, "2026-10-20T12:00:20Z", r"C:\tools\Aether\Aether.exe", 7000, "python.exe"),
    ])
    holders = {k: p for k, p in procs.items() if p["pid"] == "1112" and not p.get("is_stub")}
    assert len(holders) == 2
    # The newest holder keeps the plain PID as key, the older one is <pid>@<epoch>.
    assert holders["1112"]["name"] == "Aether.exe"
    assert len(holders["1112"]["alerts"]) == 2
    old_key = next(k for k in holders if k != "1112")
    assert old_key.startswith("1112@")
    assert holders[old_key]["name"] == "powershell.exe"
    assert len(holders[old_key]["alerts"]) == 1


def test_children_attach_to_the_holder_alive_at_their_start(tdc):
    procs = tdc.build_process_tree([
        make_alert(1, 1112, SEPT, r"C:\x\powershell.exe", 12452, "cmd.exe"),
        make_alert(2, 836, "2026-09-14T08:01:05Z", r"C:\x\RuntimeBroker.exe", 1112, "powershell.exe"),
        make_alert(3, 1112, OCT, r"C:\x\Aether.exe", 7000, "python.exe"),
        make_alert(4, 9000, "2026-10-20T12:00:30Z", r"C:\x\cmd.exe", 1112, "Aether.exe"),
    ])
    names = _by_name(procs)
    old_ps_key = names["powershell.exe"][0]
    assert names["RuntimeBroker.exe"][1]["parent_key"] == old_ps_key
    assert names["cmd.exe"][1]["parent_key"] == "1112"
    assert procs["1112"]["children"] == ["9000"]
    assert procs[old_ps_key]["children"] == ["836"]


def test_parent_with_a_different_image_is_not_taken(tdc):
    # The only known holder of PID 1112 is a PowerShell; a child whose parent
    # was DetonatorAgent.exe must not hang under it but under its own stub.
    procs = tdc.build_process_tree([
        make_alert(1, 1112, SEPT, r"C:\x\powershell.exe", 12452, "cmd.exe"),
        make_alert(2, 4072, OCT, r"C:\x\injectsim.exe", 1112, "DetonatorAgent.exe"),
        make_alert(3, 4073, "2026-10-20T12:00:13Z", r"C:\x\other.exe", 1112, "DetonatorAgent.exe"),
    ])
    sample = next(p for p in procs.values() if p["name"] == "injectsim.exe")
    parent = procs[sample["parent_key"]]
    assert parent["name"] == "DetonatorAgent.exe"
    assert parent.get("is_stub")
    assert sorted(parent["children"]) == ["4072", "4073"]
    powershell = next(p for p in procs.values() if p["name"] == "powershell.exe")
    assert powershell["children"] == []


def test_exit_starts_a_new_instance_for_the_same_image(tdc):
    ended = make_alert(1, 500, "2026-10-01T10:00:00Z", r"C:\x\cmd.exe",
                       raw={"event.action": "process_terminated"})
    procs = tdc.build_process_tree([
        ended,
        make_alert(2, 500, "2026-10-02T10:00:00Z", r"C:\x\cmd.exe"),
    ])
    assert len([p for p in procs.values() if p["pid"] == "500"]) == 2


def test_resolver_by_time_image_and_key(tdc):
    procs = {
        "7@100": {"pid": "7", "started": "1970-01-01T00:01:40Z", "image": r"C:\a.exe"},
        "7": {"pid": "7", "started": "1970-01-01T00:16:40Z", "image": r"C:\b.exe"},
    }
    r = tdc._PidInstances(procs)
    assert r.resolve("7", "1970-01-01T00:05:00Z") == "7@100"
    assert r.resolve("7", "1970-01-01T01:00:00Z") == "7"
    assert r.resolve("7", "1970-01-01T01:00:00Z", image="a.exe") == "7@100"
    # Exact starts: nothing of PID 7 was alive before the first start.
    assert r.resolve("7", "1970-01-01T00:00:01Z") is None
    assert r.resolve_key("7@100") == "7@100"
    assert r.resolve_key("7") == "7"
    assert r.resolve_key("7", at="1970-01-01T00:05:00Z") == "7@100"


def _sysmon_create(pid, ts, image, ppid, parent_image="-"):
    return {"event_id": 1, "pid": str(pid), "timestamp": ts, "image": image,
            "commandline": image, "parent_pid": str(ppid), "parent_image": parent_image,
            "user": "SYSTEM", "integrity": "System", "hashes": ""}


def _with_sysmon(tdc, monkeypatch, events):
    monkeypatch.setattr(tdc, "_is_sysmon_running", lambda: True)
    monkeypatch.setattr(tdc, "_read_sysmon_events", lambda **kw: list(events))


def test_sysmon_tree_and_graph_scope_events_to_the_instance(tdc, client, monkeypatch):
    events = [
        _sysmon_create(4072, "2026-10-20T10:00:00+00:00", r"C:\Windows\System32\wevtutil.exe", 4548),
        _sysmon_create(4548, "2026-10-20T09:00:00+00:00", r"C:\Python\python.exe", 1),
        _sysmon_create(4072, "2026-10-20T08:00:00+00:00", r"C:\Users\Public\Downloads\injectsim.exe",
                       2964, r"C:\DetonatorAgent\DetonatorAgent.exe"),
        {"event_id": 3, "pid": "4072", "timestamp": "2026-10-20T08:00:05+00:00",
         "dst_ip": "10.0.0.1", "dst_port": "443", "protocol": "tcp"},
        {"event_id": 3, "pid": "4072", "timestamp": "2026-10-20T10:00:05+00:00",
         "dst_ip": "10.9.9.9", "dst_port": "53", "protocol": "udp"},
    ]
    _with_sysmon(tdc, monkeypatch, events)

    newest = client.get("/api/process-graph?pid=4072").get_json()
    assert newest["processes"][newest["root_pid"]]["name"] == "wevtutil.exe"
    assert [e["dst_ip"] for e in newest["network"]] == ["10.9.9.9"]

    sample = client.get("/api/process-graph?pid=4072&at=2026-10-20T08:00:30Z").get_json()
    root = sample["processes"][sample["root_pid"]]
    assert root["name"] == "injectsim.exe" and sample["root_pid"].startswith("4072@")
    assert [e["dst_ip"] for e in sample["network"]] == ["10.0.0.1"]
    assert all(e["key"] == sample["root_pid"] for e in sample["network"])
    # Parent outside the event window: a stub named after Sysmon's ParentImage.
    parent = sample["processes"][root["parent_key"]]
    assert parent["name"] == "DetonatorAgent.exe" and parent["is_ancestor"]

    by_key = client.get(f"/api/process-graph?pid={sample['root_pid']}").get_json()
    assert by_key["root_pid"] == sample["root_pid"]


def test_unknown_sysmon_parent_is_not_a_nameless_stub(tdc, monkeypatch):
    _with_sysmon(tdc, monkeypatch, [
        _sysmon_create(4072, "2026-10-20T10:00:00+00:00", r"C:\x\wevtutil.exe", 4548, "-"),
    ])
    proc_map, _ = tdc._build_full_process_map()
    assert all(p.get("name") not in ("", "-") for p in proc_map.values())
    assert proc_map["4072"]["parent_name"] == ""


def test_process_detail_route_accepts_instance_keys(tdc, client):
    tdc._store_alerts([
        make_alert(1, 1112, SEPT, r"C:\x\powershell.exe"),
        make_alert(2, 1112, OCT, r"C:\x\Aether.exe"),
    ])
    assert client.get("/api/processes/1112").get_json()["name"] == "Aether.exe"
    old = next(k for k in tdc.events_store["processes"] if k.startswith("1112@"))
    assert client.get(f"/api/processes/{old}").get_json()["name"] == "powershell.exe"
    assert client.get("/api/processes/1112?at=2026-09-14T09:00:00Z").get_json()["name"] == "powershell.exe"
    assert client.get("/api/processes/999999").status_code == 404
