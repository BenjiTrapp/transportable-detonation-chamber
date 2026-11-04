"""Named pipe signature catalog and name normalization."""

import json

import pipe_analysis
from pipe_analysis import (canonical_name, load_signatures, looks_random,
                           match_signature, normalize_for_key)


def test_canonical_name():
    for name in (r"\\.\pipe\msagent_12", "msagent_12", r"\msagent_12"):
        assert canonical_name(name) == r"\msagent_12"
    assert canonical_name(r"\\.\PIPE\MSSE-1-server") == r"\MSSE-1-server"


def test_normalize_for_key():
    assert normalize_for_key("status_4a3f9c") == r"\status_*"
    assert normalize_for_key("MSSE-1234-server") == r"\msse-*-server"
    assert normalize_for_key("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}") == r"\*"


def _family(name, sigs):
    hit = match_signature(name, sigs)
    return hit["family"] if hit else None


def test_signature_catalog_matches_defaults():
    sigs = load_signatures(None)
    for name in (r"\msagent_5b", r"\postex_ab12", r"\status_33",
                 r"\MSSE-4242-server", r"\postex_ssh_1a"):
        assert _family(name, sigs) == "Cobalt Strike", name
    assert _family(r"\PSEXESVC", sigs) == "PsExec"
    for name in (r"\paexec_x", r"\RemCom_communicaton", r"\csexecsvc"):
        assert _family(name, sigs) == "PAExec/RemCom/CSExec", name
    assert match_signature(r"\lsass", sigs) is None
    assert match_signature(r"\mojo.123.456", sigs) is None


def test_catalog_entries_are_well_formed_and_skip_svcctl():
    sigs = load_signatures(None)
    assert sigs
    for sig in sigs:
        assert set(sig) >= {"family", "pattern", "match", "weight", "note"}
        assert sig["match"] in ("prefix", "exact", "contains", "regex")
        assert sig["family"] and sig["note"]
    assert match_signature(r"\svcctl", sigs) is None


def test_invalid_regex_entry_is_skipped(tmp_path):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps([
        {"family": "Broken", "pattern": "(", "match": "regex", "weight": 1.0, "note": "bad"},
        {"family": "Good", "pattern": r"\good_", "match": "prefix", "weight": 2.0, "note": "ok"},
    ]))
    sigs = load_signatures(str(path))
    assert [s["family"] for s in sigs] == ["Good"]
    assert _family(r"\GOOD_1", sigs) == "Good"


def test_looks_random():
    assert looks_random(r"\a8f3c2e9b7d1f4e6") is True
    assert looks_random(r"\docker_engine") is False
    assert looks_random(r"\{3F2504E0-4F89-11D3-9A0C-0305E82C3301}") is True


def test_module_has_default_catalog_path():
    assert pipe_analysis.DEFAULT_SIGNATURES_PATH.endswith("pipe_signatures.json")


def test_signatures_are_json_serializable():
    sigs = load_signatures(None)
    json.dumps(sigs)
    json.dumps(match_signature(r"\MSSE-1-server", sigs))


def test_prefix_pattern_without_backslash_is_canonicalized(tmp_path):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps([
        {"family": "CS", "pattern": "postex_", "match": "prefix", "weight": 4.0, "note": "n"},
    ]))
    sigs = load_signatures(str(path))
    assert _family(r"\postex_1", sigs) == "CS"
    assert _family(r"\\.\pipe\POSTEX_1", sigs) == "CS"


def test_bad_weight_and_non_dict_entries_are_skipped(tmp_path, capsys):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps([
        "not a dict",
        {"family": "Bad", "pattern": r"\bad", "match": "exact", "weight": "high", "note": "n"},
        {"family": "Good", "pattern": r"\good", "match": "exact", "weight": "2.5", "note": "n"},
    ]))
    sigs = load_signatures(str(path))
    assert [s["family"] for s in sigs] == ["Good"]
    assert sigs[0]["weight"] == 2.5
    out = capsys.readouterr().out
    assert out.count("[pipe_analysis]") >= 2


def test_normalize_keeps_english_hex_words():
    for word in (r"\feedback", r"\dbaccess", r"\cafe"):
        assert normalize_for_key(word) == word
    assert normalize_for_key("status_4a3f9c") == r"\status_*"
    assert normalize_for_key("MSSE-1234-server") == r"\msse-*-server"
    assert normalize_for_key("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}") == r"\*"


def test_sysmon_installer_switches_pipeevent_to_exclude():
    import os
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "scripts", "install-sysmon.ps1"), encoding="utf-8") as fh:
        script = fh.read()

    # Existing PipeEvent elements (the include-mode block) are removed.
    assert re.search(r"SelectNodes\([^)]*PipeEvent", script)
    assert "RemoveChild" in script
    assert 'onmatch="exclude"' in script and "<PipeEvent" in script
    assert 'onmatch="include"' not in script.split("<PipeEvent", 1)[1].split("</PipeEvent>", 1)[0]

    block = script.split('<PipeEvent onmatch="exclude">', 1)[1].split("</PipeEvent>", 1)[0]
    rules = re.findall(r'<Rule groupRelation="and">(.*?)</Rule>', block, re.S)
    assert rules
    for rule in rules:
        assert "<Image" in rule
        assert "<PipeName" in rule
    pairs = {(re.findall(r"<Image[^>]*>([^<]+)</Image>", r)[-1].rsplit("\\", 1)[-1],
              re.search(r"<PipeName[^>]*>([^<]+)</PipeName>", r).group(1)) for r in rules}
    for image in ("chrome.exe", "msedge.exe"):
        assert (image, r"\mojo.") in pairs
        assert (image, r"\crashpad_") in pairs
    for pipe in (r"\lsass", r"\ntsvcs", r"\srvsvc", r"\wkssvc"):
        assert ("svchost.exe", pipe) in pairs
    assert any(img == "MsMpEng.exe" for img, _ in pairs)
    # No rule may exclude by pipe name alone.
    assert not re.search(r"<PipeEvent onmatch=\"exclude\">\s*<PipeName", script)

    # Post-processing applies to both install paths: before -c and before -i.
    calls = [m.start() for m in re.finditer(r"Set-PipeEventExclude\b", script)]
    assert len(calls) >= 3  # definition + two call sites
    assert script.index("-c $configPath") > calls[1]
    assert script.rindex("-i $configPath") > calls[-1]

    m = re.search(r"wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:(\d+)", script)
    assert m and int(m.group(1)) >= 536870912


DEFENDER_PLATFORM = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"


def _sysmon_pipe_rules():
    import os
    import re
    import xml.etree.ElementTree as ET

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "scripts", "install-sysmon.ps1"), encoding="utf-8") as fh:
        script = fh.read()
    m = re.search(r"\$pipeGroup = @'\r?\n(.*?)\r?\n'@", script, re.S)
    assert m, "pipe rule here-string not found"
    group = ET.fromstring(m.group(1))
    pipe_event = group.find("PipeEvent")
    assert pipe_event is not None and pipe_event.get("onmatch") == "exclude"
    return pipe_event.findall("Rule")


def test_sysmon_pipe_rules_are_anchored_to_image_paths():
    rules = _sysmon_pipe_rules()
    assert rules
    for rule in rules:
        assert rule.get("groupRelation") == "and"
        assert len(rule.findall("PipeName")) == 1
        images = rule.findall("Image")
        assert images
        for image in images:
            assert image.text.startswith("\\") or image.text[1:3] == ":\\", image.text
            if image.get("condition") == "end with":
                assert image.text.startswith("\\"), image.text

    def images_of(rule):
        return [(i.get("condition"), i.text) for i in rule.findall("Image")]

    msmpeng = [r for r in rules
               if any(t.lower().endswith("\\msmpeng.exe") for _, t in images_of(r))]
    assert msmpeng
    for rule in msmpeng:
        assert ("begin with", DEFENDER_PLATFORM) in images_of(rule)


# --- Sysmon EID 17/18 parsing and attribution --------------------------------

PIPE_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>17</EventID>
<TimeCreated SystemTime='2026-11-04T10:00:01.1234567Z'/></System>
<EventData><Data Name='RuleName'>-</Data><Data Name='EventType'>CreatePipe</Data>
<Data Name='UtcTime'>2026-11-04 10:00:01.123</Data>
<Data Name='ProcessGuid'>{11111111-2222-3333-4444-555555555555}</Data>
<Data Name='ProcessId'>4072</Data><Data Name='PipeName'>\\msagent_5b</Data>
<Data Name='Image'>C:\\Users\\Public\\beacon.exe</Data><Data Name='User'>LAB\\analyst</Data>
</EventData></Event>"""


class _Proc:
    stdout, stderr, returncode = b"x", b"", 0


def test_parse_pipe_events(tdc, monkeypatch):
    seen = {}

    def fake_query(log, query=None, count=None, newest_first=True, timeout=30):
        seen["query"] = query
        return PIPE_XML, _Proc()

    monkeypatch.setattr(tdc, "_wevtutil_query", fake_query)
    events = tdc._read_sysmon_events(event_ids=[17, 18], max_events=10)
    assert "EventID=17" in seen["query"] and "EventID=18" in seen["query"]
    assert len(events) == 1
    ev = events[0]
    assert ev["type"] == "PipeCreated"
    assert ev["pipe"] == r"\msagent_5b"
    assert ev["event_type"] == "CreatePipe"
    assert ev["pid"] == "4072"
    assert ev["image"] == r"C:\Users\Public\beacon.exe"
    assert ev["user"] == r"LAB\analyst"
    assert ev["timestamp"]


def _pipe_ev(kind, pid, pipe, ts="2026-11-04T10:00:00+00:00", image="x.exe"):
    return {"type": "PipeCreated" if kind == "create" else "PipeConnected",
            "event_type": "CreatePipe" if kind == "create" else "ConnectPipe",
            "pid": str(pid), "pipe": pipe, "timestamp": ts, "image": image, "user": ""}


def _resolve(pid, ts):
    return str(pid)


def test_analyze_flags():
    events = [
        _pipe_ev("create", 4072, r"\msagent_5b", "2026-11-04T10:00:00+00:00", "beacon.exe"),
        _pipe_ev("connect", 5000, r"\msagent_5b", "2026-11-04T10:00:05+00:00", "rundll32.exe"),
    ]
    res = pipe_analysis.analyze(events, {"4072"}, _resolve, self_pid=1)
    assert res["evidence_findings"] == []
    assert len(res["pipes"]) == 1
    p = res["pipes"][0]
    assert p["pipe"] == r"\msagent_5b"
    assert p["family"] == "Cobalt Strike"
    assert p["note"]
    assert {"c2_default", "cross_process"} <= set(p["flags"])
    assert p["created_by"] == ["4072"]
    assert p["connected_by"] == ["5000"]
    assert p["first_seen"] == "2026-11-04T10:00:00+00:00"
    assert p["last_seen"] == "2026-11-04T10:00:05+00:00"


def test_analyze_sensitive_system_pipe():
    events = [_pipe_ev("connect", 4072, r"\svcctl")]
    res = pipe_analysis.analyze(events, {"4072"}, _resolve, self_pid=1)
    p = res["pipes"][0]
    assert "sensitive_system" in p["flags"]
    assert "c2_default" not in p["flags"]
    assert p["family"] is None


def test_analyze_ignores_own_proxy_and_pshost():
    events = [
        _pipe_ev("create", 4072, r"\PSHost.1.2.powershell"),
        _pipe_ev("create", 999, r"\msagent_aa"),
        _pipe_ev("connect", 999, r"\svcctl"),
        _pipe_ev("connect", 4072, r"\msagent_bb"),
        _pipe_ev("create", 999, r"\msagent_bb"),
    ]
    res = pipe_analysis.analyze(events, {"4072"}, _resolve, self_pid=999)
    names = [p["pipe"] for p in res["pipes"]]
    assert names == [r"\msagent_bb"]
    p = res["pipes"][0]
    assert p["created_by"] == [] and p["connected_by"] == ["4072"]
    assert "cross_process" not in p["flags"]


def test_unrelated_processes_are_not_attributed():
    events = [
        _pipe_ev("create", 4072, r"\status_12"),
        _pipe_ev("create", 6000, r"\msagent_99"),
        _pipe_ev("connect", 6001, r"\msagent_99"),
        _pipe_ev("connect", 6001, r"\svcctl"),
    ]
    res = pipe_analysis.analyze(events, {"4072"}, _resolve, self_pid=1)
    assert [p["pipe"] for p in res["pipes"]] == [r"\status_12"]
    p = res["pipes"][0]
    assert p["created_by"] == ["4072"] and "cross_process" not in p["flags"]


def test_analyze_random_name_and_case_insensitive_grouping():
    events = [
        _pipe_ev("create", 4072, r"\Xk9qZ2mVb7Lw4Tn"),
        _pipe_ev("connect", 4072, r"\xk9qz2mvb7lw4tn"),
    ]
    res = pipe_analysis.analyze(events, {"4072"}, _resolve, self_pid=1)
    assert len(res["pipes"]) == 1
    assert "random_name" in res["pipes"][0]["flags"]


def _local(h, m=0, s=0):
    import datetime
    return datetime.datetime(2026, 11, 4, h, m, s).astimezone().isoformat()


def test_pipe_activity_for_scopes_to_sample_subtree(tdc, monkeypatch):
    from test_process_instances import _sysmon_create

    procs = [
        _sysmon_create(4072, _local(10, 0, 0), r"C:\Users\Public\sample.exe", 2964,
                       r"C:\DetonatorAgent\DetonatorAgent.exe"),
        _sysmon_create(4100, _local(10, 0, 3), r"C:\Windows\System32\rundll32.exe", 4072),
        _sysmon_create(6000, _local(9, 0, 0), r"C:\Windows\System32\svchost.exe", 1),
    ]
    pipes = [
        _pipe_ev("create", 4100, r"\msagent_5b", _local(10, 0, 4)),
        _pipe_ev("connect", 6000, r"\msagent_5b", _local(10, 0, 6)),
        _pipe_ev("create", 6000, r"\other", _local(10, 0, 7)),
        _pipe_ev("create", tdc.os.getpid(), r"\proxy_pipe", _local(10, 0, 8)),
    ]
    calls = []

    def fake_read(**kw):
        calls.append(kw)
        return list(pipes) if kw.get("event_ids") == [17, 18] else list(procs)

    monkeypatch.setattr(tdc, "_is_sysmon_running", lambda: True)
    monkeypatch.setattr(tdc, "_read_sysmon_events", fake_read)
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [
        {"agent_pid": 4072, "timestamp": "2026-11-04T09:59:59", "sha256": "ab" * 32,
         "filename": "sample.exe"}])
    tdc._pipe_cache.clear()

    res = tdc._pipe_activity_for(4072, sha256="ab" * 32)
    assert res["available"] is True
    assert res["evidence_findings"] == []
    assert [p["pipe"] for p in res["pipes"]] == [r"\msagent_5b"]
    p = res["pipes"][0]
    assert p["created_by"] == ["4100"] and p["connected_by"] == ["6000"]
    assert "cross_process" in p["flags"]
    q = [c for c in calls if c.get("event_ids") == [17, 18]][0]
    assert q["max_events"] == 2000
    assert tdc._to_epoch(q["until"]) - tdc._to_epoch(q["since"]) == 60 + tdc._AGENT_PID_WINDOW


def test_pipe_activity_unavailable_without_sysmon(tdc):
    tdc._pipe_cache.clear()
    res = tdc._pipe_activity_for(4072)
    assert res["available"] is False
    assert res["pipes"] == [] and res["evidence_findings"] == []


def _pipe_activity_setup(tdc, monkeypatch, procs, pipes, sub_ts="2026-11-04T09:59:59"):
    calls = []

    def fake_read(**kw):
        calls.append(kw)
        return list(pipes) if kw.get("event_ids") == [17, 18] else list(procs)

    monkeypatch.setattr(tdc, "_is_sysmon_running", lambda: True)
    monkeypatch.setattr(tdc, "_read_sysmon_events", fake_read)
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [
        {"agent_pid": 4072, "timestamp": sub_ts, "sha256": "ab" * 32, "filename": "sample.exe"}])
    tdc._pipe_cache.clear()
    return calls


def test_pid_reuse_main_path_excludes_later_holder(tdc, monkeypatch):
    from test_process_instances import _sysmon_create

    procs = [
        _sysmon_create(4072, _local(10, 0, 0), r"C:\Users\Public\sample.exe", 2964),
        _sysmon_create(4072, _local(11, 0, 0), r"C:\Windows\System32\notepad.exe", 700),
    ]
    pipes = [
        _pipe_ev("create", 4072, r"\msagent_aa", _local(10, 0, 5)),
        _pipe_ev("create", 4072, r"\msagent_bb", _local(11, 0, 5)),
    ]
    _pipe_activity_setup(tdc, monkeypatch, procs, pipes)
    res = tdc._pipe_activity_for(4072)
    assert [p["pipe"] for p in res["pipes"]] == [r"\msagent_aa"]
    assert res["pipes"][0]["created_by"][0].startswith("4072@")


def test_pid_reuse_fallback_excludes_later_holder(tdc, monkeypatch):
    from test_process_instances import _sysmon_create

    # The sample's ProcessCreate fell out of the map; a later holder of the PID is in it.
    procs = [_sysmon_create(4072, _local(11, 0, 0), r"C:\Windows\System32\notepad.exe", 700)]
    pipes = [
        _pipe_ev("create", 4072, r"\msagent_aa", _local(10, 0, 5)),
        _pipe_ev("create", 4072, r"\msagent_bb", _local(11, 0, 5)),
    ]
    _pipe_activity_setup(tdc, monkeypatch, procs, pipes)
    res = tdc._pipe_activity_for(4072)
    assert [p["pipe"] for p in res["pipes"]] == [r"\msagent_aa"]


def test_fallback_rejects_older_holder_and_its_subtree(tdc, monkeypatch):
    from test_process_instances import _sysmon_create

    # Only an older holder of the PID (and its child) is in the map.
    procs = [
        _sysmon_create(4072, _local(8, 0, 0), r"C:\Windows\System32\svchost.exe", 600),
        _sysmon_create(4500, _local(8, 0, 1), r"C:\Windows\System32\conhost.exe", 4072),
    ]
    pipes = [
        _pipe_ev("create", 4500, r"\msagent_old", _local(10, 0, 2)),
        _pipe_ev("create", 4072, r"\msagent_aa", _local(10, 0, 5)),
    ]
    _pipe_activity_setup(tdc, monkeypatch, procs, pipes)
    res = tdc._pipe_activity_for(4072)
    assert [p["pipe"] for p in res["pipes"]] == [r"\msagent_aa"]


def test_cache_distinguishes_submissions_and_reports_truncation(tdc, monkeypatch):
    from test_process_instances import _sysmon_create

    procs = [_sysmon_create(4072, _local(10, 0, 0), r"C:\Users\Public\sample.exe", 2964),
             _sysmon_create(4072, _local(12, 0, 0), r"C:\Users\Public\other.exe", 2964)]
    pipes = [_pipe_ev("create", 4072, r"\msagent_aa", _local(10, 0, 5))] + \
        [_pipe_ev("create", 4072, r"\msagent_bb", _local(12, 0, 5))] * 1999
    _pipe_activity_setup(tdc, monkeypatch, procs, pipes)
    first = tdc._pipe_activity_for(4072)
    assert first["truncated"] is True
    assert [p["pipe"] for p in first["pipes"]] == [r"\msagent_aa"]
    monkeypatch.setattr(tdc, "_load_submissions", lambda: [
        {"agent_pid": 4072, "timestamp": "2026-11-04T11:59:59", "sha256": "ab" * 32}])
    second = tdc._pipe_activity_for(4072)
    assert [p["pipe"] for p in second["pipes"]] == [r"\msagent_bb"]
