"""MCP server (mcp/server.py): field names, formatting and coverage.

Regressions covered:
  * tdc_alerts printed "unknown" for every rule (read name/rule, not rule_name)
    and showed the oldest alerts first
  * tdc_detonation_results cut raw JSON at 4000 chars, before the verdict
  * tdc_process_detail's not-found branch never ran
  * tdc_process_graph mixed processes that reused a PID
  * BeaconEye/HSB findings printed as raw JSON
"""

import pytest

server = pytest.importorskip("server", reason="MCP server dependencies (mcp, httpx) not installed")


class FakeAPI:
    """Stands in for _get/_post/_call: path -> response."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, *args, **kwargs):
        # _get(path, params=..) / _call(method, path, params=..)
        path = args[1] if len(args) > 1 and args[0] in ("GET", "POST", "DELETE") else args[0]
        self.calls.append((path, kwargs.get("params") or kwargs.get("data")))
        value = self.routes[path]
        return value(kwargs) if callable(value) else value


@pytest.fixture
def api(monkeypatch):
    def install(routes):
        fake = FakeAPI(routes)
        for name in ("_get", "_post", "_call"):
            monkeypatch.setattr(server, name, fake)
        return fake
    return install


def test_alerts_show_rule_names_newest_first(api):
    fake = api({"/api/alerts": [
        {"timestamp": "2026-10-20T10:00:00Z", "severity": "high", "rule_name": "LSASS access",
         "engine": "fibratus", "pid": 6788, "process_name": "x.exe", "id": "fib_1"},
    ]})
    out = server.tdc_alerts(max_alerts=5, since="2026-10-20T00:00:00Z")
    assert "LSASS access" in out and "unknown" not in out and "id=fib_1" in out
    assert fake.calls[0][1] == {"limit": 5, "since": "2026-10-20T00:00:00Z"}


def test_detonation_results_lead_with_the_verdict(api):
    api({"/api/detonation/results": {
        "verdict": {"label": "MALICIOUS", "score": 4, "reasons": ["PE header in private memory"]},
        "memory_evidence": {"label": "MALICIOUS", "score": 6.54},
        "agent": {"execution": {"agent_logs": "x" * 50000, "stdout": "hello"}},
        "fibratus_alert_count": 0, "ready": {"memory": False},
    }})
    out = server.tdc_detonation_results(pid=4072)
    assert out.startswith("VERDICT: MALICIOUS (score 4)")
    assert "Memory evidence: MALICIOUS (6.54)" in out
    assert "Still pending: memory" in out
    assert len(out) < 5000                                # agent log not dumped


def test_process_detail_not_found(api):
    api({"/api/processes/999": {"error": "Process not found"}})
    assert server.tdc_process_detail("999") == "Process 999: Process not found"


def test_process_graph_follows_instance_keys(api):
    api({"/api/process-graph": {"root_pid": "4072@100", "processes": {
        "2964@100": {"key": "2964@100", "pid": "2964", "name": "DetonatorAgent.exe", "children": ["4072@100"],
                     "depth": -1},
        "4072@100": {"key": "4072@100", "pid": "4072", "name": "injectsim.exe", "parent_pid": "2964",
                     "parent_key": "2964@100", "children": [], "is_root": True, "depth": 0},
        "4072": {"key": "4072", "pid": "4072", "name": "wevtutil.exe", "children": [], "depth": 0},
    }, "network": [{"key": "4072@100", "pid": "4072", "dst_ip": "10.0.0.1", "dst_port": "443"},
                   {"key": "4072", "pid": "4072", "dst_ip": "9.9.9.9", "dst_port": "53"}]}})
    out = server.tdc_process_graph("4072", at="2026-10-20T08:00:00Z")
    lines = out.splitlines()
    sample = next(i for i, l in enumerate(lines) if "injectsim.exe" in l)
    assert "DetonatorAgent.exe" in lines[sample - 1]
    assert "10.0.0.1:443" in lines[sample + 1] and "9.9.9.9" not in lines[sample + 1]


def test_beacon_scanners_are_formatted(api):
    api({"/api/scan/beaconeye": {"beacons_found": 1, "findings": [
        {"summary": "Cobalt Strike beacon config in r.exe (4242)", "config": {"C2Server": "evil.example", "c2": "evil.example"}}],
        "output": "[+] Scanned 140 processes in 00:00:00.4"}})
    out = server.tdc_scan_beaconeye(4242)
    assert "C2Server: evil.example" in out and "{" not in out
    assert out.splitlines()[-1] == "[+] Scanned 140 processes in 00:00:00.4"


def test_pipes_tool_formats_families(api):
    fake = api({"/api/pipes": {"since": "2026-11-04T10:00:00+01:00", "truncated": False, "events": [
        {"type": "PipeCreated", "pipe": "\\MSSE-1234-server", "image": "C:\\x\\r.exe", "pid": 4072,
         "user": "LAB\\a", "timestamp": "2026-11-04T10:00:01.123+01:00", "family": "Cobalt Strike"},
        {"type": "PipeConnected", "pipe": "\\lsass", "image": "C:\\x\\r.exe", "pid": 4072,
         "timestamp": "2026-11-04T10:00:02+01:00", "family": None},
    ]}})
    out = server.tdc_pipes(pid="4072", name="msse", max_events=10)
    assert fake.calls[0][1] == {"max": 10, "pid": "4072", "name": "msse"}
    assert out.splitlines()[0].startswith("2 pipe event(s)")
    assert "PipeCreated" in out and "\\MSSE-1234-server" in out and "[Cobalt Strike]" in out
    assert "r.exe" in out and "C:\\x" not in out
    assert "Families: Cobalt Strike" in out

    fake = api({"/api/pipes": {"events": [], "available": False, "reason": "Sysmon not running"}})
    assert "Sysmon not running" in server.tdc_pipes(pid="4072@1700000000.5")
    assert fake.calls[0][1] == {"max": 100, "key": "4072@1700000000.5"}

    api({"/api/pipes": {"error": "invalid since: x"}})
    assert server.tdc_pipes(since="x") == "Error: invalid since: x"


def test_pipe_sessions_tool_reads_messages(api):
    import base64
    session = {"id": "s1", "pattern": "\\msagent_42", "match": "exact", "how": "attach",
               "mode": "observe", "squat": False, "state": "active", "connections": 1,
               "message_count": 2, "held_count": 0, "recording_truncated": False,
               "last_error": None, "self_connect_retries": 0}
    payload = b"MZ\x90\x00hello" + bytes(range(100))
    fake = api({
        "/api/pipes/intercept": {"sessions": [session]},
        "/api/pipes/intercept/s1": session,
        "/api/pipes/intercept/s1/messages": {"messages": [
            {"seq": 1, "conn": 1, "dir": "client_to_server", "ts": 1762246800.0, "size": len(payload),
             "data_b64": base64.b64encode(payload).decode(), "state": "passed", "truncated": False},
            {"seq": 2, "conn": 1, "dir": "server_to_client", "ts": 1762246801.0, "size": 3,
             "data_b64": base64.b64encode(b"abc").decode(), "state": "edited", "truncated": False,
             "original_b64": base64.b64encode(b"xyz").decode()},
        ]},
        "/api/pipes/intercept/nope": {"error": "Interception session nope not found"},
    })
    listing = server.tdc_pipe_sessions()
    assert "s1" in listing and "\\msagent_42" in listing and "active" in listing

    out = server.tdc_pipe_sessions("s1", max_messages=5)
    assert ("/api/pipes/intercept/s1/messages", {"after": 0, "limit": 5}) in fake.calls
    assert "\n2 message(s):" in out
    assert "4d 5a 90 00 68 65 6c 6c 6f" in out and "MZ..hello" in out
    assert out.count("00 01 02") == 1 and "..." in out          # first 64 bytes only
    assert "edited" in out and "78 79 7a" in out                # original shown
    assert server.tdc_pipe_sessions("nope") == "Error: Interception session nope not found"

    fake.routes["/api/pipes/intercept/s1"] = dict(session, message_count=7, state=None)
    out = server.tdc_pipe_sessions("s1", max_messages=2)
    assert "Session s1: ? -" in out
    assert "First 2 of 7 message(s); next page: after=2:" in out
    out = server.tdc_pipe_sessions("s1", max_messages=2, after=2)
    assert ("/api/pipes/intercept/s1/messages", {"after": 2, "limit": 2}) in fake.calls
    assert "2 of 7 message(s) after #2; next page: after=2:" in out

    fake.routes["/api/pipes/intercept"] = {"sessions": [dict(session, state=None)]}
    assert "s1  ?" in server.tdc_pipe_sessions()


def test_detonation_results_mentions_pipes(api):
    base = {"verdict": {"label": "SUSPICIOUS", "score": 2, "reasons": []}, "ready": {}}
    api({"/api/detonation/results": dict(base, named_pipes={"available": True, "pipes": [
        {"pipe": "\\MSSE-1-server", "family": "Cobalt Strike", "created_by": ["4072?"],
         "connected_by": ["812@1700000000.0"], "flags": ["c2_default", "cross_process"]},
        {"pipe": "\\MSSE-2-server", "family": "Cobalt Strike", "created_by": ["4072?"], "connected_by": [],
         "flags": ["c2_default"]},
        {"pipe": "\\abc", "family": None, "created_by": ["4072@1"], "connected_by": [], "flags": []},
        {"pipe": "\\spoolss", "family": None, "created_by": ["700@5.0"],
         "connected_by": ["4072@1", "4072@2"], "flags": ["sensitive_system"]},
    ], "evidence_findings": []})})
    out = server.tdc_detonation_results(pid=4072)
    assert "Named pipes: 4 (families Cobalt Strike)" in out and "[truncated]" not in out
    lines = out.splitlines()
    assert ("  \\MSSE-1-server [Cobalt Strike] c2_default, cross_process"
            " - created by 4072 (sample), connected by 812") in lines
    assert "  \\MSSE-2-server [Cobalt Strike] c2_default - created by 4072 (sample)" in lines
    # two instances of PID 4072 among the pipes: keep the keys apart
    assert "  \\spoolss sensitive_system - created by 700, connected by 4072@1, 4072@2" in lines
    assert not any(l.startswith("  \\abc") for l in lines)       # unflagged: count only

    # flagged pipes are picked before the 10-line cap
    plain = [{"pipe": f"\\p{i}", "family": None, "flags": []} for i in range(12)]
    api({"/api/detonation/results": dict(base, named_pipes={"available": True, "truncated": True,
        "pipes": plain + [{"pipe": "\\late", "family": None, "flags": ["random_name"]}],
        "evidence_findings": []})})
    out = server.tdc_detonation_results(pid=4072)
    assert "Named pipes: 13 [truncated]" in out and "  \\late random_name" in out

    api({"/api/detonation/results": dict(base, named_pipes={"available": True, "pipes": [
        {"pipe": "\\abc", "family": None, "flags": []}], "evidence_findings": []})})
    out = server.tdc_detonation_results(pid=4072)
    assert "Named pipes: 1" in out and "families" not in out

    api({"/api/detonation/results": dict(base, named_pipes={
        "available": False, "reason": "Sysmon not running", "pipes": [], "evidence_findings": []})})
    assert "Named pipes: unavailable (Sysmon not running)" in server.tdc_detonation_results(pid=4072)


def test_updates_status_lists_tools_and_progress(api):
    api({"/api/updates": {
        "mode": "updating", "checked_at": "2026-11-13T10:00:00Z", "progress": {"done": 1, "total": 3, "current": "LitterBox"},
        "tools": [{"id": "capa", "status": "update_available", "installed": "9.0.0", "available": "9.1.0"},
                  {"id": "rustinel", "status": "pinned_update", "installed": "1.1.1", "available": "1.2.0",
                   "pinned": "1.1.1", "detail": "Pinned"}]}})
    out = server.tdc_updates_status()
    assert "Mode: updating" in out and "Updating 1/3: LitterBox" in out
    assert "capa: update_available (9.0.0 -> 9.1.0)" in out
    assert "[pinned 1.1.1]" in out


def test_updates_apply_sends_a_list_of_ids(monkeypatch):
    sent = {}

    def fake_call(method, path, **kwargs):
        sent.update(method=method, path=path, **kwargs)
        return {"started": True, "tools": ["capa", "litterbox"]}

    monkeypatch.setattr(server, "_call", fake_call)
    out = server.tdc_updates_apply(tools="capa, litterbox", include_pinned=True)
    assert sent["method"] == "POST" and sent["path"] == "/api/updates/apply"
    assert sent["json"] == {"tools": ["capa", "litterbox"], "include_pinned": True}
    assert "capa, litterbox" in out
    server.tdc_updates_apply()
    assert sent["json"] == {"tools": "all", "include_pinned": False}


def test_updates_apply_passes_a_mixed_list_on_for_the_server_to_refuse(monkeypatch):
    sent = {}

    def fake_call(method, path, **kwargs):
        sent.update(kwargs)
        return {"error": 'Use "all" alone or a list of tool ids'}

    monkeypatch.setattr(server, "_call", fake_call)
    out = server.tdc_updates_apply(tools="all,capa")
    assert sent["json"]["tools"] == ["all", "capa"]
    assert out == 'Error: Use "all" alone or a list of tool ids'


def test_updates_apply_reports_the_refusal(monkeypatch):
    monkeypatch.setattr(server, "_call", lambda *a, **k: {"error": "A detonation is running. Wait until it finishes."})
    assert server.tdc_updates_apply().startswith("Error: A detonation is running")


def test_every_tool_has_a_docstring_with_its_arguments():
    import inspect
    tools = [getattr(server, n) for n in dir(server) if n.startswith("tdc_")]
    assert len(tools) >= 46
    for tool in tools:
        doc = inspect.getdoc(tool) or ""
        assert doc, f"{tool.__name__} has no docstring"
        for param in inspect.signature(tool).parameters:
            assert param in doc, f"{tool.__name__}: argument '{param}' not documented"


class _FakeResponse:
    is_error = False
    status_code = 200
    text = "{}"

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


def _record_httpx(monkeypatch, body):
    sent = []

    def fake(*args, **kwargs):
        sent.append({"args": args, **kwargs})
        return _FakeResponse(body)

    for name in ("get", "post", "request"):
        monkeypatch.setattr(server.httpx, name, fake)
    return sent


def test_requests_carry_the_mcp_headers_and_the_tool_name(monkeypatch):
    sent = _record_httpx(monkeypatch, {"sysmon": {"online": True}})
    server.tdc_status()
    assert sent[0]["headers"]["X-TDC-Client"] == "mcp"
    assert sent[0]["headers"]["X-TDC-MCP-Tool"] == "tdc_status"


def test_post_and_call_helpers_carry_the_headers_too(monkeypatch):
    sent = _record_httpx(monkeypatch, {"ok": True})
    server.tdc_service_launch("sysmon")                    # _post
    server.tdc_updates_check()                             # _call
    assert [s["headers"]["X-TDC-MCP-Tool"] for s in sent] == ["tdc_service_launch", "tdc_updates_check"]
    assert all(s["headers"]["X-TDC-Client"] == "mcp" for s in sent)


def test_every_registered_tool_sets_its_own_name():
    seen = {}

    def spy(*a, **k):
        seen["tool"] = server._current_tool.get()
        raise RuntimeError("stop")

    names = [n for n in dir(server) if n.startswith("tdc_")]
    assert len(names) >= 47
    original = server._get, server._post, server._call
    server._get = server._post = server._call = spy
    try:
        for name in names:
            fn = getattr(server, name)
            import inspect
            args = {p.name: "1" for p in inspect.signature(fn).parameters.values()
                    if p.default is inspect.Parameter.empty}
            seen.clear()
            try:
                fn(**args)
            except Exception:
                pass
            assert seen.get("tool") in (name, None), name
    finally:
        server._get, server._post, server._call = original
    assert server._current_tool.get() == ""


def test_logs_search_sends_the_query_and_the_headers(monkeypatch):
    sent = _record_httpx(monkeypatch, {
        "type": "events", "count": 2, "matched": 2, "truncated": False, "took_ms": 3,
        "events": [{"time": "2026-11-14T10:00:00Z", "source": "dns", "message": "evil.example -> 1.2.3.4"},
                   {"time": "2026-11-14T09:00:00Z", "source": "mcp", "message": "tdc_status \u2192 GET /api/status (200)"}]})
    out = server.tdc_logs_search(query="source=dns", earliest="-1h", limit=50)
    call = sent[0]
    assert call["args"][0] == "GET" and call["args"][1].endswith("/api/logs/search")
    assert call["params"] == {"q": "source=dns", "earliest": "-1h", "limit": 50}
    assert call["headers"]["X-TDC-MCP-Tool"] == "tdc_logs_search"
    assert "2 events" in out and "evil.example -> 1.2.3.4" in out and "dns" in out


def test_logs_search_formats_a_table_and_errors(monkeypatch):
    _record_httpx(monkeypatch, {"type": "table", "count": 2, "matched": 9, "truncated": False, "events": [],
                                "columns": ["source", "count"], "rows": [["dns", 5], ["mcp", 4]]})
    out = server.tdc_logs_search("* | stats count by source")
    assert "source" in out and "dns" in out and "5" in out and "2 rows" in out
    monkeypatch.setattr(server, "_call", lambda *a, **k: {"error": "Unknown command bogus", "pos": 9})
    out = server.tdc_logs_search("x | bogus")
    assert out.startswith("Search error: Unknown command bogus") and "9" in out


def test_firewall_connections_sends_the_filters_and_defangs(monkeypatch):
    sent = _record_httpx(monkeypatch, {
        "count": 7, "truncated": True, "isolated": True, "ask_mode": "detonation", "rules_error": None,
        "connections": [{"image": "C:\\Users\\a\\loader.exe", "pid": 4242, "protocol": "tcp", "dst_ip": "203.0.113.7",
                         "dst_port": 8443, "dst_hostname": "evil.example.com", "count": 12, "severity": "critical",
                         "state": "blocked", "rule_id": "TDC-FW-abc", "tags": ["beacon", "detonated"], "fw_dropped": 3,
                         "last_seen": "2026-11-16T10:05:00Z", "self": False,
                         "geo": {"scope": "public", "cc": "NL", "asn": 64500, "as_org": "EXAMPLE-AS"}}]})
    out = server.tdc_firewall_connections(since="-2h", tag="beacon", process="loader", limit=20)
    call = sent[0]
    assert call["args"][0] == "GET" and call["args"][1].endswith("/api/firewall/connections")
    assert call["params"]["max"] == 20 and call["params"]["tag"] == "beacon" and call["params"]["process"] == "loader"
    assert float(call["params"]["since"]) > 0               # the server takes epoch or ISO, not -2h
    assert call["headers"]["X-TDC-MCP-Tool"] == "tdc_firewall_connections"
    assert "7 connections, the 1 most severe shown" in out and "ISOLATED on" in out
    assert "loader.exe (PID 4242)" in out and "203.0.113.7:8443" in out and "TDC-FW-abc" in out
    assert "evil[.]example[.]com" in out and "evil.example.com" not in out
    assert "NL AS64500 EXAMPLE-AS" in out and "beacon,detonated" in out and "endpoint_dropped=3" in out


def test_firewall_connections_passes_iso_and_all_and_reports_errors(monkeypatch):
    sent = _record_httpx(monkeypatch, {"count": 0, "connections": []})
    server.tdc_firewall_connections(since="2026-11-16T00:00:00Z")
    server.tdc_firewall_connections(since="all")
    assert sent[0]["params"]["since"] == "2026-11-16T00:00:00Z" and "since" not in sent[1]["params"]
    monkeypatch.setattr(server, "_call", lambda *a, **k: {"error": "since must be an ISO-8601 time or epoch seconds"})
    assert server.tdc_firewall_connections(since="yesterday").startswith("Error: since must be")


def test_firewall_captures_lists_the_newest_with_a_defanged_url(api):
    fake = api({"/api/firewall/captures": {"captures": [
        {"fetched_at": "2026-11-16T10:06:00Z", "sha256": "ab" * 32, "size": 73802, "magic": "MZ",
         "url": "http://203.0.113.7:8443/stage2.exe", "dst_ip": "203.0.113.7", "dst_port": 8443,
         "image": "C:\\Users\\a\\loader.exe", "pid": 4242, "path": "C:\\tdc\\samples\\ab\\" + "ab" * 32},
        {"fetched_at": "2026-11-16T09:00:00Z", "sha256": "cd" * 32, "url": "https://x.example/a"}]}})
    out = server.tdc_firewall_captures(limit=1)
    assert fake.calls[0][0] == "/api/firewall/captures"
    assert "2 captures, the newest 1 shown" in out and "ab" * 32 in out and "cd" * 32 not in out
    assert "hxxp://203[.]0[.]113[.]7:8443/stage2.exe" in out and "http://" not in out
    assert "C:\\tdc\\samples\\ab\\" in out and "MZ" in out


def test_no_firewall_tool_changes_state():
    """The FIREWALL tools are read-only on purpose: a model must not take the chamber off the network, lift a block,
    answer a decision, kill a process or switch the firewall on by itself."""
    import inspect
    source = inspect.getsource(server)
    for route in ("/api/firewall/block", "/api/firewall/unblock", "/api/firewall/isolate", "/api/firewall/decide",
                  "/api/firewall/ask", "/api/firewall/enable", "/api/firewall/kill"):
        assert route not in source, route
    names = sorted(n for n in dir(server) if n.startswith("tdc_firewall"))
    assert names == ["tdc_firewall_captures", "tdc_firewall_connections"]
