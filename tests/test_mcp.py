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


def test_every_tool_has_a_docstring_with_its_arguments():
    import inspect
    tools = [getattr(server, n) for n in dir(server) if n.startswith("tdc_")]
    assert len(tools) >= 41
    for tool in tools:
        doc = inspect.getdoc(tool) or ""
        assert doc, f"{tool.__name__} has no docstring"
        for param in inspect.signature(tool).parameters:
            assert param in doc, f"{tool.__name__}: argument '{param}' not documented"
