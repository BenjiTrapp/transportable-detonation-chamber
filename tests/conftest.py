"""Shared fixtures for the web UI and MCP tests.

The web UI module is imported once with its background loader disabled; each
test gets a clean in-memory store and its own result/baseline files, so tests
never touch the files next to app.py or talk to the VM.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "webui"))
sys.path.insert(0, os.path.join(ROOT, "mcp"))

os.environ["TDC_NO_BACKGROUND"] = "1"
os.environ.pop("TDC_VM_WEBUI", None)


@pytest.fixture(scope="session")
def app_module():
    import app as app_module  # noqa: WPS433 - imported after env setup on purpose
    app_module.app.config["TESTING"] = True
    return app_module


@pytest.fixture
def tdc(app_module, monkeypatch, tmp_path):
    """The web UI module with an empty store and no external state."""
    m = app_module
    with m.store_lock:
        m.events_store["alerts"] = []
        m.events_store["processes"] = {}
        m.events_store["alerts_version"] = None
    monkeypatch.setattr(m, "_load_submissions", lambda: [])
    monkeypatch.setattr(m, "_load_scan_history", lambda: [])
    monkeypatch.setattr(m, "_is_sysmon_running", lambda: False)
    monkeypatch.setattr(m, "VM_WEBUI_URL", "")
    monkeypatch.setattr(m, "_beacon_results_cache", m._ResultStore(str(tmp_path / "results")))
    monkeypatch.setattr(m, "_memory_baseline",
                        m.memory_evidence.MemoryBaseline(str(tmp_path / "baseline.json")))
    m._alerts_body_cache["entry"] = None
    return m


@pytest.fixture
def client(tdc):
    return tdc.app.test_client()


def make_alert(i, pid, ts, image, ppid=None, parent_name="", engine="sigma",
               severity="high", **extra):
    """A normalized alert as produced by parse_rustinel_alert/parse_fibratus_alert."""
    alert = {
        "id": f"a{i}",
        "pid": pid,
        "timestamp": ts,
        "process_image": image,
        "process_name": image.replace("/", "\\").split("\\")[-1],
        "parent_pid": ppid,
        "parent_name": parent_name,
        "command_line": "",
        "severity": severity,
        "rule_name": f"rule {i}",
        "engine": engine,
        "category": "process",
        "raw": {},
    }
    alert.update(extra)
    return alert
