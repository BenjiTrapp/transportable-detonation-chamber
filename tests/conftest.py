"""Shared fixtures for the web UI and MCP tests.

The web UI module is imported once with its background loader disabled; each
test gets a clean in-memory store and its own result/baseline files, so tests
never touch the files next to app.py or talk to the VM.
"""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "webui"))
sys.path.insert(0, os.path.join(ROOT, "mcp"))

os.environ["TDC_NO_BACKGROUND"] = "1"
# the access log of the web UI never goes to webui/logs during tests
os.environ["TDC_LOG_DIR"] = tempfile.mkdtemp(prefix="tdc-test-logs-")
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
    # webui/submissions.json is in the repository: a test that writes the
    # submissions (a verdict kept on one) writes a file of its own
    monkeypatch.setattr(m, "SUBMISSIONS_FILE", str(tmp_path / "submissions.json"))
    monkeypatch.setattr(m, "_load_scan_history", lambda: [])
    monkeypatch.setattr(m, "_is_sysmon_running", lambda: False)
    monkeypatch.setattr(m, "VM_WEBUI_URL", "")
    monkeypatch.setattr(m, "_beacon_results_cache", m._ResultStore(str(tmp_path / "results")))
    monkeypatch.setattr(m, "_memory_baseline",
                        m.memory_evidence.MemoryBaseline(str(tmp_path / "baseline.json")))
    monkeypatch.setattr(m, "_net_reports", m._ResultStore(str(tmp_path / "net_results")))
    monkeypatch.setattr(m, "_net_baseline", m.net_baseline.NetBaseline(str(tmp_path / "net_baseline.json")))
    monkeypatch.setattr(m, "_net_upload_dir", lambda: str(tmp_path / "net_uploads"))
    m._alerts_body_cache["entry"] = None
    m.set_log_store(m.log_store.LogStore(persist_dir=str(tmp_path / "logs")))
    yield m
    m.set_log_store(None)


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
