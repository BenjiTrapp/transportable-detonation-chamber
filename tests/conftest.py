"""Shared fixtures for the web UI and MCP tests.

The web UI module is imported once with its background loader disabled; each
test gets a clean in-memory store and its own result/baseline files, so tests
never touch the files next to app.py or talk to the VM.
"""

import os
import sys
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "webui"))
sys.path.insert(0, os.path.join(ROOT, "mcp"))

os.environ["TDC_NO_BACKGROUND"] = "1"
# the access log of the web UI never goes to webui/logs during tests
os.environ["TDC_LOG_DIR"] = tempfile.mkdtemp(prefix="tdc-test-logs-")
os.environ.pop("TDC_VM_WEBUI", None)


@pytest.fixture(autouse=True)
def geoip_cache(tmp_path, monkeypatch):
    """geoip.load maps copies of the index in a cache directory: in tests the test's own, never the system's."""
    import geoip  # noqa: WPS433 - after sys.path is set
    cache = tmp_path / "geoip-cache"
    monkeypatch.setattr(geoip, "CACHE_DIR", str(cache))
    return cache


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


# --- FIREWALL tab -------------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status, body, headers):
        self.status, self._body, self._pos, self._headers = status, body, 0, headers

    def getheader(self, name, default=None):
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def read(self, n=-1):
        chunk = self._body[self._pos:self._pos + (n if n and n > 0 else len(self._body))]
        self._pos += len(chunk)
        return chunk

    read1 = read


class _FakeConnection:
    def __init__(self, fw, scheme, host, port, ip):
        self.fw, self.call = fw, {"scheme": scheme, "host": host, "port": port, "ip": ip}
        self.sock = self.io_sock = None

    def connect(self):
        pass

    def request(self, method, target, headers=None):
        self.call.update(method=method, target=target, headers=dict(headers or {}))
        self.fw.fetches.append(self.call)

    def getresponse(self):
        status, headers, body = self.fw.script.pop(0) if self.fw.script else (
            200, {"Content-Type": "application/octet-stream"}, self.fw.body)
        return _FakeResponse(status, body, headers)

    def close(self):
        pass


class FirewallFake:
    """Everything the FIREWALL routes reach outside the process, as fakes: a Windows firewall behind ``run``
    (``FakeRun`` of the rules tests), a network behind ``fetches``, and stores in tmp_path.

    ``body`` is what a fetch is served, ``script`` a list of ``(status, headers, body)`` served first (redirects),
    ``lookups`` every name that was resolved (a fetch must resolve none), ``own`` the addresses that count as
    this VM's own (a fetch must refuse them)."""

    def __init__(self, tdc, run, store, settings, pending, tmp_path):
        self.tdc, self.run, self.store, self.settings, self.pending = tdc, run, store, settings, pending
        self.samples = tmp_path / "samples"
        self.fetches, self.script, self.lookups = [], [], []
        self.body = b"MZ" + b"\x00" * 100
        self.resolve_to = "9.9.9.9"
        self.own = {"192.168.64.129", "192.168.64.1"}      # the VM's own address and its gateway

    @property
    def profiles(self):
        return self.run.profiles

    @profiles.setter
    def profiles(self, value):
        self.run.profiles = dict(value)


class _InlineExecutor:
    def submit(self, fn, *args):
        fn(*args)


@pytest.fixture
def fw(tdc, monkeypatch, tmp_path):
    from test_firewall_rules import FakeRun
    import firewall_fetch
    import firewall_store
    m = tdc
    fake = FirewallFake(m, FakeRun(), firewall_store.FirewallStore(), firewall_store.Settings(str(tmp_path / "state.json")),
                        firewall_store.PendingStore(str(tmp_path / "pending.json")), tmp_path)
    for name, value in (("_fw_runner", fake.run), ("_fw_store", fake.store), ("_fw_settings", fake.settings),
                        ("_fw_pending", fake.pending), ("_fw_executor", _InlineExecutor()),
                        ("CAPTURE_DIR", str(fake.samples)), ("CAPTURES_FILE", str(tmp_path / "captures.json")),
                        ("_fw_downloads", {}), ("_fw_scan_state", {"done": False}), ("_fw_rules_cache", None),
                        ("_fw_windows_cache", (0.0, {})), ("_fw_window_alive", {}), ("_fw_fetch_paths", {}),
                        ("_fw_fetch_open", {}), ("_fw_fetch_swept", 0.0), ("_fw_profiles_cache", None), ("_fw_allowed_cache", None),
                        ("_fw_ioc_cache", (time.time() + 1e6, (frozenset(), frozenset())))):
        monkeypatch.setattr(m, name, value)
    monkeypatch.setattr(m, "_process_started_at", lambda pid: None)
    # the fetch mechanism itself (real sockets, the deadline, the SNI) is tested in test_firewall_fetch.py;
    # here the connection is a fake, so these tests stay about the policy around it
    monkeypatch.setattr(firewall_fetch, "pinned_connection",
                        lambda scheme, host, port, ip, timeout: _FakeConnection(fake, scheme, host, port, ip))
    # the addresses of this machine are not asked for: they would be a lookup, and every test would see it
    monkeypatch.setattr(firewall_fetch, "_own_cache", (time.time(), frozenset(fake.own)))

    def resolving(host, *args, **kwargs):
        fake.lookups.append(host)
        return [(2, 1, 6, "", (fake.resolve_to, 0))]
    monkeypatch.setattr("socket.getaddrinfo", resolving)
    return fake
