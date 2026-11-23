"""Shared fixtures for the web UI and MCP tests.

The web UI module is imported once with its background loader disabled; each
test gets a clean in-memory store and its own result/baseline files, so tests
never touch the files next to app.py or talk to the VM.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
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
    # the syscall baselines, NTSleuth and the hook allowlist are files of the test's own; no symbol server is asked
    monkeypatch.setattr(m, "NTSLEUTH_DIR", str(tmp_path / "ntsleuth"))
    monkeypatch.setattr(m, "NTSLEUTH_BASELINE_DIR", str(tmp_path / "ntsleuth" / "baseline"))
    monkeypatch.setattr(m, "SYSCALL_HOOK_ALLOWLIST_FILE", str(tmp_path / "syscall_hook_allowlist.json"))
    monkeypatch.setattr(m, "_hook_allowlist", None)
    monkeypatch.setattr(m, "_syscall_baselines", {})
    monkeypatch.setattr(m, "_syscall_extract_state", m._new_syscall_extract_state())
    monkeypatch.setattr(m, "_symbol_server_reachable", lambda: False)
    m.set_log_store(m.log_store.LogStore(persist_dir=str(tmp_path / "logs")))
    # the own dashboards of a test are a file of its own, never webui/dashboards.json
    m.set_dashboard_store(m.dashboards.DashboardStore(str(tmp_path / "dashboards.json")))
    yield m
    m.set_log_store(None)
    m.set_dashboard_store(None)


@pytest.fixture
def client(tdc):
    return tdc.app.test_client()


def _baseline_dir(tdc, monkeypatch, tmp_path, symbols=None):
    """The baselines of tests/samples in a directory of the test's own, which is the one the web UI reads; the
    system it runs on has the build they were named for. `symbols` False marks them as extracted without symbols."""
    directory = tmp_path / "ntsleuth-baselines"
    directory.mkdir()
    for view in ("arm64", "x64"):
        name = f"ntsleuth-26220.5770-{view}.json"
        source = os.path.join(ROOT, "tests", "samples", name)
        if symbols is None:
            shutil.copy(source, directory / name)
            continue
        with open(source, encoding="utf-8") as fh:
            document = json.load(fh)
        document["symbols"] = symbols
        (directory / name).write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(tdc, "NTSLEUTH_BASELINE_DIR", str(directory))
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26220.5770")
    return directory


@pytest.fixture
def fake_baseline_dir(tdc, monkeypatch, tmp_path):
    return _baseline_dir(tdc, monkeypatch, tmp_path)


@pytest.fixture
def degraded_baseline_dir(tdc, monkeypatch, tmp_path):
    return _baseline_dir(tdc, monkeypatch, tmp_path, symbols=False)


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


def make_pe(*, imports=(), delay=(), exports=(), forwarders=(), code=b"",
            export_rva=None, machine=0x8664, sections=()) -> bytes:
    """A minimal PE whose directories pefile parses.

    imports, delay: (module, (function, ...)) pairs — several modules, not one; an int function is an ordinal
    exports:        names this image defines itself
    forwarders:     (name, "MODULE.Function") pairs
    sections:       (name, bytes) pairs, for a section such as ".apiset"
    machine:        0x8664 x64, 0xAA64 arm64

    A PE32+ whose first section starts at RVA 0x1000, file offset 0x200. `code` sits at RVA 0x11C0, file offset
    0x3C0, where the exports point unless `export_rva` says otherwise (without code, at 0x1000); the tables follow
    it. A forwarder's address is the RVA of its string inside the export directory's Size window: that, and only
    that, is what makes pefile report `forwarder`. Without imports or delay there is no such directory at all."""
    import struct
    base, code_at = 0x1000, 0x1C0
    body = bytearray(code_at) + code

    def align(n):
        body.extend(bytes(-len(body) % n))

    def put(blob, n=8):
        align(n)
        rva = base + len(body)
        body.extend(blob)
        return rva

    def name_table(functions):
        entries = []
        for function in functions:
            if isinstance(function, int):
                entries.append(1 << 63 | function)
            else:
                entries.append(put(struct.pack("<H", 0) + function.encode() + b"\0", 2))
        return put(struct.pack(f"<{len(entries) + 1}Q", *entries, 0))

    descriptors = b""
    for module, functions in imports:
        dll, table = put(module.encode() + b"\0", 2), name_table(functions)
        descriptors += struct.pack("<IIIII", table, 0, 0, dll, table)
    import_dir = (put(descriptors + bytes(20), 4), len(descriptors) + 20) if imports else None
    descriptors = b""
    for module, functions in delay:
        dll, table, handle = put(module.encode() + b"\0", 2), name_table(functions), put(bytes(8))
        descriptors += struct.pack("<IIIIIIII", 1, dll, handle, table, table, 0, 0, 0)
    delay_dir = (put(descriptors + bytes(32), 4), len(descriptors) + 32) if delay else None

    export_dir = None
    entries = [(name, None) for name in exports] + list(forwarders)
    if entries:
        align(4)
        start, n = base + len(body), len(entries)
        functions_at = start + 40
        names_at, ordinals_at = functions_at + 4 * n, functions_at + 8 * n
        strings = bytearray()

        def string(text):
            rva = ordinals_at + 2 * n + len(strings)
            strings.extend(text.encode() + b"\0")
            return rva

        image_name = string("image.dll")
        name_rvas = [string(name) for name, _ in entries]
        target = export_rva if export_rva is not None else (base + code_at if code else base)
        addresses = [target if forwarder is None else string(forwarder) for _, forwarder in entries]
        block = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, image_name, 1, n, n, functions_at, names_at, ordinals_at)
        block += struct.pack(f"<{n}I", *addresses) + struct.pack(f"<{n}I", *name_rvas)
        block += struct.pack(f"<{n}H", *range(n)) + bytes(strings)
        export_dir = (put(block, 1), len(block))
    align(0x200)

    assert len(sections) <= 3, "the section headers must fit before file offset 0x200"
    layout = [(b".idata", bytes(body))] + [(name.encode(), data) for name, data in sections]
    headers, rva, offset = b"", base, 0x200
    for name, data in layout:
        raw = len(data) + (-len(data) % 0x200)
        headers += struct.pack("<8sIIIIIIHHI", name, len(data), rva, raw, offset, 0, 0, 0, 0, 0x40000040)
        rva += len(data) + (-len(data) % 0x1000)
        offset += raw
    optional = struct.pack("<HBBIIIII", 0x20B, 14, 0, 0, 0x200, 0, 0, 0x1000)
    optional += struct.pack("<QIIHHHHHHIIIIHH", 0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, rva, 0x200, 0, 3, 0)
    optional += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    directories = bytearray(128)
    for index, entry in ((0, export_dir), (1, import_dir), (13, delay_dir)):
        if entry:
            directories[index * 8:index * 8 + 8] = struct.pack("<II", *entry)
    optional += bytes(directories)
    assert len(optional) == 0xF0
    coff = struct.pack("<HHIIIHH", machine, len(layout), 0, 0, 0, 0xF0, 0x22)
    header = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0" + coff + optional + headers
    out = header.ljust(0x200, b"\0")
    for _, data in layout:
        out += data + bytes(-len(data) % 0x200)
    return out


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
    this VM's own (a fetch must refuse them).

    The firewall behind ``run`` stores rules and gives them back; it does not model that a Block rule beats an Allow
    rule, or that a rule does anything to traffic. No test built on this fake can prove that a rule works (that the
    cut shuts the egress, that a block stops a flow): only the VM checks in
    docs/superpowers/plans/2026-11-16-firewall-tab-handover.md do."""

    def __init__(self, tdc, run, store, settings, pending, tmp_path):
        self.tdc, self.run, self.store, self.settings, self.pending = tdc, run, store, settings, pending
        self.samples = tmp_path / "samples"
        self.fetches, self.script, self.lookups = [], [], []
        self.body = b"MZ" + b"\x00" * 100
        self.resolve_to = "9.9.9.9"
        self.own = {"192.168.64.129", "192.168.64.1"}      # the VM's own address and its gateway
        # the convergence worker of ISOLATED: started is every worker the route asked for, waiting the ones not run yet
        self.started, self.waiting = [], []

    def spawn(self, target):
        self.started.append(target)
        self.waiting.append(target)

    def converge(self):
        """Run, here and now, the convergence worker the route started (the test's stand-in for its thread)."""
        while self.waiting:
            self.waiting.pop(0)()

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
                        ("_fw_ioc_cache", (time.time() + 1e6, (frozenset(), frozenset()))),
                        # no thread of its own: a test runs the worker with fake.converge(), or swaps in the real spawn
                        ("_fw_converge_spawn", fake.spawn), ("_fw_converge_event", threading.Event()),
                        ("_fw_converge_running", False), ("_fw_converge_again", False), ("_fw_converge_note", None),
                        ("_fw_converge_gen", 0), ("_fw_cut_verified", None), ("_fw_cut_seen", None), ("_fw_cut_unseen_at", float("-inf")), ("_fw_leaving", 0), ("_fw_pressing", 0)):
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
