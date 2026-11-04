"""Named pipe interception engine, driven through the in-memory FakePipeBackend."""

import base64
import json
import os
import subprocess
import sys
import threading
import time

import pytest

import pipe_proxy
from pipe_proxy import FakePipeBackend, InterceptManager


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def wait_for(cond, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.005)
    return cond()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def backend():
    return FakePipeBackend()


@pytest.fixture
def make_manager(backend, clock, tmp_path):
    managers = []

    def make(**kw):
        kw.setdefault("clock", clock)
        kw.setdefault("tick_interval", None)
        kw.setdefault("io_timeout", 0.02)
        kw.setdefault("poll_interval", 0.01)
        kw.setdefault("settle", 0.01)
        m = InterceptManager(backend, str(tmp_path / "sessions"), **kw)
        managers.append(m)
        real_start = m.start

        def start(*a, **k):
            # The engine returns "starting" until the first upstream is open.
            sid = real_start(*a, **k)["id"]
            assert wait_for(lambda: m.get(sid)["state"] != "starting")
            return m.get(sid)

        m.start = start
        return m

    yield make
    for m in managers:
        m.shutdown()
    leaked = [t.name for t in threading.enumerate() if t.name.startswith("pipe_proxy")]
    assert not leaked, leaked


@pytest.fixture
def mgr(make_manager):
    return make_manager()


def watcher_polls(m, sid, n=2):
    """Wait until the session's watcher has completed `n` more polls."""
    s = m._live(sid)
    target = s.watch_polls + n
    assert wait_for(lambda: s.watch_polls >= target)


def _states(m, sid):
    return [(x["dir"], x["state"]) for x in m.messages(sid)]


def test_observe_relays_both_directions(backend, mgr):
    server = backend.fake_server("svc")
    s = mgr.start(r"\\.\pipe\svc", "observe", "attach", "exact")
    assert s["state"] == "active" and s["target"] == r"\svc"
    client = backend.fake_client("svc")
    client.send(b"ping")
    assert server.recv() == b"ping"
    server.send(b"pong")
    assert client.recv() == b"pong"
    assert wait_for(lambda: len(mgr.messages(s["id"])) == 2)
    msgs = mgr.messages(s["id"])
    assert _states(mgr, s["id"]) == [("c2s", "passed"), ("s2c", "passed")]
    assert base64.b64decode(msgs[0]["data_b64"]) == b"ping"
    assert msgs[1]["size"] == 4 and msgs[0]["seq"] < msgs[1]["seq"]
    assert mgr.messages(s["id"], after=msgs[0]["seq"]) == [msgs[1]]


def test_hold_edit_forward_and_drop(backend, mgr):
    server = backend.fake_server("svc")
    sid = mgr.start("svc", "hold", "attach", "exact")["id"]
    client = backend.fake_client("svc")
    client.send(b"pinx")
    assert wait_for(lambda: len(mgr.messages(sid)) == 1)
    assert server.recv(timeout=0.05) == b""
    seq = mgr.messages(sid)[0]["seq"]
    assert mgr.get(sid)["held_count"] == 1
    rec = mgr.act(sid, seq, "edit", "cGluZw==")
    assert rec["state"] == "edited"
    assert server.recv() == b"ping"

    client.send(b"secret")
    assert wait_for(lambda: len(mgr.messages(sid)) == 2)
    mgr.act(sid, mgr.messages(sid)[1]["seq"], "drop")
    assert server.recv(timeout=0.05) == b""
    assert _states(mgr, sid) == [("c2s", "edited"), ("c2s", "dropped")]
    with pytest.raises(ValueError):
        mgr.act(sid, seq, "forward")


def test_hold_keeps_order_and_release_all(backend, mgr):
    server = backend.fake_server("svc", mode="message")
    sid = mgr.start("svc", "hold", "attach", "exact")["id"]
    client = backend.fake_client("svc")
    client.send(b"one")
    client.send(b"two")
    assert wait_for(lambda: len(mgr.messages(sid)) == 2)
    first, second = [m["seq"] for m in mgr.messages(sid)]
    mgr.act(sid, second, "forward")
    assert server.recv(timeout=0.05) == b""       # n+1 waits behind n
    mgr.act(sid, first, "forward")
    assert server.recv() == b"one"
    assert server.recv() == b"two"
    client.send(b"three")
    assert wait_for(lambda: len(mgr.messages(sid)) == 3)
    assert mgr.release_all(sid) == 1
    assert server.recv() == b"three"


def test_held_message_auto_forwarded_after_timeout(backend, mgr, clock):
    server = backend.fake_server("svc")
    sid = mgr.start("svc", "hold", "attach", "exact", hold_timeout=30)["id"]
    client = backend.fake_client("svc")
    client.send(b"ping")
    assert wait_for(lambda: len(mgr.messages(sid)) == 1)
    clock.advance(29)
    mgr.check_timers()
    assert server.recv(timeout=0.05) == b""
    clock.advance(2)
    mgr.check_timers()
    assert server.recv() == b"ping"
    assert _states(mgr, sid) == [("c2s", "auto_passed")]


def test_session_expires_and_closes_both_ends(backend, mgr, clock):
    server = backend.fake_server("svc")
    sid = mgr.start("svc", "observe", "attach", "exact")["id"]
    client = backend.fake_client("svc")
    client.send(b"ping")
    assert server.recv() == b"ping"
    clock.advance(599)
    mgr.check_timers()
    assert mgr.get(sid)["state"] == "active"
    clock.advance(2)
    mgr.check_timers()
    s = mgr.get(sid)
    assert s["state"] == "ended" and s["end_reason"] == "expired"
    assert client.recv() is None
    assert server.recv() is None
    assert wait_for(lambda: all(
        i.kind == "real" for i in backend._instances if not i.closed["server"]))


def test_server_disappears_closes_client(backend, mgr):
    server = backend.fake_server("svc")
    sid = mgr.start("svc", "observe", "attach", "exact")["id"]
    client = backend.fake_client("svc")
    client.send(b"ping")
    assert server.recv() == b"ping"
    server.close()
    assert client.recv() is None
    assert wait_for(lambda: mgr.get(sid)["active_connections"] == 0)
    assert mgr.get(sid)["state"] == "active"


def test_client_disconnect_closes_upstream(backend, mgr):
    server = backend.fake_server("svc")
    mgr.start("svc", "observe", "attach", "exact")
    client = backend.fake_client("svc")
    client.send(b"bye")
    assert server.recv() == b"bye"
    client.close()
    assert server.recv() is None


def test_arm_prefix_takes_first_new_matching_pipe(backend, mgr):
    backend.fake_server("postex_old")
    s = mgr.start(r"\postex_", "observe", "arm", "prefix")
    assert s["state"] == "armed"
    backend.fake_server("unrelated")
    watcher_polls(mgr, s["id"])
    assert mgr.get(s["id"])["state"] == "armed"
    server = backend.fake_server("postex_ab12")
    assert wait_for(lambda: mgr.get(s["id"])["state"] == "active")
    assert mgr.get(s["id"])["target"] == r"\postex_ab12"
    assert [c[0] for c in backend.created] == [r"\postex_ab12"]
    client = backend.fake_client("postex_ab12")
    client.send(b"hi")
    assert server.recv() == b"hi"


def test_arm_regex_and_blocklist_never_taken(backend, mgr):
    s = mgr.start(r"^\\(lsass|msagent_\d+)$", "observe", "arm", "regex")
    backend.fake_server("lsass")
    watcher_polls(mgr, s["id"])
    assert mgr.get(s["id"])["state"] == "armed"
    backend.fake_server("MSAGENT_42")
    assert wait_for(lambda: mgr.get(s["id"])["target"] == r"\MSAGENT_42")


def test_squat_creates_first_instance_and_waits_for_real_server(backend, mgr):
    s = mgr.start("sq", "observe", "arm", "exact", squat=True)
    assert s["state"] == "active"
    assert backend.created == [(r"\sq", "byte", True)]
    client = backend.fake_client("sq")
    client.send(b"early")
    attempts = backend.connect_attempts
    assert wait_for(lambda: backend.connect_attempts >= attempts + 2)   # upstream retries
    assert mgr.get(s["id"])["state"] == "active"
    server = backend.fake_server("sq")
    assert server.recv() == b"early"
    server.send(b"late")
    assert client.recv() == b"late"


def test_blocklist_and_validation(backend, mgr):
    backend.fake_server("lsass")
    backend.fake_server("exists")
    for name in (r"\lsass", "LSASS", r"\\.\pipe\ntsvcs", "protected_storage"):
        with pytest.raises(ValueError):
            mgr.start(name, "observe", "attach", "exact")
        with pytest.raises(ValueError):
            mgr.start(name, "observe", "arm", "exact")
    with pytest.raises(ValueError):
        mgr.start("missing", "observe", "attach", "exact")
    with pytest.raises(ValueError):
        mgr.start("sq", "observe", "arm", "prefix", squat=True)
    with pytest.raises(ValueError):
        mgr.start("exists", "observe", "attach", "exact", squat=True)
    with pytest.raises(ValueError):
        mgr.start("exists", "observe", "arm", "exact", squat=True)
    with pytest.raises(ValueError):
        mgr.start("exists", "observe", "attach", "prefix")
    with pytest.raises(ValueError):
        mgr.start("(", "observe", "arm", "regex")
    with pytest.raises(ValueError):
        mgr.start("exists", "sniff", "attach", "exact")
    with pytest.raises(ValueError):
        mgr.start("exists", "observe", "attach", "exact", max_duration=0)
    with pytest.raises(ValueError):
        mgr.start("", "observe", "arm", "prefix")
    assert mgr.list() == []
    assert backend.created == []


def test_message_mode_is_preserved(backend, mgr):
    server = backend.fake_server("msg", mode="message")
    s = mgr.start("msg", "observe", "attach", "exact")
    assert s["pipe_mode"] == "message"
    assert backend.created[0][1] == "message"
    client = backend.fake_client("msg")
    client.send(b"a")
    client.send(b"bc")
    assert server.recv() == b"a"
    assert server.recv() == b"bc"


def test_large_message_truncated_in_log_but_relayed_in_full(backend, mgr):
    server = backend.fake_server("big", mode="message")
    sid = mgr.start("big", "observe", "attach", "exact")["id"]
    client = backend.fake_client("big")
    payload = bytes(range(256)) * (4 * 4096 + 1)          # > 1 MiB
    client.send(payload)
    assert server.recv() == payload
    assert wait_for(lambda: len(mgr.messages(sid)) == 1)
    rec = mgr.messages(sid)[0]
    assert rec["size"] == len(payload) and rec["truncated"] is True
    assert base64.b64decode(rec["data_b64"]) == payload[:pipe_proxy.MAX_MESSAGE_LOG]


def test_session_recording_cap(backend, make_manager):
    m = make_manager(max_session_record=10)
    server = backend.fake_server("cap", mode="message")
    sid = m.start("cap", "observe", "attach", "exact")["id"]
    client = backend.fake_client("cap")
    for chunk in (b"123456", b"abcdef", b"xy"):
        client.send(chunk)
        assert server.recv() == chunk
    assert wait_for(lambda: len(m.messages(sid)) == 3)
    msgs = m.messages(sid)
    assert m.get(sid)["recording_truncated"] is True
    assert base64.b64decode(msgs[0]["data_b64"]) == b"123456"
    assert msgs[1]["data_b64"] == "" and msgs[2]["data_b64"] == ""
    assert msgs[2]["size"] == 2


def test_stop_persists_and_new_manager_lists_ended(backend, make_manager, tmp_path):
    m = make_manager()
    server = backend.fake_server("svc")
    sid = m.start("svc", "hold", "attach", "exact")["id"]
    client = backend.fake_client("svc")
    client.send(b"ping")
    assert wait_for(lambda: len(m.messages(sid)) == 1)
    s = m.stop(sid)
    assert s["state"] == "ended" and s["end_reason"] == "stopped"
    assert m.stop(sid)["state"] == "ended"
    assert server.recv() == b"ping"            # held messages are forwarded on stop
    assert server.recv() is None
    assert m.messages(sid)[0]["state"] == "auto_passed"
    path = tmp_path / "sessions" / f"{sid}.json"
    doc = json.loads(path.read_text())
    assert doc["session"]["id"] == sid
    assert base64.b64decode(doc["messages"][0]["data_b64"]) == b"ping"

    m2 = make_manager()
    listed = m2.list()
    assert [x["id"] for x in listed] == [sid] and listed[0]["state"] == "ended"
    assert m2.get(sid)["state"] == "ended"
    assert m2.messages(sid)[0]["seq"] == 1
    with pytest.raises(ValueError):
        m2.act(sid, 1, "forward")
    with pytest.raises(KeyError):
        m2.get("nope")


def test_arm_session_expires_while_waiting(backend, mgr, clock):
    sid = mgr.start("never", "observe", "arm", "exact", max_duration=5)["id"]
    clock.advance(6)
    mgr.check_timers()
    assert mgr.get(sid)["state"] == "ended"


def test_ticker_thread_drives_timers(backend, make_manager, clock):
    m = make_manager(tick_interval=0.01)
    backend.fake_server("svc")
    sid = m.start("svc", "observe", "attach", "exact", max_duration=10)["id"]
    clock.advance(11)
    assert wait_for(lambda: m.get(sid)["state"] == "ended")


def test_win32_backend_imports_and_guards_constructor():
    import pipe_backends
    if pipe_backends.os.name != "nt":
        with pytest.raises(RuntimeError):
            pipe_proxy.Win32PipeBackend()


def test_watcher_retries_failed_attach_and_reports_error(backend, mgr, monkeypatch):
    real_create = backend.create_server
    calls = []

    def flaky(name, mode, first_instance):
        calls.append(name)
        if len(calls) < 3:
            raise OSError("instance limit")
        return real_create(name, mode, first_instance)

    monkeypatch.setattr(backend, "create_server", flaky)
    sid = mgr.start("postex_", "observe", "arm", "prefix")["id"]
    backend.fake_server("postex_1")
    assert wait_for(lambda: mgr.get(sid)["state"] == "active")
    assert len(calls) == 3 and "instance limit" in mgr.get(sid)["last_error"]


def test_watcher_gives_up_after_bounded_retries(backend, mgr, monkeypatch):
    calls = []

    def broken(name, mode, first_instance):
        calls.append(name)
        raise OSError("nope")

    monkeypatch.setattr(backend, "create_server", broken)
    sid = mgr.start("postex_", "observe", "arm", "prefix")["id"]
    backend.fake_server("postex_1")
    assert wait_for(lambda: len(calls) == pipe_proxy.WATCH_RETRIES)
    watcher_polls(mgr, sid, 3)
    assert len(calls) == pipe_proxy.WATCH_RETRIES
    assert mgr.get(sid)["state"] == "armed"


def test_blocked_write_does_not_stall_timers_or_act(backend, make_manager, clock):
    m = make_manager(drain_timeout=0.1)
    stuck_server = backend.fake_server("stuck", mode="message")
    slow_server = backend.fake_server("slow")
    backend.fake_server("short")
    stuck = m.start("stuck", "hold", "attach", "exact")["id"]
    slow = m.start("slow", "hold", "attach", "exact", hold_timeout=30)["id"]
    short = m.start("short", "observe", "attach", "exact", max_duration=5)["id"]
    short_client = backend.fake_client("short")

    backend.block_writes("stuck")
    stuck_client = backend.fake_client("stuck")
    stuck_client.send(b"m1")
    stuck_client.send(b"m2")
    assert wait_for(lambda: len(m.messages(stuck)) == 2)
    first, second = [x["seq"] for x in m.messages(stuck)]
    m.act(stuck, first, "forward")             # the pump now blocks writing m1
    assert wait_for(lambda: m._live(stuck).conns[0].dirs["c2s"].writing)

    t0 = time.monotonic()
    m.act(stuck, second, "forward")
    assert m.release_all(stuck) == 0
    assert time.monotonic() - t0 < 0.2

    slow_client = backend.fake_client("slow")
    slow_client.send(b"later")
    assert wait_for(lambda: len(m.messages(slow)) == 1)
    clock.advance(31)
    t0 = time.monotonic()
    m.check_timers()
    assert time.monotonic() - t0 < 0.2
    assert slow_server.recv() == b"later"
    assert m.messages(slow)[0]["state"] == "auto_passed"
    assert m.get(short)["state"] == "ended"
    assert short_client.recv() is None

    t0 = time.monotonic()
    m.stop(stuck)                               # drains briefly, then closes the stuck write
    assert time.monotonic() - t0 < 1.5
    assert stuck_client.recv() is None
    assert stuck_server.recv(timeout=0.05) is None


def test_win32_client_opens_are_identification_only(monkeypatch):
    import pipe_backends
    if pipe_backends.wt is None:
        pytest.skip("ctypes.wintypes unavailable")
    assert pipe_backends.CLIENT_OPEN_FLAGS & 0x00100000      # SECURITY_SQOS_PRESENT
    assert pipe_backends.CLIENT_OPEN_FLAGS & 0x00010000      # SECURITY_IDENTIFICATION
    assert pipe_backends.CLIENT_OPEN_FLAGS & pipe_backends.FILE_FLAG_OVERLAPPED

    class K32:
        def __init__(self):
            self.calls = []

        def CreateFileW(self, path, access, share, sa, disposition, flags, template):
            self.calls.append(("CreateFileW", path, flags))
            return 4242

        def GetNamedPipeInfo(self, h, flags, *rest):
            return 0

        def CancelIoEx(self, h, ov):
            self.calls.append(("CancelIoEx", h))
            return 1

        def CloseHandle(self, h):
            self.calls.append(("CloseHandle", h))
            return 1

    k32 = K32()
    monkeypatch.setattr(pipe_backends, "_k32", k32)
    b = pipe_backends.Win32PipeBackend()
    h = b.connect("svc", 1.0)
    assert h.mode == "byte"
    b.close(h)
    assert b.pipe_mode(r"\\.\pipe\svc") == "byte"
    opens = [c for c in k32.calls if c[0] == "CreateFileW"]
    assert [c[1] for c in opens] == [r"\\.\pipe\svc"] * 2
    assert all(c[2] == pipe_backends.CLIENT_OPEN_FLAGS for c in opens)
    assert k32.calls.count(("CloseHandle", 4242)) == 2


def test_win_handle_close_waits_for_in_flight_io():
    import pipe_backends
    events = []
    h = pipe_backends._WinHandle(7, "byte", cancel=lambda v: events.append(("cancel", v)),
                                 closer=lambda v: events.append(("close", v)))
    assert h.acquire() and h.acquire()
    h.close()
    assert events == [("cancel", 7)]           # pending I/O cancelled, value not freed
    assert not h.acquire()                     # no new I/O after close
    h.release()
    assert events == [("cancel", 7)]
    h.release()
    assert events == [("cancel", 7), ("close", 7)]
    h.close()
    assert events == [("cancel", 7), ("close", 7)]

    idle = pipe_backends._WinHandle(8, "byte", cancel=lambda v: events.append(("cancel", v)),
                                    closer=lambda v: events.append(("close", v)))
    idle.close()
    idle.close()
    assert events[-1] == ("close", 8) and events.count(("close", 8)) == 1
    assert ("cancel", 8) not in events


def test_shutdown_joins_ticker_before_collecting_finishers(make_manager, monkeypatch):
    m = make_manager(tick_interval=0.01)
    late = []

    def slow_tick():
        # A tick that is still running when shutdown() starts and only then
        # spawns a session finisher.
        if not m._shutdown.wait(1.0):
            return
        time.sleep(0.05)
        t = threading.Thread(target=time.sleep, args=(0.3,), name="pipe_proxy-late-finisher")
        with m._lock:
            m._finishers.append(t)
        t.start()
        late.append(t)

    monkeypatch.setattr(m, "check_timers", slow_tick)
    m._ensure_ticker()
    time.sleep(0.03)
    m.shutdown()
    assert late and not late[0].is_alive()


class _PendingK32:
    """kernel32 stand-in whose overlapped WriteFile/ReadFile never completes
    on its own; only CancelIoEx ends it (ERROR_OPERATION_ABORTED)."""

    def __init__(self, pb):
        self.pb = pb
        self.calls = []
        self.cancelled = False
        self.err = 0

    def CreateEventW(self, *a):
        return 99

    def CloseHandle(self, h):
        return 1

    def _pending(self, name):
        self.calls.append(name)
        self.err = self.pb.ERROR_IO_PENDING
        return 0

    def WriteFile(self, *a):
        return self._pending("WriteFile")

    def ReadFile(self, *a):
        return self._pending("ReadFile")

    def WaitForSingleObject(self, ev, ms):
        end = time.monotonic() + min(ms, 2000) / 1000
        while time.monotonic() < end and not self.cancelled:
            time.sleep(0.005)
        return self.pb.WAIT_OBJECT_0 if self.cancelled else self.pb.WAIT_TIMEOUT

    def CancelIoEx(self, h, ov):
        self.calls.append("CancelIoEx")
        self.cancelled = True
        return 1

    def GetOverlappedResult(self, h, ov, n, wait):
        if self.cancelled:
            self.err = self.pb.ERROR_OPERATION_ABORTED
            return 0
        self.err = self.pb.ERROR_IO_INCOMPLETE
        return 0


@pytest.fixture
def pending_k32(monkeypatch):
    import ctypes
    import pipe_backends
    if pipe_backends.wt is None:
        pytest.skip("ctypes.wintypes unavailable")
    k32 = _PendingK32(pipe_backends)
    monkeypatch.setattr(pipe_backends, "_k32", k32)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: k32.err, raising=False)
    return k32


def test_win32_io_on_closed_handle_is_not_issued(pending_k32):
    import pipe_backends
    b = pipe_backends.Win32PipeBackend()
    h = pipe_backends._WinHandle(5, "byte", cancel=lambda v: None, closer=lambda v: None)
    assert h.acquire()
    h.close()                                  # close() between acquire() and WriteFile
    t0 = time.monotonic()
    with pytest.raises(BrokenPipeError):
        b._write(h, b"data")
    assert b._read(h, 5.0) is None
    assert time.monotonic() - t0 < 0.5
    assert "WriteFile" not in pending_k32.calls and "ReadFile" not in pending_k32.calls


def test_win32_close_during_pending_io_cancels_it(pending_k32):
    import pipe_backends
    b = pipe_backends.Win32PipeBackend()
    # The cancel in close() runs before the I/O exists, so it misses it.
    h = pipe_backends._WinHandle(5, "byte", cancel=lambda v: None, closer=lambda v: None)
    assert h.acquire()
    threading.Timer(0.05, h.close).start()
    t0 = time.monotonic()
    with pytest.raises(BrokenPipeError):
        b._write(h, b"data")
    assert time.monotonic() - t0 < 0.5
    assert pending_k32.calls == ["WriteFile", "CancelIoEx"]


# ------------------------------------------------------------------ API routes

@pytest.fixture
def api(tdc, client, make_manager, monkeypatch):
    m = make_manager()
    monkeypatch.setattr(tdc, "_intercept", m)
    return client


def test_intercept_manager_is_created_lazily(app_module, monkeypatch, tmp_path):
    # A fresh interpreter: importing app.py must not create the manager or threads.
    code = ("import threading, app; "
            "print(app._intercept is None, "
            "[t.name for t in threading.enumerate() if t.name.startswith('pipe_proxy')])")
    env = dict(os.environ, TDC_NO_BACKGROUND="1",
               PYTHONPATH=os.path.join(os.path.dirname(os.path.dirname(__file__)), "webui"))
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                         text=True, timeout=60)
    assert out.stdout.strip().splitlines()[-1] == "True []", out.stderr

    registered = []
    monkeypatch.setattr(app_module, "_intercept", None)
    monkeypatch.setattr(app_module, "PIPE_SESSIONS_DIR", str(tmp_path / "ps"))
    monkeypatch.setattr(app_module.atexit, "register", registered.append)
    m = app_module._get_intercept()
    assert app_module._get_intercept() is m and registered == [m.shutdown]
    assert isinstance(m.backend, FakePipeBackend if os.name != "nt" else pipe_proxy.Win32PipeBackend)
    m.shutdown()


def test_intercept_routes_roundtrip(api, backend):
    server = backend.fake_server("svc")
    r = api.post("/api/pipes/intercept", json={"pattern": "svc", "mode": "hold",
                                                 "how": "attach", "match": "exact"})
    assert r.status_code == 201, r.get_json()
    sid = r.get_json()["id"]
    assert r.get_json()["state"] == "active"
    assert [s["id"] for s in api.get("/api/pipes/intercept").get_json()["sessions"]] == [sid]
    assert api.get(f"/api/pipes/intercept/{sid}").get_json()["target"] == r"\svc"

    client = backend.fake_client("svc")
    client.send(b"pinx")
    assert wait_for(lambda: len(api.get(f"/api/pipes/intercept/{sid}/messages")
                                .get_json()["messages"]) == 1)
    msg = api.get(f"/api/pipes/intercept/{sid}/messages?after=0&limit=10").get_json()["messages"][0]
    assert msg["state"] == "held" and base64.b64decode(msg["data_b64"]) == b"pinx"
    r = api.post(f"/api/pipes/intercept/{sid}/messages/{msg['seq']}",
                 json={"action": "edit", "data_b64": "cGluZw=="})
    assert r.status_code == 200 and r.get_json()["state"] == "edited"
    assert server.recv() == b"ping"

    client.send(b"two")
    assert wait_for(lambda: api.get(f"/api/pipes/intercept/{sid}").get_json()["held_count"] == 1)
    assert api.post(f"/api/pipes/intercept/{sid}/release").get_json() == {"released": 1}
    assert server.recv() == b"two"
    assert api.get(f"/api/pipes/intercept/{sid}/messages?after=1").get_json()["messages"][0]["seq"] == 2

    r = api.post(f"/api/pipes/intercept/{sid}/messages/1", json={"action": "forward"})
    assert r.status_code == 400 and "not held" in r.get_json()["error"]

    r = api.delete(f"/api/pipes/intercept/{sid}")
    assert r.status_code == 200 and r.get_json()["state"] == "ended"
    assert client.recv() is None

    r = api.get(f"/api/pipes/intercept/{sid}/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["Content-Disposition"] and sid in r.headers["Content-Disposition"]
    assert r.headers["Content-Security-Policy"].startswith("sandbox")
    assert r.headers["Content-Type"] == "application/octet-stream"
    doc = json.loads(r.data)
    assert doc["session"]["id"] == sid and [x["seq"] for x in doc["messages"]] == [1, 2]
    assert base64.b64decode(doc["messages"][0]["original_b64"]) == b"pinx"


def test_intercept_rejects_cross_site_post(api, backend):
    backend.fake_server("svc")
    r = api.post("/api/pipes/intercept", json={"pattern": "svc"},
                 headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert backend.created == []
    r = api.delete("/api/pipes/intercept/abc", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_intercept_rejects_blocked_pipe(api, backend):
    backend.fake_server("lsass")
    r = api.post("/api/pipes/intercept", json={"pattern": r"\lsass", "how": "attach"})
    assert r.status_code == 400 and "blocklist" in r.get_json()["error"]
    assert backend.created == []


@pytest.mark.parametrize("body", [
    None, [], {"pattern": "svc", "bogus": 1}, {"pattern": "svc", "squat": "yes"},
    {"pattern": "svc", "max_duration": "10"}, {"pattern": "svc", "pipe_mode": "duplex"},
    {"how": "attach"}, {"pattern": "svc", "max_duration": 3601},
    {"pattern": "svc", "max_duration": 60, "hold_timeout": 61},
    '{"pattern": "svc", "max_duration": NaN}', '{"pattern": "svc", "hold_timeout": Infinity}',
    '{"pattern": "svc", "max_duration": -Infinity}',
])
def test_intercept_start_validates_body(api, backend, body):
    backend.fake_server("svc")
    if body is None:
        r = api.post("/api/pipes/intercept", data="x", content_type="text/plain")
    elif isinstance(body, str):            # raw JSON with NaN/Infinity literals
        r = api.post("/api/pipes/intercept", data=body, content_type="application/json")
    else:
        r = api.post("/api/pipes/intercept", json=body)
    assert r.status_code == 400 and r.get_json()["error"]
    assert backend.created == []


def test_intercept_start_passes_pipe_mode(api, backend, monkeypatch):
    backend.fake_server("svc")
    monkeypatch.setattr(backend, "pipe_mode", lambda name: pytest.fail("probed the server"))
    r = api.post("/api/pipes/intercept", json={"pattern": "svc", "pipe_mode": "message"})
    assert r.status_code == 201 and r.get_json()["pipe_mode"] == "message"


def test_intercept_unknown_session_and_bad_params(api, backend):
    for method, path in (("get", "/api/pipes/intercept/nope"),
                         ("delete", "/api/pipes/intercept/nope"),
                         ("get", "/api/pipes/intercept/nope/messages"),
                         ("post", "/api/pipes/intercept/nope/release"),
                         ("get", "/api/pipes/intercept/nope/export")):
        assert getattr(api, method)(path).status_code == 404, path
    r = api.post("/api/pipes/intercept/nope/messages/1", json={"action": "forward"})
    assert r.status_code == 404
    backend.fake_server("svc")
    sid = api.post("/api/pipes/intercept", json={"pattern": "svc"}).get_json()["id"]
    assert api.get(f"/api/pipes/intercept/{sid}/messages?after=x").status_code == 400
    assert api.post(f"/api/pipes/intercept/{sid}/messages/1", json=["x"]).status_code == 400
    r = api.post(f"/api/pipes/intercept/{sid}/messages/1", json={"action": "edit", "data_b64": "%%"})
    assert r.status_code == 400


def test_durations_must_be_finite_and_bounded(backend, mgr):
    backend.fake_server("svc")
    for kw in ({"max_duration": float("nan")}, {"max_duration": float("inf")},
               {"hold_timeout": float("nan")}, {"hold_timeout": float("inf")},
               {"max_duration": 3601}, {"max_duration": 60, "hold_timeout": 61}):
        with pytest.raises(ValueError):
            mgr.start("svc", "hold", "attach", "exact", **kw)
    assert backend.created == []
    s = mgr.start("svc", "hold", "attach", "exact", max_duration=3600, hold_timeout=3600)
    assert s["max_duration"] == 3600 and s["hold_timeout"] == 3600
    mgr.stop(s["id"])
    backend.fake_server("svc")                    # the server's next instance
    assert mgr.start("svc", "hold", "attach", "exact", max_duration=10)["hold_timeout"] == 10
    json.dumps(mgr.list(), allow_nan=False)


class SpareServer:
    """A real server that always keeps one free instance: when a client takes
    it, the server creates the next one (as many real servers do)."""

    def __init__(self, backend, name, mode="byte"):
        self.backend, self.name, self.mode = backend, name, mode
        self.conns = []
        self.stop = threading.Event()
        self.spare = backend.fake_server(name, mode)
        self.thread = threading.Thread(target=self._loop, name="spare-server", daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop.is_set():
            if self.spare.wait_connected(0.01):
                self.conns.append(self.spare)
                self.spare = self.backend.fake_server(self.name, self.mode)

    def close(self):
        self.stop.set()
        self.thread.join()
        for ep in self.conns + [self.spare]:
            ep.close()


def test_proxy_instance_stays_ahead_of_a_server_with_spare_instances(backend, mgr):
    server = SpareServer(backend, "spare")
    try:
        sid = mgr.start("spare", "observe", "attach", "exact")["id"]
        clients = []
        for i in range(6):
            c = backend.fake_client("spare")
            clients.append(c)              # kept open: every connection holds an instance
            c.send(f"m{i}".encode())
            assert wait_for(lambda: len(mgr.messages(sid)) == i + 1), f"client {i} bypassed"
        recorded = [base64.b64decode(m["data_b64"]) for m in mgr.messages(sid)]
        assert recorded == [f"m{i}".encode() for i in range(6)]
        assert all(m["conn"] == i + 1 for i, m in enumerate(mgr.messages(sid)))
        got = sorted(d for d in (ep.recv(timeout=0.05) for ep in server.conns[:7]) if d)
        assert got == sorted(f"m{i}".encode() for i in range(6))
        assert mgr.get(sid)["self_connect_retries"] == 0
        for c in clients:
            c.close()
    finally:
        server.close()


def test_upstream_connect_on_own_instance_is_retried(backend, make_manager, monkeypatch):
    monkeypatch.setattr(pipe_proxy, "FLUSH_TIMEOUT", 0.1)
    m = make_manager(connect_timeout=5.0)
    first = backend.fake_server("solo")           # one instance, no spare
    sid = m.start("solo", "observe", "attach", "exact")["id"]
    c1 = backend.fake_client("solo")              # gets the proxy; upstream is `first`
    c1.send(b"one")
    assert first.recv() == b"one"
    # The spare flush after the first client finds only our own instance free.
    assert wait_for(lambda: m.get(sid)["self_connect_retries"] == 1)
    time.sleep(0.2)                               # flush gave up; many attempts, one episode
    assert m.get(sid)["self_connect_retries"] == 1
    c2 = backend.fake_client("solo")              # the proxy's next instance
    c2.send(b"two")
    # The upstream for c2 again finds only the proxy's own new instance free.
    assert wait_for(lambda: m.get(sid)["self_connect_retries"] == 2)
    time.sleep(0.1)
    assert m.get(sid)["self_connect_retries"] == 2
    second = backend.fake_server("solo")          # the server offers another instance
    assert second.recv() == b"two"                # ... and the proxy's retry takes it
    assert [base64.b64decode(x["data_b64"]) for x in m.messages(sid)] == [b"one", b"two"]
    assert m.get(sid)["last_error"] is None


def test_export_reads_persisted_file_once_and_reports_errors(api, tdc, backend):
    backend.fake_server("svc")
    sid = api.post("/api/pipes/intercept", json={"pattern": "svc"}).get_json()["id"]
    c = backend.fake_client("svc")
    c.send(b"x")
    m = tdc._intercept
    assert wait_for(lambda: len(m.messages(sid)) == 1)
    api.delete(f"/api/pipes/intercept/{sid}")
    path = m._persisted[sid]["path"]
    doc = json.loads(api.get(f"/api/pipes/intercept/{sid}/export").data)
    assert [x["seq"] for x in doc["messages"]] == [1]
    with open(path, "w") as f:
        f.write("{broken")
    r = api.get(f"/api/pipes/intercept/{sid}/export")
    assert r.status_code == 500 and "export failed" in r.get_json()["error"]


def _idle_server_conns(backend, name):
    """Real server instances held by a proxy upstream that has no client."""
    return [i for i in backend._instances
            if i.kind == "real" and i.name == name and i.connected
            and not i.closed["server"] and not i.closed["client"]]


def test_server_holds_no_idle_proxy_connection_after_first_client(backend, mgr):
    server = SpareServer(backend, "idle")
    try:
        sid = mgr.start("idle", "observe", "attach", "exact")["id"]
        assert len(_idle_server_conns(backend, r"\idle")) == 1     # for the first client
        for i in range(4):
            c = backend.fake_client("idle")
            c.send(f"m{i}".encode())
            assert wait_for(lambda: len(mgr.messages(sid)) == i + 1), f"client {i} bypassed"
            assert len(_idle_server_conns(backend, r"\idle")) == 1  # only this client's
            c.close()
            assert wait_for(lambda: not _idle_server_conns(backend, r"\idle"))
            time.sleep(0.05)
            assert not _idle_server_conns(backend, r"\idle"), "idle proxy connection"
    finally:
        server.close()


def test_one_session_per_pipe(backend, mgr):
    backend.fake_server("svc")
    first = mgr.start("svc", "observe", "attach", "exact")
    for args, kw in ((("SVC", "hold", "attach", "exact"), {}),
                     ((r"\\.\pipe\svc", "observe", "arm", "exact"), {})):
        with pytest.raises(ValueError, match=first["id"]):
            mgr.start(*args, **kw)
    sq = mgr.start("sq", "observe", "arm", "exact", squat=True)
    with pytest.raises(ValueError, match=sq["id"]):
        mgr.start("sq", "observe", "arm", "exact")
    waiting = mgr.start("later", "observe", "arm", "exact")      # claims before it exists
    with pytest.raises(ValueError, match=waiting["id"]):
        mgr.start("later", "observe", "arm", "exact", squat=True)
    assert len(mgr.list()) == 3
    mgr.stop(first["id"])
    backend.fake_server("svc")                    # the server's next instance
    assert mgr.start("svc", "observe", "attach", "exact")["state"] == "active"


def test_arm_watcher_skips_pipes_owned_by_another_session(backend, mgr):
    taken = mgr.start(r"\postex_1", "observe", "arm", "exact")
    prefix = mgr.start(r"\postex_", "observe", "arm", "prefix")
    backend.fake_server("postex_1")
    assert wait_for(lambda: mgr.get(taken["id"])["state"] == "active")
    watcher_polls(mgr, prefix["id"], 3)
    assert mgr.get(prefix["id"])["state"] == "armed"
    backend.fake_server("postex_2")
    assert wait_for(lambda: mgr.get(prefix["id"])["target"] == r"\postex_2")
    with pytest.raises(ValueError, match=prefix["id"]):
        mgr.start(r"\postex_2", "observe", "attach", "exact")


def test_start_returns_starting_before_the_first_upstream(backend, make_manager, monkeypatch):
    m = make_manager()
    backend.fake_server("slow")
    gate = threading.Event()
    real_connect = backend.connect

    def slow_connect(name, timeout):
        gate.wait(2.0)
        return real_connect(name, timeout)

    monkeypatch.setattr(backend, "connect", slow_connect)
    t0 = time.monotonic()
    s = InterceptManager.start(m, "slow", "observe", "attach", "exact")
    assert time.monotonic() - t0 < 0.5 and s["state"] == "starting"
    gate.set()
    assert wait_for(lambda: m.get(s["id"])["state"] == "active")
