"""Named pipe interception engine, driven through the in-memory FakePipeBackend."""

import base64
import json
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
        m = InterceptManager(backend, str(tmp_path / "sessions"), **kw)
        managers.append(m)
        return m

    yield make
    for m in managers:
        m.shutdown()
    leaked = [t.name for t in threading.enumerate() if t.name.startswith("pipe_proxy")]
    assert not leaked, leaked


@pytest.fixture
def mgr(make_manager):
    return make_manager()


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
    assert not backend.exists("svc") or all(
        i.kind == "real" for i in backend._instances if not i.closed["server"])


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
    time.sleep(0.03)
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
    time.sleep(0.03)
    assert mgr.get(s["id"])["state"] == "armed"
    backend.fake_server("MSAGENT_42")
    assert wait_for(lambda: mgr.get(s["id"])["target"] == r"\MSAGENT_42")


def test_squat_creates_first_instance_and_waits_for_real_server(backend, mgr):
    s = mgr.start("sq", "observe", "arm", "exact", squat=True)
    assert s["state"] == "active"
    assert backend.created == [(r"\sq", "byte", True)]
    client = backend.fake_client("sq")
    client.send(b"early")
    time.sleep(0.03)
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
    assert server.recv(timeout=0.05) is None
    assert m.messages(sid)[0]["state"] == "dropped"
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
