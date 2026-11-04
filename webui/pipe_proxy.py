"""Named pipe interception engine (pipe-intercept model).

The proxy creates additional server instances of a target pipe. Every client
that lands on a proxy instance gets its own upstream connection to the real
server, and two pump threads relay client->server (`c2s`) and server->client
(`s2c`). In `hold` mode each direction is a FIFO: a message is only written
once it and every message before it have been decided (forward/edit/drop or
auto-forward after `hold_timeout`).

Session timers (hold timeout, max duration) use the injected `clock`; they are
evaluated by `check_timers()`, which a daemon ticker thread calls every
`tick_interval` seconds (None disables the ticker, as in the tests). I/O waits
use real time with short `io_timeout` slices so every thread notices `stop()`.

Each direction's pump thread is its only writer: `act`, `release_all` and
`check_timers` only change message states and wake the pump, so HTTP handlers
and the ticker never wait behind a stalled pipe write. `stop()` forwards
still-held messages (state `auto_passed`), gives the pumps up to
`drain_timeout` seconds to write them, then closes every handle.

Locks: the manager lock only guards the session dict and is never held while
taking a session lock; no I/O happens under either lock.
"""

import base64
import json
import math
import os
import re
import secrets
import threading
import time
from collections import deque
from typing import Optional

from pipe_analysis import canonical_name
from pipe_backends import (MODES, FakeEndpoint, FakePipeBackend, PipeBackend,  # noqa: F401
                           Win32PipeBackend)

BLOCKLIST = frozenset({"\\lsass", "\\ntsvcs", "\\protected_storage"})
MAX_MESSAGE_LOG = 1024 * 1024
MAX_SESSION_RECORD = 50 * 1024 * 1024
MAX_DURATION_LIMIT = 3600
DEFAULT_HOLD_TIMEOUT = 30
SESSION_MODES = ("observe", "hold")
HOWS = ("attach", "arm")
MATCHES = ("exact", "prefix", "regex")
ACTIONS = ("forward", "drop", "edit")
_SID_FILE_RE = re.compile(r"^[0-9a-f]{12}\.json$")
_JOIN_TIMEOUT = 2.0
WATCH_RETRIES = 3


def _key(name):
    return canonical_name(name).lower()


def _positive(value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) \
        and math.isfinite(value) and value > 0


class _Item:
    def __init__(self, seq, data, state, held_at, rec, direction):
        self.seq = seq
        self.data = data
        self.state = state
        self.held_at = held_at
        self.rec = rec
        self.direction = direction


class _Direction:
    def __init__(self, conn, name, src, dst):
        self.conn = conn
        self.name = name
        self.src = src
        self.dst = dst
        self.queue = deque()
        self.eof = False
        self.writing = False
        self.wake = threading.Event()


class _Conn:
    def __init__(self, cid, client, upstream):
        self.id = cid
        self.open_dirs = 2
        self.dirs = {"c2s": _Direction(self, "c2s", client, upstream),
                     "s2c": _Direction(self, "s2c", upstream, client)}


class _Session:
    def __init__(self, sid, pattern, mode, how, match, squat, max_duration, hold_timeout,
                 pipe_mode, started):
        self.id = sid
        self.pattern = pattern
        self.mode = mode
        self.how = how
        self.match = match
        self.squat = squat
        self.max_duration = max_duration
        self.hold_timeout = hold_timeout
        self.pipe_mode_hint = pipe_mode
        self.pipe_mode = None
        self.target = None
        self.started = started
        self.ended_at = None
        self.state = "armed"
        self.end_reason = None
        self.ended = False
        self.lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.threads = []
        self.handles = set()
        self.conns = []
        self.messages = []
        self.pending = {}
        self.next_seq = 1
        self.recorded_bytes = 0
        self.recording_truncated = False
        self.last_error = None
        self.watch_polls = 0
        self.self_connect_retries = 0
        self.regex = re.compile(pattern, re.IGNORECASE) if match == "regex" else None

    def matches(self, name):
        name = canonical_name(name)
        if self.match == "regex":
            return bool(self.regex.search(name))
        if self.match == "prefix":
            return name.lower().startswith(self.pattern.lower())
        return name.lower() == self.pattern.lower()


class InterceptManager:
    def __init__(self, backend, store_dir, clock=time.time, tick_interval: Optional[float] = 1.0,
                 io_timeout: float = 0.25, poll_interval: float = 0.5,
                 connect_timeout: float = 5.0, max_message_log: int = MAX_MESSAGE_LOG,
                 max_session_record: int = MAX_SESSION_RECORD, drain_timeout: float = 2.0,
                 own_pid: Optional[int] = None, settle: float = 0.1):
        self.backend = backend
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self.settle = settle
        self.store_dir = store_dir
        self.clock = clock
        self.tick_interval = tick_interval
        self.io_timeout = io_timeout
        self.poll_interval = poll_interval
        self.connect_timeout = connect_timeout
        self.max_message_log = max_message_log
        self.max_session_record = max_session_record
        self.drain_timeout = drain_timeout
        self._finishers = []
        self._lock = threading.Lock()
        self._sessions = {}
        self._persisted = {}
        self._shutdown = threading.Event()
        self._ticker = None
        os.makedirs(store_dir, exist_ok=True)
        self._load_persisted()

    # ---------------------------------------------------------------- public

    def start(self, pattern: str, mode: str, how: str, match: str, squat: bool = False,
              max_duration: int = 600, hold_timeout: Optional[int] = None,
              pipe_mode: Optional[str] = None) -> dict:
        """Start a session. `hold_timeout` defaults to min(30, max_duration)."""
        if mode not in SESSION_MODES:
            raise ValueError(f"mode must be one of {SESSION_MODES}")
        if how not in HOWS:
            raise ValueError(f"how must be one of {HOWS}")
        if match not in MATCHES:
            raise ValueError(f"match must be one of {MATCHES}")
        if pipe_mode is not None and pipe_mode not in MODES:
            raise ValueError(f"pipe_mode must be one of {MODES}")
        if hold_timeout is None and _positive(max_duration):
            hold_timeout = min(DEFAULT_HOLD_TIMEOUT, max_duration)
        for label, value in (("max_duration", max_duration), ("hold_timeout", hold_timeout)):
            if not _positive(value):
                raise ValueError(f"{label} must be a positive finite number")
        if max_duration > MAX_DURATION_LIMIT:
            raise ValueError(f"max_duration must be at most {MAX_DURATION_LIMIT} seconds")
        if hold_timeout > max_duration:
            raise ValueError("hold_timeout must not exceed max_duration")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("pattern is required")
        if match == "regex":
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"invalid regex: {e}") from None
        else:
            pattern = canonical_name(pattern)
            if pattern == "\\":
                raise ValueError("pattern is required")
            if pattern.lower() in BLOCKLIST:
                raise ValueError(f"pipe {pattern} is on the blocklist")
        if squat and (match != "exact" or how != "arm"):
            raise ValueError("squat requires match='exact' and how='arm'")
        if how == "attach" and match != "exact":
            raise ValueError("attach requires match='exact'")

        s = _Session(secrets.token_hex(6), pattern, mode, how, match, bool(squat),
                     max_duration, hold_timeout, pipe_mode, self.clock())
        first = None
        if how == "attach":
            if not self.backend.exists(pattern):
                raise ValueError(f"pipe {pattern} does not exist")
            try:
                s.pipe_mode = pipe_mode or self.backend.pipe_mode(pattern)
                first = self.backend.create_server(pattern, s.pipe_mode, False)
            except OSError as e:
                raise ValueError(f"cannot attach to {pattern}: {e}") from None
        elif squat:
            s.pipe_mode = pipe_mode or "byte"
            try:
                first = self.backend.create_server(pattern, s.pipe_mode, True)
            except OSError as e:
                raise ValueError(f"cannot squat {pattern} (already exists?): {e}") from None
        else:
            try:
                known = {_key(n) for n in self.backend.list_pipes()}
            except OSError as e:
                raise ValueError(f"cannot list pipes: {e}") from None

        with self._lock:
            self._sessions[s.id] = s
        if first is not None:
            self._activate(s, pattern, s.pipe_mode, first)
        else:
            with s.lock:
                self._spawn(s, self._watch, (s, known), "watch")
        self._ensure_ticker()
        print(f"[pipe_proxy] session {s.id} started: {how}/{match} {pattern!r} mode={mode}"
              f"{' squat' if squat else ''}")
        return self.get(s.id)

    def stop(self, sid: str, reason: str = "stopped") -> dict:
        """End a session: still-held messages are forwarded (`auto_passed`) and
        written within `drain_timeout`, then both ends of every connection close."""
        s = self._live(sid)
        if s is None:
            return self.get(sid)
        if self._begin_stop(s, reason):
            self._finish_stop(s)
        return self.get(sid)

    def get(self, sid: str) -> dict:
        s = self._live(sid)
        if s is not None:
            with s.lock:
                return self._meta(s)
        with self._lock:
            entry = self._persisted.get(sid)
        if entry is None:
            raise KeyError(sid)
        return dict(entry["session"])

    def list(self) -> list:
        with self._lock:
            live = list(self._sessions.values())
            persisted = [dict(e["session"]) for sid, e in self._persisted.items()
                         if sid not in self._sessions]
        out = persisted
        for s in live:
            with s.lock:
                out.append(self._meta(s))
        return sorted(out, key=lambda m: m.get("started") or 0, reverse=True)

    def messages(self, sid: str, after: int = 0, limit: int = 200) -> list:
        limit = max(1, min(int(limit), 1000))
        after = int(after)
        s = self._live(sid)
        if s is not None:
            with s.lock:
                recs = [dict(r) for r in s.messages if r["seq"] > after][:limit]
            return recs
        with self._lock:
            entry = self._persisted.get(sid)
        if entry is None:
            raise KeyError(sid)
        try:
            with open(entry["path"], encoding="utf-8") as f:
                msgs = json.load(f).get("messages", [])
        except (OSError, ValueError) as e:
            print(f"[pipe_proxy] cannot read {entry['path']}: {e}")
            return []
        return [m for m in msgs if m.get("seq", 0) > after][:limit]

    def export(self, sid: str) -> dict:
        """Session metadata and every message; the file of an ended session is
        read once and read errors raise (OSError/ValueError)."""
        s = self._live(sid)
        if s is not None:
            with s.lock:
                return {"session": self._meta(s), "messages": [dict(r) for r in s.messages]}
        with self._lock:
            entry = self._persisted.get(sid)
        if entry is None:
            raise KeyError(sid)
        with open(entry["path"], encoding="utf-8") as f:
            doc = json.load(f)
        msgs = doc.get("messages", []) if isinstance(doc, dict) else None
        if not isinstance(msgs, list):
            raise ValueError(f"{entry['path']}: messages is not a list")
        return {"session": dict(entry["session"]), "messages": msgs}

    def act(self, sid: str, seq: int, action: str, data_b64: Optional[str] = None) -> dict:
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        new = None
        if action == "edit":
            if not isinstance(data_b64, str):
                raise ValueError("edit requires data_b64")
            try:
                new = base64.b64decode(data_b64, validate=True)
            except (ValueError, TypeError):
                raise ValueError("data_b64 is not valid base64") from None
            if len(new) > self.max_message_log:
                raise ValueError("edited message is too large")
        s = self._live(sid)
        if s is None:
            self.get(sid)
            raise ValueError("session has ended")
        with s.lock:
            if s.ended:
                raise ValueError("session has ended")
            item = s.pending.get(seq)
            if item is None or item.state != "held":
                raise ValueError(f"message {seq} is not held")
            if action == "forward":
                self._set_state(item, "passed")
            elif action == "drop":
                self._set_state(item, "dropped")
            else:
                item.rec["original_b64"] = item.rec["data_b64"]
                item.rec["data_b64"] = base64.b64encode(new).decode("ascii")
                item.rec["size"] = len(new)
                item.rec["truncated"] = False
                item.data = new
                self._set_state(item, "edited")
            rec = dict(item.rec)
            item.direction.wake.set()
        return rec

    def release_all(self, sid: str) -> int:
        s = self._live(sid)
        if s is None:
            self.get(sid)
            return 0
        released = 0
        with s.lock:
            for item in s.pending.values():
                if item.state == "held":
                    self._set_state(item, "passed")
                    item.direction.wake.set()
                    released += 1
        return released

    def check_timers(self) -> None:
        """Expire sessions and auto-forward overdue held messages.

        Never does pipe I/O and never waits for a pump: expired sessions are
        torn down on their own thread.
        """
        now = self.clock()
        with self._lock:
            sessions = list(self._sessions.values())
        expired = []
        for s in sessions:
            with s.lock:
                if s.ended:
                    continue
                if now - s.started >= s.max_duration:
                    expired.append(s)
                    continue
                if s.mode != "hold":
                    continue
                for item in s.pending.values():
                    if item.state == "held" and now - item.held_at >= s.hold_timeout:
                        self._set_state(item, "auto_passed")
                        item.direction.wake.set()
        for s in expired:
            if self._begin_stop(s, "expired"):
                t = threading.Thread(target=self._finish_stop, args=(s,), daemon=True,
                                     name=f"pipe_proxy-{s.id}-stop")
                with self._lock:
                    self._finishers = [f for f in self._finishers if f.is_alive()]
                    self._finishers.append(t)
                    t.start()

    def shutdown(self) -> None:
        self._shutdown.set()
        me = threading.current_thread()
        with self._lock:
            ticker = self._ticker
        # A tick still in progress may start finishers; wait for it first.
        if ticker is not None and ticker is not me:
            ticker.join(_JOIN_TIMEOUT)
        with self._lock:
            sids = list(self._sessions)
        for sid in sids:
            self.stop(sid, "shutdown")
        with self._lock:
            waiters = list(self._finishers)
        for t in waiters:
            if t is not me:
                t.join(_JOIN_TIMEOUT)

    # ------------------------------------------------------------- internals

    def _begin_stop(self, s, reason):
        """Mark `s` ended (synchronously); returns False if it already was."""
        with s.lock:
            if s.ended:
                return False
            s.ended = True
            s.state = "ended"
            s.end_reason = reason
            s.ended_at = self.clock()
            for item in s.pending.values():
                if item.state == "held":
                    self._set_state(item, "auto_passed")
            for c in s.conns:
                for d in c.dirs.values():
                    d.wake.set()
        return True

    def _finish_stop(self, s):
        deadline = time.monotonic() + self.drain_timeout
        while time.monotonic() < deadline:
            with s.lock:
                busy = any(d.queue or d.writing for c in s.conns for d in c.dirs.values())
            if not busy:
                break
            time.sleep(0.005)
        with s.lock:
            handles = list(s.handles)
            s.handles.clear()
            threads = list(s.threads)
        s.stop_evt.set()
        for h in handles:
            self._close_quiet(h)
        me = threading.current_thread()
        for t in threads:
            if t is not me:
                t.join(_JOIN_TIMEOUT)
                if t.is_alive():
                    print(f"[pipe_proxy] session {s.id}: thread {t.name} did not stop")
        self._persist(s)
        print(f"[pipe_proxy] session {s.id} ended ({s.end_reason})")

    def _live(self, sid):
        with self._lock:
            return self._sessions.get(sid)

    def _meta(self, s):
        held = sum(1 for i in s.pending.values() if i.state == "held")
        return {
            "id": s.id, "pattern": s.pattern, "mode": s.mode, "how": s.how, "match": s.match,
            "squat": s.squat, "state": s.state, "target": s.target, "pipe_mode": s.pipe_mode,
            "started": s.started, "ended": s.ended_at, "max_duration": s.max_duration,
            "hold_timeout": s.hold_timeout, "connections": len(s.conns),
            "active_connections": sum(1 for c in s.conns if c.open_dirs > 0),
            "message_count": len(s.messages), "held_count": held,
            "recorded_bytes": s.recorded_bytes, "recording_truncated": s.recording_truncated,
            "end_reason": s.end_reason, "last_error": s.last_error,
            "self_connect_retries": s.self_connect_retries,
        }

    @staticmethod
    def _set_state(item, state):
        item.state = state
        item.rec["state"] = state

    def _spawn(self, s, target, args, label):
        """Start a daemon thread owned by `s`; caller holds `s.lock`."""
        s.threads = [t for t in s.threads if t.is_alive()]
        t = threading.Thread(target=target, args=args, daemon=True,
                             name=f"pipe_proxy-{s.id}-{label}")
        s.threads.append(t)
        t.start()

    def _ensure_ticker(self):
        if self.tick_interval is None:
            return
        with self._lock:
            if self._ticker is not None or self._shutdown.is_set():
                return
            self._ticker = threading.Thread(target=self._tick_loop, daemon=True,
                                            name="pipe_proxy-ticker")
            self._ticker.start()

    def _tick_loop(self):
        while not self._shutdown.wait(self.tick_interval):
            try:
                self.check_timers()
            except Exception as e:  # noqa: BLE001 - the ticker must survive
                print(f"[pipe_proxy] check_timers failed: {e}")

    def _track(self, s, h):
        with s.lock:
            if not s.ended:
                s.handles.add(h)
                return True
        self._close_quiet(h)
        return False

    def _close(self, s, h):
        self._close_quiet(h)
        with s.lock:
            s.handles.discard(h)

    def _close_quiet(self, h):
        try:
            self.backend.close(h)
        except OSError as e:
            print(f"[pipe_proxy] close failed: {e}")

    def _activate(self, s, target, mode, h):
        """Make `h` the session's listening proxy instance and start accepting.

        Unless squatting (no real server yet), an upstream connection for the
        first client is opened right here, after `h` exists: it takes the real
        server's oldest free instance, so any spare the server creates next is
        younger than `h` and the next client lands on the proxy.
        """
        with s.lock:
            ok = not s.ended
            if ok:
                s.target = canonical_name(target)
                s.pipe_mode = mode
                s.handles.add(h)
        if not ok:
            self._close_quiet(h)
            return False
        ready = None
        if not s.squat:
            ready, h = self._connect_upstream(s, h, self.connect_timeout, "first client")
        with s.lock:
            ok = not s.ended
            if ok:
                s.state = "active"
                self._spawn(s, self._accept_loop, (s, h, ready), "accept")
        if not ok:
            for x in (h, ready):
                if x is not None:
                    self._close_quiet(x)
        return ok

    def _note_error(self, s, msg):
        print(f"[pipe_proxy] session {s.id}: {msg}")
        with s.lock:
            s.last_error = msg

    def _watch(self, s, known):
        failures = {}
        while not s.ended and not s.stop_evt.wait(self.poll_interval):
            try:
                names = self.backend.list_pipes()
            except OSError as e:
                self._note_error(s, f"list_pipes failed: {e}")
                continue
            current = {}
            for n in names:
                current.setdefault(_key(n), canonical_name(n))
            known &= set(current)
            for k in list(failures):
                if k not in current:
                    del failures[k]
            taken = False
            for k in sorted(current):
                if k in known:
                    continue
                name = current[k]
                if k in BLOCKLIST or not s.matches(name):
                    known.add(k)
                    continue
                try:
                    mode = s.pipe_mode_hint or self.backend.pipe_mode(name)
                    h = self.backend.create_server(name, mode, False)
                except OSError as e:
                    failures[k] = failures.get(k, 0) + 1
                    if failures[k] >= WATCH_RETRIES:
                        known.add(k)
                    self._note_error(s, f"cannot attach to {name} "
                                        f"(try {failures[k]}/{WATCH_RETRIES}): {e}")
                    continue
                print(f"[pipe_proxy] session {s.id}: armed watcher took {name} ({mode})")
                self._activate(s, name, mode, h)
                taken = True
                break
            with s.lock:
                s.watch_polls += 1
            if taken:
                return

    def _new_instance(self, s):
        """Create and track one more listening proxy instance (None on failure)."""
        try:
            h = self.backend.create_server(s.target, s.pipe_mode, False)
        except OSError as e:
            self._note_error(s, f"create_server failed: {e}")
            s.stop_evt.wait(self.poll_interval)
            return None
        return h if self._track(s, h) else None

    def _accept_loop(self, s, h, ready):
        """Accept clients on proxy instance `h`, pairing each with an upstream.

        Windows hands a client the oldest free instance. To keep that a proxy
        instance, the next proxy instance is always created *before* the next
        upstream connection is opened: the upstream takes the server's current
        spare, and the server's next spare is younger than our instance.
        `ready` is the upstream prepared for the next client. A connection on
        `h` whose client is this process is one of our own upstream connects
        (another session on the same pipe) and is dropped.
        """
        try:
            while not s.ended:
                if h is None:
                    h = self._new_instance(s)
                    if h is None:
                        continue
                try:
                    connected = self.backend.accept(h, self.io_timeout)
                except OSError as e:
                    self._note_error(s, f"accept failed: {e}")
                    self._close(s, h)
                    h = None
                    s.stop_evt.wait(self.poll_interval)
                    continue
                if not connected:
                    continue
                if self.backend.client_pid(h) == self.own_pid:
                    # One of our own upstream connects (e.g. another session's).
                    with s.lock:
                        s.self_connect_retries += 1
                    self._close(s, h)
                    h = None
                    continue
                client, h = h, None
                upstream, ready = ready, None
                if upstream is None:
                    # No spare first: this connect must not land on ourselves.
                    upstream, _ = self._connect_upstream(
                        s, None, None if s.squat else self.connect_timeout, "client")
                    if upstream is None:
                        self._close(s, client)
                        continue
                self._start_conn(s, client, upstream)
                if h is None:
                    h = self._new_instance(s)
                if h is not None:
                    ready, h = self._connect_upstream(s, h, self.connect_timeout, "next client")
        finally:
            if ready is not None:
                self._close(s, ready)

    def _connect_upstream(self, s, spare, timeout, purpose):
        """Connect to the real server; returns (upstream or None, spare).

        `spare` is our own listening instance, if any. Windows hands the
        connect the oldest free instance; if that was `spare` (its client is
        this process), no older real instance was free: the self-connection
        and the now broken spare are closed, the server gets `settle` seconds
        to create its next instance, and a new spare - younger than that one -
        is created before the retry. Gives up after `timeout` seconds (None:
        until the session ends), or at once when a real client takes `spare`.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while not s.ended:
            try:
                up = self.backend.connect(s.target, self.io_timeout)
            except OSError as e:
                if deadline is not None and time.monotonic() >= deadline:
                    self._note_error(s, f"no upstream for {s.target} ({purpose}): {e}")
                    return None, spare
                if spare is not None and self.backend.client_pid(spare) is not None:
                    return None, spare          # a client is waiting on our spare
                if isinstance(e, FileNotFoundError):
                    s.stop_evt.wait(self.io_timeout)
                continue
            if spare is not None and self.backend.client_pid(spare) == self.own_pid:
                with s.lock:
                    s.self_connect_retries += 1
                self._close_quiet(up)
                self._close(s, spare)
                s.stop_evt.wait(self.settle)
                spare = self._new_instance(s)
                if deadline is not None and time.monotonic() >= deadline:
                    self._note_error(s, f"no upstream for {s.target} ({purpose}): "
                                        "only our own instance was free")
                    return None, spare
                continue
            return (up if self._track(s, up) else None), spare
        return None, spare

    def _start_conn(self, s, client, upstream):
        with s.lock:
            if s.ended:
                started = False
            else:
                started = True
                conn = _Conn(len(s.conns) + 1, client, upstream)
                s.conns.append(conn)
                for d in conn.dirs.values():
                    self._spawn(s, self._pump, (s, d), f"c{conn.id}-{d.name}")
        if not started:
            self._close_quiet(client)
            self._close_quiet(upstream)
        else:
            print(f"[pipe_proxy] session {s.id}: connection {conn.id} on {s.target}")

    def _pump(self, s, d):
        """Read `d.src`, record, and write decided messages to `d.dst`.

        This thread is the only writer of its direction. After EOF or session
        end it stops reading and only drains the queue.
        """
        while not s.stop_evt.is_set():
            self._flush(s, d)
            with s.lock:
                reading = not d.eof and not s.ended
                if not reading and not d.queue:
                    break
            if not reading:
                d.wake.wait(self.io_timeout)
                d.wake.clear()
                continue
            try:
                data = self.backend.read(d.src, self.io_timeout)
            except OSError as e:
                print(f"[pipe_proxy] session {s.id}: read {d.name} failed: {e}")
                data = None
            if data is None:
                with s.lock:
                    d.eof = True
            elif data:
                self._record(s, d, data)
        with s.lock:
            d.conn.open_dirs -= 1
            eof = d.eof
        if eof:
            # The source went away: propagate the close to the other side.
            self._close(s, d.src)
            self._close(s, d.dst)

    def _record(self, s, d, data):
        now = self.clock()
        with s.lock:
            if s.ended:
                return
            seq = s.next_seq
            s.next_seq += 1
            logged = data[:self.max_message_log]
            if not s.recording_truncated and \
                    s.recorded_bytes + len(logged) > self.max_session_record:
                s.recording_truncated = True
                print(f"[pipe_proxy] session {s.id}: recording limit reached, relaying only")
            if s.recording_truncated:
                logged = b""
            s.recorded_bytes += len(logged)
            state = "held" if s.mode == "hold" else "passed"
            rec = {"seq": seq, "conn": d.conn.id, "dir": d.name, "ts": now, "size": len(data),
                   "data_b64": base64.b64encode(logged).decode("ascii"), "state": state,
                   "truncated": len(logged) < len(data)}
            s.messages.append(rec)
            item = _Item(seq, data, state, now, rec, d)
            d.queue.append(item)
            s.pending[seq] = item

    def _flush(self, s, d):
        """Write every decided message at the head of `d`'s queue, in order.

        Only called from `d`'s pump thread, so writes need no lock.
        """
        while True:
            with s.lock:
                if not d.queue or d.queue[0].state == "held":
                    return
                item = d.queue.popleft()
                s.pending.pop(item.seq, None)
                if item.state == "dropped":
                    continue
                d.writing = True
            try:
                self.backend.write(d.dst, item.data)
            except OSError as e:
                print(f"[pipe_proxy] session {s.id}: write {d.name} #{item.seq} failed: {e}")
            finally:
                with s.lock:
                    d.writing = False

    def _persist(self, s):
        with s.lock:
            doc = {"session": self._meta(s), "messages": [dict(r) for r in s.messages]}
        path = os.path.join(self.store_dir, f"{s.id}.json")
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            os.replace(tmp, path)
        except OSError as e:
            print(f"[pipe_proxy] cannot write {path}: {e}")
            return
        with self._lock:
            self._persisted[s.id] = {"session": doc["session"], "path": path}
            # Served from the file from now on; frees the in-memory recording.
            self._sessions.pop(s.id, None)

    def _load_persisted(self):
        for fn in sorted(os.listdir(self.store_dir)):
            if not _SID_FILE_RE.match(fn):
                continue
            path = os.path.join(self.store_dir, fn)
            try:
                with open(path, encoding="utf-8") as f:
                    meta = json.load(f)["session"]
            except (OSError, ValueError, KeyError, TypeError) as e:
                print(f"[pipe_proxy] skipping {path}: {e}")
                continue
            if not isinstance(meta, dict):
                continue
            meta = dict(meta, id=fn[:-5], state="ended", held_count=0, active_connections=0)
            self._persisted[meta["id"]] = {"session": meta, "path": path}
