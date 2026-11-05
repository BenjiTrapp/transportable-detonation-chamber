"""Named pipe backends for the interception engine (`pipe_proxy`).

`PipeBackend` is the small protocol the engine needs. `FakePipeBackend` is an
in-memory model used by the tests and for development on macOS/Linux;
`Win32PipeBackend` talks to kernel32 through ctypes and only works on Windows.

Handles are opaque objects. `read` returns bytes, `b""` on timeout and `None`
once the handle or its peer is closed. `close` is idempotent and wakes up
threads blocked in `read`/`accept` on the same handle.
"""

import ctypes
import os
import threading
import time
from collections import deque

from pipe_analysis import canonical_name

MODES = ("byte", "message")


def _key(name):
    return canonical_name(name).lower()


class PipeBackend:
    """Protocol of the operations the engine performs on named pipes."""

    def list_pipes(self):
        raise NotImplementedError

    def exists(self, name):
        raise NotImplementedError

    def pipe_mode(self, name):
        raise NotImplementedError

    def create_server(self, name, mode, first_instance):
        raise NotImplementedError

    def accept(self, h, timeout):
        raise NotImplementedError

    def connect(self, name, timeout):
        raise NotImplementedError

    def client_pid(self, h):
        """Process id of the client connected to server instance `h` (None if none)."""
        raise NotImplementedError

    def read(self, h, timeout):
        raise NotImplementedError

    def write(self, h, data):
        raise NotImplementedError

    def close(self, h):
        raise NotImplementedError


# --------------------------------------------------------------------------
# In-memory fake
# --------------------------------------------------------------------------

FAKE_CLIENT_PID = 4             # process id of fake_client connections


class _FakeInstance:
    def __init__(self, name, mode, kind):
        self.name = canonical_name(name)
        self.mode = mode
        self.kind = kind            # "proxy" (create_server) or "real" (fake_server)
        self.client_pid = None
        self.connected = False
        self.closed = {"server": False, "client": False}
        self.inbox = {"server": deque(), "client": deque()}


class _FakeHandle:
    def __init__(self, inst, side):
        self.inst = inst
        self.side = side

    @property
    def peer(self):
        return "client" if self.side == "server" else "server"


class FakeEndpoint:
    """Test-side end of a fake pipe: the real server or a real client."""

    def __init__(self, backend, handle):
        self._b = backend
        self.handle = handle

    @property
    def connected(self):
        return self.handle.inst.connected

    @property
    def closed(self):
        return self._b._is_closed(self.handle)

    def wait_connected(self, timeout=1.0):
        return self._b.accept(self.handle, timeout)

    def send(self, data):
        if self.handle.side == "server":
            self.wait_connected()
        self._b.write(self.handle, data)

    def recv(self, timeout=1.0):
        return self._b.read(self.handle, timeout)

    def close(self):
        self._b.close(self.handle)


class FakePipeBackend(PipeBackend):
    """In-memory named pipes.

    Routing model (as observed on Windows): every client, `fake_client` and
    the engine's `connect` alike, gets the oldest free instance, whoever owns
    it. The engine's `connect` counts as process `own_pid` (default: this
    process), `fake_client` as `FAKE_CLIENT_PID`; `client_pid` reports it per
    instance. A pipe exists while at least one server end is open.
    """

    def __init__(self, own_pid=None):
        self.own_pid = os.getpid() if own_pid is None else own_pid
        self._cv = threading.Condition()
        self._instances = []
        self.created = []           # (canonical name, mode, first_instance) per create_server
        self.connect_attempts = 0   # backend.connect calls (the engine's upstream side)
        self._blocked = set()       # pipe keys whose writes block (simulates a stalled reader)

    def block_writes(self, name, blocked=True):
        """While blocked, writes into the real server of `name` (the proxy's
        upstream) wait until unblocked or closed – a server that stopped reading."""
        with self._cv:
            if blocked:
                self._blocked.add(_key(name))
            else:
                self._blocked.discard(_key(name))
            self._cv.notify_all()

    # -- test helpers --

    def fake_server(self, name, mode="byte"):
        if mode not in MODES:
            raise ValueError(f"bad mode {mode!r}")
        with self._cv:
            inst = _FakeInstance(name, mode, "real")
            self._instances.append(inst)
            self._cv.notify_all()
        return FakeEndpoint(self, _FakeHandle(inst, "server"))

    def fake_client(self, name, timeout=1.0):
        return FakeEndpoint(self, self._connect(name, timeout, FAKE_CLIENT_PID))

    # -- protocol --

    def _open(self, name):
        k = _key(name)
        return [i for i in self._instances if i.name.lower() == k and not i.closed["server"]]

    def list_pipes(self):
        with self._cv:
            seen = {}
            for i in self._instances:
                if not i.closed["server"]:
                    seen.setdefault(i.name.lower(), i.name)
            return sorted(seen.values())

    def exists(self, name):
        with self._cv:
            return bool(self._open(name))

    def pipe_mode(self, name):
        with self._cv:
            insts = self._open(name)
            if not insts:
                raise FileNotFoundError(f"pipe {canonical_name(name)} not found")
            return insts[0].mode

    def create_server(self, name, mode, first_instance):
        if mode not in MODES:
            raise ValueError(f"bad mode {mode!r}")
        with self._cv:
            if first_instance and self._open(name):
                raise PermissionError(f"pipe {canonical_name(name)} already exists")
            inst = _FakeInstance(name, mode, "proxy")
            self._instances.append(inst)
            self.created.append((inst.name, mode, bool(first_instance)))
            self._cv.notify_all()
            return _FakeHandle(inst, "server")

    def accept(self, h, timeout):
        deadline = time.monotonic() + timeout
        with self._cv:
            while True:
                if h.inst.closed["server"]:
                    return False
                if h.inst.connected:
                    return True
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._cv.wait(left)

    def _connect(self, name, timeout, pid):
        deadline = time.monotonic() + timeout
        with self._cv:
            while True:
                insts = self._open(name)
                if not insts:
                    raise FileNotFoundError(f"pipe {canonical_name(name)} not found")
                free = [i for i in insts if not i.connected]
                if free:
                    inst = free[0]          # oldest free instance
                    inst.connected = True
                    inst.client_pid = pid
                    self._cv.notify_all()
                    return _FakeHandle(inst, "client")
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"all instances of {canonical_name(name)} are busy")
                self._cv.wait(left)

    def connect(self, name, timeout):
        with self._cv:
            self.connect_attempts += 1
        return self._connect(name, timeout, self.own_pid)

    def client_pid(self, h):
        with self._cv:
            return h.inst.client_pid if h.inst.connected else None

    def _is_closed(self, h):
        with self._cv:
            return h.inst.closed[h.side]

    def read(self, h, timeout):
        deadline = time.monotonic() + timeout
        with self._cv:
            while True:
                inst = h.inst
                if inst.closed[h.side]:
                    return None
                box = inst.inbox[h.side]
                if box:
                    if inst.mode == "message":
                        return box.popleft()
                    data = b"".join(box)
                    box.clear()
                    return data
                if inst.connected and inst.closed[h.peer]:
                    return None
                left = deadline - time.monotonic()
                if left <= 0:
                    return b""
                self._cv.wait(left)

    def write(self, h, data):
        with self._cv:
            inst = h.inst
            while inst.kind == "real" and h.side == "client" \
                    and inst.name.lower() in self._blocked and not inst.closed[h.side] \
                    and not inst.closed[h.peer]:
                self._cv.wait()
            if inst.closed[h.side] or inst.closed[h.peer] or not inst.connected:
                raise BrokenPipeError("pipe is not connected")
            inst.inbox[h.peer].append(bytes(data))
            self._cv.notify_all()

    def close(self, h):
        with self._cv:
            h.inst.closed[h.side] = True
            if h.side == "server" and not h.inst.connected:
                h.inst.closed["client"] = True
            self._cv.notify_all()


# --------------------------------------------------------------------------
# Win32 (ctypes)
# --------------------------------------------------------------------------

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000
# Client opens: overlapped, and the server may only *identify* us, never
# impersonate (the server is the sample; the web UI may run as SYSTEM).
CLIENT_OPEN_FLAGS = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
PIPE_TYPE_BYTE = 0x0
PIPE_TYPE_MESSAGE = 0x4
PIPE_READMODE_BYTE = 0x0
PIPE_READMODE_MESSAGE = 0x2
PIPE_WAIT = 0x0
PIPE_UNLIMITED_INSTANCES = 255
BUFFER_SIZE = 64 * 1024
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_HANDLE = 6
ERROR_NO_MORE_FILES = 18
ERROR_BROKEN_PIPE = 109
ERROR_SEM_TIMEOUT = 121
ERROR_PIPE_BUSY = 231
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_MORE_DATA = 234
ERROR_PIPE_CONNECTED = 535
ERROR_OPERATION_ABORTED = 995
ERROR_IO_INCOMPLETE = 996
ERROR_IO_PENDING = 997
_CLOSED_ERRORS = (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED,
                  ERROR_OPERATION_ABORTED, ERROR_INVALID_HANDLE)
WRITE_TIMEOUT = 30.0
CLOSE_POLL = 0.05               # how often a pending I/O checks for close()
BUSY_BACKOFF = 0.02
_INVALID_HANDLE = ctypes.c_void_p(-1).value

try:
    import ctypes.wintypes as wt
except (ImportError, ValueError):  # pragma: no cover - very old non-Windows builds
    wt = None

if wt is not None:
    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD), ("hEvent", wt.HANDLE)]

_k32 = None
if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _LPOV = ctypes.POINTER(_OVERLAPPED)
    _LPDW = ctypes.POINTER(wt.DWORD)
    for _name, _res, _args in (
        ("CreateNamedPipeW", wt.HANDLE, [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
                                         wt.DWORD, wt.DWORD, ctypes.c_void_p]),
        ("ConnectNamedPipe", wt.BOOL, [wt.HANDLE, _LPOV]),
        ("CreateFileW", wt.HANDLE, [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                    wt.DWORD, wt.DWORD, wt.HANDLE]),
        ("WaitNamedPipeW", wt.BOOL, [wt.LPCWSTR, wt.DWORD]),
        ("SetNamedPipeHandleState", wt.BOOL, [wt.HANDLE, _LPDW, _LPDW, _LPDW]),
        ("GetNamedPipeInfo", wt.BOOL, [wt.HANDLE, _LPDW, _LPDW, _LPDW, _LPDW]),
        ("GetNamedPipeHandleStateW", wt.BOOL, [wt.HANDLE, _LPDW, _LPDW, _LPDW, _LPDW,
                                               ctypes.c_void_p, wt.DWORD]),
        ("GetNamedPipeClientProcessId", wt.BOOL, [wt.HANDLE, ctypes.POINTER(wt.ULONG)]),
        ("ReadFile", wt.BOOL, [wt.HANDLE, ctypes.c_void_p, wt.DWORD, _LPDW, _LPOV]),
        ("WriteFile", wt.BOOL, [wt.HANDLE, ctypes.c_void_p, wt.DWORD, _LPDW, _LPOV]),
        ("GetOverlappedResult", wt.BOOL, [wt.HANDLE, _LPOV, _LPDW, wt.BOOL]),
        ("CancelIoEx", wt.BOOL, [wt.HANDLE, _LPOV]),
        ("CreateEventW", wt.HANDLE, [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]),
        ("WaitForSingleObject", wt.DWORD, [wt.HANDLE, wt.DWORD]),
        ("CloseHandle", wt.BOOL, [wt.HANDLE]),
        ("FindFirstFileW", wt.HANDLE, [wt.LPCWSTR, ctypes.POINTER(wt.WIN32_FIND_DATAW)]),
        ("FindNextFileW", wt.BOOL, [wt.HANDLE, ctypes.POINTER(wt.WIN32_FIND_DATAW)]),
        ("FindClose", wt.BOOL, [wt.HANDLE]),
    ):
        _fn = getattr(_k32, _name)
        _fn.restype = _res
        _fn.argtypes = _args


def _winerr(code, what):
    fmt = getattr(ctypes, "FormatError", None)
    text = fmt(code).strip() if fmt else f"error {code}"
    return OSError(None, f"{what} failed: {text}", None, code)


def _path(name):
    return "\\\\.\\pipe" + canonical_name(name)


class _WinHandle:
    """A kernel handle shared between threads.

    I/O runs between `acquire()` and `release()`. `close()` marks the handle
    closed and cancels pending I/O at once, but the real CloseHandle only runs
    when the last in-flight user releases it, so a racing ReadFile/WriteFile
    can never hit a recycled handle value.
    """

    def __init__(self, value, mode, cancel=None, closer=None):
        self.value = value
        self.mode = mode
        self.closed = False
        self.freed = False
        self.refs = 0
        self.lock = threading.Lock()
        self._cancel = cancel or (lambda v: _k32.CancelIoEx(v, None))
        self._closer = closer or (lambda v: _k32.CloseHandle(v))

    def acquire(self):
        with self.lock:
            if self.closed:
                return False
            self.refs += 1
            return True

    def release(self):
        with self.lock:
            self.refs -= 1
            free = self.closed and self.refs == 0 and not self.freed
            if free:
                self.freed = True
        if free:
            self._closer(self.value)

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            free = self.refs == 0
            if free:
                self.freed = True
            else:
                self._cancel(self.value)    # value still valid: not freed yet
        if free:
            self._closer(self.value)


class Win32PipeBackend(PipeBackend):
    """Named pipes via kernel32 (overlapped I/O so every wait has a timeout)."""

    def __init__(self):
        if _k32 is None:
            raise RuntimeError("Win32PipeBackend needs Windows (kernel32); use FakePipeBackend")

    def list_pipes(self):
        data = wt.WIN32_FIND_DATAW()
        h = _k32.FindFirstFileW("\\\\.\\pipe\\*", ctypes.byref(data))
        if h is None or h == _INVALID_HANDLE:
            err = ctypes.get_last_error()
            if err in (ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES):
                return []
            raise _winerr(err, "FindFirstFileW")
        names = []
        try:
            while True:
                if data.cFileName:
                    names.append("\\" + data.cFileName)
                if not _k32.FindNextFileW(h, ctypes.byref(data)):
                    break
        finally:
            _k32.FindClose(h)
        return names

    def exists(self, name):
        k = _key(name)
        return any(n.lower() == k for n in self.list_pipes())

    def pipe_mode(self, name):
        # A new instance always takes the pipe type of the pipe's first
        # instance, whatever type it asks for (checked on Windows 11 ARM64,
        # build 26200). So the real server's mode is read from a throw-away
        # instance of our own; unlike a client probe this never occupies one
        # of the server's instances (single-instance servers such as SMB
        # beacons would lose their only one).
        h = self.create_server(name, "byte", False)
        try:
            count = wt.DWORD(0)
            if _k32.GetNamedPipeHandleStateW(h.value, None, ctypes.byref(count), None, None,
                                             None, 0) and count.value <= 1:
                # Ours is the only instance: the server's pipe vanished and we
                # just created a new pipe instead of probing it.
                raise FileNotFoundError(f"pipe {canonical_name(name)} not found")
            flags = wt.DWORD(0)
            if not _k32.GetNamedPipeInfo(h.value, ctypes.byref(flags), None, None, None):
                raise _winerr(ctypes.get_last_error(), "GetNamedPipeInfo")
            return "message" if flags.value & PIPE_TYPE_MESSAGE else "byte"
        finally:
            self.close(h)

    def create_server(self, name, mode, first_instance):
        open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
        if first_instance:
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE
        if mode == "message":
            pmode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
        else:
            pmode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
        h = _k32.CreateNamedPipeW(_path(name), open_mode, pmode, PIPE_UNLIMITED_INSTANCES,
                                  BUFFER_SIZE, BUFFER_SIZE, 0, None)
        if h is None or h == _INVALID_HANDLE:
            raise _winerr(ctypes.get_last_error(), "CreateNamedPipeW")
        return _WinHandle(h, mode)

    def _overlapped(self, h, start, timeout):
        """Run one overlapped call on handle `h`; returns (ok, transferred, error).

        `start(ov)` issues the call. On timeout or `h.close()` the I/O is
        cancelled and waited for, so the kernel never touches `ov` or the
        buffer after we return. The caller holds a reference on the handle, so
        `h.value` stays valid. The wait runs in short slices because a close()
        that lands before the call is issued cannot cancel it.
        """
        if h.closed:
            return False, 0, ERROR_OPERATION_ABORTED
        hv = h.value
        ev = _k32.CreateEventW(None, True, False, None)
        if not ev:
            raise _winerr(ctypes.get_last_error(), "CreateEventW")
        ov = _OVERLAPPED()
        ov.hEvent = ev
        n = wt.DWORD(0)
        try:
            if start(ov):
                _k32.GetOverlappedResult(hv, ctypes.byref(ov), ctypes.byref(n), False)
                return True, n.value, 0
            err = ctypes.get_last_error()
            if err == ERROR_MORE_DATA:
                _k32.GetOverlappedResult(hv, ctypes.byref(ov), ctypes.byref(n), False)
                return False, n.value, err
            if err != ERROR_IO_PENDING:
                return False, 0, err
            deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
            while True:
                if h.closed:
                    break
                left = CLOSE_POLL if deadline is None else \
                    min(CLOSE_POLL, max(0.0, deadline - time.monotonic()))
                if _k32.WaitForSingleObject(ev, int(left * 1000)) != WAIT_TIMEOUT:
                    ok = _k32.GetOverlappedResult(hv, ctypes.byref(ov), ctypes.byref(n), False)
                    return bool(ok), n.value, (0 if ok else ctypes.get_last_error())
                if deadline is not None and time.monotonic() >= deadline:
                    break
            _k32.CancelIoEx(hv, ctypes.byref(ov))
            ok = _k32.GetOverlappedResult(hv, ctypes.byref(ov), ctypes.byref(n), True)
            if ok:
                return True, n.value, 0
            err = ctypes.get_last_error()
            if err == ERROR_OPERATION_ABORTED and not h.closed:
                err = WAIT_TIMEOUT
            return False, n.value, err
        finally:
            _k32.CloseHandle(ev)

    def accept(self, h, timeout):
        if not h.acquire():
            return False
        try:
            ok, _, err = self._overlapped(
                h, lambda ov: _k32.ConnectNamedPipe(h.value, ctypes.byref(ov)), timeout)
        finally:
            h.release()
        if ok or err == ERROR_PIPE_CONNECTED or err == ERROR_NO_DATA:
            # ERROR_NO_DATA: client connected and already left; reads will report it.
            return not h.closed
        if err == WAIT_TIMEOUT or err in _CLOSED_ERRORS or h.closed:
            return False
        raise _winerr(err, "ConnectNamedPipe")

    def connect(self, name, timeout):
        path = _path(name)
        deadline = time.monotonic() + timeout
        while True:
            h = _k32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
                                 CLIENT_OPEN_FLAGS, None)
            if h is not None and h != _INVALID_HANDLE:
                break
            err = ctypes.get_last_error()
            if err == ERROR_FILE_NOT_FOUND:
                raise FileNotFoundError(f"pipe {canonical_name(name)} not found")
            if err != ERROR_PIPE_BUSY:
                raise _winerr(err, "CreateFileW")
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"all instances of {canonical_name(name)} are busy")
            _k32.WaitNamedPipeW(path, max(1, int(left * 1000)))
            # WaitNamedPipeW can return at once (pipe gone, instance taken by
            # another client); never spin.
            time.sleep(min(BUSY_BACKOFF, max(0.0, deadline - time.monotonic())))
        flags = wt.DWORD(0)
        mode = "byte"
        if _k32.GetNamedPipeInfo(h, ctypes.byref(flags), None, None, None) \
                and flags.value & PIPE_TYPE_MESSAGE:
            mode = "message"
            rm = wt.DWORD(PIPE_READMODE_MESSAGE)
            if not _k32.SetNamedPipeHandleState(h, ctypes.byref(rm), None, None):
                err = ctypes.get_last_error()
                _k32.CloseHandle(h)
                raise _winerr(err, "SetNamedPipeHandleState")
        return _WinHandle(h, mode)

    def client_pid(self, h):
        # Per instance. (GetNamedPipeServerProcessId is not: it reports the
        # creator of the pipe's first instance for every instance.)
        if not h.acquire():
            return None
        try:
            pid = wt.ULONG(0)
            if not _k32.GetNamedPipeClientProcessId(h.value, ctypes.byref(pid)):
                return None
            return pid.value or None
        finally:
            h.release()

    def read(self, h, timeout):
        if not h.acquire():
            return None
        try:
            return self._read(h, timeout)
        finally:
            h.release()

    def _read(self, h, timeout):
        chunks = []
        wait = timeout
        while True:
            buf = ctypes.create_string_buffer(BUFFER_SIZE)
            ok, n, err = self._overlapped(
                h,
                lambda ov: _k32.ReadFile(h.value, buf, BUFFER_SIZE, None, ctypes.byref(ov)),
                wait)
            if ok:
                chunks.append(buf.raw[:n])
                return b"".join(chunks)
            if err == ERROR_MORE_DATA:
                # Message mode: the rest of this message is already buffered.
                chunks.append(buf.raw[:n])
                wait = WRITE_TIMEOUT
                continue
            if err in _CLOSED_ERRORS or h.closed:
                return None
            if err == WAIT_TIMEOUT:
                if not chunks:
                    return b""
                raise OSError(None, f"ReadFile: rest of a {sum(map(len, chunks))}-byte "
                                    "partial message did not arrive")
            raise _winerr(err, "ReadFile")

    def write(self, h, data):
        if not h.acquire():
            raise BrokenPipeError("pipe handle is closed")
        try:
            self._write(h, bytes(data))
        finally:
            h.release()

    def _write(self, h, data):
        view = memoryview(data)
        while view:
            buf = ctypes.create_string_buffer(view.tobytes(), len(view))
            size = len(view)
            ok, n, err = self._overlapped(
                h,
                lambda ov: _k32.WriteFile(h.value, buf, size, None, ctypes.byref(ov)),
                WRITE_TIMEOUT)
            if not ok:
                if err in _CLOSED_ERRORS or h.closed:
                    raise BrokenPipeError("pipe is not connected")
                if err == WAIT_TIMEOUT:
                    raise TimeoutError("WriteFile timed out")
                raise _winerr(err, "WriteFile")
            if h.mode == "message":
                if n != size:
                    raise OSError(None, f"WriteFile wrote {n} of {size} message bytes")
                return
            if n <= 0:
                raise OSError(None, "WriteFile made no progress")
            view = view[n:]

    def close(self, h):
        h.close()
