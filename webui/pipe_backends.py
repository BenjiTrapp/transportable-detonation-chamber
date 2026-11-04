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

    def read(self, h, timeout):
        raise NotImplementedError

    def write(self, h, data):
        raise NotImplementedError

    def close(self, h):
        raise NotImplementedError


# --------------------------------------------------------------------------
# In-memory fake
# --------------------------------------------------------------------------

class _FakeInstance:
    def __init__(self, name, mode, kind):
        self.name = canonical_name(name)
        self.mode = mode
        self.kind = kind            # "proxy" (create_server) or "real" (fake_server)
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

    Routing model: a real client (`fake_client`) prefers free proxy instances,
    i.e. the proxy wins the race; the engine's upstream `connect` prefers free
    real-server instances. Within a kind the newest free instance is taken. A
    pipe exists while at least one server end is open.
    """

    def __init__(self):
        self._cv = threading.Condition()
        self._instances = []
        self.created = []           # (canonical name, mode, first_instance) per create_server

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
        return FakeEndpoint(self, self._connect(name, "proxy", timeout))

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

    def _connect(self, name, prefer, timeout):
        deadline = time.monotonic() + timeout
        with self._cv:
            while True:
                insts = self._open(name)
                if not insts:
                    raise FileNotFoundError(f"pipe {canonical_name(name)} not found")
                free = [i for i in insts if not i.connected]
                if free:
                    free.sort(key=lambda i: i.kind == prefer)
                    inst = free[-1]
                    inst.connected = True
                    self._cv.notify_all()
                    return _FakeHandle(inst, "client")
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"all instances of {canonical_name(name)} are busy")
                self._cv.wait(left)

    def connect(self, name, timeout):
        return self._connect(name, "real", timeout)

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
ERROR_IO_PENDING = 997
_CLOSED_ERRORS = (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED,
                  ERROR_OPERATION_ABORTED, ERROR_INVALID_HANDLE)
WRITE_TIMEOUT = 30.0

_k32 = None
if os.name == "nt":
    import ctypes.wintypes as wt

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE = ctypes.c_void_p(-1).value

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD), ("hEvent", wt.HANDLE)]

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
    return OSError(None, f"{what} failed: {ctypes.FormatError(code).strip()}", None, code)


def _path(name):
    return "\\\\.\\pipe" + canonical_name(name)


class _WinHandle:
    def __init__(self, value, mode):
        self.value = value
        self.mode = mode
        self.closed = False
        self.lock = threading.Lock()


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
        # GetNamedPipeInfo needs a handle, so this briefly connects as a client.
        h = self.connect(name, 1.0)
        try:
            return h.mode
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

    def _overlapped(self, hobj, start, timeout):
        """Run one overlapped call; returns (ok, transferred, error code).

        `start(ov)` issues the call. On timeout the I/O is cancelled and waited
        for, so the kernel never touches `ov` or the buffer after we return.
        """
        ev = _k32.CreateEventW(None, True, False, None)
        if not ev:
            raise _winerr(ctypes.get_last_error(), "CreateEventW")
        ov = _OVERLAPPED()
        ov.hEvent = ev
        n = wt.DWORD(0)
        try:
            if start(ov):
                _k32.GetOverlappedResult(hobj.value, ctypes.byref(ov), ctypes.byref(n), False)
                return True, n.value, 0
            err = ctypes.get_last_error()
            if err == ERROR_MORE_DATA:
                _k32.GetOverlappedResult(hobj.value, ctypes.byref(ov), ctypes.byref(n), False)
                return False, n.value, err
            if err != ERROR_IO_PENDING:
                return False, 0, err
            ms = INFINITE if timeout is None else max(0, int(timeout * 1000))
            if _k32.WaitForSingleObject(ev, ms) == WAIT_TIMEOUT:
                _k32.CancelIoEx(hobj.value, ctypes.byref(ov))
                ok = _k32.GetOverlappedResult(hobj.value, ctypes.byref(ov), ctypes.byref(n), True)
                if ok:
                    return True, n.value, 0
                err = ctypes.get_last_error()
                return False, n.value, (WAIT_TIMEOUT if err == ERROR_OPERATION_ABORTED else err)
            ok = _k32.GetOverlappedResult(hobj.value, ctypes.byref(ov), ctypes.byref(n), False)
            return bool(ok), n.value, (0 if ok else ctypes.get_last_error())
        finally:
            _k32.CloseHandle(ev)

    def accept(self, h, timeout):
        if h.closed:
            return False
        ok, _, err = self._overlapped(
            h, lambda ov: _k32.ConnectNamedPipe(h.value, ctypes.byref(ov)), timeout)
        if ok or err == ERROR_PIPE_CONNECTED or err == ERROR_NO_DATA:
            # ERROR_NO_DATA: client connected and already left; reads will report it.
            return not h.closed
        if err == WAIT_TIMEOUT or err in _CLOSED_ERRORS:
            return False
        raise _winerr(err, "ConnectNamedPipe")

    def connect(self, name, timeout):
        path = _path(name)
        deadline = time.monotonic() + timeout
        while True:
            h = _k32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
                                 FILE_FLAG_OVERLAPPED, None)
            if h is not None and h != _INVALID_HANDLE:
                break
            err = ctypes.get_last_error()
            if err == ERROR_FILE_NOT_FOUND:
                raise FileNotFoundError(f"pipe {canonical_name(name)} not found")
            left = deadline - time.monotonic()
            if err != ERROR_PIPE_BUSY:
                raise _winerr(err, "CreateFileW")
            if left <= 0:
                raise TimeoutError(f"all instances of {canonical_name(name)} are busy")
            _k32.WaitNamedPipeW(path, max(1, int(left * 1000)))
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

    def read(self, h, timeout):
        if h.closed:
            return None
        chunks = []
        wait = timeout
        while True:
            buf = ctypes.create_string_buffer(BUFFER_SIZE)
            ok, n, err = self._overlapped(
                h, lambda ov: _k32.ReadFile(h.value, buf, BUFFER_SIZE, None, ctypes.byref(ov)),
                wait)
            if ok:
                chunks.append(buf.raw[:n])
                return b"".join(chunks)
            if err == ERROR_MORE_DATA:
                # Message mode: the rest of this message is already buffered.
                chunks.append(buf.raw[:n])
                wait = WRITE_TIMEOUT
                continue
            if err == WAIT_TIMEOUT and not chunks:
                return b""
            if err in _CLOSED_ERRORS or h.closed:
                return None
            raise _winerr(err, "ReadFile")

    def write(self, h, data):
        if h.closed:
            raise BrokenPipeError("pipe handle is closed")
        data = bytes(data)
        view = memoryview(data)
        while view:
            buf = ctypes.create_string_buffer(view.tobytes(), len(view))
            ok, n, err = self._overlapped(
                h, lambda ov: _k32.WriteFile(h.value, buf, len(view), None, ctypes.byref(ov)),
                WRITE_TIMEOUT)
            if not ok:
                if err == WAIT_TIMEOUT:
                    raise TimeoutError("WriteFile timed out")
                if err in _CLOSED_ERRORS or h.closed:
                    raise BrokenPipeError("pipe is not connected")
                raise _winerr(err, "WriteFile")
            if h.mode == "message" or n <= 0:
                return
            view = view[n:]

    def close(self, h):
        with h.lock:
            if h.closed:
                return
            h.closed = True
            _k32.CancelIoEx(h.value, None)
            _k32.CloseHandle(h.value)
