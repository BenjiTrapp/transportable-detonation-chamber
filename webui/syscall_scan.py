"""Syscall scan: the live stubs of a process measured against the NTSleuth baseline.

Everything that decides lives above `ProcessReader`; `Win32Reader` only fetches, so the
whole measurement runs in tests against a fake process. The target is only ever read.
"""

from __future__ import annotations

import ctypes
import functools
import ntpath
import os
from typing import NamedTuple

from syscall_baseline import (READ_LEN, STATE_DIVERGED, STATE_HOOKED, STATE_INTACT,
                              STATE_PATCHED, STATE_UNREADABLE, OWNER_PRIVATE, Baseline,
                              Syscall, classify_stub, jump_pointer, jump_target)

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# the width of the pointer an indirect hook reads its target from
_POINTER_LEN = {"arm64": 8, "x64": 8, "x86": 4}

_STATES = (STATE_INTACT, STATE_HOOKED, STATE_PATCHED, STATE_DIVERGED, STATE_UNREADABLE)


class Region(NamedTuple):
    """What VirtualQueryEx and GetMappedFileNameW say about the region around an address."""
    state: int
    type: int
    path: str | None


def owner_from_region(region: Region | None) -> str | None:
    """The owner `classify_stub` expects: a lower-case basename, "private", or None.

    GetMappedFileNameW names a device path; passed on as is, a jump back into
    `\\Device\\...\\ntdll.dll` would not compare equal to `ntdll.dll` and read as hooked."""
    if region is None or region.state != MEM_COMMIT:
        return None
    if region.type == MEM_PRIVATE:
        return OWNER_PRIVATE
    if region.type == MEM_IMAGE and region.path:
        return ntpath.basename(region.path).lower() or None
    return None


class ProcessReader:
    """What `measure` needs from a process. Read-only: nothing here writes to it."""

    def view(self) -> str | None:
        """The baseline view of the process (`arm64`, `x64`), None if unknown."""
        raise NotImplementedError

    def build(self) -> str | None:
        """The OS build the process runs on, as baselines are named."""
        raise NotImplementedError

    def modules(self) -> list[dict] | None:
        """Loaded modules, each with `name`, `base`, `size`, `path`; None if the list
        cannot be had at all, which is not the same as a module missing from it."""
        raise NotImplementedError

    def read(self, addr: int, size: int) -> bytes | None:
        """Exactly `size` bytes at `addr`, or None."""
        raise NotImplementedError

    def region(self, addr: int) -> Region | None:
        """The memory region around `addr`, None if the query fails."""
        raise NotImplementedError

    def owner_of(self, addr: int) -> str | None:
        """Who holds `addr`, normalised here so that no reader can get the form wrong."""
        return owner_from_region(self.region(addr))


# Stubs lie a few dozen bytes apart; reading a page of the image between two of them is
# cheaper than another ReadProcessMemory. The cap bounds what one call allocates.
_SPAN_GAP = 0x1000
_SPAN_MAX = 0x10000


def read_spans(reader: ProcessReader, items, prefix_of) -> dict[str, bytes | None]:
    """Bytes for each `(key, address)` of `items`, `prefix_of(key)` of them, read in as
    few calls as adjacency allows. A failed span is retried item by item, so that one
    unreadable page does not take its neighbours with it."""
    spans: list[list[tuple[str, int, int]]] = []
    for key, addr in sorted(items, key=lambda item: item[1]):
        size = prefix_of(key)
        if spans:
            start = spans[-1][0][1]
            end = max(a + n for _, a, n in spans[-1])
            if addr - end <= _SPAN_GAP and max(end, addr + size) - start <= _SPAN_MAX:
                spans[-1].append((key, addr, size))
                continue
        spans.append([(key, addr, size)])
    out: dict[str, bytes | None] = {}
    for span in spans:
        start = span[0][1]
        length = max(a + n for _, a, n in span) - start
        data = _read_exact(reader, start, length) if len(span) > 1 else None
        for key, addr, size in span:
            if data is not None:
                out[key] = data[addr - start:addr - start + size]
            else:
                out[key] = _read_exact(reader, addr, size)
    return out


def _read_exact(reader: ProcessReader, addr: int, size: int) -> bytes | None:
    data = reader.read(addr, size)
    return data if data is not None and len(data) == size else None


class ScanRefused(Exception):
    """The scan would measure against the wrong reference; nothing was read."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _target_owner(reader: ProcessReader, live: bytes, addr: int,
                  view: str) -> tuple[str | None, bool]:
    """`(owner, failed)`. `failed` when there is a jump but its owner could not be
    looked up: an unreadable pointer or a region query that failed. Changed bytes with
    no jump have no target to ask about, which is no failure."""
    target = jump_target(live, addr, view)
    if target is None:
        pointer = jump_pointer(live, addr, view)
        if pointer is None:
            return None, False
        size = _POINTER_LEN[view]
        word = _read_exact(reader, pointer, size)
        if word is None:
            return None, True
        target = int.from_bytes(word, "little")
    region = reader.region(target)
    return owner_from_region(region), region is None


def _state(reader: ProcessReader, sc: Syscall, live: bytes | None, addr: int,
           view: str) -> tuple[dict, bool]:
    # the owner lookup costs a region query; an intact or unreadable stub needs none
    out, failed = classify_stub(sc, live, view, None), False
    if out["state"] not in (STATE_INTACT, STATE_UNREADABLE):
        owner, failed = _target_owner(reader, live, addr, view)
        out = classify_stub(sc, live, view, owner)
    out.update(name=sc.name, module=sc.module, number=sc.number, rva=sc.rva)
    return out, failed


def _module_bases(reader: ProcessReader, wanted: tuple[str, ...]):
    """`{module: base}` for each wanted module loaded exactly once, and notes on the rest.

    A name loaded twice (a WOW64 process holds two ntdll) is not guessed at: the wrong
    copy would make every stub look changed."""
    listed = reader.modules()
    if listed is None:
        return {}, ["the modules of the process could not be listed, nothing measured"]
    found: dict[str, list[int]] = {}
    for mod in listed:
        found.setdefault(mod["name"].lower(), []).append(mod["base"])
    bases, notes = {}, []
    for name in dict.fromkeys(m.lower() for m in wanted):
        hits = found.get(name, [])
        if len(hits) == 1:
            bases[name] = hits[0]
        elif hits:
            notes.append(f"{name} is loaded {len(hits)} times, not measured")
        else:
            notes.append(f"{name} is not loaded in the process")
    return bases, notes


def _stubs(n: int) -> str:
    return f"{n} stub{'s' if n != 1 else ''}"


def measure(baseline: Baseline, reader: ProcessReader, view: str | None = None,
            build: str | None = None, modules: tuple[str, ...] = ("ntdll.dll",)) -> dict:
    """The state of each baseline stub of `modules` in the process behind `reader`.

    `view` and `build` default to what the reader says. A baseline of another view or
    build is refused before anything is read. `partial` is True when a stub is
    unreadable, an owner lookup failed, or nothing was measured at all: such a result
    is never a clean process."""
    view = view or reader.view()
    build = build or reader.build()
    # RVAs and bytes hold for one build and view; read with another's, a verdict would
    # be about whatever happens to lie there
    if view != baseline.view:
        raise ScanRefused(f"process view {view or 'unknown'} does not match the baseline "
                          f"view {baseline.view}")
    if build != baseline.build:
        raise ScanRefused(f"system build {build or 'unknown'} does not match the baseline "
                          f"build {baseline.build}")
    bases, notes = _module_bases(reader, modules)
    addrs = {sc.name: bases[sc.module.lower()] + sc.rva
             for sc in baseline.syscalls.values() if sc.module.lower() in bases}
    live = read_spans(reader, addrs.items(), lambda name: READ_LEN[view])
    states, owner_errors = {}, 0
    for name, addr in addrs.items():
        states[name], failed = _state(reader, baseline.syscalls[name], live[name], addr, view)
        owner_errors += failed
    counts = dict.fromkeys(_STATES, 0)
    for s in states.values():
        counts[s["state"]] += 1
    read_errors = sum(1 for data in live.values() if data is None)
    # a stub that reads as zeros is unreadable too; in an image, which is paged in on
    # read, zeros were written there
    unreadable = counts[STATE_UNREADABLE]
    if unreadable:
        notes.append(f"{_stubs(unreadable)} unreadable ({read_errors} not read at all), "
                     "the result is partial")
    # an owner that could not be looked up turns a hook or a patch into diverged
    if owner_errors:
        notes.append(f"the jump owner of {_stubs(owner_errors)} could not be looked up, "
                     "the result is partial")
    # nothing measured is no finding, and must not read as a clean process
    partial = bool(unreadable or owner_errors) or not states
    return {
        "view": view,
        "build": build,
        "states": states,
        "counts": counts,
        "deviations": [s for s in states.values() if s["state"] != STATE_INTACT],
        "read_errors": read_errors,
        "owner_errors": owner_errors,
        "partial": partial,
        "note": "; ".join(notes),
    }


# --------------------------------------------------------------------------
# Win32 (ctypes). Untested in CI: it only fetches, and every decision on what it
# fetched is made above. Checked by hand on the VM.
# --------------------------------------------------------------------------

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
# Tried in order. VirtualQueryEx and GetModuleInformation are documented to need
# PROCESS_QUERY_INFORMATION; without it every owner lookup may fail. A protected process
# refuses that right, so the limited one follows. Both are read-only.
PROCESS_ACCESS = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                  PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
_ERROR_ACCESS_DENIED = 5
LIST_MODULES_ALL = 0x03
# in characters; device paths may exceed MAX_PATH
_PATH_CHARS = 32768

_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", _DWORD),
                ("EntryPoint", ctypes.c_void_p)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = ([("BaseAddress", ctypes.c_void_p),
                 ("AllocationBase", ctypes.c_void_p),
                 ("AllocationProtect", _DWORD)]
                + ([("PartitionId", ctypes.c_uint16)] if ctypes.sizeof(ctypes.c_void_p) == 8 else [])
                + [("RegionSize", ctypes.c_size_t),
                   ("State", _DWORD),
                   ("Protect", _DWORD),
                   ("Type", _DWORD)])


@functools.lru_cache(maxsize=None)
def _win32_api():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    wstr = ctypes.c_wchar_p
    for dll, name, res, args in (
        (k32, "OpenProcess", _HANDLE, [_DWORD, ctypes.c_int, _DWORD]),
        (k32, "CloseHandle", ctypes.c_int, [_HANDLE]),
        (k32, "ReadProcessMemory", ctypes.c_int,
         [_HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]),
        (k32, "VirtualQueryEx", ctypes.c_size_t,
         [_HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]),
        (psapi, "EnumProcessModulesEx", ctypes.c_int,
         [_HANDLE, ctypes.POINTER(ctypes.c_void_p), _DWORD, ctypes.POINTER(_DWORD), _DWORD]),
        (psapi, "GetModuleInformation", ctypes.c_int,
         [_HANDLE, ctypes.c_void_p, ctypes.POINTER(MODULEINFO), _DWORD]),
        (psapi, "GetModuleFileNameExW", _DWORD, [_HANDLE, ctypes.c_void_p, wstr, _DWORD]),
        (psapi, "GetMappedFileNameW", _DWORD, [_HANDLE, ctypes.c_void_p, wstr, _DWORD]),
    ):
        fn = getattr(dll, name)
        fn.restype, fn.argtypes = res, args
    return k32, psapi


class Win32Reader(ProcessReader):
    """A live process, opened for querying and reading only. Use as a context manager.

    `view` and `build` come from the caller, which resolves the view from the image's
    PE header: IsWow64Process2 cannot tell an emulated x64 process on ARM64 apart."""

    def __init__(self, pid: int, view: str | None, build: str | None):
        if os.name != "nt":
            raise OSError("reading a process needs Windows")
        self._view, self._build = view, build
        self._k32, self._psapi = _win32_api()
        self._handle = None
        # the right the handle holds, for telling a limited open from a failed query
        self.access = None
        for access in PROCESS_ACCESS:
            self._handle = self._k32.OpenProcess(access, False, int(pid))
            if self._handle:
                self.access = access
                return
            error = ctypes.get_last_error()
            if error != _ERROR_ACCESS_DENIED:
                break
        raise ctypes.WinError(error)

    def close(self) -> None:
        if self._handle:
            self._k32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> Win32Reader:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def view(self) -> str | None:
        return self._view

    def build(self) -> str | None:
        return self._build

    def modules(self) -> list[dict] | None:
        ptr = ctypes.sizeof(ctypes.c_void_p)
        needed = _DWORD(0)
        count = 512
        while True:
            handles = (ctypes.c_void_p * count)()
            if not self._psapi.EnumProcessModulesEx(self._handle, handles, ctypes.sizeof(handles),
                                                    ctypes.byref(needed), LIST_MODULES_ALL):
                return None
            if needed.value <= ctypes.sizeof(handles):
                break
            count = needed.value // ptr + 16
        out = []
        buf = ctypes.create_unicode_buffer(_PATH_CHARS)
        for hmod in handles[:needed.value // ptr]:
            info = MODULEINFO()
            if not hmod or not self._psapi.GetModuleInformation(
                    self._handle, hmod, ctypes.byref(info), ctypes.sizeof(info)):
                continue
            if not self._psapi.GetModuleFileNameExW(self._handle, hmod, buf, _PATH_CHARS):
                continue
            out.append({"name": ntpath.basename(buf.value), "base": info.lpBaseOfDll or 0,
                        "size": info.SizeOfImage, "path": buf.value})
        return out

    def read(self, addr: int, size: int) -> bytes | None:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        try:
            ok = self._k32.ReadProcessMemory(self._handle, addr, buf, size, ctypes.byref(got))
        except (ctypes.ArgumentError, OverflowError):
            return None
        return buf.raw if ok and got.value == size else None

    def region(self, addr: int) -> Region | None:
        mbi = MEMORY_BASIC_INFORMATION()
        try:
            if not self._k32.VirtualQueryEx(self._handle, addr, ctypes.byref(mbi),
                                            ctypes.sizeof(mbi)):
                return None
        except (ctypes.ArgumentError, OverflowError):
            return None
        buf = ctypes.create_unicode_buffer(_PATH_CHARS)
        named = self._psapi.GetMappedFileNameW(self._handle, addr, buf, _PATH_CHARS)
        return Region(mbi.State, mbi.Type, buf.value if named else None)
