"""Syscall scan: the live stubs of a process measured against the NTSleuth baseline.

Everything that decides lives above `ProcessReader`; `Win32Reader` only fetches, so the
whole measurement runs in tests against a fake process. The target is only ever read.
"""

from __future__ import annotations

import ctypes
import functools
import json
import ntpath
import os
import re
import threading
from typing import NamedTuple

from syscall_baseline import (READ_LEN, STATE_DIVERGED, STATE_HOOKED, STATE_INTACT,
                              STATE_PATCHED, STATE_UNREADABLE, NON_MODULE_OWNERS, OWNER_MAPPED,
                              OWNER_PRIVATE, Baseline, Syscall, classify_stub, jump_authenticated,
                              jump_pattern, jump_pointer, jump_target, strip_pointer_auth)

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# the width of the pointer an indirect hook reads its target from
_POINTER_LEN = {"arm64": 8, "x64": 8, "x86": 4}

_STATES = (STATE_INTACT, STATE_HOOKED, STATE_PATCHED, STATE_DIVERGED, STATE_UNREADABLE)


class Region(NamedTuple):
    """What VirtualQueryEx and GetMappedFileNameW say about the region around an address.

    `base` and `size` are the run of pages from the queried address that share these
    attributes, as VirtualQueryEx answers it; `protect` is its page protection. A reader
    that does not fill them leaves 0, which no scan treats as executable."""
    state: int
    type: int
    path: str | None
    base: int = 0
    size: int = 0
    protect: int = 0


def owner_from_region(region: Region | None) -> str | None:
    """The owner `classify_stub` expects: a lower-case basename, "private", "mapped", or None.

    "private" is memory no file backs: a private allocation, or a mapped view with no file behind it (a
    pagefile-backed section, the classic target of NtMapViewOfSection), which `_searchable` treats alike.
    "mapped" is a mapped view of a named file: file-backed, but no loaded module, which only an image is. Its
    basename is not the owner, or a data copy of ntdll.dll would read as ntdll itself. Both are weighed alike, so
    the state of a view does not hang on whether GetMappedFileNameW named its file.

    GetMappedFileNameW names a device path; passed on as is, a jump back into
    `\\Device\\...\\ntdll.dll` would not compare equal to `ntdll.dll` and read as hooked."""
    if region is None or region.state != MEM_COMMIT:
        return None
    if region.type == MEM_PRIVATE or (region.type == MEM_MAPPED and not region.path):
        return OWNER_PRIVATE
    if region.type == MEM_MAPPED:
        return OWNER_MAPPED
    if region.type == MEM_IMAGE and region.path:
        return ntpath.basename(region.path).lower() or None
    return None


def owner_lookup_failed(region: Region | None) -> bool:
    """Whether a region query gave no answer about who owns it: it failed, or it names an image without its file.
    An image is file-backed by definition, so a missing name (GetMappedFileNameW failed, which the limited access
    right makes likely) is a lookup that failed, not an owner nobody has."""
    if region is None:
        return True
    return region.state == MEM_COMMIT and region.type == MEM_IMAGE and owner_from_region(region) is None


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


def _resolve_jump(reader: ProcessReader, code: bytes, addr: int,
                  view: str) -> tuple[int | None, bool]:
    """`(target, failed)` of the hook jump at the start of `code`, which lies at `addr`. A jump that reads its
    target from memory is followed through its pointer; a pointer that cannot be read is `failed`. No jump at
    all is `(None, False)`: nothing to ask about, which is no failure."""
    target = jump_target(code, addr, view)
    if target is not None:
        return target, False
    pointer = jump_pointer(code, addr, view)
    if pointer is None:
        return None, False
    word = _read_exact(reader, pointer, _POINTER_LEN[view])
    if word is None:
        return None, True
    value = int.from_bytes(word, "little")
    # a pointer-authenticated branch goes to the address below the PAC, not to the signed value
    return (strip_pointer_auth(value) if jump_authenticated(code, view) else value), False


def _lookup_owner(reader: ProcessReader, addr: int) -> tuple[str | None, bool]:
    """`(owner, failed)` of the memory at `addr`; `failed` when the region query gives no answer about it."""
    region = reader.region(addr)
    return owner_from_region(region), owner_lookup_failed(region)


# How many relays are followed from the first target on. MinHook and Microsoft Detours, the most common x64 hooking
# libraries, do not jump from the stub into their DLL: they write `E9 rel32` to a relay they allocate near the target
# with VirtualAlloc, private memory, and only the relay jumps on (`FF 25`) to the hooking DLL. ARM64 hookers relay by
# necessity, a `B` reaching no further than 128 MB. Judged by its first hop, every EDR, overlay and browser sandbox
# that hooks this way would read as patched. Two hops cover a relay and a relay of a relay; a chain that is still in
# private memory after them has no module to explain it.
#
# The decoder is not exhaustive. An undecodable private relay is read as private code that is not a jump and classified
# patched. That direction is deliberate: read as unscored instead, undecodable private code would hand malware a free
# exit, any code the decoder does not know scoring nothing. So what remains is a false positive on a hooking form not
# yet known, never a false negative on malware. A new real-world form widens the decoder (`_X64_HOOKS`, `_ARM64_HOOKS`
# in syscall_baseline); it does not change this rule.
MAX_RELAY_HOPS = 2


def _target_owner(reader: ProcessReader, live: bytes, addr: int,
                  view: str) -> tuple[str | None, bool, list[dict]]:
    """`(owner, failed, relay)`. `owner` is who holds the final target of the hook jump, following up to
    MAX_RELAY_HOPS relays in memory that is no module (private, or a mapped view) whose bytes are a jump themselves;
    `relay` lists each relay passed (`address`, `owner`, the `pattern` of its jump). `failed` when there is a jump but an owner on the way could not
    be looked up: an unreadable pointer, an unreadable relay, or a region query that failed. A hop that fails is not
    guessed past: the owner is then None. Changed bytes with no jump have no target to ask about, which is no
    failure; private code that is no jump is the code that runs, and stays private."""
    relay: list[dict] = []
    target, failed = _resolve_jump(reader, live, addr, view)
    if target is None:
        return None, failed, relay
    owner, failed = _lookup_owner(reader, target)
    while owner in NON_MODULE_OWNERS and not failed and len(relay) < MAX_RELAY_HOPS:
        code = _read_exact(reader, target, READ_LEN[view])
        if code is None:
            relay.append({"address": target, "owner": owner, "pattern": None})
            return None, True, relay
        following, failed = _resolve_jump(reader, code, target, view)
        if following is None and not failed:
            break
        relay.append({"address": target, "owner": owner, "pattern": jump_pattern(code, view)})
        if failed:
            return None, True, relay
        target = following
        owner, failed = _lookup_owner(reader, target)
    return (None if failed else owner), failed, relay


def _state(reader: ProcessReader, sc: Syscall, live: bytes | None, addr: int,
           view: str) -> tuple[dict, bool]:
    # the owner lookup costs a region query; an intact or unreadable stub needs none
    out, failed = classify_stub(sc, live, view, None), False
    if out["state"] not in (STATE_INTACT, STATE_UNREADABLE):
        owner, failed, relay = _target_owner(reader, live, addr, view)
        out = classify_stub(sc, live, view, owner, relayed=bool(relay))
        out["relay"] = relay
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


KEY_VERSION = 1
# the separator of a set's key in the file; a view never holds it, a build may
_SET_SEP = "|"


class HookAllowlist:
    """Hooks seen on this host while it was considered clean, as `(syscall, owner)` pairs.

    This is not `MemoryBaseline`: that folds the process into every key, so a hook
    recorded in explorer.exe could never cover the same hook in the sample, and an EDR
    hooks ntdll in every process it watches. The key here has no process in it, on purpose.

    The pairs are kept in one set per `(build, view)`. A host has one build and two views,
    native ARM64 and emulated x64, and an EDR hooks both: one set for the whole file would
    lose the other view's hooks whenever one view is recorded, and every scan of it would
    score the EDR again. A set for another pair says nothing about this one, so it is never
    applied to it. Only `hooked` stubs whose owner is a module are ever recorded: a patch
    must never become suppressible, or capturing a dirty host would whitelist the
    attacker's own."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        # why the file on disk is not in use, None if it is
        self.problem: str | None = None
        self._sets: dict[tuple[str, str], frozenset] = {}
        self.load()

    @staticmethod
    def _pair(entry) -> tuple[str, str] | None:
        """The key of a deviation or stored entry, None if it must not be suppressible."""
        if not isinstance(entry, dict):
            return None
        name = entry.get("name", entry.get("syscall"))
        owner = entry.get("target_owner", entry.get("owner"))
        if not isinstance(name, str) or not name or not isinstance(owner, str):
            return None
        owner = owner.strip().lower()
        if not owner or owner in NON_MODULE_OWNERS:
            return None
        return name, owner

    @staticmethod
    def _scope(build, view) -> tuple[str, str] | None:
        """`(build, view)`, or None for neither. One of them alone is a mistake: read as a
        wildcard it would let `clear(build)` empty both views."""
        if build is None and view is None:
            return None
        if not (isinstance(build, str) and build and isinstance(view, str) and view):
            raise ValueError("a build and a view are given together, or neither")
        return build, view

    def knows(self, syscall_name: str, owner: str, build: str, view: str) -> bool:
        """Whether this hook is recorded for this build and view."""
        if not isinstance(owner, str):
            return False
        with self._lock:
            return (syscall_name, owner.strip().lower()) in self._sets.get((build, view), ())

    def status(self, build: str | None, view: str | None) -> dict:
        """Whether the list may be applied to a scan of `build` and `view`, and if not, why.

        A list that holds nothing at all has nothing to refuse. One that holds sets, but
        none for this pair, was recorded for another build or view and is not applied."""
        with self._lock:
            have = self._sets.get((build, view), ())
            reason = self.problem or ""
            if not reason and self._sets and not have:
                held = ", ".join(f"build {b} view {v}" for b, v in sorted(self._sets))
                reason = (f"the hook allowlist holds no set for build {build or 'unknown'}, "
                          f"view {view or 'unknown'} (it has: {held}): not applied")
            return {"applied": not reason, "entries": len(have), "reason": reason}

    def entries(self, build: str | None = None, view: str | None = None) -> list[dict]:
        """Every set, or the one of a pair, each entry naming its own build and view."""
        scope = self._scope(build, view)
        with self._lock:
            return [{"syscall": name, "owner": owner, "build": b, "view": v}
                    for (b, v), pairs in sorted(self._sets.items())
                    if scope in (None, (b, v)) for name, owner in sorted(pairs)]

    def add_from(self, result: dict) -> int:
        """Record the hooks of a `measure` result into the set of its build and view,
        leaving every other set alone; returns how many were new.

        Raises OSError if the list cannot be written; the list is then as before."""
        build, view = result.get("build"), result.get("view")
        if not (isinstance(build, str) and build and isinstance(view, str) and view
                and _SET_SEP not in view):
            return 0
        found = set()
        for entry in result.get("deviations") or ():
            if isinstance(entry, dict) and entry.get("state") == STATE_HOOKED:
                pair = self._pair(entry)
                if pair:
                    found.add(pair)
        with self._lock:
            have = self._sets.get((build, view), frozenset())
            added = len(found - have)
            if added:
                self._commit({**self._sets, (build, view): have | found})
            return added

    def clear(self, build: str | None = None, view: str | None = None) -> None:
        """Forget the set of a pair, or every set when called bare."""
        scope = self._scope(build, view)
        with self._lock:
            if scope is None:
                self._commit({})
            elif scope in self._sets:
                self._commit({k: v for k, v in self._sets.items() if k != scope})

    def _commit(self, sets: dict) -> None:
        before = self._sets
        self._sets = sets
        try:
            self.save()
        except OSError:
            self._sets = before
            raise
        self.problem = None

    def save(self) -> None:
        """Write beside the file, flush, then swap it in: a crash halfway leaves the old
        list, never half of one that would silently suppress the wrong hooks."""
        with self._lock:
            sets: dict[str, list] = {}
            for (build, view), pairs in sorted(self._sets.items()):
                sets[f"{build}{_SET_SEP}{view}"] = [{"syscall": n, "owner": o}
                                                    for n, o in sorted(pairs)]
            payload = {"version": KEY_VERSION, "sets": sets}
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self.path)
            except OSError:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise

    def load(self) -> None:
        """Read the file; what cannot be trusted is left out and, if it is the whole file,
        sets `problem`, so that nothing is suppressed on its say-so."""
        with self._lock:
            self._sets = {}
            self.problem = None
            if not os.path.isfile(self.path):
                return
            try:
                with open(self.path, encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, ValueError) as exc:
                self._set_aside(str(exc))
                return
            if not isinstance(data, dict):
                self._set_aside("not an object")
                return
            if data.get("version") != KEY_VERSION:
                self.problem = (f"the hook allowlist {self.path} is of version "
                                f"{data.get('version')!r}, this is version {KEY_VERSION}: "
                                "not applied until the hooks are recorded again")
                return
            sets = data.get("sets")
            if not isinstance(sets, dict):
                self._set_aside("sets missing")
                return
            for key, entries in sets.items():
                # the view is last: a build may hold the separator, a view never does
                build, sep, view = key.rpartition(_SET_SEP)
                if not (sep and build and view and isinstance(entries, list)):
                    continue
                pairs = frozenset(pair for pair in map(self._pair, entries) if pair)
                if pairs:
                    self._sets[(build, view)] = pairs

    def _set_aside(self, why: str) -> None:
        """Keep an unreadable file for inspection rather than overwrite it on the next save."""
        kept = ""
        try:
            os.replace(self.path, self.path + ".corrupt")
            kept = f", kept as {self.path}.corrupt"
        except OSError:
            pass
        self.problem = (f"the hook allowlist {self.path} is unreadable ({why}){kept}: "
                        "not applied")


def measure(baseline: Baseline, reader: ProcessReader, view: str | None = None,
            build: str | None = None, modules: tuple[str, ...] = ("ntdll.dll",),
            allowlist: HookAllowlist | None = None) -> dict:
    """The state of each baseline stub of `modules` in the process behind `reader`.

    `view` and `build` default to what the reader says. A baseline of another view or
    build is refused before anything is read. `partial` is True when a stub is
    unreadable, an owner lookup failed, or nothing was measured at all: such a result
    is never a clean process.

    With an `allowlist`, each state dict says whether its hook is a known one. Such a
    stub stays in `states`, `counts` and `deviations`: an analyst must see that the EDR
    hooks this process. Only a scorer's use of the stub is for the flag to change."""
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
    listed = None if allowlist is None else allowlist.status(build, view)
    if listed is not None and not listed["applied"]:
        notes.append(listed["reason"])
    if listed is not None:
        for s in states.values():
            s["allowlisted"] = (listed["applied"] and s["state"] == STATE_HOOKED
                                and allowlist.knows(s["name"], s["target_owner"], build, view))
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
        # stubs of intact shape that load another syscall's number: a finding whatever their state
        "renumbered": sum(1 for s in states.values() if s["number_matches"] is False),
        "read_errors": read_errors,
        "owner_errors": owner_errors,
        "partial": partial,
        "allowlist": listed,
        "note": "; ".join(notes),
    }


# --------------------------------------------------------------------------
# Stubs outside ntdll: a sample that carries its own copy of a syscall stub calls the
# kernel without passing through any hook. Measuring ntdll cannot see it; searching the
# bytes can, and the baseline turns a hit from "an SVC somewhere" into a named syscall.
# --------------------------------------------------------------------------

# One pattern per view, as a bytes regex; `ssn` is the number's placeholder. x64 is
# `mov r10, rcx; mov eax, <number>`, then a syscall within sixteen bytes (Windows 11 puts
# a test of KUSER_SHARED_DATA between them), with no second stub head in between, so a
# head cannot borrow the syscall of the stub after it. ARM64 is `SVC #<number>; RET`,
# the number being the SVC's immediate. Both are zero-width, so no hit hides another.
STUB_SHAPES: dict[str, bytes] = {
    "x64": (rb"(?s)\x4c\x8b\xd1\xb8(?=(?P<body>(?P<ssn>.{4})"
            rb"(?:(?!\x4c\x8b\xd1\xb8).){0,16}?\x0f\x05))"),
    "arm64": (rb"(?s)(?=(?P<body>(?P<ssn>[\x01\x21\x41\x61\x81\xa1\xc1\xe1].[\x00-\x1f]\xd4)"
              rb"\xc0\x03\x5f\xd6))"),
}
_STUB_REGEX = {view: re.compile(shape) for view, shape in STUB_SHAPES.items()}
_STUB_NUMBER = {
    "x64": lambda word: int.from_bytes(word, "little"),
    "arm64": lambda word: (int.from_bytes(word, "little") >> 5) & 0xFFFF,
}
_STUB_PATTERN = {"x64": "mov r10, rcx; mov eax, imm32; syscall", "arm64": "svc #imm16; ret"}


def stub_number(data: bytes, view: str) -> int | None:
    """The syscall number of `data` when it is exactly one stub of `view`'s shape, as a hit's `stub_hex` is: from
    its first byte to the end of its stub, nothing before or after. None for any other bytes and for a view that
    has no stub shape."""
    regex = _STUB_REGEX.get(view)
    m = regex.match(data) if regex is not None and isinstance(data, (bytes, bytearray)) else None
    if m is None or m.end("body") != len(data):
        return None
    return _STUB_NUMBER[view](m.group("ssn"))
_STUB_ALIGN = {"x64": 1, "arm64": 4}
# no stub is longer than this; a read that continues this far past its own start cannot
# cut one in two
_STUB_SPAN = 32

_PAGE_EXECUTABLE = 0xF0
_PAGE_GUARD = 0x100
# one read of a region; a larger region is read in steps of this
_CHUNK = 0x100000
# MmHighestUserAddress + 1; where the walk of a process's regions ends
_USER_SPACE_END = 0x7FFFFFFF0000


def _numbers(baseline: Baseline) -> dict[int, Syscall]:
    """Each syscall number of the baseline with the syscall that owns it. ntdll and win32u
    number apart in practice (the table is in the number's upper bits); were they not to,
    ntdll is the one named."""
    ordered = sorted(baseline.by_number.items(),
                     key=lambda item: (item[0][0] != "ntdll.dll", item[0]))
    out: dict[int, Syscall] = {}
    for (_, number), sc in ordered:
        out.setdefault(number, sc)
    return out


def _is_imported(sc: Syscall, imports) -> bool:
    names = {sc.name}
    if sc.name.startswith("Nt"):
        names.add("Zw" + sc.name[2:])
    return not names.isdisjoint(imports)


def _import_present(sc: Syscall | None, imports, expanded_imports) -> bool | None:
    """Whether the sample imports the syscall of a stub: True, False, or None for unknown.

    Only a presence can be read off a raw import table. An absence cannot: a sample that
    calls the documented Win32 function never imports the `Nt` name behind it, so against
    its raw table the stub of that very syscall looks unimported, and an ordinary program
    would read as a proven bypass. An absence is claimed only against `expanded_imports`,
    which the caller has run through the Win32 to Nt table. A number the build does not
    have names no function to look for."""
    if sc is None:
        return None
    if any(table is not None and _is_imported(sc, table)
           for table in (imports, expanded_imports)):
        return True
    return False if expanded_imports is not None else None


def _scan_chunk(data: bytes, view: str, numbers: dict, imports, expanded_imports,
                starts_below: int | None = None) -> list[dict]:
    decode, align = _STUB_NUMBER[view], _STUB_ALIGN[view]
    hits = []
    for m in _STUB_REGEX[view].finditer(data):
        at = m.start()
        if starts_below is not None and at >= starts_below:
            break
        if at % align:
            continue
        number = decode(m.group("ssn"))
        sc = numbers.get(number)
        hits.append({
            "syscall": sc.name if sc else None,
            "number": number,
            "module": sc.module if sc else None,
            "offset": at,
            "view": view,
            "pattern": _STUB_PATTERN[view],
            "stub_hex": data[at:m.end("body")].hex(),
            "import_present": _import_present(sc, imports, expanded_imports),
            "number_known": sc is not None,
        })
    return hits


def _shape_of(view: str) -> str:
    if view not in STUB_SHAPES:
        raise ValueError(f"no stub shape for view {view!r}")
    return view


def find_stubs_in_bytes(data: bytes, baseline: Baseline, imports: set[str] | None = None,
                        *, expanded_imports: set[str] | None = None) -> list[dict]:
    """The syscall stubs in `data`, in the shape of the baseline's view.

    A number the baseline holds names its syscall. One it does not is still a hit, with
    `number_known` False: a stub built for another Windows build.

    `import_present` says whether the sample imports the syscall of a stub, and is tri-state.
    `imports` is the sample's raw import table: it can show that the function is imported
    (True) but never that it is not, because the documented path goes through a Win32
    function whose `Nt` name the table does not hold. `expanded_imports` is that table after
    the Win32 to Nt table has been applied to it; only a set passed there can give False, a
    proven bypass of the import path. It is keyword-only so that a raw table cannot be passed
    into it by position. With neither, or with only a raw table that lacks the name, the
    answer is None."""
    view = _shape_of(baseline.view)
    return _scan_chunk(data, view, _numbers(baseline), imports, expanded_imports)


class StubScan(list):
    """The hits of a process search, with whether the search covered what it set out to.

    `partial` is True when memory could not be walked or read: no hit then is not a clean
    process. `regions_searched` counts the regions that qualified."""

    def __init__(self):
        super().__init__()
        self.partial = False
        self.regions_searched = 0
        self.notes: list[str] = []

    @property
    def note(self) -> str:
        return "; ".join(self.notes)

    def fail(self, why: str) -> None:
        self.partial = True
        self.notes.append(why)


def _searchable(region: Region) -> bool:
    """Memory that holds code no file on disk accounts for: private, or a mapped view that
    has no file behind it. Not an image and not a mapped file: a legitimate DLL carries stubs
    of its own, and ntdll's are measured by `measure`. Not a guard page: reading one
    raises it, which would change the process being watched."""
    if region.state != MEM_COMMIT:
        return False
    if not region.protect & _PAGE_EXECUTABLE or region.protect & _PAGE_GUARD:
        return False
    return region.type == MEM_PRIVATE or (region.type == MEM_MAPPED and not region.path)


def _walk(reader: ProcessReader, found: StubScan):
    addr = 0
    while addr < _USER_SPACE_END:
        region = reader.region(addr)
        if region is None or region.size <= 0:
            found.fail(f"the region query at {addr:#x} failed, memory above it not searched")
            return
        yield region
        following = region.base + region.size
        if following <= addr:
            found.fail(f"the region at {addr:#x} does not advance, memory above it not searched")
            return
        addr = following


def find_stubs_in_process(reader: ProcessReader, baseline: Baseline,
                          imports: set[str] | None = None, *,
                          expanded_imports: set[str] | None = None) -> StubScan:
    """The syscall stubs in the private, executable memory of the process behind `reader`,
    each hit with an `address` where `find_stubs_in_bytes` has an `offset`. `imports` and
    `expanded_imports` mean what they mean there.

    A baseline of another view or build is refused before anything is read: its numbers
    would name the wrong syscalls."""
    view = reader.view()
    if view != baseline.view:
        raise ScanRefused(f"process view {view or 'unknown'} does not match the baseline "
                          f"view {baseline.view}")
    build = reader.build()
    if build != baseline.build:
        raise ScanRefused(f"system build {build or 'unknown'} does not match the baseline "
                          f"build {baseline.build}")
    view = _shape_of(view)
    numbers = _numbers(baseline)
    found = StubScan()
    unread: list[int] = []
    for region in _walk(reader, found):
        if not _searchable(region):
            continue
        found.regions_searched += 1
        for off in range(0, region.size, _CHUNK):
            addr = region.base + off
            data = _read_exact(reader, addr, min(_CHUNK + _STUB_SPAN, region.size - off))
            if data is None:
                unread.append(addr)
                continue
            for hit in _scan_chunk(data, view, numbers, imports, expanded_imports,
                                   starts_below=_CHUNK):
                found.append({("address" if key == "offset" else key):
                              (addr + value if key == "offset" else value)
                              for key, value in hit.items()})
    if unread:
        found.fail(f"{len(unread)} stretch{'es' if len(unread) != 1 else ''} of executable "
                   f"memory not read (first at {unread[0]:#x}), the result is partial")
    return found


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
        return Region(mbi.State, mbi.Type, buf.value if named else None,
                      mbi.BaseAddress or 0, mbi.RegionSize, mbi.Protect)
