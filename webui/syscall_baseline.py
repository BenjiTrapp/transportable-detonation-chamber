"""Syscall baseline: the NTSleuth JSON of ntdll.dll / win32u.dll read into objects.

Pure Python; later measured against the stubs of a running process.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

_BUILD = r"[0-9A-Za-z.]+"
_VIEW = r"arm64|x64"
_FILENAME_RE = re.compile(rf"ntsleuth-(?P<build>{_BUILD})-(?P<view>{_VIEW})\.json")
_BUILD_RE = re.compile(_BUILD)
_VIEW_RE = re.compile(_VIEW)


class BaselineError(Exception):
    """The baseline file as a whole is unusable (unreadable, truncated, wrong shape)."""


class _Skip(Exception):
    pass


@dataclass
class Syscall:
    name: str
    module: str
    number: int
    rva: int
    return_type: str
    calling_convention: str
    parameters: list
    stub_bytes: bytes
    is_true_syscall: bool


@dataclass
class Baseline:
    build: str
    view: str
    syscalls: dict = field(default_factory=dict)
    by_number: dict = field(default_factory=dict)
    skipped: list = field(default_factory=list)
    # names of entries dropped because another module already owns the name; `syscalls`
    # is keyed by name alone, so each of these is a syscall the catalog cannot show
    shadowed: list = field(default_factory=list)
    # False when the file says it was extracted without the symbol server: the parameters of
    # such a baseline are incomplete, its numbers, RVAs and stub bytes are not
    symbols: bool = True


def parse_baseline(payload: list | dict, build: str, view: str) -> Baseline:
    """Entries that cannot be measured are skipped (and named in `skipped`), never fatal:
    one malformed entry must not take the whole baseline down.

    NTSleuth's README does not fix the top level, so both a bare list of entries and
    `{"syscalls": [...]}` are accepted."""
    raw = payload.get("syscalls") if isinstance(payload, dict) else payload
    if not isinstance(raw, list):
        raise BaselineError("baseline is neither a list of entries nor has a 'syscalls' list")
    bl = Baseline(build=build, view=view,
                  symbols=not (isinstance(payload, dict) and payload.get("symbols") is False))
    for i, entry in enumerate(raw):
        label = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(label, str) or not label:
            label = f"#{i}"
        try:
            sc = _parse_entry(entry)
        except _Skip as why:
            print(f"[syscall_baseline] skipping {label}: {why}")
            bl.skipped.append(label)
            continue
        if sc.name in bl.syscalls:
            if bl.syscalls[sc.name].module != sc.module:
                print(f"[syscall_baseline] {label} of {sc.module} shadowed by the one of "
                      f"{bl.syscalls[sc.name].module}")
                bl.shadowed.append(label)
            else:
                print(f"[syscall_baseline] ignoring duplicate {label}, keeping the first")
            continue
        if (sc.module, sc.number) in bl.by_number:
            print(f"[syscall_baseline] skipping {label}: number already taken")
            bl.skipped.append(label)
            continue
        bl.syscalls[sc.name] = sc
        bl.by_number[(sc.module, sc.number)] = sc
    # an entry skipped earlier may share its name with one accepted later, or the reverse
    bl.skipped = list(dict.fromkeys(n for n in bl.skipped if n not in bl.syscalls))
    bl.shadowed = list(dict.fromkeys(bl.shadowed))
    return bl


def _parse_entry(entry) -> Syscall:
    if not isinstance(entry, dict):
        raise _Skip("not an object")
    name, module = entry.get("name"), entry.get("module")
    if not isinstance(name, str) or not name or not isinstance(module, str) or not module:
        raise _Skip("missing name or module")
    if not entry.get("is_true_syscall", True):
        raise _Skip("not a true syscall")
    for key in ("syscall_number", "rva"):
        value = entry.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise _Skip(f"invalid {key} {value!r}")
    try:
        stub = bytes.fromhex(entry.get("stub_bytes"))
    except (TypeError, ValueError):
        raise _Skip("missing or invalid stub_bytes") from None
    if not stub:
        raise _Skip("empty stub_bytes")
    params = entry.get("parameters")
    return Syscall(
        name=name,
        module=module,
        number=entry["syscall_number"],
        rva=entry["rva"],
        return_type=str(entry.get("return_type") or ""),
        calling_convention=str(entry.get("calling_convention") or ""),
        parameters=[p for p in params if isinstance(p, dict)] if isinstance(params, list) else [],
        stub_bytes=stub,
        is_true_syscall=True,
    )


def load_baseline(path: str) -> Baseline:
    """Build and view come from the file name `ntsleuth-<build>-<view>.json`.

    A file that yields no usable syscall at all is an error, not an empty baseline."""
    m = _FILENAME_RE.fullmatch(os.path.basename(path))
    if not m:
        raise BaselineError(f"{path}: not named ntsleuth-<build>-<view>.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    bl = parse_baseline(payload, m.group("build"), m.group("view"))
    # measuring against an empty baseline finds no deviation, which reads as "clean"
    if not bl.syscalls:
        raise BaselineError(f"baseline {path} has no usable syscalls ({len(bl.skipped)} skipped)")
    return bl


def parse_baseline_name(filename: str) -> tuple[str, str] | None:
    """`(build, view)` of a file named `ntsleuth-<build>-<view>.json`, None for any other name."""
    m = _FILENAME_RE.fullmatch(filename)
    return (m.group("build"), m.group("view")) if m else None


def find_baseline(directory: str, build: str, view: str) -> str | None:
    """Path of `ntsleuth-<build>-<view>.json` in `directory`, or None.

    `view` can come from a request: anything but the plain name parts is refused before
    a path is built."""
    if not _BUILD_RE.fullmatch(build) or not _VIEW_RE.fullmatch(view):
        return None
    path = os.path.join(directory, f"ntsleuth-{build}-{view}.json")
    return path if os.path.isfile(path) else None


def _as_number(query: str) -> int | None:
    """A query reads as a syscall number if it is decimal, or hex with or without `0x`."""
    for base in (10, 16):
        try:
            return int(query, base)
        except ValueError:
            continue
    return None


def catalog(baseline: Baseline, query: str = "", module: str = "",
            offset: int = 0, limit: int = 200) -> dict:
    """One page of the syscalls matching `query` and `module`.

    A query that reads as a number matches that number OR the name substring: hex
    digits alone (`add`) are a number too, and must still find `NtAddAtom`."""
    query = query.strip()
    number = _as_number(query) if query else None
    needle = query.lower()
    wanted_module = module.strip().lower()
    hits = []
    for sc in baseline.syscalls.values():
        if wanted_module and sc.module.lower() != wanted_module:
            continue
        if query and needle not in sc.name.lower() and sc.number != number:
            continue
        hits.append(sc)
    hits.sort(key=lambda sc: (sc.module.lower(), sc.number))
    offset, limit = max(offset, 0), max(limit, 0)
    return {
        "items": [_item(sc) for sc in hits[offset:offset + limit]],
        "total": len(hits),
        "offset": offset,
        "limit": limit,
    }


def describe(sc: Syscall) -> dict:
    """One syscall as the catalog lists it."""
    return _item(sc)


def _item(sc: Syscall) -> dict:
    return {
        "name": sc.name,
        "module": sc.module,
        "number": sc.number,
        "rva": sc.rva,
        "return_type": sc.return_type,
        "calling_convention": sc.calling_convention,
        "parameters": sc.parameters,
        "stub_hex": sc.stub_bytes.hex(),
        "is_true_syscall": sc.is_true_syscall,
    }


# Bytes of a stub that are compared, per view. A window read from a process runs on
# into the next stub, which has nothing to do with this syscall; arm64 stubs are just
# `SVC; RET`. x64 is cut at its `syscall` instruction by `stub_prefix_len`.
PREFIX_LEN = {"arm64": 8, "x64": 32, "x86": 16}

# Bytes to read from the process: more than the prefix, so that a hook longer than the
# stub it replaces is still recognisable (`ADRP; ADD; BR` is 12 bytes, the arm64 stub 8).
# The prefix decides changed or not; patterns are recognised on everything read.
READ_LEN = {"arm64": 16, "x64": 32, "x86": 16}

_X64_SYSCALL = b"\x0f\x05"
# `4C 8B D1 B8 <ssn:4>`: the syscall number can spell 0F 05 itself, so look past it
_X64_AFTER_MOV = 8


def stub_prefix_len(sc: Syscall, view: str) -> int:
    """How many bytes of the stub at `sc.rva` to *compare*. What to read from the process
    is `READ_LEN`, which is longer: hooks are recognised on everything read."""
    n = min(PREFIX_LEN[view], len(sc.stub_bytes))
    if view == "x64":
        i = sc.stub_bytes.find(_X64_SYSCALL, _X64_AFTER_MOV)
        if i >= 0:
            n = i + len(_X64_SYSCALL)
    return n


STATE_INTACT = "intact"
STATE_HOOKED = "hooked"
STATE_PATCHED = "patched"
STATE_DIVERGED = "diverged"
STATE_UNREADABLE = "unreadable"

# Owner value for memory that no file backs; what malware leaves behind, as opposed to
# the module of an EDR
OWNER_PRIVATE = "private"

_MISS = object()
_ADDRESS_MASK = 0xFFFFFFFFFFFFFFFF


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value >> (bits - 1) else value


def _word(live: bytes, offset: int = 0) -> int | None:
    chunk = live[offset:offset + 4]
    return int.from_bytes(chunk, "little") if len(chunk) == 4 else None


def _x64_hook(regex: bytes, target=None, pointer=None):
    pattern = re.compile(regex, re.DOTALL)

    def match(live: bytes, base: int):
        m = pattern.match(live)
        if m is None:
            return _MISS
        b = m.group()
        return (target(b, base) if target else None, pointer(b, base) if pointer else None)
    return match


# A matcher yields `(target, pointer)`. A hook that reads its target from memory
# (`FF 25`, `LDR`+`BR`) has no target the stub bytes could show, and a guessed one would
# send the owner lookup to the wrong place; what the bytes do show is the address of the
# pointer, which the reader can follow.
_X64_HOOKS = (
    ("JMP rel32", _x64_hook(rb"\xe9.{4}", lambda b, base: (base + 5 + _signed(
        int.from_bytes(b[1:5], "little"), 32)) & _ADDRESS_MASK)),
    ("JMP [rip]", _x64_hook(rb"\xff\x25.{4}", pointer=lambda b, base: (base + 6 + _signed(
        int.from_bytes(b[2:6], "little"), 32)) & _ADDRESS_MASK)),
    ("MOV RAX; JMP RAX", _x64_hook(rb"\x48\xb8.{8}\xff\xe0", lambda b, base: int.from_bytes(
        b[2:10], "little"))),
    ("MOV R11; JMP R11", _x64_hook(rb"\x49\xbb.{8}\x41\xff\xe3", lambda b, base: int.from_bytes(
        b[2:10], "little"))),
    # push sign-extends its imm32, and ret pops the result
    ("PUSH; RET", _x64_hook(rb"\x68.{4}\xc3", lambda b, base: _signed(
        int.from_bytes(b[1:5], "little"), 32) & _ADDRESS_MASK)),
)

_ARM64_BR_X16 = 0xD61F0200


def _arm64_b(live: bytes, base: int):
    w = _word(live)
    if w is None or w & 0xFC000000 != 0x14000000:
        return _MISS
    return (base + _signed(w & 0x03FFFFFF, 26) * 4) & _ADDRESS_MASK, None


def _arm64_ldr_br(live: bytes, base: int):
    w, nxt = _word(live), _word(live, 4)
    if w is None or nxt is None:
        return _MISS
    if w & 0xFF000000 != 0x58000000 or w & 0x1F != 16 or nxt != _ARM64_BR_X16:
        return _MISS
    return None, (base + _signed((w >> 5) & 0x7FFFF, 19) * 4) & _ADDRESS_MASK


def _arm64_adrp_add_br(live: bytes, base: int):
    adrp, add, br = _word(live), _word(live, 4), _word(live, 8)
    if adrp is None or add is None or br is None:
        return _MISS
    reg = adrp & 0x1F
    if adrp & 0x9F000000 != 0x90000000:
        return _MISS
    # ADD <Xd>, <Xreg>, #imm12{, LSL #12}, then BR <Xd>
    if add & 0xFF800000 != 0x91000000 or (add >> 5) & 0x1F != reg:
        return _MISS
    if br & 0xFFFFFC1F != 0xD61F0000 or (br >> 5) & 0x1F != add & 0x1F:
        return _MISS
    imm = _signed(((adrp >> 5) & 0x7FFFF) << 2 | (adrp >> 29) & 0x3, 21)
    offset = (add >> 10) & 0xFFF
    if add & 0x00400000:
        offset <<= 12
    return (((base & ~0xFFF) + (imm << 12)) + offset) & _ADDRESS_MASK, None


_ARM64_HOOKS = (
    ("B", _arm64_b),
    ("LDR x16; BR x16", _arm64_ldr_br),
    ("ADRP; ADD; BR", _arm64_adrp_add_br),
)

# x86 has a prefix length but no patterns: it is not a baseline view yet
_HOOKS = {"x64": _X64_HOOKS, "arm64": _ARM64_HOOKS}


def _find_hook(live: bytes, base: int, view: str):
    """`(pattern, target, pointer)` of the hook jump at the start of `live`, or None.

    Hooks overwrite the start of the stub; a jump further in is not looked for, which is
    also what `jump_target` and `jump_pointer`, having no offset, can answer for."""
    for name, match in _HOOKS.get(view, ()):
        found = match(live, base)
        if found is not _MISS:
            return (name,) + found
    return None


def jump_target(live: bytes, base: int, view: str) -> int | None:
    """Absolute address the hook at the start of `live` jumps to, `base` being the
    address of `live[0]`. None when there is no hook or its target is not in the bytes."""
    hit = _find_hook(live, base, view)
    return hit[1] if hit else None


def jump_pointer(live: bytes, base: int, view: str) -> int | None:
    """For a hook that reads its target from memory (`FF 25`, `LDR`+`BR`): the address of
    that pointer, not the target. None for every other hook and for no hook."""
    hit = _find_hook(live, base, view)
    return hit[2] if hit else None


def _live_number(live: bytes, view: str) -> int | None:
    """The syscall number the live stub loads, None where the stub does not show it."""
    if view == "x64":
        if live[:4] == b"\x4c\x8b\xd1\xb8" and len(live) >= 8:
            return int.from_bytes(live[4:8], "little")
    elif view == "arm64":
        w = _word(live)
        if w is not None and w & 0xFFE0001F == 0xD4000001:
            return (w >> 5) & 0xFFFF
    return None


def classify_stub(sc: Syscall, live: bytes | None, view: str, owner: str | None) -> dict:
    """Compare the live stub with the baseline and decide its state.

    Which of hooked, patched, diverged follows from `owner`, the module that holds the
    jump target ("private" for memory no file backs, None if unresolved), not from the
    instruction pattern: an EDR and malware use the same jumps. A module is named by its
    lower-case basename, as `ntdll.dll`; the caller normalises, nothing here does."""
    n = stub_prefix_len(sc, view)
    expected = sc.stub_bytes[:n]
    out = {
        "state": STATE_UNREADABLE,
        "pattern": None,
        "target_owner": None,
        "expected": expected.hex(),
        "actual": None if live is None else live[:n].hex(),
        "number_matches": None,
    }
    # a page that is not paged in reads as zeros, which says nothing about the stub
    if live is None or len(live) < n or not any(live[:n]):
        return out
    number = _live_number(live, view)
    out["number_matches"] = None if number is None else number == sc.number
    if live[:n] == expected:
        out["state"] = STATE_INTACT
        return out
    hit = _find_hook(live, 0, view)
    out["pattern"] = hit[0] if hit else None
    out["target_owner"] = owner
    if owner is None or owner in ("ntdll.dll", sc.module.lower()):
        out["state"] = STATE_DIVERGED
    elif owner == OWNER_PRIVATE:
        out["state"] = STATE_PATCHED
    else:
        out["state"] = STATE_HOOKED
    return out
