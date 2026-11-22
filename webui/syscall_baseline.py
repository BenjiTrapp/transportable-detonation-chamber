"""Syscall baseline: the NTSleuth JSON of ntdll.dll / win32u.dll read into objects.

Pure Python; later measured against the stubs of a running process.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

_FILENAME_RE = re.compile(r"^ntsleuth-(?P<build>[^-]+)-(?P<view>arm64|x64)\.json$")


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


def parse_baseline(payload: list | dict, build: str, view: str) -> Baseline:
    """Entries that cannot be measured are skipped (and named in `skipped`), never fatal:
    one malformed entry must not take the whole baseline down.

    NTSleuth's README does not fix the top level, so both a bare list of entries and
    `{"syscalls": [...]}` are accepted."""
    raw = payload.get("syscalls") if isinstance(payload, dict) else payload
    if not isinstance(raw, list):
        raise BaselineError("baseline is neither a list of entries nor has a 'syscalls' list")
    bl = Baseline(build=build, view=view)
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
    """Build and view come from the file name `ntsleuth-<build>-<view>.json`."""
    m = _FILENAME_RE.match(os.path.basename(path))
    if not m:
        raise BaselineError(f"{path}: not named ntsleuth-<build>-<view>.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    return parse_baseline(payload, m.group("build"), m.group("view"))


def find_baseline(directory: str, build: str, view: str) -> str | None:
    """Path of `ntsleuth-<build>-<view>.json` in `directory`, or None."""
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
