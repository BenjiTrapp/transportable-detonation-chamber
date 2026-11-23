"""The curated table from a Win32 function to the Nt syscall it reaches.

A sample that calls `VirtualAllocEx` never imports `NtAllocateVirtualMemory`, so its raw
import table cannot show that a syscall stub it carries goes around the documented path.
Run through this table, it can: the import set gains the Nt name of each Win32 function
the table knows.

The table is not a Win32 dictionary. It holds only the functions TDC already calls
suspicious, or whose Nt counterpart it does, and a function with no direct Nt counterpart
has no row. An absence is claimed only for a syscall some row leads to (`covered`): for
any other the table does not know the Win32 functions that reach it.

A proof assumes the table names the documented entry points to that syscall. An uncommon
wrapper to a covered syscall reads as a bypass: a false positive on an unusual but clean
program that carries a raw stub, never a false negative on malware. Each newly found entry
point widens the table; it does not change the rule.

Pure data logic, no Windows calls and no dependency on the rest of the web UI."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Iterable

SOURCES = ("zw-alias", "documented", "observed")
DEFAULT_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "win32_to_nt.json")


class TableError(ValueError):
    """The table file cannot be read or is not a table of version 1."""


@dataclass(frozen=True)
class Entry:
    """One curated step. `source` is one of SOURCES; `note` names where the mapping was read."""
    win32: str
    nt: str
    source: str
    note: str = ""


class Table:
    def __init__(self, entries: Iterable[Entry]):
        self.entries: tuple[Entry, ...] = tuple(entries)
        self._by_win32 = {e.win32.lower(): e for e in self.entries}
        # the syscalls whose absence the table can speak for: those a row leads to
        self.covered: frozenset[str] = frozenset(e.nt for e in self.entries)

    def nt_for(self, win32: str) -> Entry | None:
        """The row of `win32`, matched without regard to case, or None."""
        if not isinstance(win32, str):
            return None
        return self._by_win32.get(win32.lower())

    def expand(self, names: set[str] | None) -> set[str] | None:
        """`names` plus the Nt name of every Win32 function among them the table knows. Only a matched name adds
        anything: a set the table knows nothing of comes back as it went in. None (no import table) stays None."""
        if names is None:
            return None
        out = set(names)
        for name in names:
            entry = self.nt_for(name)
            if entry is not None:
                out.add(entry.nt)
        return out

    def missing_from(self, syscall_names: Iterable[str]) -> tuple[str, ...]:
        """The Nt names of the table that `syscall_names` does not hold, in table order. Against the baseline of a
        build (`table.missing_from(baseline.syscalls)`) it should be empty: a name it lists is no syscall there."""
        held = set(syscall_names)
        return tuple(dict.fromkeys(e.nt for e in self.entries if e.nt not in held))


def parse_table(payload) -> Table:
    """A Table from the decoded JSON `{"version": 1, "entries": [{win32, nt, source, note}, ...]}`."""
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise TableError("not a Win32 to Nt table of version 1")
    raw = payload.get("entries")
    if not isinstance(raw, list):
        raise TableError("the table has no list of entries")
    entries = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise TableError(f"entry #{i} is not an object")
        win32, nt, source, note = (item.get(k) for k in ("win32", "nt", "source", "note"))
        note = "" if note is None else note
        if not all(isinstance(v, str) for v in (win32, nt, source, note)) or not win32 or not nt:
            raise TableError(f"entry #{i} needs a win32 and an nt name, a source and a note as strings")
        if source not in SOURCES:
            raise TableError(f"entry #{i} ({win32}) has the source {source!r}, not one of {', '.join(SOURCES)}")
        entries.append(Entry(win32, nt, source, note))
    return Table(entries)


_tables: dict[str, Table] = {}


def load_table(path: str | None = None) -> Table:
    """The table in `path`, by default webui/win32_to_nt.json beside this module. Read once and held."""
    path = os.path.abspath(path or DEFAULT_TABLE_PATH)
    table = _tables.get(path)
    if table is None:
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError) as exc:
            raise TableError(f"cannot read {path}: {exc}") from exc
        table = _tables[path] = parse_table(payload)
    return table
