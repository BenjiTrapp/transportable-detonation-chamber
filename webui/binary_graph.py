"""The import and export tables of the system binaries, one plain record per PE.

What a file says about itself and nothing more: the modules and functions it imports, the names it defines and
the forwarders it exports as their raw strings. Resolving a forwarder or an api-ms-win-* name is left to the layers
above, which need the strings as the file wrote them.
"""

from __future__ import annotations

import mmap
import os
from dataclasses import dataclass

MACHINES = {0xAA64: "arm64", 0x8664: "x64", 0x14C: "x86"}
MAX_BINARY_SIZE = 512 * 2**20          # System32's largest image is a fraction of this; a sample may not be

# every reason a file is skipped for: fixed strings of our own, so they can be counted and grouped. Never a library's,
# the OS's or its locale's wording, which drifts; the file name is in the pair for whoever opens that one by hand
REASONS = ("not a PE", "empty file", "larger than the size cap", "cannot be opened", "pefile is not available",
           "unreadable import directory", "unreadable delay-load directory", "unreadable export directory",
           "malformed", "the same name in another case", "cannot be listed")


class ExtractError(Exception):
    """A file that yields no record; the message is the short reason it was skipped."""


@dataclass(frozen=True)
class BinaryInfo:
    name: str                               # lower case, with its extension
    kind: str                               # "dll" | "exe"
    machine: str                            # "arm64" | "x64" | "x86" | "other"
    imports: dict[str, tuple[str, ...]]     # module, lower case -> functions, an ordinal as "#<n>"
    exports: tuple[str, ...]                # what this image defines itself, a nameless export as "#<ordinal>"
    forwarders: dict[str, str]              # export name or "#<ordinal>" -> the raw string, "NTDLL.RtlAllocateHeap"
    ordinal_names: dict[int, str]           # ordinal -> name of every named export, forwarders included
    partial: bool                           # a directory warned and kept what it read: tables may be cut short


def _text(raw):
    return raw.decode("ascii", "replace")


def _imports(pe):
    out = {}
    for table in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, table, None) or []:
            if not entry.dll:
                continue
            names = out.setdefault(_text(entry.dll).lower(), {})
            for imp in entry.imports:
                # by ordinal, whatever name pefile's own lookup (ws2_32, oleaut32) supplies: the file names a number
                if imp.import_by_ordinal:
                    name = f"#{imp.ordinal}" if imp.ordinal is not None else None
                else:
                    name = _text(imp.name) if imp.name else None
                if name is not None:
                    names[name] = None
    return {module: tuple(names) for module, names in out.items()}


def _exports(pe):
    """`(exports, forwarders, ordinal_names)`: a nameless export is named by its ordinal, "#<n>", as an import by
    ordinal is; ordinal_names turns such a number back into a name where the image gives one."""
    exports, forwarders, ordinal_names = {}, {}, {}
    for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", None) or []:
        if sym.name:
            name = _text(sym.name)
            if sym.ordinal is not None:
                ordinal_names[sym.ordinal] = name
        elif sym.ordinal is not None:
            name = f"#{sym.ordinal}"
        else:
            continue
        if sym.forwarder:
            forwarders[name] = _text(sym.forwarder)
        else:
            exports[name] = None
    return tuple(exports), forwarders, ordinal_names


def _is_dll(pe):
    """Whether IMAGE_FILE_DLL is set, None when the header yields no characteristics."""
    characteristics = getattr(getattr(pe, "FILE_HEADER", None), "Characteristics", None)
    return None if characteristics is None else bool(characteristics & 0x2000)


# the directories the record is read from: pefile's index, the attribute it sets, the reason a refusal is skipped for
DIRECTORIES = (("IMAGE_DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_IMPORT", "unreadable import directory"),
               ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT", "unreadable delay-load directory"),
               ("IMAGE_DIRECTORY_ENTRY_EXPORT", "DIRECTORY_ENTRY_EXPORT", "unreadable export directory"))


def _parse_directories(pefile, pe):
    """Parse the import, delay-load and export directories one at a time; True when one of them is partial.

    Per directory, only whether its own parse warned counts, never what the warning says. A declared directory that
    warned and yielded no entry is refused (ExtractError); one that warned and yielded entries is kept as partial,
    since pefile stops early (at 120 repeated nameless exports, say) and keeps what it read. An empty table without
    a warning is read as empty; a fault elsewhere in the file (a section cut short, say) is pefile's to tolerate."""
    # pefile refuses a truncated directory by warning, not by raising. Should an upgrade stop warning, a truncated PE
    # would read as one that imports nothing: test_a_pe_truncated_after_its_headers_is_skipped_and_does_not_raise,
    # test_a_directory_pefile_cannot_read_skips_only_when_it_is_one_the_record_needs and
    # test_a_parse_that_warned_and_still_produced_entries_is_kept_and_marked_partial are the tripwire for that
    declared = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    partial = False
    for index_name, attribute, reason in DIRECTORIES:
        index = pefile.DIRECTORY_ENTRY[index_name]
        before = len(pe.get_warnings())
        pe.parse_data_directories(directories=[index])
        if len(pe.get_warnings()) == before:
            continue
        if getattr(pe, attribute, None):
            partial = True
        elif index < len(declared) and declared[index].VirtualAddress:
            raise ExtractError(reason)
    return partial


def extract_binary(path: str) -> BinaryInfo:
    """The record of the PE at `path`; raises ExtractError with a short reason when it cannot be read.

    The file is mapped, never read whole, and refused above MAX_BINARY_SIZE; only the headers and the import,
    delay-load and export directories are parsed."""
    name = os.path.basename(path).lower()
    try:
        import pefile
    except ImportError:
        raise ExtractError("pefile is not available") from None
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size > MAX_BINARY_SIZE:
                raise ExtractError("larger than the size cap")
            if size == 0:
                raise ExtractError("empty file")
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
                return _record(pefile, name, data)
    except ExtractError:
        raise
    except OSError:
        raise ExtractError("cannot be opened") from None
    except Exception:
        raise ExtractError("malformed") from None


def _record(pefile, name, data):
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        raise ExtractError("not a PE") from None
    try:
        partial = _parse_directories(pefile, pe)
        exports, forwarders, ordinal_names = _exports(pe)
        dll = _is_dll(pe)
        if dll is None:
            dll = not name.endswith(".exe")
        return BinaryInfo(name=name, kind="dll" if dll else "exe",
                          machine=MACHINES.get(pe.FILE_HEADER.Machine, "other"), imports=_imports(pe),
                          exports=exports, forwarders=forwarders, ordinal_names=ordinal_names,
                          partial=partial)
    finally:
        pe.close()


def extract_tree(directory: str) -> tuple[list[BinaryInfo], list[tuple[str, str]]]:
    """Every *.dll and *.exe directly in `directory` (no subdirectories), sorted by name, and the files skipped as
    `(file name, reason)`. Nothing raises: a file that cannot be read is a skipped one."""
    try:
        names = sorted(os.listdir(directory), key=lambda n: (n.lower(), n))
    except OSError:
        return [], [(directory, "cannot be listed")]
    binaries, skipped, seen = [], [], set()
    for name in names:
        if not name.lower().endswith((".dll", ".exe")):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if name.lower() in seen:
            skipped.append((name, "the same name in another case"))
            continue
        seen.add(name.lower())
        try:
            binaries.append(extract_binary(path))
        except ExtractError as exc:
            skipped.append((name, str(exc)))
    return binaries, skipped
