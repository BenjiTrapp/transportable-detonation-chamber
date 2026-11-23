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


class ExtractError(Exception):
    """A file that yields no record; the message is the short reason it was skipped."""


@dataclass(frozen=True)
class BinaryInfo:
    name: str                               # lower case, with its extension
    kind: str                               # "dll" | "exe"
    machine: str                            # "arm64" | "x64" | "x86" | "other"
    imports: dict[str, tuple[str, ...]]     # module, lower case -> functions, an ordinal as "#<n>"
    exports: tuple[str, ...]                # the names this image defines itself
    forwarders: dict[str, str]              # export name -> the raw forwarder string, "NTDLL.RtlAllocateHeap"


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
    exports, forwarders = {}, {}
    for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", None) or []:
        if not sym.name:
            continue
        name = _text(sym.name)
        if sym.forwarder:
            forwarders[name] = _text(sym.forwarder)
        else:
            exports[name] = None
    return tuple(exports), forwarders


def _size_text(n):
    return f"{n // 2**20} MiB" if n >= 2**20 else f"{n} bytes"


def _truncated(pe, size):
    """The first section whose raw data runs past the end of a file of `size` bytes, or None."""
    for section in pe.sections:
        if section.PointerToRawData + section.SizeOfRawData > size:
            return _text(section.Name.rstrip(b"\0")) or "?"
    return None


def extract_binary(path: str) -> BinaryInfo:
    """The record of the PE at `path`; raises ExtractError with a short reason when it cannot be read.

    The file is mapped, never read whole, and refused above MAX_BINARY_SIZE; only the headers and the import,
    delay-load and export directories are parsed."""
    import pefile
    name = os.path.basename(path).lower()
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size > MAX_BINARY_SIZE:
                raise ExtractError(f"larger than {_size_text(MAX_BINARY_SIZE)}")
            if size == 0:
                raise ExtractError("not a PE: the file is empty")
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
                return _record(pefile, name, data, size)
    except ExtractError:
        raise
    except OSError as exc:
        raise ExtractError(f"cannot be opened: {exc.strerror or type(exc).__name__}") from None
    except Exception as exc:
        raise ExtractError(f"malformed: {type(exc).__name__}") from None


def _record(pefile, name, data, size):
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise ExtractError(f"not a PE: {str(exc.value).strip()}") from None
    try:
        section = _truncated(pe, size)
        if section is not None:
            raise ExtractError(f"truncated: section {section} runs past the end of the file")
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                               pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                                               pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exports, forwarders = _exports(pe)
        return BinaryInfo(name=name, kind="exe" if name.endswith(".exe") else "dll",
                          machine=MACHINES.get(pe.FILE_HEADER.Machine, "other"),
                          imports=_imports(pe), exports=exports, forwarders=forwarders)
    finally:
        pe.close()


def extract_tree(directory: str) -> tuple[list[BinaryInfo], list[tuple[str, str]]]:
    """Every *.dll and *.exe directly in `directory` (no subdirectories), sorted by name, and the files skipped as
    `(file name, reason)`. Nothing raises: a file that cannot be read is a skipped one."""
    try:
        names = sorted(os.listdir(directory), key=lambda n: (n.lower(), n))
    except OSError as exc:
        return [], [(directory, f"cannot be listed: {exc.strerror or type(exc).__name__}")]
    binaries, skipped, seen = [], [], set()
    for name in names:
        if not name.lower().endswith((".dll", ".exe")):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if name.lower() in seen:
            skipped.append((name, f"the same name as {name.lower()} in another case"))
            continue
        seen.add(name.lower())
        try:
            binaries.append(extract_binary(path))
        except ExtractError as exc:
            skipped.append((name, str(exc)))
    return binaries, skipped
