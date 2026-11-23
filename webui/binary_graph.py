"""The import and export tables of the system binaries, one plain record per PE.

What a file says about itself and nothing more: the modules and functions it imports, the names it defines and
the forwarders it exports as their raw strings. Resolving a forwarder or an api-ms-win-* name is left to the layers
above, which need the strings as the file wrote them.
"""

from __future__ import annotations

import mmap
import os
import struct
from dataclasses import dataclass

MACHINES = {0xAA64: "arm64", 0x8664: "x64", 0x14C: "x86"}
API_SET_SCHEMA_PATH = r"C:\Windows\System32\apisetschema.dll"
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


# The ApiSetMap, version 6 (Windows 10 and 11), in the `.apiset` section of apisetschema.dll. Every offset counts from
# the base of the map, every name is UTF-16LE and every length is in bytes; none of it is Microsoft-documented
_API_SET_VERSION = 6
_API_SET_HEADER = struct.Struct("<7I")      # Version, Size, Flags, Count, EntryOffset, HashOffset, HashFactor
_API_SET_ENTRY = struct.Struct("<6I")       # Flags, NameOffset, NameLength, HashedLength, ValueOffset, ValueCount
_API_SET_VALUE = struct.Struct("<5I")       # Flags, NameOffset, NameLength, ValueOffset, ValueLength


def _api_set_text(data, offset, length):
    """The UTF-16LE text at `offset`, or None when it is not wholly inside the map, not whole characters or not text."""
    if length % 2 or offset + length > len(data):
        return None
    try:
        return bytes(data[offset:offset + length]).decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def _api_set_hosts(data, offset, count):
    """The host modules of one entry in the map's order, or None when any value of it is unreadable, an empty host
    included: with one value lost, the default (value[0]) might be it, or an override would move into the default's
    place, and either way the chain resolves through the wrong module. Never relax this into partial acceptance."""
    end = offset + _API_SET_VALUE.size * count
    if not count or end > len(data):
        return None
    hosts = []
    for _, name_at, name_len, host_at, host_len in _API_SET_VALUE.iter_unpack(bytes(data[offset:end])):
        # the importer name is not used (the resolution is importer-independent, see parse_api_set_map), but must lie
        # inside the map too
        if name_len and _api_set_text(data, name_at, name_len) is None:
            return None
        host = _api_set_text(data, host_at, host_len)
        if not host:
            return None
        hosts.append(host)
    return tuple(hosts)


def parse_api_set_map(data: bytes) -> dict[str, tuple[str, ...]]:
    """alias (lower case, without ".dll") -> its host modules in the map's order, as the map names them.

    The hash table is not read: walking the entries is cheap. An unknown version gives an empty map. Every offset and
    length is hostile: an entry that does not lie wholly inside the map is dropped and the others are kept. Nothing
    raises. The map ends where its header's Size says, or at the end of `data` when Size is zero or larger than `data`.

    Three limits, all on purpose, all in the spec (Ziel 6). What is known of the map: value[0] of an entry is the
    default host, later values are overrides for particular importing modules. Not checked against a real loader: how
    it picks among them.
    - The resolution is importer-independent. A value's importer name is checked to lie inside the map and then
      ignored; every value's host is returned in the map's order, and the consumer resolves to the first host that
      defines the function. A chain may so pass a host the loader would use for a different importer than the one in
      the path: an edge between two real modules the map does associate, never an invented one. The order is not
      rearranged (a default put first would be made-up data).
    - One unreadable value, an empty host included, drops its whole entry, never only its host. With a value lost the
      default might be the one gone, or an override would move into the default's place: either way the chain would
      resolve through the wrong module. Do not relax this into partial acceptance.
    - The map is the window the header's Size gives (above), never a wider one."""
    if len(data) < _API_SET_HEADER.size:
        return {}
    version, size, _, count, entry_offset, _, _ = _API_SET_HEADER.unpack_from(data)
    if version != _API_SET_VERSION:
        return {}
    data = data[:size] if 0 < size <= len(data) else data       # a map that lies about its size gets no wider window
    count = min(count, max(0, len(data) - entry_offset) // _API_SET_ENTRY.size)
    aliases = {}
    for index in range(count):
        _, name_at, name_len, _, value_at, value_count = _API_SET_ENTRY.unpack_from(
            data, entry_offset + _API_SET_ENTRY.size * index)
        alias = _api_set_text(data, name_at, name_len)
        hosts = _api_set_hosts(data, value_at, value_count)
        if alias is None or hosts is None:
            continue
        alias = alias.lower()
        if alias.endswith(".dll"):
            alias = alias[:-len(".dll")]
        if alias:
            aliases.setdefault(alias, hosts)
    return aliases


def load_api_set_map(path: str) -> dict[str, tuple[str, ...]]:
    """The map in the `.apiset` section of the schema DLL at `path`; empty when the file, pefile or the section is
    missing, or the file is not one this can read. A graph without api-set resolution is degraded, not broken."""
    try:
        import pefile
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if not 0 < size <= MAX_BINARY_SIZE:
                return {}
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as image:
                pe = pefile.PE(data=image, fast_load=True)
                try:
                    for section in pe.sections:
                        if section.Name.rstrip(b"\0") == b".apiset":
                            return parse_api_set_map(section.get_data())
                finally:
                    pe.close()
    except Exception:
        return {}
    return {}


def split_forwarder(raw: str) -> tuple[str, str]:
    """`"NTDLL.RtlAllocateHeap"` -> `("ntdll.dll", "RtlAllocateHeap")`; `("", "")` when the string names no module and
    function (empty, no dot, or nothing on one side of it).

    Split at the LAST dot, never the first: an api-set name has dots of its own ("api-ms-win-core-heap-l1-1-0")."""
    module, dot, function = raw.rpartition(".")
    if not dot or not module or not function:
        return "", ""
    module = module.lower()
    return (module if module.endswith(".dll") else module + ".dll"), function


MAX_HOPS = 16       # a chain longer than this is reported as such, however it ends


@dataclass(frozen=True)
class Hop:
    module: str                             # lower case, with its extension; an api-set alias keeps its ".dll"
    function: str                           # as the file that led here wrote it, an ordinal as "#<n>"
    via: str                                # "forwards_to" (an export's forwarder) | "resolves_to" (an api-set host)


@dataclass(frozen=True)
class Resolution:
    """Where a `(module, function)` ends up. `reason` is a machine token, not prose:
    "defined"            module and function are set: that module defines the function itself. `function` is the
                         key into its `exports` (a nameless export "#<n>"), which may differ from the last hop's
                         when a forwarder named the ordinal of an export that has a name
    "missing"            the chain led to a module not in the graph, or one that does not offer the function (a
                         `partial` module, whose export table was cut short, is not told apart from a complete one)
    "cycle"              the chain came back to a (module, function) it had been at; the last hop closes the ring
    "unresolved-api-set" the chain reached an api-set name the map has no entry for: our map is missing or old
    "too-many-hops"      the chain is longer than MAX_HOPS and neither ring nor dead end within it
    `hops` are the steps taken, the start not among them; on any outcome but "defined" they are how far it got.

    `partial` is not an outcome but a caveat on it: True when a table on this chain was cut short, that is, when any
    binary the walk examined (the start, every module it passed, every api-set host it tried and passed over) has
    `BinaryInfo.partial` set. A negative answer ("missing", "unresolved-api-set", "cycle", "too-many-hops") is then
    NOT certain, since the export or forwarder that would have changed it may be in the part pefile did not read; a
    "defined" one only says the host chosen may not be the one a complete table would have given. It does not mean
    "partially resolved". The same fact makes no difference to which `reason` is given."""
    hops: tuple[Hop, ...]
    module: str | None
    function: str | None
    reason: str
    partial: bool = False


def _export_key(info, function):
    """The key `function` has in `info.exports` or `info.forwarders`, None when the image offers no such export.

    "#<n>" is the ordinal n, which is a key itself for a nameless export and otherwise names an export through
    `ordinal_names`."""
    keys = [function]
    digits = function[1:]
    if function.startswith("#") and digits.isascii() and digits.isdecimal():
        try:
            name = info.ordinal_names.get(int(digits))
        except ValueError:                  # more digits than int() is willing to read
            name = None
        if name:
            keys.append(name)
    for key in keys:
        if key in info.exports or key in info.forwarders:
            return key
    return None


def _is_api_set(api_sets, module):
    stem = module[:-len(".dll")] if module.endswith(".dll") else module
    return stem, stem in api_sets or stem.startswith(("api-", "ext-"))


def _step(binaries, api_sets, module, function, cut_short):
    """One step from `(module, function)`: `(Hop, None, None)` to go on, or `(None, reason, key)` to stop; `key` is
    the export key of a "defined" end. `cut_short` is set to True when a binary examined has `partial`."""
    stem, api_set = _is_api_set(api_sets, module)
    if api_set:
        hosts = api_sets.get(stem)
        if not hosts:
            return None, "unresolved-api-set", None
        for host in hosts:
            host = host.lower()
            if host not in binaries:
                continue
            cut_short.append(binaries[host].partial)
            if _export_key(binaries[host], function) is not None:
                return Hop(host, function, "resolves_to"), None, None
        return None, "missing", None
    info = binaries.get(module)
    if info is not None:
        cut_short.append(info.partial)
    key = _export_key(info, function) if info is not None else None
    if key is None:
        return None, "missing", None
    if key not in info.forwarders:
        return None, "defined", key
    target, target_function = split_forwarder(info.forwarders[key])
    if not target:
        return None, "missing", None
    return Hop(target, target_function, "forwards_to"), None, None


def resolve_export(binaries: dict[str, BinaryInfo], api_sets: dict[str, tuple[str, ...]],
                   module: str, function: str) -> Resolution:
    """Follow `function` of `module` through forwarders and api-set aliases to the module that defines it.

    `binaries` is keyed by lower-case file name. An api set is resolved to the first of its hosts, in the map's order,
    that is in the graph and offers the function (as a definition or as a forwarder): the importer-independent reading
    parse_api_set_map describes. Nothing raises, whatever a forwarder string or a name looks like.

    A ring is found by remembering every (module, function) the chain has stood at, so it ends as "cycle" however long
    it is. MAX_HOPS is a limit on the chain, not the ring detector: the walk goes on past it, still stopped by that
    memory, so that a ring longer than the limit is not called merely long. `Resolution.partial` is set when any binary
    the walk examined has `BinaryInfo.partial`, the walk past MAX_HOPS included."""
    module = module.lower()
    seen = {(module, function)}
    hops = []
    cut_short = []
    while True:
        hop, reason, key = _step(binaries, api_sets, module, function, cut_short)
        if hop is None:
            break
        hops.append(hop)
        module, function = hop.module, hop.function
        if (module, function) in seen:
            return Resolution(tuple(hops), None, None, "cycle", any(cut_short))
        seen.add((module, function))
    partial = any(cut_short)
    if len(hops) > MAX_HOPS:
        return Resolution(tuple(hops[:MAX_HOPS]), None, None, "too-many-hops", partial)
    if reason == "defined":
        return Resolution(tuple(hops), module, key, "defined", partial)
    return Resolution(tuple(hops), None, None, reason, partial)


def resolve_all(binaries: dict[str, BinaryInfo],
                api_sets: dict[str, tuple[str, ...]]) -> dict[tuple[str, str], Resolution]:
    """`(module, export name)` -> its Resolution, for every forwarder export of every binary; one answer each.

    The cache build asks the same chain through many importers; this is where that repetition is bundled."""
    answers = {}
    for module, info in binaries.items():
        module = module.lower()
        for name in info.forwarders:
            if (module, name) not in answers:
                answers[(module, name)] = resolve_export(binaries, api_sets, module, name)
    return answers
