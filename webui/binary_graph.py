"""The import and export tables of the system binaries, one plain record per PE.

What a file says about itself and nothing more: the modules and functions it imports, the names it defines and
the forwarders it exports as their raw strings. Resolving a forwarder or an api-ms-win-* name is left to the layers
above, which need the strings as the file wrote them.
"""

from __future__ import annotations

import json
import mmap
import os
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

MACHINES = {0xAA64: "arm64", 0x8664: "x64", 0x14C: "x86"}
SYSTEM32 = r"C:\Windows\System32"
API_SET_SCHEMA_PATH = SYSTEM32 + r"\apisetschema.dll"
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
    "missing"            the chain led to a module not in the graph, or one that does not offer the function (see
                         `partial`: where a table was cut short, that is not certain)
    "cycle"              the chain came back to a (module, function) it had been at; the last hop closes the ring
    "unresolved-api-set" the chain reached an api-set name the map has no entry for: our map is missing or old
    "too-many-hops"      the chain is longer than MAX_HOPS and neither ring nor dead end within it
    `hops` are the steps taken, the start not among them; on any outcome but "defined" they are how far it got.

    `partial` is not an outcome but a caveat on it: True when a table on this chain was cut short, that is, when any
    binary the walk examined (the start, every module it passed, every api-set host it tried and passed over) has
    `BinaryInfo.partial` set. A negative answer ("missing", "unresolved-api-set", "cycle", "too-many-hops") is then
    NOT certain, since the export or forwarder that would have changed it may be in the part pefile did not read; a
    "defined" one only says the host chosen may not be the one a complete table would have given. It does not mean
    "partially resolved"; `reason` is the same with or without it."""
    hops: tuple[Hop, ...]
    module: str | None
    function: str | None
    reason: str
    partial: bool = False


def _export_key(info, exports, function):
    """The key `function` has in `info.exports` or `info.forwarders`, None when the image offers no such export.
    `exports` is `frozenset(info.exports)`, which spares a scan of the tuple per question.

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
        if key in exports or key in info.forwarders:
            return key
    return None


def _api_set_lookup(api_sets, stem):
    """The hosts of the api set `stem` (lower case, without ".dll"), None when the map has none for it.

    The exact name first. Failing that, the first entry of the same family: the loader hashes an api-set name up to but
    not including its last hyphen (the entry's `HashedLength`), so "...-l1-1-0" and "...-l1-1-1" are one entry for it,
    and a forwarder may name a version the map does not hold by that name. We compare the truncated names directly
    instead of reading the hash table, since the entries are walked anyway; the scan only runs on a miss, and only for
    a name the loader would treat as an api set. The error direction is chosen: an exact-only lookup fails toward a
    dead chain (a false "unresolved-api-set"), this one toward a neighbouring version of the same family, whose hosts
    are the same module in practice; the second is the better failure."""
    hosts = api_sets.get(stem)
    if hosts is None and stem.startswith(("api-", "ext-")):
        family = stem.rpartition("-")[0]
        if family:
            for alias, candidate in api_sets.items():
                if alias.rpartition("-")[0] == family:
                    return candidate
    return hosts


def _step(binaries, api_sets, module, function, cut_short, exports):
    """One step from `(module, function)`: `(Hop, None, None)` to go on, or `(None, reason, key)` to stop; `key` is
    the export key of a "defined" end.

    `cut_short` is a list this appends the `partial` of every binary it examines to, an api-set host passed over
    included. `exports` is a dict, file name -> frozenset of that binary's `exports`, filled as binaries are met."""
    def exported(name, info):
        if name not in exports:
            exports[name] = frozenset(info.exports)
        return exports[name]

    stem = module[:-len(".dll")] if module.endswith(".dll") else module
    hosts = _api_set_lookup(api_sets, stem)
    if hosts is not None or stem.startswith(("api-", "ext-")):
        if not hosts:
            return None, "unresolved-api-set", None
        for host in hosts:
            host = host.lower()
            if host not in binaries:
                continue
            cut_short.append(binaries[host].partial)
            if _export_key(binaries[host], exported(host, binaries[host]), function) is not None:
                return Hop(host, function, "resolves_to"), None, None
        return None, "missing", None
    info = binaries.get(module)
    key = None
    if info is not None:
        cut_short.append(info.partial)
        key = _export_key(info, exported(module, info), function)
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
    return _resolve(binaries, api_sets, module, function, {})


def _resolve(binaries, api_sets, module, function, exports):
    module = module.lower()
    seen = {(module, function)}
    hops = []
    cut_short = []
    while True:
        hop, reason, key = _step(binaries, api_sets, module, function, cut_short, exports)
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
    answers, exports = {}, {}
    for module, info in binaries.items():
        module = module.lower()
        for name in info.forwarders:
            if (module, name) not in answers:
                answers[(module, name)] = _resolve(binaries, api_sets, module, name, exports)
    return answers


# --- the cache: one JSON file per build and architecture, beside the syscall baselines --------------------------------

CACHE_FORMAT = 1
_CACHE_BUILD_RE = re.compile(r"[0-9A-Za-z.]+")
_CACHE_ARCH_RE = re.compile(r"[0-9A-Za-z]+")


class CacheMismatch(Exception):
    """A cache this system cannot use. `reason` is a fixed token, never prose of a library or the OS:
    "other build" and "other architecture" (the cache is sound, but drawn for another system: `held_build` and
    `held_arch` say which), "unknown format", "malformed" (not JSON, cut short, or of a shape that cannot be read)
    and "unreadable" (the file cannot be opened). Nothing else escapes load_graph for a damaged file."""

    def __init__(self, reason, message, held_build=None, held_arch=None):
        super().__init__(message)
        self.reason = reason
        self.held_build = held_build
        self.held_arch = held_arch


@dataclass(frozen=True)
class Graph:
    build: str                                          # CurrentBuildNumber.UBR of the system it was built on
    arch: str                                           # "arm64" | "x64": the host's, not one process's view of it
    created: str                                        # ISO-8601, UTC
    binaries: dict[str, BinaryInfo]                     # lower-case file name -> record
    api_sets: dict[str, tuple[str, ...]]
    resolved: dict[tuple[str, str], Resolution]         # (module, forwarder export) -> where it ends up
    in_degree: dict[str, int]                           # imported module -> how many binaries import it
    skipped: tuple[tuple[str, str], ...]                # (file name, reason) of what extract_tree could not read


def cache_name(build: str, arch: str) -> str:
    """`binary-graph-<build>-<arch>.json`. The prefix keeps it from `ntsleuth-<build>-<view>.json`, which sits in the
    same directory. A build or architecture that is more than plain name characters raises ValueError: both can come
    from a command line, and neither may name another path."""
    if not (_CACHE_BUILD_RE.fullmatch(build) and _CACHE_ARCH_RE.fullmatch(arch)):
        raise ValueError("a cache is named by a build and an architecture of plain name characters")
    return f"binary-graph-{build}-{arch}.json"


def find_cache(directory: str, build: str, arch: str) -> str | None:
    """Path of the cache of this build and architecture in `directory`, or None."""
    try:
        path = os.path.join(directory, cache_name(build, arch))
    except (ValueError, TypeError):
        return None
    return path if os.path.isfile(path) else None


def build_graph(directory: str, api_set_path: str, build: str, arch: str) -> Graph:
    """The graph of every PE directly in `directory`, with the forwarders resolved through the api-set map at
    `api_set_path` (an empty map when it cannot be read: a degraded graph, not a broken one).

    `in_degree` counts binaries, not import entries: a module's value is how many binaries import it, whether by one
    function or by a hundred, and delay-loaded imports count as imports. It is keyed by the module name as the
    importers wrote it, an api-set alias included, whether or not the graph holds that module."""
    found, skipped = extract_tree(directory)
    binaries = {info.name: info for info in found}
    api_sets = load_api_set_map(api_set_path)
    in_degree = {}
    for info in binaries.values():
        for module in info.imports:
            in_degree[module] = in_degree.get(module, 0) + 1
    return Graph(build=build, arch=arch, created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 binaries=binaries, api_sets=api_sets, resolved=resolve_all(binaries, api_sets),
                 in_degree=in_degree, skipped=tuple(skipped))


def _document(graph):
    """The JSON object of a graph. The stamp comes first and the tuple keys of `resolved` become a list of records;
    the file's keys are `ordinal_names`' integers as text, which load_graph turns back."""
    return {
        "format": CACHE_FORMAT, "build": graph.build, "arch": graph.arch, "created": graph.created,
        "binaries": {key: {"name": info.name, "kind": info.kind, "machine": info.machine,
                           "imports": {module: list(names) for module, names in info.imports.items()},
                           "exports": list(info.exports), "forwarders": dict(info.forwarders),
                           "ordinal_names": {str(ordinal): name for ordinal, name in info.ordinal_names.items()},
                           "partial": info.partial}
                     for key, info in graph.binaries.items()},
        "api_sets": {alias: list(hosts) for alias, hosts in graph.api_sets.items()},
        "resolved": [{"module": module, "name": name, "reason": res.reason, "target_module": res.module,
                      "target_function": res.function, "partial": res.partial,
                      "hops": [[hop.module, hop.function, hop.via] for hop in res.hops]}
                     for (module, name), res in graph.resolved.items()],
        "in_degree": dict(graph.in_degree),
        "skipped": [list(pair) for pair in graph.skipped],
    }


def save_graph(graph: Graph, path: str) -> None:
    """Write the cache to `path`, whole or not at all: it is written beside its name and moved over it, so the web UI
    never reads half a file and a failed write leaves the earlier cache alone."""
    text = json.dumps(_document(graph), separators=(",", ":"))
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise


def _malformed():
    return CacheMismatch("malformed", "the cache file is not a graph this code can read")


def _check(condition):
    if not condition:
        raise ValueError


def _decode(doc):
    """The Graph a document describes; ValueError, KeyError or TypeError for anything that is not one. Strings are
    shared (a function name is imported by thousands of binaries), which keeps a 4,000-binary graph's memory down."""
    pool = {}

    def text(value):
        _check(type(value) is str)
        return pool.setdefault(value, value)

    def texts(value):
        _check(type(value) is list)
        return tuple(text(item) for item in value)

    def mapping(value):
        _check(type(value) is dict)
        return value

    def flag(value):
        _check(type(value) is bool)
        return value

    def optional(value):
        return None if value is None else text(value)

    binaries = {}
    for key, entry in mapping(doc["binaries"]).items():
        entry = mapping(entry)
        ordinals = {}
        for ordinal, name in mapping(entry["ordinal_names"]).items():
            _check(ordinal.isascii() and ordinal.isdecimal())
            ordinals[int(ordinal)] = text(name)
        binaries[text(key)] = BinaryInfo(
            name=text(entry["name"]), kind=text(entry["kind"]), machine=text(entry["machine"]),
            imports={text(module): texts(names) for module, names in mapping(entry["imports"]).items()},
            exports=texts(entry["exports"]),
            forwarders={text(name): text(raw) for name, raw in mapping(entry["forwarders"]).items()},
            ordinal_names=ordinals, partial=flag(entry["partial"]))
    resolved = {}
    _check(type(doc["resolved"]) is list)
    for entry in doc["resolved"]:
        entry = mapping(entry)
        hops = []
        _check(type(entry["hops"]) is list)
        for hop in entry["hops"]:
            _check(type(hop) is list and len(hop) == 3)
            hops.append(Hop(text(hop[0]), text(hop[1]), text(hop[2])))
        resolved[(text(entry["module"]), text(entry["name"]))] = Resolution(
            tuple(hops), optional(entry["target_module"]), optional(entry["target_function"]),
            text(entry["reason"]), flag(entry["partial"]))
    in_degree = {}
    for module, count in mapping(doc["in_degree"]).items():
        _check(type(count) is int and count >= 0)
        in_degree[text(module)] = count
    skipped = []
    _check(type(doc["skipped"]) is list)
    for pair in doc["skipped"]:
        _check(type(pair) is list and len(pair) == 2)
        skipped.append((text(pair[0]), text(pair[1])))
    return Graph(build=text(doc["build"]), arch=text(doc["arch"]), created=text(doc["created"]), binaries=binaries,
                 api_sets={text(alias): texts(hosts) for alias, hosts in mapping(doc["api_sets"]).items()},
                 resolved=resolved, in_degree=in_degree, skipped=tuple(skipped))


def load_graph(path: str, build: str, arch: str) -> Graph:
    """The graph at `path`, for this `build` and `arch` only; anything else raises CacheMismatch, and nothing else.

    The stamp is read before the body: a cache of another build or architecture is refused as such, naming the build
    and architecture it holds, even when its body would not have decoded. An x64 graph shown on an ARM64 VM would be
    worse than none, so a stamp that is not exactly this system's is never "close enough". A file that is cut short,
    not JSON or of the wrong shape is "malformed"."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        raise CacheMismatch("unreadable", "the cache file cannot be opened") from None
    try:
        doc = json.loads(raw)
        _check(type(doc) is dict)
        stamp = (doc["format"], doc["build"], doc["arch"])
    except Exception:
        raise _malformed() from None
    if stamp[0] != CACHE_FORMAT or type(stamp[0]) is not int:
        raise CacheMismatch("unknown format", "the cache file is of a format this code does not know")
    held_build, held_arch = stamp[1], stamp[2]
    if type(held_build) is not str or type(held_arch) is not str:
        raise _malformed()
    if held_build != build:
        raise CacheMismatch("other build", f"the cache holds build {held_build} ({held_arch}), not {build} ({arch})",
                            held_build, held_arch)
    if held_arch != arch:
        raise CacheMismatch("other architecture",
                            f"the cache holds build {held_build} for {held_arch}, not for {arch}", held_build, held_arch)
    try:
        return _decode(doc)
    except Exception:
        raise _malformed() from None


# --- the command line the provisioning script calls --------------------------------------------------------------

def host_build() -> str | None:
    r"""`<build>.<revision>` of the running system, the form the baselines are named in, or None off Windows."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            number = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            revision = winreg.QueryValueEx(key, "UBR")[0]
    except (ImportError, OSError):
        return None
    return f"{number}.{revision}"


_ARCH_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def _registry_string(subkey, name):
    r"""The REG_SZ `name` under `HKLM\<subkey>`, None when there is no registry (not Windows) or it cannot be read."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
            return winreg.QueryValueEx(key, name)[0]
    except (ImportError, OSError):
        return None


def host_arch(read_registry=_registry_string) -> str:
    r""""arm64" or "x64": the architecture of the system, not of the interpreter asking.

    It comes from PROCESSOR_ARCHITECTURE under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment,
    never from `platform.machine()`: the web UI's Python can be an x64 build running under emulation on an ARM64
    system, and there `platform.machine()` says "AMD64". install-ntsleuth.ps1 reads the registry for the same reason.
    There is exactly one cache, named by this value, so a wrong answer is not a wrong default view that the user can
    switch: it is no graph at all, with a good cache on disk under the other name. Callers that choose which cache to
    load must use this, and not the syscall tab's `_syscall_default_view()`, which has the weaker reading.

    `read_registry(subkey, name)` is the seam: it returns the value, or None when it cannot be read; a test drives it
    without Windows. When the registry gives no answer this module knows (off Windows, the key missing, a value other
    than ARM64 or AMD64), the interpreter's own `platform.machine()` stands in."""
    try:
        held = read_registry(_ARCH_KEY, "PROCESSOR_ARCHITECTURE")
    except (ImportError, OSError):
        held = None
    if isinstance(held, str) and held.upper() in ("ARM64", "AMD64"):
        return "arm64" if held.upper() == "ARM64" else "x64"
    import platform
    return "arm64" if platform.machine().upper() in ("ARM64", "AARCH64") else "x64"


def _arguments(argv):
    """`{option: value}` of `--out`, `--system32`, `--build` and `--arch`, None for anything else."""
    known = ("--out", "--system32", "--build", "--arch")
    if len(argv) % 2 or any(option not in known for option in argv[::2]) or len(set(argv[::2])) != len(argv) // 2:
        return None
    return dict(zip(argv[::2], argv[1::2]))


def main(argv=None) -> int:
    """`binary_graph.py --out <dir> [--system32 <dir>] [--build <b>] [--arch <a>]`: build the cache and write it to
    `<dir>`. One `name: number` line per count on stdout, then `cache: <path>`; the reason of a failure goes to stderr.
    Returns 0 on success and 1 otherwise, a directory without a PE in it included: a graph of nothing is not written.
    The api-set map is read from `apisetschema.dll` of the directory."""
    options = _arguments(sys.argv[1:] if argv is None else list(argv))
    if options is None or "--out" not in options:
        print("usage: binary_graph.py --out <dir> [--system32 <dir>] [--build <b>] [--arch <a>]", file=sys.stderr)
        return 1
    system32 = options.get("--system32", SYSTEM32)
    build = options.get("--build") or host_build()
    arch = options.get("--arch") or host_arch()
    if not build:
        print("the build of this system cannot be read: pass --build", file=sys.stderr)
        return 1
    try:
        name = cache_name(build, arch)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    graph = build_graph(system32, os.path.join(system32, "apisetschema.dll"), build, arch)
    for label, count in (("binaries", len(graph.binaries)), ("skipped", len(graph.skipped)),
                         ("api_sets", len(graph.api_sets)), ("resolved", len(graph.resolved)),
                         ("modules", len(graph.in_degree))):
        print(f"{label}: {count}")
    if not graph.binaries:
        print("no PE could be read in " + system32, file=sys.stderr)
        return 1
    target = os.path.join(options["--out"], name)
    try:
        os.makedirs(options["--out"], exist_ok=True)
        save_graph(graph, target)
    except OSError as exc:
        print(f"the cache cannot be written ({exc.__class__.__name__})", file=sys.stderr)
        return 1
    print(f"cache: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
