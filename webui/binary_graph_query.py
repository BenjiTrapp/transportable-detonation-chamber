"""The questions the SYSCALLS tab asks of the import graph, each answered as nodes and edges ready to draw.

Every query returns an `Answer`; none raises for a name it does not know. An answer that finds nothing has no nodes and
a `note` that says why, never a bare empty answer that a view would draw as "no edges". An answer larger than
MAX_NODES is cut and says so; a cut drops whole paths, never half of one, and keeps the roots it starts from.

Node ids: a module is its lower-case file name ("kernel32.dll"), a function is "<module>!<function>" with the module
as the importer or forwarder wrote it ("api-ms-win-core-heap-l1-1-0.dll!HeapAlloc"), a syscall is "syscall:<Nt name>".
A colon cannot be part of a Windows file name, so a syscall id never collides with a module's.
"""

from __future__ import annotations

import ntpath
from dataclasses import asdict, dataclass

import binary_graph

MAX_NODES = 400

NODE_KINDS = ("dll", "exe", "function", "syscall", "api-set")
EDGE_KINDS = ("imports", "forwards_to", "resolves_to", "reaches_syscall")


@dataclass(frozen=True)
class Node:
    id: str
    label: str
    kind: str                   # one of NODE_KINDS
    in_degree: int              # how many binaries import this module; 0 for a function or a syscall
    category: str               # the SUSPICIOUS_IMPORTS category of a function, or ""


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: str                   # one of EDGE_KINDS
    origin: str                 # "derived" (read from the binaries) | "curated" (the Win32 to Nt table)
    label: str


@dataclass(frozen=True)
class Answer:
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    truncated: bool             # nodes were dropped to stay within MAX_NODES
    note: str                   # prose for the reader, English, whole sentences; not a token for code
    roots: tuple[str, ...]      # ids of the nodes the view starts from, always among `nodes`
    total: int                  # how many parts (importers, chains, ...) the answer had before the cut; 0 when empty


# function name -> its SUSPICIOUS_IMPORTS category; the web UI fills it (set_categories) so this module needs no app
_categories: dict[str, str] = {}


def set_categories(suspicious_imports: dict[str, list[str]]) -> None:
    """Take the categories from the web UI's SUSPICIOUS_IMPORTS (category -> API names). A name in more than one
    category keeps the first."""
    flat = {}
    for category, names in suspicious_imports.items():
        for name in names:
            flat.setdefault(name, category)
    _categories.clear()
    _categories.update(flat)


def category_of(function: str) -> str:
    """The category of `function`, or "". SUSPICIOUS_IMPORTS names most APIs without their A or W ("RegSetValueEx"),
    while System32 imports them with one ("RegSetValueExW"): the name without that last letter counts too."""
    found = _categories.get(function)
    if found is None and function[-1:] in ("A", "W"):
        found = _categories.get(function[:-1])
    return found or ""


# --- names and nodes ---------------------------------------------------------------------------------------------

def _module_name(graph, raw):
    """`raw` as the graph keys a module: lower case, ".dll" added to a bare name ("KERNEL32" -> "kernel32.dll")."""
    name = (raw or "").strip().lower()
    if name and name not in graph.binaries and not name.endswith((".dll", ".exe")):
        name += ".dll"
    return name


def _is_api_set(graph, name):
    """Whether the loader reads `name` as an api set, the way binary_graph's walk decides it: the map holds it, or it
    has the "api-" or "ext-" prefix. Checked before the binaries, as the loader does."""
    stem = name[:-len(".dll")] if name.endswith(".dll") else name
    return binary_graph.api_set_hosts(graph.api_sets, name) is not None or stem.startswith(("api-", "ext-"))


def _module_node(graph, name):
    if _is_api_set(graph, name):
        kind = "api-set"
    elif name in graph.binaries:
        kind = graph.binaries[name].kind
    else:
        kind = "exe" if name.endswith(".exe") else "dll"
    return Node(name, name, kind, graph.in_degree.get(name, 0), "")


def _function_id(module, function):
    return f"{module}!{function}"


def _function_node(module, function):
    return Node(_function_id(module, function), function, "function", 0, category_of(function))


def _syscall_node(nt):
    return Node(f"syscall:{nt}", nt, "syscall", 0, "")


def _edge(source, target, kind, label=""):
    return Edge(source, target, kind, "derived", label)


# --- the cut -------------------------------------------------------------------------------------------------------

@dataclass
class _Part:
    """A piece of an answer that is kept whole or dropped whole: one importer, one chain."""
    nodes: list
    edges: list
    roots: list


def _empty(note):
    return Answer((), (), False, note, (), 0)


def _answer(fixed, parts, note, what):
    """The answer of `fixed` (always kept: the start the view needs) and `parts` in their order, as many as fit in
    MAX_NODES. The first part that does not fit ends it, so what is shown is the first k of them and the note can say
    so; `what` names the parts in the plural ("binaries that import it")."""
    nodes, edges, roots = {}, {}, []

    def take(part):
        for node in part.nodes:
            nodes.setdefault(node.id, node)
        for edge in part.edges:
            edges.setdefault((edge.source, edge.target, edge.kind, edge.label), edge)
        for root in part.roots:
            if root not in roots:
                roots.append(root)

    take(fixed)
    kept = 0
    for part in parts:
        new = {node.id for node in part.nodes} - nodes.keys()
        if len(nodes) + len(new) > MAX_NODES:
            break
        take(part)
        kept += 1
    truncated = kept < len(parts)
    if truncated:
        note += (f" Only the first {kept} of {len(parts)} {what} are drawn: an answer is cut at {MAX_NODES} "
                 f"nodes.")
    return Answer(tuple(nodes.values()), tuple(edges.values()), truncated, note, tuple(roots), len(parts))


def _plural(count, one, many):
    return f"{count} {one if count == 1 else many}"


# --- the five queries -----------------------------------------------------------------------------------------------

def importers_of(graph, module: str, function: str | None = None) -> Answer:
    """The binaries that import `module`, or only `function` of it: directly, and through an api set the loader
    resolves to `module`. An importer through an api set is drawn as importer -> alias -> module; with `function`,
    an alias counts only where its first host to offer the function is `module`.

    One step on purpose: "who imports this" is the reverse of an `imports` edge, and an import edge is one step by
    definition. The api-set hop is not a second step but the loader's reading of the name the importer wrote (the
    first host, in the map's order, that offers the function). A binary that imports a forwarder which ends here
    does not import this; following forwarders transitively is callers_of_syscall's question, and must not be
    added here."""
    target = _module_name(graph, module)
    function = function or None
    what = f"{function} from {target}" if function else target
    if not target or not (target in graph.binaries or target in graph.in_degree or _is_api_set(graph, target)):
        return _empty(f"{target or 'That name'} is not in the binary graph of this system, and no binary in it "
                      f"imports it.")
    label = function or ""
    known = {}

    def node(name):
        if name not in known:
            known[name] = _module_node(graph, name)
        return known[name]

    aliases = set()
    if not _is_api_set(graph, target):
        for alias in {module for info in graph.binaries.values() for module in info.imports}:
            if not _is_api_set(graph, alias):
                continue
            if function is None:
                if target in (host.lower() for host in binary_graph.api_set_hosts(graph.api_sets, alias) or ()):
                    aliases.add(alias)
            else:
                hops = binary_graph.resolve_export(graph.binaries, graph.api_sets, alias, function).hops
                if hops and hops[0].module == target:
                    aliases.add(alias)
    # one part per importer, its direct edge and every alias it reaches the module through: kept or dropped whole
    parts = []
    for name in sorted(graph.binaries):
        part = _Part([node(name)], [], [])
        for imported, names in graph.binaries[name].imports.items():
            if function is not None and function not in names:
                continue
            if imported == target:
                part.edges.append(_edge(name, target, "imports", label))
            elif imported in aliases:
                part.nodes.append(node(imported))
                part.edges += [_edge(name, imported, "imports", label),
                               _edge(imported, target, "resolves_to", label)]
        if part.edges:
            parts.append(part)
    if not parts:
        return _empty(f"No binary in the graph imports {what}.")
    fixed = _Part([node(target)], [], [target])
    note = f"{_plural(len(parts), 'binary imports', 'binaries import')} {what}, directly or through an api set."
    return _answer(fixed, parts, note, "binaries that import it")


def imports_of(graph, module: str) -> Answer:
    """Every function `module` imports, one node each, delay-loads included; the edge's label is the module it
    imports the function from, as the file names it."""
    name = _module_name(graph, module)
    info = graph.binaries.get(name)
    if info is None:
        return _empty(f"{name or 'That name'} is not in the binary graph of this system.")
    caveat = (" Its import table was cut short when it was read, so the list may be incomplete."
              if info.partial else "")
    parts = [_Part([_function_node(imported, function)],
                   [_edge(name, _function_id(imported, function), "imports", imported)], [])
             for imported, functions in info.imports.items() for function in functions]
    if not parts:
        return _empty(f"{name} imports nothing.{caveat}")
    note = (f"{name} imports {_plural(len(parts), 'function', 'functions')} from "
            f"{_plural(len(info.imports), 'module', 'modules')}.{caveat}")
    return _answer(_Part([_module_node(graph, name)], [], [name]), parts, note, "imported functions")


def _chain(start, resolution):
    """`[(module, function), ...]` from `start` along the hops of `resolution`; a "defined" end is named by the key
    the defining module exports it under, which differs from the last hop where a forwarder named an ordinal."""
    pairs = [start] + [(hop.module, hop.function) for hop in resolution.hops]
    if resolution.reason == "defined":
        pairs[-1] = (resolution.module, resolution.function)
    return pairs


def _chain_part(pairs, resolution, head=None, roots=()):
    """The nodes and edges of a chain, with `head` (an importer's id and node) importing its first function."""
    nodes = [_function_node(module, function) for module, function in pairs]
    ids = [node.id for node in nodes]
    edges = [_edge(ids[i], ids[i + 1], hop.via) for i, hop in enumerate(resolution.hops)]
    if head is not None:
        nodes.insert(0, head)
        edges.insert(0, _edge(head.id, ids[0], "imports"))
    return _Part(nodes, edges, list(roots))


def callers_of_syscall(graph, nt_name: str) -> Answer:
    """The normal callers of a syscall: every binary whose import reaches its stub in ntdll.dll, by importing it
    there (under its Nt or its Zw name), through a forwarder or through an api set. Only the chains the binaries
    themselves describe; a Win32 function that calls the syscall in its own code is not a chain, and the curated
    Win32 to Nt table is not read here."""
    raw = (nt_name or "").strip()
    if len(raw) < 3 or raw[:2] not in ("Nt", "Zw"):
        return _empty(f"{raw or 'That'} is not a syscall name: a syscall name starts with Nt or Zw.")
    nt = "Nt" + raw[2:]
    ntdll = graph.binaries.get("ntdll.dll")
    if ntdll is None:
        return _empty("ntdll.dll is not in the binary graph of this system, so no chain to a syscall can be followed.")
    exported = set(ntdll.exports)
    names = [name for name in (nt, "Zw" + nt[2:]) if name in exported]
    if not names:
        return _empty(f"ntdll.dll in the binary graph of this system does not export {nt}.")
    targets = {("ntdll.dll", name) for name in names}
    # a function name an import must carry to reach the stub: a forwarder keeps the name it was imported by, an api
    # set keeps the name it was asked for, so the name is either the stub's or that of a forwarder ending there
    doors = set(names) | {name for (_, name), res in graph.resolved.items()
                          if res.reason == "defined" and (res.module, res.function) in targets}
    syscall = _syscall_node(nt)
    fixed = _Part([syscall], [], [syscall.id])
    for name in names:
        fixed.nodes.append(_function_node("ntdll.dll", name))
        fixed.edges.append(_edge(_function_id("ntdll.dll", name), syscall.id, "reaches_syscall"))
    parts, callers, cut_short, answers = [], set(), False, {}
    for importer in sorted(graph.binaries):
        for module, functions in graph.binaries[importer].imports.items():
            for function in functions:
                if function not in doors:
                    continue
                key = (module, function)
                if key not in answers:
                    answers[key] = binary_graph.resolve_export(graph.binaries, graph.api_sets, module, function)
                resolution = answers[key]
                if resolution.reason != "defined" or (resolution.module, resolution.function) not in targets:
                    continue
                callers.add(importer)
                cut_short = cut_short or resolution.partial
                parts.append(_chain_part(_chain(key, resolution), resolution,
                                         head=_module_node(graph, importer)))
    if not parts:
        return _empty(f"No binary in the graph reaches {nt} through an import, a forwarder or an api set.")
    note = (f"{_plural(len(callers), 'binary reaches', 'binaries reach')} {nt} in ntdll.dll through an import, a "
            f"forwarder or an api set. A Win32 function that calls it in its own code is not such a chain and is not "
            f"counted here.")
    if cut_short:
        note += " A table on one of these chains was cut short when it was read, so the list may be incomplete."
    return _answer(fixed, parts, note, "import chains")


# the outcome of a forwarder chain, as prose: Resolution.reason is the token the code reads
_OUTCOMES = {
    "defined": "reach the module that defines them",
    "missing": "end at a module that is not in the graph or does not offer the function",
    "cycle": "come back to an export they had already passed, a cycle",
    "unresolved-api-set": "end at an api set the map of this system has no entry for",
    "too-many-hops": f"are longer than {binary_graph.MAX_HOPS} hops",
}


def forwarder_chains(graph, module: str) -> Answer:
    """One path per forwarded export of `module`, from the export through every forwarder and api-set hop to where
    it ends; a chain that does not reach a definition is drawn as far as it got, and the note counts how each ended."""
    name = _module_name(graph, module)
    info = graph.binaries.get(name)
    if info is None:
        return _empty(f"{name or 'That name'} is not in the binary graph of this system.")
    if not info.forwarders:
        return _empty(f"{name} forwards none of its exports.")
    parts, outcomes, cut_short = [], {}, 0
    for export in info.forwarders:
        resolution = graph.resolved.get((name, export))
        if resolution is None:
            resolution = binary_graph.resolve_export(graph.binaries, graph.api_sets, name, export)
        outcomes[resolution.reason] = outcomes.get(resolution.reason, 0) + 1
        cut_short += resolution.partial
        parts.append(_chain_part(_chain((name, export), resolution), resolution,
                                 roots=[_function_id(name, export)]))
    ends = [f"{count} {_OUTCOMES.get(reason, 'end for a reason this view does not know')}"
            for reason, count in sorted(outcomes.items(), key=lambda item: -item[1])]
    note = f"{name} forwards {_plural(len(parts), 'export', 'exports')}: {', '.join(ends)}."
    if cut_short:
        note += (f" On {cut_short} of them a table was cut short when it was read, so where they end is not "
                 f"certain.")
    return _answer(_Part([], [], []), parts, note, "forwarded exports")


def _reached(graph, info):
    """module -> the names `info` imports it by: itself, or the api sets that stand for it. An api set counts as its
    first host in the map's order, the default the map gives at module level; one the map has no host for counts as
    itself."""
    reached = {}
    for imported in info.imports:
        module = imported
        if _is_api_set(graph, imported):
            hosts = binary_graph.api_set_hosts(graph.api_sets, imported)
            if hosts:
                module = hosts[0].lower()
        reached.setdefault(module, []).append(imported)
    return reached


def shared_dependencies(graph, a: str, b: str) -> Answer:
    """The modules both `a` and `b` import, compared after api-set resolution: most of System32 imports through api
    sets, and two binaries that reach kernelbase.dll through different api-set names do share it. Each binary is
    drawn importing a shared module directly, or importing the alias that resolves to it."""
    first, second = _module_name(graph, a), _module_name(graph, b)
    for name in (first, second):
        if name not in graph.binaries:
            return _empty(f"{name or 'That name'} is not in the binary graph of this system.")
    reached = {name: _reached(graph, graph.binaries[name]) for name in (first, second)}
    shared = sorted(module for module in reached[first] if module in reached[second])
    if not shared:
        return _empty(f"{first} and {second} import no module in common, compared after api-set resolution.")
    fixed = _Part([_module_node(graph, first), _module_node(graph, second)], [], [first, second])
    parts = []
    for module in shared:
        part = _Part([_module_node(graph, module)], [], [])
        for name in (first, second):
            for imported in reached[name][module]:
                if imported == module:
                    part.edges.append(_edge(name, module, "imports"))
                else:
                    part.nodes.append(_module_node(graph, imported))
                    part.edges += [_edge(name, imported, "imports"), _edge(imported, module, "resolves_to")]
        parts.append(part)
    note = (f"{first} and {second} both import {_plural(len(shared), 'module', 'modules')}, compared after api-set "
            f"resolution: an api set counts as its first host.")
    return _answer(fixed, parts, note, "shared modules")


def node_detail(graph, name: str) -> dict:
    """What the graph knows of one name: `is` says whether it is a "binary", an "api-set" or "none" of them (a name
    only imported, or not known at all). Every key is there whatever `is` says, empty where it does not apply.
    `forwarders` maps each forwarded export to its raw string and where it resolves: `reason` is the token of
    binary_graph.Resolution, for code to read."""
    module = _module_name(graph, name)
    detail = {"name": module, "is": "none", "kind": "", "machine": "", "in_degree": graph.in_degree.get(module, 0),
              "partial": False, "imports": {}, "exports": [], "forwarders": {}, "hosts": []}
    if module and _is_api_set(graph, module):
        detail.update({"is": "api-set", "kind": "api-set",
                       "hosts": list(binary_graph.api_set_hosts(graph.api_sets, module) or ())})
        return detail
    info = graph.binaries.get(module)
    if info is None:
        return detail
    forwarders = {}
    for export, raw in info.forwarders.items():
        resolution = graph.resolved.get((module, export))
        if resolution is None:
            resolution = binary_graph.resolve_export(graph.binaries, graph.api_sets, module, export)
        forwarders[export] = {"raw": raw, "reason": resolution.reason, "module": resolution.module,
                              "function": resolution.function, "partial": resolution.partial}
    detail.update({"is": "binary", "kind": info.kind, "machine": info.machine, "partial": info.partial,
                   "imports": {imported: list(functions) for imported, functions in info.imports.items()},
                   "exports": list(info.exports), "forwarders": forwarders})
    return detail


# --- what the route calls -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Context:
    """What a query may read besides its parameters. A later query (the path to a syscall) adds the curated table
    and the syscall baseline here; the queries keep their own signatures and only the adapters unpack."""
    graph: binary_graph.Graph


class MissingParameter(ValueError):
    """A query was asked without a parameter it needs; `name` is the parameter."""

    def __init__(self, name):
        super().__init__(f"the parameter {name} is required for this query")
        self.name = name


# query name -> the parameters it cannot do without, checked by the route before any graph is fetched: a malformed
# request must not start minutes of building
NEEDS = {
    "importers": ("module",),
    "imports": ("module",),
    "syscall-callers": ("syscall",),
    "forwarders": ("module",),
    "shared": ("module", "other"),
}


def check_parameters(name: str, params: dict) -> None:
    """Raise MissingParameter for the first parameter query `name` needs and `params` does not give."""
    for needed in NEEDS[name]:
        _need(params, needed)


def _need(params, name):
    value = (params.get(name) or "").strip()
    if not value:
        raise MissingParameter(name)
    return value


def _importers(ctx, params):
    return importers_of(ctx.graph, _need(params, "module"), (params.get("function") or "").strip() or None)


def _imports(ctx, params):
    return imports_of(ctx.graph, _need(params, "module"))


def _callers(ctx, params):
    return callers_of_syscall(ctx.graph, _need(params, "syscall"))


def _forwarders(ctx, params):
    return forwarder_chains(ctx.graph, _need(params, "module"))


def _shared(ctx, params):
    return shared_dependencies(ctx.graph, _need(params, "module"), _need(params, "other"))


# query name -> adapter `(Context, params) -> Answer`; `params` is the request's strings (module, function, syscall,
# other, metric), and an adapter raises MissingParameter for one it needs and was not given
QUERIES = {
    "importers": _importers,
    "imports": _imports,
    "syscall-callers": _callers,
    "forwarders": _forwarders,
    "shared": _shared,
}


def answer_json(answer: Answer) -> dict:
    """The answer as plain JSON data."""
    return asdict(answer)



# --- the doors of a process -----------------------------------------------------------------------------------------

def _windows_path(path):
    return ntpath.normcase(ntpath.normpath(path))


def _add_ordinal(graph, importer, module, function, names):
    """Add the names the import `function` ("#<n>") of `module` goes by to `names`; the reason it cannot be named, or
    "". The record of the exporting module names it (`ordinal_names`), followed through its forwarders and api sets.
    An ordinal the cache cannot name (its module is not in the graph, or no export of it has that number) may be a
    door, so whoever asks must not claim an absence."""
    resolution = binary_graph.resolve_export(graph.binaries, graph.api_sets, module, function)
    if resolution.reason != "defined":
        return f"{importer} imports {function} of {module}, which the binary graph cannot name"
    names.update(hop.function for hop in resolution.hops)
    names.add(resolution.function)
    return ""


def name_ordinal_imports(graph, imports, *, view, importer="the file") -> tuple[set[str] | None, str]:
    """`(names, why)`: the names the imports by ordinal of `imports` (module -> functions, an ordinal as "#<n>", named
    ones passed over) go by, or None and the reason when one of them cannot be named: there is no graph, it is of
    another view than the importer's (the x64 side of an ARM64X binary may number its exports otherwise), or the
    cache does not know the ordinal. A door imported by ordinal is a door all the same."""
    ordinals = [(module, f) for module, functions in imports.items() for f in functions if f.startswith("#")]
    names = set()
    if not ordinals:
        return names, ""
    if graph is None:
        return None, f"{importer} imports by ordinal, and there is no binary graph of this system to name them"
    if graph.arch != view:
        return None, (f"{importer} imports by ordinal, and the binary graph is of {graph.arch}, not of {view}")
    for module, function in ordinals:
        why = _add_ordinal(graph, importer, module.lower(), function, names)
        if why:
            return None, why
    return names, ""


def _record_doors(graph, info, names):
    """Add the names `info` imports to `names`; the reason the record cannot speak for its imports, or "".

    An import by ordinal is named by the cache (_add_ordinal); one it cannot name may be a door, so it leaves the
    union incomplete."""
    if info.partial:
        return f"the import table of {info.name} was cut short when it was read"
    for module, functions in info.imports.items():
        for function in functions:
            if not function.startswith("#"):
                names.add(function)
                continue
            why = _add_ordinal(graph, info.name, module, function, names)
            if why:
                return why
    return ""


def doors_of_process(graph, modules, table, *, view, image_path=None, image=None,
                     system32=binary_graph.SYSTEM32) -> tuple[set[str] | None, str]:
    """`(doors, why)`: the names every loaded module of a process imports, expanded through the Win32 to Nt `table`,
    or None and the reason when that union is incomplete. Only a complete union may carry a proof that a stub in the
    process's private memory goes around every documented path.

    `modules` is the reader's list (`name`, `base`, `size`, `path`); a caller that listed more than once passes every
    module of every list. A module counts by its path, never its name: one directly in `system32` is the file the
    cache read, and contributes the imports of its record there.

    Two halves, both deliberate. The process image is the sample, and its own import table is the very question
    asked: it counts by the record `image` read from the file at `image_path`, and a sample that imports a door is
    no proven bypass. Every other module the cache does not hold (a DLL the sample brought, a runtime or a hook
    engine outside System32, a DLL of System32's name side-loaded from elsewhere, one in System32 the cache does not
    hold, or whose record was cut short) contributes neither imports nor exports and leaves the union incomplete:
    were its table to count, a sample would ship a DLL with a made-up table and switch the proof off for the whole
    process. Malware that loads a DLL of its own thus mostly gets None here; the proof then comes from its file.

    The union is also incomplete for a list that cannot be had, a module without a path, an image not identified
    or not read, an import by ordinal the cache cannot name, and a process of another view than the cache's: an x64
    process on ARM64 runs the x64 side of the ARM64X binaries whose native side the cache read, and that side may
    import otherwise. A door is what a module imports; no module's exports count: the stub lies in private memory,
    which no export resolves to, and ntdll exports every Nt name."""
    if graph.arch != view:
        return None, f"the binary graph is of {graph.arch}, the process runs as {view}"
    if not modules:
        return None, "the modules of the process could not be listed"
    folder = _windows_path(system32)
    image_at = _windows_path(image_path) if image_path else None
    names, image_seen = set(), False
    for module in modules:
        path = module.get("path") if isinstance(module, dict) else None
        if not isinstance(path, str) or not path:
            return None, "a loaded module has no path"
        at = _windows_path(path)
        if at == image_at:
            image_seen = True
            if image is None:
                return None, f"the import table of the process image {path} could not be read"
            why = _record_doors(graph, image, names)
        else:
            directory, name = ntpath.split(at)
            info = graph.binaries.get(name) if directory == folder else None
            if info is None:
                return None, f"{path} is a loaded module the binary graph does not hold"
            why = _record_doors(graph, info, names)
        if why:
            return None, why
    if not image_seen:
        return None, "the process image is not among the loaded modules"
    return table.expand(names), ""


def imported_doors(graph, modules, table, *, view, image_path=None, image=None,
                   system32=binary_graph.SYSTEM32) -> set[str] | None:
    """The doors of `doors_of_process`, None when the union is incomplete: the expanded set to pass to
    syscall_scan.find_stubs_in_process, with the table's `covered`, only when it is not None."""
    return doors_of_process(graph, modules, table, view=view, image_path=image_path, image=image,
                            system32=system32)[0]
