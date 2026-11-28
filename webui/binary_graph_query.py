"""The questions the SYSCALLS tab asks of the import graph, each answered as nodes and edges ready to draw.

Every query returns an `Answer`; none raises for a name it does not know. An answer that finds nothing has no nodes and
a `note` that says why, never a bare empty answer that a view would draw as "no edges". An answer larger than
MAX_NODES is cut and says so; a cut drops whole paths, never half of one, and keeps the roots it starts from.

Node ids: a module is its lower-case file name ("kernel32.dll"), a function is "<module>!<function>" with the module
as the importer or forwarder wrote it ("api-ms-win-core-heap-l1-1-0.dll!HeapAlloc"), a syscall is "syscall:<Nt name>".
A colon cannot be part of a Windows file name, so a syscall id never collides with a module's.

An edge's `origin` is its claim: "derived" is read from the binaries, "curated" is the Win32 to Nt table's word. The one
curated edge of a path to a syscall is its last (`path_to_syscall`: at most one, and only ever the last; the spec's
sharpest anti-goal is a curated edge given out as a derived one). There are exactly two exceptions, decided and not
drifted into. `callers_of_syscall` draws the step from ntdll's Zw export to its Nt syscall as curated, labelled
"curated: zw-alias" as the table calls a mechanical rename, since that the one name is the other is not read from any
binary. `metric_members("curated_transitions")`, the list of the table's own rows, has every edge curated because
every row of the table is a curated mapping, each labelled "curated: <its source>". No other query and no other
figure's list carries a curated edge; tests/test_binary_graph.py enforces all three over every query. A Win32
function of that list has no module, so its id is its bare name.

The figures of the whole stock (`metrics`) are numbers, not a graph; `metric_members` answers what lies behind one as an
Answer like the others, a list of nodes that the view shows as rows, not as a picture.
"""

from __future__ import annotations

import ntpath
from dataclasses import asdict, dataclass

import binary_graph
import syscall_baseline
import win32_to_nt

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
    partial: bool = False       # a table the answer read was cut short when it was read: a negative or a count is not certain


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


def _empty(note, partial=False):
    return Answer((), (), False, note, (), 0, partial)


def _any_partial(graph):
    """Whether any binary of the graph has a table that was cut short: what a query that reads every binary (to find who
    imports a module, or who reaches a syscall) has read, so what it may be missing."""
    return any(info.partial for info in graph.binaries.values())


def _answer(fixed, parts, note, what, partial=False, total=None):
    """The answer of `fixed` (always kept: the start the view needs) and `parts` in their order, as many as fit in
    MAX_NODES. The first part that does not fit ends it, so what is shown is the first k of them and the note can say
    so; `what` names the parts in the plural ("binaries that import it"). `partial` is the caveat of every table the
    answer read, as `BinaryInfo.partial` and `Resolution.partial` mean it: the same word and meaning at each level.

    `parts` may be an iterator that is not read past the first part that does not fit, where its `total` is already
    known (the figures of the whole stock know their count without building a part for each); a list needs no `total`.
    An iterator that ends having given another number of parts than `total` is a bug, and says so: two numbers for
    one fact must not both be shown."""
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
    total = len(parts) if total is None else total
    kept = 0
    for part in parts:
        new = {node.id for node in part.nodes} - nodes.keys()
        if len(nodes) + len(new) > MAX_NODES:
            break
        take(part)
        kept += 1
    else:
        if kept != total:
            raise ValueError(f"the list of {what} had {kept} parts and its figure said {total}")
    truncated = kept < total
    if truncated:
        note += (f" Only the first {kept} of {total} {what} are drawn: an answer is cut at {MAX_NODES} "
                 f"nodes.")
    return Answer(tuple(nodes.values()), tuple(edges.values()), truncated, note, tuple(roots), total, partial)


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
        # "no binary in it imports it" is concluded from the in-degree, which every table makes: a cut one may hide the only importer
        return _empty(f"{target or 'That name'} is not in the binary graph of this system, and no binary in it "
                      f"imports it.", _any_partial(graph))
    label = function or ""
    known = {}
    # every binary's table is read to find the importers, so a cut one anywhere may be hiding one
    partial = _any_partial(graph)

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
        return _empty(f"No binary in the graph imports {what}.", partial)
    fixed = _Part([node(target)], [], [target])
    note = f"{_plural(len(parts), 'binary imports', 'binaries import')} {what}, directly or through an api set."
    return _answer(fixed, parts, note, "binaries that import it", partial)


def imports_of(graph, module: str) -> Answer:
    """Every function `module` imports, one node each, delay-loads included; the edge's label is the module it
    imports the function from, as the file names it."""
    name = _module_name(graph, module)
    info = graph.binaries.get(name)
    if info is None:
        return _empty(f"{name or 'That name'} is not in the binary graph of this system.")
    caveat = (" It has a table (import, delay-load or export) that was cut short when it was read, so the list may be incomplete."
              if info.partial else "")
    parts = [_Part([_function_node(imported, function)],
                   [_edge(name, _function_id(imported, function), "imports", imported)], [])
             for imported, functions in info.imports.items() for function in functions]
    if not parts:
        return _empty(f"{name} imports nothing.{caveat}", info.partial)
    note = (f"{name} imports {_plural(len(parts), 'function', 'functions')} from "
            f"{_plural(len(info.imports), 'module', 'modules')}.{caveat}")
    return _answer(_Part([_module_node(graph, name)], [], [name]), parts, note, "imported functions", info.partial)


def _chain(start, resolution):
    """`[(module, function), ...]` from `start` along the hops of `resolution`; a "defined" end is named by the key
    the defining module exports it under, which differs from the last hop where a forwarder named an ordinal."""
    pairs = [start] + [(hop.module, hop.function) for hop in resolution.hops]
    if resolution.reason == "defined":
        pairs[-1] = (resolution.module, resolution.function)
    return pairs


def _chain_part(pairs, resolution, head=None, roots=(), label=""):
    """The nodes and edges of a chain, with `head` (an importer's id and node) importing its first function, the edge
    labelled `label` (the module it imports it from)."""
    nodes = [_function_node(module, function) for module, function in pairs]
    ids = [node.id for node in nodes]
    edges = [_edge(ids[i], ids[i + 1], hop.via) for i, hop in enumerate(resolution.hops)]
    if head is not None:
        nodes.insert(0, head)
        edges.insert(0, _edge(head.id, ids[0], "imports", label))
    return _Part(nodes, edges, list(roots))


def callers_of_syscall(graph, nt_name: str) -> Answer:
    """The normal callers of a syscall: every binary whose import reaches its stub in ntdll.dll, by importing it
    there (under its Nt or its Zw name), through a forwarder or through an api set. Only the chains the binaries
    themselves describe; a Win32 function that calls the syscall in its own code is not a chain, and the curated
    Win32 to Nt table is not read here. The one edge that is not read from a binary is the step from the Zw export
    to the syscall: that the one name is the other is a naming convention, so it is curated, labelled
    "curated: zw-alias" as path_to_syscall labels it."""
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
        return _empty(f"ntdll.dll in the binary graph of this system does not export {nt}.", ntdll.partial)
    targets = {("ntdll.dll", name) for name in names}
    # a function name an import must carry to reach the stub: a forwarder keeps the name it was imported by, an api
    # set keeps the name it was asked for, so the name is either the stub's or that of a forwarder ending there
    doors = set(names) | {name for (_, name), res in graph.resolved.items()
                          if res.reason == "defined" and (res.module, res.function) in targets}
    syscall = _syscall_node(nt)
    fixed = _Part([syscall], [], [syscall.id])
    for name in names:
        fixed.nodes.append(_function_node("ntdll.dll", name))
        if name == nt:
            fixed.edges.append(_edge(_function_id("ntdll.dll", name), syscall.id, "reaches_syscall"))
        else:
            # that ZwClose is NtClose is a naming convention, not read from a binary: curated, as path_to_syscall
            # draws it
            fixed.edges.append(Edge(_function_id("ntdll.dll", name), syscall.id, "reaches_syscall", "curated",
                                    f"curated: {_ZW_ALIAS}"))
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
        return _empty(f"No binary in the graph reaches {nt} through an import, a forwarder or an api set.", _any_partial(graph))
    note = (f"{_plural(len(callers), 'binary reaches', 'binaries reach')} {nt} in ntdll.dll through an import, a "
            f"forwarder or an api set. A Win32 function that calls it in its own code is not such a chain and is not "
            f"counted here.")
    if cut_short:
        note += " A table on one of these chains was cut short when it was read, so the list may be incomplete."
    return _answer(fixed, parts, note, "import chains", cut_short or _any_partial(graph))


# --- the descent from an import to a syscall number --------------------------------------------------------------

def _stop_reason(graph, resolution, module, function):
    """Why a chain that did not reach a definition stopped at `module`!`function`, as a clause that follows
    "because". Never a claim that the function exists nowhere: only that this graph has no such export."""
    reason = resolution.reason
    if reason == "missing":
        if _is_api_set(graph, module):
            return f"no host of the api set {module} in the binary graph exports {function}"
        if module not in graph.binaries:
            return f"{module} is not in the binary graph of this system"
        return f"{module} has no export {function} in the binary graph"
    if reason == "cycle":
        return "it comes back to an export it had already passed, a cycle"
    if reason == "unresolved-api-set":
        return f"the api-set map of this system has no entry for {module}"
    if reason == "too-many-hops":
        return f"it is longer than {binary_graph.MAX_HOPS} hops"
    return "it ends for a reason this view does not know"


# what the curated table calls the rename of a Zw name to its Nt name (win32_to_nt.SOURCES)
_ZW_ALIAS = "zw-alias"
_CUT_SHORT_NEGATIVE = (" A table on this chain was cut short when it was read, so this end is not certain: what is "
                       "missing here may lie in the part that was not read, and it is not proof that the chain really "
                       "ends here.")
_CUT_SHORT_REACHED = (" A table on this chain was cut short when it was read, so the definition named here may not be "
                      "the one a complete table would give.")
_CUT_SHORT_POSITIVE = (" A table on this chain was cut short when it was read, so a complete one might have led "
                       "elsewhere.")


def path_to_syscall(graph, table, baseline, module: str, function: str) -> Answer:
    """The import of `function` followed down to a syscall number: over the forwarders and api sets the binaries
    describe (edges "derived") to the export that defines it, and from there to the syscall `baseline` holds.

    The tables prove no more than that: `kernelbase!WriteProcessMemory` defines it, it does not forward to ntdll, it
    calls `NtWriteVirtualMemory` in its own code. So where the chain ends in a Win32 function, one edge
    "reaches_syscall" with origin "curated", the word of the Win32 to Nt `table`, goes from there to the syscall; no
    node of ntdll stands between, as no kind of edge honestly joins it. Where the chain ends in the stub itself (an
    Nt name that ntdll or win32u exports and the baseline holds), the same edge is "derived" and the path has no
    curated edge at all, unless the stub is reached by its Zw name: ntdll exports `ZwClose` and `NtClose`, and that the
    one is the other is a naming convention, not something a binary says, so the edge from a Zw name is curated too,
    labelled "curated: zw-alias" as the table calls it. A path has at most one curated edge, and it is the last.

    What `module` means depends on what the graph holds of it, in this order:
      1. The importer: the graph holds `module`, its import table holds `function`, and it does not itself export or
         forward that name. The path starts at `module`, with an "imports" edge (derived, labelled with the module it
         imports `function` from; the first, if it imports it from several, and the note says so) to the function node.
      2. The exporter: every other case where the graph holds `module`, or knows it as an api set or an imported name.
         `function` is looked up in `module`, the function node is the root, and no edge claims an import.
      3. A module the graph does not know: nothing is derived of it, so it is not drawn as importing anything. The
         function node is the root, with no edge, and the note says the import could not be confirmed.
    A binary that both imports and exports the same name is read as the exporter (2), never as the importer. What a
    view or a later task passes in `module` is whatever the user typed, so the reading is decided here, by the graph.

    A path ends visibly, never by vanishing, and the note says which end it was: the chain reaches no definition at
    all, the table has no entry for the function it ends at, the table's Nt name is no syscall of the baseline, or
    there is no baseline or table to ask (a missing baseline is named first: without it nothing can be numbered,
    whatever the table holds); and, with any of them, that a table on the chain was cut short when it was
    read, so a negative end is not certain. `table` and `baseline` may be None."""
    name = _module_name(graph, module)
    function = (function or "").strip()
    if not name or not function:
        return _empty("A module and a function are needed to follow an import down to a syscall.")
    info = graph.binaries.get(name)
    imported = []
    if info is not None and function not in info.exports and function not in info.forwarders:
        imported = [source for source, names in info.imports.items() if function in names]
    head, label, extra = None, "", ""
    if imported:
        head, label = _module_node(graph, name), imported[0]
        start = (imported[0], function)
        if len(imported) > 1:
            extra = (f" It imports it from {len(imported)} modules ({', '.join(imported)}); this path follows the "
                     f"first.")
    else:
        unknown = info is None and name not in graph.in_degree and not _is_api_set(graph, name)
        start = ((module or "").strip().lower() if unknown else name, function)
        if unknown:
            extra = " The module is not known to the graph, so the import itself could not be confirmed."
    resolution = binary_graph.resolve_export(graph.binaries, graph.api_sets, *start)
    if info is not None and not imported and resolution.reason == "missing" and not resolution.hops:
        # a binary the graph holds that has no such function in its tables: there is nothing to draw, not a function
        # node for something that exists nowhere
        return _empty(f"{name} neither imports nor exports {function} in the binary graph."
                      + (_CUT_SHORT_NEGATIVE if resolution.partial else ""), resolution.partial or info.partial)
    pairs = _chain(start, resolution)
    part = _chain_part(pairs, resolution, head=head, label=label,
                       roots=[head.id if head else _function_id(*pairs[0])])
    # a table on the chain, and the importer's own, which the first edge reads
    partial = resolution.partial or bool(imported and info.partial)

    def ended(note, caveat=_CUT_SHORT_REACHED):
        note += extra
        if resolution.partial:
            note += caveat
        return _answer(_Part([], [], []), [part], note, "paths", partial)

    end_module, end_function = pairs[-1]
    end = _function_id(end_module, end_function)
    if resolution.reason != "defined":
        note = (f"The chain reaches no definition at all: it stops at {end}, because "
                f"{_stop_reason(graph, resolution, end_module, end_function)}.")
        if resolution.hops:
            note += " The hops it did take are drawn."
        return ended(note, _CUT_SHORT_NEGATIVE)
    hops = _plural(len(resolution.hops), "hop", "hops")
    # the stub itself: ntdll exports each under its Nt and its Zw name, and the baseline holds one of the two, whichever
    # NTSleuth emitted first (on 26200.9974 ZwWriteVirtualMemory on x64): found under either, drawn under the Nt name
    nt_name = "Nt" + end_function[2:] if end_function.startswith("Zw") and len(end_function) > 2 else end_function
    stub = syscall_baseline.find(baseline, nt_name) if baseline is not None else None
    if stub is not None and stub.module.lower() == end_module:
        syscall = Node(f"syscall:{nt_name}", f"{nt_name} ({stub.module}, 0x{stub.number:x})", "syscall", 0, "")
        part.nodes.append(syscall)
        number = f"the baseline of this build gives {nt_name} the number {stub.number:#x} ({stub.number})."
        if nt_name != end_function:
            # ntdll exports both names, but that one is the other is a naming convention, not something a binary says
            part.edges.append(Edge(end, syscall.id, "reaches_syscall", "curated", f"curated: {_ZW_ALIAS}"))
            return ended(f"{function} is defined at {end}, after {hops}, and that export is the Zw name of the stub of "
                         f"{nt_name}. The last step is not read from any binary: that the Zw name is the Nt name is a "
                         f"naming convention, which the curated Win32 to Nt table calls {_ZW_ALIAS}. Given that, "
                         f"{number}", _CUT_SHORT_POSITIVE)
        part.edges.append(_edge(end, syscall.id, "reaches_syscall"))
        return ended(f"{function} is defined at {end}, after {hops}, and that export is the stub of a syscall "
                     f"itself: no curated step is needed, and {number}", _CUT_SHORT_POSITIVE)
    rows, via = (), ""
    for candidate in dict.fromkeys((function, end_function)) if table is not None else ():
        rows = table.entries_for(candidate)
        if rows:
            if function != end_function:
                via = (f" The row is for the imported name {function}, not for the name that defines it, "
                       f"{end_function}." if candidate == function else
                       f" The row is for the defining name {end_function}, not for the imported name {function}.")
            break
    if baseline is None:
        # whatever the table says, nothing can be numbered without a baseline: that is the end, not the table's
        text = (f"The curated table leads {rows[0].win32} to {rows[0].nt}, but no" if rows else
                f"{end} defines it, but no")
        text += " syscall baseline is loaded for this system, so the number of the syscall cannot be given."
        if table is None:
            text += " The curated Win32 to Nt table could not be read either."
        elif len(rows) > 1:
            text += f" The table lists {_plural(len(rows) - 1, 'more syscall', 'more syscalls')} for it."
        return ended(text + via)
    if table is None:
        return ended(f"{end} defines it, but the curated Win32 to Nt table could not be read on this system, so the "
                     f"step to a syscall cannot be followed.")
    if not rows:
        return ended(f"The path ends at {end}, which defines it: no curated transition known from "
                     f"{end_function} to a syscall, so the path ends there.")
    entry = rows[0]
    more = ""
    if len(rows) > 1:
        more = (f" The table lists {_plural(len(rows) - 1, 'more syscall', 'more syscalls')} for it "
                f"({', '.join(row.nt for row in rows[1:])}); this path follows the first.")
    more += via
    if entry.nt in table.missing_from(baseline.syscalls):
        ntdll = graph.binaries.get("ntdll.dll")
        exported = ntdll is not None and entry.nt in ntdll.exports
        clause = ("ntdll exports it, but no syscall of this build has that name" if exported else
                  "ntdll in the binary graph does not export it either, and no syscall of this build has that name")
        return ended(f"The path ends at {end}. The curated table leads {entry.win32} to {entry.nt}: {clause}, so no "
                     f"syscall number can be given. The baseline may be of another build, or incomplete.{more}")
    target = syscall_baseline.find(baseline, entry.nt)        # missing_from accepts the Zw form: so does this
    syscall = Node(f"syscall:{entry.nt}", f"{entry.nt} ({target.module}, 0x{target.number:x})", "syscall", 0, "")
    part.nodes.append(syscall)
    part.edges.append(Edge(end, syscall.id, "reaches_syscall", "curated", f"curated: {entry.source}"))
    source = f"{entry.source}: {entry.note}" if entry.note else entry.source
    return ended(f"{function} is defined at {end}, after {hops}. The last step is not read from any binary: the "
                 f"curated Win32 to Nt table ({source}) leads {entry.win32} to {entry.nt}, which is syscall number "
                 f"{target.number:#x} ({target.number}) in the baseline of this build.{more}", _CUT_SHORT_POSITIVE)


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
        return _empty(f"{name} forwards none of its exports.", info.partial)
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
    return _answer(_Part([], [], []), parts, note, "forwarded exports", info.partial or cut_short > 0)


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
        return _empty(f"{first} and {second} import no module in common, compared after api-set resolution.",
                      graph.binaries[first].partial or graph.binaries[second].partial)
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
    return _answer(fixed, parts, note, "shared modules", graph.binaries[first].partial or graph.binaries[second].partial)


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


# --- the figures of the whole stock ---------------------------------------------------------------------------------

# the figures in the order of the table that shows them, and how many of the most imported modules are listed
METRICS = ("binaries", "edges", "api_sets_resolved", "forwarders", "isolated", "circular_pairs",
           "curated_transitions", "most_imported", "skipped", "partial")
MOST_IMPORTED = 20


def _reach(graph, module, every, skipped):
    """The files an import of `module` reaches: the module itself where the graph holds it, or a file it had to skip
    (it is System32's, though unread); for an api set its hosts that are one or the other, all of them where `every`,
    otherwise the first only, the default the map gives at module level. A host that was skipped counts like a skipped
    module: an absence is not claimed over a file nobody could read."""
    if _is_api_set(graph, module):
        hosts = [host.lower() for host in binary_graph.api_set_hosts(graph.api_sets, module) or ()]
        return [host for host in (hosts if every else hosts[:1]) if host in graph.binaries or host in skipped]
    return [module] if module in graph.binaries or module in skipped else []


def _links(graph, every):
    """binary -> {the other file it imports: the api set it goes through, or "" for a direct import}. A file that
    imports itself is linked to nothing by it. `every` reads an api set as all its hosts, which only makes a claim of
    absence weaker; without it as its first, which only makes a claim of presence weaker."""
    skipped = {name.lower() for name, _ in graph.skipped}
    reached = {}
    links = {}
    for name, info in graph.binaries.items():
        mine = {}
        for module in info.imports:
            if module not in reached:
                reached[module] = _reach(graph, module, every, skipped)
            for target in reached[module]:
                if target != name:
                    mine.setdefault(target, "" if target == module else module)
        links[name] = mine
    return links


def _isolated(graph):
    """The binaries nothing imports, directly or through any host of an api set, and that import no other file of
    System32: both halves, or every leaf .exe would be isolated."""
    links = _links(graph, every=True)
    imported = {target for mine in links.values() for target in mine}
    return sorted(name for name, mine in links.items() if not mine and name not in imported)


def _circular_pairs(graph, links=None):
    """Two binaries that import each other, each pair once as (a, b) with a < b: a pair, not its two directed edges,
    and no binary with itself. `links` is `_links(graph, every=False)` where the caller has it already."""
    links = _links(graph, every=False) if links is None else links
    return sorted((a, b) for a, mine in links.items() for b in mine if a < b and a in links.get(b, {}))


def _resolved_api_sets(graph):
    """The api sets some binary imports and the map has a host for, the most imported first."""
    names = [name for name in graph.in_degree
             if _is_api_set(graph, name) and binary_graph.api_set_hosts(graph.api_sets, name)]
    return sorted(names, key=lambda name: (-graph.in_degree[name], name))


def _most_imported(graph):
    """The modules most binaries import, by the name the importers wrote (an api set counts as itself)."""
    return sorted(graph.in_degree.items(), key=lambda item: (-item[1], item[0]))[:MOST_IMPORTED]


def _edge_count(graph):
    return sum(len(info.imports) for info in graph.binaries.values())


def _forwarder_count(graph):
    return sum(len(info.forwarders) for info in graph.binaries.values())


def _partial_names(graph):
    return sorted(name for name, info in graph.binaries.items() if info.partial)


def metrics(graph, table) -> dict:
    """The figures of the whole stock, as numbers; the lists behind them are `metric_members`. Each is made from the
    records in one pass, none from a query, and a figure that cannot be had is None, never 0: `curated_transitions`
    without a `table`.

    `edges` are the imports of every binary, one for each module it imports as the file names it (delay-loads
    included); `forwarders` the forwarded exports, not the binaries that hold them; `api_sets_resolved` the api sets
    some binary imports and the map has a host for; `isolated` the binaries nothing imports and that import nothing
    else of System32 (an api set counts as every host it has: a claim of absence must not overreach);
    `circular_pairs` pairs of binaries that import each other (an api set counts as its first host, as the shared
    dependencies read it: a claim of presence must not either); `curated_transitions` the rows of the Win32 to Nt
    table, not the Nt names they lead to; `most_imported` the modules with the highest in-degree; `skipped` the files
    that could not be read; and `partial` the binaries with a table (import, delay-load or export) cut short when it was read, which
    makes every count that reads tables a lower bound and `isolated` an upper one."""
    return {
        "binaries": len(graph.binaries),
        "edges": _edge_count(graph),
        "api_sets_resolved": len(_resolved_api_sets(graph)),
        "forwarders": _forwarder_count(graph),
        "isolated": len(_isolated(graph)),
        "circular_pairs": len(_circular_pairs(graph)),
        "curated_transitions": None if table is None else len(table.entries),
        "most_imported": [{"name": name, "in_degree": degree} for name, degree in _most_imported(graph)],
        "skipped": len(graph.skipped),
        "partial": len(_partial_names(graph)),
    }


def _cut_note(graph, effect):
    count = sum(1 for info in graph.binaries.values() if info.partial)
    return (f" {_plural(count, 'binary has', 'binaries have')} a table (import, delay-load or export) that was cut short "
            f"when the graph was read, so {effect}.") if count else ""


# Each list is `(parts, total, note, what, reads_tables, nothing)`: its parts as an iterator, built only as far as the cap
# reaches (a real System32 has tens of thousands of edges, and a click on a number must not build them all), the `total`
# it was counted to by the very function `metrics` counts it with, so that the two cannot be two numbers, the note of an
# answer, the plural of its parts, whether it read the tables of every binary, and the note of an empty one.

def _members_binaries(graph, table):
    total = len(graph.binaries)
    parts = (_Part([_module_node(graph, name)], [], [name]) for name in sorted(graph.binaries))
    dlls = sum(1 for info in graph.binaries.values() if info.kind == "dll")
    return (parts, total, f"The graph holds {_plural(total, 'binary', 'binaries')}, {_plural(dlls, 'DLL', 'DLLs')} and "
                          f"{_plural(total - dlls, 'EXE', 'EXEs')}, listed by name.", "binaries", False,
            "The graph holds no binary.")


def _members_edges(graph, table):
    known = {}

    def node(name):
        if name not in known:
            known[name] = _module_node(graph, name)
        return known[name]

    total = _edge_count(graph)
    parts = (_Part([node(name), node(module)], [_edge(name, module, "imports")], [name])
             for name in sorted(graph.binaries) for module in graph.binaries[name].imports)
    return (parts, total, f"{_plural(total, 'import', 'imports')}: a binary and a module it imports, counted by the name "
                          f"the importer wrote, so an api set counts as itself, and delay-loaded imports count."
                          + _cut_note(graph, "this count may be too low"), "imports", True, "No binary of the graph imports anything.")


def _members_api_sets(graph, table):
    names = _resolved_api_sets(graph)
    parts = (_Part([_module_node(graph, name)], [], [name]) for name in names)
    return (parts, len(names), f"{_plural(len(names), 'api set', 'api sets')} that binaries import and the api-set map of this "
                               f"system has a host for, the most imported first." + _cut_note(graph, "this count may be too low"),
            "api sets", True, "No binary of the graph imports an api set that the map of this system has a host for.")


def _members_forwarders(graph, table):
    holders = sorted((name for name, info in graph.binaries.items() if info.forwarders),
                     key=lambda name: (-len(graph.binaries[name].forwarders), name))
    total = _forwarder_count(graph)
    parts = (_Part([_function_node(name, export)], [], [_function_id(name, export)])
             for name in holders for export in graph.binaries[name].forwarders)
    return (parts, total, f"{_plural(total, 'forwarded export', 'forwarded exports')} in "
                          f"{_plural(len(holders), 'binary', 'binaries')}: an export that names a function of another module "
                          f"instead of holding its code. The binary that forwards the most comes first."
                          + _cut_note(graph, "this count may be too low"), "forwarded exports", True,
            "No binary of the graph forwards an export.")


def _members_isolated(graph, table):
    names = _isolated(graph)
    parts = (_Part([_module_node(graph, name)], [], [name]) for name in names)
    return (parts, len(names), f"{_plural(len(names), 'binary is', 'binaries are')} isolated: nothing imports "
                               f"{'it' if len(names) == 1 else 'them'}, directly or through an api set, and "
                               f"{'it imports' if len(names) == 1 else 'they import'} nothing else of System32."
                               + _cut_note(graph, "a binary may be listed here only because an import that would link it was in a table that was cut short"),
            "isolated binaries", True, "No binary of the graph is isolated: each is imported by another, or imports another.")


def _members_circular(graph, table):
    links = _links(graph, every=False)
    pairs = _circular_pairs(graph, links)
    parts = (_Part([_module_node(graph, a), _module_node(graph, b)],
                   [_edge(a, b, "imports", links[a][b]), _edge(b, a, "imports", links[b][a])], [a, b])
             for a, b in pairs)
    return (parts, len(pairs), f"{_plural(len(pairs), 'pair', 'pairs')} of binaries that import each other, each pair listed once; "
                               f"an api set counts as its first host, and the edge names it." + _cut_note(graph, "this count may be too low"),
            "pairs", True, "No two binaries of the graph import each other.")


def _members_curated(graph, table):
    if table is None:
        return ((), 0, "", "", False, "The curated Win32 to Nt table could not be read on this system, so its transitions "
                                      "cannot be listed.")
    parts = (_Part([Node(entry.win32, entry.win32, "function", 0, category_of(entry.win32)), _syscall_node(entry.nt)],
                   [Edge(entry.win32, f"syscall:{entry.nt}", "reaches_syscall", "curated", f"curated: {entry.source}")],
                   [entry.win32]) for entry in table.entries)
    names = len({entry.win32 for entry in table.entries})
    return (parts, len(table.entries), f"{_plural(len(table.entries), 'row', 'rows')} of the curated Win32 to Nt table, for "
                                       f"{_plural(names, 'Win32 function', 'Win32 functions')}: each is the table's word, not read "
                                       f"from any binary.", "rows", False, "The curated Win32 to Nt table has no rows.")


def _members_most_imported(graph, table):
    top = _most_imported(graph)
    parts = (_Part([_module_node(graph, name)], [], [name]) for name, _ in top)
    return (parts, len(top), f"The {_plural(len(top), 'module', 'modules')} that most binaries import, by the name the importers "
                             f"wrote, so an api set counts as itself." + _cut_note(graph, "an in-degree may be too low"),
            "modules", True, "No binary of the graph imports anything.")


def _members_skipped(graph, table):
    total = len(graph.skipped)
    parts = (_Part([Node(name, f"{name}: {reason}", "exe" if name.lower().endswith(".exe") else "dll", 0, "")], [], [name])
             for name, reason in graph.skipped)
    return (parts, total, f"{_plural(total, 'file', 'files')} of System32 could not be read and {'is' if total == 1 else 'are'} "
                          f"not in the graph, each with the reason.", "files", False, "Every file of System32 was read.")


def _members_partial(graph, table):
    names = _partial_names(graph)
    parts = (_Part([_module_node(graph, name)], [], [name]) for name in names)
    return (parts, len(names), f"{_plural(len(names), 'binary has', 'binaries have')} a table (import, delay-load or export) that was cut "
                               f"short when it was read: what it imports or exports may be more than the graph holds.", "binaries", False,
            "No table (import, delay-load or export) was cut short when the graph was read.")


_MEMBERS = {"binaries": _members_binaries, "edges": _members_edges, "api_sets_resolved": _members_api_sets,
            "forwarders": _members_forwarders, "isolated": _members_isolated, "circular_pairs": _members_circular,
            "curated_transitions": _members_curated, "most_imported": _members_most_imported,
            "skipped": _members_skipped, "partial": _members_partial}


def metric_members(graph, table, name: str) -> Answer:
    """The list behind the figure `name` of `metrics`, as an Answer: its nodes are the rows, in the order that keeps what
    says most when it is cut at MAX_NODES, and its `total` is the figure itself, counted by the same function and not
    by building the list. The list is built only as far as the cap reaches. `edges` lists the imports, each with
    both of its ends; `circular_pairs` both binaries of a pair, joined by the two edges; `forwarders` the forwarded
    exports; `curated_transitions` the table's rows, each a curated edge. A figure of zero, one that cannot be had and a
    name that is none of METRICS give an empty answer with a note.

    `curated_transitions` is the one list that carries curated edges, and the only answer besides `path_to_syscall` and
    `callers_of_syscall` (its Zw step) that does: every row of the Win32 to Nt table is a curated mapping, so an edge for it is honest, each labelled
    "curated: <its source>" and none drawn as read from a binary. No other list may carry one."""
    if not isinstance(name, str) or name not in _MEMBERS:
        shown = name[:40] if isinstance(name, str) and name.strip() else "That name"
        return _empty(f"{shown} is not a figure of the graph: the figures are {', '.join(METRICS)}.")
    parts, total, note, what, reads_tables, nothing = _MEMBERS[name](graph, table)
    partial = reads_tables and _any_partial(graph)
    if not total:
        return _empty(nothing + (_cut_note(graph, "what is missing here may lie in the part that was not read") if partial else ""),
                      partial)
    return _answer(_Part([], [], []), parts, note, what, partial, total)


# --- what the route calls -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Context:
    """What a query may read besides its parameters: the graph, and for the path to a syscall the curated Win32 to Nt
    table and the syscall baseline of this build, None where there is none. The queries keep their own signatures and
    only the adapters unpack."""
    graph: binary_graph.Graph
    table: win32_to_nt.Table | None = None
    baseline: syscall_baseline.Baseline | None = None


class BadParameter(ValueError):
    """A parameter is not one of the values it can have; `name` is the parameter."""

    def __init__(self, name, allowed):
        super().__init__(f"the parameter {name} must be one of {', '.join(allowed)}")
        self.name = name


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
    "path-to-syscall": ("module", "function"),
    "metric": ("metric",),
}

# parameter -> the values it can have, where they are a closed set: refused before any graph is fetched too
VOCABULARY = {"metric": METRICS}


def check_parameters(name: str, params: dict) -> None:
    """Raise MissingParameter for the first parameter query `name` needs and `params` does not give, and BadParameter for
    one that is not among the values it can have."""
    for needed in NEEDS[name]:
        value = _need(params, needed)
        if needed in VOCABULARY and value not in VOCABULARY[needed]:
            raise BadParameter(needed, VOCABULARY[needed])


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


def _path(ctx, params):
    return path_to_syscall(ctx.graph, ctx.table, ctx.baseline, _need(params, "module"), _need(params, "function"))


def _metric(ctx, params):
    return metric_members(ctx.graph, ctx.table, _need(params, "metric"))


# query name -> adapter `(Context, params) -> Answer`; `params` is the request's strings (module, function, syscall,
# other, metric), and an adapter raises MissingParameter for one it needs and was not given
QUERIES = {
    "importers": _importers,
    "imports": _imports,
    "syscall-callers": _callers,
    "forwarders": _forwarders,
    "shared": _shared,
    "path-to-syscall": _path,
    "metric": _metric,
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
    if resolution.partial:
        return f"{importer} imports {function} of {module}, named over a table that was cut short when it was read"
    # the name the exporting module gives the number, as a named import keeps the name it was imported by
    first = graph.binaries.get(module)
    digits = function[1:]
    if first is not None and digits.isascii() and digits.isdecimal():
        own = first.ordinal_names.get(int(digits))
        if own:
            names.add(own)
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

    A named import is followed through the exporting module's forwarders and api sets, the way `_add_ordinal`
    already follows what it names: a module importing `FlushProcessWriteBuffers` of kernel32 really reaches
    `NtFlushProcessWriteBuffers`, and a set holding only the imported name is an incomplete union - which means a
    missing door, which means a `false` nobody earned. Measured on build 26200.9974: of 4,944 System32 forwarders
    1,538 rename, 234 of those point at a door, and five of those carry a real name (three D3DKMT… of gdi32 and
    `FlushProcessWriteBuffers` of kernel32 and kernelbase), imported by eight System32 binaries.

    Only a name whose chain begins at a forwarder is resolved, and whether it does is `binary_graph.forwards_name`,
    which answers by taking the walk's own step. That matters: an earlier version of this gate read the api-set map
    itself and took `hosts[0]`, which is not the loader's rule - the walk reads the map before `binaries` and takes
    the first host that is in the graph AND offers the name. A gate narrower than the resolver it guards refuses to
    ask where the resolver would have found another name, and then the union is reported complete with a door
    missing. An adversarial review found three live shapes of that.

    The gate is what keeps the cost down. Measured on the chamber, three processes, three runs each, the minimum
    per process: 0.34-0.41s before, 1.05-1.64s resolving every named import, 0.39-0.56s with the gate - and of
    3,671 resolutions over twelve modules, 3,551 were names behind an api set that the host defines itself. (An
    earlier version of this docstring paired the best case before with the worst case after; the ranges are the
    measurement.)

    Unlike an ordinal, a named import that cannot be resolved leaves the union complete: its own name is recorded
    either way, so a failed resolution loses a possible second name and nothing that was there before. For an
    ordinal the name itself is unknown, so one that cannot be named may be any door and the union is incomplete.
    That difference is deliberate, not an oversight: making a failed resolution incomplete would switch proofs off
    far more widely and needs its own measurement. A table cut short on the chain is one such failure, so the two
    paths do not behave alike in the failure direction - the commit that introduced this said they did, which was
    wrong.
    """
    if info.partial:
        return f"a table (import, delay-load or export) of {info.name} was cut short when it was read"
    for module, functions in info.imports.items():
        for function in functions:
            if not function.startswith("#"):
                names.add(function)
                if binary_graph.forwards_name(graph.binaries, graph.api_sets, module, function):
                    resolution = binary_graph.resolve_export(graph.binaries, graph.api_sets, module, function)
                    if resolution.reason == "defined" and not resolution.partial:
                        reached = [hop.function for hop in resolution.hops] + [resolution.function]
                        # a forwarder may name its target by number, and then the door the import really reaches is
                        # one the graph cannot name: ruling 33's case, on the named path
                        nameless = next((one for one in reached if one.startswith("#")), "")
                        if nameless:
                            return (f"{info.name} imports {function} of {module}, which is forwarded to "
                                    f"{nameless}, a function the binary graph cannot name")
                        names.update(reached)
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
