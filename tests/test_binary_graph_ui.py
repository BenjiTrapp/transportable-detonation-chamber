"""The GRAPH surface of the SYSCALLS tab (block SYSCALLS of static/js/app.js): the binary graph's answers as layered
paths, left to right, one layer per hop.

Regressions covered:
  * the curated hop from a Win32 function to its Nt counterpart drawn like an edge read from a binary, missing from
    the legend, or not named as the table's word in the detail panel: the reader takes a curated edge for a derived one
  * a path drawn out of its order, or two hops in one layer
  * an answer with a note and no nodes drawn as an empty canvas; a cut answer that does not say it was cut, so a
    missing node reads as "does not import"
  * a deviation and a filter match in one colour; a node in a deviation tone before any scan; a path to a deviating
    syscall that does not carry its tone
  * the map and the graph choosing different syscalls
  * a module name from an import table, or the note or error that echoes what the user typed, taken as markup

EXPLORE, the same graph opened one node at a time on a canvas of its own (tests at the end of this file):
  * the exploration drawing more than the binary that was asked for, an expansion that replaced what was drawn, a depth
    outside 1 to 3 taken in silently, a canvas that outgrew its cap without saying so
  * a node's size not following its in-degree, its colour not following its kind
  * the edges of the chosen node drawn like all the others
  * the process graph's state written by a render of the binary graph (both views share functions, never state)
"""

import re
from html.parser import HTMLParser

from test_frontend import needs_node
from test_syscalls_ui import FLOW_CONSTS, FLOW_DOM, FLOW_FUNCTIONS, _const, _flow, _run_node
from test_theme import INDEX_HTML, _const_source, _cyberpunk_palette, _hex_rgb, _read, _root_values, _tab_markup


class _Elements(HTMLParser):
    """Every element of a piece of markup with its attributes, and the text inside each, as a browser reads them."""

    def __init__(self, html):
        super().__init__()
        self.elements, self._open = [], []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        element = {"tag": tag, "attrs": dict(attrs), "text": ""}
        self.elements.append(element)
        self._open.append(element)

    def handle_endtag(self, tag):
        while self._open:
            if self._open.pop()["tag"] == tag:
                break

    def handle_data(self, data):
        for element in self._open:
            element["text"] += data


def _classes(element):
    return element["attrs"].get("class", "").split()


# The functions the pure drawing calls, and a themeColor that returns the variable's name (and the alpha)
DRAW = ["binaryGraphLayout", "binaryGraphSvg", "binaryGraphEdgeLook", "binaryGraphNodeLook", "binaryGraphTones",
        "binaryGraphMatches", "binaryGraphCut", "binaryGraphLegend", "binaryGraphOwn", "binaryGraphOrigin"]
def _draw_prelude():
    return ("const themeColor = (name, alpha) => alpha === undefined ? name : name + '/' + alpha;\n"
            + "\n".join(_const_source(c)
                         for c in ("BINARY_GRAPH", "BINARY_GRAPH_SYSCALL", "BINARY_GRAPH_KINDS", "BINARY_GRAPH_EDGE_WORDS", "SYSCALL_STATE_COLORS", "SYSCALL_SEVERITY_RANK"))
            + "\n")

# A path as /api/binary-graph/query answers it: a sample's import of CloseHandle through an api set to the export
# that defines it, and the curated last hop to its syscall
PATH = r"""
const PATH = (syscall = 'NtClose', number = 15) => ({
  nodes: [
    { id: 'sample.dll', label: 'sample.dll', kind: 'dll', in_degree: 0, category: '' },
    { id: 'api-ms-win-core-handle-l1-1-0.dll!CloseHandle', label: 'CloseHandle', kind: 'function', in_degree: 0, category: '' },
    { id: 'kernelbase.dll!CloseHandle', label: 'CloseHandle', kind: 'function', in_degree: 0, category: '' },
    { id: 'syscall:' + syscall, label: syscall + ' (ntdll.dll, 0x' + number.toString(16) + ')', kind: 'syscall', in_degree: 0, category: '' }],
  edges: [
    { source: 'sample.dll', target: 'api-ms-win-core-handle-l1-1-0.dll!CloseHandle', kind: 'imports', origin: 'derived', label: 'api-ms-win-core-handle-l1-1-0.dll' },
    { source: 'api-ms-win-core-handle-l1-1-0.dll!CloseHandle', target: 'kernelbase.dll!CloseHandle', kind: 'resolves_to', origin: 'derived', label: '' },
    { source: 'kernelbase.dll!CloseHandle', target: 'syscall:' + syscall, kind: 'reaches_syscall', origin: 'curated', label: 'curated: phnt' }],
  truncated: false, total: 1, roots: ['sample.dll'], build: '26220.5770', arch: 'arm64', created: '2026-11-22T10:00:00Z',
  note: 'CloseHandle is defined at kernelbase.dll!CloseHandle, after 1 hop. The last step is not read from any binary.' });
const quiet = { tones: binaryGraphTones(PATH().nodes, PATH().edges, null), match: null, selected: null };
"""


def _draw(script):
    return _run_node(DRAW, PATH + script, _draw_prelude())


# The page of the flow tests (FLOW_DOM of test_syscalls_ui) and the elements of the GRAPH surface
GRAPH_DOM = PATH + r"""
for (const id of ['syscall-surface-graph', 'binary-graph-query', 'binary-graph-module', 'binary-graph-function', 'binary-graph-run',
                  'binary-graph-status', 'binary-graph-canvas', 'binary-graph-legend']) els[id] = Object.assign(new Node('div'), { id });
els['syscall-surface-graph'].hidden = true;
els['binary-graph-query'].value = 'path-to-syscall';
const ask = async (answer, module = 'sample.dll', fn = 'CloseHandle') => {
  routes['/api/binary-graph/query'] = answer;
  els['binary-graph-module'].value = module; els['binary-graph-function'].value = fn;
  await binaryGraphRun();
};
"""


def _graph_flow(script):
    return _flow(GRAPH_DOM + script)


def _svg_parts(svg):
    elements = _Elements(svg).elements
    nodes = [e for e in elements if "binary-graph-node" in _classes(e)]
    lines = [e for e in elements if "binary-graph-edge-line" in _classes(e)]
    return elements, nodes, lines


# --- The toggle and the surface ------------------------------------------------------------------------------------

def test_the_graph_button_is_no_longer_disabled_and_switches_the_surface():
    tab = _tab_markup("syscalls")
    button = re.search(r'<button[^>]*id="syscall-view-graph"[^>]*>GRAPH</button>', tab).group(0)
    assert "disabled" not in button and "comes with the binary graph" not in button
    assert "syscallSetView('graph')" in button
    # the surface is a sibling of the map's in the work area, hidden until GRAPH is chosen
    work = tab[tab.index('id="syscall-work"'):]
    assert work.index('id="syscall-surface-map"') < work.index('id="syscall-surface-graph"') < work.index('id="syscall-detail"')
    surface = re.search(r'<div[^>]*id="syscall-surface-graph"[^>]*>', tab).group(0)
    assert " hidden" in surface
    for needed in ("binary-graph-query", "binary-graph-module", "binary-graph-function", "binary-graph-run",
                   "binary-graph-status", "binary-graph-canvas", "binary-graph-legend"):
        assert f'id="{needed}"' in tab, needed
    query = re.search(r'<select[^>]*id="binary-graph-query".*?</select>', tab, re.S).group(0)
    assert re.findall(r'<option value="([^"]+)"', query)[0] == "path-to-syscall"
    head = tab[tab.index('id="syscall-surface-graph"'):tab.index('id="syscall-detail"')]
    info = re.findall(r'data-info="([^"]+)"', head)
    assert info and all(len(t) <= 300 and t[-1] in ".!?" for t in info)


@needs_node
def test_the_graph_view_shows_its_surface_and_the_pane_toggle_names_it():
    r = _graph_flow(r"""
      initSyscalls();
      const look = () => ({ map: els['syscall-surface-map'].hidden, graph: els['syscall-surface-graph'].hidden,
                            pressed: [els['syscall-view-map'].attrs['aria-pressed'], els['syscall-view-graph'].attrs['aria-pressed']],
                            pane: els['syscall-pane-map'].textContent });
      const before = look();
      const switched = syscallSetView('graph');
      const graph = look();
      syscallSetView('map');
      out({ before, switched, graph, back: look() });""")
    assert r["switched"] is True
    assert r["graph"] == {"map": True, "graph": False, "pressed": ["false", "true"], "pane": "GRAPH"}
    assert r["back"] == {"map": False, "graph": True, "pressed": ["true", "false"], "pane": "MAP"}


# --- The layers and the curated hop --------------------------------------------------------------------------------

@needs_node
def test_a_path_answer_draws_one_layer_per_hop_in_the_order_the_answer_gives():
    r = _draw(r"""
      const a = PATH();
      const layout = binaryGraphLayout(a.nodes, a.edges, a.roots);
      // the same path with its nodes listed backwards: the layers follow the hops, not the list
      const back = binaryGraphLayout([...a.nodes].reverse(), a.edges, a.roots);
      out({ boxes: layout.boxes.map(b => [b.id, b.layer, b.x, b.y]), back: back.boxes.map(b => [b.id, b.layer]),
            svg: binaryGraphSvg(layout, quiet) });""")
    order = ["sample.dll", "api-ms-win-core-handle-l1-1-0.dll!CloseHandle", "kernelbase.dll!CloseHandle", "syscall:NtClose"]
    boxes = {b[0]: b for b in r["boxes"]}
    assert sorted(boxes) == sorted(order)
    assert [boxes[i][1] for i in order] == [0, 1, 2, 3], "one layer per hop"
    xs = [boxes[i][2] for i in order]
    assert xs == sorted(xs) and len(set(xs)) == 4, "left to right in the order of the path"
    assert len({boxes[i][3] for i in order}) == 1, "a single path runs in one straight row"
    assert {b[0]: b[1] for b in r["back"]} == {i: n for n, i in enumerate(order)}
    _, nodes, lines = _svg_parts(r["svg"])
    assert [n["attrs"]["data-id"] for n in nodes] and len(nodes) == 4 and len(lines) == 3
    assert {n["attrs"]["data-id"]: n["attrs"]["data-layer"] for n in nodes} == {i: str(n) for n, i in enumerate(order)}


@needs_node
def test_the_curated_edge_is_drawn_with_its_own_stroke_and_named_in_the_legend():
    r = _draw(r"""
      const a = PATH();
      out({ svg: binaryGraphSvg(binaryGraphLayout(a.nodes, a.edges, a.roots), quiet), legend: binaryGraphLegend() });""")
    _, _, lines = _svg_parts(r["svg"])
    # the shape first: two derived edges and one curated, the curated one the last hop
    origins = [l["attrs"].get("data-origin") for l in lines]
    assert sorted(origins) == ["curated", "derived", "derived"], origins
    curated = next(l["attrs"] for l in lines if l["attrs"]["data-origin"] == "curated")
    derived = [l["attrs"] for l in lines if l["attrs"]["data-origin"] == "derived"]
    assert curated["data-target"] == "syscall:NtClose"
    # its own stroke: dashed, in its own colour, where a derived edge is solid
    assert curated.get("stroke-dasharray"), "the curated edge is not dashed"
    assert all(not d.get("stroke-dasharray") for d in derived)
    assert curated["stroke"] == "--graph-edge-curated" and all(d["stroke"] != curated["stroke"] for d in derived)
    # and named in words on the canvas, not by the dash alone
    tags = [e for e in _Elements(r["svg"]).elements if "binary-graph-edge-tag" in _classes(e)]
    assert [t["text"] for t in tags] == ["curated"]
    # the legend has a row for each origin, and the curated one draws the same stroke and says what it is
    rows = {e["attrs"]["data-legend"]: e for e in _Elements(r["legend"]).elements if "data-legend" in e["attrs"]}
    assert {"edge-derived", "edge-curated"} <= set(rows), sorted(rows)
    sample = [e for e in _Elements(r["legend"]).elements if e["tag"] == "line" and e["attrs"].get("data-origin") == "curated"]
    assert sample and sample[0]["attrs"].get("stroke-dasharray") == curated["stroke-dasharray"]
    assert sample[0]["attrs"]["stroke"] == curated["stroke"]
    words = rows["edge-curated"]["text"].lower()
    assert "curated" in words and "table" in words and "not read from any binary" in words
    assert "read from the binaries" in rows["edge-derived"]["text"].lower()


@needs_node
def test_the_detail_of_a_curated_edge_says_the_mapping_comes_from_a_table():
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallSetView('graph');
        await ask({ body: PATH() });
        const lines = () => (els['binary-graph-canvas'].innerHTML.match(/<path class="binary-graph-edge-line[^>]*>/g) || []);
        const curated = lines().find(l => l.includes('data-origin="curated"'));
        const index = /data-edge="(\d+)"/.exec(curated)[1];
        binaryGraphSelect('edge:' + index);
        const detail = els['syscall-detail-body'].innerHTML, marked = lines().find(l => l.includes('data-origin="curated"'));
        const derived = lines().find(l => l.includes('data-origin="derived"'));
        binaryGraphSelect('edge:' + /data-edge="(\d+)"/.exec(derived)[1]);
        out({ detail, derived: els['syscall-detail-body'].innerHTML, edges: lines().length });
      })();""")
    assert r["edges"] == 3
    detail = re.sub(r"<[^>]+>", " ", r["detail"])
    text = " ".join(detail.split()).lower()
    assert "closehandle" in text and "ntclose" in text, "the panel names the edge it speaks of"
    assert "curated" in text and "not derived" in text
    assert "not read from any binary" in text and "win32 to nt table" in text
    assert "curated: phnt" in text, "the table's own word for the row"
    other = " ".join(re.sub(r"<[^>]+>", " ", r["derived"]).split()).lower()
    assert "derived" in other and "not read from any binary" not in other and "curated" not in other


# --- What the view says besides the drawing ------------------------------------------------------------------------

@needs_node
def test_a_note_from_the_answer_is_shown_instead_of_an_empty_canvas():
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallSetView('graph');
        const empty = { nodes: [], edges: [], truncated: false, total: 0, roots: [], build: '26220.5770', arch: 'arm64', created: '',
                        note: 'sample.dll neither imports nor exports CloseHandle in the binary graph.' };
        await ask({ body: empty });
        out({ canvas: els['binary-graph-canvas'].innerHTML, state: binaryGraphState.note });
      })();""")
    assert "<svg" not in r["canvas"]
    assert "sample.dll neither imports nor exports CloseHandle in the binary graph." in r["canvas"]
    assert r["state"] == "sample.dll neither imports nor exports CloseHandle in the binary graph."


@needs_node
def test_a_truncated_answer_says_so_in_the_view():
    # the cap keeps the first parts in name order and never draws half a path, so a
    # missing node means "not shown", never "does not import" — the view must say which
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallSetView('graph');
        const many = [...Array(249)].map((_, i) => ({ id: 'b' + i + '.dll', label: 'b' + i + '.dll', kind: 'dll', in_degree: 0, category: '' }));
        const cut = { nodes: [{ id: 'kernel32.dll', label: 'kernel32.dll', kind: 'dll', in_degree: 4000, category: '' }, ...many],
                      edges: many.map(n => ({ source: n.id, target: 'kernel32.dll', kind: 'imports', origin: 'derived', label: '' })),
                      truncated: true, total: 4000, roots: ['kernel32.dll'], build: '26220.5770', arch: 'arm64', created: '',
                      note: 'Only the first 249 of 4000 binaries that import it are drawn.' };
        await ask({ body: cut }, 'kernel32.dll', '');
        const truncated = els['binary-graph-status'].textContent || els['binary-graph-status'].innerHTML;
        // a cut answer that kept no node still says it was cut
        await ask({ body: { ...cut, nodes: [], edges: [], roots: [] } }, 'kernel32.dll', '');
        const bare = [els['binary-graph-status'].innerHTML, els['binary-graph-status'].hidden, els['binary-graph-canvas'].innerHTML];
        await ask({ body: PATH() });
        out({ truncated, bare, whole: els['binary-graph-status'].textContent || els['binary-graph-status'].innerHTML,
              drawn: (els['binary-graph-canvas'].innerHTML.match(/class="binary-graph-node /g) || []).length });
      })();""")
    cut = " ".join(re.sub(r"<[^>]+>", " ", r["truncated"]).split())
    assert "4,000" in cut and "250 nodes" in cut, cut
    # the count comes from the answer, not from a copy of the backend's cap that may go stale
    line = re.search(r'<strong class="binary-graph-cut">(.*?)</strong>', r["truncated"]).group(1)
    assert "400" not in line.replace("4,000", ""), line
    assert "not shown" in cut and "does not mean" in cut and "not imported" in cut, cut
    bare = " ".join(re.sub(r"<[^>]+>", " ", r["bare"][0]).split())
    assert r["bare"][1] is False and "4,000" in bare and "not shown" in bare, bare
    assert "Only the first 249" in r["bare"][2], "the note still stands in the canvas"
    whole = " ".join(re.sub(r"<[^>]+>", " ", r["whole"]).split())
    assert "4,000" not in whole and "not shown" not in whole, "a whole answer does not claim to be cut"
    assert r["drawn"] == 4


@needs_node
def test_an_edge_of_an_unknown_origin_is_neither_drawn_nor_described_as_derived():
    # Ruling 49: only origin "derived" may claim it was read from a binary; a missing, misspelled or future value
    # must not round toward the generous reading
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallSetView('graph');
        const a = PATH();
        a.edges[0] = { ...a.edges[0], origin: undefined };
        a.edges[1] = { ...a.edges[1], origin: 'Derived' };
        a.edges.push({ source: 'sample.dll', target: 'kernelbase.dll!CloseHandle', kind: 'imports', origin: 'inferred', label: '' });
        a.edges.push({ source: 'sample.dll', target: 'syscall:NtClose', kind: 'imports', origin: 'derived', label: '' });
        await ask({ body: a });
        const lines = els['binary-graph-canvas'].innerHTML.match(/<path class="binary-graph-edge-line[^>]*>/g) || [];
        const details = [0, 1, 3, 4].map(i => { binaryGraphSelect('edge:' + i); return els['syscall-detail-body'].innerHTML; });
        out({ lines, details, legend: els['binary-graph-legend'].innerHTML });
      })();""")
    lines = [_Elements(l).elements[0]["attrs"] for l in r["lines"]]
    assert len(lines) == 5
    by_edge = {l["data-edge"]: l for l in lines}
    assert by_edge["4"]["data-origin"] == "derived" and by_edge["2"]["data-origin"] == "curated"
    derived = by_edge["4"]
    for key in ("0", "1", "3"):
        unknown = by_edge[key]
        assert unknown["data-origin"] == "unknown", unknown
        assert "binary-graph-edge-derived" not in unknown["class"]
        assert (unknown["stroke"], unknown.get("stroke-dasharray")) != (derived["stroke"], derived.get("stroke-dasharray"))
        assert unknown.get("stroke-dasharray") != by_edge["2"].get("stroke-dasharray"), "nor does it pass for curated"
    texts = [" ".join(re.sub(r"<[^>]+>", " ", d).split()).lower() for d in r["details"]]
    for text in texts[:3]:
        assert "unknown" in text and "derived" not in text and "read from the binaries" not in text, text
    assert "derived" in texts[3] and "read from the binaries" in texts[3]
    rows = {e["attrs"]["data-legend"]: e for e in _Elements(r["legend"]).elements if "data-legend" in e["attrs"]}
    assert "edge-unknown" in rows and "unknown" in rows["edge-unknown"]["text"].lower()


@needs_node
def test_a_kind_named_like_an_object_member_is_not_read_off_the_prototype():
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallSetView('graph');
        const a = PATH();
        a.nodes[0] = { ...a.nodes[0], kind: 'constructor' };
        a.edges[0] = { ...a.edges[0], kind: 'toString' };
        await ask({ body: a });
        const svg = els['binary-graph-canvas'].innerHTML;
        binaryGraphSelect('sample.dll'); const node = els['syscall-detail-body'].innerHTML;
        binaryGraphSelect('edge:0'); const edge = els['syscall-detail-body'].innerHTML;
        out({ svg, node, edge });
      })();""")
    for key in ("svg", "node", "edge"):
        assert "native code" not in r[key] and "function Object" not in r[key] and "function toString" not in r[key], key
    assert "constructor" in r["node"] and "toString" in r["edge"]


# --- A deviation and a filter match --------------------------------------------------------------------------------

SCANNED = r"""
const scanned = async (deviations) => {
  initSyscalls(); syscallsTabShown(); await settle();
  routes['/api/syscalls/scan'] = { body: scanBody(deviations) };
  chooseTarget(4242);
  await runSyscallScan();
  syscallSetView('graph');
};
const canvasParts = () => {
  const svg = els['binary-graph-canvas'].innerHTML;
  return { nodes: svg.match(/<g class="binary-graph-node [^>]*>(?:(?!<\/g>).)*<\/g>/gs) || [],
           lines: svg.match(/<path class="binary-graph-edge-line[^>]*>/g) || [] };
};
"""


def _node_rect(node_markup):
    """The box of a node: its first rect, with the stroke and fill it is drawn in."""
    rects = [e for e in _Elements(node_markup).elements if "binary-graph-box" in _classes(e)]
    assert len(rects) == 1, node_markup
    return rects[0]["attrs"]


@needs_node
def test_a_syscall_node_whose_stub_deviated_in_the_last_scan_is_drawn_in_the_patched_tone():
    r = _graph_flow(SCANNED + r"""
      (async () => {
        await scanned({ Nt5: 'patched' });
        await ask({ body: PATH('Nt5', 5) });
        out(canvasParts());
      })();""")
    assert len(r["nodes"]) == 4
    syscall = next(n for n in r["nodes"] if 'data-id="syscall:Nt5"' in n)
    assert 'data-tone="patched"' in syscall
    box = _node_rect(syscall)
    assert box["stroke"] == "--syscall-patched" and box["fill"].startswith("--syscall-patched/")
    for other in (n for n in r["nodes"] if n is not syscall):
        assert "--syscall-" not in _node_rect(other)["stroke"], "only the deviating syscall is in its tone"


@needs_node
def test_the_edges_of_the_path_to_a_deviating_syscall_are_drawn_in_that_tone_too():
    r = _graph_flow(SCANNED + r"""
      (async () => {
        await scanned({ Nt5: 'patched' });
        // two paths: one to the patched Nt5, one to the intact Nt6, sharing nothing
        const a = PATH('Nt5', 5), b = PATH('Nt6', 6);
        const rename = id => id === 'syscall:Nt6' ? id : 'other-' + id;
        const both = { ...a, nodes: [...a.nodes, ...b.nodes.map(n => ({ ...n, id: rename(n.id) }))],
                       edges: [...a.edges, ...b.edges.map(e => ({ ...e, source: rename(e.source), target: rename(e.target) }))],
                       roots: ['sample.dll', 'other-sample.dll'] };
        await ask({ body: both });
        out(canvasParts());
      })();""")
    lines = [_Elements(l).elements[0]["attrs"] for l in r["lines"]]
    assert len(lines) == 6
    to_patched = [l for l in lines if not l["data-source"].startswith("other-") and l["data-target"] != "syscall:Nt6"]
    to_intact = [l for l in lines if l not in to_patched]
    assert len(to_patched) == 3 and len(to_intact) == 3
    assert all(l["stroke"] == "--syscall-patched" and l["data-tone"] == "patched" for l in to_patched), to_patched
    assert all("--syscall-" not in l["stroke"] and "data-tone" not in l for l in to_intact), to_intact
    # the curated hop keeps its own dash in the tone: the colour says "deviated", the dash still says "curated"
    curated = [l for l in to_patched if l["data-origin"] == "curated"]
    assert len(curated) == 1 and curated[0].get("stroke-dasharray")


@needs_node
def test_a_filter_match_is_highlighted_in_its_own_tone_and_not_in_the_deviation_tone():
    r = _graph_flow(SCANNED + r"""
      (async () => {
        await scanned({ Nt5: 'patched' });
        await ask({ body: PATH('Nt7', 7) });
        els['syscall-filter'].value = 'Nt7'; syscallOnFilter();
        const filtered = canvasParts();
        els['syscall-filter'].value = 'kernelbase'; syscallOnFilter();
        out({ filtered, module: canvasParts() });
      })();""")
    nodes = r["filtered"]["nodes"]
    assert len(nodes) == 4
    match = next(n for n in nodes if 'data-id="syscall:Nt7"' in n)
    rings = [e["attrs"] for e in _Elements(match).elements if "binary-graph-match-ring" in _classes(e)]
    assert len(rings) == 1 and rings[0]["stroke"] == "--graph-match"
    assert "--syscall-patched" not in match and "data-tone" not in match, "a match is not a deviation"
    assert all("binary-graph-match-ring" not in n for n in nodes if n is not match)
    by_module = [n for n in r["module"]["nodes"] if "binary-graph-match-ring" in n]
    assert len(by_module) == 1 and 'data-id="kernelbase.dll!CloseHandle"' in by_module[0]


@needs_node
def test_a_node_that_both_matches_and_deviated_keeps_the_ring_and_the_tone():
    r = _graph_flow(SCANNED + r"""
      (async () => {
        await scanned({ Nt5: 'patched' });
        await ask({ body: PATH('Nt5', 5) });
        els['syscall-filter'].value = 'Nt5'; syscallOnFilter();
        out(canvasParts());
      })();""")
    assert len(r["nodes"]) == 4
    node = next(n for n in r["nodes"] if 'data-id="syscall:Nt5"' in n)
    assert 'data-tone="patched"' in node
    rings = [e["attrs"] for e in _Elements(node).elements if "binary-graph-match-ring" in _classes(e)]
    assert len(rings) == 1 and rings[0]["stroke"] == "--graph-match"
    box = _node_rect(node)
    assert box["stroke"] == "--syscall-patched", "the match does not cover the tone"


@needs_node
def test_without_a_scan_no_node_is_drawn_in_a_deviation_tone():
    r = _graph_flow(SCANNED + r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle(); syscallSetView('graph');
        await ask({ body: PATH('Nt5', 5) });
        const before = canvasParts();
        // a scan of another view than the graph's says nothing about the graph's syscalls either
        routes['/api/syscalls/scan'] = { body: scanBody({ Nt5: 'patched' }) };
        chooseTarget(4242); await runSyscallScan();
        const scannedArm = canvasParts();
        await ask({ body: { ...PATH('Nt5', 5), arch: 'x64' } });
        out({ before, scannedArm, other: canvasParts() });
      })();""")
    for key in ("before", "other"):
        parts = r[key]
        assert len(parts["nodes"]) == 4 and len(parts["lines"]) == 3, key
        markup = "".join(parts["nodes"] + parts["lines"])
        assert "--syscall-" not in markup and "data-tone" not in markup, key
    # the guard is not vacuous: the same answer after a scan of its view is in the tone
    assert any('data-tone="patched"' in n for n in r["scannedArm"]["nodes"])


# --- The map and the graph share one detail panel ------------------------------------------------------------------

@needs_node
def test_clicking_a_syscall_node_selects_the_same_cell_in_the_map():
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle(); syscallSetView('graph');
        await ask({ body: PATH('Nt5', 5) });
        binaryGraphSelect('syscall:Nt5'); await settle();
        out({ selected: syscallState.selected, asked: requests.some(q => q.url.startsWith('/api/syscalls/Nt5')),
              row: /<button[^>]*class="syscall-row selected"[^>]*data-name="Nt5"/.test(els['syscall-rows'].innerHTML),
              detail: els['syscall-detail-body'].innerHTML, graph: binaryGraphState.selected });
      })();""")
    assert r["selected"] == "Nt5" and r["asked"] and r["row"]
    assert "Nt5" in r["detail"]
    assert r["graph"] == "syscall:Nt5"


@needs_node
def test_selecting_a_cell_in_the_map_marks_the_same_node_in_the_graph():
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle(); syscallSetView('graph');
        await ask({ body: PATH('Nt5', 5) });
        const before = (els['binary-graph-canvas'].innerHTML.match(/<g class="binary-graph-node [^"]*selected/g) || []).length;
        syscallSelect('Nt5'); await settle();
        const svg = els['binary-graph-canvas'].innerHTML;
        out({ before, marked: (svg.match(/<g class="binary-graph-node [^"]*\bselected\b[^"]*"[^>]*data-id="([^"]+)"/g) || []) });
      })();""")
    assert r["before"] == 0
    assert len(r["marked"]) == 1 and 'data-id="syscall:Nt5"' in r["marked"][0]


# --- Escaping ------------------------------------------------------------------------------------------------------

@needs_node
def test_a_module_name_from_an_import_table_reaches_the_graph_as_text_and_not_as_markup():
    r = _draw(r"""
      const evil = '<img src=x onerror=alert(1)>.dll';
      const a = PATH();
      a.nodes[0] = { ...a.nodes[0], id: evil, label: evil, kind: 'x" onclick="alert(1)' };
      a.edges[0] = { ...a.edges[0], source: evil, origin: 'derived" onmouseover="alert(2)' };
      a.roots = [evil];
      out(binaryGraphSvg(binaryGraphLayout(a.nodes, a.edges, a.roots), { ...quiet, tones: binaryGraphTones(a.nodes, a.edges, null) }));""")
    assert "<img" not in r and "&lt;img" in r
    elements = _Elements(r).elements
    assert all(e["tag"] != "img" for e in elements)
    node = next(e for e in elements if e["attrs"].get("data-id") == "<img src=x onerror=alert(1)>.dll")
    assert set(_classes(node)) >= {"binary-graph-node", "binary-graph-node-xonclickalert1"}
    assert node["attrs"]["onclick"] == 'binaryGraphSelect("<img src=x onerror=alert(1)>.dll")'
    for e in elements:
        assert not {k for k in e["attrs"] if k.startswith("on")} - {"onclick"}, e


@needs_node
def test_the_note_and_the_error_of_an_answer_are_escaped_like_any_node_label():
    # both echo what the user typed for `module` or `name`: safe as JSON, not as HTML
    r = _graph_flow(r"""
      (async () => {
        initSyscalls(); syscallSetView('graph');
        const typed = '<img src=x onerror=alert(1)>';
        await ask({ body: { ...PATH(), note: typed + ' neither imports nor exports it.' } }, typed);
        const withNodes = els['binary-graph-status'].innerHTML + els['binary-graph-canvas'].innerHTML;
        await ask({ body: { nodes: [], edges: [], truncated: false, total: 0, roots: [], note: typed + ' is not in the binary graph.' } }, typed);
        const note = els['binary-graph-canvas'].innerHTML + els['binary-graph-status'].innerHTML;
        await ask({ status: 404, body: { error: 'There is no binary graph for build ' + typed + ' yet.', cache: null } }, typed);
        out({ withNodes, note, error: els['binary-graph-canvas'].innerHTML + els['binary-graph-status'].innerHTML });
      })();""")
    for key in ("withNodes", "note", "error"):
        assert "<img" not in r[key] and "&lt;img" in r[key], key
    assert "There is no binary graph for build &lt;img" in r["error"]


# --- Colours -------------------------------------------------------------------------------------------------------

GRAPH_VARS = ["--graph-node-dll", "--graph-node-exe", "--graph-node-syscall", "--graph-node-apiset", "--graph-edge-curated",
              "--graph-match"]


def test_the_graph_colours_exist_in_both_themes_with_their_rgb_triplets():
    for theme, values in (("Telemetry", _root_values()), ("Cyberpunk", _cyberpunk_palette())):
        for name in GRAPH_VARS:
            assert values.get(name) and values.get(name + "-rgb"), f"{theme}: {name}"


def test_the_curated_edge_and_the_match_do_not_look_like_a_deviation():
    def distance(a, b):
        return sum((x - y) ** 2 for x, y in zip(_hex_rgb(a), _hex_rgb(b))) ** 0.5
    for theme, values in (("Telemetry", _root_values()), ("Cyberpunk", _cyberpunk_palette())):
        for name in ("--graph-edge-curated", "--graph-match"):
            for state in ("--syscall-patched", "--syscall-hooked", "--syscall-diverged"):
                assert distance(values[name], values[state]) >= 60, f"{theme}: {name} looks like {state}"
        assert distance(values["--graph-edge-curated"], values["--graph-match"]) >= 60, theme


def test_the_assets_moved_on():
    html = _read(INDEX_HTML)
    for asset, minimum in (("style.css", 89), ("theme-cyberpunk.css", 38), ("app.js", 147)):
        version = int(re.search(rf"{re.escape(asset)}\?v=(\d+)", html).group(1))
        assert version >= minimum, f"{asset} was changed and kept its ?v="


# === EXPLORE: the graph opened one node at a time ======================================================================

# the functions and constants of the block are in the flow's lists (tests/test_syscalls_ui.py); the process graph's
# layout and its state are not of the block
EXPLORE_FUNCTIONS = ["applyForceLayout"]
EXPLORE_CONSTS = ["graphState"]
EXPLORE_IDS = ["binary-graph-path", "binary-explore", "binary-graph-mode-path", "binary-graph-mode-explore", "binary-explore-start",
               "binary-explore-status", "binary-explore-stage", "binary-explore-canvas", "binary-explore-info",
               "binary-explore-legend", "binary-explore-expand", "binary-explore-zoom", "binary-explore-depth-1",
               "binary-explore-depth-2", "binary-explore-depth-3", "binary-explore-functions", "binary-graph-legend", "binary-graph-status", "binary-graph-canvas"]

# The page of the explore view, a canvas that writes down what is drawn on it (the last frame: clearRect starts it
# again), and the binary graph behind /api/binary-graph/node and /api/binary-graph/query answering the way the server
# does: an `imports` answer has the module and one function node per import, an `importers` answer the module and one
# node per importer (with the api set it imports through), both cut whole at 400 nodes with `truncated` and `total`
EXPLORE_DOM = r"""
for (const id of __IDS__) els[id] = Object.assign(new Node(id.endsWith('canvas') ? 'canvas' : 'div'), { id });
els['binary-explore'].hidden = true;
els['binary-explore-stage'].clientWidth = 600; els['binary-explore-stage'].clientHeight = 400;
const seen = [];
const realGet = document.getElementById;
document.getElementById = id => { seen.push(id); return realGet(id); };
const log = [];
const ctx = { globalAlpha: 1, fillStyle: '', strokeStyle: '', lineWidth: 1, font: '', textAlign: '', textBaseline: '', dash: [],
  save() {}, restore() {}, translate(x, y) { log.push({ op: 'translate', x, y }); }, scale(k) { log.push({ op: 'scale', k }); },
  clearRect() { log.length = 0; }, beginPath() { log.push({ op: 'begin' }); }, closePath() {},
  arc(x, y, r) { log.push({ op: 'arc', x, y, r }); }, moveTo(x, y) { log.push({ op: 'moveTo', x, y }); },
  lineTo(x, y) { log.push({ op: 'lineTo', x, y }); }, setLineDash(d) { this.dash = d; },
  fill() { log.push({ op: 'fill', color: this.fillStyle, alpha: this.globalAlpha }); },
  stroke() { log.push({ op: 'stroke', color: this.strokeStyle, width: this.lineWidth, alpha: this.globalAlpha, dash: this.dash.join(' ') }); },
  fillText(text, x, y) { log.push({ op: 'text', text: String(text), x, y, color: this.fillStyle }); },
  fillRect() {}, measureText: t => ({ width: String(t).length * 6 }) };
els['binary-explore-canvas'].ctx = ctx; els['binary-explore-canvas'].getContext = () => ctx;
els['binary-explore-canvas'].width = 600; els['binary-explore-canvas'].height = 400;
// the last frame: node discs (an arc that is filled), rings (an arc that is only stroked) and edges (a stroked line,
// in the order of the edges that are drawn)
const frame = () => {
  const shapes = []; let cur = null;
  for (const e of log) { if (e.op === 'begin') { cur = { ops: [] }; shapes.push(cur); } else if (cur && e.op !== 'text') cur.ops.push(e); }
  const f = { discs: [], rings: [], lines: [], texts: log.filter(e => e.op === 'text').map(e => e.text) };
  for (const s of shapes) {
    const arc = s.ops.find(o => o.op === 'arc'), stroke = s.ops.find(o => o.op === 'stroke'), fill = s.ops.find(o => o.op === 'fill');
    if (arc && fill) f.discs.push({ x: arc.x, y: arc.y, r: arc.r, fill: fill.color, stroke: stroke && stroke.color, dash: stroke && stroke.dash });
    else if (arc && stroke) f.rings.push({ x: arc.x, y: arc.y, r: arc.r, color: stroke.color });
    else if (stroke) f.lines.push({ color: stroke.color, width: stroke.width, alpha: stroke.alpha, dash: stroke.dash });
  }
  return f;
};
const st = binaryGraphExplore;
const at = id => st.nodes.find(n => n.id === id);
const drawnIds = () => st.nodes.map(n => n.id).sort();
// the drawn disc of a node, found by where it is
const discOf = (f, id) => { const n = at(id); const found = f.discs.filter(d => d.x === n.x && d.y === n.y); return found.length === 1 ? found[0] : null; };
const screenOf = id => { const n = at(id), c = st.camera; return { offsetX: n.x * c.zoom + c.x, offsetY: n.y * c.zoom + c.y }; };
const queries = (from = 0) => requests.slice(from).filter(q => q.url.startsWith('/api/binary-graph/query')).map(q => Object.fromEntries(new URL(q.url, 'http://x').searchParams));
const GRAPH = {
  'app.exe': { in_degree: 0, imports: { 'kernel32.dll': ['CreateFileW', 'CloseHandle'], 'ntdll.dll': ['NtClose'], 'user32.dll': ['MessageBoxW'] } },
  'kernel32.dll': { in_degree: 3900, machine: 'ARM64',
    imports: { 'kernelbase.dll': ['CreateFileW'], 'ntdll.dll': ['NtClose', 'RtlFoo'], 'api-ms-win-core-handle-l1-1-0.dll': ['CloseHandle'] } },
  'ntdll.dll': { in_degree: 4000, imports: {} },
  'kernelbase.dll': { in_degree: 3500, imports: { 'ntdll.dll': ['NtClose'] } },
  'user32.dll': { in_degree: 2000, imports: { 'win32u.dll': ['NtUserFoo'], 'gdi32.dll': ['GetDC'] } },
  'win32u.dll': { in_degree: 1500, imports: { 'ntdll.dll': ['NtClose'] } },
  'gdi32.dll': { in_degree: 1800, imports: {} },
  'api-ms-win-core-handle-l1-1-0.dll': { is: 'api-set', in_degree: 900, hosts: ['kernelbase.dll'] },
};
const nodeRoute = (url) => {
  let name = new URL(url, 'http://x').searchParams.get('name').trim().toLowerCase();
  if (!/[.](dll|exe)$/.test(name)) name += '.dll';
  const g = GRAPH[name];
  if (!g) return { status: 404, body: { error: name + ' is neither a binary nor an api set in the binary graph of this system.', in_degree: 0 } };
  return { body: { name, is: g.is || 'binary', kind: g.is === 'api-set' ? 'api-set' : /[.]exe$/.test(name) ? 'exe' : 'dll', machine: g.machine || '',
                   in_degree: g.in_degree, partial: false, imports: g.imports || {}, exports: [], forwarders: {}, hosts: g.hosts || [] } };
};
const modNode = name => { const g = GRAPH[name] || {}; return { id: name, label: name, kind: g.is === 'api-set' ? 'api-set' : /[.]exe$/.test(name) ? 'exe' : 'dll', in_degree: g.in_degree || 0, category: '' }; };
const STAMP = { build: '26220.5770', arch: 'arm64', created: '' };
const cutAnswer = (fixed, parts, note, what, partial = false) => {
  const nodes = new Map(), edges = new Map(), roots = [];
  const take = p => { for (const n of p.nodes) if (!nodes.has(n.id)) nodes.set(n.id, n);
                      for (const e of p.edges) edges.set([e.source, e.target, e.kind, e.label].join('|'), e);
                      for (const r of p.roots) if (!roots.includes(r)) roots.push(r); };
  take(fixed); let kept = 0;
  for (const p of parts) { if (nodes.size + p.nodes.filter(n => !nodes.has(n.id)).length > 400) break; take(p); kept++; }
  const truncated = kept < parts.length;
  if (truncated) note += ' Only the first ' + kept + ' of ' + parts.length + ' ' + what + ' are drawn: an answer is cut at 400 nodes.';
  return { nodes: [...nodes.values()], edges: [...edges.values()], truncated, note, roots, total: parts.length, partial, ...STAMP };
};
const none = (note, partial = false) => ({ nodes: [], edges: [], truncated: false, note, roots: [], total: 0, partial, ...STAMP });
// as the backend: a table of the binary itself for its imports, any table the query read for who imports it
const anyCut = () => Object.values(GRAPH).some(g => g.partial === true);
const derived = (source, target, kind, label) => ({ source, target, kind, origin: 'derived', label });
const importsOf = name => {
  const g = GRAPH[name];
  if (!g || g.is === 'api-set') return none(name + ' is not in the binary graph of this system.');
  const parts = [];
  for (const [imported, names] of Object.entries(g.imports || {})) for (const fn of names) {
    const id = imported + '!' + fn;
    parts.push({ nodes: [{ id, label: fn, kind: 'function', in_degree: 0, category: '' }], edges: [derived(name, id, 'imports', imported)], roots: [] });
  }
  if (!parts.length) return none(name + ' imports nothing.', g.partial === true);
  return cutAnswer({ nodes: [modNode(name)], edges: [], roots: [name] }, parts, name + ' imports ' + parts.length + ' functions.'
    + (g.partial ? ' Its import table was cut short when it was read, so the list may be incomplete.' : ''), 'imported functions', g.partial === true);
};
const importersOf = (target, fn) => {
  const t = GRAPH[target];
  if (!t) return none(target + ' is not in the binary graph of this system, and no binary in it imports it.');
  const aliases = t.is === 'api-set' ? [] : Object.keys(GRAPH).filter(a => GRAPH[a].is === 'api-set' && (GRAPH[a].hosts || []).includes(target));
  const parts = [];
  for (const name of Object.keys(GRAPH).sort()) {
    const g = GRAPH[name];
    if (g.is === 'api-set') continue;
    const part = { nodes: [modNode(name)], edges: [], roots: [] };
    for (const [imported, names] of Object.entries(g.imports || {})) {
      if (fn && !names.includes(fn)) continue;
      if (imported === target) part.edges.push(derived(name, target, 'imports', fn || ''));
      else if (aliases.includes(imported)) {
        part.nodes.push(modNode(imported));
        part.edges.push(derived(name, imported, 'imports', fn || ''), derived(imported, target, 'resolves_to', fn || ''));
      }
    }
    if (part.edges.length) parts.push(part);
  }
  if (!parts.length) return none('No binary in the graph imports ' + (fn ? fn + ' from ' : '') + target + '.', anyCut());
  return cutAnswer({ nodes: [modNode(target)], edges: [], roots: [target] }, parts, parts.length + ' binaries import ' + target + '.', 'binaries that import it', anyCut());
};
const queryRoute = url => {
  const q = new URL(url, 'http://x').searchParams, module = (q.get('module') || '').toLowerCase();
  if (q.get('q') === 'imports') return { body: importsOf(module) };
  if (q.get('q') === 'importers') return { body: importersOf(module, q.get('function') || '') };
  return { status: 400, body: { error: 'q must be one of importers, imports' } };
};
routes['/api/binary-graph/node'] = nodeRoute;
routes['/api/binary-graph/query'] = queryRoute;
""".replace("__IDS__", "[" + ", ".join(f"'{i}'" for i in EXPLORE_IDS) + "]")


def _explore_flow(script):
    consts = "\n".join(_const(c) for c in FLOW_CONSTS + EXPLORE_CONSTS)
    return _run_node(FLOW_FUNCTIONS + EXPLORE_FUNCTIONS, FLOW_DOM + EXPLORE_DOM + script,
                     "const themeColor = (name, alpha) => alpha === undefined ? name : name + '/' + alpha;\n" + consts)


def _explore_markup():
    tab = _tab_markup("syscalls")
    start = tab.index('id="binary-explore"')
    return tab[tab.rindex("<div", 0, start):tab.index('id="syscall-detail"')]


def _plain(html):
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def test_the_explore_view_is_in_the_page_with_its_canvas_and_its_depth_control():
    tab = _tab_markup("syscalls")
    for needed in ("binary-graph-path", "binary-explore", "binary-explore-start", "binary-explore-status", "binary-explore-stage",
                   "binary-explore-canvas", "binary-explore-info", "binary-explore-legend", "binary-explore-expand",
                   "binary-explore-zoom", "binary-graph-mode-path", "binary-graph-mode-explore"):
        assert f'id="{needed}"' in tab, needed
    # the query bar, its status, canvas and legend sit in the path view; the explore view is hidden until it is chosen
    path = re.search(r'<div[^>]*id="binary-graph-path"[^>]*>', tab).group(0)
    explore = re.search(r'<div[^>]*id="binary-explore"[^>]*>', tab).group(0)
    assert " hidden" in explore and " hidden" not in path
    assert tab.index('id="binary-graph-path"') < tab.index('id="binary-graph-query"') < tab.index('id="binary-explore"')
    canvas = re.search(r'<canvas[^>]*id="binary-explore-canvas"[^>]*>', tab).group(0)
    assert "onclick" not in canvas, "the canvas is wired by the script, from the one place that owns its state"
    info = re.findall(r'data-info="([^"]+)"', _explore_markup())
    assert info, "the explore view explains itself"
    for text in info:
        assert len(text) <= 300 and text[-1] in ".!?" and not any(bad in text for bad in ("<", "&", "${")), text


def test_the_depth_control_offers_one_to_three_and_nothing_outside():
    markup = _explore_markup()
    group = re.search(r'<span[^>]*id="binary-explore-depth"[^>]*>(.*?)</span>', markup, re.S).group(1)
    buttons = [b for b in _Elements(group).elements if b["tag"] == "button"]
    calls = [re.fullmatch(r"binaryGraphSetDepth\((\d+)\)", b["attrs"].get("onclick", "")) for b in buttons]
    assert calls and all(calls), "every button of the control sets a depth"
    assert [int(c.group(1)) for c in calls] == [1, 2, 3]
    assert [b["attrs"]["id"] for b in buttons] == ["binary-explore-depth-1", "binary-explore-depth-2", "binary-explore-depth-3"]


@needs_node
def test_a_depth_outside_one_to_three_is_refused_and_not_clamped():
    r = _explore_flow(r"""
      const depth = () => binaryGraphState.depth;
      const accepted = [1, 2, 3].map(n => [binaryGraphSetDepth(n), depth(), els['binary-explore-depth-' + n].attrs['aria-pressed']]);
      binaryGraphSetDepth(2);
      const refused = [0, 4, -1, 1.5, '2', NaN, null, undefined, Infinity, [2], true, 10].map(v => [binaryGraphSetDepth(v), depth()]);
      out({ accepted, refused, pressed: [1, 2, 3].map(n => els['binary-explore-depth-' + n].attrs['aria-pressed']) });""")
    assert r["accepted"] == [[True, 1, "true"], [True, 2, "true"], [True, 3, "true"]]
    assert len(r["refused"]) == 12 and all(a is False and d == 2 for a, d in r["refused"]), r["refused"]
    assert r["pressed"] == ["false", "true", "false"], "the control still shows the depth that is in force"


@needs_node
def test_the_explore_mode_starts_from_the_searched_binary_and_nothing_else():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls();
        binaryGraphSetMode('explore');
        const empty = frame();
        await binaryGraphExploreStart('KERNEL32');
        const first = { ids: st.nodes.map(n => n.id), edges: st.edges.length, urls: requests.map(q => q.url), selected: st.selected,
                        frame: frame(), info: els['binary-explore-info'].innerHTML };
        // a second search starts again from that binary alone; a name that is not in the graph keeps what is drawn
        await binaryGraphExploreStart('app.exe');
        const second = { ids: st.nodes.map(n => n.id), edges: st.edges.length };
        await binaryGraphExploreStart('nowhere.dll');
        const missing = { ids: st.nodes.map(n => n.id), note: st.note, status: els['binary-explore-status'].innerHTML };
        // a function as the path view names it opens its module
        await binaryGraphExploreStart('kernelbase.dll!CreateFileW');
        out({ empty, first, second, missing, fromFunction: st.nodes.map(n => n.id), all: requests.map(q => q.url) });
      })();""")
    first = r["first"]
    assert first["ids"] == ["kernel32.dll"] and first["edges"] == 0 and first["selected"] == "kernel32.dll"
    assert len(first["urls"]) == 1 and first["urls"][0].startswith("/api/binary-graph/node?") and "name=KERNEL32" in first["urls"][0]
    assert len(first["frame"]["discs"]) == 1 and first["frame"]["lines"] == [], "one disc, no edge: nothing else is drawn"
    assert "kernel32.dll" in first["frame"]["texts"]
    assert "kernel32.dll" in first["info"] and "3,900" in first["info"]
    assert r["empty"]["discs"] == [] and any("START" in t for t in r["empty"]["texts"]), "before a search the canvas says how to begin"
    assert r["second"] == {"ids": ["app.exe"], "edges": 0}
    assert r["missing"]["ids"] == ["app.exe"], "a name that is not in the graph does not wipe the exploration"
    assert "nowhere.dll is neither a binary nor an api set" in r["missing"]["note"] and "nowhere.dll" in r["missing"]["status"]
    assert r["fromFunction"] == ["kernelbase.dll"]
    assert not any("!" in u or "%21" in u for u in r["all"]), "only the module was asked for"


@needs_node
def test_the_mode_switch_shows_one_view_and_refuses_a_mode_it_does_not_have():
    r = _explore_flow(r"""
      initSyscalls();
      const look = () => ({ path: els['binary-graph-path'].hidden, explore: els['binary-explore'].hidden,
        pressed: [els['binary-graph-mode-path'].attrs['aria-pressed'], els['binary-graph-mode-explore'].attrs['aria-pressed']] });
      const result = [binaryGraphSetMode('explore'), look(), binaryGraphSetMode('path'), look(), binaryGraphSetMode('globe'), look(), binaryGraphSetMode(undefined)];
      out(result);""")
    assert r == [True, {"path": True, "explore": False, "pressed": ["false", "true"]}, True,
                 {"path": False, "explore": True, "pressed": ["true", "false"]}, False,
                 {"path": False, "explore": True, "pressed": ["true", "false"]}, False]


@needs_node
def test_expanding_ntdll_draws_who_imports_it_where_a_forward_only_expansion_saw_nothing():
    # ntdll imports nothing, and is the most interesting node of the graph: its neighbours are its importers
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('ntdll.dll');
        const asked = requests.length;
        const outgoing = importsOf('ntdll.dll');
        const opened = await binaryGraphExpand('ntdll.dll');
        out({ opened, outgoing: { nodes: outgoing.nodes.length, note: outgoing.note }, queries: queries(asked), ids: drawnIds(),
              edges: st.edges.map(e => [e.source, e.target, e.kind, e.origin]),
              kinds: Object.fromEntries(st.nodes.map(n => [n.id, [n.kind, n.in_degree]])), status: els['binary-explore-status'].innerHTML });
      })();""")
    assert r["outgoing"] == {"nodes": 0, "note": "ntdll.dll imports nothing."}, "the case that was blind: nothing goes out of ntdll"
    assert r["opened"] is True
    assert r["queries"] == [{"q": "imports", "module": "ntdll.dll"}, {"q": "importers", "module": "ntdll.dll"}]
    assert r["ids"] == ["app.exe", "kernel32.dll", "kernelbase.dll", "ntdll.dll", "win32u.dll"]
    assert sorted(r["edges"]) == sorted([[i, "ntdll.dll", "imports", "derived"] for i in ("app.exe", "kernel32.dll", "kernelbase.dll", "win32u.dll")])
    # size and colour came with the answer: no query asked for them
    assert r["kinds"]["kernel32.dll"] == ["dll", 3900] and r["kinds"]["app.exe"] == ["exe", 0] and r["kinds"]["ntdll.dll"] == ["dll", 4000]
    assert r["status"] == ""


@needs_node
def test_expanding_a_node_adds_its_neighbours_and_keeps_what_is_already_drawn():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('app.exe');
        const before = { x: at('app.exe').x, y: at('app.exe').y }, asked = requests.length;
        const one = await binaryGraphExpand('app.exe');
        const afterOne = { ids: drawnIds(), edges: st.edges.map(e => [e.source, e.target, e.kind, e.label, e.functions]), app: { x: at('app.exe').x, y: at('app.exe').y },
                           queries: queries(asked), kinds: [...new Set(st.nodes.map(n => n.kind))].sort() };
        // the functions of the module, the level deeper
        const functions = await binaryGraphOpenFunctions('app.exe');
        const placed = Object.fromEntries(st.nodes.map(n => [n.id, [n.x, n.y]])), askedAgain = requests.length;
        // a function is opened by who imports it: its edges end at the function, not at the module it is of
        const two = await binaryGraphExpand('ntdll.dll!NtClose');
        const askedTwo = queries(askedAgain);
        const moved = st.nodes.filter(n => placed[n.id] && (placed[n.id][0] !== n.x || placed[n.id][1] !== n.y)).map(n => n.id);
        const edges = st.edges.map(e => [e.source, e.target, e.kind, e.label]);
        // the same node twice gives no node and no edge twice
        await binaryGraphExpand('ntdll.dll!NtClose');
        out({ before, one, functions, afterOne, two, moved, ids: drawnIds(), edges, again: [st.nodes.length, st.edges.length],
              asked: askedTwo, frame: frame(), in_degree: at('kernel32.dll').in_degree });
      })();""")
    one = r["afterOne"]
    assert r["one"] is True and r["functions"] is True and r["two"] is True
    assert one["ids"] == ["app.exe", "kernel32.dll", "ntdll.dll", "user32.dll"]
    assert sorted(one["edges"]) == sorted([["app.exe", "kernel32.dll", "imports", "2 functions", 2], ["app.exe", "ntdll.dll", "imports", "1 function", 1],
                                           ["app.exe", "user32.dll", "imports", "1 function", 1]])
    assert one["kinds"] == ["dll", "exe"]
    assert one["queries"] == [{"q": "imports", "module": "app.exe"}, {"q": "importers", "module": "app.exe"}], "two queries, both directions"
    assert one["app"] == r["before"], "the node that was opened stays where it was"
    assert r["moved"] == [], "opening a function moves none of what was drawn"
    assert r["asked"] == [{"q": "importers", "module": "ntdll.dll", "function": "NtClose"}]
    assert r["ids"] == sorted(["app.exe", "kernel32.dll", "ntdll.dll", "user32.dll", "kernel32.dll!CloseHandle", "kernel32.dll!CreateFileW",
                               "ntdll.dll!NtClose", "user32.dll!MessageBoxW", "kernelbase.dll", "win32u.dll"]), "the module of the function is not drawn again, its importers are"
    assert ["kernelbase.dll", "ntdll.dll!NtClose", "imports", "NtClose"] in r["edges"] and ["kernel32.dll", "ntdll.dll!NtClose", "imports", "NtClose"] in r["edges"]
    assert r["edges"].count(["app.exe", "ntdll.dll!NtClose", "imports", "ntdll.dll"]) == 1 and len(r["edges"]) == 10
    assert r["again"] == [10, 10]
    assert r["in_degree"] == 3900
    assert len(r["frame"]["discs"]) == 10 and len(r["frame"]["lines"]) == 10


@needs_node
def test_the_depth_says_how_many_hops_an_expansion_opens():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const seen = {};
        for (const depth of [1, 2, 3]) {
          binaryGraphSetDepth(depth);
          await binaryGraphExploreStart('kernelbase.dll');
          const asked = requests.length;
          await binaryGraphExpand('kernelbase.dll');
          seen[depth] = { ids: drawnIds(), queries: queries(asked).length };
        }
        out(seen);
      })();""")
    one = ["api-ms-win-core-handle-l1-1-0.dll", "kernel32.dll", "kernelbase.dll", "ntdll.dll"]
    two = sorted(one + ["app.exe", "win32u.dll"])
    three = sorted(two + ["user32.dll"])
    assert r["1"]["ids"] == one
    assert r["2"]["ids"] == two, "the second hop opens the modules the first drew, and only them"
    assert r["3"]["ids"] == three
    assert [r[d]["queries"] for d in "123"] == [2, 7, 11]


@needs_node
def test_a_deeper_expansion_stops_when_the_canvas_is_full_and_says_so():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        GRAPH['hub.dll'] = { in_degree: 450, imports: {} };
        for (let i = 0; i < 450; i++) GRAPH['c' + String(i).padStart(3, '0') + '.dll'] = { in_degree: 1, imports: { 'hub.dll': ['F'] } };
        binaryGraphSetDepth(2);
        await binaryGraphExploreStart('hub.dll');
        const asked = requests.length;
        await binaryGraphExpand('hub.dll');
        out({ count: st.nodes.length, queries: queries(asked), note: st.note });
      })();""")
    assert r["count"] == 400 and len(r["queries"]) == 2, "the second hop asked for nothing: there is no room to draw it"
    assert "stopped because the canvas is full" in r["note"] and "399 nodes" in r["note"] and "not opened" in r["note"], r["note"]


@needs_node
def test_a_deep_walk_stops_after_its_budget_of_requests_and_says_how_much_it_left():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        GRAPH['pool.dll'] = { in_degree: 100, imports: {} };
        for (let i = 0; i < 100; i++) GRAPH['p' + String(i).padStart(3, '0') + '.dll'] = { in_degree: 1, imports: { 'pool.dll': ['F'] } };
        binaryGraphSetDepth(2);
        await binaryGraphExploreStart('pool.dll');
        const asked = requests.length;
        await binaryGraphExpand('pool.dll');
        out({ queries: queries(asked).length, requests: requests.length - asked, note: st.note, status: els['binary-explore-status'].innerHTML });
      })();""")
    # the walk spends its budget on the modules it opens and no more: two requests for the first hop, then two for each module
    # of the second, until the next one would not fit; the note says how many it left
    opened = (r["requests"] - 2) // 2
    assert r["requests"] == r["queries"] <= 60 < r["requests"] + 2, "every request is a query: nothing is read besides the answers"
    assert 0 < opened < 100 and f"after {r['requests']} requests" in r["note"] and f"{100 - opened} nodes" in r["note"] and "not opened" in r["note"], r["note"]
    assert f"{100 - opened} nodes" in _plain(r["status"])


@needs_node
def test_a_canvas_with_room_for_only_some_of_both_directions_gives_each_its_share():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const lib = i => 'q' + String(i).padStart(3, '0') + '.dll';
        GRAPH['mix.dll'] = { in_degree: 300, imports: Object.fromEntries([...Array(300)].map((_, i) => [lib(i), ['F']])) };
        for (let i = 0; i < 300; i++) { GRAPH[lib(i)] = { in_degree: 1, imports: {} }; GRAPH['i' + String(i).padStart(3, '0') + '.dll'] = { in_degree: 1, imports: { 'mix.dll': ['G'] } }; }
        await binaryGraphExploreStart('mix.dll');
        const started = requests.length;
        await binaryGraphExpand('mix.dll');
        out({ count: st.nodes.length, imported: st.nodes.filter(n => n.id.startsWith('q')).length, importers: st.nodes.filter(n => n.id.startsWith('i')).length,
              reads: requests.slice(started).filter(q => q.url.startsWith('/api/binary-graph/node')).length,
              status: (h => h.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim())(els['binary-explore-status'].innerHTML) });
      })();""")
    assert r["count"] == 400 and r["imported"] == 199 and r["importers"] == 200, "neither direction starves the other"
    assert r["reads"] == 199, "only the modules that are drawn are read, not the 300 that were imported"
    assert "201 neighbours are not shown" in r["status"] and "of 1 opened node" in r["status"] and "400 nodes" in r["status"], r["status"]


@needs_node
def test_the_node_size_follows_the_in_degree_so_the_most_imported_dll_is_the_largest():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        const f = frame();
        out({ f: f.discs.length, rows: st.nodes.map(n => ({ id: n.id, degree: n.in_degree, disc: discOf(f, n.id) })) });
      })();""")
    rows = r["rows"]
    # the shape first: every node has exactly one disc, and the in-degrees really differ
    assert len(rows) == 5 and r["f"] == 5 and all(row["disc"] for row in rows)
    assert len({row["degree"] for row in rows}) == len(rows), "a test of the size needs nodes of different in-degree"
    by_degree = sorted(rows, key=lambda row: row["degree"])
    radii = [row["disc"]["r"] for row in by_degree]
    assert radii == sorted(radii) and len(set(radii)) == len(radii), "a node imported by more binaries is drawn larger"
    largest = max(rows, key=lambda row: row["disc"]["r"])
    assert largest["id"] == "ntdll.dll" and largest["degree"] == 4000
    assert by_degree[0]["id"] == "app.exe" and by_degree[0]["disc"]["r"] == min(radii)


@needs_node
def test_the_node_colour_follows_the_kind_dll_exe_or_syscall():
    r = _explore_flow(r"""
      initSyscalls(); binaryGraphSetMode('explore');
      const kinds = ['dll', 'exe', 'syscall', 'api-set', 'function', 'constructor'];
      st.nodes = kinds.map((kind, i) => ({ id: kind + '-node', label: kind, kind, in_degree: 10, category: '', x: i * 90, y: 0, radius: 12, placed: true }));
      st.edges = [];
      binaryGraphDraw();
      const f = frame();
      out(kinds.map(k => { const d = f.discs.find(d => d.x === st.nodes.find(n => n.kind === k).x); return [k, d && d.stroke, d && d.fill]; }));""")
    colours = {kind: stroke for kind, stroke, _ in r}
    assert len(r) == 6 and all(stroke for _, stroke, _ in r), r
    assert colours["dll"] == "--graph-node-dll" and colours["exe"] == "--graph-node-exe"
    assert colours["syscall"] == "--graph-node-syscall" and colours["api-set"] == "--graph-node-apiset"
    assert len({colours[k] for k in ("dll", "exe", "syscall", "api-set")}) == 4, "the four kinds are four colours"
    assert colours["constructor"] == "--text-muted", "a kind named like an object member is no kind"


@needs_node
def test_an_answer_that_hit_the_node_cap_says_so_on_the_canvas():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const name = i => 'c' + String(i).padStart(3, '0') + '.dll';
        GRAPH['hub.dll'] = { in_degree: 450, imports: {} };
        for (let i = 0; i < 450; i++) GRAPH[name(i)] = { in_degree: 1, imports: { 'hub.dll': ['F'] } };
        GRAPH['c010.dll'].imports = { 'hub.dll': ['F'], 'z.dll': ['Z0', 'Z1', 'Z2', 'Z3', 'Z4'] };
        GRAPH['c011.dll'].imports = { 'hub.dll': ['F'], 'c012.dll': ['G'] };
        await binaryGraphExploreStart('hub.dll');
        const quiet = { texts: frame().texts, status: els['binary-explore-status'].innerHTML, hidden: els['binary-explore-status'].hidden };
        await binaryGraphExpand('hub.dll');
        const cut = { count: st.nodes.length, edges: st.edges.length, texts: frame().texts, discs: frame().discs.length,
                      status: els['binary-explore-status'].innerHTML, hidden: els['binary-explore-status'].hidden,
                      last: st.nodes[st.nodes.length - 1].id, has399: !!at(name(399)), has398: !!at(name(398)) };
        // opening more of a canvas that is full draws no node, and says how many did not fit, on top of the server's cut
        await binaryGraphExpand('c010.dll');
        const again = { count: st.nodes.length, z: !!at('z.dll'), status: els['binary-explore-status'].innerHTML, texts: frame().texts,
                        counted: st.edges.find(e => e.source === 'c010.dll' && e.target === 'hub.dll').functions, hub: at('hub.dll').in_degree };
        // an edge between two nodes that are drawn needs no new node, so it is drawn
        await binaryGraphExpand('c012.dll');
        const edge = { count: st.nodes.length, drawn: st.edges.some(e => e.source === 'c011.dll' && e.target === 'c012.dll' && e.kind === 'imports') };
        // starting over empties the cut
        await binaryGraphExploreStart('app.exe');
        out({ quiet, cut, again, edge, over: { texts: frame().texts, status: els['binary-explore-status'].innerHTML } });
      })();""")
    assert not any("not shown" in t for t in r["quiet"]["texts"]) and r["quiet"]["hidden"] is True, "a whole answer does not claim to be cut"
    cut = r["cut"]
    assert cut["count"] == 400 and cut["edges"] == 399 and cut["discs"] == 400
    assert cut["has398"] and not cut["has399"] and cut["last"] == "c398.dll", "the first parts in name order are kept"
    banner = [t for t in cut["texts"] if "not shown" in t]
    assert len(banner) == 1 and "400" in banner[0] and "51" in banner[0], banner
    status = _plain(cut["status"])
    assert cut["hidden"] is False and "51 neighbours are not shown" in status and "cut by the server" in status, status
    assert "does not mean" in status and "not shown" in status and "did not fit" not in status, "nothing of this canvas's own was dropped yet"
    again = r["again"]
    assert again["count"] == 400 and not again["z"], "a full canvas stays at its cap"
    assert again["counted"] == 1, "an edge that was drawn gains the count of the functions it stands for"
    assert again["hub"] == 450, "a module that is drawn keeps the in-degree the graph gave it when a grouping only guesses"
    assert any("52" in t for t in again["texts"] if "not shown" in t), "the server's 51 and the 1 module that did not fit are counted together"
    text = _plain(again["status"])
    assert "of 2 opened nodes" in text and "51 were cut by the server" in text and "1 did not fit on this canvas, which holds at most 400 nodes" in text, text
    assert r["edge"] == {"count": 400, "drawn": True}
    assert not any("not shown" in t for t in r["over"]["texts"]) and r["over"]["status"] == ""


@needs_node
def test_the_edges_of_the_selected_node_are_drawn_apart_from_the_others():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll'); await binaryGraphExpand('app.exe');
        // the lines of a frame are in the order of the edges
        const near = st.edges.map(e => e.source === 'ntdll.dll' || e.target === 'ntdll.dll');
        const split = f => ({ near: f.lines.filter((_, i) => near[i]), rest: f.lines.filter((_, i) => !near[i]) });
        st.selected = null; binaryGraphDraw();
        const alike = split(frame());
        // a click on the node chooses it; a click on nothing lets go
        const clicked = binaryGraphOnCanvasClick(screenOf('ntdll.dll'));
        const chosen = split(frame()), rings = frame().rings, info = [els['binary-explore-info'].innerHTML, els['binary-explore-expand'].disabled];
        const cleared = binaryGraphOnCanvasClick({ offsetX: 599, offsetY: 399 });
        out({ clicked, selected: st.selected, cleared, alike, chosen, rings, after: frame().rings, info, lines: frame().lines.length, kernel32: at('kernel32.dll').in_degree });
      })();""")
    assert r["clicked"] is True and r["cleared"] is False and r["selected"] is None
    alike, chosen = r["alike"], r["chosen"]
    assert len(chosen["near"]) == 4 and len(chosen["rest"]) == 2, "the shape first: four importers of ntdll, two other imports of app.exe"
    assert len(alike["near"]) == 4 and len(alike["rest"]) == 2
    assert len({(l["width"], l["alpha"]) for l in alike["near"] + alike["rest"]}) == 1, "with nothing chosen every edge is drawn alike"
    assert min(l["width"] for l in chosen["near"]) > max(l["width"] for l in chosen["rest"])
    assert all(l["alpha"] == 1 for l in chosen["near"]) and all(l["alpha"] < 1 for l in chosen["rest"])
    assert len(r["rings"]) == 1 and r["after"] == [], "the chosen node has a ring, and only while it is chosen"
    assert "ntdll.dll" in r["info"][0] and r["info"][1] is False
    assert r["lines"] == 6
    assert r["kernel32"] == 3900, "a module drawn from an importers answer keeps its in-degree when app.exe's imports group it again"


@needs_node
def test_the_dash_of_the_curated_and_the_unknown_edge_survives_on_the_explore_canvas():
    r = _explore_flow(r"""
      initSyscalls(); binaryGraphSetMode('explore');
      st.nodes = ['a', 'b', 'c'].map((id, i) => ({ id, label: id, kind: 'dll', in_degree: 1, category: '', x: i * 100, y: 0, radius: 10, placed: true }));
      st.edges = [{ source: 'a', target: 'b', kind: 'imports', origin: 'derived', label: '' },
                  { source: 'b', target: 'c', kind: 'reaches_syscall', origin: 'curated', label: '' },
                  { source: 'a', target: 'c', kind: 'imports', origin: 'mystery', label: '' }];
      binaryGraphDraw();
      out(frame().lines.map(l => [l.color, l.dash]));""")
    assert len(r) == 3
    derived, curated, unknown = r
    assert derived[1] == "" and curated[1] != "" and unknown[1] != "" and curated[1] != unknown[1]
    assert curated[0] == "--graph-edge-curated" and derived[0] != unknown[0]


def _legend_rows(html):
    return {e["attrs"]["data-legend"] for e in _Elements(html).elements if "data-legend" in e["attrs"]}


@needs_node
def test_the_legend_of_the_explore_view_names_only_what_the_explore_canvas_can_draw():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls();
        const edge = origin => ({ source: 'a', target: 'b', kind: 'imports', origin, label: '' });
        binaryGraphSetMode('explore');
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        const onPage = els['binary-explore-legend'].innerHTML;
        out({ path: binaryGraphLegend(), pathExplicit: binaryGraphLegend('path', []), onPage,
              explore: binaryGraphLegend('explore', []), curated: binaryGraphLegend('explore', [edge('curated'), edge('derived')]),
              unknown: binaryGraphLegend('explore', [edge('mystery')]), pathLegend: (binaryGraphSetMode('path'), els['binary-graph-legend'].innerHTML) });
      })();""")
    everything = {"node-dll", "node-exe", "node-api-set", "node-function", "node-syscall", "edge-derived", "edge-curated", "edge-unknown", "deviation", "match"}
    assert _legend_rows(r["path"]) == everything and r["path"] == r["pathExplicit"], "the path view's legend is as it was"
    assert _legend_rows(r["pathLegend"]) == everything
    assert _legend_rows(r["explore"]) == {"node-dll", "node-exe", "node-api-set", "node-function", "edge-derived"}
    assert _legend_rows(r["onPage"]) == _legend_rows(r["explore"]), "the page shows what the function says"
    assert _legend_rows(r["curated"]) == _legend_rows(r["explore"]) | {"edge-curated"}, "an edge of the curated origin is explained where one is drawn"
    assert _legend_rows(r["unknown"]) == _legend_rows(r["explore"]) | {"edge-unknown"}


@needs_node
def test_dragging_moves_one_node_or_the_view_and_the_click_that_ends_a_drag_selects_nothing():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        const was = Object.fromEntries(st.nodes.map(n => [n.id, [n.x, n.y]]));
        st.selected = null;
        const from = screenOf('kernel32.dll'), cam = { ...st.camera };
        binaryGraphOnCanvasDown(from); binaryGraphOnCanvasMove({ offsetX: from.offsetX + 40, offsetY: from.offsetY + 20 });
        binaryGraphOnCanvasUp(); const dragged = binaryGraphOnCanvasClick({ offsetX: from.offsetX + 40, offsetY: from.offsetY + 20 });
        const moved = st.nodes.filter(n => n.x !== was[n.id][0] || n.y !== was[n.id][1]).map(n => n.id);
        const afterDrag = { selected: st.selected, camera: { ...st.camera }, cam };
        // empty ground pans the view: a point where no node is
        const free = [[2, 2], [598, 2], [2, 398], [598, 398]].find(([x, y]) => { const w = binaryGraphToWorld(x, y); return !binaryGraphNodeAt(w.x, w.y); });
        const still = { ...st.camera };
        binaryGraphOnCanvasDown({ offsetX: free[0], offsetY: free[1] }); binaryGraphOnCanvasMove({ offsetX: free[0] + 30, offsetY: free[1] + 10 }); binaryGraphOnCanvasUp();
        binaryGraphOnCanvasClick({ offsetX: free[0] + 30, offsetY: free[1] + 10 });
        const panned = { x: st.camera.x - still.x, y: st.camera.y - still.y, zoom: st.camera.zoom - still.zoom };
        // a wheel turn zooms, a button too, and FIT brings every node back
        const z0 = st.camera.zoom;
        binaryGraphOnCanvasWheel({ offsetX: 300, offsetY: 200, deltaY: -100, preventDefault() {} });
        const zoomed = st.camera.zoom; binaryGraphZoom(0.5); const smaller = st.camera.zoom; binaryGraphFit();
        out({ moved, dragged, afterDrag, panned, z0, zoomed, smaller, fitted: st.camera.zoom, label: els['binary-explore-zoom'].textContent });
      })();""")
    assert r["moved"] == ["kernel32.dll"] and r["dragged"] is False
    assert r["afterDrag"]["selected"] is None and r["afterDrag"]["camera"] == r["afterDrag"]["cam"]
    assert r["panned"] == {"x": 30, "y": 10, "zoom": 0}
    assert r["zoomed"] > r["z0"] and r["smaller"] < r["zoomed"] and 0.1 <= r["fitted"] <= 2
    assert r["label"].endswith("%")


# --- The process graph is not touched --------------------------------------------------------------------------------

@needs_node
def test_the_process_graph_state_is_untouched_by_a_binary_graph_render():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls();
        const pid = { id: 'pid:4', x: 5, y: 6, radius: 9, type: 'process' };
        Object.assign(graphState, { nodes: [pid], edges: [{ source: 'pid:4', target: 'pid:4', type: 'spawn' }], focusPid: '4', layoutMode: 'force',
                                    selectedNode: pid, isoCollapsed: new Set(['4']), camera: { x: 7, y: 8, zoom: 1.5 } });
        const key = () => JSON.stringify(graphState, (k, v) => v instanceof Set ? ['Set', ...v] : v);
        const camera = graphState.camera, nodes = graphState.nodes, before = key();
        seen.length = 0;
        binaryGraphSetMode('explore'); binaryGraphSetDepth(2);
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        binaryGraphOnCanvasClick(screenOf('kernel32.dll'));
        binaryGraphOnCanvasDown(screenOf('app.exe')); binaryGraphOnCanvasMove({ offsetX: 10, offsetY: 10 }); binaryGraphOnCanvasUp();
        binaryGraphOnCanvasWheel({ offsetX: 300, offsetY: 200, deltaY: 100, preventDefault() {} });
        binaryGraphZoom(1.25); binaryGraphFit(); binaryGraphRelayout(); binaryGraphDraw(); binaryGraphSetMode('path');
        out({ same: key() === before, before, after: key(), sameCamera: graphState.camera === camera, sameNodes: graphState.nodes === nodes,
              explored: st.nodes.length, drawn: frame().discs.length, touched: seen.filter(id => id.startsWith('graph-')) });
      })();""")
    # the guard is not vacuous: the exploration really ran, and the process graph really held something
    assert r["explored"] > 5 and r["drawn"] == r["explored"]
    assert '"zoom":1.5' in r["before"] and "pid:4" in r["before"] and r["before"].count('"Set"') == 1
    assert r["same"] is True, r["after"]
    assert r["sameCamera"] and r["sameNodes"]
    assert r["touched"] == [], "the explore view reached for an element of the process graph"


def test_the_explore_cap_is_the_cap_of_the_backend():
    import binary_graph_query
    assert int(re.search(r"cap:\s*(\d+)", _const_source("BINARY_GRAPH_EXPLORE")).group(1)) == binary_graph_query.MAX_NODES == 400


@needs_node
def test_a_binary_name_from_an_import_table_reaches_the_explore_view_as_text_and_not_as_markup():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const evil = '<img src=x onerror=alert(1)>.dll';
        GRAPH[evil] = { in_degree: 3, imports: { 'ntdll.dll': ['<b>F</b>'] } };
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        binaryGraphOnCanvasClick(screenOf(evil));
        const chosen = els['binary-explore-info'].innerHTML + els['binary-explore-status'].innerHTML, selected = st.selected;
        binaryGraphOnCanvasMove(screenOf(evil));
        const title = els['binary-explore-canvas'].title;
        await binaryGraphOpenFunctions(evil);
        binaryGraphOnCanvasClick(screenOf(st.nodes.find(n => n.kind === 'function').id));
        const fn = els['binary-explore-info'].innerHTML;
        await binaryGraphExploreStart('<img src=y onerror=alert(2)>');
        out({ chosen, selected, title, fn, missing: els['binary-explore-status'].innerHTML + els['binary-explore-info'].innerHTML });
      })();""")
    assert r["selected"] == "<img src=x onerror=alert(1)>.dll"
    for key in ("chosen", "missing", "fn"):
        assert "<img" not in r[key] and "<b>" not in r[key], key
    assert "&lt;img" in r["chosen"] and "&lt;img" in r["missing"] and "&lt;b&gt;F" in r["fn"]
    assert "<img src=x" in r["title"], "the tooltip is a property of the canvas, not markup"


# --- Ruling 54: the exploration view draws modules; functions are a level deeper -----------------------------------------

MANY = r"""
const fns = (prefix, n) => [...Array(n)].map((_, i) => prefix + String(i).padStart(3, '0'));
GRAPH['many.exe'] = { in_degree: 0, imports: { 'kernel32.dll': fns('K', 60), 'user32.dll': fns('U', 25) } };
"""


@needs_node
def test_an_executable_that_imports_many_functions_from_two_dlls_draws_two_module_nodes_with_counts_on_their_edges():
    r = _explore_flow(MANY + r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('many.exe');
        const asked = requests.length;
        const opened = await binaryGraphExpand('many.exe');
        const f = frame();
        out({ opened, ids: drawnIds(), kinds: [...new Set(st.nodes.map(n => n.kind))].sort(),
              reads: requests.slice(asked).filter(q => q.url.startsWith('/api/binary-graph/node')).map(q => new URL(q.url, 'http://x').searchParams.get('name')).sort(),
              edges: st.edges.map(e => [e.source, e.target, e.kind, e.origin, e.label, e.functions]),
              degrees: Object.fromEntries(st.nodes.map(n => [n.id, n.in_degree])), queries: queries(asked),
              texts: f.texts, discs: f.discs.length, lines: f.lines.length });
      })();""")
    assert r["opened"] is True
    assert r["ids"] == ["kernel32.dll", "many.exe", "user32.dll"], "85 imported functions are two nodes, not 85"
    assert r["kinds"] == ["dll", "exe"]
    assert sorted(r["edges"]) == sorted([["many.exe", "kernel32.dll", "imports", "derived", "60 functions", 60],
                                         ["many.exe", "user32.dll", "imports", "derived", "25 functions", 25]])
    assert r["degrees"] == {"many.exe": 0, "kernel32.dll": 3900, "user32.dll": 2000}, "the size of a module is its in-degree, read from the graph"
    assert r["queries"] == [{"q": "imports", "module": "many.exe"}, {"q": "importers", "module": "many.exe"}]
    assert r["reads"] == ["kernel32.dll", "user32.dll"], "a read per module that is drawn, never one per function"
    assert r["discs"] == 3 and r["lines"] == 2
    assert "60 functions" in r["texts"] and "25 functions" in r["texts"], "the count is on the edge, not only in the data"


@needs_node
def test_opening_a_module_node_yields_its_functions_one_level_deeper():
    r = _explore_flow(MANY + r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('many.exe'); await binaryGraphExpand('many.exe');
        const modules = drawnIds(), placed = Object.fromEntries(st.nodes.map(n => [n.id, [n.x, n.y]])), asked = requests.length;
        const opened = await binaryGraphOpenFunctions('many.exe');
        const functions = st.nodes.filter(n => n.kind === 'function');
        out({ opened, modules, queries: queries(asked), functions: functions.length, first: functions.map(n => n.id).sort()[0],
              sample: st.edges.find(e => e.target === 'kernel32.dll!K007'), edges: st.edges.length,
              moved: st.nodes.filter(n => placed[n.id] && (placed[n.id][0] !== n.x || placed[n.id][1] !== n.y)).map(n => n.id),
              modulesStill: modules.every(id => !!at(id)) });
      })();""")
    assert r["modules"] == ["kernel32.dll", "many.exe", "user32.dll"]
    assert r["opened"] is True and r["functions"] == 85 and r["first"] == "kernel32.dll!K000"
    assert r["queries"] == [{"q": "imports", "module": "many.exe"}], "the functions of a module are the one query that names them"
    assert r["sample"]["source"] == "many.exe" and r["sample"]["kind"] == "imports" and r["sample"]["origin"] == "derived"
    assert r["edges"] == 2 + 85 and r["moved"] == [] and r["modulesStill"]


@needs_node
def test_grouping_functions_by_module_never_lends_an_edge_a_claim_one_of_its_parts_did_not_make():
    r = _explore_flow(r"""
      const request = { dir: 'out', params: {}, module: 'x.exe', via: '', level: 'modules' };
      const edge = (module, fn, origin) => ({ source: 'x.exe', target: module + '!' + fn, kind: 'imports', origin, label: module });
      const group = edges => Object.fromEntries(binaryGraphExploreParts(request, { nodes: [], edges, truncated: false, total: edges.length }).parts
                                .map(p => [p.head, [p.edges[0].origin, p.edges[0].functions, p.edges[0].label]]));
      out({ derived: group([edge('a.dll', 'F', 'derived'), edge('a.dll', 'G', 'derived')]),
            oneOther: group([edge('a.dll', 'F', 'derived'), edge('a.dll', 'G', 'inferred')]),
            oneMissing: group([edge('a.dll', 'F', 'derived'), edge('a.dll', 'G', undefined)]),
            curated: group([edge('a.dll', 'F', 'curated')]),
            apart: group([edge('a.dll', 'F', 'derived'), edge('b.dll', 'G', 'inferred'), edge('b.dll', 'H', 'derived')]),
            combine: [['derived', 'derived'], ['derived', undefined], ['curated', 'curated'], ['curated', 'derived'], ['x', 'x']].map(([a, b]) => binaryGraphCombineOrigin(a, b)) });""")
    assert r["derived"] == {"a.dll": ["derived", 2, "2 functions"]}
    assert r["oneOther"]["a.dll"][0] == "unknown", "one edge that is not derived makes the whole unknown"
    assert r["oneMissing"]["a.dll"][0] == "unknown" and r["curated"]["a.dll"][0] == "unknown"
    assert r["apart"] == {"a.dll": ["derived", 1, "1 function"], "b.dll": ["unknown", 2, "2 functions"]}, "each module's edge answers for its own functions only"
    assert r["combine"] == ["derived", "unknown", "curated", "unknown", "unknown"], "two drawings of one edge keep a claim only where both make it"


@needs_node
def test_an_aggregated_edge_of_an_unknown_origin_is_drawn_as_unknown_not_as_read_from_a_binary():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const real = importsOf;
        routes['/api/binary-graph/query'] = url => {
          const body = queryRoute(url).body;
          if (new URL(url, 'http://x').searchParams.get('q') === 'imports') body.edges = body.edges.map(e => e.target === 'user32.dll!MessageBoxW' ? { ...e, origin: 'inferred' } : e);
          return { body };
        };
        await binaryGraphExploreStart('app.exe'); await binaryGraphExpand('app.exe');
        const lines = frame().lines, order = st.edges.map(e => [e.target, e.origin]);
        out({ order, dashes: lines.map(l => l.dash), colours: lines.map(l => l.color) });
      })();""")
    origins = dict(r["order"])
    assert origins["kernel32.dll"] == "derived" and origins["user32.dll"] == "unknown"
    drawn = {target: (dash, colour) for (target, _), dash, colour in zip(r["order"], r["dashes"], r["colours"])}
    assert drawn["kernel32.dll"][0] == "" and drawn["user32.dll"][0] != "", "the unknown one is dotted, the derived one solid"
    assert drawn["user32.dll"][1] != drawn["kernel32.dll"][1]


@needs_node
def test_a_list_of_imports_the_server_cut_makes_the_last_count_a_lower_bound_and_says_what_is_missing():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const fns = (p, n) => [...Array(n)].map((_, i) => p + String(i).padStart(3, '0'));
        GRAPH['big.exe'] = { in_degree: 0, imports: { 'kernel32.dll': fns('K', 300), 'user32.dll': fns('U', 250), 'gdi32.dll': fns('G', 50) } };
        await binaryGraphExploreStart('big.exe'); await binaryGraphExpand('big.exe');
        out({ ids: drawnIds(), edges: st.edges.map(e => [e.target, e.functions, e.label, e.partial]), status: els['binary-explore-status'].innerHTML,
              info: els['binary-explore-info'].innerHTML, texts: frame().texts });
      })();""")
    assert r["ids"] == ["big.exe", "kernel32.dll", "user32.dll"], "gdi32.dll came after the server's cut"
    assert sorted(r["edges"]) == sorted([["kernel32.dll", 300, "300 functions", False], ["user32.dll", 99, "at least 99 functions", True]])
    status = _plain(r["status"])
    assert "201 imported functions were cut by the server" in status and "at least what it says" in status and "does not mean" in status, status
    assert "201 of its imported functions are not shown" in r["info"]
    assert any("201 imported functions not shown" in t for t in r["texts"]) and "at least 99 functions" in r["texts"]


# --- Review: an edge between drawn nodes is never dropped silently, a cut table keeps its caveat -----------------------

@needs_node
def test_an_edge_between_two_drawn_nodes_is_drawn_even_when_the_canvas_is_full():
    # the reviewer's reproduction: c010 imports a module that does not fit, one that is drawn, and hub
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const name = i => 'c' + String(i).padStart(3, '0') + '.dll';
        GRAPH['hub.dll'] = { in_degree: 450, imports: {} };
        for (let i = 0; i < 450; i++) GRAPH[name(i)] = { in_degree: 1, imports: { 'hub.dll': ['F'] } };
        GRAPH['c010.dll'].imports = { 'hub.dll': ['F'], 'a.dll': ['A'], 'c005.dll': ['G'] };
        await binaryGraphExploreStart('hub.dll'); await binaryGraphExpand('hub.dll');
        const full = st.nodes.length;
        await binaryGraphExpand('c010.dll');
        out({ full, count: st.nodes.length, drawn: !!at('c005.dll'), a: !!at('a.dll'),
              edge: st.edges.find(e => e.source === 'c010.dll' && e.target === 'c005.dll') || null,
              status: els['binary-explore-status'].innerHTML });
      })();""")
    assert r["full"] == 400 and r["count"] == 400 and r["drawn"] and not r["a"]
    assert r["edge"] and r["edge"]["functions"] == 1, "the edge between two nodes that are on the canvas is real and costs no node"
    assert "1 did not fit" in _plain(r["status"])


@needs_node
def test_an_edge_that_could_not_be_drawn_because_its_head_is_drawn_but_its_alias_is_not_is_counted():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const name = i => 'c' + String(i).padStart(3, '0') + '.dll';
        GRAPH['hub.dll'] = { in_degree: 450, imports: {} };
        for (let i = 0; i < 450; i++) GRAPH[name(i)] = { in_degree: 1, imports: { 'hub.dll': ['F'] } };
        GRAPH['api-ms-x-l1-1-0.dll'] = { is: 'api-set', in_degree: 5, hosts: ['c007.dll'] };
        GRAPH['c003.dll'].imports = { 'hub.dll': ['F'], 'api-ms-x-l1-1-0.dll': ['H'] };
        await binaryGraphExploreStart('hub.dll'); await binaryGraphExpand('hub.dll');
        await binaryGraphExpand('c007.dll');
        out({ count: st.nodes.length, alias: !!at('api-ms-x-l1-1-0.dll'), edge: st.edges.some(e => e.source === 'c003.dll' && e.target === 'api-ms-x-l1-1-0.dll'),
              status: els['binary-explore-status'].innerHTML, texts: frame().texts });
      })();""")
    assert r["count"] == 400 and not r["alias"] and not r["edge"]
    assert "1 did not fit" in _plain(r["status"]), "c003 is drawn, but its path to c007 is not: that is said, not hidden"
    assert any("2 not shown" in t or "52 not shown" in t for t in r["texts"]), r["texts"]


@needs_node
def test_a_cut_import_table_keeps_its_caveat_once_modules_are_drawn():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('app.exe'); await binaryGraphExpand('app.exe');
        const whole = { status: els['binary-explore-status'].innerHTML, labels: st.edges.map(e => e.label), texts: frame().texts };
        GRAPH['cutbin.exe'] = { in_degree: 0, partial: true, imports: { 'kernel32.dll': ['A', 'B'], 'user32.dll': ['C'] } };
        await binaryGraphExploreStart('cutbin.exe'); await binaryGraphExpand('cutbin.exe');
        const cut = { status: els['binary-explore-status'].innerHTML, edges: st.edges.map(e => [e.target, e.functions, e.label, e.partial]),
                      info: els['binary-explore-info'].innerHTML, texts: frame().texts };
        // functions of a cut table are a list that may be incomplete too
        await binaryGraphOpenFunctions('cutbin.exe');
        out({ whole, cut, afterFunctions: _p(els['binary-explore-status'].innerHTML), keys: st.cut.size });
      })();""".replace("_p(", "(h => h.replace(/<[^>]+>/g, ' ').replace(/\\s+/g, ' ').trim())("))
    assert r["whole"]["status"] == "" and not any("cut" in t for t in r["whole"]["texts"]), "a whole table says nothing"
    assert all(label.startswith("at least") is False for label in r["whole"]["labels"])
    cut = r["cut"]
    assert sorted(cut["edges"]) == sorted([["kernel32.dll", 2, "at least 2 functions", True], ["user32.dll", 1, "at least 1 function", True]])
    status = _plain(cut["status"])
    assert "import table" in status and "cut short when it was read" in status and "modules may be missing" in status, status
    assert "at least what they say" in status and "does not mean" in status
    assert "import table was cut short" in cut["info"] and "modules may be missing" in cut["info"]
    assert any("import table" in t and "cut short" in t for t in cut["texts"]) and "at least 2 functions" in cut["texts"]
    assert "cut short when it was read" in r["afterFunctions"], "the list of functions of a cut table says so too"


@needs_node
def test_a_read_that_failed_says_the_in_degree_is_unknown_and_not_zero():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        GRAPH['x.exe'] = { in_degree: 0, imports: { 'broken.dll': ['F'], 'kernel32.dll': ['G'] } };
        const route = routes['/api/binary-graph/node'];
        routes['/api/binary-graph/node'] = url => new URL(url, 'http://x').searchParams.get('name') === 'broken.dll' ? { status: 500, body: { error: 'down' } } : route(url);
        await binaryGraphExploreStart('x.exe'); await binaryGraphExpand('x.exe');
        binaryGraphOnCanvasClick(screenOf('broken.dll'));
        const broken = els['binary-explore-info'].innerHTML;
        binaryGraphOnCanvasMove(screenOf('broken.dll'));
        const tip = els['binary-explore-canvas'].title;
        binaryGraphOnCanvasClick(screenOf('kernel32.dll'));
        out({ broken, tip, good: els['binary-explore-info'].innerHTML, known: at('kernel32.dll').in_degree });
      })();""")
    assert "not read" in r["broken"] and "0 binaries" not in r["broken"] and "not read" in r["tip"] and "0 binaries" not in r["tip"]
    assert "3,900 binaries" in r["good"] and r["known"] == 3900


@needs_node
def test_expanding_and_opening_the_functions_keep_each_its_own_record_of_what_was_cut():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const fns = (p, n) => [...Array(n)].map((_, i) => p + String(i).padStart(3, '0'));
        GRAPH['big.exe'] = { in_degree: 0, imports: { 'kernel32.dll': fns('K', 300), 'user32.dll': fns('U', 250), 'gdi32.dll': fns('G', 50) } };
        await binaryGraphExploreStart('big.exe'); await binaryGraphExpand('big.exe');
        const label = () => st.edges.find(e => e.target === 'user32.dll').label;
        const first = { label: label(), status: els['binary-explore-status'].innerHTML, keys: st.cut.size };
        await binaryGraphOpenFunctions('big.exe');
        out({ first, label: label(), status: els['binary-explore-status'].innerHTML, keys: st.cut.size });
      })();""")
    assert r["first"]["keys"] == 1 and r["keys"] == 2
    assert r["label"] == r["first"]["label"] == "at least 99 functions"
    status = _plain(r["status"])
    assert "imported functions were cut by the server" in status and "at least what it says" in status, "opening the functions did not replace the wording of the table"


@needs_node
def test_the_status_points_at_the_edge_of_the_cut_list_only_where_that_edge_is_drawn():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        const fns = (p, n) => [...Array(n)].map((_, i) => p + String(i).padStart(3, '0'));
        GRAPH['big.exe'] = { in_degree: 0, imports: { 'kernel32.dll': fns('K', 300), 'user32.dll': fns('U', 250), 'gdi32.dll': fns('G', 50) } };
        const room = async free => {
          await binaryGraphExploreStart('big.exe');
          for (let i = 0; i < 400 - 1 - free; i++) st.nodes.push({ id: 'fill' + i, label: 'fill' + i, kind: 'dll', in_degree: 1, category: '', x: 0, y: 0, radius: 6, placed: true });
          await binaryGraphExpand('big.exe');
          return { user32: !!at('user32.dll'), text: (h => h.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim())(els['binary-explore-status'].innerHTML) };
        };
        out({ two: await room(2), one: await room(1) });
      })();""")
    assert r["two"]["user32"] and "the count on that edge is at least what it says" in r["two"]["text"]
    assert not r["one"]["user32"] and "imported functions were cut by the server" in r["one"]["text"]
    assert "the count on that edge" not in r["one"]["text"], "the edge that the sentence points at is not drawn"


@needs_node
def test_the_cut_of_a_table_comes_with_the_answer_and_costs_no_read_of_the_module():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        const asked = requests.length;
        await binaryGraphExpand('kernel32.dll');
        const sent = requests.slice(asked);
        out({ reads: sent.filter(q => q.url.startsWith('/api/binary-graph/node')).map(q => new URL(q.url, 'http://x').searchParams.get('name')).sort(),
              queries: queries(asked) });
      })();""")
    assert r["queries"] == [{"q": "imports", "module": "kernel32.dll"}, {"q": "importers", "module": "kernel32.dll"}]
    assert r["reads"] == ["api-ms-win-core-handle-l1-1-0.dll"], "kernel32 itself was not read for its table: only the module it drew for the first time"


@needs_node
def test_importers_that_may_be_missing_because_a_table_was_cut_are_said_so():
    r = _explore_flow(r"""
      (async () => {
        initSyscalls(); binaryGraphSetMode('explore');
        await binaryGraphExploreStart('app.exe'); await binaryGraphExpand('app.exe');
        const whole = { status: els['binary-explore-status'].innerHTML, texts: frame().texts };
        GRAPH['odd.dll'] = { in_degree: 1, partial: true, imports: {} };
        await binaryGraphExploreStart('ntdll.dll'); await binaryGraphExpand('ntdll.dll');
        out({ whole, status: els['binary-explore-status'].innerHTML, info: els['binary-explore-info'].innerHTML, texts: frame().texts,
              ids: drawnIds(), labels: st.edges.map(e => e.label) });
      })();""")
    assert r["whole"]["status"] == "" and not any("cut short" in t for t in r["whole"]["texts"])
    status = _plain(r["status"])
    assert "who imports" in status and "may be incomplete" in status and "some import tables of the graph were cut short when the graph was read" in status, status
    assert "the figures say how many" in status, "the sentence points at the count instead of standing alone"
    assert "does not mean" in status
    assert "importers may be incomplete" in r["info"] and "some import tables" in r["info"] and "the figures say how many" in r["info"]
    assert any("importers" in t and "cut short" in t and "figures" in t for t in r["texts"])
    assert r["ids"] == ["app.exe", "kernel32.dll", "kernelbase.dll", "ntdll.dll", "win32u.dll"], "the importers that are known are still drawn"
