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
"""

import re
from html.parser import HTMLParser

from test_frontend import needs_node
from test_syscalls_ui import _flow, _run_node
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
        "binaryGraphMatches", "binaryGraphCut", "binaryGraphLegend"]
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
        const many = [...Array(400)].map((_, i) => ({ id: 'b' + i + '.dll', label: 'b' + i + '.dll', kind: 'dll', in_degree: 0, category: '' }));
        const cut = { nodes: [{ id: 'kernel32.dll', label: 'kernel32.dll', kind: 'dll', in_degree: 4000, category: '' }, ...many.slice(0, 399)],
                      edges: many.slice(0, 399).map(n => ({ source: n.id, target: 'kernel32.dll', kind: 'imports', origin: 'derived', label: '' })),
                      truncated: true, total: 4000, roots: ['kernel32.dll'], build: '26220.5770', arch: 'arm64', created: '',
                      note: '4000 binaries import kernel32.dll, directly or through an api set. Only the first 399 of 4000 binaries that import it are drawn.' };
        await ask({ body: cut }, 'kernel32.dll', '');
        const truncated = els['binary-graph-status'].textContent || els['binary-graph-status'].innerHTML;
        await ask({ body: PATH() });
        out({ truncated, whole: els['binary-graph-status'].textContent || els['binary-graph-status'].innerHTML,
              drawn: (els['binary-graph-canvas'].innerHTML.match(/class="binary-graph-node /g) || []).length });
      })();""")
    cut = " ".join(re.sub(r"<[^>]+>", " ", r["truncated"]).split())
    assert "4,000" in cut and "400 nodes" in cut, cut
    assert "not shown" in cut and "does not mean" in cut and "not imported" in cut, cut
    whole = " ".join(re.sub(r"<[^>]+>", " ", r["whole"]).split())
    assert "4,000" not in whole and "not shown" not in whole, "a whole answer does not claim to be cut"
    assert r["drawn"] == 4


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
    for asset, minimum in (("style.css", 88), ("theme-cyberpunk.css", 38), ("app.js", 140)):
        version = int(re.search(rf"{re.escape(asset)}\?v=(\d+)", html).group(1))
        assert version >= minimum, f"{asset} was changed and kept its ?v="
