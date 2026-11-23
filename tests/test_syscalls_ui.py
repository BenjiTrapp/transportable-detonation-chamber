"""The SYSCALLS tab (block SYSCALLS of static/js/app.js): the map, the legend and the catalog under it.

Regressions covered:
  * a syscall name from the baseline or the target taken as markup, a state that leaves its class attribute, a
    reason or a process name from the server or the host inserted as markup
  * a map that draws the eye before anything was measured, or in which one patched stub among 2,461 cells is no
    louder than the rest; a deviation painted under the ring of a neighbour; a filter that removes or moves cells
    instead of dimming them; a point that finds the wrong cell, or one in a gap
  * "no baseline" and "the x64 view cannot be told from arm64 on this host" worded alike
  * a scan that is refused, times out or cannot be reached leaving the measurement of an earlier scan on the map,
    SCAN left on while one runs or with no target, win32u scanned unasked, a late answer of another scan
  * the baseline read again at every visit of the tab, an extraction nobody asks about again
  * GRAPH that can be switched to before the binary graph exists
  * the tab missing in the tab bar or the guide, a script that reads an element the page does not have, a state
    colour that is missing in a theme, or an intact stub louder than a deviation in one of them
"""

import re
from html.parser import HTMLParser

from test_frontend import SOURCE, _run_node as _run, needs_node
from test_theme import (INDEX_HTML, STYLE_CSS, THEME_CSS, _contrast, _cyberpunk_palette, _read, _root_values, _rules,
                        _same_value, _tab_markup)

OUT = "const out = value => console.log(JSON.stringify(value));\n"


# What every function of the block may call: the helpers of the page and the block's own small ones and constants
HELPERS = ["escapeHtml", "jsArg", "jsInt", "cssToken", "syscallHex"]
BLOCK_CONSTS = ["SYSCALL_STATES", "SYSCALL_STATE_COLORS", "SYSCALL_STATE_HELP", "SYSCALL_MODULES"]


def _const(name):
    from test_theme import _const_source
    return _const_source(name)


def _run_node(functions, script, prelude=""):
    consts = "\n".join(_const(c) for c in BLOCK_CONSTS if c not in prelude)
    return _run(list(dict.fromkeys(HELPERS + list(functions))), script, OUT + consts + "\n" + prelude)


@needs_node
def test_legend_names_every_state_with_its_count():
    html = _run_node(["syscallMapLegendHtml"], """
      out(syscallMapLegendHtml({intact: 962, hooked: 5, patched: 2,
                                diverged: 2, unreadable: 7}));""")
    for word in ("962", "5", "2", "7"):
        assert word in html
    assert html.count("syscall-legend-dot") == 5


@needs_node
def test_a_syscall_name_from_the_target_is_escaped():
    html = _run_node(["syscallRowHtml"], """
      out(syscallRowHtml({name: "<img src=x onerror=alert(1)>", number: 58,
                          state: "patched"}));""")
    assert "<img" not in html
    assert "&lt;img" in html


class _Attributes(HTMLParser):
    """The attributes of every element of a piece of markup, as a browser reads them."""

    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


@needs_node
def test_state_class_goes_through_csstoken():
    html = _run_node(["syscallRowHtml", "cssToken"], """
      out(syscallRowHtml({name: "NtFoo", number: 1, state: "a b\\"c"}));""")
    # read as a browser reads it: the state leaves neither its class nor the element
    elements = _Attributes(html).elements
    assert [tag for tag, _ in elements] == ["button", "span", "span", "span", "span"]
    dot = elements[1][1]
    assert dot["class"] == "syscall-row-dot syscall-state-abc"
    for tag, attrs in elements:
        assert set(attrs) <= {"type", "class", "data-name", "aria-label", "onclick", "title"}, (tag, attrs)


@needs_node
def test_the_selected_row_is_marked():
    r = _run_node(["syscallRowHtml"], """
      out({ plain: syscallRowHtml({ name: "NtFoo", number: 1 }), chosen: syscallRowHtml({ name: "NtFoo", number: 1, selected: true }) });""")
    plain, chosen = (_Attributes(h).elements[0][1] for h in (r["plain"], r["chosen"]))
    assert plain["class"] == "syscall-row" and "aria-current" not in plain
    assert chosen["class"] == "syscall-row selected" and chosen["aria-current"] == "true"


# --- The map: bands, geometry and what a cell looks like --------------------------

# The constants of the block that a drawing reads
MAP_CONSTS = ["SYSCALL_MAP", "SYSCALL_STATE_COLORS", "SYSCALL_MODULES"]
MAP_FUNCTIONS = ["syscallBands", "syscallBandLayout", "syscallCellOrigin", "syscallCellAt", "syscallCellLook",
                 "syscallStateColor", "syscallDrawBand"]

# 2,461 cells of one band in the order of the baseline, and a canvas context that writes down what is painted
RECORDER = r"""
const cells = Array.from({ length: 2461 }, (_, i) => ({ name: 'Nt' + i, module: 'ntdll.dll', number: i }));
const record = () => {
    const calls = [];
    const ctx = { globalAlpha: 1, fillStyle: '', strokeStyle: '', lineWidth: 1,
        fillRect(x, y, w, h) { calls.push({ op: 'fill', x, y, w, h, color: this.fillStyle, alpha: this.globalAlpha }); },
        strokeRect(x, y, w, h) { calls.push({ op: 'stroke', x, y, w, h, color: this.strokeStyle, alpha: this.globalAlpha }); },
        clearRect() {} };
    return { ctx, calls };
};
const layout = syscallBandLayout(cells.length, 900);
const quietModel = { states: null, match: null, selected: null, hover: null };
"""


def _map_prelude():
    """The constants the drawing reads, and a themeColor that returns the variable's name (and the alpha)."""
    from test_theme import _const_source
    return ("\n".join(_const_source(c) for c in MAP_CONSTS)
            + "\nconst themeColor = (name, alpha) => alpha === undefined ? name : name + '/' + alpha;\n")


def _map_run(script):
    return _run_node(MAP_FUNCTIONS, RECORDER + script, _map_prelude())


@needs_node
def test_bands_are_one_per_module_in_syscall_number_order():
    r = _run_node(["syscallBands"], r"""
      const items = [
        { name: 'NtUserB', module: 'win32u.dll', number: 4100 }, { name: 'NtB', module: 'ntdll.dll', number: 7 },
        { name: 'NtUserA', module: 'win32u.dll', number: 4099 }, { name: 'NtA', module: 'ntdll.dll', number: 3 }];
      out(syscallBands(items).map(b => [b.module, b.items.map(i => i.name)]));""", _map_prelude())
    assert r == [["ntdll.dll", ["NtA", "NtB"]], ["win32u.dll", ["NtUserA", "NtUserB"]]]


@needs_node
def test_every_cell_has_its_own_place_and_a_point_finds_it_again():
    r = _map_run(r"""
      const seen = new Set(); let lost = 0, overlapping = 0;
      for (let i = 0; i < cells.length; i++) {
        const { x, y } = syscallCellOrigin(layout, i);
        if (seen.has(x + ',' + y)) overlapping++;
        seen.add(x + ',' + y);
        // the middle of the cell, its first and its last pixel
        for (const [dx, dy] of [[5, 5], [0, 0], [9, 9]]) if (syscallCellAt(layout, x + dx, y + dy) !== i) lost++;
      }
      const first = syscallCellOrigin(layout, 0), last = syscallCellOrigin(layout, cells.length - 1);
      out({ layout, overlapping, lost,
            inGap: syscallCellAt(layout, first.x + 10, first.y + 3), inGapBelow: syscallCellAt(layout, first.x + 3, first.y + 10),
            outside: [syscallCellAt(layout, -5, 3), syscallCellAt(layout, 3, -5), syscallCellAt(layout, 5000, 3),
                      syscallCellAt(layout, 3, 5000)],
            pastTheEnd: syscallCellAt(layout, last.x + layout.pitch + 3, last.y + 3),
            narrow: syscallBandLayout(40, 5).cols, empty: syscallBandLayout(0, 900) });""")
    assert r["overlapping"] == 0 and r["lost"] == 0
    assert r["inGap"] == -1 and r["inGapBelow"] == -1 and r["outside"] == [-1, -1, -1, -1] and r["pastTheEnd"] == -1
    layout = r["layout"]
    # 900 px hold a whole number of columns, no cell leaves the canvas and its height holds the last row
    assert layout["cols"] * layout["pitch"] <= 900 and layout["rows"] == -(-2461 // layout["cols"])
    assert layout["height"] >= layout["rows"] * layout["pitch"] - (layout["pitch"] - layout["cell"])
    assert r["narrow"] == 1, "a canvas narrower than a cell still has one column"
    assert r["empty"]["rows"] == 0 and r["empty"]["height"] == 0


@needs_node
def test_without_a_scan_every_cell_is_drawn_alike_and_quiet():
    r = _map_run(r"""
      const { ctx, calls } = record();
      syscallDrawBand(ctx, layout, cells, quietModel);
      out({ count: calls.length, looks: [...new Set(calls.map(c => [c.op, c.color, c.alpha, c.w, c.h].join('|')))] });""")
    assert r["count"] == 2461, "one painted cell per syscall, nothing around them"
    assert len(r["looks"]) == 1, r["looks"]
    op, color, alpha, w, h = r["looks"][0].split("|")
    # the baseline tone: the colour of an intact stub, held back
    assert (op, color, w, h) == ("fill", "--syscall-intact", "10", "10") and float(alpha) < 1


@needs_node
def test_one_patched_stub_among_2461_cells_is_the_only_loud_one_and_is_painted_last():
    r = _map_run(r"""
      const states = new Map(cells.map(c => [c.name, 'intact']));
      states.set('Nt1200', 'patched');
      const { ctx, calls } = record();
      syscallDrawBand(ctx, layout, cells, { ...quietModel, states });
      const quiet = calls.filter(c => c.color === '--syscall-intact');
      const loud = calls.filter(c => c.color !== '--syscall-intact');
      out({ quiet: quiet.length, loud, at: syscallCellOrigin(layout, 1200), quietAlphas: [...new Set(quiet.map(c => c.alpha))],
            // the loud calls come after every quiet one, so no neighbour paints over the ring
            lastQuiet: calls.lastIndexOf(quiet[quiet.length - 1]), firstLoud: calls.indexOf(loud[0]) });""")
    assert r["quiet"] == 2460 and r["firstLoud"] > r["lastQuiet"]
    assert [c["color"] for c in r["loud"]] == ["--syscall-patched/0.35", "--syscall-patched"], r["loud"]
    ring, core = r["loud"]
    at = r["at"]
    # the core is a cell like the others; the ring around it reaches into the gap on every side
    assert (core["x"], core["y"], core["w"], core["h"]) == (at["x"], at["y"], 10, 10) and core["alpha"] == 1
    assert ring["x"] < core["x"] and ring["y"] < core["y"]
    assert ring["x"] + ring["w"] > core["x"] + core["w"] and ring["y"] + ring["h"] > core["y"] + core["h"]
    # and what is intact is held back: a measured stub is no louder than the baseline tone it replaces
    assert r["quietAlphas"] == [1]


@needs_node
def test_each_state_has_a_look_of_its_own_and_only_the_deviations_are_loud():
    r = _map_run(r"""
      const states = ['intact', 'hooked', 'patched', 'diverged', 'unreadable'];
      out({ looks: Object.fromEntries(states.map(s => [s, syscallCellLook(s, false)])),
            baseline: syscallCellLook(null, false), unscanned: syscallCellLook(undefined, false),
            unknown: syscallCellLook('hooked-ish', false), prototype: syscallCellLook('constructor', false),
            dimmed: Object.fromEntries(states.map(s => [s, syscallCellLook(s, true)])) });""")
    looks = r["looks"]
    assert len({v["color"] for v in looks.values()}) == 5, "five states, five colours"
    assert [s for s, v in looks.items() if v["loud"]] == ["hooked", "patched", "diverged", "unreadable"]
    assert looks["patched"]["halo"] > 0 and looks["diverged"]["halo"] > 0, "what must be looked at has a ring"
    assert looks["intact"]["halo"] == 0 and looks["hooked"]["halo"] == 0
    assert looks["unreadable"]["hollow"] and not looks["patched"]["hollow"]
    assert r["baseline"] == r["unscanned"] and not r["baseline"]["loud"]
    assert r["baseline"]["color"] == looks["intact"]["color"] and r["baseline"]["alpha"] < looks["intact"]["alpha"]
    # a state the server does not send is never taken for a quiet one
    assert r["unknown"]["color"] == looks["diverged"]["color"] == r["prototype"]["color"]
    for state, dimmed in r["dimmed"].items():
        assert dimmed["alpha"] < 0.3 and dimmed["halo"] == 0 and not dimmed["loud"], state
        assert dimmed["color"] == looks[state]["color"], state


@needs_node
def test_the_filter_dims_cells_it_does_not_match_and_none_moves():
    r = _map_run(r"""
      const run = match => { const { ctx, calls } = record();
        syscallDrawBand(ctx, layout, cells, { ...quietModel, match }); return calls; };
      const all = run(null), some = run(new Set(['Nt5', 'Nt900']));
      const byPlace = calls => new Map(calls.map(c => [c.x + ',' + c.y, c.alpha]));
      const a = byPlace(all), s = byPlace(some), shown = [...a.values()][0];
      out({ samePlaces: some.length === all.length && [...a.keys()].every(k => s.has(k)),
            full: [...s.values()].filter(v => v === shown).length,
            dim: [...new Set([...s.values()].filter(v => v !== shown))], none: run(new Set()).length });""")
    assert r["samePlaces"], "the filter takes no cell away and moves none"
    assert r["full"] == 2 and len(r["dim"]) == 1 and r["dim"][0] < 0.3
    assert r["none"] == 2461, "a filter that matches nothing dims everything and still draws everything"


@needs_node
def test_a_hollow_cell_is_an_outline_and_the_selected_and_hovered_cells_are_ringed():
    r = _map_run(r"""
      const states = new Map([['Nt3', 'unreadable']]);
      const { ctx, calls } = record();
      syscallDrawBand(ctx, layout, cells, { ...quietModel, states, selected: 'Nt10', hover: 'Nt20' });
      out({ strokes: calls.filter(c => c.op === 'stroke'), fills: calls.filter(c => c.op === 'fill').length,
            a: syscallCellOrigin(layout, 10), b: syscallCellOrigin(layout, 20), c: syscallCellOrigin(layout, 3) });""")
    hollow, selected, hovered = r["strokes"]
    assert hollow["color"] == "--syscall-unreadable" and r["fills"] == 2460, "unreadable is outlined, not filled"
    assert (selected["color"], hovered["color"]) == ("--text-primary", "--text-secondary")
    assert selected["x"] < r["a"]["x"] and hovered["x"] < r["b"]["x"], "a ring around the cell, not on it"


@needs_node
def test_state_colours_are_read_from_the_theme():
    r = _map_run(r"""
      const states = ['intact', 'hooked', 'patched', 'diverged', 'unreadable'];
      out({ colours: states.map(s => syscallStateColor(s)), unknown: syscallStateColor('x'),
            alpha: syscallStateColor('patched', 0.35) });""")
    assert r["colours"] == [f"--syscall-{s}" for s in ("intact", "hooked", "patched", "diverged", "unreadable")]
    assert r["unknown"] == "--syscall-diverged" and r["alpha"] == "--syscall-patched/0.35"


# --- The filter, the notices, the target list and the scan's summary ---------------

ITEMS = r"""
const items = [
  { name: 'NtAddAtom', module: 'ntdll.dll', number: 0x4c },       // 76: hex digits "add" in a name, 0xadd elsewhere
  { name: 'NtClose', module: 'ntdll.dll', number: 0x0f },
  { name: 'NtWriteVirtualMemory', module: 'ntdll.dll', number: 0x3a },
  { name: 'NtUserGetDC', module: 'win32u.dll', number: 0x1003 },
  { name: 'NtUserAdd', module: 'win32u.dll', number: 0xadd },
];
const names = set => set === null ? null : items.filter(i => set.has(i.name)).map(i => i.name);
"""


@needs_node
def test_the_filter_matches_a_name_a_decimal_number_a_hex_number_and_a_module():
    r = _run_node(["syscallNumberOf", "syscallMatches", "syscallMatchSet"], ITEMS + r"""
      const q = (query, module = '') => names(syscallMatchSet(items, query, module));
      out({ none: syscallMatchSet(items, '', ''), blank: syscallMatchSet(items, '   ', ''),
            name: q('writevirtual'), upper: q('NTCLOSE'), decimal: q('58'), hex: q('0x3a'), bareHex: q('3A'),
            // hex digits alone are a number too, and still find the name: the server's catalog does the same
            digits: q('add'), module: q('', 'win32u.dll'), both: q('user', 'win32u.dll'), apart: q('close', 'win32u.dll'),
            nothing: q('nothing at all'), moduleCase: q('', 'WIN32U.DLL') });""")
    assert r["none"] is None and r["blank"] is None, "no filter is no set: every cell matches"
    assert r["name"] == ["NtWriteVirtualMemory"] and r["upper"] == ["NtClose"]
    assert r["decimal"] == ["NtWriteVirtualMemory"] and r["hex"] == ["NtWriteVirtualMemory"]
    assert r["bareHex"] == ["NtWriteVirtualMemory"]
    assert r["digits"] == ["NtAddAtom", "NtUserAdd"]
    assert r["module"] == ["NtUserGetDC", "NtUserAdd"] and r["moduleCase"] == r["module"]
    assert r["both"] == ["NtUserGetDC", "NtUserAdd"] and r["apart"] == [] and r["nothing"] == []


STATUS = r"""
const status = (extra = {}) => ({ installed: true, path: 'C:\\tools\\ntsleuth', build: '26220.5770', machine: 'ARM64',
  default_view: 'arm64', executables: { arm64: true, x64: true },
  baselines: [{ file: 'ntsleuth-26220.5770-arm64.json', build: '26220.5770', view: 'arm64', current: true, symbols: true, syscalls: 2461 }],
  extraction: { running: [], failed: [] }, ...extra });
const states = s => Object.fromEntries(syscallViewStates(s).map(v => [v.view, v.state]));
"""


@needs_node
def test_view_states_tell_no_baseline_from_a_view_that_cannot_be_told_apart():
    r = _run_node(["syscallViewStates"], STATUS + r"""
      const same = { build: '26220.5770', view: 'x64', reason: 'x64 view is the arm64 view', indistinguishable: true };
      const broke = { build: '26220.5770', view: 'x64', reason: 'ntsleuth-x64.exe exited with 1', indistinguishable: false };
      const stale = { file: 'ntsleuth-26100.1-x64.json', build: '26100.1', view: 'x64', current: false, symbols: true, syscalls: 2400 };
      const broken = { file: 'ntsleuth-26220.5770-x64.json', build: '26220.5770', view: 'x64', current: true, symbols: null, error: 'bad json' };
      const both = { baselines: [...status().baselines, { ...status().baselines[0], view: 'x64', file: 'ntsleuth-26220.5770-x64.json' }] };
      out({ ready: states(status(both)), missing: states(status()),
            same: states(status({ extraction: { running: [], failed: [same] } })),
            broke: states(status({ extraction: { running: [], failed: [broke] } })),
            running: states(status({ extraction: { running: [{ build: '26220.5770', view: 'x64' }], failed: [] } })),
            stale: states(status({ baselines: [...status().baselines, stale] })),
            broken: states(status({ baselines: [...status().baselines, broken] })),
            // a baseline that is there wins over the leftover of an earlier failed run
            winning: states(status({ baselines: [...status().baselines, { ...stale, build: '26220.5770', current: true }],
                                     extraction: { running: [], failed: [same] } })),
            x64Host: states(status({ machine: 'AMD64', default_view: 'x64', baselines: [] })),
            text: syscallViewStates(status({ extraction: { running: [], failed: [same] } })).find(v => v.view === 'x64') });""")
    assert r["ready"] == {"arm64": "ready", "x64": "ready"}
    assert r["missing"] == {"arm64": "ready", "x64": "missing"}
    assert r["same"] == {"arm64": "ready", "x64": "indistinguishable"}
    assert r["broke"]["x64"] == "failed" and r["running"]["x64"] == "extracting"
    assert r["stale"]["x64"] == "stale" and r["broken"]["x64"] == "unusable"
    assert r["winning"]["x64"] == "ready"
    assert r["x64Host"] == {"x64": "missing"}, "an x64 host has the one view"
    # the two states that must read differently, in their words
    assert "same view" in r["text"]["text"] and "arm64" in r["text"]["text"]


@needs_node
def test_notices_say_what_is_missing_and_a_hostile_reason_stays_text():
    r = _run_node(["syscallViewStates", "syscallNotices", "syscallNoticesHtml"], STATUS + r"""
      const same = { build: '26220.5770', view: 'x64', reason: 'x64 view is the arm64 view', indistinguishable: true };
      const none = { baselines: [], extraction: { running: [], failed: [] } };
      const hostile = { build: '26220.5770', view: 'x64', reason: '<img src=x onerror=alert(1)>', indistinguishable: false };
      const html = s => syscallNoticesHtml(syscallNotices(s, null));
      const both = { baselines: [...status().baselines, { ...status().baselines[0], view: 'x64', file: 'ntsleuth-26220.5770-x64.json' }] };
      out({ clean: html(status(both)),
            noBaseline: html(status(none)),
            indistinguishable: html(status({ extraction: { running: [], failed: [same] } })),
            notInstalled: html(status({ installed: false, executables: { arm64: false, x64: false } })),
            hostile: html(status({ extraction: { running: [], failed: [hostile] } })),
            symbols: syscallNoticesHtml(syscallNotices(status(), { view: 'arm64', build: 'x', symbols: false, items: [] })) });""")
    assert r["clean"] == "", "nothing to say when every view has its baseline"
    # "no baseline" and "not distinguishable" are two notices, each with its own class and its own words
    assert "syscall-notice-missing" in r["noBaseline"] and "syscall-notice-indistinguishable" not in r["noBaseline"]
    assert "syscall-notice-indistinguishable" in r["indistinguishable"] and "syscall-notice-missing" not in r["indistinguishable"]
    assert "not distinguishable" in r["indistinguishable"] and "not distinguishable" not in r["noBaseline"]
    assert "no baseline" in r["noBaseline"].lower()
    assert "NTSleuth not installed" in r["notInstalled"] and "C:\\tools\\ntsleuth" in r["notInstalled"]
    assert "<img" not in r["hostile"] and "&lt;img" in r["hostile"]
    assert "parameter" in r["symbols"].lower() and "syscall-notice-symbols" in r["symbols"]


@needs_node
def test_subtitle_names_the_stock_the_build_and_the_view():
    r = _run_node(["syscallSubtitle", "syscallBands"], r"""
      const items = [...Array(3)].map((_, i) => ({ module: 'ntdll.dll', number: i, name: 'N' + i }))
        .concat([...Array(2)].map((_, i) => ({ module: 'win32u.dll', number: 100 + i, name: 'U' + i })));
      out({ full: syscallSubtitle({ build: '26220.5770', view: 'arm64', items }), none: syscallSubtitle(null) });""",
                 _const("SYSCALL_MODULES"))
    assert r["full"] == "5 syscalls · ntdll.dll 3 · win32u.dll 2 · build 26220.5770 · arm64"
    assert r["none"] and "syscall" in r["none"].lower()


@needs_node
def test_the_target_list_has_the_running_processes_and_escapes_their_names():
    r = _run_node(["syscallTargetsHtml"], r"""
      const procs = {
        '4242': { pid: 4242, name: 'sample.exe', exit_time: null },
        '4242@1700000000': { pid: 4242, key: '4242@1700000000', name: 'old.exe', exit_time: '2026-11-23T10:00:00Z' },
        '77': { pid: 77, name: 'zz<img src=x onerror=alert(1)>', exit_time: null },
        '9': { pid: 'nine', name: 'broken', exit_time: null },
        '12': { pid: 12, name: 'alpha.exe', exit_time: null } };
      out({ html: syscallTargetsHtml(procs, '77'), none: syscallTargetsHtml({}, ''), bad: syscallTargetsHtml(null, '') });""")
    html = r["html"]
    assert "<img" not in html and "&lt;img" in html
    assert "old.exe" not in html and "broken" not in html, "an exited instance and a PID that is no number are no targets"
    values = re.findall(r'<option value="([^"]*)"', html)
    assert values == ["", "12", "4242", "77"], "by name, then PID; the first option is the empty choice"
    assert re.search(r'<option value="77" selected>', html)
    assert re.findall(r'<option value="([^"]*)"', r["none"]) == [""] == re.findall(r'<option value="([^"]*)"', r["bad"])


@needs_node
def test_the_scan_summary_names_the_process_the_counts_and_the_score():
    r = _run_node(["syscallScanSummary"], r"""
      const scan = { pid: 4242, process: 'C:\\Users\\x\\sample.exe', view: 'x64', build: '26220.5770', partial: false, note: '',
        counts: { intact: 2455, hooked: 3, patched: 1, diverged: 2, unreadable: 0 },
        evidence: { label: 'SUSPICIOUS', score: 3.456 } };
      out({ full: syscallScanSummary(scan), partial: syscallScanSummary({ ...scan, partial: true, note: '7 stubs unreadable, the result is partial' }),
            clean: syscallScanSummary({ ...scan, counts: { intact: 2461, hooked: 0, patched: 0, diverged: 0, unreadable: 0 } }),
            bare: syscallScanSummary({ pid: 5, counts: {} }) });""")
    assert "PID 4242" in r["full"] and "sample.exe" in r["full"] and "x64" in r["full"]
    assert "6 deviations" in r["full"] and "SUSPICIOUS" in r["full"] and "3.46" in r["full"]
    assert "partial" in r["partial"] and "7 stubs unreadable" in r["partial"]
    assert "no deviations" in r["clean"] and "partial" not in r["clean"]
    assert "PID 5" in r["bare"]


# --- The tab at work: loading, the map on its canvases, scanning ------------------

# Every function, constant and `let` of the block that the flow reaches, so a test hands it to node
FLOW_FUNCTIONS = [
    "syscallBands", "syscallBandLayout", "syscallCellOrigin", "syscallCellAt", "syscallCellLook", "syscallStateColor",
    "syscallDrawBand", "syscallHex", "syscallMapLegendHtml", "syscallRowHtml", "syscallNumberOf", "syscallMatches",
    "syscallMatchSet", "syscallViewStates", "syscallNotices", "syscallNoticesHtml", "syscallSubtitle",
    "syscallTargetsHtml", "syscallScanSummary", "syscallApi", "syscallErrorText", "syscallLoadStatus",
    "syscallLoadBaseline", "syscallRefresh", "syscallSchedulePoll", "syscallLoadTargets", "syscallOnTarget",
    "syscallEmptyText", "syscallEnsureBands", "syscallPaintCanvas", "renderSyscallMap", "renderSyscallLegend",
    "renderSyscallRows", "renderSyscallNotices", "renderSyscallToolbar", "renderSyscallTargets", "renderSyscallScan",
    "syscallRenderAll", "syscallApplyFilter", "syscallOnFilter", "syscallSelect", "syscallCellFromEvent",
    "syscallShowTip", "syscallHideTip", "syscallOnMapMove", "syscallOnMapLeave", "syscallOnMapClick",
    "syscallSetScanNote", "runSyscallScan", "syscallSetView", "syscallResized", "initSyscalls", "syscallsTabShown",
]
FLOW_CONSTS = ["SYSCALL_STATES", "SYSCALL_STATE_COLORS", "SYSCALL_STATE_HELP", "SYSCALL_MODULES", "SYSCALL_MAP",
               "SYSCALL_ROWS_MAX", "SYSCALL_PAGE", "SYSCALL_POLL_MS", "SYSCALL_VIEW_NAMES", "syscallState"]

# Just enough page for the tab: elements that hold children, attributes and listeners, a canvas that writes down
# what is painted on it, a fetch that answers from a table of routes, and timers that wait to be fired
FLOW_DOM = r"""
const realSetTimeout = setTimeout;
const settle = () => new Promise(resolve => realSetTimeout(resolve, 0));
class Node {
    constructor(tag) {
        Object.assign(this, { tagName: tag.toUpperCase(), id: '', children: [], attrs: {}, dataset: {}, style: {},
            listeners: {}, parentElement: null, html: '', text: '', value: '', disabled: false, checked: false,
            hidden: false, className: '', width: 300, height: 150, boxWidth: 0, scrollTop: 0, offsetWidth: 0, calls: [] });
        this.ctx = { globalAlpha: 1, fillStyle: '', strokeStyle: '', lineWidth: 1, transform: null,
            fillRect: (x, y, w, h) => this.calls.push({ op: 'fill', x, y, w, h, color: this.ctx.fillStyle, alpha: this.ctx.globalAlpha }),
            strokeRect: (x, y, w, h) => this.calls.push({ op: 'stroke', x, y, w, h, color: this.ctx.strokeStyle }),
            clearRect: () => { this.calls = []; }, setTransform: (...t) => { this.ctx.transform = t; } };
    }
    get classList() {
        const el = this, names = () => el.className.split(/\s+/).filter(Boolean);
        return { contains: c => names().includes(c),
                 toggle: (c, on) => { el.className = (on ? [...new Set([...names(), c])] : names().filter(n => n !== c)).join(' '); } };
    }
    set textContent(v) { this.children = []; this.text = String(v); }
    get textContent() { return this.text + this.children.map(c => c.textContent).join(''); }
    set innerHTML(v) { this.children = []; this.html = String(v); }
    get innerHTML() { return this.html; }
    appendChild(c) { c.parentElement = this; this.children.push(c); return c; }
    replaceChildren() { this.children = []; this.text = ''; this.html = ''; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
    fire(type, event) { (this.listeners[type] || []).forEach(f => f(event)); }
    getBoundingClientRect() { return { left: 10, top: 20, width: this.boxWidth, height: 0 }; }
    getContext() { return this.ctx; }
    closest(sel) { return sel === 'canvas.syscall-canvas' && this.tagName === 'CANVAS' ? this : null; }
    querySelectorAll(tag) {
        const found = []; const walk = n => n.children.forEach(c => { if (c.tagName.toLowerCase() === tag) found.push(c); walk(c); });
        walk(this); return found;
    }
}
const ids = ['syscalls-subtitle', 'syscall-view-map', 'syscall-view-graph', 'syscall-surface-map', 'syscall-target',
             'syscall-win32u', 'syscall-scan', 'syscall-filter', 'syscall-module-filter', 'syscall-notices',
             'syscall-scan-result', 'syscall-legend', 'syscall-map', 'syscall-tip', 'syscall-catalog-head', 'syscall-rows'];
const els = Object.fromEntries(ids.map(id => [id, Object.assign(new Node('div'), { id })]));
els['syscall-view-graph'].disabled = true;
els['syscall-map'].parentElement = Object.assign(new Node('div'), { boxWidth: 800 });
els['syscall-tip'].hidden = true;
globalThis.window = globalThis;
globalThis.devicePixelRatio = 2;
globalThis.document = { getElementById: id => els[id] || null,
    createElement: tag => Object.assign(new Node(tag), { boxWidth: 900 }) };
globalThis.requestAnimationFrame = fn => fn();
globalThis.state = { activeTab: 'syscalls' };
globalThis.ResizeObserver = class { constructor(fn) { globalThis.resized = fn; } observe() {} };
const timers = [];
globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
globalThis.clearTimeout = () => {};
const requests = [];
let routes = {};
globalThis.fetch = async (url, options) => {
    requests.push({ url, method: (options && options.method) || 'GET', body: options && options.body ? JSON.parse(options.body) : null });
    const route = routes[url.split('?')[0]];
    if (!route) throw new Error('no route for ' + url);
    const answer = typeof route === 'function' ? route(url, options) : route;
    if (answer instanceof Error) throw answer;
    return { ok: (answer.status || 200) < 400, status: answer.status || 200, json: async () => answer.body };
};
const STATUS = { installed: true, path: 'C:\\tools\\ntsleuth', build: '26220.5770', machine: 'ARM64', default_view: 'arm64',
    executables: { arm64: true, x64: true },
    baselines: [{ file: 'a', build: '26220.5770', view: 'arm64', current: true, symbols: true, syscalls: 1100 },
                { file: 'b', build: '26220.5770', view: 'x64', current: true, symbols: true, syscalls: 1100 }],
    extraction: { running: [], failed: [] } };
const ALL = [...Array(600)].map((_, i) => ({ name: 'Nt' + i, module: 'ntdll.dll', number: i, rva: 4096 + i * 32, stub_hex: '00' }))
    .concat([...Array(500)].map((_, i) => ({ name: 'NtUser' + i, module: 'win32u.dll', number: 4096 + i, rva: 8192 + i * 32, stub_hex: '00' })));
const baselineRoute = (url) => {
    const q = new URL(url, 'http://x').searchParams, offset = +q.get('offset') || 0, limit = +q.get('limit') || 200;
    return { body: { items: ALL.slice(offset, offset + limit), total: ALL.length, offset, limit, build: '26220.5770',
                     view: q.get('view') || 'arm64', symbols: true } };
};
const PROCESSES = { '4242': { pid: 4242, name: 'sample.exe', exit_time: null }, '12': { pid: 12, name: 'alpha.exe', exit_time: null } };
// What the server answers to a scan of the 600 ntdll syscalls, the named ones in the state given
const scanBody = (deviations = {}) => {
    const named = Object.keys(deviations).length;
    return { view: 'arm64', build: '26220.5770', pid: 4242, process: 'C:\\x\\sample.exe', modules: ['ntdll.dll'], partial: false, note: '',
        counts: { intact: 600 - named, hooked: 0, patched: 0, diverged: 0, unreadable: 0,
                  ...Object.fromEntries(Object.values(deviations).map(s => [s, Object.values(deviations).filter(d => d === s).length])) },
        evidence: { label: 'SUSPICIOUS', score: 4 },
        states: Object.fromEntries(ALL.slice(0, 600).map(a => [a.name, { name: a.name, state: deviations[a.name] || 'intact' }])) };
};
const freshRoutes = () => { routes = { '/api/syscalls/status': { body: STATUS }, '/api/syscalls/baseline': baselineRoute,
                                      '/api/processes': { body: PROCESSES } }; };
freshRoutes();
const canvases = () => els['syscall-map'].querySelectorAll('canvas');
const chooseTarget = (pid) => { els['syscall-target'].value = String(pid); syscallOnTarget(); };
"""


def _flow(script):
    consts = "\n".join(_const(c) for c in FLOW_CONSTS)
    return _run_node(FLOW_FUNCTIONS, FLOW_DOM + script,
                     "const themeColor = (name, alpha) => alpha === undefined ? name : name + '/' + alpha;\n" + consts)


@needs_node
def test_the_tab_loads_the_whole_baseline_page_by_page_and_draws_a_band_per_module():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const bands = els['syscall-map'].children;
        out({ requests: requests.map(q => q.url), bands: bands.map(b => [b.tagName, b.dataset.module, b.children.map(c => c.tagName + ':' + c.className)]),
              painted: canvases().map(c => [c.dataset.module, c.calls.length, c.width, c.height, c.style.height, c.ctx.transform]),
              subtitle: els['syscalls-subtitle'].textContent, legend: els['syscall-legend'].innerHTML,
              head: els['syscall-catalog-head'].textContent, rows: (els['syscall-rows'].innerHTML.match(/class="syscall-row"/g) || []).length,
              targets: els['syscall-target'].innerHTML });
      })();""")
    baseline = [u for u in r["requests"] if "/api/syscalls/baseline" in u]
    assert [re.search(r"offset=(\d+)", u).group(1) for u in baseline] == ["0", "500", "1000"]
    assert all("limit=500" in u for u in baseline)
    assert sum("/api/syscalls/status" in u for u in r["requests"]) == 1 and any("/api/processes" in u for u in r["requests"])
    assert [b[1] for b in r["bands"]] == ["ntdll.dll", "win32u.dll"]
    assert [[c.split(":")[0] for c in b[2]] for b in r["bands"]] == [["H3", "CANVAS"], ["H3", "CANVAS"]]
    painted = {p[0]: p for p in r["painted"]}
    assert painted["ntdll.dll"][1] == 600 and painted["win32u.dll"][1] == 500, "one painted cell per syscall"
    # drawn for a screen of twice the density: the bitmap is twice the size of the box it fills
    layout_cols = (900 - 6 + 2) // 12
    rows = -(-600 // layout_cols)
    assert painted["ntdll.dll"][2] == 1800 and painted["ntdll.dll"][4] == f"{rows * 12 - 2 + 6}px"
    assert painted["ntdll.dll"][3] == (rows * 12 - 2 + 6) * 2 and painted["ntdll.dll"][5][:1] == [2]
    assert r["subtitle"] == "1,100 syscalls · ntdll.dll 600 · win32u.dll 500 · build 26220.5770 · arm64"
    assert r["legend"].count("syscall-legend-dot") == 5 and "–" in r["legend"], "no counts before a scan"
    assert "1,100 of 1,100" in r["head"] and "first 300 listed" in r["head"] and r["rows"] == 300
    assert '<option value="12">alpha.exe (12)</option>' in r["targets"]


@needs_node
def test_showing_the_tab_again_asks_for_the_status_but_not_for_the_baseline_again():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const before = requests.length;
        syscallsTabShown(); await settle();
        const again = requests.slice(before).map(q => q.url.split('?')[0]);
        syscallRefresh(true); await settle();
        out({ again, forced: requests.slice(before + again.length).map(q => q.url.split('?')[0]) });
      })();""")
    assert sorted(r["again"]) == ["/api/processes", "/api/syscalls/status"]
    assert r["forced"].count("/api/syscalls/baseline") == 3, "a forced refresh reads the baseline anew"


@needs_node
def test_without_a_baseline_the_map_says_why_and_the_tab_asks_again_while_it_is_extracted():
    r = _flow(r"""
      (async () => {
        const reason = 'no syscall baseline for build 26220.5770, view arm64. NTSleuth is extracting it.';
        routes['/api/syscalls/baseline'] = { status: 503, body: { error: reason, view: 'arm64' } };
        routes['/api/syscalls/status'] = { body: { ...STATUS, baselines: [], extraction: { running: [{ build: '26220.5770', view: 'arm64' }], failed: [] } } };
        initSyscalls(); syscallsTabShown(); await settle();
        out({ map: els['syscall-map'].textContent, canvases: canvases().length, notices: els['syscall-notices'].innerHTML,
              subtitle: els['syscalls-subtitle'].textContent, timers: timers.map(t => t.ms), rows: els['syscall-rows'].innerHTML,
              legend: els['syscall-legend'].innerHTML.includes('syscall-legend-dot') });
      })();""")
    assert "NTSleuth is extracting it" in r["map"] and r["canvases"] == 0
    assert "syscall-notice-extracting" in r["notices"]
    assert r["timers"] == [4000], "it looks again when the extraction may be done"
    assert "syscall" in r["subtitle"].lower() and r["legend"]


@needs_node
def test_the_tab_does_not_ask_again_once_it_is_left():
    r = _flow(r"""
      (async () => {
        routes['/api/syscalls/status'] = { body: { ...STATUS, baselines: [], extraction: { running: [{ build: '26220.5770', view: 'arm64' }], failed: [] } } };
        initSyscalls(); syscallsTabShown(); await settle();
        const before = requests.length, timer = timers[0];
        state.activeTab = 'dashboard';
        timer.fn(); await settle();
        out({ asked: requests.length - before, timers: timers.length });
      })();""")
    assert r == {"asked": 0, "timers": 1}, "a timer that fires in another tab asks nothing and sets no new one"


@needs_node
def test_a_scan_colours_the_cells_with_what_was_measured_and_the_legend_counts_them():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        routes['/api/syscalls/scan'] = { body: scanBody({ Nt7: 'patched', Nt9: 'hooked', Nt11: 'hooked' }) };
        chooseTarget(4242);
        await runSyscallScan();
        const ntdll = canvases().find(c => c.dataset.module === 'ntdll.dll'), win32u = canvases().find(c => c.dataset.module === 'win32u.dll');
        const colours = calls => Object.fromEntries([...new Set(calls.map(c => c.color))].map(k => [k, calls.filter(c => c.color === k).length]));
        out({ request: requests.filter(q => q.method === 'POST')[0], ntdll: colours(ntdll.calls), win32u: colours(win32u.calls),
              legend: els['syscall-legend'].innerHTML, result: els['syscall-scan-result'].textContent, tone: els['syscall-scan-result'].className,
              button: [els['syscall-scan'].disabled, els['syscall-scan'].textContent], rows: els['syscall-rows'].innerHTML.includes('syscall-state-patched') });
      })();""")
    assert r["request"]["body"] == {"pid": 4242, "modules": ["ntdll.dll"]}, "ntdll alone unless win32u is asked for"
    assert r["ntdll"] == {"--syscall-intact": 597, "--syscall-hooked": 2, "--syscall-patched/0.35": 1, "--syscall-patched": 1}
    # win32u was not measured: its cells keep the baseline tone
    assert r["win32u"] == {"--syscall-intact": 500}
    assert ">597<" in r["legend"] and ">2<" in r["legend"] and ">1<" in r["legend"] and "500 not scanned" in r["legend"]
    assert "PID 4242" in r["result"] and "3 deviations" in r["result"] and "SUSPICIOUS" in r["result"]
    assert "syscall-scan-result-" in r["tone"]
    assert r["button"] == [False, "SCAN"]
    assert r["rows"], "the rows of the catalog carry the states too"


@needs_node
def test_while_a_scan_runs_scan_is_off_and_a_second_press_asks_nothing():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        // a scan that has not answered yet: the fetch of /scan waits until the test lets it go
        let release;
        const fetchOriginal = globalThis.fetch;
        globalThis.fetch = (url, options) => {
          if (!url.includes('/scan')) return fetchOriginal(url, options);
          requests.push({ url, method: 'POST' });
          return new Promise(resolve => { release = () => resolve({ ok: true, status: 200, json: async () => scanBody() }); });
        };
        chooseTarget(4242);
        const running = runSyscallScan();
        await settle();
        const during = { disabled: els['syscall-scan'].disabled, text: els['syscall-scan'].textContent, note: els['syscall-scan-result'].textContent };
        runSyscallScan(); await settle();
        const posts = requests.filter(q => q.method === 'POST').length;
        release(); await running;
        out({ during, posts, after: [els['syscall-scan'].disabled, els['syscall-scan'].textContent] });
      })();""")
    assert r["during"]["disabled"] is True and r["during"]["text"] == "SCANNING…" and "4242" in r["during"]["note"]
    assert r["posts"] == 1, "a second press while a scan runs asks nothing"
    assert r["after"] == [False, "SCAN"]


@needs_node
def test_win32u_is_scanned_only_when_asked_for():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        routes['/api/syscalls/scan'] = { body: scanBody() };
        chooseTarget(4242); els['syscall-win32u'].checked = true;
        await runSyscallScan();
        out(requests.filter(q => q.method === 'POST')[0].body);
      })();""")
    assert r == {"pid": 4242, "modules": ["ntdll.dll", "win32u.dll"]}


@needs_node
def test_a_scan_that_is_refused_or_times_out_says_so_and_the_map_goes_back_to_the_baseline():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        chooseTarget(4242);
        const outcome = async (answer) => {
          routes['/api/syscalls/scan'] = answer;
          await runSyscallScan();
          const ntdll = canvases().find(c => c.dataset.module === 'ntdll.dll');
          return { note: els['syscall-scan-result'].textContent, tone: els['syscall-scan-result'].className,
                   colours: [...new Set(ntdll.calls.map(c => c.color))], button: els['syscall-scan'].disabled };
        };
        routes['/api/syscalls/scan'] = { body: scanBody({ Nt7: 'patched' }) };
        await runSyscallScan();
        const refused = await outcome({ status: 400, body: { error: 'process view x64 does not match the baseline view arm64' } });
        routes['/api/syscalls/scan'] = { body: scanBody({ Nt7: 'patched' }) };
        await runSyscallScan();
        const timedOut = await outcome({ status: 504, body: { error: 'the scan of process 4242 timed out (120s)' } });
        const unreachable = await outcome(new Error('Failed to fetch'));
        const html = await outcome({ status: 500, body: null });
        out({ refused, timedOut, unreachable, html });
      })();""")
    assert r["refused"]["note"] == "process view x64 does not match the baseline view arm64"
    assert "timed out" in r["timedOut"]["note"] and "4242" in r["timedOut"]["note"]
    assert "Failed to fetch" in r["unreachable"]["note"]
    assert "500" in r["html"]["note"], "an answer that is no JSON still says what happened"
    for outcome in r.values():
        assert outcome["colours"] == ["--syscall-intact"], "a measurement of the earlier scan must not stay on the map"
        assert "error" in outcome["tone"] and outcome["button"] is False


@needs_node
def test_a_scan_needs_a_target_and_asks_nothing_without_one():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const before = requests.length;
        els['syscall-target'].value = '';
        await runSyscallScan();
        out({ asked: requests.length - before, note: els['syscall-scan-result'].textContent, button: els['syscall-scan'].disabled });
      })();""")
    assert r["asked"] == 0 and "process" in r["note"].lower()
    assert r["button"] is True, "SCAN is off while no process is chosen"


@needs_node
def test_a_scan_of_another_view_shows_that_views_baseline():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        routes['/api/syscalls/scan'] = { body: { ...scanBody({ Nt7: 'patched' }), view: 'x64' } };
        chooseTarget(4242);
        await runSyscallScan();
        out({ urls: requests.map(q => q.url).filter(u => u.includes('view=x64')), subtitle: els['syscalls-subtitle'].textContent });
      })();""")
    assert len(r["urls"]) == 3 and r["subtitle"].endswith("· x64")


@needs_node
def test_hover_names_the_cell_click_selects_it_and_leaving_hides_the_tip():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const canvas = canvases().find(c => c.dataset.module === 'ntdll.dll');
        const layout = syscallBandLayout(600, 900), at = syscallCellOrigin(layout, 41);
        // the canvas sits at left 10, top 20 of the page
        const event = (dx, dy) => ({ target: canvas, clientX: 10 + at.x + dx, clientY: 20 + at.y + dy });
        els['syscall-map'].fire('pointermove', event(4, 4));
        const over = { tip: els['syscall-tip'].textContent, hidden: els['syscall-tip'].hidden, hover: syscallState.hover };
        els['syscall-map'].fire('pointermove', event(11, 4));
        const gap = { hidden: els['syscall-tip'].hidden, hover: syscallState.hover };
        els['syscall-map'].fire('pointermove', event(4, 4));
        els['syscall-map'].fire('click', event(4, 4));
        const rings = canvas.calls.filter(c => c.op === 'stroke').map(c => c.color);
        els['syscall-map'].fire('pointerleave', {});
        out({ over, gap, selected: syscallState.selected, rings, left: { hidden: els['syscall-tip'].hidden, hover: syscallState.hover } });
      })();""")
    assert r["over"]["hover"] == "Nt41" and r["over"]["hidden"] is False
    assert "Nt41" in r["over"]["tip"] and "0x29" in r["over"]["tip"] and "41" in r["over"]["tip"] and "ntdll.dll" in r["over"]["tip"]
    assert r["gap"] == {"hidden": True, "hover": ""}, "between two cells there is nothing to name"
    assert r["selected"] == "Nt41" and "--text-primary" in r["rings"]
    assert r["left"] == {"hidden": True, "hover": ""}


@needs_node
def test_the_filter_dims_the_map_and_narrows_the_catalog():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const canvas = canvases().find(c => c.dataset.module === 'ntdll.dll');
        const places = () => canvas.calls.map(c => c.x + ',' + c.y).join(';');
        const before = places();
        els['syscall-filter'].value = 'Nt41'; syscallOnFilter();
        const alphas = [...new Set(canvas.calls.map(c => c.alpha))].sort();
        const narrowed = { head: els['syscall-catalog-head'].textContent, rows: els['syscall-rows'].innerHTML, samePlaces: places() === before, alphas };
        els['syscall-filter'].value = 'no such syscall'; syscallOnFilter();
        const none = { head: els['syscall-catalog-head'].textContent, rows: els['syscall-rows'].innerHTML, drawn: canvas.calls.length };
        els['syscall-filter'].value = ''; els['syscall-module-filter'].value = 'win32u.dll'; syscallOnFilter();
        const module = { head: els['syscall-catalog-head'].textContent, ntdllDimmed: [...new Set(canvas.calls.map(c => c.alpha))] };
        out({ narrowed, none, module });
      })();""")
    assert r["narrowed"]["samePlaces"] and len(r["narrowed"]["alphas"]) == 2 and min(r["narrowed"]["alphas"]) < 0.3
    assert r["narrowed"]["rows"].count('class="syscall-row"') == 11 and r["narrowed"]["head"].startswith("Catalog")
    assert "11 of 1,100" in r["narrowed"]["head"]
    assert 'class="syscall-row"' not in r["none"]["rows"] and "No syscall matches" in r["none"]["rows"]
    assert r["none"]["drawn"] == 600, "nothing matches and every cell is still there"
    assert "500 of 1,100" in r["module"]["head"]
    assert r["module"]["ntdllDimmed"] == [0.18], "the whole ntdll band is dimmed, not drawn away"


@needs_node
def test_the_toggle_has_map_pressed_and_graph_switched_off():
    r = _flow(r"""
      initSyscalls();
      const pressed = () => [els['syscall-view-map'].attrs['aria-pressed'], els['syscall-view-graph'].attrs['aria-pressed']];
      syscallRenderAll();
      const first = pressed();
      out({ first, graph: syscallSetView('graph'), after: pressed(), view: syscallState.view,
            unknown: syscallSetView('__proto__'), map: syscallSetView('map'), surface: els['syscall-surface-map'].hidden });""")
    assert r["first"] == ["true", "false"]
    assert r["graph"] is False and r["after"] == ["true", "false"] and r["view"] == "map", "GRAPH is disabled in this plan"
    assert r["unknown"] is False and r["map"] is True and r["surface"] is False


@needs_node
def test_a_resize_and_a_theme_change_draw_the_map_again():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const canvas = canvases().find(c => c.dataset.module === 'ntdll.dll');
        canvas.width = 5; canvas.calls = [];
        globalThis.resized();
        const afterResize = canvas.calls.length;
        // another tab: nothing is drawn for a map that is not on screen
        state.activeTab = 'dashboard'; canvas.calls = [];
        globalThis.resized();
        out({ afterResize, hidden: canvas.calls.length });
      })();""")
    assert r["afterResize"] == 600 and r["hidden"] == 0


@needs_node
def test_a_theme_change_repaints_the_map_while_its_tab_is_open():
    r = _run_node(["onThemeChange"], r"""
      const _themeColorCache = new Map(); _themeColorCache.set('x', 1);
      const calls = [];
      globalThis.state = { activeTab: 'syscalls' };
      globalThis.renderGraph = () => calls.push('graph'); globalThis.renderRtraceTimeline = () => calls.push('timeline');
      globalThis.renderDashboard = () => calls.push('dashboard'); globalThis.FileMapView = { repaint: () => calls.push('filemap') };
      globalThis.renderSyscallMap = () => calls.push('syscalls');
      onThemeChange();
      const open = [...calls]; calls.length = 0; state.activeTab = 'alerts'; onThemeChange();
      out({ open, closed: calls, cache: _themeColorCache.size });""")
    assert "syscalls" in r["open"] and "syscalls" not in r["closed"] and r["cache"] == 0


# --- The page: markup, styles and themes ------------------------------------------

def _block():
    """The source of the SYSCALLS block of app.js."""
    start = SOURCE.index("// =============================================\n// SYSCALLS\n")
    return SOURCE[start:]


def test_the_tab_sits_after_rizin_and_has_its_head_and_the_toggle():
    html = _read(INDEX_HTML)
    assert re.search(r'data-tab="rizin">Rizin</button>\s*<button class="tab" data-tab="syscalls">SYSCALLS</button>', html)
    tab = _tab_markup("syscalls")
    assert re.search(r'<h2 data-info="[^"]+">Syscalls</h2>', tab)
    assert 'class="content-subtitle" id="syscalls-subtitle"' in tab
    # The toggle: MAP pressed and on, GRAPH shown and switched off until the binary graph exists
    assert re.search(r'role="group"[^>]*aria-label="Surface"', tab)
    map_button = re.search(r'<button[^>]*id="syscall-view-map"[^>]*>MAP</button>', tab).group(0)
    graph_button = re.search(r'<button[^>]*id="syscall-view-graph"[^>]*>GRAPH</button>', tab).group(0)
    assert 'aria-pressed="true"' in map_button and "disabled" not in map_button
    assert 'aria-pressed="false"' in graph_button and " disabled" in graph_button
    assert 'title="comes with the binary graph"' in graph_button
    assert "syscallSetView('map')" in map_button
    # Above the work area: the toolbar (target and SCAN, the filter), the notices and the line a scan leaves
    order = ["syscall-toolbar", "syscall-notices", "syscall-scan-result", "syscall-work"]
    assert [tab.find(f'id="{i}"') for i in order] == sorted(tab.find(f'id="{i}"') for i in order) and tab.find('id="syscall-work"') > 0
    assert 'onclick="runSyscallScan()"' in tab and "oninput=\"syscallOnFilter()\"" in tab


def test_every_element_the_block_reads_is_in_the_page():
    tab = _tab_markup("syscalls")
    ids = set(re.findall(r"getElementById\('(syscalls?-[\w-]+)'\)", _block()))
    ids |= {f"syscall-view-{n}" for n in ("map", "graph")} | {f"syscall-surface-{n}" for n in ("map",)}
    assert {"syscall-map", "syscall-legend", "syscall-rows", "syscall-target", "syscall-scan", "syscall-tip"} <= ids
    page = set(re.findall(r'\bid="([^"]+)"', tab))
    # the surface of GRAPH is the binary graph's: it is inserted when that exists
    assert not sorted(ids - page - {"syscall-surface-graph"}), sorted(ids - page)
    # an inline handler names a function of the block
    handlers = set(re.findall(r'on\w+="(\w+)\(', tab))
    assert handlers and all(re.search(rf"^(async )?function {h}\(", SOURCE, re.M) for h in handlers), handlers
    for name in re.findall(r"onclick=\"[^\"]*\"", tab):
        assert "${" not in name


def test_the_assets_moved_on_and_the_switch_in_the_tab_bar_is_wired():
    html = _read(INDEX_HTML)
    for asset, minimum in (("style.css", 82), ("theme-cyberpunk.css", 37), ("app.js", 120)):
        version = int(re.search(rf"{re.escape(asset)}\?v=(\d+)", html).group(1))
        assert version >= minimum, f"{asset} was changed and kept its ?v="
    assert re.search(r"if \(tabName === 'syscalls'\)[^\n]*syscallsTabShown\(\)", SOURCE)


STATES = ("intact", "hooked", "patched", "diverged", "unreadable")


def test_five_state_colours_exist_in_both_themes_with_their_rgb_triplets():
    classic = _root_values()
    cyberpunk = _cyberpunk_palette()
    for state in STATES:
        for values, where in ((classic, "style.css :root"), (cyberpunk, "Cyberpunk")):
            assert f"--syscall-{state}" in values and f"--syscall-{state}-rgb" in values, (state, where)
    # a colour of its own in each theme, five apart within each
    for values in (classic, cyberpunk):
        assert len({re.sub(r"\s+", "", values[f"--syscall-{s}"]).lower() for s in STATES}) == 5
    assert not [s for s in STATES if _same_value(classic[f"--syscall-{s}"], cyberpunk[f"--syscall-{s}"])]


def test_an_intact_stub_is_the_quietest_colour_and_every_deviation_is_louder_in_both_themes():
    """The map is quiet until something deviates: against the surface the map sits on, the intact colour has the
    lowest contrast and each deviation has clearly more."""
    for name, values in (("Classic", _root_values()), ("Cyberpunk", _cyberpunk_palette())):
        surface = values["--bg-card"]
        contrast = {s: _contrast(values[f"--syscall-{s}"], surface) for s in STATES}
        for state in ("hooked", "patched", "diverged", "unreadable"):
            assert contrast[state] > contrast["intact"] * 1.5, (name, state, contrast)
        assert contrast["intact"] >= 1.3, f"{name}: the baseline tone is too dim to see the grid: {contrast['intact']}"
        # and the deviations that must be looked at beat the surface by a wide margin
        for state in ("hooked", "patched", "diverged"):
            assert contrast[state] >= 4.5, (name, state, contrast[state])


def test_each_state_has_its_class_for_the_dots_of_the_legend_and_the_rows():
    classic = _rules(STYLE_CSS)
    for state in STATES + ("baseline",):
        body = classic.get(f".syscall-state-{state}", "")
        assert f"--syscall-{'intact' if state == 'baseline' else state}" in body, state
    assert "transparent" in classic[".syscall-state-unreadable"], "unreadable is hollow, as on the map"
    assert classic[".syscall-state-baseline"] != classic[".syscall-state-intact"], "the baseline tone is held back"


def _declared(body, prop):
    found = re.findall(r"(?:^|;)\s*%s\s*:\s*([^;]+)" % re.escape(prop), body or "")
    return found[-1].strip() if found else None


def test_the_work_area_fills_the_tab_and_each_list_scrolls_in_itself():
    classic = _rules(STYLE_CSS)
    work = classic[".syscall-work"]
    assert _declared(work, "flex") in ("1", "1 1 0", "1 1 auto") and _declared(work, "min-height") == "0"
    assert _declared(work, "display") == "flex" or _declared(work, "display") == "grid"
    for selector in (".syscall-map", ".syscall-rows"):
        body = classic[selector]
        assert _declared(body, "overflow-y") in ("auto", "scroll") or _declared(body, "overflow") == "auto", selector
        assert _declared(body, "min-height") == "0", selector
    canvas = classic[".syscall-canvas"]
    assert _declared(canvas, "display") == "block" and _declared(canvas, "width") == "100%"
    assert "scrollbar-gutter" in classic[".syscall-map"], "a scroll bar appearing must not change the width cells are laid out for"
    # a 1280 px window: the toolbar wraps instead of pushing the page wider
    assert _declared(classic[".syscall-toolbar"], "flex-wrap") == "wrap"
    assert _declared(classic[".syscall-switch .chart-range-btn:disabled"], "cursor") == "not-allowed" \
        or _declared(classic[".syscall-switch .chart-range-btn:disabled"], "opacity")


def test_the_styles_of_the_tab_are_colours_by_variable_in_both_sheets():
    from test_theme import LITERAL_COLOR
    classic = {s: b for s, b in _rules(STYLE_CSS).items() if "syscall" in s}
    assert len(classic) >= 25
    assert not [f"{s}: {m.group(0)}" for s, b in classic.items() for m in LITERAL_COLOR.finditer(b)]
    # the colours of the states are values of :root in each sheet, and nothing else in them sets one
    from test_theme import _cyberpunk_values
    for values in (_root_values(), _cyberpunk_values()):
        assert sorted(n for n in values if n.startswith("--syscall-")) == sorted(
            f"--syscall-{s}{suffix}" for s in STATES for suffix in ("", "-rgb"))


def test_the_lists_of_the_tests_cover_the_whole_block():
    """Every function and constant of the block is handed to node by the flow tests (a function added to the block
    and left out of the list would be called as undefined by them, or not at all)."""
    block = _block()
    functions = re.findall(r"^(?:async )?function (\w+)\(", block, re.M)
    assert sorted(functions) == sorted(FLOW_FUNCTIONS)
    consts = re.findall(r"^(?:const|let) (\w+) = ", block, re.M)
    assert sorted(consts) == sorted(FLOW_CONSTS)
