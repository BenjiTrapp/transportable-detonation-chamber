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
  * a view switched to whose button is disabled or that the tab does not have
  * the tab missing in the tab bar or the guide, a script that reads an element the page does not have, a state
    colour that is missing in a theme, or an intact stub louder than a deviation in one of them
"""

import os
import re
from html.parser import HTMLParser

from test_frontend import SOURCE, _run_node as _run, needs_node
from test_theme import (APP_JS, INDEX_HTML, LAYOUT_CSS, STYLE_CSS, THEME_CSS, _contrast, _cyberpunk_palette, _read, _root_values, _rules,
                        _same_value, _tab_markup)

OUT = "const out = value => console.log(JSON.stringify(value));\n"


# What every function of the block may call: the helpers of the page and the block's own small ones and constants
HELPERS = ["escapeHtml", "jsArg", "jsInt", "cssToken", "syscallHex"]
BLOCK_CONSTS = ["SYSCALL_STATES", "SYSCALL_STATE_COLORS", "SYSCALL_STATE_HELP", "SYSCALL_MODULES", "SYSCALL_DOC_URL", "SYSCALL_WINGRAPH_URL",
                "SYSCALL_SEVERITY_RANK", "SYSCALL_ROWS_MAX"]


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
    # a measured intact stub is the baseline colour in full: a little more opaque than the baseline tone (0.75), and
    # still the quietest colour on the map
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
    assert all(looks[s]["halo"] > 0 for s in ("patched", "diverged", "unreadable")), "what must be looked at has a ring"
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
      const ring = calls.find(c => c.op === 'fill' && c.w > 10), outline = calls.find(c => c.op === 'stroke');
      out({ strokes: calls.filter(c => c.op === 'stroke'), fills: calls.filter(c => c.op === 'fill').length,
            ring: { color: ring.color, wider: ring.w > 10 && ring.x < syscallCellOrigin(layout, 3).x }, ringBeforeOutline: calls.indexOf(ring) < calls.indexOf(outline),
            a: syscallCellOrigin(layout, 10), b: syscallCellOrigin(layout, 20), c: syscallCellOrigin(layout, 3) });""")
    hollow, selected, hovered = r["strokes"]
    # unreadable is an outline, not a fill, and has the ring of the other deviations around it (a zeroed stub is
    # tampering, not absence): 2,460 cells filled, one ring filled, the outline stroked on top of it
    assert hollow["color"] == "--syscall-unreadable" and r["fills"] == 2461
    assert r["ring"] == {"color": "--syscall-unreadable/0.35", "wider": True}
    assert r["ringBeforeOutline"], "the outline is drawn over its ring"
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


@needs_node
def test_the_scan_summary_of_a_scan_that_read_no_stub_says_so_and_counts_no_deviation():
    r = _run_node(["syscallScanSummary"], r"""
      out(syscallScanSummary({ pid: 7, partial: true, note: '490 stubs unreadable',
        counts: { intact: 0, hooked: 0, patched: 0, diverged: 0, unreadable: 490 },
        evidence: { label: 'NOT OBSERVED', score: 0 } }));""")
    assert "no stub could be read" in r and "490 unreadable" in r and "NOT OBSERVED" in r
    assert "deviation" not in r and "CLEAN" not in r


# --- The tab at work: loading, the map on its canvases, scanning ------------------

# Every function, constant and `let` of the block that the flow reaches, so a test hands it to node
FLOW_FUNCTIONS = [
    "syscallBands", "syscallBandLayout", "syscallCellOrigin", "syscallCellAt", "syscallCellLook", "syscallStateColor",
    "syscallDrawBand", "syscallHex", "syscallMapLegendHtml", "syscallRowHtml", "syscallNumberOf", "syscallMatches",
    "syscallMatchSet", "syscallViewStates", "syscallNotices", "syscallNoticesHtml", "syscallSubtitle",
    "syscallTargetsHtml", "syscallScanSummary", "syscallApi", "syscallErrorText", "syscallLoadStatus",
    "syscallLoadBaseline", "syscallDropForeignScan", "syscallRefresh", "syscallSchedulePoll", "syscallLoadTargets", "syscallOnTarget",
    "syscallEmptyText", "syscallEnsureBands", "syscallPaintCanvas", "renderSyscallMap", "renderSyscallLegend",
    "renderSyscallRows", "renderSyscallNotices", "renderSyscallToolbar", "renderSyscallTargets", "renderSyscallScan",
    "syscallRenderAll", "syscallApplyFilter", "syscallOnFilter", "syscallMapName", "syscallSelect", "syscallCellFromEvent",
    "syscallShowTip", "syscallHideTip", "syscallOnMapMove", "syscallOnMapLeave", "syscallOnMapClick",
    "syscallSetScanNote", "runSyscallScan", "syscallSetView", "syscallResized", "initSyscalls", "syscallsTabShown",
    # the detail panel, the deviation list, the rule draft and the known hooks
    "syscallBytesOf", "syscallBytesHtml", "syscallBytesDiffer", "syscallOwnerHtml", "syscallSignature", "renderSyscallDetail",
    "renderSyscallDeviations", "showSyscallRuleDraft", "syscallHookWarning", "syscallCaptureQuestion", "renderHookAllowlist",
    "syscallDetailModel", "syscallRizinTarget", "renderSyscallDetailPanel", "syscallLoadDetail", "syscallSyncDetail",
    "syscallOpenRizin", "syscallCopySignature", "syscallCopyDraft", "syscallCloseDraft", "syscallScores", "renderSyscallDeviationPanel",
    "syscallDraftRule", "renderSyscallDraft", "applySyscallRule", "syscallHooksModel", "renderSyscallHooks", "syscallLoadHooks",
    "syscallCaptureHooks", "syscallClearHooks", "syscallSetPane", "syscallModel", "syscallRepaintCells", "syscallShowDraft",
    "syscallCopyText", "syscallTargetProcess", "syscallStubsModel", "renderSyscallStubs", "renderSyscallStubsPanel", "runSyscallStubs",
    "syscallRequestDraft", "syscallDraftStubRule",
    "syscallHookKey", "syscallHookPairs", "syscallHookDifference", "syscallHookDrift", "syscallWin32uMissing", "syscallSyncModuleFilter",
    "syscallToggleLower", "syscallApplyLower", "syscallLowerNote",
    # a past measurement on the map
    "syscallWhen", "syscallPastOptionsHtml", "syscallPastBannerHtml", "syscallPastRefusal", "syscallLoadPastList", "renderSyscallPastList",
    "renderSyscallPast", "syscallOnPast", "syscallOpenMeasurement", "syscallBackToLive",
    # the GRAPH surface (tests/test_binary_graph_ui.py): the map's choice and filter reach it
    "binaryGraphLayout", "binaryGraphEdgeLook", "binaryGraphNodeLook", "binaryGraphTones", "binaryGraphMatches", "binaryGraphCut",
    "binaryGraphSvg", "binaryGraphLegend", "binaryGraphStatus", "binaryGraphModel", "renderBinaryGraph", "binaryGraphOnQuery",
    "binaryGraphSubmit", "binaryGraphRun", "binaryGraphItem", "binaryGraphSelect", "binaryGraphFollowMap", "binaryGraphDetailItem",
    "binaryGraphDetailHtml", "binaryGraphOwn", "binaryGraphOrigin",
    # EXPLORE (tests/test_binary_graph_ui.py): the graph opened one node at a time on a canvas of its own
    "binaryGraphNodeRadius", "binaryGraphGuessKind", "binaryGraphDetailKind", "binaryGraphExploreRequests", "binaryGraphCombineOrigin",
    "binaryGraphExploreParts", "binaryGraphExploreModules", "binaryGraphExploreFill", "binaryGraphOpenFunctions", "binaryGraphExploreWalk",
    "binaryGraphExploreFresh", "binaryGraphExploreAddEdge", "binaryGraphExploreMerge", "binaryGraphExploreRelease", "binaryGraphExploreCut", "binaryGraphExploreDegree", "binaryGraphExploreStatus", "binaryGraphExploreInfo",
    "binaryGraphExploreLayout", "binaryGraphExploreAsk", "binaryGraphExploreStart", "binaryGraphExploreSubmit",
    "binaryGraphExpand", "binaryGraphRelayout", "binaryGraphSetDepth", "binaryGraphSetMode", "binaryGraphExploreRender", "binaryGraphDraw",
    "binaryGraphToggleMax", "binaryGraphApplyMax", "binaryGraphExploreNextStep", "binaryGraphCanvasResized",
    "binaryGraphToWorld", "binaryGraphNodeAt", "binaryGraphFit", "binaryGraphZoom", "binaryGraphOnCanvasDown", "binaryGraphOnCanvasMove",
    "binaryGraphOnCanvasUp", "binaryGraphOnCanvasLeave", "binaryGraphOnCanvasWheel", "binaryGraphOnCanvasClick",
    "binaryGraphOnCanvasDblClick", "initBinaryGraphExplore",
    # FIGURES (tests/test_binary_graph_ui.py): the stock as a table, each number opening its list in the detail panel
    "binaryGraphMetricRows", "binaryGraphMetricRowHtml", "binaryGraphMetricsStatus", "renderBinaryGraphMetrics", "binaryGraphMetricsLoad",
    "binaryGraphMetricShown", "binaryGraphMetricForget", "binaryGraphMetricClose", "binaryGraphMetricOpen", "binaryGraphMetricJump",
    "binaryGraphMetricLinks", "binaryGraphMetricHtml", "binaryGraphMetricGo",
]
FLOW_CONSTS = ["SYSCALL_STATES", "SYSCALL_STATE_COLORS", "SYSCALL_STATE_HELP", "SYSCALL_MODULES", "SYSCALL_WIN32U_TITLE", "SYSCALL_MAP",
               "SYSCALL_ROWS_MAX", "SYSCALL_PAGE", "SYSCALL_POLL_MS", "SYSCALL_VIEW_NAMES", "syscallState",
               "SYSCALL_DOC_URL", "SYSCALL_WINGRAPH_URL", "SYSCALL_SYSTEM_DIR", "SYSCALL_NARROW", "SYSCALL_PANE_NAMES", "SYSCALL_SEVERITY_RANK",
               "BINARY_GRAPH", "BINARY_GRAPH_SYSCALL", "BINARY_GRAPH_KINDS", "BINARY_GRAPH_PARTIAL", "BINARY_GRAPH_QUERIES", "BINARY_GRAPH_EDGE_WORDS",
               "binaryGraphState", "binaryGraphRequests", "BINARY_GRAPH_EXPLORE", "binaryGraphExplore", "BINARY_GRAPH_METRICS", "BINARY_GRAPH_MEMBER_LINKS"]

# Just enough page for the tab: elements that hold children, attributes and listeners, a canvas that writes down
# what is painted on it, a fetch that answers from a table of routes, and timers that wait to be fired
FLOW_DOM = r"""
const realSetTimeout = setTimeout;
const settle = () => new Promise(resolve => realSetTimeout(resolve, 0));
class Node {
    constructor(tag) {
        Object.assign(this, { tagName: tag.toUpperCase(), id: '', children: [], attrs: {}, dataset: {}, style: {},
            listeners: {}, parentElement: null, html: '', text: '', value: '', disabled: false, checked: false,
            hidden: false, className: '', width: 300, height: 150, boxWidth: 0, scrollTop: 0, offsetWidth: 0, calls: [], clears: [] });
        this.ctx = { globalAlpha: 1, fillStyle: '', strokeStyle: '', lineWidth: 1, transform: null,
            fillRect: (x, y, w, h) => this.calls.push({ op: 'fill', x, y, w, h, color: this.ctx.fillStyle, alpha: this.ctx.globalAlpha }),
            strokeRect: (x, y, w, h) => this.calls.push({ op: 'stroke', x, y, w, h, color: this.ctx.strokeStyle }),
            clearRect: (...area) => { this.calls = []; this.clears.push(area); }, setTransform: (...t) => { this.ctx.transform = t; },
            save() {}, restore() {}, beginPath() {}, rect() {}, clip() {} };
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
             'syscall-scan-result', 'syscall-legend', 'syscall-map', 'syscall-tip', 'syscall-catalog-head', 'syscall-rows',
             'syscall-work', 'syscall-pane-map', 'syscall-pane-detail', 'syscall-detail-body', 'syscall-draft',
             'syscall-deviations', 'syscall-deviations-head', 'syscall-hooks', 'syscall-hooks-head',
             'syscall-stubs', 'syscall-stubs-body', 'syscall-stubs-head', 'syscall-stubs-run', 'syscall-lower',
             'syscall-lower-fold', 'syscall-lower-note', 'syscall-lower-body', 'syscall-past', 'syscall-past-banner'];
const els = Object.fromEntries(ids.map(id => [id, Object.assign(new Node('div'), { id })]));
els['syscall-map'].parentElement = Object.assign(new Node('div'), { boxWidth: 800 });
els['syscall-tip'].hidden = true;
els['syscall-draft'].hidden = true;
els['syscall-stubs'].hidden = true;
els['syscall-past-banner'].hidden = true;
els['syscall-work'].dataset.pane = 'map';
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
const PROCESSES = { '4242': { pid: 4242, name: 'sample.exe', image: 'C:\\Users\\x\\sample.exe', exit_time: null },
                    '12': { pid: 12, name: 'alpha.exe', exit_time: null } };
// What the server answers to a scan of the 600 ntdll syscalls, the named ones in the state given
const scanBody = (deviations = {}) => {
    const named = Object.keys(deviations).length;
    return { view: 'arm64', build: '26220.5770', pid: 4242, process: 'C:\\x\\sample.exe', modules: ['ntdll.dll'], partial: false, note: '',
        counts: { intact: 600 - named, hooked: 0, patched: 0, diverged: 0, unreadable: 0,
                  ...Object.fromEntries(Object.values(deviations).map(s => [s, Object.values(deviations).filter(d => d === s).length])) },
        evidence: { label: 'SUSPICIOUS', score: 4 },
        states: Object.fromEntries(ALL.slice(0, 600).map(a => [a.name, { name: a.name, state: deviations[a.name] || 'intact' }])) };
};
const HOOKS = { entries: [{ syscall: 'NtBar', owner: 'MsMpEng.exe', build: '26220.5770', view: 'arm64' }], problem: null, path: 'C:\\hooks.json' };
// What the server answers for one syscall of the baseline
const lookupBody = (name, view = 'arm64') => { const a = ALL.find(x => x.name === name);
    return { body: { ...a, return_type: 'NTSTATUS', calling_convention: 'stdcall', is_true_syscall: true, build: '26220.5770', view, prefix_len: 8,
                     stub_hex: '010300d4c0035fd60000000000000000', parameters: [{ name: 'Handle', type: 'HANDLE', sal_annotation: '_In_' }] } }; };
const freshRoutes = () => { routes = { '/api/syscalls/status': { body: STATUS }, '/api/syscalls/baseline': baselineRoute,
                                      '/api/processes': { body: PROCESSES }, '/api/syscalls/hook-baseline': { body: HOOKS },
                                      '/api/syscalls/measurements': { body: { measurements: [] } } };
                            for (const a of ALL) routes['/api/syscalls/' + a.name] = () => lookupBody(a.name, currentView()); };
const currentView = () => (syscallState.baseline && syscallState.baseline.view) || 'arm64';
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
    # the map draws a name, a number and a module: it does not ask for parameters and stub bytes
    assert all("lean=1" in u for u in baseline)
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
    # the past measurements are read again too: a detonation may have added one since
    assert sorted(r["again"]) == ["/api/processes", "/api/syscalls/hook-baseline", "/api/syscalls/measurements", "/api/syscalls/status"]
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
def test_a_baseline_without_win32u_draws_no_band_for_it_and_switches_its_toggle_off_with_the_reason():
    # measured on the VM: the x64 view of build 26200.9974 holds 490 ntdll syscalls and no win32u one
    r = _flow(r"""
      (async () => {
        const NTDLL = ALL.filter(a => a.module === 'ntdll.dll');
        const only = url => { const q = new URL(url, 'http://x').searchParams, offset = +q.get('offset') || 0, limit = +q.get('limit') || 200;
                              return { body: { items: NTDLL.slice(offset, offset + limit), total: NTDLL.length, offset, limit,
                                               build: '26200.9974', view: 'x64', symbols: true } }; };
        initSyscalls(); syscallsTabShown(); await settle();
        const before = { disabled: els['syscall-win32u'].disabled, title: els['syscall-win32u'].title || '' };
        els['syscall-win32u'].checked = true;
        routes['/api/syscalls/baseline'] = only;
        await syscallRefresh(true); await settle();
        routes['/api/syscalls/scan'] = { body: { ...scanBody(), view: 'x64', build: '26200.9974' } };
        chooseTarget(4242);
        await runSyscallScan();
        const after = { bands: els['syscall-map'].children.map(b => b.dataset.module), disabled: els['syscall-win32u'].disabled,
                        checked: els['syscall-win32u'].checked, title: els['syscall-win32u'].title || '',
                        body: requests.filter(q => q.method === 'POST')[0].body };
        routes['/api/syscalls/baseline'] = baselineRoute;
        await syscallRefresh(true); await settle();
        const again = { disabled: els['syscall-win32u'].disabled, title: els['syscall-win32u'].title || '', checked: els['syscall-win32u'].checked };
        // an unticked box stays unticked across the same round trip
        els['syscall-win32u'].checked = false;
        routes['/api/syscalls/baseline'] = only;
        await syscallRefresh(true); await settle();
        routes['/api/syscalls/baseline'] = baselineRoute;
        await syscallRefresh(true); await settle();
        out({ before, after, again, unticked: els['syscall-win32u'].checked });
      })();""")
    assert r["before"]["disabled"] is False
    assert r["after"]["bands"] == ["ntdll.dll"], "no empty band for a module the baseline does not hold"
    assert r["after"]["disabled"] is True and r["after"]["checked"] is False
    assert "win32u.dll" in r["after"]["title"] and "x64" in r["after"]["title"] and "26200.9974" in r["after"]["title"]
    assert r["after"]["body"]["modules"] == ["ntdll.dll"], "nothing of win32u is asked for when there is none to measure"
    assert r["again"]["disabled"] is False and "GUI" in r["again"]["title"], "a baseline with win32u offers it again"
    assert r["again"]["checked"] is True, "and the box is as the user left it before it was switched off"
    assert r["unticked"] is False


@needs_node
def test_a_refresh_after_a_scan_of_another_view_does_not_draw_its_states_on_this_views_baseline():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        routes['/api/syscalls/scan'] = { body: { ...scanBody({ Nt7: 'patched' }), view: 'x64' } };
        chooseTarget(4242);
        await runSyscallScan();
        const ntdll = () => canvases().find(c => c.dataset.module === 'ntdll.dll');
        const shown = { subtitle: els['syscalls-subtitle'].textContent, loud: ntdll().calls.filter(c => c.color.includes('patched')).length };
        await syscallRefresh(true); await settle();
        out({ shown, subtitle: els['syscalls-subtitle'].textContent, colours: [...new Set(ntdll().calls.map(c => c.color))],
              alphas: [...new Set(ntdll().calls.map(c => c.alpha))], legend: els['syscall-legend'].innerHTML,
              note: els['syscall-scan-result'].textContent, tone: els['syscall-scan-result'].className, states: syscallState.states === null });
      })();""")
    assert r["shown"]["subtitle"].endswith("· x64") and r["shown"]["loud"] == 2, "the x64 scan is drawn on the x64 baseline"
    assert r["subtitle"].endswith("· arm64")
    assert r["colours"] == ["--syscall-intact"] and r["alphas"] == [0.75], "the map is the baseline again, in its quiet tone"
    assert r["states"] and "–" in r["legend"] and "patched" not in r["legend"].split("syscall-legend-count")[3]
    assert "x64" in r["note"] and "arm64" in r["note"] and "cleared" in r["note"] and "warn" in r["tone"]


@needs_node
def test_a_scan_whose_views_baseline_cannot_be_loaded_is_not_drawn_on_the_other_view():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const asked = baselineRoute;
        routes['/api/syscalls/baseline'] = url => url.includes('view=x64') ? { status: 503, body: { error: 'no syscall baseline for build 26220.5770, view x64.' } } : asked(url);
        routes['/api/syscalls/scan'] = { body: { ...scanBody({ Nt7: 'patched' }), view: 'x64' } };
        chooseTarget(4242);
        await runSyscallScan();
        const ntdll = canvases().find(c => c.dataset.module === 'ntdll.dll');
        out({ colours: [...new Set(ntdll.calls.map(c => c.color))], note: els['syscall-scan-result'].textContent,
              tone: els['syscall-scan-result'].className, scan: syscallState.scan, subtitle: els['syscalls-subtitle'].textContent,
              legend: els['syscall-legend'].innerHTML, button: els['syscall-scan'].disabled });
      })();""")
    assert r["colours"] == ["--syscall-intact"] and r["scan"] is None and r["subtitle"].endswith("· arm64")
    assert "x64" in r["note"] and "no syscall baseline for build 26220.5770, view x64" in r["note"] and "error" in r["tone"]
    assert "–" in r["legend"] and r["button"] is False


@needs_node
def test_a_scan_whose_views_baseline_load_is_overtaken_is_not_drawn_either():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const asked = baselineRoute;
        let overtaken = false;
        // while the x64 baseline is read, a refresh starts its own read of the baseline: the x64 read is superseded
        routes['/api/syscalls/baseline'] = url => { if (url.includes('view=x64') && !overtaken) { overtaken = true; syscallLoadBaseline(''); } return asked(url); };
        routes['/api/syscalls/scan'] = { body: { ...scanBody({ Nt7: 'patched' }), view: 'x64' } };
        chooseTarget(4242);
        await runSyscallScan(); await settle();
        const ntdll = canvases().find(c => c.dataset.module === 'ntdll.dll');
        out({ colours: [...new Set(ntdll.calls.map(c => c.color))], note: els['syscall-scan-result'].textContent,
              scan: syscallState.scan, subtitle: els['syscalls-subtitle'].textContent });
      })();""")
    assert r["colours"] == ["--syscall-intact"] and r["scan"] is None and r["subtitle"].endswith("· arm64")
    assert "scan again" in r["note"].lower()


@needs_node
def test_a_refresh_overtaken_by_another_read_of_the_baseline_still_ends_its_loading_and_its_polling():
    r = _flow(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        routes['/api/syscalls/status'] = { body: { ...STATUS, extraction: { running: [{ build: '26220.5770', view: 'x64' }], failed: [] } } };
        timers.length = 0;
        const refreshing = syscallRefresh(true);
        syscallLoadBaseline('x64');               // overtakes the refresh's read, as a scan's reload does
        await refreshing; await settle();
        out({ loading: syscallState.loading, timers: timers.map(t => t.ms), empty: els['syscall-map'].textContent.includes('Loading') });
      })();""")
    assert not r["loading"] and not r["empty"]
    assert r["timers"] == [4000], "the extraction is still asked about"


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
    assert all("lean=1" in u for u in r["urls"]), "the other view's baseline is read lean as well"


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
def test_the_module_filter_offers_only_the_modules_the_baseline_holds():
    r = _flow(r"""
      (async () => {
        const NTDLL = ALL.filter(a => a.module === 'ntdll.dll');
        const only = url => { const q = new URL(url, 'http://x').searchParams, offset = +q.get('offset') || 0, limit = +q.get('limit') || 200;
                              return { body: { items: NTDLL.slice(offset, offset + limit), total: NTDLL.length, offset, limit,
                                               build: '26200.9974', view: 'x64', symbols: true } }; };
        initSyscalls(); syscallsTabShown(); await settle();
        const full = els['syscall-module-filter'].innerHTML;
        els['syscall-module-filter'].value = 'win32u.dll'; syscallOnFilter();
        routes['/api/syscalls/baseline'] = only;
        await syscallRefresh(true); await settle();
        const canvas = canvases().find(c => c.dataset.module === 'ntdll.dll');
        out({ full, lean: els['syscall-module-filter'].innerHTML, value: els['syscall-module-filter'].value, module: syscallState.module,
              alphas: [...new Set(canvas.calls.map(c => c.alpha))] });
      })();""")
    values = lambda html: re.findall(r'<option value="([^"]*)"', html)
    assert values(r["full"]) == ["", "ntdll.dll", "win32u.dll"]
    assert values(r["lean"]) == ["", "ntdll.dll"], "a module with no entries in the baseline is not offered"
    assert r["value"] == "" and r["module"] == "", "a chosen module the baseline no longer holds is let go"
    assert r["alphas"] == [0.75], "so the map is not left dimmed all over"


@needs_node
def test_the_toggle_has_map_pressed_and_switches_only_to_a_view_it_has():
    r = _flow(r"""
      initSyscalls();
      const pressed = () => [els['syscall-view-map'].attrs['aria-pressed'], els['syscall-view-graph'].attrs['aria-pressed']];
      syscallRenderAll();
      const first = pressed();
      const graph = syscallSetView('graph'), after = pressed(), view = syscallState.view;
      // a disabled button is not switched to
      syscallSetView('map'); els['syscall-view-graph'].disabled = true;
      out({ first, graph, after, view, disabled: syscallSetView('graph'), still: syscallState.view,
            unknown: syscallSetView('__proto__'), map: syscallSetView('map'), surface: els['syscall-surface-map'].hidden });""")
    assert r["first"] == ["true", "false"]
    assert r["graph"] is True and r["after"] == ["false", "true"] and r["view"] == "graph"
    assert r["disabled"] is False and r["still"] == "map"
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
      globalThis.renderBinaryGraph = () => calls.push('binary-graph');
      onThemeChange();
      const open = [...calls]; calls.length = 0; state.activeTab = 'alerts'; onThemeChange();
      out({ open, closed: calls, cache: _themeColorCache.size });""")
    assert "syscalls" in r["open"] and "syscalls" not in r["closed"] and r["cache"] == 0
    assert "binary-graph" in r["open"] and "binary-graph" not in r["closed"], "the GRAPH surface takes the new colours too"


# --- The detail panel, the deviation list and the rule draft -----------------------

# What the pure renderers of the panels call
DETAIL_FUNCTIONS = ["renderSyscallDetail", "syscallBytesOf", "syscallBytesHtml", "syscallBytesDiffer", "syscallSignature",
                    "syscallOwnerHtml"]
DEVIATION_FUNCTIONS = ["renderSyscallDeviations", "syscallBytesOf", "syscallBytesHtml", "syscallOwnerHtml"]
DRAFT_FUNCTIONS = ["showSyscallRuleDraft"]


@needs_node
def test_detail_marks_the_changed_bytes():
    html = _run_node(["renderSyscallDetail"] + DETAIL_FUNCTIONS, """
      out(renderSyscallDetail({name: "NtFoo", number: 58, module: "ntdll.dll",
        expected: "4c8bd1b8", actual: "e92b1700", state: "patched",
        target_owner: "private", parameters: []}));""")
    assert "4c8bd1b8" in html and "e92b1700" in html
    assert "private" in html


@needs_node
def test_only_the_bytes_that_differ_are_marked():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      out({ part: syscallBytesHtml("4c8bd1b8", "4c8bd1e9"), all: syscallBytesHtml("aabb", "aabb"),
            none: syscallBytesHtml("aabb", null), longer: syscallBytesHtml("aabbcc", "aabb"), bad: syscallBytesHtml("zz", "aa"),
            count: [syscallBytesDiffer("4c8bd1b8", "4c8bd1e9"), syscallBytesDiffer("aabb", "aabb"), syscallBytesDiffer("aabbcc", "aabb")] });""")
    assert r["part"] == '<span class="syscall-bytes-same">4c8bd1</span><span class="syscall-bytes-diff">b8</span>'
    assert "syscall-bytes-diff" not in r["all"] and "syscall-bytes-diff" not in r["none"]
    assert r["longer"].endswith('<span class="syscall-bytes-diff">cc</span>'), "a byte past the end of the other side differs"
    assert r["bad"] == "", "anything that is not whole bytes of hex is not drawn as bytes"
    assert r["count"] == [1, 0, 1]


def _detail(sc):
    return _run_node(DETAIL_FUNCTIONS, "out(renderSyscallDetail(%s));" % sc)


@needs_node
def test_detail_names_the_number_in_hex_and_decimal_and_the_stub_it_compares():
    html = _detail('{name: "NtFoo", number: 58, module: "ntdll.dll", rva: 651680, return_type: "NTSTATUS", '
                   'calling_convention: "stdcall", stub_hex: "010300d4c0035fd60000000000000000", prefix_len: 8, '
                   'build: "26220.5770", view: "arm64", parameters: []}')
    assert "0x3A" in html and "(58)" in html and "0x9F1A0" in html
    assert "NTSTATUS" in html and "stdcall" in html and "26220.5770" in html
    # no scan: the baseline's own bytes, only as far as they are compared
    assert "010300d4c0035fd6" in html and "0000000000000000" not in html
    assert "8 bytes" in html
    assert "syscall-finding" not in html, "nothing was measured: there is no classification to show"


@needs_node
def test_a_syscall_that_nothing_is_chosen_for_says_so():
    html = _run_node(DETAIL_FUNCTIONS, "out([renderSyscallDetail(null), renderSyscallDetail(undefined), renderSyscallDetail('x')]);")
    assert all("Choose a syscall" in h for h in html)


@needs_node
def test_detail_tells_a_syscall_with_no_parameters_from_a_baseline_without_the_symbols():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      const base = { name: "NtYield", number: 1, module: "ntdll.dll" };
      out({ none: renderSyscallDetail({ ...base, parameters: [] }),
            noSymbols: renderSyscallDetail({ ...base, parameters: [], symbols: false }),
            some: renderSyscallDetail({ ...base, parameters: [{ name: "Handle", type: "HANDLE", sal_annotation: "_In_" },
                                                               { name: "Size", type: "SIZE_T", sal_annotation: "_Out_" }] }) });""")
    assert "takes no parameters" in r["none"].lower()
    assert "without the symbol server" in r["noSymbols"] and "takes no parameters" not in r["noSymbols"].lower()
    some = r["some"]
    assert 'data-sortable' in some and 'data-sort-id="syscall-params"' in some
    assert "HANDLE" in some and "_Out_" in some and "SIZE_T" in some
    assert "NTSTATUS" not in some and "?" in some, "an unknown return type is not made up"
    assert "_In_ HANDLE Handle," in some and "_Out_ SIZE_T Size" in some, "the signature is one text to copy"


@needs_node
def test_detail_reads_the_tri_state_number_and_never_renders_none_as_no():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      const base = { name: "NtFoo", number: 58, module: "ntdll.dll", state: "hooked", expected: "4c8bd1b8", actual: "e9aabbcc",
                     target_owner: "edr.dll", parameters: [] };
      out({ yes: renderSyscallDetail({ ...base, number_matches: true }), no: renderSyscallDetail({ ...base, number_matches: false }),
            unknown: renderSyscallDetail({ ...base, number_matches: null }), missing: renderSyscallDetail(base) });""")
    assert "number of the baseline" in r["yes"] and "NOT" not in r["yes"]
    assert "NOT" in r["no"] and "another syscall" in r["no"]
    for key in ("unknown", "missing"):
        assert "do not show a number" in r[key], key
        assert "NOT" not in r[key], f"{key}: a jump over the prologue is not a different number"


@needs_node
def test_detail_says_who_the_jump_goes_to_and_that_an_unresolved_one_is_not_guessed():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      const base = { name: "NtFoo", number: 58, module: "ntdll.dll", expected: "4c8bd1b8", actual: "e9aabbcc", parameters: [] };
      out({ hooked: renderSyscallDetail({ ...base, state: "hooked", target_owner: "edr.dll", pattern: "JMP rel32" }),
            patched: renderSyscallDetail({ ...base, state: "patched", target_owner: "private" }),
            diverged: renderSyscallDetail({ ...base, state: "diverged", target_owner: null }),
            intact: renderSyscallDetail({ ...base, state: "intact", actual: "4c8bd1b8" }) });""")
    assert "edr.dll" in r["hooked"] and "JMP rel32" in r["hooked"] and "file-backed module" in r["hooked"] and "EDR hook" not in r["hooked"]
    assert "private memory" in r["patched"] and "no file backs" in r["patched"]
    assert "unresolved" in r["diverged"]
    assert "Jump target" not in r["intact"], "an intact stub jumps nowhere"
    assert r["intact"].count("syscall-bytes-diff") == 0


@needs_node
def test_an_unreadable_stub_is_not_shown_as_a_stub_that_matches():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      const base = { name: "NtFoo", number: 58, module: "ntdll.dll", state: "unreadable", expected: "010300d4c0035fd6", parameters: [] };
      out({ none: renderSyscallDetail({ ...base, actual: null }), zeros: renderSyscallDetail({ ...base, actual: "0000000000000000" }) });""")
    assert "No bytes could be read" in r["none"] and "syscall-bytes-diff" not in r["none"]
    assert "zeros" in r["zeros"] and "0000000000000000" in r["zeros"]


@needs_node
def test_a_syscall_the_scan_did_not_cover_says_so():
    html = _run_node(DETAIL_FUNCTIONS, 'out(renderSyscallDetail({name: "NtUserFoo", number: 4100, module: "win32u.dll", scanned: false, parameters: []}));')
    assert "not part of the last scan" in html


@needs_node
def test_a_known_hook_says_in_the_detail_that_it_does_not_score_and_stays_there():
    html = _run_node(DETAIL_FUNCTIONS, r"""
      out(renderSyscallDetail({name: "NtBar", number: 80, module: "ntdll.dll", state: "hooked", target_owner: "MsMpEng.exe",
        allowlisted: true, expected: "4c8bd1b8", actual: "e9aabbcc", parameters: []}));""")
    assert "MsMpEng.exe" in html and "allowlist" in html.lower() and "does not score" in html
    assert "e9aabbcc" in html, "the hook is still shown"


@needs_node
def test_everything_the_baseline_and_the_target_hold_is_escaped_in_the_detail():
    evil = '<img src=x onerror=alert(1)>'
    html = _run_node(DETAIL_FUNCTIONS, r"""
      const evil = '<img src=x onerror=alert(1)>';
      out(renderSyscallDetail({ name: evil, number: evil, module: evil, rva: evil, return_type: evil, calling_convention: evil,
        build: evil, view: evil, state: evil, pattern: evil, target_owner: evil, expected: evil, actual: evil, number_matches: false,
        parameters: [{ name: evil, type: evil, sal_annotation: evil }, null, "x"], stub_hex: evil }));""")
    assert "<img" not in html
    assert "&lt;img" in html
    # the state of a stub from the target leaves neither the class attribute nor the element
    attrs = _Attributes(html).elements
    assert "img" not in [tag for tag, _ in attrs]


@needs_node
def test_the_docs_link_is_made_of_the_encoded_name_and_opens_safely():
    html = _run_node(DETAIL_FUNCTIONS, 'out(renderSyscallDetail({name: "Nt/Foo\\"x", number: 1, module: "ntdll.dll", parameters: []}));')
    link = next(a for tag, a in _Attributes(html).elements if tag == "a")
    assert link["href"] == "https://ntdoc.m417z.com/nt%2ffoo%22x"
    assert link["target"] == "_blank" and "noopener" in link["rel"] and "noreferrer" in link["rel"]


@needs_node
def test_open_in_rizin_is_offered_only_when_the_view_can_be_opened():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      const base = { name: "NtFoo", number: 1, module: "ntdll.dll", parameters: [] };
      out({ yes: renderSyscallDetail({ ...base, rizin: true }), no: renderSyscallDetail(base),
            why: renderSyscallDetail({ ...base, rizin_note: "Rizin opens the native view" }) });""")
    assert 'onclick="syscallOpenRizin()"' in r["yes"]
    assert "syscallOpenRizin" not in r["no"] and "syscallOpenRizin" not in r["why"] and "native view" in r["why"]


@needs_node
def test_an_allowlisted_hook_shows_that_it_does_not_score():
    html = _run_node(DEVIATION_FUNCTIONS, """
      out(renderSyscallDeviations([{name: "NtBar", number: 80, state: "hooked",
        target_owner: "MsMpEng.exe", allowlisted: true}]));""")
    assert "MsMpEng.exe" in html
    assert "allowlist" in html.lower()


@needs_node
def test_the_deviation_table_is_sortable():
    html = _run_node(DEVIATION_FUNCTIONS, "out(renderSyscallDeviations([]));")
    assert "data-sortable" in html and "data-sort-id=" in html
    assert "data-sort-skip" in html


def _devs(script):
    return _run_node(DEVIATION_FUNCTIONS, script)


@needs_node
def test_an_allowlisted_hook_stays_in_the_list_with_its_owner_and_says_why_it_has_no_score():
    r = _devs(r"""
      out(renderSyscallDeviations([
        { name: "NtBar", number: 80, state: "hooked", target_owner: "MsMpEng.exe", allowlisted: true, expected: "4c8bd1b8", actual: "e9aabbcc" },
        { name: "NtBaz", number: 81, state: "hooked", target_owner: "other.dll", allowlisted: false, expected: "4c8bd1b8", actual: "e9aabbcc" }],
        { scanned: true, scores: { NtBaz: 0.8 } }));""")
    rows = r.split("<tr")
    known = next(row for row in rows if "NtBar" in row)
    unlisted = next(row for row in rows if "NtBaz" in row)
    assert "MsMpEng.exe" in known and "allowlist" in known and "not scored" in known and "+0" not in known
    assert "+0.80" in unlisted and "allowlist" not in unlisted.lower()


@needs_node
def test_every_state_but_intact_is_listed_the_loudest_first_and_only_a_finding_gets_a_rule_button():
    html = _devs(r"""
      const row = (name, state, extra = {}) => ({ name, number: 5, state, expected: "aabb", actual: "ccdd", target_owner: "x.dll", ...extra });
      out(renderSyscallDeviations([ row("NtUnreadable", "unreadable", { actual: null }), row("NtDiverged", "diverged"),
        row("NtHooked", "hooked"), row("NtKnown", "hooked", { allowlisted: true }), row("NtPatched", "patched"),
        row("NtNoBytes", "patched", { actual: null }) ]));""")
    names = re.findall(r"syscallSelect\(&quot;(\w+)&quot;\)", html)
    assert names == ["NtPatched", "NtNoBytes", "NtHooked", "NtKnown", "NtDiverged", "NtUnreadable"], names
    drafted = re.findall(r"syscallDraftRule\(&quot;(\w+)&quot;\)", html)
    assert drafted == ["NtPatched", "NtHooked", "NtDiverged"], drafted


@needs_node
def test_the_tri_state_number_is_not_read_as_no_in_the_list():
    r = _devs(r"""
      const row = (name, nm) => ({ name, number: 5, state: "hooked", expected: "aabb", actual: "ccdd", target_owner: "x.dll", number_matches: nm });
      out({ no: renderSyscallDeviations([row("NtA", false)]), yes: renderSyscallDeviations([row("NtA", true)]),
            unknown: renderSyscallDeviations([row("NtA", null)]), missing: renderSyscallDeviations([row("NtA", undefined)]) });""")
    assert "number differs" in r["no"]
    for key in ("yes", "unknown", "missing"):
        assert "number differs" not in r[key], key


@needs_node
def test_the_deviation_list_says_why_it_is_empty():
    r = _devs(r"""out({ clean: renderSyscallDeviations([], { scanned: true }), unscanned: renderSyscallDeviations([], { scanned: false }),
                        bare: renderSyscallDeviations(undefined), junk: renderSyscallDeviations([null, 3, "x"]) });""")
    assert "No deviations" in r["clean"] and "Scan a process" in r["unscanned"] and "No deviations" in r["bare"]
    assert r["junk"].count("data-sort-skip") == 1 and "syscallSelect" not in r["junk"]


@needs_node
def test_the_deviation_list_is_capped_and_says_so():
    html = _devs(r"""
      const many = Array.from({ length: 450 }, (_, i) => ({ name: "Nt" + i, number: i, state: "unreadable", expected: "aabb", actual: null }));
      out(renderSyscallDeviations(many, { scanned: true }));""")
    assert html.count("syscallSelect(") == 300
    assert "first 300 of 450" in html and html.count("data-sort-skip") == 1


@needs_node
def test_the_deviation_list_escapes_what_the_target_and_the_baseline_hold():
    html = _devs(r"""
      const evil = '<img src=x onerror=alert(1)>';
      out(renderSyscallDeviations([{ name: evil, number: evil, module: evil, state: evil, pattern: evil, target_owner: evil,
        expected: evil, actual: evil, number_matches: false }, { name: 'a"b', number: 1, state: "patched", expected: "aa", actual: "bb", target_owner: "private" }],
        { scanned: true, selected: evil, scores: { [evil]: 1 } }));""")
    assert "<img" not in html
    assert "img" not in [tag for tag, _ in _Attributes(html).elements]
    elements = _Attributes(html).elements
    # a handler holds one quoted literal of the name and nothing else
    handlers = [a["onclick"] for _, a in elements if "onclick" in a]
    assert handlers and all(re.fullmatch(r'(?:syscallSelect|syscallDraftRule)\("(?:[^"\\]|\\.)*"\)', h) for h in handlers), handlers


@needs_node
def test_the_selected_deviation_is_marked_and_the_state_has_its_dot():
    html = _devs(r"""
      out(renderSyscallDeviations([{ name: "NtA", number: 1, state: "patched", expected: "aa", actual: "bb", target_owner: "private" },
                                   { name: "NtB", number: 2, state: "hooked", expected: "aa", actual: "bb", target_owner: "x.dll" }],
        { scanned: true, selected: "NtB" }));""")
    rows = [a for tag, a in _Attributes(html).elements if tag == "tr" and "data-sort-skip" not in a]
    assert [r.get("class", "") for r in rows[1:]] == ["", "selected"], "the first row is the head"
    assert "syscall-state-patched" in html and "syscall-state-hooked" in html


@needs_node
def test_a_rule_draft_is_shown_as_text_not_html():
    html = _run_node(DRAFT_FUNCTIONS, """
      out(showSyscallRuleDraft({name: "TDC_X", text: "rule TDC_X { <b>x</b> }"}));""")
    assert "<b>" not in html


# as the JavaScript string literal it goes into
YARA = r"rule TDC_DirectSyscall_NtFoo_arm64_0123abcd {\n    meta:\n        description = \"x\"\n    condition:\n        true\n}\n"


def _draft(draft, options="undefined"):
    return _run_node(DRAFT_FUNCTIONS, "out(showSyscallRuleDraft(%s, %s));" % (draft, options))


@needs_node
def test_a_drafted_rule_is_text_in_every_place_it_appears():
    html = _draft(r"""{ kind: "signature", name: "<b>n</b>", text: "<script>alert(1)</script>", target: "<i>t</i>",
      entry: { family: "<u>f</u>" }, covered_by: [{ family: "<em>x</em>", pattern: "<s>p</s>", match: "<a>m</a>" }] }""",
                  '{ note: { tone: "ok", text: "<b>done</b>" } }')
    assert "<b>" not in html and "<script" not in html and "<i>" not in html and "<u>" not in html
    assert "<em>" not in html and "<s>" not in html and "<a>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    yara = _draft(r'{ name: "TDC_DirectSyscall_NtX_x64_aaaaaaaa", text: "<img src=x onerror=alert(1)>", target: "<b>x</b>" }')
    assert "<img" not in yara and "<b>" not in yara
    assert "img" not in [tag for tag, _ in _Attributes(yara).elements]


@needs_node
def test_apply_and_download_are_two_things_that_read_as_two_things():
    html = _draft('{ kind: "yara", name: "TDC_DirectSyscall_NtFoo_arm64_0123abcd", text: "%s", target: "TDC_DirectSyscall_NtFoo_arm64_0123abcd.yar" }' % YARA)
    elements = _Attributes(html).elements
    vm = next(a for t, a in elements if "syscall-draft-vm" in a.get("class", "").split())
    repo = next(a for t, a in elements if "syscall-draft-repo" in a.get("class", "").split())
    assert vm is not repo
    # the one acts on this VM, now; the other hands the rule back and writes nothing
    vm_text, repo_text = (re.search(r'class="syscall-draft-action %s">(.*?)</div>\s*(?:<div class="syscall-draft-action|</section>|$)' % c, html, re.S).group(1)
                          for c in ("syscall-draft-vm", "syscall-draft-repo"))
    assert "APPLY TO THIS VM" in vm_text and "about 2 seconds" in vm_text and "rebuilt VM" in vm_text and "Writes" in vm_text
    assert "DOWNLOAD FOR THE REPO" in repo_text and "rules/yara/" in repo_text and "writes nothing" in repo_text.lower()
    assert "APPLY" not in repo_text and "DOWNLOAD" not in vm_text
    apply = next(a for t, a in elements if t == "button" and a.get("onclick", "").startswith("applySyscallRule"))
    download = next(a for t, a in elements if t == "a")
    assert apply["onclick"] == 'applySyscallRule("TDC_DirectSyscall_NtFoo_arm64_0123abcd")'
    assert "btn-primary" in apply["class"] and "btn-primary" not in download["class"]
    assert "Nothing has been written" in html, "a draft only drafts"


@needs_node
def test_the_download_link_hands_back_exactly_the_draft():
    from urllib.parse import urlsplit, parse_qs
    html = _draft('{ name: "TDC_DirectSyscall_NtFoo_arm64_0123abcd", text: "%s" }' % YARA)
    link = next(a for t, a in _Attributes(html).elements if t == "a")
    parts = urlsplit(link["href"])
    assert parts.path == "/api/syscalls/rule/download"
    query = parse_qs(parts.query, keep_blank_values=True)
    assert query["name"] == ["TDC_DirectSyscall_NtFoo_arm64_0123abcd"] and query["text"] == [YARA.replace('\\"', '"').replace("\\n", "\n")]
    assert link["download"] == "TDC_DirectSyscall_NtFoo_arm64_0123abcd.yar"


@needs_node
def test_while_an_apply_is_under_way_it_cannot_be_pressed_again_and_its_answer_is_shown():
    r = _run_node(DRAFT_FUNCTIONS, r"""
      const d = { name: "TDC_DirectSyscall_NtFoo_arm64_0123abcd", text: "rule x { condition: true }" };
      out({ busy: showSyscallRuleDraft(d, { busy: true }), done: showSyscallRuleDraft(d, { note: { tone: "ok", text: "Written to C:\\rules\\x.yar" } }),
            idle: showSyscallRuleDraft(d) });""")
    apply = lambda h: next(a for t, a in _Attributes(h).elements if t == "button" and "applySyscallRule" in a.get("onclick", ""))
    assert "disabled" in apply(r["busy"]) and "disabled" not in apply(r["idle"])
    assert "Written to C:\\rules\\x.yar" in r["done"] and 'role="status"' in r["done"] and "syscall-draft-result-ok" in r["done"]
    assert "Nothing has been written" in r["idle"] and "Nothing has been written" not in r["done"]


@needs_node
def test_a_signature_draft_is_added_by_hand_and_offers_neither_apply_nor_download():
    html = _draft(r"""{ kind: "signature", entry: { family: "Inline hook", pattern: "e92b1700", match: "prefix", weight: 1 },
        text: '{\n  "family": "Inline hook"\n}', target: "webui/syscall_signatures.json",
        covered_by: [{ family: "Inline hook", pattern: "e9", match: "prefix" }] }""")
    assert "applySyscallRule" not in html and "<a " not in html and "DOWNLOAD" not in html
    assert "by hand" in html and "webui/syscall_signatures.json" in html
    assert "already covered" in html.lower() and "Inline hook" in html


@needs_node
def test_a_draft_without_a_usable_name_offers_nothing_to_write():
    r = _run_node(DRAFT_FUNCTIONS, 'out([showSyscallRuleDraft({}), showSyscallRuleDraft(null), showSyscallRuleDraft({ text: "x" })]);')
    for html in r:
        assert "applySyscallRule" not in html and "<a " not in html


HOOK_FUNCTIONS = ["renderHookAllowlist", "syscallNoticesHtml", "syscallCaptureQuestion", "syscallHookWarning"]


def _hooks(state):
    return _run_node(HOOK_FUNCTIONS, "out(renderHookAllowlist(%s));" % state)


SCAN_OF_A_RUN = '{ pid: 4242, name: "sample.exe", hookable: 3, known: 1, allowlist: { applied: true, entries: 1, reason: "" } }'


@needs_node
def test_recording_hooks_names_its_precondition_instead_of_saying_record_hooks():
    html = _hooks('{ entries: [], loaded: true, scan: %s, scope: { build: "26220.5770", view: "arm64" } }' % SCAN_OF_A_RUN)
    button = next((a, t) for t, a in _Attributes(html).elements if t == "button" and "syscallCaptureHooks" in a.get("onclick", ""))[0]
    assert "disabled" not in button
    label = re.search(r'<button[^>]*syscallCaptureHooks[^>]*>(.*?)</button>', html, re.S).group(1)
    assert label == "RECORD THE HOOKS OF THIS RUN AS KNOWN"
    warning = re.search(r'<p class="syscall-hook-warning"[^>]*>(.*?)</p>', html, re.S).group(1)
    assert warning.startswith("<strong>Only on a host you believe is clean.</strong>")
    for phrase in ("PID 4242", "sample.exe", "whoever installed them", "every process", "hides real findings", "never recorded"):
        assert phrase in warning, phrase
    # the warning is on the page next to the button, not in a tooltip that nobody reads
    assert html.index("syscall-hook-warning") < html.index("syscallCaptureHooks")


@needs_node
def test_the_confirmation_repeats_the_precondition_and_the_number_of_hooks():
    q = _run_node(HOOK_FUNCTIONS, 'out(syscallCaptureQuestion({ pid: 4242, name: "sample.exe", hookable: 3 }));')
    assert "PID 4242" in q and "3" in q and "believe is clean" in q and "hides real findings" in q


@needs_node
def test_without_a_scan_or_without_a_hook_there_is_nothing_to_record():
    r = _run_node(HOOK_FUNCTIONS, r"""
      const find = html => /<button[^>]*syscallCaptureHooks[^>]*>/.exec(html)[0];
      out({ none: find(renderHookAllowlist({ entries: [], loaded: true, scan: null })),
            zero: find(renderHookAllowlist({ entries: [], loaded: true, scan: { pid: 5, name: "a.exe", hookable: 0, known: 2 } })),
            busy: find(renderHookAllowlist({ entries: [], loaded: true, busy: true, scan: { pid: 5, name: "a.exe", hookable: 2 } })),
            ok: find(renderHookAllowlist({ entries: [], loaded: true, scan: { pid: 5, name: "a.exe", hookable: 2 } })) });""")
    assert " disabled" in r["none"] and " disabled" in r["zero"] and " disabled" in r["busy"] and " disabled" not in r["ok"]


@needs_node
def test_the_known_hooks_are_listed_sortable_and_escaped_and_each_set_names_its_build_and_view():
    html = _hooks(r"""{ loaded: true, entries: [{ syscall: "NtBar", owner: "MsMpEng.exe", build: "26220.5770", view: "arm64" },
        { syscall: "<img src=x>", owner: "<b>x</b>", build: "<i>1</i>", view: "x64" }], scan: null, scope: null }""")
    assert 'data-sortable' in html and 'data-sort-id="syscall-hooks"' in html
    assert "MsMpEng.exe" in html and "26220.5770" in html and "arm64" in html and "x64" in html
    assert "<img" not in html and "<b>" not in html and "<i>" not in html
    empty = _hooks("{ loaded: true, entries: [] }")
    assert "data-sort-skip" in empty and "No hook is recorded" in empty
    assert "Loading" in _hooks("{ loaded: false, entries: [] }")


@needs_node
def test_an_unusable_list_and_an_allowlist_that_was_not_applied_are_said_not_skipped():
    html = _hooks(r"""{ loaded: true, entries: [], problem: "the file is corrupt <b>", error: "",
        scan: { pid: 5, name: "a.exe", hookable: 1, allowlist: { applied: false, entries: 3, reason: "no set for build 1, view x64" } } }""")
    assert "the file is corrupt &lt;b&gt;" in html and "no set for build 1, view x64" in html
    assert "not applied" in html.lower()
    failed = _hooks('{ loaded: false, entries: [], error: "The server answered with status 500." }')
    assert "status 500" in failed


@needs_node
def test_forgetting_hooks_asks_for_a_scope_and_has_nothing_to_forget_on_an_empty_list():
    r = _run_node(HOOK_FUNCTIONS, r"""
      const buttons = html => [...html.matchAll(/<button[^>]*onclick="(syscallClearHooks\('\w+'\))"([^>]*)>/g)].map(m => [m[1], / disabled/.test(m[2])]);
      const entry = { syscall: "NtBar", owner: "x.dll", build: "1", view: "arm64" };
      out({ empty: buttons(renderHookAllowlist({ loaded: true, entries: [], scope: { build: "1", view: "arm64" } })),
            full: buttons(renderHookAllowlist({ loaded: true, entries: [entry], scope: { build: "1", view: "arm64" } })),
            noScope: buttons(renderHookAllowlist({ loaded: true, entries: [entry], scope: null })) });""")
    assert r["empty"] == [["syscallClearHooks('this')", True], ["syscallClearHooks('all')", True]]
    assert r["full"] == [["syscallClearHooks('this')", False], ["syscallClearHooks('all')", False]]
    assert r["noScope"] == [["syscallClearHooks('this')", True], ["syscallClearHooks('all')", False]]


# --- The panels at work: choosing, drafting, applying, recording ------------------

# A scan that found a patch, an EDR hook, a hook the allowlist knows and one stub that could not be read
DEVIATIONS_SCAN = r"""
const dev = (name, state, extra = {}) => ({ name, module: 'ntdll.dll', number: +name.slice(2), rva: 4096, state, pattern: null,
    target_owner: null, expected: '010300d4c0035fd6', actual: 'e92b170000000000', number_matches: null, ...extra });
const DEVS = [dev('Nt7', 'patched', { target_owner: 'private', pattern: 'B' }), dev('Nt9', 'hooked', { target_owner: 'edr.dll', pattern: 'B' }),
              dev('Nt11', 'hooked', { target_owner: 'edr.dll', allowlisted: true }), dev('Nt13', 'unreadable', { actual: null })];
const scanWithDeviations = () => ({ ...scanBody({ Nt7: 'patched', Nt9: 'hooked', Nt11: 'hooked', Nt13: 'unreadable' }),
    states: { ...scanBody().states, ...Object.fromEntries(DEVS.map(d => [d.name, d])) }, deviations: DEVS,
    allowlist: { applied: true, entries: 1, reason: '' },
    evidence: { label: 'SUSPICIOUS', score: 4.8, findings: [{ kind: 'syscall_stub_patched', syscall: 'Nt7', score: 4 },
                                                          { kind: 'syscall_stub_hooked', syscall: 'Nt9', score: 0.8 }] } });
const scanned = async () => { initSyscalls(); syscallsTabShown(); await settle(); routes['/api/syscalls/scan'] = { body: scanWithDeviations() };
                              chooseTarget(4242); await runSyscallScan(); };
"""


def _panels(script):
    return _flow(DEVIATIONS_SCAN + script)


@needs_node
def test_choosing_a_syscall_reads_its_detail_for_the_view_of_the_map_and_shows_it():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const before = requests.length;
        syscallSelect('Nt41');
        const loading = els['syscall-detail-body'].innerHTML;
        await settle();
        out({ urls: requests.slice(before).map(q => q.url), loading, body: els['syscall-detail-body'].innerHTML,
              empty: (syscallSelect(''), els['syscall-detail-body'].innerHTML) });
      })();""")
    assert r["urls"] == ["/api/syscalls/Nt41?view=arm64"]
    assert "Loading" in r["loading"] and "Nt41" in r["loading"]
    assert "0x29" in r["body"] and "HANDLE" in r["body"] and "010300d4c0035fd6" in r["body"]
    assert "Choose a syscall" in r["empty"]


@needs_node
def test_a_late_answer_for_a_syscall_that_is_no_longer_chosen_is_dropped():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const original = globalThis.fetch; let release;
        globalThis.fetch = (url, options) => url.includes('/Nt1?') ? new Promise(resolve => { release = () => resolve({ ok: true, status: 200, json: async () => lookupBody('Nt1').body }); })
                                                                    : original(url, options);
        syscallSelect('Nt1'); await settle();
        syscallSelect('Nt2'); await settle();
        release(); await settle();
        out(els['syscall-detail-body'].innerHTML);
      })();""")
    assert ">Nt2<" in r and ">Nt1<" not in r


@needs_node
def test_a_syscall_that_cannot_be_read_says_so_instead_of_showing_the_last_one():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        syscallSelect('Nt1'); await settle();
        routes['/api/syscalls/Nt5'] = { status: 404, body: { error: 'unknown syscall Nt5' } };
        syscallSelect('Nt5'); await settle();
        const missing = els['syscall-detail-body'].innerHTML;
        routes['/api/syscalls/Nt6'] = new Error('Connection lost');
        syscallSelect('Nt6'); await settle();
        out({ missing, lost: els['syscall-detail-body'].innerHTML });
      })();""")
    assert "unknown syscall Nt5" in r["missing"] and ">Nt1<" not in r["missing"] and "data-sortable" not in r["missing"]
    assert "Connection lost" in r["lost"]


@needs_node
def test_a_scan_puts_what_was_measured_into_the_open_detail_and_the_deviation_list():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        syscallSelect('Nt7'); await settle();
        const before = els['syscall-detail-body'].innerHTML;
        routes['/api/syscalls/scan'] = { body: scanWithDeviations() };
        chooseTarget(4242); await runSyscallScan();
        const after = els['syscall-detail-body'].innerHTML;
        syscallSelect('NtUser3'); await settle();
        const outside = els['syscall-detail-body'].innerHTML;
        out({ before, after, outside, list: els['syscall-deviations'].innerHTML, head: els['syscall-deviations-head'].textContent });
      })();""")
    assert "Jump target" not in r["before"] and "patched" in r["after"] and "private memory" in r["after"] and "e92b170000000000" in r["after"]
    assert "not part of the last scan" in r["outside"]
    for name in ("Nt7", "Nt9", "Nt11", "Nt13"):
        assert f"syscallSelect(&quot;{name}&quot;)" in r["list"], name
    assert "+4.00" in r["list"] and "+0.80" in r["list"], "what each stub added to the score, from the evidence"
    assert "allowlist" in r["list"].lower()
    assert r["head"].startswith("4 of 600"), r["head"]


@needs_node
def test_without_a_scan_the_deviation_list_says_to_scan_and_a_scan_that_fails_empties_it():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const first = els['syscall-deviations'].innerHTML;
        await scanned();
        const full = els['syscall-deviations'].innerHTML;
        routes['/api/syscalls/scan'] = { status: 504, body: { error: 'the scan took too long' } };
        await runSyscallScan();
        out({ first, full, failed: els['syscall-deviations'].innerHTML });
      })();""")
    assert "Scan a process" in r["first"] and "syscallSelect" not in r["first"]
    assert "syscallSelect" in r["full"]
    assert "Scan a process" in r["failed"] and "syscallSelect" not in r["failed"], "no row of a scan that did not happen"


@needs_node
def test_a_rule_is_drafted_from_the_deviation_as_the_scan_returned_it_and_nothing_is_written():
    r = _panels(r"""
      (async () => {
        await scanned();
        const draft = { kind: 'signature', entry: { family: 'Stub patch', pattern: 'e92b1700', match: 'prefix', weight: 3 },
                        text: '{ "family": "Stub patch" }', target: 'webui/syscall_signatures.json', covered_by: [] };
        routes['/api/syscalls/rule'] = { body: draft };
        const before = requests.length;
        const unknown = await syscallDraftRule('NtNope');
        const done = await syscallDraftRule('Nt7');
        out({ unknown, done, posts: requests.slice(before).map(q => [q.method, q.url, q.body]), panel: els['syscall-draft'].innerHTML,
              hidden: els['syscall-draft'].hidden });
      })();""")
    assert r["unknown"] is False and r["done"] is True
    assert len(r["posts"]) == 1, "an unknown syscall asks nothing, a draft asks once, and neither apply nor download is asked"
    method, url, body = r["posts"][0]
    assert (method, url) == ("POST", "/api/syscalls/rule")
    assert body["view"] == "arm64" and body["build"] == "26220.5770" and body["deviation"]["name"] == "Nt7"
    assert body["deviation"]["actual"] == "e92b170000000000" and body["deviation"]["state"] == "patched"
    assert r["hidden"] is False and "RULE DRAFT" in r["panel"] and "Stub patch" in r["panel"] and "Nothing has been written" in r["panel"]


@needs_node
def test_a_draft_the_server_refuses_shows_its_reason_and_keeps_no_old_draft():
    r = _panels(r"""
      (async () => {
        await scanned();
        routes['/api/syscalls/rule'] = { body: { kind: 'signature', entry: { family: 'Old' }, text: 'OLD DRAFT', target: 't', covered_by: [] } };
        await syscallDraftRule('Nt7');
        routes['/api/syscalls/rule'] = { status: 400, body: { error: 'this hook is known on this host <b>x</b>' } };
        const done = await syscallDraftRule('Nt9');
        out({ done, panel: els['syscall-draft'].innerHTML, hidden: els['syscall-draft'].hidden });
      })();""")
    assert r["done"] is False and r["hidden"] is False
    assert "this hook is known on this host &lt;b&gt;x&lt;/b&gt;" in r["panel"] and "OLD DRAFT" not in r["panel"]
    assert "applySyscallRule" not in r["panel"]


YARA_DRAFT = ("{ kind: 'yara', name: 'TDC_DirectSyscall_NtFoo_arm64_0123abcd', text: 'rule TDC_DirectSyscall_NtFoo_arm64_0123abcd { condition: true }', "
              "target: 'TDC_DirectSyscall_NtFoo_arm64_0123abcd.yar' }")


@needs_node
def test_applying_a_rule_writes_it_once_and_says_the_applied_copy_is_lost_and_a_commit_is_not_yet_verified():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const draft = %s;
        syscallShowDraft(draft);
        routes['/api/syscalls/rule/apply'] = { body: { status: 'written', name: draft.name, path: 'C:\\rules\\tdc\\x.yar', reload_seconds: 2 } };
        const before = requests.length;
        const wrong = await applySyscallRule('TDC_DirectSyscall_Other_x64_aaaaaaaa');
        const both = [applySyscallRule(draft.name), applySyscallRule(draft.name)];
        await Promise.all(both);
        out({ wrong, posts: requests.slice(before).map(q => [q.url, q.body]), panel: els['syscall-draft'].innerHTML });
      })();""" % YARA_DRAFT)
    assert r["wrong"] is False
    assert [u for u, _ in r["posts"]] == ["/api/syscalls/rule/apply"], "a second press while the first is under way asks nothing"
    body = r["posts"][0][1]
    assert body["name"] == "TDC_DirectSyscall_NtFoo_arm64_0123abcd" and "condition: true" in body["text"]
    assert "C:\\rules\\tdc\\x.yar" in r["panel"] and "about 2 seconds" in r["panel"] and "rebuilt" in r["panel"] and "not yet verified" in r["panel"]
    assert "syscall-draft-result-ok" in r["panel"]


@needs_node
def test_a_rule_that_is_there_already_is_not_an_error_and_a_failed_write_is():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const draft = %s;
        syscallShowDraft(draft);
        routes['/api/syscalls/rule/apply'] = { status: 409, body: { status: 'exists', name: draft.name, path: 'C:\\rules\\tdc\\x.yar',
            error: 'a rule of this name is already there' } };
        await applySyscallRule(draft.name);
        const exists = els['syscall-draft'].innerHTML;
        routes['/api/syscalls/rule/apply'] = { status: 500, body: { error: 'cannot write the rule: Access is denied' } };
        await applySyscallRule(draft.name);
        const failed = els['syscall-draft'].innerHTML;
        routes['/api/syscalls/rule/apply'] = new Error('Connection lost');
        await applySyscallRule(draft.name);
        out({ exists, failed, lost: els['syscall-draft'].innerHTML });
      })();""" % YARA_DRAFT)
    assert "syscall-draft-result-info" in r["exists"] and "left alone" in r["exists"] and "Nothing was written" in r["exists"]
    assert "syscall-draft-result-error" in r["failed"] and "Access is denied" in r["failed"]
    assert "syscall-draft-result-error" in r["lost"] and "Connection lost" in r["lost"]
    assert "disabled" not in re.search(r"<button[^>]*applySyscallRule[^>]*>", r["lost"]).group(0), "a failed apply can be tried again"


@needs_node
def test_a_signature_draft_cannot_be_applied_and_a_closed_draft_is_gone():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        syscallShowDraft({ kind: 'signature', entry: { family: 'x' }, text: 'x', target: 't', name: 'TDC_DirectSyscall_NtFoo_arm64_0123abcd' });
        const before = requests.length;
        const applied = await applySyscallRule('TDC_DirectSyscall_NtFoo_arm64_0123abcd');
        const asked = requests.length - before;
        syscallCloseDraft();
        out({ applied, asked, hidden: els['syscall-draft'].hidden, panel: els['syscall-draft'].innerHTML });
      })();""")
    assert r["applied"] is False and r["asked"] == 0
    assert r["hidden"] is True and r["panel"] == ""


@needs_node
def test_the_known_hooks_are_read_with_the_tab_and_listed():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        out({ html: els['syscall-hooks'].innerHTML, head: els['syscall-hooks-head'].textContent,
              urls: requests.map(q => q.url).filter(u => u.includes('hook-baseline')) });
      })();""")
    assert r["urls"] == ["/api/syscalls/hook-baseline"]
    assert "MsMpEng.exe" in r["html"] and "NtBar" in r["html"]
    assert r["head"] == "1 known"


# The hook list as the server keeps it: a recording adds the hooks of the process as the server measures them just then
HOOK_SERVER = r"""
const REVIEWED = { name: 'Nt9', owner: 'edr.dll' };
const hookServer = (recorded = [REVIEWED]) => {
    const entries = [...HOOKS.entries]; const calls = [];
    routes['/api/syscalls/hook-baseline'] = (url, options) => {
        if (options && options.method === 'POST') {
            calls.push('record');
            for (const r of recorded) entries.push({ syscall: r.name, owner: r.owner, build: '26220.5770', view: 'arm64' });
            return { body: { pid: 4242, build: '26220.5770', view: 'arm64', added: recorded.length, entries: entries.length, partial: false } };
        }
        return { body: { entries, problem: null } };
    };
    return calls;
};
const agree = () => { globalThis.confirm = question => { asked.push(question); return true; }; };
const asked = [];
"""


@needs_node
def test_the_hooks_that_are_recorded_are_the_ones_of_the_scan_the_analyst_reviewed():
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const beforeScan = requests.length;
        const noScan = await syscallCaptureHooks();
        const asksWithoutScan = requests.length - beforeScan;
        await scanned();
        const calls = hookServer();
        let answer = false;
        globalThis.confirm = question => { asked.push(question); return answer; };
        const before = requests.length;
        const declined = await syscallCaptureHooks();
        const afterDecline = requests.slice(before).length;
        answer = true;
        const mark = requests.length;
        const done = await syscallCaptureHooks();
        out({ noScan, asksWithoutScan, declined, afterDecline, done, asked, requests: requests.slice(mark).map(q => [q.method, q.url, q.body]),
              html: els['syscall-hooks'].innerHTML });
      })();""")
    assert r["noScan"] is False and r["asksWithoutScan"] == 0, "without a scan there is no run to record"
    assert r["declined"] is False and r["afterDecline"] == 0, "a declined question measures and records nothing"
    assert r["done"] is True
    kinds = [(m, u.split("?")[0], b and sorted(b)) for m, u, b in r["requests"]]
    assert kinds == [("POST", "/api/syscalls/scan", ["modules", "pid"]), ("POST", "/api/syscalls/hook-baseline", ["pid"]),
                     ("GET", "/api/syscalls/hook-baseline", None)], "the process is measured again and compared before anything is recorded"
    assert r["requests"][1][2] == {"pid": 4242}
    assert len(r["asked"]) == 2 and "believe is clean" in r["asked"][0] and "PID 4242" in r["asked"][0]
    assert "1 hooked stub that is not known yet" in r["asked"][0], "the known hook is not counted again"
    assert "Nt9" in r["asked"][0] and "edr.dll" in r["asked"][0], "the question names the hooks that will be recorded"
    assert "Recorded 1 new hook" in r["html"] and "Nt9" in r["html"] and "syscall-draft-result-ok" in r["html"]
    assert "scan again" in r["html"].lower()


@needs_node
def test_a_hook_that_appeared_since_the_scan_is_not_recorded_and_the_analyst_is_told_which():
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        await scanned(); agree();
        const calls = hookServer();
        // the sample dropped another module-backed hook after the scan was reviewed
        const again = scanWithDeviations(); again.deviations = [...DEVS, dev('Nt15', 'hooked', { target_owner: 'dropped.dll' })];
        routes['/api/syscalls/scan'] = { body: again };
        const done = await syscallCaptureHooks();
        out({ done, calls, html: els['syscall-hooks'].innerHTML, busy: syscallState.hooks.busy });
      })();""")
    assert r["done"] is False and r["calls"] == [], "nothing is recorded"
    assert "Nothing was recorded" in r["html"] and "syscall-draft-result-error" in r["html"]
    assert "Nt15" in r["html"] and "dropped.dll" in r["html"] and "no longer those of the scan you reviewed" in r["html"]
    assert r["busy"] is False and " disabled" not in re.search(r"<button[^>]*syscallCaptureHooks[^>]*>", r["html"]).group(0)


@needs_node
def test_a_pid_that_now_belongs_to_another_process_is_not_recorded():
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        await scanned(); agree();
        const calls = hookServer();
        routes['/api/syscalls/scan'] = { body: { ...scanWithDeviations(), process: 'C:\\Windows\\System32\\other.exe' } };
        const done = await syscallCaptureHooks();
        out({ done, calls, html: els['syscall-hooks'].innerHTML });
      })();""")
    assert r["done"] is False and r["calls"] == []
    assert "other.exe" in r["html"] and "sample.exe" in r["html"] and "reused" in r["html"]


@needs_node
def test_a_hook_that_is_gone_or_a_measurement_that_fails_records_nothing_either():
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        await scanned(); agree();
        const calls = hookServer();
        routes['/api/syscalls/scan'] = { body: { ...scanWithDeviations(), deviations: DEVS.filter(d => d.name !== 'Nt9') } };
        const gone = await syscallCaptureHooks(); const goneHtml = els['syscall-hooks'].innerHTML;
        routes['/api/syscalls/scan'] = { status: 504, body: { error: 'the scan took too long' } };
        const failed = await syscallCaptureHooks();
        out({ gone, failed, calls, goneHtml, html: els['syscall-hooks'].innerHTML });
      })();""")
    assert r["gone"] is False and r["failed"] is False and r["calls"] == []
    assert "Nt9" in r["goneHtml"] and "Nothing was recorded" in r["goneHtml"]
    assert "could not be measured again" in r["html"] and "the scan took too long" in r["html"]


@needs_node
def test_a_hook_the_server_recorded_that_was_not_reviewed_is_said_loudly_with_the_way_back():
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        await scanned(); agree();
        // the two measurements agree, but the server's own measurement a moment later found one more
        hookServer([REVIEWED, { name: 'Nt21', owner: 'late.dll' }]);
        const done = await syscallCaptureHooks();
        out({ done, html: els['syscall-hooks'].innerHTML });
      })();""")
    assert r["done"] is True
    assert "syscall-draft-result-error" in r["html"] and "did not review" in r["html"] and "Nt21" in r["html"] and "late.dll" in r["html"]
    assert "FORGET THIS BUILD AND VIEW" in r["html"] and "syscall-draft-result-ok" not in r["html"]


@needs_node
def test_nothing_is_recorded_while_the_list_of_known_hooks_has_not_been_read():
    """With no list read, every hook already known would look like one the analyst did not review, and the way back that
    the note names would wipe a list that was built on a clean host."""
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        await scanned(); agree();
        // the list cannot be read
        routes['/api/syscalls/hook-baseline'] = { status: 500, body: { error: 'the allowlist cannot be read' } };
        await syscallLoadHooks();
        const loadedBefore = syscallState.hooks.loaded;
        const mark = requests.length;
        syscallState.hooks.loaded = false;
        const refused = await syscallCaptureHooks();
        const asked = requests.slice(mark).map(q => [q.method, q.url]);
        const html = els['syscall-hooks'].innerHTML;
        const button = /<button[^>]*syscallCaptureHooks[^>]*>/.exec(html)[0];
        // the list can be read again: it is read first, and what is known is not taken for new
        const calls = hookServer();
        syscallState.hooks.loaded = false;
        const done = await syscallCaptureHooks();
        out({ loadedBefore, refused, asked, html, button, done, calls, after: els['syscall-hooks'].innerHTML });
      })();""")
    assert r["refused"] is False
    assert all(not (m == "POST" or u.startswith("/api/syscalls/scan")) for m, u in r["asked"]), "no measurement, no recording"
    assert "has not been read" in r["html"] and "syscall-draft-result-error" in r["html"]
    assert "FORGET" not in re.sub(r"<button.*?</button>", "", r["html"], flags=re.S), "no way back is suggested for a false alarm"
    assert " disabled" in r["button"], "and the button waits"
    assert r["done"] is True and r["calls"] == ["record"]
    assert "did not review" not in r["after"] and "Recorded 1 new hook" in r["after"], "NtBar was known: it is not counted as recorded"


@needs_node
def test_the_record_button_is_off_until_the_list_has_loaded():
    r = _run_node(HOOK_FUNCTIONS, r"""
      const scan = { pid: 5, name: 'a.exe', hookable: 2 };
      const find = html => /<button[^>]*syscallCaptureHooks[^>]*>/.exec(html)[0];
      out({ unread: find(renderHookAllowlist({ entries: [], loaded: false, scan })), read: find(renderHookAllowlist({ entries: [], loaded: true, scan })) });""")
    assert " disabled" in r["unread"] and " disabled" not in r["read"]


@needs_node
def test_a_failed_recording_says_so_and_can_be_tried_again():
    r = _panels(HOOK_SERVER + r"""
      (async () => {
        await scanned(); agree();
        routes['/api/syscalls/hook-baseline'] = (url, options) => options && options.method === 'POST'
            ? { status: 500, body: { error: 'cannot write the hook allowlist: Access is denied' } } : { body: HOOKS };
        await syscallCaptureHooks();
        out({ html: els['syscall-hooks'].innerHTML });
      })();""")
    assert "syscall-draft-result-error" in r["html"] and "Access is denied" in r["html"]
    assert " disabled" not in re.search(r"<button[^>]*syscallCaptureHooks[^>]*>", r["html"]).group(0)


HOOK_PAIR_FUNCTIONS = ["syscallHookPairs", "syscallHookDifference", "syscallHookDrift", "syscallHookKey"]


@needs_node
def test_only_the_hooks_that_the_server_would_record_are_the_reviewed_ones():
    r = _run_node(HOOK_PAIR_FUNCTIONS, r"""
      const d = (name, state, extra = {}) => ({ name, module: 'ntdll.dll', state, target_owner: 'EDR.dll', ...extra });
      out(syscallHookPairs({ deviations: [d('NtA', 'hooked'), d('NtA', 'hooked'), d('NtB', 'patched', { target_owner: 'private' }),
        d('NtC', 'hooked', { allowlisted: true }), d('NtD', 'hooked', { target_owner: 'private' }), d('NtE', 'hooked', { target_owner: null }),
        d('NtUserF', 'hooked', { module: 'win32u.dll' }), d('NtG', 'diverged'), d('NtH', 'unreadable', { target_owner: null }), null] }));""")
    assert r == [{"name": "NtA", "owner": "EDR.dll"}], "ntdll only (that is all the server measures), a module owner, not known, once"


@needs_node
def test_a_difference_in_hooks_names_what_is_new_and_what_is_gone_and_a_same_measurement_has_none():
    r = _run_node(HOOK_PAIR_FUNCTIONS, r"""
      const scan = (names, extra = {}) => ({ pid: 5, process: 'C:\\a\\x.exe', build: '1', view: 'arm64',
        deviations: names.map(n => ({ name: n, module: 'ntdll.dll', state: 'hooked', target_owner: 'e.dll' })), ...extra });
      out({ same: syscallHookDrift(scan(['NtA', 'NtB']), scan(['NtB', 'NtA'])), more: syscallHookDrift(scan(['NtA']), scan(['NtA', 'NtC'])),
            less: syscallHookDrift(scan(['NtA', 'NtB']), scan(['NtA'])), pid: syscallHookDrift(scan(['NtA']), scan(['NtA'], { process: 'C:\\b\\y.exe' })),
            view: syscallHookDrift(scan(['NtA']), scan(['NtA'], { view: 'x64' })),
            diff: syscallHookDifference(['a|1', 'b|1'], ['b|1', 'c|1']) });""")
    assert r["same"] == ""
    assert "NtC" in r["more"] and "new since" in r["more"] and "gone since" not in r["more"]
    assert "NtB" in r["less"] and "gone since" in r["less"]
    assert "x.exe" in r["pid"] and "y.exe" in r["pid"] and "reused" in r["pid"]
    assert "x64" in r["view"] and "arm64" in r["view"]
    assert r["diff"] == {"extra": ["c|1"], "missing": ["a|1"]}


@needs_node
def test_forgetting_known_hooks_asks_first_and_names_its_scope():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const asked = []; let answer = false;
        globalThis.confirm = question => { asked.push(question); return answer; };
        routes['/api/syscalls/hook-baseline'] = (url, options) => options && options.method === 'DELETE' ? { body: { ok: true, entries: 0 } } : { body: HOOKS };
        const before = requests.length;
        const declined = await syscallClearHooks('this');
        const afterDecline = requests.length - before;
        answer = true;
        await syscallClearHooks('this'); await syscallClearHooks('all');
        const unknown = await syscallClearHooks('everything');
        out({ declined, afterDecline, asked: asked.length, unknown,
              deletes: requests.slice(before).filter(q => q.method === 'DELETE').map(q => q.url) });
      })();""")
    assert r["declined"] is False and r["afterDecline"] == 0
    assert r["deletes"] == ["/api/syscalls/hook-baseline?build=26220.5770&view=arm64", "/api/syscalls/hook-baseline"]
    assert r["unknown"] is False


@needs_node
def test_the_panes_switch_below_the_narrow_width_and_a_choice_there_shows_the_detail():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const pressed = () => [els['syscall-pane-map'].attrs['aria-pressed'], els['syscall-pane-detail'].attrs['aria-pressed']];
        const wide = (syscallSelect('Nt41'), els['syscall-work'].dataset.pane);
        globalThis.matchMedia = query => ({ matches: query === SYSCALL_NARROW });
        syscallSelect('Nt42');
        const narrow = els['syscall-work'].dataset.pane, narrowPressed = pressed();
        const back = syscallSetPane('map');
        out({ wide, narrow, narrowPressed, back, after: [els['syscall-work'].dataset.pane, pressed()], unknown: syscallSetPane('__proto__'),
              painted: canvases().every(c => c.calls.length > 0) });
      })();""")
    assert r["wide"] == "map" and r["narrow"] == "detail" and r["narrowPressed"] == ["false", "true"]
    assert r["back"] is True and r["after"] == ["map", ["true", "false"]] and r["unknown"] is False and r["painted"]


@needs_node
def test_the_signature_and_the_draft_are_copied_as_text():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const copied = [], toasts = [];
        // node has a navigator of its own, which an assignment does not replace
        const setNavigator = value => Object.defineProperty(globalThis, 'navigator', { value, configurable: true, writable: true });
        setNavigator({ clipboard: { writeText: text => { copied.push(text); return Promise.resolve(); } } });
        globalThis.showToast = (type, title) => toasts.push(type + ':' + title);
        syscallSelect('Nt41'); await settle();
        syscallCopySignature();
        syscallShowDraft({ kind: 'signature', entry: { family: 'x' }, text: 'THE TEXT <b>', target: 't' });
        syscallCopyDraft(); await settle();
        setNavigator({});
        const without = [syscallCopySignature(), syscallCopyDraft()];
        out({ copied, toasts, without });
      })();""")
    assert r["copied"][0].startswith("? Nt41(") or r["copied"][0].startswith("NTSTATUS Nt41(")
    assert "_In_ HANDLE Handle" in r["copied"][0] and r["copied"][1] == "THE TEXT <b>"
    assert r["without"] == [False, False], "no clipboard: it says no instead of throwing"


@needs_node
def test_open_in_rizin_opens_the_native_module_and_goes_to_the_syscall_and_is_not_offered_for_an_emulated_view():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const calls = [];
        globalThis.openInRizin = path => { calls.push(['open', path]); return Promise.resolve(true); };
        globalThis.rizinSeek = (addr, source) => { calls.push(['seek', addr, source]); return Promise.resolve(true); };
        syscallSelect('Nt41'); await settle();
        const native = els['syscall-detail-body'].innerHTML;
        await syscallOpenRizin();
        // an emulated x64 process on an arm64 host: the baseline of the map is the x64 view
        routes['/api/syscalls/scan'] = { body: { ...scanBody(), view: 'x64' } };
        chooseTarget(4242); await runSyscallScan(); await settle();
        const emulated = els['syscall-detail-body'].innerHTML;
        const none = await syscallOpenRizin();
        out({ calls, native, emulated, none });
      })();""")
    assert 'onclick="syscallOpenRizin()"' in r["native"]
    assert r["calls"] == [["open", "C:\\Windows\\System32\\ntdll.dll"], ["seek", "Nt41", "syscalls"]]
    assert "syscallOpenRizin" not in r["emulated"] and "native view" in r["emulated"]
    assert r["none"] is False and len(r["calls"]) == 2, "nothing is opened for a view Rizin would not show"


@needs_node
def test_the_detail_is_read_again_when_the_view_of_the_map_changes_and_dropped_when_its_syscall_goes():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        syscallSelect('Nt41'); await settle();
        const before = requests.length;
        routes['/api/syscalls/scan'] = { body: { ...scanBody(), view: 'x64' } };
        chooseTarget(4242); await runSyscallScan(); await settle();
        const reread = requests.slice(before).map(q => q.url).filter(u => u.includes('/Nt41'));
        syscallState.baseline = { ...syscallState.baseline, items: [] }; syscallState.selected = '';
        syscallRenderAll();
        out({ reread, cleared: els['syscall-detail-body'].innerHTML });
      })();""")
    assert r["reread"] == ["/api/syscalls/Nt41?view=x64"]
    assert "Choose a syscall" in r["cleared"]


# --- Hover: only the two cells that changed are drawn again -----------------------

# A canvas that is a grid of pixels: each pixel remembers what was painted on it since it was last cleared, the
# clip is honoured, and a stroke is the four bars it is made of. Two canvases that were painted by different routes
# are alike when every pixel remembers the same.
RASTER = r"""
class Raster {
    constructor(w, h) { this.w = w; this.h = h; this.px = new Map(); this.globalAlpha = 1; this.fillStyle = ''; this.strokeStyle = ''; this.lineWidth = 1;
                        this.clipRect = null; this.stack = []; this.ops = 0; }
    inClip(x, y) { const c = this.clipRect; return !c || (x >= c[0] && x < c[2] && y >= c[1] && y < c[3]); }
    cover(x0, y0, x1, y1, fn) {
        for (let y = Math.max(0, Math.floor(y0)); y < Math.min(this.h, Math.ceil(y1)); y++)
            for (let x = Math.max(0, Math.floor(x0)); x < Math.min(this.w, Math.ceil(x1)); x++)
                if (this.inClip(x, y) && Math.min(x + 1, x1) - Math.max(x, x0) > 0 && Math.min(y + 1, y1) - Math.max(y, y0) > 0) fn(x + ',' + y);
    }
    fillRect(x, y, w, h) { this.ops++; const tag = this.fillStyle + '@' + this.globalAlpha;
        this.cover(x, y, x + w, y + h, k => this.px.set(k, (this.px.get(k) || '') + '|' + tag)); }
    strokeRect(x, y, w, h) { this.ops++; const t = this.lineWidth / 2, tag = 'S' + this.strokeStyle + '@' + this.globalAlpha + 'w' + this.lineWidth;
        for (const [a, b, c, d] of [[x - t, y - t, x + w + t, y + t], [x - t, y + h - t, x + w + t, y + h + t], [x - t, y - t, x + t, y + h + t], [x + w - t, y - t, x + w + t, y + h + t]])
            this.cover(a, b, c, d, k => this.px.set(k, (this.px.get(k) || '') + '|' + tag)); }
    clearRect(x, y, w, h) { this.cover(x, y, x + w, y + h, k => this.px.delete(k)); }
    save() { this.stack.push(this.clipRect); }
    restore() { this.clipRect = this.stack.pop(); }
    beginPath() { this.path = null; }
    rect(x, y, w, h) { this.path = [x, y, x + w, y + h]; }
    clip() { const p = this.path, c = this.clipRect; this.clipRect = c ? [Math.max(c[0], p[0]), Math.max(c[1], p[1]), Math.min(c[2], p[2]), Math.min(c[3], p[3])] : p; }
    snapshot() { return [...this.px.entries()].sort().map(([k, v]) => k + '=' + v).join('\n'); }
}
"""

REPAINT_FUNCTIONS = ["syscallBands", "syscallBandLayout", "syscallCellOrigin", "syscallCellAt", "syscallCellLook", "syscallStateColor",
                     "syscallDrawBand"]


def _repaint(script):
    return _run_node(REPAINT_FUNCTIONS, RASTER + RECORDER + script, _map_prelude())


@needs_node
def test_drawing_again_only_the_cells_that_changed_leaves_the_same_picture_as_drawing_them_all():
    r = _repaint(r"""
      const width = 140, grid = syscallBandLayout(60, width);     // 11 columns: rows of cells that touch each other's rings
      const items = cells.slice(0, 60);
      const states = new Map(items.map((c, i) => [c.name, i % 7 === 3 ? 'patched' : i % 11 === 5 ? 'hooked' : i % 13 === 2 ? 'unreadable' : i % 17 === 4 ? 'diverged' : 'intact']));
      const match = new Set(items.filter((c, i) => i % 3 !== 0).map(c => c.name));
      const mismatches = [];
      // every pair of neighbours in a grid and some far apart, with and without a filter and a selected cell
      for (const withMatch of [false, true]) for (const selected of [null, 'Nt14', 'Nt3']) for (const from of [0, 3, 10, 11, 12, 21, 43, 59]) for (const to of [0, 4, 11, 12, 22, 33, 58]) {
        const model = hover => ({ states, match: withMatch ? match : null, selected, hover });
        const partial = new Raster(width, grid.height);
        syscallDrawBand(partial, grid, items, model(items[from].name));
        syscallDrawBand(partial, grid, items, model(items[to].name), [from, to]);
        const whole = new Raster(width, grid.height);
        syscallDrawBand(whole, grid, items, model(items[to].name));
        if (partial.snapshot() !== whole.snapshot()) mismatches.push([withMatch, selected, from, to]);
      }
      out({ mismatches: mismatches.slice(0, 5), count: mismatches.length });""")
    assert r["count"] == 0, r["mismatches"]


@needs_node
def test_a_repaint_clears_and_draws_only_around_the_cells_it_is_given():
    r = _repaint(r"""
      const layout2 = syscallBandLayout(cells.length, 900);
      const full = record(); syscallDrawBand(full.ctx, layout2, cells, quietModel);
      const part = record(); part.ctx.save = part.ctx.restore = part.ctx.beginPath = part.ctx.clip = () => {};
      const rects = []; part.ctx.rect = (...a) => rects.push(a);
      syscallDrawBand(part.ctx, layout2, cells, { ...quietModel, hover: 'Nt500' }, [500]);
      const o = syscallCellOrigin(layout2, 500);
      out({ full: full.calls.length, part: part.calls.length, rects, origin: o,
            inside: part.calls.every(c => c.x >= o.x - 12 - 3 && c.x <= o.x + 12 + 3 && c.y >= o.y - 12 - 3 && c.y <= o.y + 12 + 3) });""")
    assert r["full"] == 2461 and r["part"] <= 10, "a cell and the neighbours its ring reaches, and the ring"
    reach = 3
    assert r["rects"] == [[r["origin"]["x"] - reach, r["origin"]["y"] - reach, 10 + 2 * reach, 10 + 2 * reach]]
    assert r["inside"]


@needs_node
def test_a_hover_that_crosses_a_cell_paints_the_two_cells_of_its_own_band_and_nothing_else():
    r = _panels(r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        const ntdll = canvases().find(c => c.dataset.module === 'ntdll.dll'), win32u = canvases().find(c => c.dataset.module === 'win32u.dll');
        const layout = syscallBandLayout(600, 900), at = i => syscallCellOrigin(layout, i);
        const event = i => ({ target: ntdll, clientX: 10 + at(i).x + 4, clientY: 20 + at(i).y + 4 });
        els['syscall-map'].fire('pointermove', event(41));
        ntdll.clears = []; win32u.clears = []; ntdll.calls.length = 0; const winBefore = win32u.calls.length;
        els['syscall-map'].fire('pointermove', event(42));
        const move = { clears: ntdll.clears.length, other: win32u.clears.length, otherCalls: win32u.calls.length === winBefore, drawn: ntdll.calls.length };
        ntdll.clears = [];
        els['syscall-map'].fire('pointermove', event(42));
        const same = ntdll.clears.length;
        els['syscall-map'].fire('pointerleave', {});
        const leave = { clears: ntdll.clears.length, hover: syscallState.hover };
        out({ move, same, leave });
      })();""")
    assert r["move"]["clears"] == 2 and r["move"]["other"] == 0 and r["move"]["otherCalls"], "the old and the new cell, in their own band"
    assert r["move"]["drawn"] < 30, "a few cells, not 600"
    assert r["same"] == 0, "a pointer that stays in its cell paints nothing"
    assert r["leave"] == {"clears": 1, "hover": ""}, "leaving draws the one cell that was ringed"


# --- The stub search: the sample's own syscall stubs --------------------------------

STUB_FUNCTIONS = ["renderSyscallStubs", "syscallNoticesHtml", "syscallBytesOf", "syscallOwnerHtml"]
HIT = ("{ syscall: 'NtWriteVirtualMemory', number: 58, module: 'ntdll.dll', address: 0x7ffa0000, view: 'arm64', pattern: 'SVC; RET',"
       " stub_hex: '010300d4c0035fd6', import_present: null, number_known: true, source: 'process' }")


def _stubs(model):
    return _run_node(STUB_FUNCTIONS, "out(renderSyscallStubs(%s));" % model)


@needs_node
def test_a_hit_names_the_syscall_the_number_where_it_was_found_and_the_pattern():
    html = _stubs("{ hits: [%s, { ...%s, source: 'file', address: undefined, offset: 0x400, syscall: 'NtOpenProcess', number: 38 }] }" % (HIT, HIT))
    rows = html.split("<tr")
    process, file = next(r for r in rows if "NtWriteVirtualMemory" in r), next(r for r in rows if "NtOpenProcess" in r)
    assert "0x3A" in process and "process memory 0x7FFA0000" in process and "SVC; RET" in process
    assert "file offset 0x400" in file and "0x26" in file
    assert 'data-sortable' in html and 'data-sort-id="syscall-stubs"' in html


@needs_node
def test_a_number_this_build_does_not_have_is_its_own_thing():
    html = _stubs("{ hits: [{ ...%s, syscall: null, number: 4000, number_known: false }, %s] }" % (HIT, HIT))
    odd = next(r for r in html.split("<tr") if "0xFA0" in r)
    assert "not in this build" in odd and "another Windows build" in odd
    assert "null" not in odd and "NtWriteVirtualMemory" not in odd
    known = next(r for r in html.split("<tr") if "NtWriteVirtualMemory" in r)
    assert "not in this build" not in known and "in this build" in known


@needs_node
def test_an_unknown_import_table_is_never_read_as_not_imported():
    r = _run_node(STUB_FUNCTIONS, r"""
      const hit = (extra) => ({ syscall: 'NtFoo', number: 1, address: 4096, view: 'x64', pattern: 'p', stub_hex: '4c8bd1b8', number_known: true, source: 'process', ...extra });
      out({ unknown: renderSyscallStubs({ hits: [hit({ import_present: null })] }), missing: renderSyscallStubs({ hits: [hit({})] }),
            yes: renderSyscallStubs({ hits: [hit({ import_present: true })] }), no: renderSyscallStubs({ hits: [hit({ import_present: false })] }) });""")
    for key in ("unknown", "missing"):
        assert "unknown" in r[key] and "not imported" not in r[key].lower() and "never imported" not in r[key].lower(), key
        assert "proves nothing" in r[key], "the table says why a missing import means nothing"
    assert "imported too" in r["yes"] and "not imported" not in r["yes"].lower()
    assert "not imported" in r["no"].lower()


@needs_node
def test_a_process_hit_is_never_said_to_be_imported_or_not_by_the_sample():
    # the final review, I4: in process memory true means some loaded module imports a door, nearly always kernelbase,
    # and false that none does; neither is a word about the sample's own imports, which only its file can give
    r = _run_node(STUB_FUNCTIONS, r"""
      const hit = (extra) => ({ syscall: 'NtFoo', number: 1, address: 4096, offset: 64, view: 'x64', pattern: 'p', stub_hex: '4c8bd1b8', number_known: true, ...extra });
      const cell = html => /<td>(<span[^>]*>[^<]*<\/span>)<\/td><td>(<button|)/.exec(html)[1];
      out({ processYes: cell(renderSyscallStubs({ hits: [hit({ source: 'process', import_present: true })] })),
            processNo: cell(renderSyscallStubs({ hits: [hit({ source: 'process', import_present: false })] })),
            fileYes: cell(renderSyscallStubs({ hits: [hit({ source: 'file', import_present: true })] })),
            fileNo: cell(renderSyscallStubs({ hits: [hit({ source: 'file', import_present: false })] })),
            page: renderSyscallStubs({ hits: [hit({ source: 'process' })] }) });""")
    for key in ("processYes", "processNo"):
        assert "the sample imports" not in r[key].lower() and "sample does not import" not in r[key].lower(), key
        assert "loaded" in r[key] and "module" in r[key], key
    assert "kernelbase" in r["processYes"], "says why that is nearly every process hit"
    assert "no module loaded in the process imports a door" in r["processNo"].lower()
    assert "The sample imports this function as well" in r["fileYes"]
    assert "proven bypass" in r["fileNo"]
    page = " ".join(re.sub(r"<[^>]+>", " ", r["page"]).split())
    assert "stub in the sample's own memory or file whose function the sample does not import" not in page
    assert "kernelbase.dll" in page and "practically never" in page and "comes from the sample file" in page


@needs_node
def test_a_file_hit_its_own_export_names_says_so_and_not_that_it_is_imported():
    # Ruling 73: the rescue fired for this hit, a fact of the hit; "The sample imports this function" would be false
    r = _run_node(STUB_FUNCTIONS, r"""
      const hit = (extra) => ({ syscall: 'NtFoo', number: 1, offset: 64, view: 'arm64', pattern: 'p', stub_hex: '01', number_known: true, source: 'file', import_present: true, ...extra });
      const cell = html => /<td>(<span[^>]*>[^<]*<\/span>)<\/td><td>(<button|)/.exec(html)[1];
      out({ own: cell(renderSyscallStubs({ hits: [hit({ own_export: true })] })),
            imported: cell(renderSyscallStubs({ hits: [hit({ own_export: false })] })) });""")
    assert ">own export<" in r["own"] and "exports this stub under its own name" in r["own"]
    assert "The sample imports this function" not in r["own"]
    assert "The sample imports this function as well" in r["imported"]
    assert 'app.js?v=157"' not in _read(INDEX_HTML), "app.js changed, its version did not"


@needs_node
def test_the_list_says_when_a_stub_is_a_proof_and_when_a_hint():
    html = _stubs("{ hits: [%s] }" % HIT)
    low = html.lower()
    assert "hints, not proof" not in low, "the curated table exists: a stub without the import is a proof"
    assert "proven bypass" in low and "win32 to nt table" in low, "it says what makes a proof"
    assert "stays a hint" in low and "no curated row" in low, "and where a hit remains a hint"
    assert "could not be read" in low and "process memory" in low, "every reason a hit stays a hint"


@needs_node
def test_an_empty_search_is_not_called_clean_when_it_was_partial():
    r = _run_node(STUB_FUNCTIONS, r"""out({ none: renderSyscallStubs({ hits: [], partial: false }), partial: renderSyscallStubs({ hits: [], partial: true }) });""")
    assert "No syscall stub of its own" in r["none"] and "not a clean result" not in r["none"]
    assert "not a clean result" in r["partial"]
    assert r["none"].count("data-sort-skip") == 1


@needs_node
def test_hits_and_notes_are_escaped_and_the_draft_button_names_the_hit_by_number_only():
    html = _stubs(r"""{ hits: [{ syscall: '<img src=x onerror=alert(1)>', number: '<b>', address: '<i>', view: '<u>', pattern: '<s>', stub_hex: '4c8bd1b8',
        number_known: true, source: 'process' }, %s, { ...%s, stub_hex: null }],
        notes: [{ tone: 'warn', text: '<script>x</script>' }], summary: '<em>sum</em>' }""" % (HIT, HIT))
    assert "<img" not in html and "<script" not in html and "<em>" not in html and "<b>" not in html
    handlers = [a["onclick"] for t, a in _Attributes(html).elements if "onclick" in a]
    assert handlers == ["syscallDraftStubRule(1)"], "a hit with no bytes or a number that is no number makes no rule; the others are named by index"


# The tab at work: the search, its two ways in, the draft per hit and the chain to apply
STUBS_FLOW = r"""
const stubHit = (extra = {}) => ({ syscall: 'NtWriteVirtualMemory', number: 58, module: 'ntdll.dll', view: 'arm64', pattern: 'SVC; RET',
    stub_hex: '3a0300d4c0035fd6', import_present: null, number_known: true, ...extra });
const stubsRoute = (url, options) => { const body = JSON.parse(options.body);
    if (body.pid) return { body: { mode: 'process', pid: body.pid, view: 'arm64', build: '26220.5770', partial: false, regions_searched: 3, note: '',
                                   hits: [stubHit({ address: 0x7ffa1000 })], evidence: { label: 'SUSPICIOUS', score: 4 } } };
    return { body: { mode: 'file', path: body.path, view: body.view, build: '26220.5770', imports_read: true, partial: false, note: '',
                     hits: [stubHit({ offset: 0x400, syscall: null, number: 4000, number_known: false })], evidence: { label: 'CLEAN', score: 1 } } }; };
const searchable = async () => { initSyscalls(); syscallsTabShown(); await settle(); routes['/api/syscalls/stubs'] = stubsRoute; chooseTarget(4242); };
"""


@needs_node
def test_the_search_asks_the_process_and_then_its_image_file_in_the_view_the_process_has():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        const before = requests.length;
        await runSyscallStubs();
        out({ posts: requests.slice(before).map(q => [q.url, q.body]), body: els['syscall-stubs-body'].innerHTML,
              hidden: els['syscall-stubs'].hidden, head: els['syscall-stubs-head'].textContent });
      })();""")
    assert r["posts"] == [["/api/syscalls/stubs", {"pid": 4242}],
                          ["/api/syscalls/stubs", {"path": "C:\\Users\\x\\sample.exe", "view": "arm64"}]]
    assert r["hidden"] is False
    assert "process memory 0x7FFA1000" in r["body"] and "file offset 0x400" in r["body"], "both hit lists, each where it was found"
    assert "NtWriteVirtualMemory" in r["body"] and "not in this build" in r["body"]
    assert "PID 4242" in r["head"] and "2 hits" in r["head"]


@needs_node
def test_the_search_that_cannot_find_an_image_or_reach_the_process_says_so_and_still_searches_what_it_can():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        // no image path known: the process alone
        PROCESSES['4242'].image = ''; syscallState.targets = PROCESSES; chooseTarget(4242);
        let before = requests.length;
        await runSyscallStubs();
        const noImage = { posts: requests.slice(before).map(q => q.body), body: els['syscall-stubs-body'].innerHTML };
        // the process is gone: its image is searched in the view of the map
        PROCESSES['4242'].image = 'C:\\Users\\x\\sample.exe'; syscallState.targets = PROCESSES; chooseTarget(4242);
        routes['/api/syscalls/stubs'] = (url, options) => JSON.parse(options.body).pid ? { status: 400, body: { error: 'cannot open process 4242' } } : stubsRoute(url, options);
        before = requests.length;
        await runSyscallStubs();
        const gone = { posts: requests.slice(before).map(q => q.body), body: els['syscall-stubs-body'].innerHTML };
        // the file is refused
        routes['/api/syscalls/stubs'] = (url, options) => JSON.parse(options.body).pid ? stubsRoute(url, options) : { status: 403, body: { error: 'Access denied: path outside allowed directories' } };
        await runSyscallStubs();
        out({ noImage, gone, refused: els['syscall-stubs-body'].innerHTML });
      })();""")
    assert r["noImage"]["posts"] == [{"pid": 4242}] and "No image path" in r["noImage"]["body"] and "process memory" in r["noImage"]["body"]
    assert r["gone"]["posts"][-1] == {"path": "C:\\Users\\x\\sample.exe", "view": "arm64"}
    assert "cannot open process 4242" in r["gone"]["body"] and "file offset 0x400" in r["gone"]["body"]
    assert "Access denied" in r["refused"] and "process memory 0x7FFA1000" in r["refused"]


@needs_node
def test_the_file_is_searched_in_the_view_the_process_has_not_the_one_of_the_map():
    """An emulated x64 process on an arm64 host: the map shows arm64, the process x64. The file is the sample's, so it is x64."""
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        routes['/api/syscalls/stubs'] = (url, options) => { const body = JSON.parse(options.body);
            return body.pid ? { body: { mode: 'process', pid: body.pid, view: 'x64', build: '26220.5770', partial: false, note: '', hits: [] } }
                            : { body: { mode: 'file', path: body.path, view: body.view, build: '26220.5770', partial: false, note: '', hits: [] } }; };
        const mapView = syscallState.baseline.view;
        await runSyscallStubs();
        out({ mapView, posts: requests.filter(q => q.url.includes('/stubs')).map(q => q.body) });
      })();""")
    assert r["mapView"] == "arm64"
    assert r["posts"][1] == {"path": "C:\\Users\\x\\sample.exe", "view": "x64"}


@needs_node
def test_a_process_that_has_exited_is_not_searched_but_its_file_is_and_the_note_says_why():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        // chosen while it ran, gone by the time STUBS is pressed: the PID may be another process by now
        PROCESSES['4242'].exit_time = '2026-11-23T01:00:00Z'; syscallState.targets = PROCESSES;
        await runSyscallStubs();
        out({ posts: requests.filter(q => q.url.includes('/stubs')).map(q => q.body), body: els['syscall-stubs-body'].innerHTML });
      })();""")
    assert r["posts"] == [{"path": "C:\\Users\\x\\sample.exe", "view": "arm64"}], "the PID is not measured: it may belong to another process"
    assert "has exited" in r["body"] and "may belong to another process" in r["body"]
    assert "No image path" not in r["body"], "the path is known"
    assert "file offset 0x400" in r["body"]


@needs_node
def test_a_process_search_that_could_not_prove_says_which_module_it_could_not_account_for():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        const original = stubsRoute;
        routes['/api/syscalls/stubs'] = (url, options) => { const answer = original(url, options);
            if (JSON.parse(options.body).pid) Object.assign(answer.body, { doors_complete: false,
                doors_note: 'C:\\Program Files\\Hook\\engine.dll is a loaded module the binary graph does not hold' });
            return answer; };
        await runSyscallStubs();
        const incomplete = els['syscall-stubs-body'].innerHTML;
        routes['/api/syscalls/stubs'] = (url, options) => { const answer = original(url, options);
            if (JSON.parse(options.body).pid) Object.assign(answer.body, { doors_complete: true, doors_note: '' });
            return answer; };
        await runSyscallStubs();
        out({ incomplete, complete: els['syscall-stubs-body'].innerHTML });
      })();""")
    assert "engine.dll is a loaded module the binary graph does not hold" in r["incomplete"]
    assert "no proof" in r["incomplete"].lower()
    assert "no proof" not in r["complete"].lower()


@needs_node
def test_the_list_does_not_say_process_memory_can_never_prove():
    low = _stubs("{ hits: [%s] }" % HIT).lower()
    assert "always for a stub in process memory" not in low
    assert "binary graph" in low, "it says what a stub in process memory needs to be a proof"


@needs_node
def test_the_search_needs_a_target_and_runs_once_at_a_time():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        initSyscalls(); syscallsTabShown(); await settle();
        routes['/api/syscalls/stubs'] = stubsRoute;
        const none = await runSyscallStubs(); const asked = requests.filter(q => q.url.includes('/stubs')).length;
        const disabled = els['syscall-stubs-run'].disabled;
        chooseTarget(4242);
        const original = globalThis.fetch; let release;
        globalThis.fetch = (url, options) => url.includes('/stubs') ? new Promise(resolve => { release = () => resolve({ ok: true, status: 200, json: async () => stubsRoute(url, options).body }); }) : original(url, options);
        const running = runSyscallStubs(); await settle();
        const during = { off: els['syscall-stubs-run'].disabled, text: els['syscall-stubs-run'].textContent };
        const second = await runSyscallStubs();
        release(); await settle(); release && release(); await running;
        out({ none, asked, disabled, during, second, after: [els['syscall-stubs-run'].disabled, els['syscall-stubs-run'].textContent] });
      })();""")
    assert r["none"] is False and r["asked"] == 0 and r["disabled"] is True
    assert r["during"]["off"] is True and "SEARCHING" in r["during"]["text"] and r["second"] is False
    assert r["after"] == [False, "STUBS"]


@needs_node
def test_draft_rule_on_a_hit_leads_to_the_yara_draft_and_from_there_to_apply():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        await runSyscallStubs();
        const yara = { kind: 'yara', name: 'TDC_DirectSyscall_NtWriteVirtualMemory_arm64_0123abcd', target: 'TDC_DirectSyscall_NtWriteVirtualMemory_arm64_0123abcd.yar',
                       text: 'rule TDC_DirectSyscall_NtWriteVirtualMemory_arm64_0123abcd { condition: true }' };
        routes['/api/syscalls/rule'] = { body: yara };
        routes['/api/syscalls/rule/apply'] = { body: { status: 'written', name: yara.name, path: 'C:\\rules\\x.yar', reload_seconds: 2 } };
        const before = requests.length;
        const unknown = await syscallDraftStubRule(99);
        const drafted = await syscallDraftStubRule(0);
        const draftPosts = requests.slice(before).map(q => [q.url, q.body]);
        const panel = els['syscall-draft'].innerHTML;
        const applied = await applySyscallRule(yara.name);
        out({ unknown, drafted, draftPosts, panel, applied, last: requests[requests.length - 1].url });
      })();""")
    assert r["unknown"] is False and r["drafted"] is True
    assert len(r["draftPosts"]) == 1
    url, body = r["draftPosts"][0]
    assert url == "/api/syscalls/rule" and "deviation" not in body
    assert body["hit"]["syscall"] == "NtWriteVirtualMemory" and body["hit"]["stub_hex"] == "3a0300d4c0035fd6"
    assert body["hit"]["sample"] == "sample.exe" and body["view"] == "arm64" and body["build"] == "26220.5770"
    assert "APPLY TO THIS VM" in r["panel"] and "DOWNLOAD FOR THE REPO" in r["panel"]
    assert r["applied"] is True and r["last"] == "/api/syscalls/rule/apply"


@needs_node
def test_a_hit_of_the_file_is_drafted_with_the_name_of_the_file_as_its_sample():
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable(); await runSyscallStubs();
        routes['/api/syscalls/rule'] = { body: { kind: 'yara', name: 'TDC_DirectSyscall_Number0xFA0_arm64_aaaaaaaa', text: 'x', target: 't' } };
        const before = requests.length;
        await syscallDraftStubRule(1);
        out(requests.slice(before)[0].body);
      })();""")
    assert r["hit"]["number"] == 4000 and r["hit"]["number_known"] is False and r["hit"]["sample"] == "sample.exe"
    assert "source" in r and "file" in r["source"]


@needs_node
def test_the_detail_links_to_wingraph_at_its_root_and_says_so():
    html = _run_node(DETAIL_FUNCTIONS, 'out(renderSyscallDetail({name: "NtFoo", number: 1, module: "ntdll.dll", parameters: []}));')
    links = [a for t, a in _Attributes(html).elements if t == "a"]
    wingraph = next(a for a in links if "wingraph" in a["href"])
    assert wingraph["href"] == "https://wingraph.m0n1x90.dev/", "the site's root: it has no address for one module"
    assert wingraph["target"] == "_blank" and "noopener" in wingraph["rel"] and "noreferrer" in wingraph["rel"]
    assert "root" in wingraph["title"] or "not one module" in wingraph["title"]
    assert any(a["href"].startswith("https://ntdoc.m417z.com/") for a in links), "beside the ntdoc link"
    label = re.search(r'<a[^>]*wingraph[^>]*>(.*?)</a>', html).group(1)
    assert label == "WinGraph"


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
    # The toggle: MAP pressed and on, GRAPH beside it and not pressed (tests/test_binary_graph_ui.py has the rest)
    assert re.search(r'role="group"[^>]*aria-label="Surface"', tab)
    map_button = re.search(r'<button[^>]*id="syscall-view-map"[^>]*>MAP</button>', tab).group(0)
    graph_button = re.search(r'<button[^>]*id="syscall-view-graph"[^>]*>GRAPH</button>', tab).group(0)
    assert 'aria-pressed="true"' in map_button and "disabled" not in map_button
    assert 'aria-pressed="false"' in graph_button
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
    ids |= {"syscall-surface-graph"} | set(re.findall(r"getElementById\('(binary-graph-[\w-]+)'\)", _block()))
    assert {"binary-graph-canvas", "binary-graph-legend", "binary-graph-status"} <= ids
    assert not sorted(ids - page), sorted(ids - page)
    # an inline handler names a function of the block
    handlers = set(re.findall(r'on\w+="(\w+)\(', tab))
    assert handlers and all(re.search(rf"^(async )?function {h}\(", SOURCE, re.M) for h in handlers), handlers
    for name in re.findall(r"onclick=\"[^\"]*\"", tab):
        assert "${" not in name


def test_the_assets_moved_on_and_the_switch_in_the_tab_bar_is_wired():
    html = _read(INDEX_HTML)
    for asset, minimum in (("style.css", 87), ("theme-cyberpunk.css", 37), ("app.js", 126)):
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


def _over(colour, surface, alpha):
    """The colour a translucent `colour` gives over `surface`, as hex."""
    from test_theme import _hex_rgb
    mixed = [round(alpha * c + (1 - alpha) * s) for c, s in zip(_hex_rgb(colour), _hex_rgb(surface))]
    return "#%02x%02x%02x" % tuple(mixed)


def test_an_intact_stub_is_the_quietest_colour_and_every_deviation_is_louder_in_both_themes():
    """The map is quiet until something deviates: against the surface the map sits on, the intact colour has the
    lowest contrast and each deviation has clearly more. What is painted for a state is its colour (for unreadable
    an outline of that colour, for patched, diverged and unreadable also a ring of it at the alpha of the ring)."""
    for name, values in (("Classic", _root_values()), ("Cyberpunk", _cyberpunk_palette())):
        surface = values["--bg-card"]
        contrast = {s: _contrast(values[f"--syscall-{s}"], surface) for s in STATES}
        for state in ("hooked", "patched", "diverged", "unreadable"):
            assert contrast[state] > contrast["intact"] * 1.5, (name, state, contrast)
        assert contrast["intact"] >= 1.3, f"{name}: the baseline tone is too dim to see the grid: {contrast['intact']}"
        # every deviation, unreadable too, beats the surface by a wide margin
        for state in ("hooked", "patched", "diverged", "unreadable"):
            assert contrast[state] >= 4.5, (name, state, contrast[state])
        # and the ring of a state that has one is a visible mark of its own on the surface
        for state in ("patched", "diverged", "unreadable"):
            ring = _contrast(_over(values[f"--syscall-{state}"], surface, 0.35), surface)
            assert ring >= 1.3 and ring > contrast["intact"] * 0.7, (name, state, ring)


def test_each_state_has_its_class_for_the_dots_of_the_legend_and_the_rows():
    classic = _rules(STYLE_CSS)
    for state in STATES + ("baseline",):
        body = classic.get(f".syscall-state-{state}", "")
        assert f"--syscall-{'intact' if state == 'baseline' else state}" in body, state
    assert "transparent" in classic[".syscall-state-unreadable"], "unreadable is hollow, as on the map"
    for state in ("patched", "diverged", "unreadable"):
        assert f"--syscall-{state}-rgb" in classic[f".syscall-state-{state}"], f"{state} has its ring in the dots too"
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


def test_the_detail_the_deviations_and_the_known_hooks_are_in_the_work_area_and_the_panes_switch_when_narrow():
    tab = _tab_markup("syscalls")
    work = tab[tab.index('id="syscall-work"'):]
    for needle in ('id="syscall-detail"', 'id="syscall-detail-body"', 'id="syscall-draft"', 'id="syscall-lower"',
                   'id="syscall-deviations"', 'id="syscall-hooks"', 'id="syscall-stubs"', 'id="syscall-stubs-body"'):
        assert needle in work, needle
    # panels in the manner of the Rizin tab: a section with a head and a title that explains itself (the fifth is the
    # query bar of the GRAPH surface, the sixth the bar of its explore view, the seventh the figures under them)
    assert len(re.findall(r'<h3 class="syscall-panel-title" data-info="[^"<&]{1,300}">', tab)) == 7
    assert "syscallSetPane('map')" in tab and "syscallSetPane('detail')" in tab
    assert re.search(r'<button[^>]*id="syscall-stubs-run"[^>]*onclick="runSyscallStubs\(\)"', tab)
    assert re.search(r'id="syscall-stubs"[^>]*\shidden', tab), "the list of hits is there once a search was run"
    css = _read(STYLE_CSS)
    media = css[css.index("@media (max-width: 1399px)"):]
    assert 'data-pane="detail"] .syscall-main' in media and 'data-pane="map"] .syscall-detail' in media
    assert _declared(_rules(STYLE_CSS)[".syscall-pane-switch"], "display") == "none", "one place on a wide screen: no tabs"
    # apply (this VM, now) and download (the repo, for good) are told apart by their own accents
    rules = _rules(STYLE_CSS)
    assert _declared(rules[".syscall-draft-vm"], "border-left-color") != _declared(rules[".syscall-draft-repo"], "border-left-color")


# The words that give German away, the plain ones a German speaker writes most among them. A word counts in lower case
# or capitalised (not as DiE, a tool's name) and with punctuation after it ("einer Regel."); a name that holds it
# (renderer, a.die) does not.
GERMAN_WORDS = ("der die das ein eine einer einen und oder aber nicht kein keine ist sind wird werden wurde mit ohne von dem den "
                "des wenn dann nur noch auch wir nach bei zum zur für über sich hier nichts gibt zurueck zurück wert liste prozess "
                "regel erzeugen datei sicht befund abweichung übernehmen schreibt muss kann soll dieser diese").split()
GERMAN = re.compile(r"(?<![\w$#.-])(?:%s)(?![\w$#-])" % "|".join(f"{w}|{w.capitalize()}" for w in GERMAN_WORDS))


def test_the_guard_against_german_catches_the_comments_a_german_speaker_writes():
    for line in ("// Das ist der Wert, den wir lesen", "// Gibt die Liste zurueck, wenn nichts da ist", "// Nur die Hooks von dem Prozess",
                 "// Entwurf einer Regel.", "/* Regel erzeugen: der Entwurf */", "// Wert für den Prozess", "<!-- Die Karte, nach dem Scan -->",
                 "// Das Ergebnis ist da; es wird nicht gespeichert", "// Übernehmen schreibt in das Verzeichnis"):
        assert GERMAN.search(line) or re.search("[äöüÄÖÜß]", line), line
    for line in ("// --- Detection Results (cards like DiE) ---", "// the renderer draws it", "const n = state.die.size;",
                 "// Draft rule: the deviation as the scan returned it", "// A syscall is chosen, on the map or in the catalog."):
        assert not GERMAN.search(line), line


def test_the_front_end_has_no_german_in_it():
    """The UI text and every identifier and comment are English. The plan and the spec are German, and this is where
    it leaks: a comment copied from them. Umlauts, and the words that give German away."""
    problems = []
    for path in (APP_JS, INDEX_HTML, STYLE_CSS, THEME_CSS, LAYOUT_CSS):
        for number, line in enumerate(_read(path).splitlines(), 1):
            if re.search("[äöüÄÖÜß]", line) or GERMAN.search(line):
                problems.append(f"{os.path.basename(path)}:{number}: {line.strip()[:100]}")
    assert not problems, "German in the front end:\n" + "\n".join(problems)


def test_every_tone_a_note_can_have_has_its_accent_in_both_themes():
    """A note's tone is ok, info, warn or error: each has a rule for its accent, in tokens that both themes define."""
    rules = _rules(STYLE_CSS)
    classic, cyberpunk = _root_values(), _cyberpunk_palette()
    for tone in ("ok", "info", "warn", "error"):
        body = rules.get(f".syscall-draft-result-{tone}")
        assert body, f"no accent for the tone {tone}"
        token = re.search(r"border-left-color:\s*var\((--[\w-]+)\)", body)
        assert token, tone
        assert token.group(1) in classic and token.group(1) in cyberpunk, (tone, token.group(1))
    tones = set(re.findall(r"tone: '(\w+)'", _block())) - {"ok", "info", "warn", "error"}
    assert not tones, f"a tone with no accent: {tones}"


# --- the syscall stage in the Memory tab of a detonation ---------------------------------------------

STAGE_FUNCTIONS = ["renderSyscallStageBlock", "_detRawButton", "syscallOwnerHtml", "jsArg"]
STAGE_PRELUDE = "const _detRawPayloads = [];\n"


@needs_node
def test_a_detonation_whose_only_memory_tool_is_the_syscall_stage_has_a_memory_tab():
    r = _run_node(["detHasMemoryResults"], """
      out([detHasMemoryResults({syscalls: {tool: 'Syscalls', skipped: 'no baseline'}}),
           detHasMemoryResults({syscalls: {tool: 'Syscalls', counts: {intact: 3}}}),
           detHasMemoryResults({}), detHasMemoryResults({aether: {report: {}}})]);""")
    assert [bool(x) for x in r] == [True, True, False, True]


def test_the_detonation_panels_take_the_memory_tab_from_one_place_and_draw_the_syscall_stage():
    from test_frontend import _function_source
    panels = _function_source("renderDetonationPanels")
    assert "detHasMemoryResults(data)" in panels
    assert "renderSyscallStageBlock(data.syscalls)" in panels


@needs_node
def test_a_stage_that_skipped_itself_says_why_and_that_it_is_no_clean_result():
    html = _run_node(STAGE_FUNCTIONS, """
      out([renderSyscallStageBlock({tool: 'Syscalls', skipped: '<img src=x onerror=alert(1)> no baseline'}),
           renderSyscallStageBlock({tool: 'Syscalls', error: 'broke <b>'})]);""", STAGE_PRELUDE)
    assert "<img" not in html[0] and "&lt;img" in html[0] and "Skipped" in html[0]
    assert "not evidence of being clean" in html[0]
    assert "<b>" not in html[1] and "broke &lt;b&gt;" in html[1]


@needs_node
def test_the_stage_block_has_the_counts_the_partial_note_and_the_deviations_escaped():
    html = _run_node(STAGE_FUNCTIONS, """
      out(renderSyscallStageBlock({tool: 'Syscalls', pid: 4812, build: '26220.5770', view: 'x64',
          counts: {intact: 2400, hooked: 7, patched: 1, diverged: 2, unreadable: 3}, renumbered: 1,
          partial: true, note: '3 stubs unreadable <script>, the result is partial',
          deviations: [
            {name: '<svg onload=alert(1)>', state: 'patched', target_owner: 'private', pattern: 'JMP rel32', relay: []},
            {name: 'NtProtectVirtualMemory', state: 'hooked', target_owner: 'edr<x>.dll', pattern: 'JMP rel32',
             relay: [{address: 140703380275200, owner: 'private', pattern: 'JMP [rip]'}], allowlisted: true},
            {name: 'NtClose', state: 'diverged', target_owner: null, number_matches: false, live_number: 80, number: 15}],
          stubs: {process: {hits: [{}], partial: true, note: 'region query failed'}, file: {hits: [], skipped: 'path unknown'}},
          evidence_findings: []}));""", STAGE_PRELUDE)
    for text in ("2400", "intact", "hooked", "patched", "diverged", "unreadable", "renumbered"):
        assert text in html, text
    assert "Partial" in html and "&lt;script&gt;" in html and "<script" not in html
    assert "<svg" not in html and "&lt;svg" in html
    assert "edr&lt;x&gt;.dll" in html
    assert "relay" in html and "0x7FF80F000000" in html
    assert "allowlist" in html
    assert "another syscall" in html
    assert "region query failed" in html and "path unknown" in html
    assert 'data-sortable data-sort-id="det-syscall-deviations"' in html



@needs_node
def test_a_jump_into_a_mapped_view_is_named_as_one_and_not_as_a_module():
    r = _run_node(DETAIL_FUNCTIONS, r"""
      out({ mapped: syscallOwnerHtml("mapped"), help: SYSCALL_STATE_HELP.patched });""")
    assert "mapped view" in r["mapped"] and "no loaded module" in r["mapped"]
    assert 'class="syscall-owner">mapped<' not in r["mapped"], "not drawn as a module called mapped"
    assert "mapped view" in r["help"]


@needs_node
def test_a_hooked_stub_is_named_by_what_backs_its_target_and_not_called_an_edr_hook():
    r = _run_node([], "out(SYSCALL_STATE_HELP);")
    assert "file-backed module" in r["hooked"]
    assert "EDR hook" not in r["hooked"]


@needs_node
def test_the_detail_names_the_relay_a_hook_went_through():
    html = _run_node(DETAIL_FUNCTIONS, """
      out(renderSyscallDetail({name: "NtFoo", number: 58, module: "ntdll.dll", expected: "4c8bd1b8", actual: "e92b1700",
        state: "hooked", target_owner: "edr.dll", pattern: "JMP rel32", parameters: [],
        relay: [{address: 140703380275200, owner: "private", pattern: "JMP [rip]<b>"}]}));""")
    assert "Relay" in html and "0x7FF80F000000" in html and "JMP [rip]&lt;b&gt;" in html
    assert "<b>" not in html


@needs_node
def test_the_fold_bar_follows_a_stub_run_and_says_when_a_count_is_not_the_whole_story():
    """Found in review. The graph view folds DEVIATIONS, DIRECT SYSCALL STUBS and KNOWN HOOKS away and the bar is
    all the reader has of them, but the bar was written only from syscallSetView and syscallRenderAll - and a stub
    run ends in renderSyscallStubsPanel, a hooks load in renderSyscallHooks, neither of which touched it. So a stub
    run in the graph view finished, wrote the proof of this whole feature into a folded row, and the bar still said
    "DEVIATIONS · KNOWN HOOKS": the one case the fold was justified by.

    A count alone is not the whole story either. A search that could read only one of its two ways in, or one the
    server marked partial, would show as a plain "2 hits". The bar says so, and so does a hooks list that could not
    be read, where an empty head otherwise looks exactly like "nothing to report"."""
    r = _panels(STUBS_FLOW + r"""
      (async () => {
        await searchable();
        syscallSetView('graph');
        const folded = () => els['syscall-lower'].className.includes('syscall-lower-folded');
        const bar = () => els['syscall-lower-note'].textContent;
        const before = { folded: folded(), bar: bar() };
        await runSyscallStubs();
        const after = bar();
        // a search that could read only one of its two ways in
        syscallState.stubs.sources.file = { skipped: 'no image path is known for this process' };
        renderSyscallStubsPanel();
        const incomplete = bar();
        syscallState.stubs.running = true;
        renderSyscallStubsPanel();
        const running = bar();
        syscallState.stubs.running = false;
        syscallState.hooks = { ...syscallState.hooks, loaded: false, error: 'the hook baseline could not be read' };
        renderSyscallHooks();
        out({ before, after, incomplete, running, hooks: bar() });
      })();""")
    assert r["before"]["folded"] is True and "DIRECT SYSCALL STUBS" not in r["before"]["bar"]
    assert "DIRECT SYSCALL STUBS" in r["after"] and "hit" in r["after"], r["after"]
    assert "4242" in r["after"], "and which process it was"
    assert r["incomplete"] != r["after"] and "complete" in r["incomplete"].lower(), r["incomplete"]
    assert "earch" in r["running"], r["running"]
    assert "KNOWN HOOKS" in r["hooks"] and "read" in r["hooks"].lower(), r["hooks"]


# --- a past measurement on the map --------------------------------------------------------------------
# The scan history keeps every syscall scan, the one a detonation makes too. The map can show one of them, but a past
# measurement may never read as a scan of now: a banner says what it is, SCAN and STUBS are off while it is on the
# map, and where its cells cannot be placed on this system's baseline none are drawn.

PAST = r"""
const PAST_DEVS = [{ name: 'Nt7', module: 'ntdll.dll', number: 7, rva: 4096, state: 'patched', pattern: 'B', target_owner: 'private',
                     expected: '010300d4c0035fd6', actual: 'e92b170000000000', number_matches: null }];
// What /api/syscalls/measurement answers: the shape of a scan, with live false and the time it was measured
const pastBody = (extra = {}) => ({ ...scanBody({ Nt7: 'patched' }), deviations: PAST_DEVS,
    states: { ...scanBody().states, Nt7: PAST_DEVS[0] },
    id: 'a1b2c3d4e5f6', measured_at: '2026-11-20T09:15:42.123456', live: false, problem: null, process: 'C:\\samples\\sample.exe', ...extra });
const PAST_LIST = { measurements: [
    { id: 'a1b2c3d4e5f6', at: '2026-11-20T09:15:42.123456', pid: 4242, process: 'sample.exe', build: '26220.5770', view: 'arm64',
      counts: { intact: 599, hooked: 0, patched: 1, diverged: 0, unreadable: 0 }, partial: false },
    { id: 'ffff00001111', at: '2026-11-19T18:01:02', pid: 77, process: '<img src=x>.exe', build: '26220.5770', view: 'x64',
      counts: { intact: 3, hooked: 0, patched: 0, diverged: 0, unreadable: 0 }, partial: true }] };
routes['/api/syscalls/measurements'] = { body: PAST_LIST };
routes['/api/syscalls/measurement'] = { body: pastBody() };
const shown = async () => { initSyscalls(); syscallsTabShown(); await settle(); };
const choosePast = async (id) => { els['syscall-past'].value = id; await syscallOnPast(); await settle(); };
const colours = calls => Object.fromEntries([...new Set(calls.map(c => c.color))].map(k => [k, calls.filter(c => c.color === k).length]));
const ntdll = () => canvases().find(c => c.dataset.module === 'ntdll.dll');
const banner = () => ({ html: els['syscall-past-banner'].innerHTML, hidden: els['syscall-past-banner'].hidden,
                        cls: els['syscall-past-banner'].className });
"""


def _past(script):
    return _panels(PAST + script)


def test_the_past_measurements_have_a_control_of_their_own_after_stubs():
    """One control, one verb: the process list measures, this one looks. It is not a second meaning of the target list."""
    tab = _tab_markup("syscalls")
    group = tab[tab.index('class="syscall-group syscall-target-group"'):tab.index('class="syscall-group syscall-filter-group"')]
    stubs, past = group.find('id="syscall-stubs-run"'), group.find('id="syscall-past"')
    assert 0 < stubs < past, "the past measurements come after STUBS"
    select = re.search(r'<select[^>]*id="syscall-past"[^>]*>(.*?)</select>', group, re.S)
    assert select and 'onchange="syscallOnPast()"' in select.group(0)
    assert re.search(r'<option value="">— a past measurement —</option>', select.group(1))
    target = re.search(r'<select[^>]*id="syscall-target"[^>]*>(.*?)</select>', group, re.S).group(1)
    assert "past" not in target.lower()
    # the banner over the map has its place before the notices
    assert 0 < tab.find('id="syscall-toolbar"') < tab.find('id="syscall-past-banner"') < tab.find('id="syscall-notices"')
    assert re.search(r'id="syscall-past-banner"[^>]*\shidden', tab)


@needs_node
def test_each_past_measurement_is_named_by_process_pid_time_and_view_and_escaped():
    r = _past(r"""
      (async () => { await shown(); out({ html: els['syscall-past'].innerHTML, urls: requests.map(q => q.url) }); })();""")
    assert "/api/syscalls/measurements" in r["urls"], "the list is read with the tab"
    options = re.findall(r'<option value="([^"]*)"[^>]*>([^<]*)</option>', r["html"])
    assert options[0] == ("", "— a past measurement —")
    assert options[1] == ("a1b2c3d4e5f6", "sample.exe · PID 4242 · 2026-11-20 09:15:42 · arm64")
    assert "<img" not in r["html"] and "&lt;img src=x&gt;.exe · PID 77 · 2026-11-19 18:01:02 · x64" in r["html"]


@needs_node
def test_a_past_measurement_draws_its_map_under_a_banner_that_says_it_is_not_a_scan_of_now():
    r = _past(r"""
      (async () => {
        await shown();
        await choosePast('a1b2c3d4e5f6');
        out({ urls: requests.map(q => q.url), cells: colours(ntdll().calls), banner: banner(),
              scan: [els['syscall-scan'].disabled, els['syscall-scan'].title], stubs: [els['syscall-stubs-run'].disabled, els['syscall-stubs-run'].title],
              head: els['syscall-deviations-head'].textContent, list: els['syscall-deviations'].innerHTML,
              legend: els['syscall-legend'].innerHTML, result: [els['syscall-scan-result'].hidden, els['syscall-scan-result'].textContent],
              select: els['syscall-past'].value });
      })();""")
    assert "/api/syscalls/measurement?id=a1b2c3d4e5f6" in r["urls"]
    assert r["cells"]["--syscall-patched"] == 1 and r["cells"]["--syscall-intact"] == 599
    b = r["banner"]
    assert b["hidden"] is False and "syscall-notice-warn" in b["cls"]
    for needle in ("PAST MEASUREMENT", "sample.exe", "PID 4242", "2026-11-20 09:15:42", "build 26220.5770", "arm64", "not a scan of now"):
        assert needle in b["html"], needle
    assert 'onclick="syscallBackToLive()"' in b["html"]
    # SCAN and STUBS are off, and say how to measure now
    for disabled, title in (r["scan"], r["stubs"]):
        assert disabled is True and "back to live" in title.lower(), title
    assert "2026-11-20 09:15:42" in r["head"] and "1 of 600" in r["head"], r["head"]
    assert "syscallSelect(&quot;Nt7&quot;)" in r["list"]
    assert ">599<" in r["legend"]
    # the line a live scan leaves is not left standing beside it
    assert r["result"][0] is True
    assert r["select"] == "a1b2c3d4e5f6"


@needs_node
def test_going_back_to_live_clears_the_past_measurement_and_gives_scan_and_stubs_back():
    r = _past(r"""
      (async () => {
        await shown(); chooseTarget(4242);
        await choosePast('a1b2c3d4e5f6');
        syscallBackToLive(); await settle();
        out({ cells: colours(ntdll().calls), banner: banner(), scan: els['syscall-scan'].disabled, stubs: els['syscall-stubs-run'].disabled,
              head: els['syscall-deviations-head'].textContent, select: els['syscall-past'].value, list: els['syscall-deviations'].innerHTML });
      })();""")
    assert r["cells"] == {"--syscall-intact": 600}, "the map is the baseline again, quiet"
    assert r["banner"]["hidden"] is True
    assert r["scan"] is False and r["stubs"] is False
    assert r["head"] == "" and r["select"] == ""
    assert "Scan a process" in r["list"]


@needs_node
def test_choosing_the_empty_option_goes_back_to_live():
    r = _past(r"""
      (async () => {
        await shown(); await choosePast('a1b2c3d4e5f6');
        await choosePast('');
        out({ banner: banner(), past: syscallState.past, scan: syscallState.scan });
      })();""")
    assert r == {"banner": {"html": r["banner"]["html"], "hidden": True, "cls": r["banner"]["cls"]}, "past": None, "scan": None}


@needs_node
def test_a_measurement_whose_map_cannot_be_drawn_draws_no_cells_and_keeps_its_figures_and_deviations():
    r = _past(r"""
      (async () => {
        await shown();
        routes['/api/syscalls/measurement'] = { body: pastBody({ states: null,
            problem: 'this system has no syscall baseline for build 26100.1, view arm64: the stubs of another build are numbered differently, so its map cannot be drawn here' }) };
        await choosePast('a1b2c3d4e5f6');
        out({ canvases: canvases().length, map: els['syscall-map'].textContent, banner: banner(), legend: els['syscall-legend'].innerHTML,
              list: els['syscall-deviations'].innerHTML, head: els['syscall-deviations-head'].textContent,
              rows: els['syscall-rows'].innerHTML.includes('syscall-state-intact'), scan: els['syscall-scan'].disabled });
      })();""")
    assert r["canvases"] == 0, "no cell is drawn against another baseline"
    assert "no syscall baseline for build 26100.1" in r["map"]
    assert "syscall-notice-error" in r["banner"]["cls"] and "no syscall baseline for build 26100.1" in r["banner"]["html"]
    assert "PAST MEASUREMENT" in r["banner"]["html"] and 'onclick="syscallBackToLive()"' in r["banner"]["html"]
    assert ">599<" in r["legend"] and "not scanned" not in r["legend"], "its figures, and no claim about cells it does not draw"
    assert "syscallSelect(&quot;Nt7&quot;)" in r["list"] and "1 of 600" in r["head"]
    assert r["rows"] is False, "the catalog carries no state of it either"
    assert r["scan"] is True


@needs_node
def test_a_measurement_of_another_build_is_not_drawn_on_this_builds_baseline_even_with_states():
    """The server rebuilds states against the baseline of the measurement's own build, which this system may still
    hold. The map can draw only this build's baseline (/api/syscalls/baseline has no build): other numbers, other cells."""
    r = _past(r"""
      (async () => {
        await shown();
        routes['/api/syscalls/measurement'] = { body: pastBody({ build: '26100.4000' }) };
        await choosePast('a1b2c3d4e5f6');
        out({ canvases: canvases().length, map: els['syscall-map'].textContent, banner: banner(), states: syscallState.states });
      })();""")
    assert r["canvases"] == 0 and r["states"] is None
    assert "26100.4000" in r["map"] and "26220.5770" in r["map"]
    assert "syscall-notice-error" in r["banner"]["cls"] and "26100.4000" in r["banner"]["html"]


@needs_node
def test_a_measurement_of_another_view_is_drawn_on_that_views_baseline():
    r = _past(r"""
      (async () => {
        await shown();
        routes['/api/syscalls/measurement'] = { body: pastBody({ view: 'x64' }) };
        await choosePast('a1b2c3d4e5f6');
        out({ view: syscallState.baseline.view, urls: requests.map(q => q.url).filter(u => u.includes('view=x64')).length,
              cells: colours(ntdll().calls), banner: banner() });
      })();""")
    assert r["view"] == "x64" and r["urls"] >= 1
    assert r["cells"]["--syscall-patched"] == 1
    assert "syscall-notice-warn" in r["banner"]["cls"] and "x64" in r["banner"]["html"]


@needs_node
def test_a_measurement_the_history_does_not_hold_says_so_and_draws_nothing_of_it():
    r = _past(r"""
      (async () => {
        await shown();
        routes['/api/syscalls/measurement'] = { status: 404, body: { error: 'no syscall measurement <b>zz</b> in the scan history' } };
        await choosePast('a1b2c3d4e5f6');
        out({ banner: banner(), cells: colours(ntdll().calls), scan: els['syscall-scan'].disabled });
      })();""")
    assert "syscall-notice-error" in r["banner"]["cls"] and "&lt;b&gt;zz" in r["banner"]["html"] and "<b>" not in r["banner"]["html"]
    assert 'onclick="syscallBackToLive()"' in r["banner"]["html"]
    assert r["cells"] == {"--syscall-intact": 600}
    assert r["scan"] is True, "one measurement at a time holds while the past one is chosen, whatever it answered"


@needs_node
def test_a_late_answer_for_a_past_measurement_left_meanwhile_is_dropped():
    r = _past(r"""
      (async () => {
        await shown();
        let release;
        routes['/api/syscalls/measurement'] = () => ({ body: pastBody() });
        const original = globalThis.fetch;
        globalThis.fetch = (url, options) => url.includes('/measurement?') ? new Promise(resolve => { release = () => resolve({ ok: true, status: 200, json: async () => pastBody() }); })
                                                                            : original(url, options);
        els['syscall-past'].value = 'a1b2c3d4e5f6'; const pending = syscallOnPast(); await settle();
        const loading = banner();
        syscallBackToLive();
        release(); await pending; await settle();
        out({ loading, banner: banner(), cells: colours(ntdll().calls), past: syscallState.past });
      })();""")
    assert r["loading"]["hidden"] is False and "PAST MEASUREMENT" in r["loading"]["html"]
    assert r["banner"]["hidden"] is True and r["past"] is None
    assert r["cells"] == {"--syscall-intact": 600}


@needs_node
def test_nothing_is_measured_while_a_past_measurement_is_on_the_map():
    r = _past(r"""
      (async () => {
        await shown(); chooseTarget(4242);
        routes['/api/syscalls/scan'] = { body: scanBody({ Nt9: 'hooked' }) };
        routes['/api/syscalls/stubs'] = { body: { hits: [] } };
        await choosePast('a1b2c3d4e5f6');
        const before = requests.length;
        await runSyscallScan(); await runSyscallStubs();
        out({ asked: requests.slice(before).map(q => q.url), cells: colours(ntdll().calls) });
      })();""")
    assert r["asked"] == []
    assert r["cells"]["--syscall-patched"] == 1 and "--syscall-hooked" not in r["cells"]


@needs_node
def test_a_past_measurement_replaces_the_live_scan_and_the_stub_search_on_the_page():
    r = _past(r"""
      (async () => {
        await scanned();
        routes['/api/syscalls/stubs'] = { body: { mode: 'process', pid: 4242, view: 'arm64', build: '26220.5770', hits: [], partial: false, note: '' } };
        await runSyscallStubs();
        const stubsBefore = els['syscall-stubs'].hidden;
        await choosePast('a1b2c3d4e5f6');
        out({ stubsBefore, stubs: els['syscall-stubs'].hidden, cells: colours(ntdll().calls), list: els['syscall-deviations'].innerHTML });
      })();""")
    assert r["stubsBefore"] is False and r["stubs"] is True, "no live stub search beside a past measurement"
    assert "--syscall-hooked" not in r["cells"] and r["cells"]["--syscall-patched"] == 1
    assert "Nt9" not in r["list"]


@needs_node
def test_a_past_measurement_is_not_chosen_while_a_measurement_of_now_runs():
    r = _past(r"""
      (async () => {
        await shown(); chooseTarget(4242);
        let release;
        const original = globalThis.fetch;
        globalThis.fetch = (url, options) => url.includes('/api/syscalls/scan') ? new Promise(resolve => { release = () => resolve({ ok: true, status: 200, json: async () => scanBody({ Nt9: 'hooked' }) }); })
                                                                                : original(url, options);
        const scanning = runSyscallScan(); await settle();
        const disabled = els['syscall-past'].disabled;
        const before = requests.length;
        await syscallOpenMeasurement('a1b2c3d4e5f6');
        const asked = requests.length - before;
        release(); await scanning; await settle();
        out({ disabled, asked, past: syscallState.past, cells: colours(ntdll().calls), after: els['syscall-past'].disabled });
      })();""")
    assert r["disabled"] is True and r["after"] is False
    assert r["asked"] == 0 and r["past"] is None
    assert r["cells"]["--syscall-hooked"] == 1


@needs_node
def test_an_intact_stub_of_a_past_measurement_does_not_claim_that_no_bytes_could_be_read():
    r = _past(r"""
      (async () => {
        await shown(); await choosePast('a1b2c3d4e5f6');
        syscallSelect('Nt41'); await settle();
        const intact = els['syscall-detail-body'].innerHTML;
        syscallSelect('NtUser3'); await settle();
        const outside = els['syscall-detail-body'].innerHTML;
        syscallSelect('Nt7'); await settle();
        out({ intact, outside, patched: els['syscall-detail-body'].innerHTML });
      })();""")
    assert "intact" in r["intact"] and "No bytes could be read" not in r["intact"]
    assert "not kept" in r["intact"], "the bytes were read and not kept, which is what it says"
    assert "not part of this past measurement" in r["outside"] and "last scan" not in r["outside"]
    assert "e92b170000000000" in r["patched"], "a deviation keeps its bytes"


@needs_node
def test_the_hooks_of_a_past_measurement_cannot_be_recorded():
    """Recording measures the process again, now: under a past measurement that is a measurement of another time."""
    r = _past(r"""
      (async () => {
        await shown();
        routes['/api/syscalls/measurement'] = { body: pastBody({ deviations: [{ ...PAST_DEVS[0], name: 'Nt9', state: 'hooked', target_owner: 'edr.dll' }],
            states: { ...scanBody().states, Nt9: { ...PAST_DEVS[0], name: 'Nt9', state: 'hooked', target_owner: 'edr.dll' } },
            counts: { intact: 599, hooked: 1, patched: 0, diverged: 0, unreadable: 0 } }) };
        await choosePast('a1b2c3d4e5f6');
        const before = requests.length;
        globalThis.confirm = () => true;
        const done = await syscallCaptureHooks();
        out({ done, asked: requests.length - before, model: syscallHooksModel().scan });
      })();""")
    assert r == {"done": False, "asked": 0, "model": None}


@needs_node
def test_a_past_measurement_put_away_by_a_baseline_of_another_view_says_so():
    r = _past(r"""
      (async () => {
        await shown(); chooseTarget(4242);
        routes['/api/syscalls/measurement'] = { body: pastBody({ view: 'x64' }) };
        await choosePast('a1b2c3d4e5f6');
        await syscallRefresh(true); await settle();
        out({ past: syscallState.past, banner: banner(), note: els['syscall-scan-result'].textContent, scan: els['syscall-scan'].disabled });
      })();""")
    assert r["past"] is None and r["banner"]["hidden"] is True
    assert "past measurement" in r["note"] and "x64" in r["note"]
    assert r["scan"] is False


@needs_node
def test_the_detonation_block_opens_its_measurement_on_the_map_only_when_it_has_one():
    r = _run_node(STAGE_FUNCTIONS, r"""
      const base = { tool: 'Syscalls', pid: 4242, build: '26220.5770', view: 'arm64', counts: { intact: 600 }, deviations: [], stubs: {} };
      out([renderSyscallStageBlock({ ...base, history_id: 'a1b2c3d4e5f6' }), renderSyscallStageBlock(base),
           renderSyscallStageBlock({ ...base, history_id: '' }), renderSyscallStageBlock({ ...base, history_id: 7 }),
           renderSyscallStageBlock({ ...base, history_id: 'x"); alert(1); ("' })]);""", STAGE_PRELUDE)
    button = re.search(r'<button[^>]*onclick="([^"]*syscallOpenMeasurement[^"]*)"[^>]*>([^<]*)</button>', r[0])
    assert button, r[0]
    handler = button.group(1)
    assert handler.index("switchTab('syscalls')") < handler.index("syscallSetView('map')") < handler.index("syscallOpenMeasurement(")
    assert "syscallOpenMeasurement(&quot;a1b2c3d4e5f6&quot;)" in handler
    assert r[0].index("syscallOpenMeasurement") < r[0].index("View Syscalls raw"), "beside the raw button"
    assert all("syscallOpenMeasurement" not in html for html in r[1:4])
    assert 'alert(1); ("\'' not in r[4] and "&quot;x\\&quot;); alert(1)" in r[4]


@needs_node
def test_the_map_opens_a_measurement_the_list_did_not_hold_yet():
    r = _past(r"""
      (async () => {
        await shown();
        routes['/api/syscalls/measurement'] = { body: pastBody({ id: 'newnewnew123', measured_at: '2026-11-25T11:00:00' }) };
        await syscallOpenMeasurement('newnewnew123'); await settle();
        out({ html: els['syscall-past'].innerHTML, value: els['syscall-past'].value, banner: banner() });
      })();""")
    assert 'value="newnewnew123"' in r["html"] and r["value"] == "newnewnew123"
    assert "2026-11-25 11:00:00" in r["banner"]["html"]


def test_app_js_moved_on_with_the_past_measurement():
    html = _read(INDEX_HTML)
    assert 'app.js?v=162"' not in html, "app.js changed, its version did not"


def test_the_banner_of_a_past_measurement_is_a_notice_of_the_warning_tone_and_hides_when_it_is_put_away():
    rules = _rules(STYLE_CSS)
    # .syscall-notice is a flex box, which would show the element over its hidden attribute
    assert _declared(rules[".syscall-past-banner[hidden]"], "display") == "none"
    assert "var(--severity-medium)" in rules[".syscall-past-tag"], "the tag in the warning tone of the tab"
    assert "--severity-medium" in rules[".syscall-notice-warn"] and "--severity-critical" in rules[".syscall-notice-error"]
    from test_theme import _cyberpunk_values
    assert "cp-amber" in _cyberpunk_values()["--severity-medium"], "which is the --cp-amber family in Cyberpunk"
