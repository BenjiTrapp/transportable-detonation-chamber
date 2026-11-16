"""The world map of the FIREWALL tab: the land outline committed as
webui/static/data/world.json, the script that refreshes it, and the SVG that
app.js draws from it (project, worldMapSvg).

Regressions covered:
  * an outline too large to ship, or in another shape than app.js reads
    (floats, odd lengths, degrees out of range)
  * a refresh that keeps the closing point twice, keeps rings too small to
    see, or reads anything but the file it is given
  * a point drawn without a position (lat/lon null) at 0°/0°, or a point
    beyond the cut of the projection drawn outside the map
  * an arc that leaves the map, or two arcs between the same two points
    drawn so exactly on top of each other that one cannot be seen or clicked
  * twenty labels of one country drawn over each other, or a label at the
    edge cut off by it
  * a colour written as a literal or a tone from the data reaching a class,
    which a theme switch cannot change
  * an AS organisation, a label or an id (malware text) reaching the markup
  * a point or an arc that a click cannot tell apart (no data-fw-id)
  * the travelling dash on more than arcs with an open decision, or moving
    under prefers-reduced-motion; the hover fade running there either
  * a destination at or next to the chamber (0° / 12° N, West Africa) that
    loses its arc or hides under the chamber's dot
  * NaN in a coordinate (it kills the whole path) from an infinite radius,
    a weight that is no number, or an arc whose ends are one point
  * a label pill that takes the clicks of the dots and arcs under it
  * a label in a wide script overflowing its pill, or bidi controls in an AS
    name reordering what the analyst reads
"""

import json
import os
import re
import subprocess
import sys

from test_frontend import _function_source, _run_node, needs_node
from test_theme import LITERAL_COLOR, STYLE_CSS, _const_source, _read

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORLD_JSON = os.path.join(ROOT, "webui", "static", "data", "world.json")
BUILD_SCRIPT = os.path.join(ROOT, "scripts", "build-worldmap.py")

MAP_FUNCTIONS = ["project", "worldMapSvg", "_worldXY", "_worldArcPath", "_worldRingPath", "_worldLabelBox",
                 "_worldTone", "_worldText", "_worldTextWidth", "escapeHtml", "_chartCoord", "_chartEllipsis"]
MAP_CONSTS = ["ALERT_SEVERITIES", "WORLD_BOX", "WORLD_CHAMBER_ID"]


def _map_prelude():
    return "\n".join(_const_source(name) for name in MAP_CONSTS)


def _map(script):
    return _run_node(MAP_FUNCTIONS, script, _map_prelude())


def test_world_data_is_small_and_well_formed():
    with open(WORLD_JSON, encoding="utf-8") as f:
        data = json.load(f)
    assert data["scale"] == 10
    assert 20 <= len(data["shapes"]) <= 400
    for ring in data["shapes"]:
        assert len(ring) >= 6 and len(ring) % 2 == 0
        assert all(isinstance(v, int) for v in ring)
        assert all(-1800 <= ring[i] <= 1800 for i in range(0, len(ring), 2))
        assert all(-900 <= ring[i] <= 900 for i in range(1, len(ring), 2))
    assert os.path.getsize(WORLD_JSON) < 300_000


def test_world_data_names_its_source():
    sources = _read(os.path.join(ROOT, "webui", "static", "data", "SOURCES.md"))
    assert "Natural Earth" in sources and "public domain" in sources
    assert "scripts/build-worldmap.py" in sources


def test_build_script_simplifies_rounds_and_drops_small_rings(tmp_path):
    # A square of 10 degrees with a point 0.1 degree off one edge (simplified
    # away), an islet of 0.3 degree per side (perimeter 1.2, dropped) and a
    # multipolygon with a hole (kept, both rings)
    square = [[0, 0], [5, 0.1], [10, 0], [10, 10], [0, 10], [0, 0]]
    islet = [[20, 20], [20.3, 20], [20.3, 20.3], [20, 20.3], [20, 20]]
    outer = [[-30, -30], [-10, -30], [-10, -10], [-30, -10], [-30, -30]]
    hole = [[-25, -25], [-15, -25], [-15, -15], [-25, -25]]
    source = {"type": "FeatureCollection", "features": [
        {"type": "Feature", "properties": {}, "geometry": {"type": "Polygon", "coordinates": [square]}},
        {"type": "Feature", "properties": {}, "geometry": {"type": "Polygon", "coordinates": [islet]}},
        {"type": "Feature", "properties": {},
         "geometry": {"type": "MultiPolygon", "coordinates": [[outer, hole]]}},
    ]}
    src, out = tmp_path / "land.geojson", tmp_path / "world.json"
    src.write_text(json.dumps(source), encoding="utf-8")
    run = subprocess.run([sys.executable, BUILD_SCRIPT, str(src), str(out)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data == {"scale": 10, "shapes": [
        [0, 0, 100, 0, 100, 100, 0, 100],
        [-300, -300, -100, -300, -100, -100, -300, -100],
        [-250, -250, -150, -250, -150, -150],
    ]}


def test_build_script_wants_the_source_path():
    run = subprocess.run([sys.executable, BUILD_SCRIPT], capture_output=True, text=True)
    assert run.returncode != 0
    assert "usage" in (run.stderr + run.stdout).lower()


@needs_node
def test_project_is_equirectangular_and_cut_to_the_box():
    r = _map(r"""
        const b = WORLD_BOX;
        console.log(JSON.stringify({
            corners: [project(-180, 82, b), project(180, -58, b), project(0, 12, b)],
            beyond: [project(10, 89, b), project(10, -80, b), project(200, 0, b)],
            missing: [project(null, 10, b), project(10, null, b), project(undefined, 1, b), project('', 1, b),
                      project(NaN, 1, b), project(1, Infinity, b)],
            otherBox: project(0, 0, { lon0: -10, lon1: 10, lat0: 10, lat1: -10, w: 100, h: 50 }),
            defaultBox: project(-180, 82),
        }));""")
    assert r["corners"] == [[0, 0], [720, 280], [360, 140]]
    assert r["beyond"] == [[380, 0], [380, 280], [720, 164]]
    assert r["missing"] == [None] * 6
    assert r["otherBox"] == [50, 25]
    assert r["defaultBox"] == [0, 0]


def _svg_elements(svg, cls):
    """The opening tags whose class list holds `cls` as a whole word (fw-arc, not fw-arc-line)."""
    return re.findall(r'<[a-z]+ [^>]*class="(?:[^"]* )?%s(?: [^"]*)?"[^>]*>' % re.escape(cls), svg)


@needs_node
def test_world_map_draws_graticule_land_arcs_and_points_in_that_order():
    r = _map(r"""
        const world = { scale: 10, shapes: [[0, 0, 100, 0, 100, 100], [-1800, 820, -1700, 820, -1700, 700]] };
        const points = [{ id: '1.2.3.4', lon: 37.6, lat: 55.7, label: 'RU · AS-EVIL', tone: 'critical', r: 4 }];
        const arcs = [{ from: WORLD_CHAMBER_ID, to: '1.2.3.4', tone: 'critical', weight: 3, pending: false }];
        console.log(JSON.stringify(worldMapSvg(points, arcs, { world })));""")
    svg = r
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert 'viewBox="0 0 720 280"' in svg
    order = [svg.index(m) for m in ('class="fw-grat"', 'class="fw-land"', "fw-arc ", "fw-point ")]
    assert order == sorted(order)
    land = re.search(r'<path class="fw-land"[^>]* d="([^"]+)"', svg).group(1)
    # Tenths of a degree back to degrees, 2 px per degree: 0°/0° is (360, 164), 10°/10° (380, 144)
    assert land.startswith("M360 164L380 164L380 144Z")
    assert "M0 0L20 0L20 24Z" in land
    assert 'fill-rule="evenodd"' in svg
    assert LITERAL_COLOR.search(svg) is None and "style=" not in svg


@needs_node
def test_world_map_chamber_sits_in_the_middle_and_arcs_start_there():
    r = _map(r"""
        const points = [{ id: 'a', lon: 100, lat: 12, label: 'A', tone: 'low' }];
        const arcs = [{ from: WORLD_CHAMBER_ID, to: 'a', tone: 'low', weight: 1 }];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    chamber = re.search(r'<g class="fw-point fw-chamber"[^>]*data-fw-id="([^"]*)"[^>]*>(.*?)</g>', r)
    assert chamber, r
    assert chamber.group(1) == "@chamber"
    assert 'cx="360" cy="140"' in chamber.group(2)
    assert ">CHAMBER</text>" in chamber.group(2)
    arc = re.search(r'<path class="fw-arc-line" d="M([\d.]+) ([\d.]+) Q', r)
    assert arc and arc.group(1, 2) == ("360", "140")


@needs_node
def test_world_map_marks_every_point_and_arc_with_its_id_and_tone():
    r = _map(r"""
        const points = [
            { id: 'p1', lon: 10, lat: 50, label: 'one', tone: 'critical' },
            { id: 'p2', lon: -70, lat: -20, label: 'two', tone: 'medium' },
            { id: 'p3', lon: 140, lat: 35, label: 'three', tone: 'red" onclick="x' },
        ];
        const arcs = [
            { from: WORLD_CHAMBER_ID, to: 'p1', tone: 'critical', weight: 9 },
            { from: WORLD_CHAMBER_ID, to: 'p2', tone: 'medium', weight: 1, id: 'flow-7' },
            { from: WORLD_CHAMBER_ID, to: 'p3', tone: 'bogus', weight: 1 },
        ];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    point_groups = _svg_elements(r, "fw-point")
    arc_groups = _svg_elements(r, "fw-arc")
    assert len(point_groups) == 4 and len(arc_groups) == 3     # the chamber is a point too
    assert all("data-fw-id=" in g for g in point_groups + arc_groups)
    ids = {re.search(r'data-fw-id="([^"]*)"', g).group(1) for g in arc_groups}
    assert ids == {"p1", "flow-7", "p3"}
    assert any("fw-tone-critical" in g and 'data-fw-id="p1"' in g for g in point_groups)
    assert any("fw-tone-medium" in g and 'data-fw-id="p2"' in g for g in point_groups)
    # A tone that is no severity is info, never a class of its own
    assert any("fw-tone-info" in g and 'data-fw-id="p3"' in g for g in point_groups)
    assert "onclick" not in r and "bogus" not in r


@needs_node
def test_world_map_skips_points_without_a_position_and_their_arcs():
    r = _map(r"""
        const points = [
            { id: 'nowhere', lon: null, lat: null, label: 'no geo', tone: 'high' },
            { id: 'half', lon: 10, lat: null, label: 'half', tone: 'high' },
            { id: 'here', lon: 10, lat: 10, label: 'here', tone: 'high' },
        ];
        const arcs = [
            { from: WORLD_CHAMBER_ID, to: 'nowhere', tone: 'high', weight: 1 },
            { from: WORLD_CHAMBER_ID, to: 'half', tone: 'high', weight: 1 },
            { from: WORLD_CHAMBER_ID, to: 'here', tone: 'high', weight: 1 },
            { from: WORLD_CHAMBER_ID, to: 'unknown', tone: 'high', weight: 1 },
        ];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    assert 'data-fw-id="nowhere"' not in r and 'data-fw-id="half"' not in r
    assert 'data-fw-id="unknown"' not in r
    assert len(_svg_elements(r, "fw-arc")) == 1


@needs_node
def test_world_map_escapes_labels_ids_and_titles():
    r = _map(r"""
        const evil = '<script>alert(1)</script>"&\'';
        const points = [{ id: evil, lon: 10, lat: 10, label: evil, title: evil, tone: 'high' }];
        const arcs = [{ from: WORLD_CHAMBER_ID, to: evil, tone: 'high', weight: 1, title: evil }];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    assert "<script" not in r and "alert(1)</" not in r
    assert "&lt;script&gt;" in r and "&quot;" in r and "&#39;" in r


@needs_node
def test_world_map_arcs_stay_inside_the_map_and_bend_up():
    r = _map(r"""
        const corners = [[-180, 82], [180, 82], [-180, -58], [180, -58], [179.9, 0], [0, 81.9], [5, 12.01]];
        const points = corners.map(([lon, lat], i) => ({ id: 'c' + i, lon, lat, label: 'c' + i, tone: 'low' }));
        const arcs = points.map(p => ({ from: WORLD_CHAMBER_ID, to: p.id, tone: 'low', weight: 1 }));
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    curves = re.findall(r'class="fw-arc-line" d="M([-\d.]+) ([-\d.]+) Q([-\d.]+) ([-\d.]+) ([-\d.]+) ([-\d.]+)"', r)
    assert len(curves) == 7
    for x0, y0, cx, cy, x1, y1 in (tuple(map(float, c)) for c in curves):
        # A quadratic Bézier lies within the triangle of its points: control point in the box, arc in the box
        assert 0 <= cx <= 720 and 0 <= cy <= 280
        if abs(x1 - x0) > abs(y1 - y0):
            assert cy <= (y0 + y1) / 2          # a mostly level arc bends up, as a flight route does


@needs_node
def test_world_map_fans_out_arcs_between_the_same_points():
    r = _map(r"""
        const points = [{ id: 'p', lon: 60, lat: 40, label: 'p', tone: 'high' }];
        const arcs = [
            { from: WORLD_CHAMBER_ID, to: 'p', tone: 'high', weight: 1, id: 'f1' },
            { from: WORLD_CHAMBER_ID, to: 'p', tone: 'high', weight: 1, id: 'f2' },
            { from: WORLD_CHAMBER_ID, to: 'p', tone: 'high', weight: 1, id: 'f3' },
        ];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    paths = re.findall(r'class="fw-arc-line" d="([^"]+)"', r)
    assert len(paths) == 3 and len(set(paths)) == 3


@needs_node
def test_world_map_draws_the_thin_arcs_over_the_thick_ones():
    r = _map(r"""
        const points = [{ id: 'a', lon: 60, lat: 40, label: 'a' }, { id: 'b', lon: 61, lat: 40, label: 'b' }];
        const arcs = [
            { from: WORLD_CHAMBER_ID, to: 'a', tone: 'low', weight: 1 },
            { from: WORLD_CHAMBER_ID, to: 'b', tone: 'low', weight: 100 },
        ];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    ids = re.findall(r'<g class="fw-arc [^"]*" data-fw-id="([^"]*)"', r)
    assert ids == ["b", "a"]
    widths = [float(w) for w in re.findall(r'class="fw-arc-line"[^>]* stroke-width="([\d.]+)"', r)]
    assert widths[0] > widths[1] >= 1


@needs_node
def test_world_map_labels_do_not_cover_each_other():
    r = _map(r"""
        // Twenty destinations of one country, within the 2 degrees of their jitter
        const points = Array.from({ length: 20 }, (_, i) => ({
            id: 'ip' + i, lon: 8 + (i % 5) * 0.4, lat: 50 + Math.floor(i / 5) * 0.4,
            label: 'DE · AS' + i, tone: i === 13 ? 'critical' : 'low' }));
        console.log(JSON.stringify(worldMapSvg(points, [], {})));""")
    pills = [tuple(map(float, m)) for m in
             re.findall(r'<rect class="fw-pill" x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)"', r)]
    assert 2 <= len(pills) < 21
    for i, (ax, ay, aw, ah) in enumerate(pills):
        for bx, by, bw, bh in pills[i + 1:]:
            assert ax + aw <= bx or bx + bw <= ax or ay + ah <= by or by + bh <= ay
    # The most severe keeps its label; every point keeps its name in its tooltip
    assert ">DE · AS13</text>" in r
    assert r.count("<title>DE · AS") == 20


@needs_node
def test_world_map_labels_at_the_edge_stay_inside():
    r = _map(r"""
        const points = [
            { id: 'e', lon: 179, lat: 0, label: 'FJ · A long organisation name', tone: 'low' },
            { id: 'n', lon: 0, lat: 82, label: 'North', tone: 'low' },
            { id: 's', lon: -179, lat: -58, label: 'South', tone: 'low' },
        ];
        console.log(JSON.stringify(worldMapSvg(points, [], {})));""")
    pills = [tuple(map(float, m)) for m in
             re.findall(r'<rect class="fw-pill" x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)"', r)]
    assert len(pills) == 4
    for x, y, w, h in pills:
        assert 0 <= x and x + w <= 720 and 0 <= y and y + h <= 280


@needs_node
def test_world_map_animates_only_pending_arcs():
    r = _map(r"""
        const points = [{ id: 'a', lon: 60, lat: 40, label: 'a' }, { id: 'b', lon: -60, lat: 40, label: 'b' }];
        const arcs = [
            { from: WORLD_CHAMBER_ID, to: 'a', tone: 'high', weight: 1, pending: true },
            { from: WORLD_CHAMBER_ID, to: 'b', tone: 'high', weight: 1, pending: 'yes' },
        ];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    # Only `pending: true`: a truthy string from elsewhere does not set the dash going
    pending = {re.search(r'data-fw-id="([^"]*)"', g).group(1): "fw-arc-pending" in g
               for g in _svg_elements(r, "fw-arc")}
    assert pending == {"a": True, "b": False}


def _css_rules(css, selector_part):
    return [m.group(0) for m in re.finditer(r"[^{}]*%s[^{}]*\{[^}]*\}" % re.escape(selector_part), css)]


def test_map_css_moves_only_pending_arcs_and_stops_under_reduced_motion():
    css = re.sub(r"/\*.*?\*/", "", _read(STYLE_CSS), flags=re.S)
    animated = [rule for rule in re.findall(r"[^{}]*\{[^{}]*\banimation\s*:[^}]*\}", css)
                if ".fw-" in rule.split("{")[0]]
    assert animated, "no animation for .fw-arc-pending"
    moving = [rule for rule in animated if not re.search(r"animation\s*:\s*none", rule)]
    assert moving and all(".fw-arc-pending" in rule.split("{")[0] for rule in moving)
    reduced = [m.end() for m in re.finditer(r"@media \(prefers-reduced-motion: reduce\)\s*\{", css)]
    stilled = False
    for start in reduced:
        depth, i = 1, start
        while depth:
            depth += {"{": 1, "}": -1}.get(css[i], 0)
            i += 1
        block = css[start:i]
        stilled |= bool(re.search(r"\.fw-arc-pending[^{]*\{[^}]*animation\s*:\s*none", block))
    assert stilled


def test_map_tones_are_theme_variables():
    css = re.sub(r"/\*.*?\*/", "", _read(STYLE_CSS), flags=re.S)
    root = css[css.index(":root {"):css.index("}", css.index(":root {"))]
    for tone in ("critical", "high", "medium", "low", "info"):
        rules = _css_rules(css, ".fw-tone-%s" % tone)
        # directly, or through the FIREWALL tab's token for that severity
        token = re.search(r"--fw-tone-%s:\s*var\(--severity-%s\)" % (tone, tone), root)
        assert rules and any("var(--severity-%s)" % tone in rule or (token and "var(--fw-tone-%s)" % tone in rule)
                             for rule in rules), tone


def test_map_functions_hold_no_colour_literal():
    for name in ("project", "worldMapSvg", "_worldXY", "_worldArcPath", "_worldRingPath", "_worldLabelBox",
                 "_worldTone", "_worldText", "_worldTextWidth"):
        assert LITERAL_COLOR.search(_function_source(name)) is None, name


@needs_node
def test_world_map_destination_at_the_chamber_keeps_a_visible_target_above_it():
    r = _map(r"""
        const points = [
            { id: 'on', lon: 0, lat: 12, label: 'GH · on the chamber', tone: 'high' },
            { id: 'near', lon: 1, lat: 12.5, label: 'BF · beside it', tone: 'low' },
        ];
        const arcs = [
            { from: WORLD_CHAMBER_ID, to: 'on', tone: 'high', weight: 2 },
            { from: WORLD_CHAMBER_ID, to: 'on', tone: 'high', weight: 1, id: 'on-2' },
            { from: WORLD_CHAMBER_ID, to: 'near', tone: 'low', weight: 1, pending: true },
        ];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    assert "NaN" not in r
    arcs = {re.search(r'data-fw-id="([^"]*)"', g).group(1): g for g in _svg_elements(r, "fw-arc")}
    assert set(arcs) == {"on", "on-2", "near"}
    rings = dict(re.findall(r'<g class="fw-arc [^"]*" data-fw-id="([^"]*)">.*?<path class="fw-arc-hit" d="([^"]+)"', r))
    assert all(" A" in d for d in rings.values())          # a ring, not a zero-length line
    assert rings["on"] != rings["on-2"]                     # and two of them do not cover each other
    assert "fw-arc-pending" in arcs["near"]
    # The destinations' dots come after (over) the chamber's
    chamber = r.index('data-fw-id="@chamber"')
    assert chamber < r.index('<g class="fw-point fw-tone-high" data-fw-id="on"')
    assert chamber < r.index('<g class="fw-point fw-tone-low" data-fw-id="near"')


@needs_node
def test_world_map_survives_empty_and_broken_numbers():
    r = _map(r"""
        console.log(JSON.stringify([
            worldMapSvg([], [], {}),
            worldMapSvg(null, undefined),
            worldMapSvg(
                [{ id: 'a', lon: 20, lat: 20, label: 'a', r: Infinity }, { id: 'b', lon: 'x', lat: 1, r: NaN },
                 { id: 'c', lon: -40, lat: Infinity }, { id: 'd', lon: -40, lat: 10, r: -Infinity }],
                [{ from: 'a', to: 'a', weight: NaN }, { from: WORLD_CHAMBER_ID, to: 'a', weight: Infinity },
                 { from: WORLD_CHAMBER_ID, to: 'd', weight: NaN }, { from: 'd', to: 'a', weight: -3 }],
                { world: { scale: 10, shapes: [[0, 0, NaN, 1, 2, 3], [0, 0, 100, 0, 100, 100], 'junk', [1, 2]] } }),
        ]));""")
    for svg in r:
        assert "NaN" not in svg and "Infinity" not in svg
        assert re.fullmatch(r"<svg [^>]*>.*</svg>", svg, re.S)
        assert svg.count("<g ") == svg.count("</g>")
        assert 'data-fw-id="@chamber"' in svg
    assert "M360 164L380 164L380 144Z" in r[2] and r[2].count('class="fw-land"') == 1


@needs_node
def test_world_map_labels_lose_bidi_controls_and_wide_scripts_get_room():
    r = _map(r"""
        const spoof = 'evil\u202Egpj.exe\u2066x\u2069\u200F';
        const points = [
            { id: 'b', lon: -100, lat: 40, label: spoof, title: spoof, tone: 'high' },
            { id: 'cjk', lon: 100, lat: 30, label: '中国电信', tone: 'low' },
            { id: 'lat', lon: 100, lat: -30, label: 'abcd', tone: 'low' },
        ];
        const arcs = [{ from: WORLD_CHAMBER_ID, to: 'b', tone: 'high', weight: 1, title: spoof }];
        console.log(JSON.stringify(worldMapSvg(points, arcs, {})));""")
    assert not re.search("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]", r)
    assert ">evilgpj.exex</text>" in r
    widths = dict(re.findall(r'data-fw-id="(cjk|lat)">.*?<rect class="fw-pill"[^>]* width="([\d.]+)"', r))
    assert float(widths["cjk"]) >= 4 * 9 + 8 > float(widths["lat"])


def test_map_labels_take_no_clicks_and_nothing_fades_under_reduced_motion():
    css = re.sub(r"/\*.*?\*/", "", _read(STYLE_CSS), flags=re.S)
    assert any(".fw-pill" in rule.split("{")[0] and ".fw-label" in rule.split("{")[0]
               and re.search(r"pointer-events\s*:\s*none", rule) for rule in _css_rules(css, ".fw-pill"))
    blocks = re.findall(r"@media \(prefers-reduced-motion: reduce\)\s*\{((?:[^{}]*\{[^}]*\})*)\s*\}", css)
    assert any(re.search(r"\.fw-arc-line[^{]*\{[^}]*transition\s*:\s*none", b) for b in blocks)
