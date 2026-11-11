"""Charts (webui/static/js/app.js, block CHARTS): counting and time bins, and
the SVG building blocks of the charts of the Dashboard, the Alerts tab,
Sysmon, ThreatScan, Submit, the graph detail and the detonation results.

Regressions covered:
  * a category written in capitals or as a list counted apart from the same
    category written as text ("Registry", ["registry"], "registry")
  * ties of a ranking in another order on every render
  * time bins that start at a UTC instead of a local midnight or full hour,
    drift by an hour after a change to or from daylight saving time, leave
    out the empty periods between items, count items outside the chosen range
    or items without a time
  * a sample that sets the clock of the VM to the year 9999 freezing the page
    with millions of bins, or alerts lost when the bins are capped
  * a share of 100 % that draws nothing (an arc from a point back to itself),
    a chart of zeros drawn as a broken graphic, a tiny share that vanishes,
    a legend in other colours than its donut
  * bars whose parts do not add up to their bin or are stacked in another
    order, midnight labelled 24:00, a selection beside the bins it selects
  * a rule, process, file or category name (data from the sample) reaching a
    chart, a tooltip, a legend or a data-* attribute as markup
  * a colour written as a literal, or a colour of the caller that is no theme
    variable, which a theme switch cannot change
  * Sankey bands that do not add up to their nodes, nodes that overlap or
    leave the chart, a tiny flow that vanishes, links that skip a column or
    point nowhere drawn anyway
  * an engine, rule or process counted apart by its case while the Alerts
    filter matches any case; an "other rules" that stands for a single rule
  * a process named like a rule, an engine or "other processes" merged with
    it into one node (a node in two columns breaks the layout)
  * a band whose ends a click cannot tell apart again
  * an Alerts filter a chart sets (time range, category, rule, process) that
    lists other alerts than the chart counted: a range that takes its end or
    an alert without a time, a category or a name compared in its case, a
    name matched as a part of another, alerts without a process unreachable
  * such a filter that is not shown, cannot be taken off, takes the others
    with it, or shows a rule or process name as markup
  * the Alerts list scrolling under a filter bar that scrolls away, or rows
    seen through the bar
  * a chart of the Alerts tab that counts other alerts than the table: the
    2000 rows it shows instead of all it lists, an alert without a time lost
    between the bars and the slices, a rule written with blanks or in other
    capitals a node of its own, a name without a filter of its own
  * a click on a chart that sets no filter, one the filter bar does not show,
    or a filter on "other rules"; a slice for the wrong severity or engine
  * a slice or legend row of SEVERITY that switched its severity off (the
    others left pressed, or none) instead of showing it alone
  * a chart card without its (i), its CHART / TABLE switch or a table with
    the same numbers; LINEAR forgotten on the next refresh
  * bars and a Sankey drawn for a card width they no longer have
  * one alert with a time no clock can have had (1970, 1601, 9999) squeezing
    every other bar into one, or lost between the slices and the bars
  * Sigma's "informational" outside the severity info (grey, no chip)
  * a sorted column of OVER TIME moving when its "Other" column comes and goes
  * OVER TIME of a range narrowed to a few hours in a bar or two of an hour,
    or ALERT ACTIVITY in bars of minutes; bars of minutes that leave a gap or
    change their length in the night the clocks go back
  * the chip of a range of bars of seconds named without its seconds, so
    ranges a few seconds apart go by the same name
  * a drilldown step that BACK does not take back exactly (other counts or
    rows than before it), a click that changes nothing (the same slice, an
    engine in other capitals) taken as a step, a step that holds filters it
    did not change or names them otherwise than the charts and chips do
  * BACK or a jump in the path undoing a setting of one's own (the search,
    a severity chip, the engine choice, the × of a chip), or a path that
    still names a step such a setting replaced; a path drawn before the
    steps forgot what was set by hand
  * a jump from the dashboard that adds to the old path instead of starting
    a new one, that is no step when it changes nothing, whose BACK leaves the
    tab or brings back what the jump cleared
  * a range drawn across OVER TIME that is no step, a step of other bars
    than those marked, or two (its click as well); a press that did not move
    setting nothing when Chrome sends its click to the <svg>; a range of bars
    without alerts emptying every card
  * new alerts drawing OVER TIME again while a range is drawn across it (the
    mark lost), or not once the press is over; a range drawn across the
    dashboard's bars taken as a step of the Alerts tab
  * a bar a range cuts off the full minute named without its seconds, unlike
    the chip of its period; OVER TIME without the hint how to use its bars,
    or with one where it shows none; a half of the hint running into the
    next card
  * a press on bars of OVER TIME held back for new alerts (they came during
    the press before it) that marks or narrows by bars not on screen
  * a drilldown bar shown without a step or hidden with one; a path drawn
    again only when the filters changed (the same jump twice kept the old
    path), that names a step no longer in effect or a name from the data as
    markup; new alerts taking a step in focus off it, the focus lost with the
    bar or with a step drawn anew
  * the first row of the list under the drilldown bar or the filter bar
    after a filter change, the filter bar or the table head over the
    drilldown bar, the drilldown bar shrunk into the tab
  * the underline of a step of the path cut off by the step's own box (it
    cuts a long name); the current step cut at the path's edge without an
    ellipsis, or losing a letter while a step before it could still give way
  * a click of the mouse that takes the drilldown bar away lighting up the
    search box (on a touch screen: opening the keyboard); the bar taking the
    focus off a control outside it as it goes
  * a screen reader reading the ‹ of BACK, BACK without a word of where it
    goes (or of a step no longer there), the folded steps of "…" named only
    in its tooltip, which screen readers do not read; that text shown in the
    bar
  * an engine given with blanks around it a choice of its own that lists
    nothing; BACK of a step of an engine and a rule leaving one of them set
  * the dashboard counting all alerts again on every poll, for a list or a
    range that did not change, or while it is hidden; a preset that stays at
    the time it was chosen while the clock runs on
  * a range of the dashboard (24H, 7D, 30D, ALL, a range drawn across the
    bars) that the bars, the donuts and the Alerts tab after a click count
    differently; a click on a bar, a segment or "other categories" that opens
    other alerts than it counted, or a drag across the bars that also clicks
  * sparklines of other days than the last 45 local ones; PROCESSES TRACKED
    still counting the stopped processes "Clear stopped" took out of the list
  * a drag across the bars that goes on drawing after its button went up
    elsewhere (macOS opens the context menu on Ctrl+click)
  * two charts of bars that take a range drawn across them reaching into
    each other: a drag on one setting the range of the other, marking its
    bars or holding them still; the click of a press on one standing for a
    bar of the other; a chart not told that a press on it is over; the page
    listening twice for each press
  * a Sysmon capture of minutes in a single hourly bar; bins of seconds or
    minutes that begin at UTC instead of local multiples of their step
  * Sysmon charts that count other events than the table lists, or the
    table's time window as well (the bars no longer show where to click
    next); a time window, image or event type a click sets that the filter
    bar does not show or cannot take off; a window kept for events that no
    longer reach it; "other images" as a filter
  * an event type in another colour after a refresh; image names from the
    sample as markup in the charts, their chips or their tables
  * a Sysmon that is not running, a failed query or no events drawn as empty
    charts instead of saying so
  * PipeConnected in nearly the amber of ProcessAccess; an event type of no
    colour of its own given a lighter or darker step of a known type's hue;
    ProcessTerminate in a darker step of CreateRemoteThread's red
  * a Sysmon events table wider than the tab cut off at its edge
  * a scan without a score drawn on the axis instead of in its lane, the
    scans in another order than they ran, a verdict in other capitals in
    another colour
  * EMBER2024's probability (or another tool's score) drawn on the axis of
    the evidence score, or sorted among the evidence scores
  * one score far above the others pressing them under the threshold lines
  * a point of SCORE HISTORY that leads to another entry of the list than its
    scan's, or to none after a new scan; that leaves its entry closed
  * a file name from the sample as markup in SCORE HISTORY, its tooltips or
    its table
  * the list calling a suspicious memory scan DETECTED in red while the chart
    shows it amber
  * the points drawn for the width of the plot before the legend took its
    room beside it
  * a submission's bar in another order than they were submitted, not as high
    as its verdict's score, in another colour than its verdict, or missing
    (a score of 0, a verdict without a score, one not evaluated); threshold
    lines of another scale than the verdict's (the memory evidence's 2 and 6)
  * a bar that opens other results than its submission's Results button
  * a file name from the sample as markup in VERDICT HISTORY, its tooltips or
    its table
  * a verdict computed in a results view that the open history goes on
    showing as "not evaluated", or a history loaded again on every poll;
    loaded again for a verdict the server keeps on none of the sample's runs,
    or on every poll for one it could not keep (a file it cannot write)
  * ACTIVITY MIX of a process counting the Sysmon activity of another
    process that had the same PID, or its alerts as a part of the ring
    (counted twice: the Activity grid counts alerts); a broken ring for a
    process without Sysmon activity
  * a VERDICT FLOW whose kinds show other numbers than the results view:
    the EDR alerts beyond the 50 the server lists lost, an exit-capture,
    network or pipe finding counted a second time as live memory; a verdict
    the LitterBox score alone made shown as "No findings"
  * findings the verdict did not count (suppressed by the host baseline,
    capped as a repeat of their kind, an evidence below SUSPICIOUS) drawn as
    counted, or the other way round
  * the two results views (Submit tab, detail panel) open at once sharing
    element ids, a sort order, LINEAR or the TABLE view; a process name from
    the sample as markup in the flow, its tooltips or its table
  * the Submit tab's spinner turning on after polling had ended without an
    answer, under a note that pointed at results above
  * the table of FLOW in the Alerts tab cutting its targets (rules,
    processes) to a few letters
"""

import json
import math
import re
from html.parser import HTMLParser

import pytest

from conftest import make_alert
from test_frontend import _function_source, _run_node, needs_node
from test_theme import (ALERTS_CHART_FUNCTIONS, ALERTS_TAB_FUNCTIONS, APP_JS, BARS_BRUSH_FUNCTIONS, CHART_CONSTS,
                        CHART_FUNCTIONS, DASHBOARD_CHART_CONSTS, DASHBOARD_CHART_FUNCTIONS, INDEX_HTML,
                        LITERAL_COLOR, NEWEST_ALERTS_FUNCTIONS, SORT_DOM, STYLE_CSS, SYSMON_TAB_FUNCTIONS, THEME_CSS,
                        _alerts_prelude, _const_source, _cyberpunk_palette, _element_markup, _Elements, _hex_rgb,
                        _read, _resolve, _root_values, _rules, _strip_js_comments, _sysmon_prelude, _tab_markup)

CHART_JS = CHART_FUNCTIONS + ["escapeHtml", "alertRuleName", "alertProcessName", "_alertsNameKey"]

# The zone of the run (CI sets TZ to UTC and to Europe/Berlin) and zones set in
# the test: daylight saving time in Europe and in the US, and an offset of half
# an hour, where a local full hour is no UTC full hour.
ZONES = [None, "UTC", "Europe/Berlin", "America/New_York", "Asia/Kolkata"]


def _prelude(zone=None):
    zone_js = "" if zone is None else "process.env.TZ = %s;\n" % json.dumps(zone)
    return zone_js + "\n".join(_const_source(name) for name in CHART_CONSTS)


class _Tree(HTMLParser):
    """The elements of a piece of markup: tag, attributes (decoded, in their
    order), the text directly inside, children."""

    def __init__(self, markup):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "#root", "attrs": {}, "names": [], "text": "", "children": []}
        self.all = []
        self._open = [self.root]
        self.feed(markup)
        self.close()

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "names": [k for k, _ in attrs], "text": "", "children": []}
        self._open[-1]["children"].append(node)
        self.all.append(node)
        self._open.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self._open.pop()

    def handle_endtag(self, tag):
        for i in range(len(self._open) - 1, 0, -1):
            if self._open[i]["tag"] == tag:
                del self._open[i:]
                return

    def handle_data(self, data):
        self._open[-1]["text"] += data

    def find(self, tag=None, cls=None, attr=None):
        return [n for n in self.all if (tag is None or n["tag"] == tag)
                and (cls is None or cls in n["attrs"].get("class", "").split())
                and (attr is None or attr in n["attrs"])]


def _child(node, tag):
    return next((c for c in node["children"] if c["tag"] == tag), None)


def _num(node, name):
    return float(node["attrs"][name])


def _style(node):
    """The declarations of an element's style attribute as a dict."""
    pairs = (decl.split(":", 1) for decl in node["attrs"].get("style", "").split(";") if ":" in decl)
    return {k.strip(): v.strip() for k, v in pairs}


def _numbers(path):
    return [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", path)]


def _close(a, b, tolerance=0.05):
    return all(abs(x - y) <= tolerance for x, y in zip(a, b)) and len(a) == len(b)


# --- Counting -------------------------------------------------------------------

@needs_node
def test_alert_category_and_count_by():
    r = _run_node(["alertCategory", "countBy"], r"""
        console.log(JSON.stringify({
            categories: [{ category: ['Registry'] }, { category: 'process' }, {}, { category: [] }, { category: '' },
                         { category: ['Network', 'dns'] }, { category: ' File ' }, null].map(alertCategory),
            counts: countBy(['c', 'b', 'a', 'b'], x => x),
            categories2: countBy([{ category: 'Registry' }, { category: ['registry'] }, { category: 'process' }, {}],
                                 alertCategory),
            // keys from the data: no key is special
            hostile: countBy(['__proto__', 'constructor', '__proto__'], x => x),
            empty: [countBy([], x => x), countBy(undefined, x => x)],
        }));""")
    assert r["categories"] == ["registry", "process", "other", "other", "other", "network", "file", "other"]
    assert r["counts"] == [{"key": "b", "count": 2}, {"key": "a", "count": 1}, {"key": "c", "count": 1}], \
        "not by count, or ties not by key"
    assert r["categories2"] == [{"key": "registry", "count": 2}, {"key": "other", "count": 1},
                                {"key": "process", "count": 1}], "a list and a text of the same category counted apart"
    assert r["hostile"] == [{"key": "__proto__", "count": 2}, {"key": "constructor", "count": 1}]
    assert r["empty"] == [[], []]


# --- Time bins ------------------------------------------------------------------

BINS_LOOK = r"""
    const at = (...a) => new Date(...a).getTime();          // local time of the zone
    const time = x => x.t;
    const fields = t => { const d = new Date(t); return [d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getDay()]; };
    const look = ({ unit, bins }) => ({
        unit, totals: bins.map(b => b.total), counts: bins.map(b => b.counts), starts: bins.map(b => fields(b.start)),
        end: bins.length ? fields(bins[bins.length - 1].end) : null,
        lengths: bins.map(b => b.end - b.start),
        gapless: bins.every((b, i) => b.end > b.start && (i === 0 || b.start === bins[i - 1].end)),
    });
"""


@needs_node
@pytest.mark.parametrize("zone", ZONES)
def test_bin_by_time_units_and_local_midnight(zone):
    r = _run_node(CHART_JS, BINS_LOOK + r"""
        const DAY = 86400000, t0 = at(2026, 6, 1);
        console.log(JSON.stringify({
            hour: look(binByTime([{ t: at(2026, 6, 14, 10, 5) }, { t: at(2026, 6, 14, 10, 55) }, { t: NaN }, {},
                                  { t: at(2026, 6, 14, 13, 20) }], { time })),
            // 20 Oct - 3 Nov: Europe leaves daylight saving time on 25 Oct, the US on 1 Nov
            day: look(binByTime([{ t: at(2026, 9, 20, 9), k: 'high' }, { t: at(2026, 9, 25, 2, 30), k: 'low' },
                                 { t: at(2026, 9, 25, 12), k: 'high' }, { t: at(2026, 10, 3, 18), k: 'weird' }],
                                { time, key: x => x.k, keys: ['high', 'low'] })),
            // 2 Mar (a Monday) - 30 Sep: the US starts daylight saving time on 8 Mar, Europe on 29 Mar
            week: look(binByTime([{ t: at(2026, 2, 2, 8) }, { t: at(2026, 2, 29, 3, 30) }, { t: at(2026, 5, 15, 12) },
                                  { t: at(2026, 8, 30, 20) }], { time })),
            // The night Europe turns the clocks back: 02:00 - 03:00 comes twice
            night: look(binByTime([{ t: at(2026, 9, 25, 0, 30) }, { t: at(2026, 9, 25, 5, 30) }], { time })),
            // ... and an item in the second 02:00 - 03:00 of that night (01:30 UTC) as the earliest
            repeated: look(binByTime([{ t: Date.UTC(2026, 9, 25, 1, 30) }, { t: Date.UTC(2026, 9, 25, 3) }], { time })),
            units: [2 * DAY, 2 * DAY + 3600000, 120 * DAY, 121 * DAY].map(span => binByTime([], { from: t0, to: t0 + span }).unit),
            // Without `time`: the item's timestamp
            byTimestamp: binByTime([{ timestamp: '2026-07-14T10:00:00Z' }, { timestamp: 'not a time' }, {}]).bins.map(b => b.total),
            none: binByTime([], {}).bins,
        }));
    """, _prelude(zone))
    hour = r["hour"]
    assert hour["unit"] == "hour" and hour["gapless"]
    assert [s[:4] for s in hour["starts"]] == [[7, 14, 10, 0], [7, 14, 11, 0], [7, 14, 12, 0], [7, 14, 13, 0]], \
        "the bins do not start at the local full hours, or an hour between is missing"
    assert hour["end"][:4] == [7, 14, 14, 0]
    assert hour["totals"] == [2, 0, 0, 1], "an item without a time was counted"

    day = r["day"]
    assert day["unit"] == "day" and day["gapless"]
    assert [s[:2] for s in day["starts"]] == [[10, d] for d in range(20, 32)] + [[11, d] for d in range(1, 4)], \
        "a day is missing"
    assert all(s[2:4] == [0, 0] for s in day["starts"]), "a bin does not start at local midnight: " + str(day["starts"])
    assert day["end"][:4] == [11, 4, 0, 0]
    assert day["totals"] == [1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1] and sum(day["totals"]) == 4
    assert day["counts"][1] == {"high": 0, "low": 0}, "the keys asked for are not in every bin"
    assert day["counts"][5] == {"high": 1, "low": 1}
    assert day["counts"][14] == {"high": 0, "low": 0, "weird": 1}, "an item with another key is not counted"

    week = r["week"]
    assert week["unit"] == "week" and week["gapless"] and len(week["starts"]) == 31
    assert all(s[4] == 1 and s[2:4] == [0, 0] for s in week["starts"]), "a week does not start on Monday at midnight"
    assert week["starts"][0][:2] == [3, 2] and week["starts"][-1][:2] == [9, 28]
    assert [i for i, n in enumerate(week["totals"]) if n] == [0, 3, 15, 30] and sum(week["totals"]) == 4

    night = r["night"]
    assert night["unit"] == "hour" and night["gapless"] and sum(night["totals"]) == 2
    assert all(s[3] == 0 for s in night["starts"]) and set(night["lengths"]) == {3600000}
    assert night["starts"][0][2] == 0 and night["starts"][-1][2] == 5
    repeated = r["repeated"]
    assert repeated["unit"] == "hour" and repeated["gapless"] and set(repeated["lengths"]) == {3600000}
    assert all(s[3] == 0 for s in repeated["starts"])

    # Without a range the bins reach from the earliest to the latest item: no empty bin before or after them
    for name in ("hour", "day", "week", "night", "repeated"):
        assert r[name]["totals"][0] and r[name]["totals"][-1], f"{name}: an empty bin at an end: {r[name]['totals']}"

    assert r["units"] == ["hour", "day", "day", "week"], "unit: hour up to 2 days, day up to 120 days, then week"
    assert r["byTimestamp"] == [1]
    assert r["none"] == []


@needs_node
@pytest.mark.parametrize("zone", ZONES)
def test_bin_by_time_counts_only_the_chosen_range(zone):
    """A range (the dashboard's 7D, a bar clicked in the Alerts tab) counts the
    items from `from` up to `to`, `to` not included, in bins that begin at
    `from` and end at `to`: a bar that opens the Alerts tab with its start and
    end shows there exactly the alerts it counted."""
    r = _run_node(CHART_JS, BINS_LOOK + r"""
        const from = at(2026, 6, 14, 10, 30), to = at(2026, 6, 17, 6);
        const items = [at(2026, 6, 14, 9), from, at(2026, 6, 16, 23, 59), at(2026, 6, 17, 5, 59), to, at(2026, 6, 20)]
            .map(t => ({ t, sev: 'high' }));
        const range = binByTime(items, { time, key: x => x.sev, keys: ['critical', 'high'], from, to });
        console.log(JSON.stringify({
            range: look(range), first: range.bins[0].start === from, last: range.bins[range.bins.length - 1].end === to,
            nothing: binByTime(items, { time, from, to: from }).bins.length,
            after: binByTime(items, { time, from: at(2026, 6, 21) }).bins.length,
            noData: binByTime([], { time, from, to }).bins.map(b => b.total),
        }));
    """, _prelude(zone))
    rng = r["range"]
    assert rng["unit"] == "day" and rng["gapless"] and r["first"] and r["last"]
    assert rng["totals"] == [1, 0, 1, 1], "an item before `from` or at `to` was counted, or one inside was not"
    assert [s[2:4] for s in rng["starts"]] == [[10, 30], [0, 0], [0, 0], [0, 0]]
    assert rng["counts"][0] == {"critical": 0, "high": 1} and rng["counts"][1] == {"critical": 0, "high": 0}
    assert r["nothing"] == 0 and r["after"] == 0, "an empty range has bins"
    assert r["noData"] == [0, 0, 0, 0], "a range without data lacks its empty bins"


@needs_node
def test_bin_by_time_caps_absurd_ranges():
    """A sample can set the VM's clock: one alert dated 9999 must not give the
    dashboard millions of bins to draw, and no alert may get lost on the way:
    the last bin reaches to the end of the range."""
    r = _run_node(CHART_JS, r"""
        const started = Date.now();
        const items = ['2026-07-14T10:00:00Z', '2026-07-15T10:00:00Z', '9999-12-31T00:00:00Z'].map(timestamp => ({ timestamp }));
        const to = Date.parse('9000-01-01T00:00:00Z');
        const look = ({ unit, bins }) => ({
            unit, n: bins.length, sum: bins.reduce((sum, b) => sum + b.total, 0), first: bins[0].total,
            last: bins[bins.length - 1].total, end: bins[bins.length - 1].end,
            gapless: bins.every((b, i) => b.end > b.start && (i === 0 || b.start === bins[i - 1].end)),
        });
        const all = look(binByTime(items)), range = look(binByTime([], { from: 0, to }));
        console.log(JSON.stringify({ all, range, to, latest: Date.parse(items[2].timestamp), ms: Date.now() - started,
                                     max: CHART_MAX_BINS }));
    """, _prelude())
    assert 100 < r["max"] <= 2000
    for name in ("all", "range"):
        assert r[name]["unit"] == "week" and r[name]["gapless"] and r[name]["n"] == r["max"], r[name]
    assert (r["all"]["sum"], r["all"]["first"], r["all"]["last"]) == (3, 2, 1), "an alert was lost"
    assert r["all"]["end"] > r["latest"] and r["range"]["end"] == r["to"], "the bins stop before the end"
    assert r["range"]["sum"] == 0
    assert r["ms"] < 2000


# --- Stacked bars ---------------------------------------------------------------

@needs_node
@pytest.mark.parametrize("zone", [None, "Europe/Berlin", "Asia/Kolkata"])
def test_stacked_bars_draw_each_bin_with_its_counts(zone):
    r = _run_node(CHART_JS, r"""
        const at = (...a) => new Date(...a).getTime();
        const H = 3600000, t0 = at(2026, 6, 14, 22);
        const bins = [
            { start: t0, end: t0 + H, counts: { critical: 1, high: 3 }, total: 4 },
            { start: t0 + H, end: t0 + 2 * H, counts: { critical: 0, high: 0 }, total: 0 },
            { start: t0 + 2 * H, end: t0 + 3 * H, counts: { critical: 0, high: 2 }, total: 2 },      // midnight
        ];
        const colors = { critical: 'var(--severity-critical)', high: 'var(--severity-high)' };
        console.log(JSON.stringify({
            starts: bins.map(b => String(b.start)), ends: bins.map(b => String(b.end)),
            svg: stackedBarsSvg(bins, { width: 300, height: 128, keys: ['critical', 'high'], colors,
                                        selection: { from: t0 + H, to: t0 + 3 * H } }),
            // A range dragged across the chart ends inside bins; one beside the bins marks nothing
            dragged: [{ from: t0 + H / 4, to: t0 + 2.5 * H }, { from: t0 + 3 * H, to: t0 + 4 * H }, { from: t0 + H }]
                .map(selection => stackedBarsSvg(bins, { width: 300, height: 128, keys: ['critical', 'high'], colors, selection })),
            extra: stackedBarsSvg([{ start: t0, end: t0 + H, counts: { high: 1, bogus: 2 }, total: 3 }],
                                  { width: 300, height: 128, keys: ['high', 'high'], colors }),
            zeros: stackedBarsSvg(bins.map(b => ({ ...b, counts: { critical: 0, high: 0 }, total: 0 })),
                                  { width: 300, height: 128, keys: ['critical', 'high'], colors }),
            single: stackedBarsSvg([bins[0]], { width: 300, height: 128, keys: ['critical', 'high'], colors }),
            many: stackedBarsSvg(Array.from({ length: 60 }, (_, i) => ({ ...bins[0], start: t0 + i * H, end: t0 + (i + 1) * H })),
                                 { width: 300, height: 128, keys: ['critical', 'high'], colors }),
            none: [stackedBarsSvg([], { width: 300, height: 128 }), stackedBarsSvg(undefined)],
        }));
    """, _prelude(zone))
    tree = _Tree(r["svg"])
    groups = tree.find("g", attr="data-bin-start")
    assert [g["attrs"]["data-bin-start"] for g in groups] == r["starts"]
    assert [g["attrs"]["data-bin-end"] for g in groups] == r["ends"]
    bars = [{rect["attrs"]["data-key"]: rect for rect in g["children"] if "chart-bar" in rect["attrs"].get("class", "")}
            for g in groups]
    assert [sorted(b) for b in bars] == [["critical", "high"], [], ["high"]], "a bin without its parts, or a part of 0"
    assert [sum(int(rect["attrs"]["data-count"]) for rect in b.values()) for b in bars] == [4, 0, 2]
    hit = _child(groups[0], "rect")                     # the bin's area under its bars
    top, bottom = _num(hit, "y"), _num(hit, "y") + _num(hit, "height")
    crit, high = bars[0]["critical"], bars[0]["high"]
    assert _close([_num(crit, "y")], [top]), "the highest bin does not reach the top of the plot"
    assert _close([_num(crit, "y") + _num(crit, "height")], [_num(high, "y")]), "critical is not on top of high"
    assert _close([_num(high, "y") + _num(high, "height")], [bottom]), "the stack does not stand on the axis"
    assert _close([_num(high, "height")], [3 * _num(crit, "height")]), "3 high are not three times 1 critical"
    later = bars[2]["high"]
    assert _close([_num(later, "height")], [(bottom - top) / 2]) and _close([_num(later, "y") + _num(later, "height")], [bottom])
    assert _style(crit)["fill"] == "var(--severity-critical)" and _style(high)["fill"] == "var(--severity-high)"
    # Tooltips: the period in local time (hours 00-23), the total and the parts that are not 0
    titles = [_child(g, "title")["text"] for g in groups]
    assert titles == ["14 Jul 2026, 22:00\u201323:00\ntotal: 4\ncritical: 1\nhigh: 3",
                      "14 Jul 2026, 23:00\u201300:00\ntotal: 0",
                      "15 Jul 2026, 00:00\u201301:00\ntotal: 2\nhigh: 2"]
    ticks = [t["text"] for t in tree.find("text", cls="chart-tick")]
    assert ticks == ["22:00", "23:00", "15 Jul"], "axis labels: the hours, a new day by its date"
    assert "24:00" not in r["svg"]
    # The selection covers bins 2 and 3, from the left edge of one to the right edge of the other
    selection = tree.find("rect", cls="chart-selection")
    assert len(selection) == 1
    first, last = _child(groups[1], "rect"), _child(groups[2], "rect")
    assert _close([_num(selection[0], "x"), _num(selection[0], "x") + _num(selection[0], "width")],
                  [_num(first, "x"), _num(last, "x") + _num(last, "width")])
    dragged = [[(_num(s, "x"), _num(s, "x") + _num(s, "width")) for s in _Tree(svg).find("rect", cls="chart-selection")]
               for svg in r["dragged"]]
    assert dragged[0] == [(25, 250)], "a selection that ends inside a bin is not drawn where it ends"
    assert dragged[1] == [] and dragged[2] == [(100, 300)], "an open selection does not reach to the end"
    # A key that is not asked for is drawn too, a key asked for twice once: the bar adds up to its bin
    extra = _Tree(r["extra"]).find("rect", cls="chart-bar")
    assert sorted(rect["attrs"]["data-key"] for rect in extra) == ["bogus", "high"]
    assert r["zeros"] == "" and r["none"] == ["", ""], "nothing but empty bins is drawn instead of left to a hint"
    # A single bin is a bar, not a block across the chart, with its label under it; many bins fill their slots
    single = _Tree(r["single"])
    bar, hit = single.find("rect", cls="chart-bar")[0], single.find("rect", cls="chart-hit")[0]
    assert _num(bar, "width") <= 40 and _close([_num(bar, "x") + _num(bar, "width") / 2], [150]), "a bin is one block"
    assert _num(hit, "width") == 300, "the bin takes the click only on its bar"
    tick = single.find("text", cls="chart-tick")[0]
    assert _num(bar, "x") <= _num(tick, "x") <= _num(bar, "x") + _num(bar, "width"), "the label is not under its bar"
    many = _Tree(r["many"]).find("rect", cls="chart-bar")
    assert _close([_num(many[0], "width")], [4]) and _close([_num(many[-1], "x")], [295.5]), "60 bins do not fill 300 px"


@needs_node
@pytest.mark.parametrize("zone", ZONES + ["Asia/Kathmandu"])
def test_bin_by_time_takes_seconds_and_minutes_for_short_spans(zone):
    """Sysmon captures span minutes, where hours give a single bar: with
    `fine`, a span of up to 20 hours is counted in steps of 1, 2, 5, 10, 15
    or 30 seconds or minutes, the shortest that takes at most 40 of them,
    each beginning at a multiple of its step in local time (Kathmandu is 5:45
    ahead of UTC: its half hours are no UTC half hours), gapless and of one
    length also through the night the clocks go back. A longer span, and
    every call without `fine` (ALERT ACTIVITY of the dashboard), keeps hours,
    days and weeks."""
    r = _run_node(CHART_JS, BINS_LOOK + r"""
        const S = 1000, M = 60000, H = 3600000;
        const t0 = at(2026, 10, 10, 19, 30, 45, 449);
        // A time of day in local time, ms: a bin of a step begins where it divides it
        const local = t => { const d = new Date(t); return ((d.getHours() * 60 + d.getMinutes()) * 60 + d.getSeconds()) * S + d.getMilliseconds(); };
        const sum = bins => bins.reduce((n, b) => n + b.total, 0);
        const spans = [0, 40 * S, 41 * S, 3 * M, 17 * M, 30 * M, 2 * H, 6 * H, 20 * H, 20 * H + M, 2 * 86400000];
        const spanned = spans.map(ms => {
            const result = binByTime([{ t: t0 }, { t: t0 + ms }], { time, fine: true });
            const { unit, bins } = result;
            return { ms, unit, step: result.step ?? null, n: bins.length, total: sum(bins), first: fields(bins[0].start),
                     gapless: bins.every((b, i) => b.end > b.start && (i === 0 || b.start === bins[i - 1].end)),
                     aligned: bins.every(b => local(b.start) % (result.step || H) === 0) };
        });
        // The night Europe turns the clocks back (01:00 UTC on 25 Oct): four hours by ten minutes
        const night = binByTime([{ t: Date.UTC(2026, 9, 24, 23) }, { t: Date.UTC(2026, 9, 25, 3) }], { time, fine: true });
        // A range: its first and last bin begin and end there, the others at multiples of the step
        const from = t0 + 7 * S, to = t0 + 3 * M;
        const items = [t0, from, from + 10 * S, to - 1, to].map(t => ({ t }));
        const range = binByTime(items, { time, fine: true, from, to });
        console.log(JSON.stringify({
            spanned,
            night: { step: night.step, lengths: [...new Set(night.bins.map(b => b.end - b.start))], n: night.bins.length,
                     aligned: night.bins.every(b => local(b.start) % (10 * M) === 0),
                     gapless: night.bins.every((b, i) => i === 0 || b.start === night.bins[i - 1].end) },
            range: { step: range.step, first: range.bins[0].start === from, last: range.bins[range.bins.length - 1].end === to,
                     inner: range.bins.slice(1).every(b => local(b.start) % (5 * S) === 0), total: sum(range.bins) },
            // Without `fine`: hours, as before, and no step
            coarse: ((result) => ({ unit: result.unit, n: result.bins.length, step: 'step' in result }))(
                binByTime([{ t: t0 }, { t: t0 + 17 * M }], { time })),
        }));
    """, _prelude(zone))
    want = {0: ("second", 1000, 1), 40000: ("second", 1000, 41), 41000: ("second", 2000, 22),
            180000: ("second", 5000, 37), 1020000: ("second", 30000, 35), 1800000: ("minute", 60000, 31),
            7200000: ("minute", 300000, 25), 21600000: ("minute", 600000, 37), 72000000: ("minute", 1800000, 41),
            72060000: ("hour", None, 21), 172800000: ("hour", None, 49)}
    for span in r["spanned"]:
        assert (span["unit"], span["step"], span["n"]) == want[span["ms"]], span
        assert span["gapless"] and span["aligned"] and span["total"] == 2, span
    # 17 minutes from 19:30:45: half minutes from 19:30:30
    assert next(s for s in r["spanned"] if s["ms"] == 1020000)["first"][2:4] == [19, 30]
    night = r["night"]
    assert night["step"] == 600000 and night["lengths"] == [600000] and night["gapless"] and night["aligned"], night
    assert night["n"] == 25
    rng = r["range"]
    assert rng == {"step": 5000, "first": True, "last": True, "inner": True, "total": 3}, rng
    assert r["coarse"] == {"unit": "hour", "n": 1, "step": False}, "a call without fine no longer gets hours"


@needs_node
@pytest.mark.parametrize("zone", [None, "Europe/Berlin", "Asia/Kolkata"])
def test_stacked_bars_label_seconds_and_minutes(zone):
    """Bars of seconds name their periods to the second ("10 Nov 2026,
    19:30:30–19:31:00") and their ticks round times with their seconds, which
    take 56 px between them (not the 48 px of shorter labels: at 900 px, a
    tick a minute would stand 51 px apart); bars of minutes without them;
    midnight is the date, never 24:00. A bar a range cuts off the full minute
    is named to the second, as the chip of its period ("10 Nov 2026,
    15:30:17–15:31:00"), among bars of minutes and of hours alike; the bars
    it does not cut keep their names."""
    r = _run_node(CHART_JS + ["chartRangeLabel"], r"""
        const at = (...a) => new Date(...a).getTime();
        const S = 1000, M = 60000, H = 3600000;
        const items = (t, n, gap) => Array.from({ length: n }, (_, i) => ({ t: t + i * gap, k: i % 3 ? 'PipeCreated' : 'ProcessCreate' }));
        const draw = (list, width = 700, range = {}) => {
            const { unit, step, bins } = binByTime(list, { time: x => x.t, key: x => x.k, fine: true, ...range });
            const svg = stackedBarsSvg(bins, { width, height: 140, keys: ['ProcessCreate', 'PipeCreated'], unit, step });
            return { unit, step, n: bins.length, svg,
                     titles: [...svg.matchAll(/<title>([^<]*)<\/title>/g)].map(m => m[1].split('\n')[0]),
                     ticks: [...svg.matchAll(/<text class="chart-tick"[^>]*>([^<]*)<\/text>/g)].map(m => m[1]),
                     chips: bins.map(bin => chartRangeLabel(bin.start, bin.end)) };
        };
        const cut = at(2026, 10, 10, 15, 30, 17);
        console.log(JSON.stringify({
            halfMinutes: draw(items(at(2026, 10, 10, 19, 30, 45), 35, 30 * S)),      // 17 minutes
            wide: draw(items(at(2026, 10, 10, 19, 30, 45), 35, 30 * S), 900),
            minutes: draw(items(at(2026, 10, 10, 23, 40), 40, 3 * M)),               // two hours over midnight
            seconds: draw(items(at(2026, 10, 10, 9, 0, 7), 12, 3 * S)),              // 33 seconds
            // A range from 15:30:17: 39 minutes to 16:09:40, a day to 15:30:17 the next day
            cutMinutes: draw(items(at(2026, 10, 10, 15, 31), 38, M), 700, { from: cut, to: at(2026, 10, 10, 16, 9, 40) }),
            cutHours: draw(items(at(2026, 10, 10, 16), 23, H), 700, { from: cut, to: at(2026, 10, 11, 15, 30, 17) }),
        }));
    """, _prelude(zone))
    half = r["halfMinutes"]
    assert (half["unit"], half["step"], half["n"]) == ("second", 30000, 35)
    assert half["titles"][:2] == ["10 Nov 2026, 19:30:30\u201319:31:00", "10 Nov 2026, 19:31:00\u201319:31:30"]
    assert half["ticks"] == ["19:30:30", "19:32:00", "19:34:00", "19:36:00", "19:38:00", "19:40:00", "19:42:00",
                             "19:44:00", "19:46:00"], half["ticks"]
    assert r["wide"]["ticks"] == half["ticks"], r["wide"]["ticks"]
    minutes = r["minutes"]
    assert (minutes["unit"], minutes["step"], minutes["n"]) == ("minute", 300000, 24)
    assert minutes["titles"][3:5] == ["10 Nov 2026, 23:55\u201300:00", "11 Nov 2026, 00:00\u201300:05"]
    assert minutes["ticks"] == ["23:40", "23:50", "11 Nov", "00:10", "00:20", "00:30", "00:40", "00:50", "01:00",
                                "01:10", "01:20", "01:30"], minutes["ticks"]
    seconds = r["seconds"]
    assert (seconds["unit"], seconds["step"], seconds["n"]) == ("second", 1000, 34)
    assert seconds["titles"][0] == "10 Nov 2026, 09:00:07\u201309:00:08"
    assert seconds["ticks"] == ["09:00:07", "09:00:10", "09:00:15", "09:00:20", "09:00:25", "09:00:30", "09:00:35"], \
        seconds["ticks"]
    for view in (half, minutes, seconds):
        assert "24:" not in view["svg"]
    # Cut off the full minute by the range: its first and last bar to the second, as their chips; the others not
    cut = r["cutMinutes"]
    assert (cut["unit"], cut["step"], cut["n"]) == ("minute", 60000, 40)
    assert [cut["titles"][i] for i in (0, 1, -1)] == ["10 Nov 2026, 15:30:17\u201315:31:00", "10 Nov 2026, 15:31\u201315:32",
                                                     "10 Nov 2026, 16:09:00\u201316:09:40"], cut["titles"][:2]
    assert [cut["chips"][i] for i in (0, 1, -1)] == ["10 Nov 15:30:17\u201315:31:00", "10 Nov 15:31\u201315:32",
                                                    "10 Nov 16:09:00\u201316:09:40"]
    hours = r["cutHours"]
    assert (hours["unit"], hours["n"]) == ("hour", 25)
    assert [hours["titles"][i] for i in (0, 1, -1)] == ["10 Nov 2026, 15:30:17\u201316:00:00", "10 Nov 2026, 16:00\u201317:00",
                                                       "11 Nov 2026, 15:00:00\u201315:30:17"], hours["titles"][:2]


# --- Donut, pie, legend ---------------------------------------------------------

@needs_node
def test_donut_full_circle_and_empty():
    r = _run_node(CHART_JS, r"""
        console.log(JSON.stringify({
            donut: donutSvg([{ key: 'high', label: 'HIGH', value: 5, color: 'var(--severity-high)' }], { size: 100, thickness: 20 }),
            withZero: donutSvg([{ key: 'a', value: 5 }, { key: 'b', value: 0 }], { size: 100, thickness: 20 }),
            pie: pieSvg([{ key: 'x', value: 7 }], { size: 100 }),
            zeros: [donutSvg([{ key: 'a', value: 0 }, { key: 'b', value: 0 }]), pieSvg([{ key: 'a', value: 0 }]),
                    donutSvg([]), pieSvg([]), donutSvg(null), pieSvg(undefined),
                    donutSvg([{ key: 'a', value: -3 }, { key: 'b', value: NaN }, { key: 'c' }, null])],
        }));
    """, _prelude())
    for name, radius in (("donut", 40), ("withZero", 40), ("pie", 48)):
        shapes = _Tree(r[name]).find(attr="data-key")
        assert len(shapes) == 1, f"{name}: {shapes}"
        # One share of 100 %: a circle (an arc from a point back to itself draws nothing)
        assert shapes[0]["tag"] == "circle" and _close([_num(shapes[0], "r")], [radius]), r[name]
        assert _close([_num(shapes[0], "cx"), _num(shapes[0], "cy")], [50, 50])
    assert "<path" not in r["donut"] + r["withZero"] + r["pie"]
    assert r["zeros"] == [""] * 7, "a chart of nothing but zeros is drawn"


@needs_node
def test_donut_and_pie_segments_follow_their_shares():
    """1 and 3: a quarter from 12 o'clock to 3 o'clock, then the rest back to
    12 o'clock; a share of 1 in 10 000 still shows as a sliver."""
    r = _run_node(CHART_JS, r"""
        const items = [{ key: 'a', label: 'A', value: 1 }, { key: 'b', label: 'B', value: 3 }];
        console.log(JSON.stringify({
            donut: donutSvg(items, { size: 100, thickness: 20, centerLabel: '4', centerSub: 'ALERTS' }),
            pie: pieSvg(items, { size: 100 }),
            total: donutSvg(items, { size: 100, thickness: 20 }),
            tiny: donutSvg([{ key: 'a', value: 1 }, { key: 'b', value: 9999 }], { size: 100, thickness: 20 }),
        }));
    """, _prelude())
    donut = {p["attrs"]["data-key"]: p for p in _Tree(r["donut"]).find("path", attr="data-key")}
    assert _close(_numbers(donut["a"]["attrs"]["d"]), [50, 10, 40, 40, 0, 0, 1, 90, 50])
    assert _close(_numbers(donut["b"]["attrs"]["d"]), [90, 50, 40, 40, 0, 1, 1, 50, 10])
    assert "25.0%" in _child(donut["a"], "title")["text"] and "75.0%" in _child(donut["b"], "title")["text"]
    assert [t["text"] for t in _Tree(r["donut"]).find("text")] == ["4", "ALERTS"]
    assert [t["text"] for t in _Tree(r["total"]).find("text")] == ["4"], "without a centre label the total shows"
    pie = {p["attrs"]["data-key"]: p for p in _Tree(r["pie"]).find("path", attr="data-key")}
    assert _close(_numbers(pie["a"]["attrs"]["d"]), [50, 50, 50, 2, 48, 48, 0, 0, 1, 98, 50])
    assert _close(_numbers(pie["b"]["attrs"]["d"]), [50, 50, 98, 50, 48, 48, 0, 1, 1, 50, 2])
    tiny = {p["attrs"]["data-key"]: _numbers(p["attrs"]["d"]) for p in _Tree(r["tiny"]).find("path", attr="data-key")}
    x0, y0, x1, y1 = tiny["a"][0], tiny["a"][1], tiny["a"][-2], tiny["a"][-1]
    assert math.hypot(x1 - x0, y1 - y0) >= 0.9, "a share of 1 in 10 000 vanishes"
    assert _close(tiny["b"][-2:], [50, 10]), "the segments do not close the circle"


@needs_node
def test_chart_legend_counts_and_shares():
    r = _run_node(CHART_JS, r"""
        const severities = [['critical', 196], ['high', 2700], ['medium', 6720], ['low', 4], ['info', 0]]
            .map(([key, value]) => ({ key, label: key.toUpperCase(), value, color: SEVERITY_COLORS[key] }));
        const plain = [{ key: 'a', value: 0 }, { key: 'b', value: 2 }, { key: 'c', value: 1 }];
        console.log(JSON.stringify({
            legend: chartLegendHtml(severities),
            ofTotal: chartLegendHtml([{ key: 'registry', label: 'registry', value: 50 }], { total: 200 }),
            empty: [chartLegendHtml([]), chartLegendHtml(undefined)],
            plainLegend: chartLegendHtml(plain), plainDonut: donutSvg(plain), plainPie: pieSvg(plain),
        }));
    """, _prelude())
    rows = _Tree(r["legend"]).find(cls="chart-legend-row")

    def cells(row):
        return [c["text"] for c in row["children"] if c["tag"] == "span"][1:]
    assert [row["attrs"]["data-key"] for row in rows] == ["critical", "high", "medium", "low", "info"]
    assert [cells(row) for row in rows] == [["CRITICAL", "196", "2.0%"], ["HIGH", "2,700", "28.1%"],
                                            ["MEDIUM", "6,720", "69.9%"], ["LOW", "4", "<0.1%"], ["INFO", "0", "0.0%"]]
    assert [_style(swatch)["background"] for swatch in _Tree(r["legend"]).find(cls="chart-legend-swatch")] == \
        [f"var(--severity-{s})" for s in ("critical", "high", "medium", "low", "info")]
    assert [cells(row) for row in _Tree(r["ofTotal"]).find(cls="chart-legend-row")] == [["registry", "50", "25.0%"]]
    assert r["empty"] == ["", ""]
    # Without colours of their own the items take the palette: the same in the legend, the donut and the pie
    legend = {row["attrs"]["data-key"]: _style(row["children"][0])["background"]
              for row in _Tree(r["plainLegend"]).find(cls="chart-legend-row")}
    donut = {seg["attrs"]["data-key"]: _style(seg)["stroke"] for seg in _Tree(r["plainDonut"]).find(attr="data-key")}
    pie = {seg["attrs"]["data-key"]: _style(seg)["fill"] for seg in _Tree(r["plainPie"]).find(attr="data-key")}
    assert donut == pie == {k: legend[k] for k in ("b", "c")} and legend["b"] != legend["c"]


# --- Sparkline, scatter, empty --------------------------------------------------

@needs_node
def test_sparkline_and_scatter_place_their_points():
    r = _run_node(CHART_JS, r"""
        const scans = [
            { x: 1, y: 2.24, color: 'var(--severity-medium)', title: 'Aether a.exe 2.24', key: 's1' },
            { x: 2, y: 6.54, color: 'var(--severity-critical)', title: 'Exit Capture a.exe 6.54', key: 's2' },
            { x: 3, y: null, color: 'var(--text-muted)', title: 'Process Dump a.exe', key: 's3' },
            { x: 4, y: 99, color: 'var(--severity-critical)', title: 'off the scale', key: 's4' },
        ];
        const thresholds = [{ y: 2, label: 'SUSPICIOUS' }, { y: 6, label: 'MALICIOUS' }];
        console.log(JSON.stringify({
            spark: sparklineSvg([0, 5, 10], { width: 100, height: 20, color: 'var(--accent-cyan)' }),
            one: sparklineSvg([3], { width: 100, height: 20 }),
            zeros: sparklineSvg([0, 0, 0], { width: 100, height: 20 }),
            noSpark: [sparklineSvg([]), sparklineSvg(undefined)],
            scatter: scatterSvg(scans, { width: 400, height: 140, yMax: 8, thresholds }),
            scored: scatterSvg([{ x: 1, y: 1, key: 'k' }], { width: 400, height: 140, thresholds }),
            noScatter: [scatterSvg([], { thresholds }), scatterSvg(undefined)],
            empty: chartEmptyHtml('No scans yet'),
        }));
    """, _prelude())

    def points(svg):
        line = _Tree(svg).find("polyline")[0]
        return [tuple(map(float, p.split(","))) for p in line["attrs"]["points"].split()]
    spark = points(r["spark"])
    assert [x for x, _ in spark] == [0, 50, 100]
    (_, y0), (_, y5), (_, y10) = spark
    assert y10 <= 4 and y0 >= 16 and _close([y5], [(y0 + y10) / 2]), "the highest value is not at the top"
    assert _style(_Tree(r["spark"]).find("polygon")[0])["fill"] == "var(--accent-cyan)"
    one = points(r["one"])
    assert [x for x, _ in one] == [0, 100] and one[0][1] == one[1][1], "a single value is no line across"
    assert all(y >= 16 for _, y in points(r["zeros"])), "zeros are not drawn on the ground"
    assert "NaN" not in r["one"] + r["zeros"] + r["spark"] and r["noSpark"] == ["", ""]

    tree = _Tree(r["scatter"])
    dots = {c["attrs"]["data-key"]: c for c in tree.find("circle", attr="data-key")}
    axis = _num(tree.find("line", cls="chart-axis")[0], "y1")
    lines = {round(_num(line, "y1"), 2): line for line in tree.find("line", cls="chart-threshold")}
    y2, y6 = sorted(lines, reverse=True)                  # the line of 2 lies lower (larger y) than the one of 6
    cy = {k: _num(c, "cy") for k, c in dots.items()}
    assert cy["s3"] > axis, "a scan without a score is not in the lane under the axis"
    assert all(cy[k] < axis for k in ("s1", "s2", "s4")), "a scored scan is not above the axis"
    assert y6 < cy["s1"] < y2 and cy["s2"] < y6, "the points are not placed by their scores"
    assert cy["s4"] >= 0 and cy["s4"] <= cy["s2"], "a score above yMax leaves the chart"
    assert [_num(dots[k], "cx") for k in ("s1", "s2", "s3", "s4")] == sorted(_num(dots[k], "cx") for k in dots)
    assert all(line["attrs"].get("stroke-dasharray") for line in lines.values()), "a threshold is not dashed"
    texts = [t["text"] for t in tree.find("text")]
    assert "SUSPICIOUS 2" in texts and "MALICIOUS 6" in texts and "no score" in texts
    assert _child(dots["s2"], "title")["text"] == "Exit Capture a.exe 6.54"
    assert "no score" not in r["scored"], "a lane without scans"
    assert r["noScatter"] == ["", ""]
    assert _Tree(r["empty"]).find(cls="chart-empty")[0]["text"] == "No scans yet"


# --- Sankey ---------------------------------------------------------------------

# Two sources, three middle nodes, two sinks. Node values by hand, max(in, out):
# a 130, b 11, m1 100, m2 40, m3 1, x 120, y 21; a middle node passes on what
# it receives. The links not in the order of the nodes they join.
FLOW_COLUMNS = [["a", "b"], ["m1", "m2", "m3"], ["x", "y"]]
FLOW_LINKS = [["m1", "y", 20], ["a", "m2", 30], ["m2", "x", 40], ["b", "m3", 1],
              ["a", "m1", 100], ["m3", "y", 1], ["b", "m2", 10], ["m1", "x", 80]]
FLOW_VALUES = {"a": 130, "b": 11, "m1": 100, "m2": 40, "m3": 1, "x": 120, "y": 21}


def _flow_js(script):
    return ("const columns = __COLUMNS__, links = __LINKS__.map(([source, target, value]) => ({ source, target, value }));\n"
            + script).replace("__COLUMNS__", json.dumps(FLOW_COLUMNS)).replace("__LINKS__", json.dumps(FLOW_LINKS))


@needs_node
def test_layout_sankey_conserves_flow():
    """A node is as high as its value (or its square root), its bands lie side
    by side and fill it, what enters a middle node leaves it; the nodes of a
    column keep their order and gap and stay inside the chart."""
    r = _run_node(CHART_JS, _flow_js(r"""
        const opts = { width: 600, height: 400, nodeWidth: 10, gap: 10 };
        console.log(JSON.stringify({
            sqrt: layoutSankey(columns, links, opts),
            linear: layoutSankey(columns, links, { ...opts, scale: 'linear' }),
            room: layoutSankey(columns, links, { ...opts, labelWidth: 200 }),
            // m receives 10 and passes on 4
            leaky: layoutSankey([['a'], ['m'], ['x']], [{ source: 'a', target: 'm', value: 10 }, { source: 'm', target: 'x', value: 4 }],
                                { ...opts, scale: 'linear' }),
        }));
    """), _prelude())
    for name in ("sqrt", "linear"):
        layout = r[name]
        nodes = {n["id"]: n for n in layout["nodes"]}
        assert {k: n["value"] for k, n in nodes.items()} == FLOW_VALUES, name
        assert {k: n["col"] for k, n in nodes.items()} == {k: c for c, col in enumerate(FLOW_COLUMNS) for k in col}
        bands = layout["links"]
        assert sorted([b["source"], b["target"], b["value"]] for b in bands) == sorted(FLOW_LINKS)
        for key, node in nodes.items():
            ins = sorted((b for b in bands if b["target"] == key), key=lambda b: b["ty"])
            outs = sorted((b for b in bands if b["source"] == key), key=lambda b: b["sy"])
            if node["col"] == 1:
                assert sum(b["value"] for b in ins) == sum(b["value"] for b in outs) == node["value"], \
                    f"{name}: what enters {key} does not leave it"
            for side, at, thick, far, far_at in ((ins, "ty", "thickness_t", "source", "sy"),
                                                 (outs, "sy", "thickness_s", "target", "ty")):
                if not side:
                    continue
                for b in side:
                    assert _close([b[thick]], [node["h"] * b["value"] / node["value"]]), \
                        f"{name}: {b} is not as thick as its share of {key}"
                assert _close([b[at] for b in side], [node["y"]] + [b[at] + b[thick] for b in side][:-1]), \
                    f"{name}: the bands of {key} do not lie side by side from its top"
                assert _close([side[-1][at] + side[-1][thick]], [node["y"] + node["h"]]), f"{name}: {key} not filled"
                ends = [nodes[b[far]]["y"] for b in side]
                assert ends == sorted(ends), f"{name}: the bands of {key} cross each other at {key}"
        for c, column in enumerate(FLOW_COLUMNS):
            placed = [nodes[k] for k in column]
            assert len({n["x"] for n in placed}) == 1, f"{name}: column {c} is not one column"
            for upper, lower in zip(placed, placed[1:]):
                assert lower["y"] - (upper["y"] + upper["h"]) >= 10 - 1e-6, \
                    f"{name}: {upper['id']} and {lower['id']} overlap or lost their gap"
            assert all(n["y"] >= -1e-6 and n["y"] + n["h"] <= 400 + 1e-6 for n in placed), f"{name}: a node leaves the chart"
        xs = [nodes[col[0]]["x"] for col in FLOW_COLUMNS]
        assert 0 <= xs[0] < xs[1] < xs[2] and xs[2] + 10 <= 600 - 100, f"{name}: columns at {xs}, no room for labels"
        spans = [nodes[col[-1]]["y"] + nodes[col[-1]]["h"] - nodes[col[0]]["y"] for col in FLOW_COLUMNS]
        assert _close([max(spans)], [400]), f"{name}: the fullest column does not take the height: {spans}"
    sqrt, linear = ({n["id"]: n for n in r[name]["nodes"]} for name in ("sqrt", "linear"))
    assert _close([sqrt["m1"]["h"] / sqrt["m3"]["h"]], [10], 0.01), "sqrt: 100 is not 10 times as high as 1"
    assert _close([linear["m1"]["h"] / linear["m3"]["h"]], [100], 0.1), "linear: 100 is not 100 times as high as 1"
    room = {n["id"]: n for n in r["room"]["nodes"]}
    assert _close([room["x"]["x"] + 10], [400]), "labelWidth does not keep its room right of the last column"
    m = next(n for n in r["leaky"]["nodes"] if n["id"] == "m")
    out = next(b for b in r["leaky"]["links"] if b["source"] == "m")
    assert m["value"] == 10 and _close([out["thickness_s"], out["thickness_t"]], [m["h"] * 0.4, m["h"] * 0.4]), \
        "a node that passes on less than it receives: its band out is not its share of the node"


@needs_node
def test_layout_sankey_fits_crowded_columns():
    """40 nodes of 1 beside one of 10 000 in 120 px, and a flow of 1 beside
    one of 10 000 in true proportions: every node stays visible, none
    overlaps another or leaves the chart."""
    r = _run_node(CHART_JS, r"""
        const many = Array.from({ length: 40 }, (_, i) => 's' + i);
        const links = [{ source: 'big', target: 'sink', value: 10000 }, ...many.map(source => ({ source, target: 'sink', value: 1 }))];
        console.log(JSON.stringify({
            crowded: layoutSankey([['big', ...many], ['sink']], links, { height: 120, gap: 10 }),
            tiny: layoutSankey([['big', 's0'], ['sink']], links.slice(0, 2), { height: 100, scale: 'linear' }),
        }));
    """, _prelude())
    for name, height, count in (("crowded", 120, 42), ("tiny", 100, 3)):
        nodes = r[name]["nodes"]
        assert len(nodes) == count, name
        for col in (0, 1):
            placed = sorted((n for n in nodes if n["col"] == col), key=lambda n: n["y"])
            assert all(n["h"] >= 1 for n in placed), f"{name}: a node too thin to see: {placed}"
            for upper, lower in zip(placed, placed[1:]):
                assert lower["y"] >= upper["y"] + upper["h"] - 1e-6, f"{name}: {upper['id']} and {lower['id']} overlap"
            assert placed[0]["y"] >= -1e-6 and placed[-1]["y"] + placed[-1]["h"] <= height + 1e-6, f"{name}: off the chart"
    big = {n["id"]: n["h"] for n in r["crowded"]["nodes"]}
    assert big["big"] > 10 * big["s0"], "the node of 10 000 is no bigger than one of 1"


@needs_node
def test_layout_sankey_ignores_what_it_cannot_draw():
    """Only links from a column to the next with a value above 0 count; the
    same pair twice adds up; a node without flow and an id listed a second
    time are left out; nothing to draw is no layout and no SVG."""
    r = _run_node(CHART_JS, r"""
        const columns = [['a', 'b', 'lonely'], ['m', 'a'], ['x']];
        const links = [
            { source: 'a', target: 'm', value: 2 }, { source: 'a', target: 'm', value: 3 },
            { source: 'b', target: 'm', value: 4 }, { source: 'm', target: 'x', value: 9 },
            { source: 'a', target: 'x', value: 7 }, { source: 'm', target: 'b', value: 7 },
            { source: 'a', target: 'a', value: 7 }, { source: 'a', target: 'ghost', value: 7 },
            { source: 'b', target: 'm', value: 0 }, { source: 'b', target: 'm', value: -2 },
            { source: 'b', target: 'm', value: NaN }, { source: 'b', target: 'm', value: Infinity }, null,
        ];
        const look = layout => ({ nodes: layout.nodes.map(n => [n.id, n.col, n.value]),
                                  links: layout.links.map(l => [l.source, l.target, l.value]) });
        const empties = [layoutSankey([], []), layoutSankey(undefined, undefined),
                         layoutSankey([['a', 'b']], [{ source: 'a', target: 'b', value: 1 }]),
                         layoutSankey([['a'], ['b']], [{ source: 'a', target: 'b', value: 0 }])];
        console.log(JSON.stringify({
            layout: look(layoutSankey(columns, links)),
            empties: empties.map(look),
            svgs: [...empties.map(layout => sankeySvg(layout)), sankeySvg(undefined), sankeySvg({})],
        }));
    """, _prelude())
    assert sorted(r["layout"]["nodes"]) == [["a", 0, 5], ["b", 0, 4], ["m", 1, 9], ["x", 2, 9]]
    assert sorted(r["layout"]["links"]) == [["a", "m", 5], ["b", "m", 4], ["m", "x", 9]]
    assert r["empties"] == [{"nodes": [], "links": []}] * 4
    assert r["svgs"] == [""] * 6, "nothing to draw is drawn instead of left to a hint"


@needs_node
def test_top_with_other_keeps_the_most_frequent():
    r = _run_node(CHART_JS, r"""
        const counts = [{ key: 'a', count: 5 }, { key: 'b', count: 3 }, { key: 'c', count: 2 }, { key: 'd', count: 1 }];
        const two = topWithOther(counts, 2, 'other');
        console.log(JSON.stringify({
            two: [...two.keep], labels: ['a', 'b', 'c', 'd', 'unseen'].map(two.label),
            three: [...topWithOther(counts, 3, 'other').keep],
            shuffled: [...topWithOther([counts[3], counts[1], counts[0], counts[2]], 2, 'other').keep],
            ties: [...topWithOther(countBy(['y', 'x', 'z', 'x', 'y', 'w']), 2, 'other').keep],
            empty: [[...topWithOther([], 6, 'other').keep], [...topWithOther(undefined, 6, 'other').keep]],
        }));
    """, _prelude())
    assert sorted(r["two"]) == ["a", "b"] and r["labels"] == ["a", "b", "other", "other", "other"]
    assert sorted(r["three"]) == ["a", "b", "c", "d"], "an 'other' that stands for a single key hides its name for nothing"
    assert sorted(r["shuffled"]) == ["a", "b"], "the kept keys are not the most frequent"
    assert sorted(r["ties"]) == ["x", "y"], "a tie at the cut is not settled in the order of countBy"
    assert r["empty"] == [[], []]


# Rule i (1-9) fires 10 - i times: R1 9 times ... R9 once (only `name`), 45
# alerts. R1-R6 come from Sigma, written in three ways; R7-R9 from Yara. The
# first alert of each rule runs in powershell.exe (in another case after R1),
# the others in a process of their rule: P1, P2 (known only by its image), none
# for R3 ("(unknown)"), P4 ... P8. Processes: powershell.exe 9, P1 8, P2 7,
# (unknown) 6, P4 5, P5 4, P6 3, P7 2, P8 1.
ALERT_FLOW_FIXTURE = r"""
    const alerts = [];
    for (let i = 1; i <= 9; i++) {
        for (let j = 0; j < 10 - i; j++) {
            const alert = { engine: i <= 6 ? ['Sigma', 'sigma', 'SIGMA'][j % 3] : 'Yara', severity: 'high' };
            if (i === 9) alert.name = 'R9'; else alert.rule_name = 'R' + i;
            if (j === 0) alert.process_name = i === 1 ? 'powershell.exe' : 'PowerShell.EXE';
            else if (i === 2) { alert.process_name = ''; alert.process_image = 'C:\\Windows\\P2'; }
            else if (i !== 3) alert.process_name = 'P' + i;
            alerts.push(alert);
        }
    }
"""


@needs_node
def test_alert_flow_groups_other():
    r = _run_node(CHART_JS, ALERT_FLOW_FIXTURE + r"""
        const look = flow => ({
            columns: flow.columns.map(column => column.map(id => flow.labels[id])),
            ids: flow.columns.flat(),
            links: flow.links.map(l => [flow.labels[l.source], flow.labels[l.target], l.value,
                                        flow.columns.findIndex(column => column.includes(l.source))]),
        });
        const flow = alertFlow(alerts, { top: 6 });
        const layout = layoutSankey(flow.columns, flow.links);
        console.log(JSON.stringify({
            n: alerts.length, six: look(flow), byDefault: look(alertFlow(alerts)), eight: look(alertFlow(alerts, { top: 8 })),
            placed: layout.nodes.map(n => [n.id, n.col, n.value]),
            none: [alertFlow([]), alertFlow(undefined), alertFlow([null])].map(f => [f.columns.flat().length, f.links.length]),
        }));
    """, _prelude())
    assert r["n"] == 45
    six = r["six"]
    assert six["columns"] == [["Sigma", "Yara"],
                              ["R1", "R2", "R3", "R4", "R5", "R6", "other rules"],
                              ["powershell.exe", "P1", "P2", "(unknown)", "P4", "P5", "other processes"]], \
        "not the 6 most frequent and the rest, or a name not in its first spelling"
    links = {(s, t): v for s, t, v, _ in six["links"]}
    assert len(links) == len(six["links"]), "a pair of nodes with two bands"
    assert links == {
        ("Sigma", "R1"): 9, ("Sigma", "R2"): 8, ("Sigma", "R3"): 7, ("Sigma", "R4"): 6, ("Sigma", "R5"): 5,
        ("Sigma", "R6"): 4, ("Yara", "other rules"): 6,
        ("R1", "powershell.exe"): 1, ("R1", "P1"): 8, ("R2", "powershell.exe"): 1, ("R2", "P2"): 7,
        ("R3", "powershell.exe"): 1, ("R3", "(unknown)"): 6, ("R4", "powershell.exe"): 1, ("R4", "P4"): 5,
        ("R5", "powershell.exe"): 1, ("R5", "P5"): 4, ("R6", "powershell.exe"): 1, ("R6", "other processes"): 3,
        ("other rules", "powershell.exe"): 3, ("other rules", "other processes"): 3,
    }
    assert sum(v for *_, v, c in six["links"] if c == 0) == 45 == sum(v for *_, v, c in six["links"] if c == 1), \
        "engine -> rule or rule -> process does not count every alert once"
    assert len(set(six["ids"])) == len(six["ids"]) == 16
    assert r["byDefault"] == six, "top is not 6 by default"
    # 9 rules and 9 processes for 8 places: a rest of one is shown by its name
    eight = r["eight"]
    assert eight["columns"][1] == ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"]
    assert eight["columns"][2] == ["powershell.exe", "P1", "P2", "(unknown)", "P4", "P5", "P6", "P7", "P8"]
    # The flow draws: every node in its column, the rules pass on what they receive
    placed = {node: (col, value) for node, col, value in r["placed"]}
    assert len(placed) == 16 and {c for c, _ in placed.values()} == {0, 1, 2}
    assert sum(v for c, v in placed.values() if c == 0) == sum(v for c, v in placed.values() if c == 2) == 45
    assert r["none"] == [[0, 0], [0, 0], [0, 0]]


@needs_node
def test_alert_flow_keeps_columns_apart():
    """A node's id names its column ("engine:Sigma", "rule:...", "process:..."),
    so a process named like an engine, a rule or "other processes", or a rule
    named "other rules", stays a node of its own; a missing name is
    "(unknown)", which the filters of the rule and the process take too."""
    r = _run_node(CHART_JS, r"""
        const alerts = [
            { engine: 'Sigma', rule_name: 'other rules', process_name: 'Sigma' },
            { engine: 'Sigma', rule_name: 'other rules', process_name: 'other processes' },
            { engine: 'Sigma', rule_name: 'other rules', process_name: 'other rules' },
            { engine: 'yara', rule_name: 'A', process_name: 'A' },
            { engine: 'Yara', rule_name: 'B', process_name: 'B' },
            { rule_name: '', process_name: '' },
        ];
        const flow = alertFlow(alerts, { top: 1 });
        const layout = layoutSankey(flow.columns, flow.links);
        console.log(JSON.stringify({ ...flow, placed: layout.nodes.map(n => [n.id, n.col, n.value]) }));
    """, _prelude())
    assert r["columns"] == [["engine:Sigma", "engine:yara", "engine:"], ["rule:other rules", "other rules"],
                            ["process:(unknown)", "other processes"]]
    assert r["labels"] == {"engine:Sigma": "Sigma", "engine:yara": "yara", "engine:": "(unknown)",
                           "rule:other rules": "other rules", "other rules": "other rules",
                           "process:(unknown)": "(unknown)", "other processes": "other processes"}
    assert sorted([l["source"], l["target"], l["value"]] for l in r["links"]) == sorted([
        ["engine:Sigma", "rule:other rules", 3], ["engine:yara", "other rules", 2], ["engine:", "other rules", 1],
        ["rule:other rules", "other processes", 3], ["other rules", "process:(unknown)", 1],
        ["other rules", "other processes", 2],
    ])
    assert sorted(r["placed"]) == sorted([
        ["engine:Sigma", 0, 3], ["engine:yara", 0, 2], ["engine:", 0, 1], ["rule:other rules", 1, 3],
        ["other rules", 1, 3], ["process:(unknown)", 2, 1], ["other processes", 2, 5]])


@needs_node
def test_alert_flow_names_nodes_as_the_filters_compare_them():
    """A node counts what the filter its click sets lists: a rule or a process
    with blanks around it or in other capitals is the node of its name, an
    alert without a name and one named "(Unknown)" are "(unknown)" (which the
    filter takes both for); an engine in any case, as the engine choice
    compares it. With `names` the nodes take the spelling of another list
    (every alert, while the flow shows those of the filters)."""
    r = _run_node(ALERT_FILTER_JS, r"""
        const alerts = [
            { engine: 'Sigma', rule_name: '  Run Key ', process_name: 'MsMpEng.exe' },
            { engine: 'sigma', rule_name: 'run key', process_name: ' msmpeng.exe' },
            { engine: 'SIGMA', rule_name: 'RUN KEY', process_name: '', process_image: 'C:\\x\\MSMPENG.EXE' },
            { engine: 'Yara', rule_name: '', process_name: '   ' },
            { engine: 'Yara', rule_name: '(Unknown)', process_name: '(unknown)' },
            { engine: '', name: '   ', process_name: 'cmd.exe' },
            { engine: 'yara', rule_name: 'Beacon', process_name: 'Cmd.exe ' },
            { engine: 'Sigma', rule_name: 'Run key', process_name: 'MsMpEng.exe' },
        ];
        const flow = alertFlow(alerts);
        const into = id => flow.links.filter(l => l.target === id).reduce((sum, l) => sum + l.value, 0);
        const out = id => flow.links.filter(l => l.source === id).reduce((sum, l) => sum + l.value, 0);
        const listed = id => {
            const [, kind, name] = /^(engine|rule|process):([\s\S]*)$/.exec(id);
            return filterAlerts(alerts, { [kind]: name }).length;
        };
        const named = alertFlow(alerts.slice(1, 3), { names: alerts });
        // The engine choice compares an engine in any case but with its blanks
        const blanks = [{ engine: 'Sigma' }, { engine: ' sigma ' }, { engine: ' sigma ' }];
        console.log(JSON.stringify({
            columns: flow.columns, labels: flow.labels,
            rules: flow.columns[1].map(id => [id, into(id), listed(id)]),
            processes: flow.columns[2].map(id => [id, into(id), listed(id)]),
            engines: flow.columns[0].filter(id => id !== 'engine:').map(id => [id, out(id), listed(id)]),
            named: named.columns, unnamed: alertFlow(alerts.slice(1, 3)).columns,
            noList: alertFlow(alerts.slice(1, 3), { names: 'all' }).columns,
            blanks: alertFlow(blanks).columns[0].map(id => [id, filterAlerts(blanks, { engine: id.slice(7) }).length]),
        }));
    """, _prelude())
    assert r["columns"] == [["engine:Sigma", "engine:Yara", "engine:"],
                            ["rule:Run Key", "rule:(unknown)", "rule:Beacon"],
                            ["process:MsMpEng.exe", "process:(unknown)", "process:cmd.exe"]], \
        "a name with blanks or in other capitals, or without a name, is a node of its own"
    assert r["labels"]["rule:(unknown)"] == r["labels"]["process:(unknown)"] == r["labels"]["engine:"] == "(unknown)"
    assert r["labels"]["rule:Run Key"] == "Run Key", "the label keeps the blanks around the name"
    # Every node counts what its filter lists (an engine without a name has no filter of its own)
    for column in ("rules", "processes", "engines"):
        assert all(value == listed for _, value, listed in r[column]), f"{column}: {r[column]}"
    assert [value for _, value, _ in r["rules"]] == [4, 3, 1] and [v for _, v, _ in r["processes"]] == [4, 2, 2]
    # Named after the first spelling of `names`, not of the alerts drawn
    assert r["named"] == [["engine:Sigma"], ["rule:Run Key"], ["process:MsMpEng.exe"]]
    assert r["unnamed"] == [["engine:sigma"], ["rule:run key"], ["process:msmpeng.exe"]]
    assert r["noList"] == r["unnamed"], "names that are no list"
    assert r["blanks"] == [["engine: sigma ", 2], ["engine:Sigma", 1]], \
        "an engine with blanks shares a node with one the engine choice tells apart"


# Two sources into one sink, in true proportions: a 3, b 1, x 4. By hand: k =
# 90 / 4 (column 0: 100 px less one gap of 10); a 67.5 high at y 0, b 22.5 at
# y 77.5; x 90 high, centred at y 5; the columns at x 0 and 400 - 100 - 10 = 290.
SVG_LAYOUT = r"""
    const layout = layoutSankey([['a', 'b'], ['x']], [{ source: 'a', target: 'x', value: 3 }, { source: 'b', target: 'x', value: 1 }],
                                { width: 400, height: 100, nodeWidth: 10, gap: 10, scale: 'linear', labelWidth: 100 });
"""


@needs_node
def test_sankey_svg_draws_bands_between_their_nodes():
    r = _run_node(CHART_JS, SVG_LAYOUT + r"""
        const long = 'A'.repeat(200), longX = 'X'.repeat(200);
        const thin = layoutSankey([['big', 'small'], ['sink']], [{ source: 'big', target: 'sink', value: 1000 },
                                  { source: 'small', target: 'sink', value: 1 }], { height: 100, scale: 'linear' });
        console.log(JSON.stringify({
            layout,
            svg: sankeySvg(layout, { labels: { a: 'Alpha' } }),
            colored: sankeySvg(layout, { colors: { x: 'var(--accent-green)', b: '#ff0000' } }),
            byFunction: sankeySvg(layout, { colors: n => (n.id === 'a' ? 'var(--severity-high)' : undefined),
                                            labels: id => id.toUpperCase() }),
            long: sankeySvg(layout, { labels: { a: long, x: longX } }),
            thin, thinSvg: sankeySvg(thin),
            big: sankeySvg(layoutSankey([['s'], ['t']], [{ source: 's', target: 't', value: 9415 }])),
        }));
    """, _prelude())
    tree = _Tree(r["svg"])
    nodes = {g["attrs"]["data-sankey-node"]: g for g in tree.find("g", attr="data-sankey-node")}
    assert sorted(nodes) == ["a", "b", "x"]
    rects = {k: _child(g, "rect") for k, g in nodes.items()}
    assert {k: [_num(rc, a) for a in ("x", "y", "width", "height")] for k, rc in rects.items()} == \
        {"a": [0, 0, 10, 67.5], "b": [0, 77.5, 10, 22.5], "x": [290, 5, 10, 90]}
    bands = {tuple(json.loads(p["attrs"]["data-sankey-link"])): p for p in tree.find("path", attr="data-sankey-link")}
    assert sorted(bands) == [("a", "x"), ("b", "x")]
    # From the right edge of the source to the left edge of the target, as thick as the layout says at each end
    assert _close(_numbers(bands[("a", "x")]["attrs"]["d"]),
                  [10, 0, 150, 0, 150, 5, 290, 5, 290, 72.5, 150, 72.5, 150, 67.5, 10, 67.5])
    assert _close(_numbers(bands[("b", "x")]["attrs"]["d"]),
                  [10, 77.5, 150, 77.5, 150, 72.5, 290, 72.5, 290, 95, 150, 95, 150, 100, 10, 100])
    for (source, target), band in bands.items():
        assert (band["attrs"]["data-source"], band["attrs"]["data-target"]) == (source, target)
        assert _style(band)["fill"] == _style(rects[source])["fill"], "a band not in the colour of its source"
    assert bands[("a", "x")]["attrs"]["data-value"] == "3"
    assert _child(bands[("a", "x")], "title")["text"] == "Alpha \u2192 x: 3"
    assert _child(nodes["a"], "title")["text"] == "Alpha: 3" and nodes["x"]["attrs"]["data-value"] == "4"
    # The name, then the value, right of the node and at its height
    for key, name, value in (("a", "Alpha", "3"), ("b", "b", "1"), ("x", "x", "4")):
        text = _child(nodes[key], "text")
        assert text["text"].strip() == name and _child(text, "tspan")["text"] == value
        rc = rects[key]
        assert _num(text, "x") > _num(rc, "x") + _num(rc, "width")
        assert abs(_num(text, "y") - (_num(rc, "y") + _num(rc, "height") / 2)) <= 5
    assert _child(_child(_Tree(r["big"]).find("g", attr="data-sankey-node")[0], "text"), "tspan")["text"] == "9,415"
    assert _style(rects["a"])["fill"] != _style(rects["b"])["fill"], "the nodes of a column in one colour"
    colored = {g["attrs"]["data-sankey-node"]: _style(_child(g, "rect"))["fill"] for g in _Tree(r["colored"]).find("g")
               if "data-sankey-node" in g["attrs"]}
    assert colored["x"] == "var(--accent-green)" and colored["b"].startswith("var(--"), colored
    by_function = _Tree(r["byFunction"])
    fills = {g["attrs"]["data-sankey-node"]: _style(_child(g, "rect"))["fill"] for g in by_function.find("g", attr="data-sankey-node")}
    assert fills["a"] == "var(--severity-high)" and fills["b"].startswith("var(--")
    assert [_child(g, "text")["text"].strip() for g in by_function.find("g", attr="data-sankey-node")] == ["A", "B", "X"]
    # A long name is cut to the room up to the next column, less in the last column; its title has it in full
    cut = {g["attrs"]["data-sankey-node"]: g for g in _Tree(r["long"]).find("g", attr="data-sankey-node")}
    shown = {k: _child(cut[k], "text")["text"].strip() for k in ("a", "x")}
    assert all(s.endswith("\u2026") for s in shown.values()), shown
    assert 4 < len(shown["x"]) < len(shown["a"]) < 200, shown
    # At 10 px a monospace character is about 6 px wide: "<name> 3" ends before the next column (x 290), "<name> 4" in the chart
    for key, edge in (("a", _num(_child(cut["x"], "rect"), "x")), ("x", 400)):
        assert _num(_child(cut[key], "text"), "x") + (len(shown[key]) + 2) * 6 <= edge, f"the label of {key} runs on past {edge}"
    assert _child(cut["a"], "title")["text"] == "A" * 200 + ": 3" and _child(cut["x"], "title")["text"] == "X" * 200 + ": 4"
    # A flow of 1 into 1001 is drawn 1 px thick, around where it enters
    small = next(b for b in r["thin"]["links"] if b["source"] == "small")
    path = next(p for p in _Tree(r["thinSvg"]).find("path", attr="data-sankey-link") if p["attrs"]["data-source"] == "small")
    nums = _numbers(path["attrs"]["d"])
    assert small["thickness_t"] < 0.2 and nums[9] - nums[7] >= 1 - 1e-6, "a thin flow vanishes"
    assert _close([(nums[7] + nums[9]) / 2], [small["ty"] + small["thickness_t"] / 2], 0.01)
    assert "NaN" not in r["svg"] + r["thinSvg"] + r["long"]


# --- Hostile labels and colours ---------------------------------------------------

EVIL = "<img src=x onerror=alert(1)>"
QUOTE = 'x" onmouseover="alert(1)'


@needs_node
def test_chart_markup_escapes_labels():
    """Rule, process, file and category names come from the sample: in a
    chart, its tooltips, its legend and its data-* attributes they stay text,
    and a colour that is no theme variable is not written at all."""
    r = _run_node(CHART_JS, r"""
        const evil = EVIL, quote = QUOTE;
        const t0 = new Date(2026, 6, 14, 10).getTime();
        const bins = [{ start: t0, end: t0 + 3600000, counts: { [evil]: 2, [quote]: 1 }, total: 3 }];
        const items = [{ key: quote, label: evil, value: 3, color: 'var(--severity-high)' },
                       { key: evil, label: quote, value: 1, color: '"><img src=x onerror=alert(2)>' }];
        console.log(JSON.stringify({
            bars: stackedBarsSvg(bins, { keys: [evil, quote], colors: { [evil]: 'red;background:url(x)' } }),
            donut: donutSvg(items, { centerLabel: evil, centerSub: quote }),
            pie: pieSvg(items),
            legend: chartLegendHtml(items),
            scatter: scatterSvg([{ x: 1, y: 3, title: evil + ' "quoted"', key: quote, color: quote },
                                 { x: 2, y: null, title: quote, key: evil }], { thresholds: [{ y: 2, label: evil }] }),
            verdict: verdictBarsSvg([{ y: 3, title: evil + ' "quoted"', key: quote, color: quote },
                                     { y: null, title: quote, key: evil }], { thresholds: [{ y: 2, label: evil }] }),
            empty: chartEmptyHtml(evil),
        }));
    """.replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE)), _prelude())
    keyed = {"bars": "rect", "donut": "path", "pie": "path", "legend": "div", "scatter": "circle", "verdict": "g"}
    for name, markup in r.items():
        assert "<img" not in markup and "<script" not in markup, f"{name}: markup from a label: {markup}"
        tree = _Tree(markup)
        assert not tree.find("img")
        handlers = [(n["tag"], a) for n in tree.all for a in n["names"]
                    if a.startswith("on") or not re.fullmatch(r"[a-z][a-z0-9-]*", a)]
        assert not handlers, f"{name}: a label left its attribute: {handlers}"
        styles = [n["attrs"]["style"] for n in tree.all if "style" in n["attrs"]]
        assert not [s for s in styles if "url(" in s or "red;" in s or "<" in s or '"' in s], \
            f"{name}: a colour that is no variable: {styles}"
        if name in keyed:
            # The attribute keeps the whole key: it did not end at a quote
            keys = {n["attrs"]["data-key"] for n in tree.find(keyed[name], attr="data-key")}
            assert keys == {EVIL, QUOTE}, f"{name}: {keys}"
    titles = " ".join(t["text"] for t in _Tree(r["bars"]).find("title"))
    assert f"{EVIL}: 2" in titles and f"{QUOTE}: 1" in titles
    assert [t["text"] for t in _Tree(r["donut"]).find("text")] == [EVIL, QUOTE]
    assert {t["text"].split(":")[0] for t in _Tree(r["pie"]).find("title")} == {EVIL, QUOTE}
    assert [row["attrs"]["title"] for row in _Tree(r["legend"]).find(cls="chart-legend-row")] == [EVIL, QUOTE]
    assert sorted(t["text"] for t in _Tree(r["scatter"]).find("title")) == sorted([EVIL + ' "quoted"', QUOTE])
    assert EVIL + " 2" in [t["text"] for t in _Tree(r["scatter"]).find("text")]
    assert sorted(t["text"] for t in _Tree(r["verdict"]).find("title")) == sorted([EVIL + ' "quoted"', QUOTE])
    assert EVIL + " 2" in [t["text"] for t in _Tree(r["verdict"]).find("text")]
    assert _Tree(r["empty"]).find(cls="chart-empty")[0]["text"] == EVIL


@needs_node
def test_sankey_svg_escapes():
    """A rule <script>x</script>, a process a"b, an engine and a rule with
    markup and an & reach the flow as text: in the labels, the tooltips and
    the data-* attributes, which give back the exact ids of both ends of a
    band."""
    r = _run_node(CHART_JS, r"""
        const evil = EVIL;
        const alerts = [
            { engine: 'Sigma', rule_name: '<script>x</script>', process_name: 'a"b' },
            { engine: 'Sigma', rule_name: '<script>x</script>', process_name: 'a"b' },
            { engine: '<b>Yara</b>', rule_name: "R&D 'quoted'", process_name: evil },
        ];
        const flow = alertFlow(alerts);
        const colors = Object.fromEntries(flow.columns.flat().map(id => [id, 'red;background:url(x)']));
        console.log(JSON.stringify({
            svg: sankeySvg(layoutSankey(flow.columns, flow.links), { labels: flow.labels, colors }),
            ids: flow.columns.flat(), links: flow.links.map(l => [l.source, l.target]),
        }));
    """.replace("EVIL", json.dumps(EVIL)), _prelude())
    svg = r["svg"]
    assert "<script" not in svg and "<img" not in svg and "<b>" not in svg, svg
    tree = _Tree(svg)
    assert not tree.find("script") and not tree.find("img") and not tree.find("b")
    handlers = [(n["tag"], a) for n in tree.all for a in n["names"] if a.startswith("on") or not re.fullmatch(r"[a-z][a-z0-9-]*", a)]
    assert not handlers, f"a label left its attribute: {handlers}"
    styles = [n["attrs"]["style"] for n in tree.all if "style" in n["attrs"]]
    assert styles and not [s for s in styles if "url(" in s or "red;" in s], f"a colour that is no variable: {styles}"
    # The attributes keep the whole ids: a click finds the node, and both ends of a band
    assert sorted(g["attrs"]["data-sankey-node"] for g in tree.find("g", attr="data-sankey-node")) == sorted(r["ids"])
    bands = tree.find("path", attr="data-sankey-link")
    pairs = [json.loads(p["attrs"]["data-sankey-link"]) for p in bands]
    assert sorted(pairs) == sorted(r["links"])
    assert all([p["attrs"]["data-source"], p["attrs"]["data-target"]] == pair for p, pair in zip(bands, pairs))
    titles = {t["text"] for t in tree.find("title")}
    for title in ("<script>x</script>: 2", 'a"b: 2', EVIL + ": 1", "<b>Yara</b>: 1", "R&D 'quoted': 1",
                  "Sigma \u2192 <script>x</script>: 2", '<script>x</script> \u2192 a"b: 2',
                  "<b>Yara</b> \u2192 R&D 'quoted': 1", "R&D 'quoted' \u2192 " + EVIL + ": 1"):
        assert title in titles, f"{title!r} not among {titles}"
    labels = {t["text"].strip() for t in tree.find("text", cls="sankey-label")}
    assert {"<script>x</script>", 'a"b', "<b>Yara</b>", "R&D 'quoted'"} <= labels, labels


COLOUR_PROPERTIES = {"fill", "stroke", "color", "background", "background-color", "stop-color", "border-color"}
# A colour assigned by name in the source: fill="white", stroke: black, background:red
NAMED_COLOUR = re.compile(r"""\b(?:fill|stroke|color|background(?:-color)?|stop-color)\s*[:=]\s*["'`]?"""
                          r"""(white|black|red|green|blue|yellow|orange|gr[ae]y|purple|pink|cyan|magenta|silver|gold|"""
                          r"""navy|teal|lime|maroon|olive|aqua|fuchsia)\b""", re.I)


def _colours(markup):
    """Every colour of a piece of markup: presentation attributes and style declarations."""
    found = []
    for node in _Tree(markup).all:
        found += [value for name, value in node["attrs"].items() if name in COLOUR_PROPERTIES]
        found += [value for name, value in _style(node).items() if name in COLOUR_PROPERTIES]
    return found


@needs_node
def test_chart_colours_are_variables():
    """Every colour of a chart is a variable of the theme, so a theme switch
    recolours it: none is written in the source, and a colour passed in that
    is no variable gives way to the palette."""
    source = "\n".join([_strip_js_comments(_function_source(name)) for name in CHART_FUNCTIONS]
                       + [_strip_js_comments(_const_source(name)) for name in CHART_CONSTS])
    assert not LITERAL_COLOR.findall(source), LITERAL_COLOR.findall(source)
    named = [m.group(0) for m in NAMED_COLOUR.finditer(source)]
    assert not named, f"colours by name in the chart source: {named}"
    r = _run_node(CHART_JS, r"""
        const t0 = new Date(2026, 6, 14, 10).getTime();
        const bins = [{ start: t0, end: t0 + 3600000, counts: { critical: 1, high: 2, other: 1 }, total: 4 }];
        const flow = layoutSankey([['a', 'b'], ['c']], [{ source: 'a', target: 'c', value: 2 }, { source: 'b', target: 'c', value: 1 }]);
        const draw = color => {
            const items = [{ key: 'a', value: 2, color }, { key: 'b', value: 1, color }];
            return {
                bars: stackedBarsSvg(bins, { keys: SEVERITY_ORDER, colors: color === undefined ? SEVERITY_COLORS : { critical: color },
                                             selection: { from: t0, to: t0 + 1800000 } }),
                donut: donutSvg(items, { centerSub: 'ALERTS' }), pie: pieSvg(items), legend: chartLegendHtml(items),
                spark: sparklineSvg([1, 3, 2], { color }),
                scatter: scatterSvg([{ x: 1, y: 3, color }, { x: 2, y: null, color }], { thresholds: [{ y: 2, label: 'SUSPICIOUS' }] }),
                verdict: verdictBarsSvg([{ y: 3, color }, { y: null, color }], { thresholds: [{ y: 2, label: 'SUSPICIOUS' }] }),
                sankey: sankeySvg(flow, { colors: { a: color, c: color } }),
                sankeyByFunction: sankeySvg(flow, { colors: () => color }),
                empty: chartEmptyHtml('No alerts in this range'),
            };
        };
        console.log(JSON.stringify({
            severities: SEVERITY_ORDER.map(s => SEVERITY_COLORS[s]),
            drawn: [undefined, 'var(--accent-cyan)', '#ff0000', 'red', 'rgb(255, 0, 0)', 'var(--x);background:url(y)', '']
                .map(draw),
        }));
    """, _prelude())
    assert r["severities"] == [f"var(--severity-{s})" for s in ("critical", "high", "medium", "low", "info")]
    defined = set(_root_values())
    for drawn in r["drawn"]:
        for name, markup in drawn.items():
            colours = _colours(markup)
            if name != "empty":
                assert any(c.startswith("var(--") for c in colours), f"{name} draws without a theme colour: {markup}"
            for colour in colours:
                m = re.fullmatch(r"var\((--[\w-]+)\)", colour)
                assert colour in ("none", "transparent") or (m and m.group(1) in defined), \
                    f"{name}: {colour!r} is no variable of style.css :root"
            assert not re.search(r"#[0-9a-fA-F]{3,6}\b|rgb\(|\bred\b|url\(", markup), f"{name}: {markup}"


def _painted(rules, subject, prop):
    """A rule of style.css whose subject (the last compound of its selector)
    matches the regex `subject` and that sets `prop` from a theme variable."""
    for selector, body in rules.items():
        last = re.split(r"[\s>+~]+", selector.strip())[-1]
        if re.search(subject, last) and ":hover" not in last \
                and re.search(r"(?:^|;)\s*%s\s*:\s*(?:rgba\(\s*)?var\(--" % re.escape(prop), body):
            return selector
    return None


def _cls(name):
    return r"\.%s(?![\w-])" % re.escape(name)


@needs_node
def test_chart_parts_are_styled_in_both_themes():
    """SVG draws a line without a stroke not at all and text in black, which
    no theme can change: the lines and texts of a chart take their colour
    from a theme variable, its shapes and legend parts have their rules (a
    class written differently in app.js and style.css styles nothing). The
    chart cards of the views look like the other cards in Cyberpunk."""
    r = _run_node(CHART_JS, r"""
        const t0 = new Date(2026, 6, 14, 10).getTime();
        const bins = [{ start: t0, end: t0 + 3600000, counts: { high: 2 }, total: 2 }];
        const items = [{ key: 'a', value: 2 }, { key: 'b', value: 1 }];
        console.log(JSON.stringify([
            stackedBarsSvg(bins, { keys: ['high'], selection: { from: t0 } }), donutSvg(items, { centerSub: 'ALERTS' }),
            pieSvg(items), chartLegendHtml(items), sparklineSvg([1, 2]), chartEmptyHtml('No scans yet'),
            scatterSvg([{ x: 1, y: 3 }, { x: 2, y: null }], { thresholds: [{ y: 2, label: 'SUSPICIOUS' }] }),
            verdictBarsSvg([{ y: 3 }, { y: null }], { thresholds: [{ y: 2, label: 'SUSPICIOUS' }] }),
            sankeySvg(layoutSankey([['a', 'b'], ['c'], ['d']], [{ source: 'a', target: 'c', value: 2 },
                                   { source: 'b', target: 'c', value: 1 }, { source: 'c', target: 'd', value: 3 }])),
        ]));
    """, _prelude())
    rules = _rules(STYLE_CSS)
    nodes = [node for markup in r for node in _Tree(markup).all]
    shapes = {cls for node in nodes if node["tag"] not in ("svg", "g", "text", "title")
              for cls in node["attrs"].get("class", "").split()}
    unstyled = sorted(cls for cls in shapes | {"chart-svg"} if not any(re.search(_cls(cls), s) for s in rules))
    assert not unstyled, f"classes the charts write that style.css does not style: {unstyled}"
    unpainted = set()
    for node in nodes:
        own = node["attrs"].get("class", "").split()
        if node["tag"] == "line" and not any(_painted(rules, _cls(c), "stroke") for c in own):
            unpainted.add(f"line.{'.'.join(own)}: stroke")
        if node["tag"] == "text" and not (_painted(rules, r"^text$", "fill") or any(_painted(rules, _cls(c), "fill") for c in own)):
            unpainted.add(f"text.{'.'.join(own)}: fill")
        if node["tag"] == "rect" and node["attrs"].get("fill") == "none" and not any(_painted(rules, _cls(c), "fill") for c in own):
            unpainted.add(f"rect.{'.'.join(own)}: fill")
    assert not unpainted, f"chart parts without a colour from the theme: {sorted(unpainted)}"
    assert _painted(rules, _cls("chart-center-label"), "fill"), "the donut's centre takes the muted colour of the axis labels"
    for selector in (".chart-card", ".chart-card-head", ".chart-card-title", ".chart-card-tools", ".chart-split"):
        assert selector in rules, f"{selector} has no rule in style.css"
    legend = rules.get(".chart-legend-name", "")
    assert all(re.search(p, legend) for p in (r"overflow:\s*hidden", r"text-overflow:\s*ellipsis", r"white-space:\s*nowrap")), \
        "a 300-character name widens the legend"
    assert re.search(r"(?:^|;)\s*fill-opacity:\s*0?\.\d", rules.get(".sankey-link", "")), \
        "Sankey bands are opaque: a band hides the bands under it"
    assert _painted(rules, _cls("sankey-label"), "fill"), "a Sankey's names in the muted colour of its values"
    theme = _rules(THEME_CSS)
    card = theme.get('[data-theme="cyberpunk"] .chart-card', "")
    assert re.search(r"border:\s*var\(--cp-card-border\)", card) and re.search(r"box-shadow:", card)
    assert re.search(r"color:\s*var\(--", theme.get('[data-theme="cyberpunk"] .chart-card-title', ""))


# --- Alerts filters set by the charts: time range, category, rule, process -------

ALERT_FILTER_FUNCTIONS = ["filterAlerts", "alertSeverity", "alertRuleName", "alertProcessName", "alertCategory",
                          "_alertsTimeBound", "_alertsNameKey", "_alertNameIs"]
ALERT_FILTER_JS = CHART_JS + [f for f in ALERT_FILTER_FUNCTIONS if f not in CHART_JS]

# Six alerts as the engines write them: times in UTC (Z) and with an offset,
# the category as a list or as text in any case, the process by name or only
# by its image, an alert without a process, one without a rule and one
# without a time. The range 10:00 - 12:00 UTC of 14 July takes f2 (at its
# start), f3, and f4 (a millisecond before its end), but not f1 (a
# millisecond before its start), f5 (at its end) or f6.
ALERT_FILTER_FIXTURE = r"""
    const from = Date.UTC(2026, 6, 14, 10), to = Date.UTC(2026, 6, 14, 12);
    const alerts = [
        { id: 'f1', timestamp: '2026-07-14T09:59:59.999Z', severity: 'medium', engine: 'Sigma', category: ['registry'],
          rule_name: 'Registry Run Key Persistence', process_name: 'MsMpEng.exe' },
        { id: 'f2', timestamp: '2026-07-14T12:00:00+02:00', severity: 'High', engine: 'Sigma', category: 'Registry',
          rule_name: 'registry run key persistence', process_name: '',
          process_image: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe' },
        { id: 'f3', timestamp: '2026-07-14T11:30:00Z', severity: 'critical', engine: 'Yara',
          category: ['process', 'registry'], rule_name: 'Registry Run Key Persistence 2', process_name: 'powershell.exe' },
        { id: 'f4', timestamp: '2026-07-14T12:59:59.9990000+01:00', severity: 'medium', engine: 'fibratus',
          category: [' REGISTRY '], name: 'Credential access', process_name: ' ', process_image: '' },
        { id: 'f5', timestamp: '2026-07-14T14:00:00+02:00', severity: 'low', engine: 'Sigma', category: 'process',
          rule_name: '', process_name: 'msmpeng.exe' },
        { id: 'f6', timestamp: 'not a time', severity: 'high', engine: 'Sigma', category: 'registry',
          rule_name: 'Registry Run Key Persistence', process_name: 'MsMpEng.exe' },
    ];
    const ids = filter => filterAlerts(alerts, filter).map(a => a.id);
"""


@needs_node
@pytest.mark.parametrize("zone", ZONES)
def test_filter_alerts_range_category_rule_process(zone):
    """The filters a click on a chart sets: a time range (from included, to
    not, as the bins of a bar chart), a category (alertCategory: list or text,
    any case), a rule and a process (whole names in any case, the process as
    the table shows it); "(unknown)" is the chart's name for none. With the
    same filter the table lists exactly what the chart counted."""
    r = _run_node(ALERT_FILTER_JS, ALERT_FILTER_FIXTURE + r"""
        const order = alerts.map(a => a.id).join();
        const all = ids({});
        // What a chart counts, and what the table lists for its filter
        const counted = (key, counts, name) => counts.map(c => [c.count, filterAlerts(alerts, { [key]: name(c.key) }).length]);
        const flow = alertFlow(alerts);
        const into = id => flow.links.filter(l => l.target === id).reduce((sum, l) => sum + l.value, 0);
        const nodes = kind => flow.columns.flat().filter(id => id.startsWith(kind + ':'))
            .map(id => [into(id), filterAlerts(alerts, { [kind]: id.slice(kind.length + 1) || '(unknown)' }).length]);
        console.log(JSON.stringify({
            all,
            range: ids({ from, to }), fromOnly: ids({ from }), toOnly: ids({ to }),
            textAndDate: ids({ from: String(from), to: new Date(to) }),
            empty: [ids({ from, to: from }), ids({ from: to, to: from })],
            noBounds: [{ from: null, to: undefined }, { from: NaN, to: Infinity }, { from: 'abc', to: '' }, { from: {} }]
                .map(f => ids(f)),
            category: [ids({ category: 'registry' }), ids({ category: 'REGISTRY' }), ids({ category: ' registry ' }),
                       ids({ category: 'process' }), ids({ category: 'reg' })],
            rule: [ids({ rule: 'Registry Run Key Persistence' }), ids({ rule: 'REGISTRY RUN KEY PERSISTENCE' }),
                   ids({ rule: '  registry run key persistence ' }), ids({ rule: 'Registry Run Key' }),
                   ids({ rule: 'credential access' }), ids({ rule: '(unknown)' }), ids({ rule: '(Unknown)' })],
            process: [ids({ process: 'msmpeng.exe' }), ids({ process: 'MSMPENG.EXE' }), ids({ process: 'MsMpEng' }),
                      ids({ process: 'powershell.exe' }), ids({ process: '(unknown)' })],
            combined: [ids({ from, to, category: 'registry' }), ids({ from, to, category: 'registry', process: 'msmpeng.exe' }),
                       ids({ from, to, severities: ['high'] }), ids({ from, to, engine: 'SIGMA' }),
                       ids({ from, to, text: 'credential' }), ids({ from, to, rule: '(unknown)' })],
            none: ids({ category: '', rule: '  ', process: null }),
            bins: binByTime(alerts).bins.map(b => [b.total, filterAlerts(alerts, { from: b.start, to: b.end }).length]),
            categories: counted('category', countBy(alerts, alertCategory), key => key),
            rules: nodes('rule'), processes: nodes('process'),
            unchanged: alerts.map(a => a.id).join() === order,
        }));
    """, _prelude(zone))
    assert r["all"] == ["f5", "f4", "f3", "f2", "f1", "f6"]
    assert r["range"] == ["f4", "f3", "f2"], "the range takes its end, misses its start, or reads a time zone wrongly"
    assert r["fromOnly"] == ["f5", "f4", "f3", "f2"] and r["toOnly"] == ["f4", "f3", "f2", "f1"]
    assert r["textAndDate"] == r["range"], "a bound as text (a data-* attribute) or as a Date is not taken"
    assert r["empty"] == [[], []], "an empty or reversed range lists alerts"
    assert r["noBounds"] == [r["all"]] * 4, "a bound that is no time filters (an alert without a time is lost)"
    # registry as a list (f1, f4 with blanks and capitals) and as text (f2 "Registry", f6); f3 starts with process
    assert r["category"] == [["f4", "f2", "f1", "f6"]] * 3 + [["f5", "f3"], []]
    # Whole names in any case: "... Persistence 2" is another rule, and the name of a rule is no part of it
    assert r["rule"] == [["f2", "f1", "f6"]] * 3 + [[], ["f4"], ["f5"], ["f5"]]
    # The process as the table names it: f2 by its image only; f4 has none ("(unknown)" in the charts)
    assert r["process"] == [["f5", "f2", "f1", "f6"]] * 2 + [[], ["f3"], ["f4"]]
    assert r["combined"] == [["f4", "f2"], ["f2"], ["f2"], ["f2"], ["f4"], []]
    assert r["none"] == r["all"], "an empty name filters"
    # The round trip: every bar, category, rule and process node counts what its filter lists
    assert sum(t for t, _ in r["bins"]) == 5 and all(t == n for t, n in r["bins"]), r["bins"]
    assert r["categories"] == [[4, 4], [2, 2]]
    assert sorted(r["rules"]) == [[1, 1], [1, 1], [1, 1], [3, 3]], r["rules"]
    assert sorted(r["processes"]) == [[1, 1], [1, 1], [4, 4]], r["processes"]
    assert r["unchanged"], "filterAlerts sorted the list in place"


@needs_node
@pytest.mark.parametrize("zone", ZONES)
def test_chart_range_label_names_local_days_and_times(zone):
    """The chip of a time range in local time: whole days by their dates (the
    last one included, as the tooltip of a week's bar), other ranges with
    their times (hours 00-23, the end not included; with seconds where an end
    is not on a full minute)."""
    r = _run_node(["chartRangeLabel", "_chartDate", "_chartClock", "_chartPeriodStart"], r"""
        const at = (...a) => new Date(...a).getTime();          // local time of the zone
        console.log(JSON.stringify([
            chartRangeLabel(at(2026, 6, 14), at(2026, 6, 21)),
            chartRangeLabel(at(2026, 6, 14), at(2026, 6, 15)),
            chartRangeLabel(at(2026, 2, 29), at(2026, 2, 30)),                  // 23 hours in Europe
            chartRangeLabel(at(2026, 9, 25), at(2026, 9, 26)),                  // 25 hours in Europe
            chartRangeLabel(at(2026, 6, 14, 22), at(2026, 6, 14, 23)),
            chartRangeLabel(at(2026, 6, 14, 23), at(2026, 6, 15)),
            chartRangeLabel(at(2026, 10, 3, 14, 23, 5), at(2026, 10, 10, 14, 23, 5)),
            chartRangeLabel(at(2026, 6, 14), null), chartRangeLabel(null, at(2026, 6, 21)),
            chartRangeLabel(at(2026, 10, 3, 14, 23), null),
            chartRangeLabel(at(2025, 11, 29), at(2026, 0, 5)),
            chartRangeLabel(at(2025, 11, 31), at(2026, 0, 1)),
            chartRangeLabel(at(2026, 6, 14), at(2026, 6, 14)),
            chartRangeLabel(null, null),
        ]));
    """, _prelude(zone))
    assert r == ["14 Jul \u2013 20 Jul", "14 Jul", "29 Mar", "25 Oct", "14 Jul 22:00\u201323:00",
                 "14 Jul 23:00 \u2013 15 Jul 00:00", "03 Nov 14:23:05 \u2013 10 Nov 14:23:05", "from 14 Jul",
                 "before 21 Jul", "from 03 Nov 14:23", "29 Dec 2025 \u2013 04 Jan 2026", "31 Dec",
                 "14 Jul 00:00 \u2013 14 Jul 00:00", ""]


@needs_node
@pytest.mark.parametrize("zone", ZONES)
def test_chart_range_label_names_seconds_when_needed(zone):
    """A range of bars of seconds is named to the second: as soon as one of
    its ends is not on a full minute of local time (by its seconds or its
    milliseconds), both ends show their seconds. A range on full minutes is
    named as before."""
    r = _run_node(["chartRangeLabel", "_chartDate", "_chartClock", "_chartPeriodStart"], r"""
        const at = (...a) => new Date(...a).getTime();          // local time of the zone
        console.log(JSON.stringify([
            chartRangeLabel(at(2026, 6, 27, 11, 45, 10), at(2026, 6, 27, 11, 45, 40)),
            chartRangeLabel(at(2026, 6, 27, 11, 45), at(2026, 6, 27, 12)),
            chartRangeLabel(at(2026, 6, 27), at(2026, 6, 28)),
            chartRangeLabel(at(2026, 6, 27, 23, 59, 30), at(2026, 6, 28, 0, 0, 30)),
            // One end off the minute (by a second or a millisecond), or the only end
            chartRangeLabel(at(2026, 6, 27, 11, 45), at(2026, 6, 27, 11, 45, 30)),
            chartRangeLabel(at(2026, 6, 27, 11, 45, 0, 500), at(2026, 6, 27, 12)),
            chartRangeLabel(at(2026, 6, 27, 11, 45, 10), null), chartRangeLabel(null, at(2026, 6, 27, 11, 45, 10)),
        ]));
    """, _prelude(zone))
    assert r == ["27 Jul 11:45:10\u201311:45:40", "27 Jul 11:45\u201312:00", "27 Jul",
                 "27 Jul 23:59:30 \u2013 28 Jul 00:00:30", "27 Jul 11:45:00\u201311:45:30",
                 "27 Jul 11:45:00\u201312:00:00", "from 27 Jul 11:45:10", "before 27 Jul 11:45:10"]


# The Alerts tab of index.html in the test DOM (SORT_DOM: markup is parsed,
# clicks run the inline handlers); its time zone is UTC
ALERTS_TAB_DOM = r"""
    document.body.innerHTML = MARKUP;
    const $ = id => document.getElementById(id);
    $('tab-alerts').scrollTop = 0;
    globalThis.switchTab = name => { state.activeTab = name; if (name === 'alerts') renderAlertsTab(); };
"""


@needs_node
def test_active_filter_chips_are_removable():
    """A filter a chart sets shows as a chip in the filter bar; a click on its
    × takes off that filter only, and the table lists the alerts of the
    filters left. From the keyboard the focus moves on to the next chip (the
    search box after the last one). Names from the data stay text."""
    script = ALERTS_TAB_DOM + r"""
        const alerts = [
            { id: 'c1', timestamp: '2026-07-13T23:59:59Z', severity: 'high', engine: 'Sigma', category: ['registry'],
              rule_name: 'Run Key', process_name: 'MsMpEng.exe' },
            { id: 'c2', timestamp: '2026-07-14T00:00:00Z', severity: 'medium', engine: 'Sigma', category: ['registry'],
              rule_name: 'Run Key', process_name: 'MsMpEng.exe' },
            { id: 'c3', timestamp: '2026-07-16T12:00:00+02:00', severity: 'medium', engine: 'Sigma', category: 'process',
              rule_name: 'Encoded PowerShell', process_name: 'powershell.exe' },
            { id: 'c4', timestamp: '2026-07-20T23:59:59.999Z', severity: 'high', engine: 'Yara', category: 'Registry',
              rule_name: 'Winlogon Helper', process_name: '', process_image: '' },
            { id: 'c5', timestamp: '2026-07-21T00:00:00Z', severity: 'high', engine: 'Sigma', category: ['registry'],
              rule_name: 'Run Key', process_name: 'MsMpEng.exe' },
        ];
        globalThis.state = { alerts, processes: {}, activeTab: 'dashboard' };
        const holder = $('alerts-active-filters');
        const chips = () => holder.querySelectorAll('.alerts-filter-chip');
        const chip = kind => chips().find(c => c.getAttribute('data-filter') === kind);
        const view = () => ({
            chips: chips().map(c => c.textContent.replace(/\s+/g, ' ').trim()), hidden: holder.hidden,
            ids: $('alerts-rows').querySelectorAll('tr.alerts-row')
                .map(row => /openAlertDetailById\("(\w+)"\)/.exec(row.getAttribute('onclick'))[1]),
            count: $('alerts-count').textContent,
        });
        const focused = () => document.activeElement && (document.activeElement.getAttribute('data-filter')
                                                         || document.activeElement.id);
        const from = new Date(2026, 6, 14).getTime(), to = new Date(2026, 6, 21).getTime();
        const r = { start: view() };
        openAlertsTab({ from, to, category: 'registry' });
        r.both = { ...view(), tab: state.activeTab, kinds: chips().map(c => c.getAttribute('data-filter')),
                   handlers: chips().map(c => c.getAttribute('onclick')), titles: chips().map(c => c.getAttribute('title')),
                   listed: filterAlerts(alerts, { from, to, category: 'registry' }).length };
        click(chip('category').querySelector('.alerts-filter-chip-x'));
        r.range = { ...view(), filter: { ...alertsExtraFilter }, bounds: [from, to] };
        openAlertsTab({ from, to, rule: 'Run Key', process: 'msmpeng.exe' });
        r.three = view();
        // New alerts with the same filters: the chips stay as they are (a chip keeps the focus)
        const ruleChip = chip('rule');
        ruleChip.focus();
        state.alerts = [...alerts, { id: 'c6', timestamp: '2026-07-15T08:00:00Z', severity: 'low', engine: 'Sigma',
                                     category: ['registry'], rule_name: 'Run Key', process_name: 'MsMpEng.exe' }];
        renderAlertsTab();
        r.refreshed = { ...view(), kept: chip('rule') === ruleChip && document.activeElement === ruleChip };
        state.alerts = alerts; renderAlertsTab();
        chip('rule').focus(); click(chip('rule'));
        r.keyboard = [[view().chips, view().ids, focused()]];
        click(chip('process')); r.keyboard.push([view().chips, view().ids, focused()]);
        click(chip('range')); r.keyboard.push([view().chips, view().ids, focused(), holder.hidden]);
        openAlertsTab({ rule: EVIL, process: QUOTE, category: '<b>x</b>' });
        r.hostile = { ...view(), markup: ['img', 'b', 'script'].map(tag => holder.querySelectorAll(tag).length),
                      values: chips().map(c => c.querySelector('.alerts-filter-chip-value').textContent),
                      titles: chips().map(c => c.getAttribute('title')),
                      attrs: chips().map(c => Object.keys(c.attrs).sort().join(' ')),
                      empty: /No alerts match the filters/.test($('alerts-rows').textContent) };
        openAlertsTab({ process: '(unknown)' }); r.unknown = view();
        // A chart sets a filter and keeps the others; the chip writes the name as given last
        setAlertsFilters({ rule: 'run key' }); setAlertsFilters({ rule: 'Run Key' }); r.added = view();
        openAlertsTab({ severities: ['high'] }); r.reset = view();
        console.log(JSON.stringify(r));
    """
    script = (script.replace("MARKUP", json.dumps(_tab_markup("alerts")))
              .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE)))
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    assert r["start"] == {"chips": [], "hidden": True, "ids": [], "count": ""}, "the template shows a chip row"
    both = r["both"]
    assert both["chips"] == ["\u00d7 14 Jul \u2013 20 Jul", "\u00d7 category: registry"] and not both["hidden"]
    assert (both["ids"], both["count"], both["listed"], both["tab"]) == (["c4", "c2"], "2 of 5", 2, "alerts")
    assert both["kinds"] == ["range", "category"]
    assert both["handlers"] == ['removeAlertsFilter("range")', 'removeAlertsFilter("category")']
    assert both["titles"] == ["Remove the time range 2026-07-14 00:00:00 \u2013 2026-07-21 00:00:00 (end not included)",
                              "Remove the category filter: registry"]
    # The × of the category takes off the category only
    assert r["range"]["chips"] == ["\u00d7 14 Jul \u2013 20 Jul"]
    assert (r["range"]["ids"], r["range"]["count"]) == (["c4", "c3", "c2"], "3 of 5")
    assert r["range"]["filter"] == {"from": r["range"]["bounds"][0], "to": r["range"]["bounds"][1], "category": None,
                                    "rule": None, "process": None}
    assert r["three"]["chips"] == ["\u00d7 14 Jul \u2013 20 Jul", "\u00d7 rule: Run Key", "\u00d7 process: msmpeng.exe"]
    assert r["three"]["ids"] == ["c2"]
    assert (r["refreshed"]["ids"], r["refreshed"]["count"]) == (["c6", "c2"], "2 of 6")
    assert r["refreshed"]["kept"], "new alerts rebuilt the chips: the chip in focus lost it"
    assert r["keyboard"] == [
        [["\u00d7 14 Jul \u2013 20 Jul", "\u00d7 process: msmpeng.exe"], ["c2"], "process"],
        [["\u00d7 14 Jul \u2013 20 Jul"], ["c4", "c3", "c2"], "range"],
        [[], ["c5", "c4", "c3", "c2", "c1"], "alerts-filter-text", True],
    ], "a chip took other filters with it, or the focus got lost with its chip"
    hostile = r["hostile"]
    assert hostile["chips"] == ["\u00d7 category: <b>x</b>", f"\u00d7 rule: {EVIL}", f"\u00d7 process: {QUOTE}"]
    assert hostile["markup"] == [0, 0, 0] and hostile["values"] == ["<b>x</b>", EVIL, QUOTE]
    assert hostile["titles"] == ["Remove the category filter: <b>x</b>", f"Remove the rule filter: {EVIL}",
                                 f"Remove the process filter: {QUOTE}"]
    assert set(hostile["attrs"]) == {"aria-label class data-filter onclick title type"}, "a name left its attribute"
    assert hostile["empty"] and hostile["count"] == "0 of 5"
    assert (r["unknown"]["chips"], r["unknown"]["ids"]) == (["\u00d7 process: (unknown)"], ["c4"])
    assert r["added"]["chips"] == ["\u00d7 rule: Run Key", "\u00d7 process: (unknown)"], \
        "a chart's filter took the others off, or its chip keeps an old spelling"
    assert r["added"]["ids"] == [], "c4, the alert without a process, has another rule"
    # openAlertsTab sets exactly the filters it is given
    assert r["reset"] == {"chips": [], "hidden": True, "ids": ["c5", "c4", "c1"], "count": "3 of 5"}


@needs_node
def test_the_alerts_table_head_stands_under_the_filter_bar():
    """The tab scrolls as a whole: the filter bar stands right under the
    drilldown bar, the table head right under both; each bar grows with its
    contents (the chips, the path) and when it wraps, so each one's border
    box, the height the bars below have to clear, is followed: the drilldown
    bar's on the tab (--alerts-path-height, 0 px while it is hidden), the
    filter bar's on the head (--alerts-bar-height). The charts above the
    filter bar are drawn again when their width changes, in the next frame.
    OVER TIME takes a range drawn across its bars, once however often it is
    set up, and also without ResizeObserver. A page without the tab or
    without ResizeObserver starts all the same."""
    functions = ["initAlertsTab", "_followBarHeight"] + BARS_BRUSH_FUNCTIONS
    presses = "$('alerts-time-chart').listeners.filter(l => l.type === 'pointerdown').length"
    r = _run_node(functions, r"""
        const $ = id => document.getElementById(id);
        const resizers = [], frames = [];
        let redraws = 0;
        globalThis.ResizeObserver = class {
            constructor(callback) { this.callback = callback; resizers.push(this); }
            observe(el, options) { this.el = el; this.options = options; }
        };
        globalThis.requestAnimationFrame = fn => frames.push(fn);
        globalThis.redrawAlertsChartsOnResize = () => redraws++;
        document.body.innerHTML = MARKUP;
        const tab = $('tab-alerts'), drillBar = $('alerts-drill');
        const bar = document.querySelector('#tab-alerts .alerts-filters'), head = document.querySelector('#alerts-table thead');
        for (const el of [tab, head]) el.style.setProperty = (name, value) => { el.style[name] = value; };
        drillBar.rect = { top: 0, height: 38.5 };
        bar.rect = { top: 0, height: 45.5 };
        initAlertsTab();
        const r = { observed: resizers.map(o => [o.el.id || o.el.className, o.options || null]), presses: PRESSES };
        const observer = el => resizers.find(o => o.el === el);
        observer(drillBar).callback([]); observer(bar).callback([]);
        r.first = [tab.style['--alerts-path-height'], head.style['--alerts-bar-height']];
        drillBar.rect = { top: 0, height: 0 };      // hidden: no step
        bar.rect = { top: 0, height: 79 };          // a row of chips
        observer(drillBar).callback([]); observer(bar).callback([]);
        r.chips = [tab.style['--alerts-path-height'], head.style['--alerts-bar-height']];
        r.onHead = '--alerts-path-height' in head.style || '--alerts-bar-height' in tab.style;
        observer($('alerts-charts')).callback([]); r.resized = [redraws, frames.length];
        frames.splice(0).forEach(fn => fn()); r.drawn = redraws;
        document.body.innerHTML = '';
        try { initAlertsTab(); r.noTab = 'ok'; } catch (e) { r.noTab = e.message; }
        document.body.innerHTML = MARKUP;
        delete globalThis.ResizeObserver;
        try { initAlertsTab(); r.noObserver = 'ok'; } catch (e) { r.noObserver = e.message; }
        console.log(JSON.stringify(r));
    """.replace("MARKUP", json.dumps(_tab_markup("alerts"))).replace("PRESSES", presses), SORT_DOM + _alerts_prelude())
    assert sorted(r["observed"], key=json.dumps) == sorted([["alerts-drill", {"box": "border-box"}],
                                                           ["alerts-filters", {"box": "border-box"}],
                                                           ["alerts-charts", None]], key=json.dumps), \
        f"a bar's height without its border, or the bars or the charts not watched: {r['observed']}"
    assert (r["first"], r["chips"]) == (["38.5px", "45.5px"], ["0px", "79px"])
    assert r["onHead"] is False, "a bar's height is kept on the wrong element"
    assert r["resized"] == [0, 1] and r["drawn"] == 1, "the charts are drawn again inside the observer, or not at all"
    assert r["noTab"] == "ok" and r["noObserver"] == "ok"
    assert r["presses"] == 1, "OVER TIME takes no range drawn across its bars"
    # A page without ResizeObserver, set up twice: its bars take each press once, the page its moves and ends
    bare = _run_node(functions, r"""
        const $ = id => document.getElementById(id);
        document.body.innerHTML = MARKUP;
        initAlertsTab();
        initAlertsTab();
        console.log(JSON.stringify({ presses: PRESSES, page: document.listeners.map(l => l.type) }));
    """.replace("MARKUP", json.dumps(_tab_markup("alerts"))).replace("PRESSES", presses), SORT_DOM + _alerts_prelude())
    assert bare == {"presses": 1, "page": ["pointermove", "pointerup", "pointercancel", "contextmenu"]}, \
        f"without ResizeObserver OVER TIME takes no range drawn across its bars, or takes each press twice: {bare}"
    js = _strip_js_comments(_read(APP_JS))
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    assert re.search(r"^\s*initAlertsTab\(\);", js[start:js.index("\n});", start)], re.M), "not set up at start-up"


def _background(body):
    m = re.search(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;]+)", body or "")
    return m.group(1).strip() if m else None


def _declared(body, prop):
    """The value a rule body gives `prop`: its last declaration (None for none)."""
    values = re.findall(r"(?:^|;)\s*%s\s*:\s*([^;]+)" % re.escape(prop), body or "")
    return re.sub(r"\s+", " ", values[-1]).strip() if values else None


def test_the_alerts_tab_scrolls_as_a_whole_under_a_standing_filter_bar():
    """The tab scrolls as a whole and the table has no scrolling of its own;
    the filter bar stands at the top of the tab (in Cyberpunk under the fixed
    top bar: the tab begins below it), right under the drilldown bar while a
    step shows it (--alerts-path-height, 0 px without), opaque in both
    themes, so the rows pass under it unseen; the table head stands right
    under both bars. The chip row takes no room while there is no chip, and a
    long name is cut."""
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    assert re.search(r"(?:^|;)\s*overflow-y:\s*auto", rules.get("#tab-alerts", "")), "the tab does not scroll"
    wrap = rules.get(".alerts-table-wrap", "")
    assert not re.search(r"overflow(?:-y)?:\s*(?:auto|scroll)|min-height:\s*0", wrap), "the table scrolls on its own"
    assert re.search(r"(?:^|;)\s*flex:\s*1 0 auto", wrap), "the table shrinks into the tab instead of making it scroll"
    bar = rules.get(".alerts-filters", "")
    assert re.search(r"position:\s*sticky", bar) and _declared(bar, "top") == "var(--alerts-path-height)", \
        "the filter bar scrolls away, or does not stand right under the drilldown bar"
    head = rules.get(".alerts-table thead th", "")
    assert re.search(r"position:\s*sticky", head) \
        and _declared(head, "top") == "calc(var(--alerts-path-height) + var(--alerts-bar-height))", \
        "the table head stands under the bars instead of right below them"
    def layer(body):
        return int(re.search(r"z-index:\s*(\d+)", body).group(1))

    assert layer(bar) > layer(head), "the table head passes over the filter bar"
    assert "--alerts-bar-height" in _root_values() and _root_values().get("--alerts-path-height") == "0px"
    cyberpunk_bar = theme.get('[data-theme="cyberpunk"] .alerts-filters', "")
    for name, palette, value in (("Classic", _resolve(_root_values()), _background(bar)),
                                 ("Cyberpunk", _cyberpunk_palette(), _background(cyberpunk_bar) or _background(bar))):
        colour = re.sub(r"var\(\s*(--[\w-]+)\s*\)", lambda m: palette[m.group(1)], value or "")
        assert re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", colour), f"{name}: the rows show through the bar ({value})"
    # Cyberpunk moves neither the bar nor the scrolling: the tab begins below the fixed top bar
    assert re.search(r"padding-top:\s*var\(--topbar-height\)", theme.get('[data-theme="cyberpunk"] #app', ""))
    for selector, body in theme.items():
        if re.search(r"\.alerts-filters$|#tab-alerts$|\.tab-content$|\.alerts-table-wrap$", selector):
            assert not re.search(r"(?:^|;)\s*(?:position|top|overflow(?:-[xy])?)\s*:", body), selector
    # The chips
    assert re.search(r"display:\s*none", rules.get(".alerts-active-filters[hidden]", "")), "an empty chip row takes room"
    assert re.search(r"flex:\s*1 0 100%", rules.get(".alerts-active-filters", "")), "the chips do not get a row of their own"
    for cls in ("alerts-filter-chip", "alerts-filter-chip-x", "alerts-filter-chip-kind", "alerts-filter-chip-value"):
        assert any(re.search(_cls(cls), s) for s in rules), f".{cls} has no rule in style.css"
    for cls in ("alerts-filter-chip", "alerts-filter-chip-x"):
        assert any(re.search(_cls(cls), s) for s in theme), f".{cls} has no Cyberpunk rule"
    value = rules.get(".alerts-filter-chip-value", "")
    assert all(re.search(p, value) for p in (r"overflow:\s*hidden", r"text-overflow:\s*ellipsis", r"white-space:\s*nowrap",
                                             r"min-width:\s*0")), "a 300-character name widens the chip"
    assert re.search(r"max-width:\s*100%", rules.get(".alerts-filter-chip", "")), "a chip runs out of the bar"


# --- The charts of the Alerts tab -------------------------------------------------

# 2,345 alerts over 40 days, more than the 2000 rows the table shows. The
# severities in any case, the server's "unknown" and two no chip names (one
# that cssToken would turn into "high"); engines in three spellings, one alert
# in ten without an engine; rules and processes with blanks around them, in
# other capitals, without a name, named "(Unknown)" and hostile (EVIL,
# QUOTE); times in UTC and with an offset; about one alert in 50 without a
# time (not a time, or none at all).
ALERT_CHARTS_FIXTURE = r"""
    const DAY = 86400000, HOUR = 3600000, t0 = Date.UTC(2026, 6, 14, 9);
    const pick = (list, i) => list[i % list.length];
    const SEVERITIES = ['medium', 'High', 'medium', 'critical', 'MEDIUM', 'low', 'unknown', 'high', '', 'High!', 'Warning'];
    const ENGINES = ['Sigma', 'sigma', 'Sigma', 'SIGMA', 'yara', 'Sigma', 'fibratus', 'Sigma', 'Yara', ''];
    const RULES = ['Run Key', ' run key ', 'Run Key', 'RUN KEY', 'Run Key', 'encoded powershell', 'Encoded PowerShell',
                   EVIL, EVIL, '', '(Unknown)', 'Winlogon Helper', 'WMI Subscription', 'COFF Loader', 'CobaltStrike', 'DPAPI'];
    const PROCESSES = [['MsMpEng.exe'], ['msmpeng.exe '], ['MsMpEng.exe'], ['MsMpEng.exe'], ['MSMPENG.EXE'],
                       ['', 'C:\\Windows\\powershell.exe'], ['powershell.exe'], [''], ['', ''], [QUOTE], [QUOTE],
                       ['svchost.exe'], ['explorer.exe'], ['msedge.exe'], ['beacon.exe'], ['lsass.exe'], ['cmd.exe']];
    const alerts = Array.from({ length: 2345 }, (_, i) => {
        const [process_name, process_image] = pick(PROCESSES, i * 7);
        const t = t0 + ((i * 7919) % 40) * DAY + (i % 23) * HOUR + (i % 60) * 60000;
        const timestamp = i % 97 === 5 ? 'not a time' : i % 101 === 7 ? undefined
            : i % 2 ? new Date(t).toISOString() : new Date(t + 2 * HOUR).toISOString().replace('Z', '+02:00');
        return { id: 'k' + i, timestamp, severity: pick(SEVERITIES, i), engine: pick(ENGINES, i * 3), category: 'registry',
                 rule_name: pick(RULES, i * 3), process_name, process_image, pid: 1000 + (i % 50) };
    });
"""

# What the charts of the tab show: their parts with the numbers they carry,
# their notes and hints, their table views, and the count and rows of the table
ALERT_CHARTS_LOOK = r"""
    const num = text => Number(String(text).replace(/,/g, ''));
    const hint = el => (el.querySelector('.chart-empty') || { textContent: null }).textContent;
    const tableOf = id => {
        const table = $(id).querySelector('table');
        const rows = table ? table.tBodies[0].rows : [];
        return table && {
            id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
            head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
            rows: rows.filter(row => !row.hasAttribute('data-sort-skip'))
                .map(row => row.cells.map(c => [c.textContent.trim(), c.getAttribute('data-sort-value')])),
            notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()),
        };
    };
    const pie = id => ({
        slices: $(id).querySelectorAll('.chart-seg').map(s => [s.getAttribute('data-key'), Number(s.getAttribute('data-value')),
                                                              s.tagName.toLowerCase(), s.classList.contains('chart-inert')]),
        colors: Object.fromEntries($(id).querySelectorAll('.chart-seg')
            .map(s => [s.getAttribute('data-key'), (s.getAttribute('style') || '').replace(/^fill:/, '')])),
        legend: $(id).querySelectorAll('.chart-legend-row').map(row => [row.getAttribute('data-key'),
            row.querySelector('.chart-legend-name').textContent, num(row.querySelector('.chart-legend-count').textContent),
            row.querySelector('.chart-legend-pct').textContent, row.classList.contains('chart-inert')]),
        empty: hint($(id)),
    });
    const charts = () => {
        const time = $('alerts-time-chart'), flow = $('alerts-flow-chart'), note = time.querySelector('.alerts-time-missed');
        return {
            severity: pie('alerts-severity-chart'), engine: pie('alerts-engine-chart'),
            bins: time.querySelectorAll('.chart-bin').map(g => [Number(g.getAttribute('data-bin-start')),
                Number(g.getAttribute('data-bin-end')), Number(g.getAttribute('data-total')),
                Object.fromEntries(g.querySelectorAll('.chart-bar').map(b => [b.getAttribute('data-key'), Number(b.getAttribute('data-count'))]))]),
            inertBins: time.querySelectorAll('.chart-bin').map(g => g.classList.contains('chart-inert')),
            // Each key's fills over all the bars (one, if a key has one colour everywhere)
            barFills: (() => {
                const fills = new Map();
                time.querySelectorAll('.chart-bar').forEach(b => {
                    const key = b.getAttribute('data-key');
                    if (!fills.has(key)) fills.set(key, new Set());
                    fills.get(key).add((b.getAttribute('style') || '').replace(/^fill:/, ''));
                });
                return Object.fromEntries([...fills].map(([key, set]) => [key, [...set].join(' ')]));
            })(),
            untimed: note ? note.textContent.trim() : null, timeEmpty: hint(time),
            nodes: flow.querySelectorAll('.sankey-node').map(g => [g.getAttribute('data-sankey-node'), Number(g.getAttribute('data-value')),
                                                                   g.classList.contains('chart-inert')]),
            nodeColors: Object.fromEntries(flow.querySelectorAll('.sankey-node').map(g => [g.getAttribute('data-sankey-node'),
                (g.querySelector('.sankey-bar').getAttribute('style') || '').replace(/^fill:/, '')])),
            bands: flow.querySelectorAll('.sankey-link').map(p => [p.getAttribute('data-source'), p.getAttribute('data-target'),
                Number(p.getAttribute('data-value')), p.classList.contains('chart-inert'), p.querySelector('title').textContent]),
            flowEmpty: hint(flow),
            count: $('alerts-count').textContent,
            rows: $('alerts-rows').querySelectorAll('tr.alerts-row').length,
            limit: !!$('alerts-rows').querySelector('tr.alerts-limit-row'),
            tables: { severity: tableOf('alerts-severity-table'), engine: tableOf('alerts-engine-table'),
                      time: tableOf('alerts-time-table'), flow: tableOf('alerts-flow-table') },
        };
    };
"""


def _alert_charts_script(script):
    return ((ALERTS_TAB_DOM + ALERT_CHARTS_FIXTURE + ALERT_CHARTS_LOOK + script)
            .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE))
            .replace("MARKUP", json.dumps(_tab_markup("alerts"))))


def _untimed(view):
    """The alerts the note under OVER TIME counts as without a time."""
    if view["untimed"] is None:
        return 0
    m = re.fullmatch(r"([\d,]+) without time", view["untimed"])
    assert m, view["untimed"]
    return int(m.group(1).replace(",", ""))


def _chart_totals(view):
    """The count of the table ("n of m") and what each chart and table view adds up to."""
    n = int(view["count"].split(" of ")[0])
    bands, tables = view["bands"], view["tables"]
    column = lambda name, col: sum(int(row[col][1]) for row in tables[name]["rows"])
    return n, {
        "severity slices": sum(value for _, value, *_ in view["severity"]["slices"]),
        "severity legend": sum(row[2] for row in view["severity"]["legend"]),
        "severity table": column("severity", 1),
        "engine slices": sum(value for _, value, *_ in view["engine"]["slices"]),
        "engine legend": sum(row[2] for row in view["engine"]["legend"]),
        "engine table": column("engine", 1),
        "bars + without time": sum(total for _, _, total, _ in view["bins"]) + _untimed(view),
        # The Total column (the 7th): an "Other" column comes after it
        "time table + without time": column("time", 6) + sum(
            int(re.fullmatch(r"([\d,]+) without time", note).group(1).replace(",", "")) for note in tables["time"]["notes"]
            if re.fullmatch(r"([\d,]+) without time", note)),
        "flow from the engines": sum(value for source, _, value, *_ in bands if source.startswith("engine:")),
        "flow into the processes": sum(value for _, target, value, *_ in bands
                                       if target.startswith("process:") or target == "other processes"),
        "engine nodes": sum(value for node, value, _ in view["nodes"] if node.startswith("engine:")),
        "flow table / 2": column("flow", 2) / 2,
    }


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "Asia/Kolkata"])
def test_alerts_chart_totals_match_the_table(zone):
    """Every chart of the Alerts tab counts the alerts of the filters, all of
    them: the slices of SEVERITY and ENGINE, the bars of OVER TIME with its
    note of the alerts without a time, the flow of the Sankey, and their table
    views add up to the count "n of m" of the table, also beyond the 2000 rows
    it shows. Each slice, bar and node counts what its filter lists. The
    charts are drawn again only when the alerts or the filters change."""
    script = _alert_charts_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        const r = { untimed: alerts.filter(a => Number.isNaN(Date.parse(a.timestamp))).length };
        renderAlertsTab();
        r.all = charts();
        // What each part counts, and what its filter lists
        const flowFilter = id => _alertsFlowFilter(id);
        r.trips = {
            severity: r.all.severity.slices.map(([key, value]) => [key, value, filterAlerts(alerts, { severities: [key] }).length]),
            engine: r.all.engine.slices.filter(([key]) => key)
                .map(([key, value]) => [key, value, filterAlerts(alerts, { engine: key }).length]),
            bins: r.all.bins.map(([start, end, total]) => [start, total, filterAlerts(alerts, { from: start, to: end }).length]),
            nodes: r.all.nodes.filter(([id]) => Object.keys(flowFilter(id)).length)
                .map(([id, value]) => [id, value, filterAlerts(alerts, flowFilter(id)).length]),
        };
        // Drawn again only when the alerts or the filters change: not for a new process list
        let draws = 0;
        const html = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        for (const id of ['alerts-severity-chart', 'alerts-time-chart', 'alerts-engine-chart', 'alerts-flow-chart'])
            Object.defineProperty($(id), 'innerHTML', { configurable: true, set(v) { draws++; html.set.call(this, v); } });
        renderAlertsTab(); r.unchanged = draws;
        state.processes = {}; renderAlertsTab(); r.processes = draws;
        state.alerts = [...alerts]; renderAlertsTab(); r.newList = draws;
        openAlertsTab({ severities: ['high', 'medium'], rule: 'RUN KEY ' });
        r.filtered = { ...charts(), listed: filterAlerts(alerts, { severities: ['high', 'medium'], rule: 'run key' }).length };
        const [start, end] = r.all.bins.filter(bin => bin[2] > 0)[2];
        openAlertsTab({ from: start, to: end });
        r.range = { ...charts(), listed: filterAlerts(alerts, { from: start, to: end }).length };
        openAlertsTab({ process: 'nothing like it' });
        r.none = charts();
        state.alerts = []; renderAlertsTab();
        r.noAlerts = charts();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone) + _alerts_prelude())
    untimed = r["untimed"]
    assert untimed > 20
    for name in ("all", "filtered", "range"):
        n, totals = _chart_totals(r[name])
        assert all(total == n for total in totals.values()), f"{name}: the charts count other alerts than the table ({n}): {totals}"
        assert r[name]["rows"] == min(n, 2000) and r[name]["limit"] == (n > 2000)
        assert len({(source, target) for source, target, *_ in r[name]["bands"]}) == len(r[name]["bands"])
        # A period's columns add up to its total, the severities no chip names in "Other" (after the total)
        time = r[name]["tables"]["time"]
        assert all(sum(int(cell[1]) for cell in row[1:6] + row[7:]) == int(row[6][1]) for row in time["rows"]), \
            f"{name}: the columns of a period do not add up to its total: {time['rows'][:3]}"
        # The bars in the colours of the slices: a severity no chip names muted in both
        assert r[name]["barFills"] == r[name]["severity"]["colors"], (r[name]["barFills"], r[name]["severity"]["colors"])
    assert r["all"]["barFills"]["high!"] == r["all"]["barFills"]["warning"] == "var(--text-muted)", \
        "a severity no chip names drawn in the colour of another (high)"
    assert r["all"]["tables"]["time"]["head"] == ["Period", "Critical", "High", "Medium", "Low", "Info", "Total", "Other"], \
        "Other is not after Total (a remembered sort column would move when it comes and goes)"
    assert r["filtered"]["tables"]["time"]["head"] == ["Period", "Critical", "High", "Medium", "Low", "Info", "Total"], \
        "an Other column without alerts in it"
    assert int(r["all"]["count"].split(" of ")[0]) == 2345 and r["all"]["rows"] == 2000, \
        "the charts count the 2000 rows the table shows, not every alert of the filters"
    assert _untimed(r["all"]) == untimed, "the alerts without a time are lost between the slices and the bars"
    assert r["all"]["tables"]["time"]["notes"] == [f"{untimed} without time"]
    for name in ("filtered", "range"):
        assert int(r[name]["count"].split(" of ")[0]) == r[name]["listed"] > 0
    assert r["range"]["untimed"] is None, "a range lists no alert without a time: there is nothing to note"
    # Each part counts what its filter lists
    for name, trips in r["trips"].items():
        assert trips and all(value == listed for _, value, listed in trips), f"{name}: {trips}"
    assert len(r["trips"]["nodes"]) >= 15, "nodes without a filter of their own"
    assert (r["unchanged"], r["processes"], r["newList"]) == (0, 0, 4), \
        "the charts are drawn on every refresh, or not for new alerts"
    # No alert of the filters, no alert at all: a hint instead of the charts
    for name, text in (("none", "No alerts match the filters"), ("noAlerts", "No alerts yet")):
        view = r[name]
        assert view["severity"]["empty"] == view["engine"]["empty"] == view["timeEmpty"] == view["flowEmpty"] == text, view
        assert not view["severity"]["slices"] and not view["bins"] and not view["nodes"] and view["untimed"] is None
        assert all(not table["rows"] and table["notes"] == [text + "."] for table in view["tables"].values()), view["tables"]


@needs_node
def test_alerts_chart_clicks_set_visible_filters():
    """A click on a chart sets a filter the filter bar shows and can take off,
    and the table then lists what the part counted: a severity's slice or
    legend row shows that severity alone (its chip pressed, the others not;
    nothing changes when it is the only one pressed), while the chips of the
    filter bar still switch one severity on or off; an engine's chooses it in
    the engine choice, a bar sets a range chip, a Sankey node an engine, rule
    or process, a band both of its ends. "other rules", "other processes"
    and the engine of alerts without one set nothing and show no pointer.
    Names from the sample stay text. Coming from another tab, the tab opens
    at its top."""
    script = _alert_charts_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        const holder = $('alerts-active-filters');
        const bar = () => ({
            pressed: document.querySelectorAll('#tab-alerts .alerts-sev-chip')
                .filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.dataset.severity),
            engine: $('alerts-filter-engine').value,
            chips: holder.querySelectorAll('.alerts-filter-chip').map(c => c.textContent.replace(/\s+/g, ' ').trim()),
            values: holder.querySelectorAll('.alerts-filter-chip-value').map(c => c.textContent),
            count: Number($('alerts-count').textContent.split(' of ')[0]),
            filter: { ...alertsExtraFilter },
        });
        const part = (id, cls, attr, value) => $(id).querySelectorAll(cls).find(el => el.getAttribute(attr) === value);
        const band = (test) => $('alerts-flow-chart').querySelectorAll('.sankey-link')
            .find(p => test(p.getAttribute('data-source'), p.getAttribute('data-target')));
        const r = {};
        renderAlertsTab();
        const all = charts();
        r.all = all;
        r.start = bar();
        const valueOf = (list, id) => (list.find(item => item[0] === id) || [])[1];
        // SEVERITY: the slice of high shows the alerts of high alone; its legend row, high the only one pressed, changes nothing
        click(part('alerts-severity-chart', '.chart-seg', 'data-key', 'high'));
        r.high = { ...bar(), slices: charts().severity.slices, expected: valueOf(all.severity.slices, 'high') };
        click(part('alerts-severity-chart', '.chart-legend-row', 'data-key', 'high').querySelector('.chart-legend-name'));
        r.highAgain = bar();
        // Several chips pressed (the dashboard's "high" tag presses critical and high): a slice or a legend row keeps
        // only its own
        openAlertsTab({ severities: ['critical', 'high'] });
        r.two = { ...bar(), slices: charts().severity.slices.map(slice => slice[0]) };
        click(part('alerts-severity-chart', '.chart-seg', 'data-key', 'high'));
        r.twoHigh = bar();
        openAlertsTab({ severities: ['critical', 'high', 'medium'] });
        click(part('alerts-severity-chart', '.chart-legend-row', 'data-key', 'critical').querySelector('.chart-legend-count'));
        r.threeCritical = { ...bar(), expected: valueOf(all.severity.slices, 'critical') };
        // The chips of the filter bar still switch one severity on or off
        click(document.querySelector('#tab-alerts .alerts-sev-chip[data-severity="medium"]'));
        r.chipOn = bar();
        click(document.querySelector('#tab-alerts .alerts-sev-chip[data-severity="critical"]'));
        r.chipOff = bar();
        // A severity no chip names sets nothing, also one cssToken turns into "high"
        openAlertsTab({});
        click(part('alerts-severity-chart', '.chart-seg', 'data-key', 'high!'));
        click(part('alerts-severity-chart', '.chart-legend-row', 'data-key', 'warning'));
        r.noChip = bar();
        // ENGINE: the slice of yara chooses the engine in its first spelling; one without a name does nothing
        click(part('alerts-engine-chart', '.chart-seg', 'data-key', 'yara'));
        r.yara = { ...bar(), expected: valueOf(all.engine.slices, 'yara'), colors: charts().engine.colors,
                   nodeColors: charts().nodeColors };
        openAlertsTab({});
        click(part('alerts-engine-chart', '.chart-seg', 'data-key', ''));
        click(part('alerts-engine-chart', '.chart-legend-row', 'data-key', ''));
        r.noEngine = bar();
        // OVER TIME: a bar sets its period
        const bin = $('alerts-time-chart').querySelectorAll('.chart-bin').filter(g => Number(g.getAttribute('data-total')) > 0)[3];
        const [start, end] = ['data-bin-start', 'data-bin-end'].map(a => Number(bin.getAttribute(a)));
        click(bin.querySelector('.chart-bar'));
        r.bar = { ...bar(), start, end, expected: Number(bin.getAttribute('data-total')), label: chartRangeLabel(start, end),
                  bins: charts().bins.map(([s, e]) => [s, e]) };
        // A range reaching past the alerts: the bars span the range, empty days too
        setAlertsFilters({ from: t0 - 3 * DAY, to: t0 + DAY });
        r.wide = { bins: charts().bins.map(([s, e, total]) => [s, e, total]), from: t0 - 3 * DAY, to: t0 + DAY,
                   table: charts().tables.time.rows.map(row => Number(row[0][1])), inert: charts().inertBins };
        // ... and a bar without alerts sets no range: it would empty every card
        const before = bar();
        click($('alerts-time-chart').querySelectorAll('.chart-bin').find(g => g.getAttribute('data-total') === '0')
            .querySelector('.chart-hit'));
        r.emptyBin = { before, after: bar() };
        // FLOW: a rule node, the process "(unknown)", an engine node
        openAlertsTab({});
        click(part('alerts-flow-chart', '.sankey-node', 'data-sankey-node', 'rule:Run Key').querySelector('text'));
        r.rule = { ...bar(), expected: valueOf(all.nodes, 'rule:Run Key') };
        click(holder.querySelector('.alerts-filter-chip'));
        r.ruleOff = bar();
        click(part('alerts-flow-chart', '.sankey-node', 'data-sankey-node', 'process:(unknown)'));
        r.unknown = { ...bar(), expected: valueOf(all.nodes, 'process:(unknown)') };
        openAlertsTab({});
        click(part('alerts-flow-chart', '.sankey-node', 'data-sankey-node', 'engine:Yara'));
        r.engineNode = { ...bar(), expected: valueOf(all.nodes, 'engine:Yara') };
        // "other ..." and the engine without a name: no filter
        openAlertsTab({});
        for (const id of ['other rules', 'other processes', 'engine:']) click(part('alerts-flow-chart', '.sankey-node', 'data-sankey-node', id));
        click(band((s, t) => s === 'other rules' && t === 'other processes'));
        click(band((s, t) => s === 'engine:' && t === 'other rules'));
        r.other = bar();
        // A band sets both of its ends; a band with an end that sets nothing ("other ...", the engine
        // of alerts without one) sets nothing: it would list more alerts than it carries
        const both = band((s, t) => s === 'engine:Sigma' && t === 'rule:Run Key');
        const bothValue = Number(both.getAttribute('data-value'));
        click(both);
        r.band = { ...bar(), expected: bothValue };
        openAlertsTab({});
        const halves = [band((s, t) => s.startsWith('rule:') && t === 'other processes'),
                        band((s, t) => s === 'engine:' && t.startsWith('rule:')),
                        band((s, t) => s === 'engine:Sigma' && t === 'other rules')];
        r.halfFound = halves.map(Boolean);
        halves.forEach(half => click(half));
        r.halfBands = bar();
        // Hostile names: the chip names them as text, the filter takes them whole
        openAlertsTab({});
        click(part('alerts-flow-chart', '.sankey-node', 'data-sankey-node', 'rule:' + EVIL));
        click(part('alerts-flow-chart', '.sankey-node', 'data-sankey-node', 'process:' + QUOTE));
        r.hostile = { ...bar(), markup: ['img', 'script'].map(tag => $('tab-alerts').querySelectorAll(tag).length),
                      expected: filterAlerts(alerts, { rule: EVIL, process: QUOTE }).length };
        // From another tab, scrolled down: the tab opens at its top, charts and filters in view
        $('tab-alerts').scrollTop = 700; state.activeTab = 'dashboard';
        openAlertsTab({ severities: ['critical'] });
        r.opened = [$('tab-alerts').scrollTop, state.activeTab, bar().pressed];
        // Engines named like markup: text in the slices, the legend and the table
        state.alerts = [...alerts.slice(0, 5), { ...alerts[0], id: 'evil', engine: EVIL }, { ...alerts[1], id: 'quote', engine: QUOTE }];
        openAlertsTab({});
        r.hostileEngine = { markup: ['img', 'script'].map(tag => $('tab-alerts').querySelectorAll(tag).length),
                            legend: charts().engine.legend.map(row => row[1]), table: charts().tables.engine.rows.map(row => row[0][0]) };
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    n = 2345
    none = {"pressed": [], "engine": "", "chips": [], "values": [], "count": n,
            "filter": {"from": None, "to": None, "category": None, "rule": None, "process": None}}
    assert r["start"] == none
    high = r["high"]
    assert (high["pressed"], high["count"], high["chips"]) == (["high"], high["expected"], []) and high["expected"] > 0
    assert high["slices"] == [["high", high["expected"], "circle", False]], "the pie of one severity is no full disc"
    assert r["highAgain"] == {k: v for k, v in high.items() if k not in ("slices", "expected")}, \
        "the legend row of the only severity pressed let go of it"
    assert r["two"]["pressed"] == ["critical", "high"] and r["two"]["slices"] == ["critical", "high"]
    assert (r["twoHigh"]["pressed"], r["twoHigh"]["count"]) == (["high"], high["expected"]), \
        "a slice switched its severity off (critical left) instead of showing it alone"
    three = r["threeCritical"]
    assert (three["pressed"], three["count"]) == (["critical"], three["expected"]) and three["expected"] > 0, \
        "a legend row did not show its severity alone"
    assert r["chipOn"]["pressed"] == ["critical", "medium"], "a chip of the filter bar does not switch its severity on"
    assert r["chipOff"]["pressed"] == ["medium"], "a chip of the filter bar does not switch its severity off"
    assert r["noChip"] == none, "a severity without a chip pressed another chip"
    assert (r["yara"]["engine"], r["yara"]["count"]) == ("Yara", r["yara"]["expected"]), \
        "the engine is not chosen, or not in the spelling the engine choice offers"
    # An engine keeps its colour when a filter is set, and has the same in FLOW
    colors = r["all"]["engine"]["colors"]
    assert len(set(colors.values())) == 4 and all(c.startswith("var(--") for c in colors.values()), colors
    assert r["yara"]["colors"] == {"yara": colors["yara"]}, "an engine changes its colour with the filters"
    assert {k: v for k, v in r["all"]["nodeColors"].items() if k.startswith("engine:")} == \
        {"engine:Sigma": colors["sigma"], "engine:Yara": colors["yara"], "engine:fibratus": colors["fibratus"],
         "engine:": colors[""]}, "FLOW colours an engine other than ENGINE"
    assert r["yara"]["nodeColors"]["engine:Yara"] == colors["yara"]
    assert {r["all"]["nodeColors"][k] for k in ("other rules", "other processes")} == {"var(--text-muted)"}
    assert r["noEngine"] == none, "the slice of alerts without an engine set a filter"
    b = r["bar"]
    assert (b["filter"]["from"], b["filter"]["to"]) == (b["start"], b["end"]) and b["chips"] == ["\u00d7 " + b["label"]]
    assert b["count"] == b["expected"] > 0, "a bar lists other alerts than it counted"
    assert b["bins"][0][0] == b["start"] and b["bins"][-1][1] == b["end"] and len(b["bins"]) >= 20, \
        "the bars do not span the period of the bar clicked (by hours)"
    wide = r["wide"]
    # 11 Jul 09:00 - 15 Jul 09:00: the first alerts are on 14 Jul from 09:00 to 15 Jul 08:59
    assert (wide["bins"][0][0], wide["bins"][-1][1], len(wide["bins"])) == (wide["from"], wide["to"], 5), \
        "the bars do not span the range of the filter"
    assert [total > 0 for *_, total in wide["bins"]] == [False, False, False, True, True]
    assert wide["table"] == [wide["bins"][3][0], wide["bins"][4][0]], "the table of OVER TIME lists periods without alerts"
    assert wide["inert"] == [True, True, True, False, False], "a bar without alerts shows the pointer"
    assert r["emptyBin"]["after"] == r["emptyBin"]["before"], "a bar without alerts set a range"
    assert not any(r["all"]["inertBins"]) and len(r["all"]["inertBins"]) == len(r["all"]["bins"])
    assert (r["rule"]["chips"], r["rule"]["count"]) == (["\u00d7 rule: Run Key"], r["rule"]["expected"])
    assert r["ruleOff"] == none, "the chip a node set cannot be taken off"
    assert (r["unknown"]["chips"], r["unknown"]["count"]) == (["\u00d7 process: (unknown)"], r["unknown"]["expected"])
    assert (r["engineNode"]["engine"], r["engineNode"]["chips"], r["engineNode"]["count"]) == \
        ("Yara", [], r["engineNode"]["expected"])
    assert r["other"] == none, "a click on other rules / other processes set a filter"
    assert (r["band"]["engine"], r["band"]["chips"], r["band"]["count"]) == ("Sigma", ["\u00d7 rule: Run Key"], r["band"]["expected"])
    assert r["halfFound"] == [True, True, True] and r["halfBands"] == none, \
        "a band with an end that sets no filter set the other end's (more alerts than the band carries)"
    hostile = r["hostile"]
    assert hostile["values"] == [EVIL, QUOTE] and (hostile["filter"]["rule"], hostile["filter"]["process"]) == (EVIL, QUOTE)
    assert hostile["markup"] == [0, 0] and hostile["count"] == hostile["expected"] > 0
    assert r["opened"] == [0, "alerts", ["critical"]], "the tab opens where it was scrolled to"
    engines = r["hostileEngine"]
    assert engines["markup"] == [0, 0] and {EVIL, QUOTE} <= set(engines["legend"]) and {EVIL, QUOTE} <= set(engines["table"]), \
        engines
    # No pointer where a click sets nothing: the buckets, the engine without a name, a band with one of them
    nodes, bands = r["all"]["nodes"], r["all"]["bands"]
    assert sorted(node for node, _, inert in nodes if inert) == ["engine:", "other processes", "other rules"]
    inert = {"engine:", "other processes", "other rules"}
    assert all(flag == (source in inert or target in inert) for source, target, _, flag, _ in bands), bands
    assert any(flag for *_, flag, _ in bands) and not all(flag for *_, flag, _ in bands)
    assert [key for key, *_, flag in r["all"]["engine"]["slices"] if flag] == [""]
    assert [row[0] for row in r["all"]["engine"]["legend"] if row[4]] == [""]
    assert [key for key, *_, flag in r["all"]["severity"]["slices"] if flag] == ["high!", "warning"]
    assert [row[0] for row in r["all"]["severity"]["legend"] if row[4]] == ["high!", "warning"]


@needs_node
def test_alerts_charts_have_info_and_table():
    """Above the filter bar: SEVERITY, OVER TIME (twice as wide), ENGINE and
    the card FLOW: ENGINE → RULE → PROCESS, each with its (i) and its CHART /
    TABLE switch; each table view is sortable and shows the numbers of its
    chart. LINEAR draws the Sankey in true proportions (square roots by
    default) and stays on until the page is reloaded. The bars and the Sankey
    are drawn for the width of their card, and again when it changes. The
    table of FLOW gives its two name columns the same width."""
    tab = _Elements(_read(INDEX_HTML)).by_id("tab-alerts")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def by_id(node, element_id):
        found = find(node, lambda e: e["attrs"].get("id") == element_id)
        assert len(found) == 1, element_id
        return found[0]

    def text(node):
        return node.get("text", "") + "".join(text(c) for c in node["children"])

    parts = [c["attrs"].get("id") or c["attrs"].get("class") for c in tab["children"]]
    assert parts == ["content-header", "alerts-drill", "alerts-charts", "alerts-filters", "alerts-table-wrap"], \
        "the charts are not above the filter bar, under the drilldown bar"
    charts = by_id(tab, "alerts-charts")
    assert "hidden" not in charts["attrs"]
    cards = find(charts, lambda e: "chart-card" in e["attrs"].get("class", "").split())
    assert [c["attrs"].get("id") for c in cards] == ["alerts-severity-card", "alerts-time-card", "alerts-engine-card",
                                                     "alerts-flow-card"]
    titles = {"severity": "SEVERITY", "time": "OVER TIME", "engine": "ENGINE", "flow": "FLOW: ENGINE \u2192 RULE \u2192 PROCESS"}
    for card, (kind, title) in zip(cards, titles.items()):
        view = f"alerts-{kind}"
        heading = find(card, lambda e: "chart-card-title" in e["attrs"].get("class", "").split())
        assert len(heading) == 1 and text(heading[0]).strip() == title, kind
        assert heading[0]["attrs"].get("data-info", "").strip(), f"{kind}: no (i)"
        assert by_id(card, f"{view}-toggle") is not None
        chart, table = by_id(card, f"{view}-chart"), by_id(card, f"{view}-table")
        assert (chart["attrs"].get("data-view-of"), chart["attrs"].get("data-view"), "hidden" in chart["attrs"]) == \
            (view, "chart", False)
        assert (table["attrs"].get("data-view-of"), table["attrs"].get("data-view"), "hidden" in table["attrs"]) == \
            (view, "table", True)
        assert "chart-clickable" in chart["attrs"].get("class", "").split()
        assert chart["attrs"].get("onclick") == f"onAlertsChartClick(event, '{kind}')"
        if kind == "severity":
            info = heading[0]["attrs"]["data-info"]
            assert "only" in info and "chips" in info and "on or off" in info, \
                f"the (i) of SEVERITY does not say a slice shows its severity alone, the chips switch: {info}"
    linear = by_id(cards[3], "alerts-flow-linear")
    assert (linear["tag"], text(linear).strip(), linear["attrs"].get("aria-pressed"), linear["attrs"].get("onclick"),
            linear["attrs"].get("data-view-of"), linear["attrs"].get("data-view")) == \
        ("button", "LINEAR", "false", "toggleAlertsFlowScale()", "alerts-flow", "chart")
    assert "viewToggleHtml(" in _function_source("renderAlertsCharts")
    source = "\n".join(_strip_js_comments(_function_source(name)) for name in ALERTS_CHART_FUNCTIONS)
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"

    script = _alert_charts_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        const head = kind => document.querySelector(`#alerts-${kind}-card .chart-card-head`);
        head('time').rect = { width: 640 }; head('flow').rect = { width: 1200 };
        renderAlertsTab();
        const r = { view: charts() };
        r.badges = $('alerts-severity-table').querySelectorAll('.event-severity').map(s => [s.textContent, s.className]);
        r.otherTitles = $('alerts-time-table').querySelector('table').tBodies[0].rows.filter(row => !row.hasAttribute('data-sort-skip'))
            .map(row => row.cells[7].getAttribute('title') || '');
        const toggle = kind => $(`alerts-${kind}-toggle`).querySelector('.view-toggle');
        r.toggles = ['severity', 'time', 'engine', 'flow'].map(kind => [toggle(kind).getAttribute('data-view-toggle'),
                                                                        toggle(kind).textContent]);
        const svg = kind => $(`alerts-${kind}-chart`).querySelector('svg');
        const heights = () => Object.fromEntries(['engine:Sigma', 'engine:Yara'].map(id => [id,
            Number($('alerts-flow-chart').querySelectorAll('.sankey-node').find(g => g.getAttribute('data-sankey-node') === id)
                .querySelector('.sankey-bar').getAttribute('height'))]));
        r.widths = [svg('time').getAttribute('width'), svg('flow').getAttribute('width')];
        r.sqrt = heights();
        // LINEAR: true proportions, until the page is reloaded
        const linear = $('alerts-flow-linear');
        click(linear);
        r.linear = { heights: heights(), pressed: linear.getAttribute('aria-pressed') };
        state.alerts = [...alerts, { ...alerts[0], id: 'new' }]; renderAlertsTab();
        r.refreshed = { heights: heights(), pressed: linear.getAttribute('aria-pressed') };
        click(linear);
        r.back = { heights: heights(), pressed: linear.getAttribute('aria-pressed') };
        // The width of the cards: drawn again when it changes, not while the tab is hidden, not for the same width
        head('time').rect = { width: 500 }; head('flow').rect = { width: 900 };
        redrawAlertsChartsOnResize();
        r.resized = [svg('time').getAttribute('width'), svg('flow').getAttribute('width')];
        const drawn = [svg('time'), svg('flow')];
        redrawAlertsChartsOnResize();
        head('time').rect = { width: 0 }; head('flow').rect = { width: 0 };
        redrawAlertsChartsOnResize();
        r.kept = [svg('time') === drawn[0], svg('flow') === drawn[1]];
        // TABLE: the table in place of the chart, kept on the next refresh; LINEAR goes with the chart
        click(toggle('severity')); click(toggle('flow'));
        state.alerts = alerts; renderAlertsTab();
        r.tables = ['severity', 'time', 'engine', 'flow'].map(kind => [$(`alerts-${kind}-chart`).hidden,
                                                                       $(`alerts-${kind}-table`).hidden, toggle(kind).textContent]);
        r.linearHidden = linear.hidden;
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    view = r["view"]
    assert r["toggles"] == [["alerts-severity", "TABLE"], ["alerts-time", "TABLE"], ["alerts-engine", "TABLE"],
                            ["alerts-flow", "TABLE"]], "a card without its CHART / TABLE switch"
    tables = view["tables"]
    assert {kind: t["id"] for kind, t in tables.items()} == {kind: f"alerts-{kind}" for kind in ("severity", "time", "engine", "flow")}
    assert all(t["sortable"] for t in tables.values())
    # SEVERITY and ENGINE: one row per legend row, with its count and share
    assert tables["severity"]["head"] == ["Severity", "Count", "Share"]
    assert [[row[0][0], int(row[1][1]), row[2][0]] for row in tables["severity"]["rows"]] == \
        [[key, count, share] for key, _, count, share, _ in view["severity"]["legend"]]
    # After the five of the chips, the severities no chip names (by count, a tie in the order of the keys)
    assert [row[0][0] for row in tables["severity"]["rows"]] == ["critical", "high", "medium", "low", "info", "high!",
                                                                 "warning"]
    assert [row[1] for row in view["severity"]["legend"]] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "HIGH!",
                                                              "WARNING"]
    assert r["badges"] == [[s, f"event-severity {s}"] for s in ("critical", "high", "medium", "low", "info")] + \
        [["high!", "event-severity "], ["warning", "event-severity "]], "a severity without a chip in the colour of another"
    assert view["severity"]["colors"] == {**{s: f"var(--severity-{s})" for s in ("critical", "high", "medium", "low", "info")},
                                          "high!": "var(--text-muted)", "warning": "var(--text-muted)"}
    assert tables["engine"]["head"] == ["Engine", "Count", "Share"]
    assert [[row[0][0], int(row[1][1]), row[2][0]] for row in tables["engine"]["rows"]] == \
        [[name, count, share] for _, name, count, share, _ in view["engine"]["legend"]]
    # By count, a tie in the order of the keys (fibratus and the alerts without an engine have 235 each)
    assert [row[1] for row in view["engine"]["legend"]] == ["Sigma", "Yara", "(unknown)", "fibratus"], \
        "an engine not in the first spelling of all alerts"
    # OVER TIME: a row per bar that has alerts, its counts by severity and its total, those no chip names as Other
    assert tables["time"]["head"] == ["Period", "Critical", "High", "Medium", "Low", "Info", "Total", "Other"]
    bars = [(start, counts, total) for start, _, total, counts in view["bins"] if total]
    five = ("critical", "high", "medium", "low", "info")
    assert [int(row[0][1]) for row in tables["time"]["rows"]] == [start for start, _, _ in bars]
    assert [[int(cell[1]) for cell in row[1:]] for row in tables["time"]["rows"]] == \
        [[counts.get(s, 0) for s in five] + [total, sum(n for k, n in counts.items() if k not in five)]
         for _, counts, total in bars]
    def title_counts(title):
        return dict((k, int(n.replace(",", ""))) for k, n in (part.rsplit(": ", 1) for part in title.split(", ") if part))
    assert [title_counts(title) for title in r["otherTitles"]] == \
        [{k: n for k, n in counts.items() if k not in five} for _, counts, _ in bars], \
        "the title of Other does not name its severities"
    # FLOW: a row per band
    assert tables["flow"]["head"] == ["Source", "Target", "Count"]

    def band(title):
        names, count = title.rsplit(": ", 1)
        source, target = names.split(" \u2192 ", 1)
        return [source, target, int(count.replace(",", ""))]
    assert sorted([row[0][0], row[1][0], int(row[2][1])] for row in tables["flow"]["rows"]) == \
        sorted(band(title) for *_, title in view["bands"])
    # Drawn for the width of the card
    assert r["widths"] == ["640", "1200"] and r["resized"] == ["500", "900"], "not drawn for the width of the card"
    assert r["kept"] == [True, True], "drawn again for the same width, or while the tab is hidden"
    # LINEAR: Sigma (6 alerts in 10) and Yara (2 in 10) by their square roots, then in true proportions
    ratio = lambda heights: heights["engine:Sigma"] / heights["engine:Yara"]
    assert abs(ratio(r["sqrt"]) - 3 ** 0.5) < 0.05 and r["linear"]["pressed"] == "true"
    assert abs(ratio(r["linear"]["heights"]) - 3) < 0.05, "LINEAR does not show true proportions"
    assert abs(ratio(r["refreshed"]["heights"]) - 3) < 0.05 and r["refreshed"]["pressed"] == "true", \
        "LINEAR is lost on the next refresh"
    assert abs(ratio(r["back"]["heights"]) - 3 ** 0.5) < 0.05 and r["back"]["pressed"] == "false"
    assert r["tables"] == [[True, False, "CHART"], [False, True, "TABLE"], [False, True, "TABLE"], [True, False, "CHART"]]
    assert r["linearHidden"] is True, "LINEAR shows beside the table, where it changes nothing"
    # Both themes: the strip, the note, LINEAR pressed, no pointer where a click does nothing
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    assert re.search(r"grid-template-columns:[^;]*\b2fr\b", rules.get(".alerts-chart-strip", "")), \
        "OVER TIME is not twice as wide as the pies"
    assert re.search(r"(?:^|;)\s*flex:\s*0 0 auto", rules.get(".alerts-charts", "")), "the charts shrink into the tab"
    assert _painted(rules, _cls("alerts-chart-note"), "color")
    assert re.search(r"cursor:\s*default", rules.get(".chart-clickable .chart-inert", ""))
    assert re.search(r"fill:\s*transparent", rules.get(".chart-clickable .chart-bin.chart-inert:hover .chart-hit", "")), \
        "a bar without alerts lights up under the pointer"
    assert _painted(rules, r"\.chart-scale-toggle\[aria-pressed=\"true\"\]", "color")
    assert re.search(r"(?:^|;)\s*width:\s*50%", rules.get("#alerts-flow-table .view-table .view-table-text", "")), \
        "the table of FLOW cuts its targets (rules, processes) to a few letters"
    for selector in ('[data-theme="cyberpunk"] .alerts-charts', '[data-theme="cyberpunk"] .chart-scale-toggle[aria-pressed="true"]'):
        assert selector in theme, f"{selector} has no Cyberpunk rule"


@needs_node
def test_alert_severity_maps_informational_to_info():
    """Sigma's level "informational" is the severity info: the INFO chip
    filters it and the charts count it as info, not as a grey severity of
    its own that no chip names."""
    r = _run_node(ALERT_FILTER_JS + ["alertsSeverityItems", "_alertsSeverityColor"], r"""
        const alerts = [{ id: 'i1', severity: 'informational', timestamp: '2026-11-09T10:00:00Z' },
                        { id: 'i2', severity: 'Informational' }, { id: 'i3', severity: 'INFO' }, { id: 'i4' },
                        { id: 'w', severity: 'warning' }, { id: 'h', severity: 'High' }];
        console.log(JSON.stringify({
            severities: alerts.map(alertSeverity), info: filterAlerts(alerts, { severities: ['info'] }).map(a => a.id),
            items: alertsSeverityItems(alerts).map(item => [item.key, item.value, item.color]),
        }));
    """, _prelude())
    assert r["severities"] == ["info", "info", "info", "info", "warning", "high"]
    assert sorted(r["info"]) == ["i1", "i2", "i3", "i4"], "the INFO chip misses Sigma's informational alerts"
    assert r["items"] == [["high", 1, "var(--severity-high)"], ["info", 4, "var(--severity-info)"],
                          ["warning", 1, "var(--text-muted)"]]


@needs_node
def test_alerts_over_time_leaves_out_implausible_times():
    """An alert with a time no clock can have had (before 2000, or more than
    a day from now: a VM clock set to 1970, a 1601 FILETIME zero, 9999) is in
    no bar of OVER TIME, which would otherwise span decades in one squeezed
    bar; a note counts these alerts beside those without a time, and the
    slices count them all. The last bar ends where plausible times do, so its
    period lists exactly what it counted."""
    script = (ALERTS_TAB_DOM + r"""
        const now = Date.UTC(2026, 10, 10, 12); Date.now = () => now;
        const HOUR = 3600000;
        const alerts = [0, 5, 26, 30, 49, 50, 51, 70].map((h, i) => ({ id: 'p' + i, severity: 'high', engine: 'Sigma',
            rule_name: 'r', timestamp: new Date(now - h * HOUR).toISOString() }));
        alerts.push({ id: 'soon', severity: 'low', engine: 'Sigma', timestamp: new Date(now + 20 * HOUR).toISOString() },
                    { id: 'tooSoon', severity: 'low', engine: 'Sigma', timestamp: new Date(now + 30 * HOUR).toISOString() },
                    { id: 'y1970', severity: 'high', engine: 'Sigma', timestamp: '1970-01-01T00:00:00Z' },
                    { id: 'y1601', severity: 'high', engine: 'Sigma', timestamp: '1601-01-01T00:00:00.0000000Z' },
                    { id: 'y9999', severity: 'high', engine: 'Sigma', timestamp: '9999-12-31T23:59:59Z' },
                    { id: 'nat', severity: 'high', engine: 'Sigma', timestamp: 'not a time' });
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        const time = $('alerts-time-chart');
        const bins = time.querySelectorAll('.chart-bin').map(g => ['data-bin-start', 'data-bin-end', 'data-total']
            .map(a => Number(g.getAttribute(a))));
        const table = $('alerts-time-table').querySelector('table');
        console.log(JSON.stringify({
            bins, listed: bins.map(([start, end]) => filterAlerts(alerts, { from: start, to: end }).length),
            note: time.querySelector('.alerts-time-missed').textContent.trim(),
            notes: table.tBodies[0].rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()),
            slices: $('alerts-severity-chart').querySelectorAll('.chart-seg').reduce((sum, s) => sum + Number(s.getAttribute('data-value')), 0),
            count: $('alerts-count').textContent, now, latest: now + 24 * HOUR,
        }));
    """).replace("MARKUP", json.dumps(_tab_markup("alerts")))
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    bins = r["bins"]
    assert 4 <= len(bins) <= 5 and all(end - start <= 86400000 for start, end, _ in bins), \
        f"the bars span the years of the implausible times: {len(bins)} bins"
    assert sum(total for *_, total in bins) == 9, "the plausible alerts (one a few hours ahead) are not all in a bar"
    assert r["note"] == "1 without time \u00b7 4 with implausible time"
    assert r["notes"] == ["1 without time", "4 with implausible time"]
    assert r["slices"] == 14 and r["count"] == "14 of 14", "the slices do not count every alert"
    assert bins[-1][1] <= r["latest"], "the last bar reaches past the plausible times"
    assert r["listed"] == [total for *_, total in bins], "a bar's period lists other alerts than it counted"


# Alerts of 27 Jul 2026 in the local time of the zone: one every 2:59 for two
# hours from 10:00 on, two in its first second, one a millisecond before
# 10:00, one before 12:00 and one at 12:00 (the end of 10:00-12:00, not in it),
# and three more that day (08:15 the first, 23:59:59 the last); then one
# every 20 minutes from 22:05 on 24 Oct, through the night the clocks go back
# in Europe (25 Oct: 03:00 summer time is 02:00 winter time).
SHORT_SPAN_FIXTURE = r"""
    const at = (...a) => new Date(...a).getTime();          // local time of the zone
    const S = 1000, M = 60000;
    const from = at(2026, 6, 27, 10), to = at(2026, 6, 27, 12);
    const july = [...Array.from({ length: 40 }, (_, i) => from + i * 179 * S), from + 800, from + 1100, from - 1, to - 1, to,
                  at(2026, 6, 27, 8, 15), at(2026, 6, 27, 13, 40), at(2026, 6, 27, 23, 59, 59)];
    const night = { from: at(2026, 9, 24, 22), to: at(2026, 9, 25, 6) };
    const october = Array.from({ length: 27 }, (_, i) => night.from + 5 * M + i * 20 * M);
    const SHORT_SEVERITIES = ['high', 'medium', 'critical', 'low', 'info'];
    const alertsAt = times => times.map((t, i) => ({ id: 's' + i, timestamp: new Date(t).toISOString(),
        severity: SHORT_SEVERITIES[i % 5], engine: 'Sigma', rule_name: 'Run Key', process_name: 'p.exe' }));
"""


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin"])
def test_alerts_over_time_gets_finer_for_short_spans(zone):
    """Narrowed to a short range, OVER TIME shows its detail: a span of up to
    20 hours takes bars of seconds or minutes (at most 40), whether a filter
    or the alerts themselves set it. 27 Jul 10:00-12:00 are 24 bars of 5
    minutes, the first from the start of the range, the last up to its end,
    together counting what the table lists, their periods named in the table
    view as in their tooltips. A whole day keeps its 24 hours, and ALERT
    ACTIVITY of the dashboard its hours, also over alerts of 16 hours.
    Through the night the clocks go back (Europe, 25 Oct) the bars of 15
    minutes follow each other without a gap, named in local time. Bars a
    range cuts short at both ends are labelled by their step."""
    script = _alert_charts_script(SHORT_SPAN_FIXTURE + r"""
        Date.now = () => Date.UTC(2026, 10, 10, 12);                // after all of them: no time is implausible
        globalThis.state = { alerts: alertsAt([...july, ...october]), processes: {}, activeTab: 'alerts' };
        const look = () => {
            const view = charts(), time = $('alerts-time-chart'), counted = _alertsChartsDrawn.time;
            return {
                unit: counted.unit, step: counted.step ?? null, count: view.count,
                bins: view.bins.map(([start, end, total]) => [start, end, total]),
                titles: time.querySelectorAll('.chart-bin').map(g => g.querySelector('title').textContent.split('\n')[0]),
                periods: view.tables.time.rows.map(row => row[0][0]),
                chips: $('alerts-active-filters').querySelectorAll('.alerts-filter-chip')
                    .map(c => c.textContent.replace(/\s+/g, ' ').trim()),
            };
        };
        renderAlertsTab();
        const r = { from, to, night, day: { from: at(2026, 6, 27), to: at(2026, 6, 28) },
                    ownSpan: { from: at(2026, 6, 27, 8), to: at(2026, 6, 28) } };
        setAlertsFilters({ from, to }); r.twoHours = look();
        setAlertsFilters(r.day); r.wholeDay = look();
        setAlertsFilters(night); r.overNight = look();
        // No range: the span of the alerts themselves, 27 Jul from 08:15 to 23:59:59
        setAlertsFilters({ from: null, to: null });
        state.alerts = alertsAt(july); renderAlertsTab(); r.own = look();
        // Bars a range cuts short at both ends (it lasts half a second here): labelled by their step
        const cut = alertSeverityBins(state.alerts, { from: from + 700, to: from + 1200, fine: true });
        r.cut = { unit: cut.unit, step: cut.step, ticks: [..._alertsTimeBarsSvg(cut, { width: 560, height: 120 })
            .matchAll(/<text class="chart-tick"[^>]*>([^<]*)<\/text>/g)].map(m => m[1]) };
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone) + _alerts_prelude())
    MINUTES_5, QUARTER, HALF, HOUR = 300000, 900000, 1800000, 3600000

    def gapless(view, length, span):
        bins = view["bins"]
        return (bins and all(end - start == length for start, end, _ in bins)
                and all(b[0] == a[1] for a, b in zip(bins, bins[1:]))
                and (bins[0][0], bins[-1][1]) == (span["from"], span["to"]))

    def listed(view):
        return int(view["count"].split(" of ")[0])

    two = r["twoHours"]
    assert (two["unit"], two["step"], len(two["bins"])) == ("minute", MINUTES_5, 24), \
        f"10:00-12:00 in {len(two['bins'])} bars of {two['unit']}"
    assert gapless(two, MINUTES_5, r), "the bars of 5 minutes do not span the range, or leave a gap"
    assert sum(total for *_, total in two["bins"]) == listed(two) and two["count"] == "43 of 75", \
        "the bars count other alerts than the table lists"
    assert "27 Jul 2026, 10:10\u201310:15" in two["periods"] and two["titles"][2] == "27 Jul 2026, 10:10\u201310:15", \
        (two["periods"], two["titles"][:3])
    assert two["periods"] == [title for title, (*_, total) in zip(two["titles"], two["bins"]) if total], \
        "the table view follows other periods than the bars"
    assert two["chips"] == ["\u00d7 27 Jul 10:00\u201312:00"]
    day = r["wholeDay"]
    assert (day["unit"], day["step"], len(day["bins"])) == ("hour", None, 24) and gapless(day, HOUR, r["day"]), \
        "a whole day is no longer 24 bars of an hour"
    assert sum(total for *_, total in day["bins"]) == listed(day) and day["count"] == "48 of 75"
    assert "27 Jul 2026, 10:00\u201311:00" in day["periods"] and day["chips"] == ["\u00d7 27 Jul"]
    # The night of 24 Oct, 22:00 to 06:00: 9 hours in Berlin (the hour from 02:00 twice), 8 in UTC
    night = r["overNight"]
    quarters = {"UTC": 32, "Europe/Berlin": 36}[zone]
    assert (night["unit"], night["step"], len(night["bins"])) == ("minute", QUARTER, quarters), \
        f"{len(night['bins'])} bars of {night['unit']} ({night['step']})"
    assert gapless(night, QUARTER, r["night"]), "the bars of 15 minutes leave a gap or change length in the night"
    assert sum(total for *_, total in night["bins"]) == listed(night) == {"UTC": 24, "Europe/Berlin": 27}[zone]
    assert (night["titles"][0], night["titles"][-1]) == ("24 Oct 2026, 22:00\u201322:15", "25 Oct 2026, 05:45\u201306:00")
    assert night["titles"][8] == "25 Oct 2026, 00:00\u201300:15"
    if zone == "Europe/Berlin":
        # The last quarter of summer time ends at 03:00, which is 02:00 winter time; that hour comes again
        assert night["titles"][19:21] == ["25 Oct 2026, 02:45\u201302:00", "25 Oct 2026, 02:00\u201302:15"], \
            night["titles"][17:23]
        assert night["titles"].count("25 Oct 2026, 02:00\u201302:15") == 2
    assert night["chips"] == ["\u00d7 24 Oct 22:00 \u2013 25 Oct 06:00"]
    own = r["own"]
    assert (own["unit"], own["step"], len(own["bins"])) == ("minute", HALF, 32) and gapless(own, HALF, r["ownSpan"]), \
        "the alerts of 16 hours, without a range, are not in bars of half an hour"
    assert sum(total for *_, total in own["bins"]) == listed(own) == 48 and own["chips"] == []
    assert r["cut"] == {"unit": "second", "step": 1000, "ticks": ["10:00:00", "10:00:01"]}, \
        "bars cut short by the range are labelled by their length instead of their step"

    # ALERT ACTIVITY of the dashboard keeps hours: for 24H, and for ALL over the alerts of 27 Jul alone
    script = _dashboard_script(SHORT_SPAN_FIXTURE + r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const bars = () => ({ unit: _dashboardDrawn.bars.unit, step: 'step' in _dashboardDrawn.bars,
                              bins: look().bins.map(([start, end]) => [start, end]) });
        renderDashboard();
        setDashboardRange('24h');
        const r = { day: bars() };
        state.alerts = alertsAt(july);
        setDashboardRange('all');
        r.all = { ...bars(), from: at(2026, 6, 27, 8), to: at(2026, 6, 28) };
        console.log(JSON.stringify(r));
    """)
    d = _run_node(DASHBOARD_JS, script, _dashboard_prelude(zone))
    assert (d["day"]["unit"], d["day"]["step"]) == ("hour", False), d["day"]["unit"]
    assert len(d["day"]["bins"]) >= 24 and all(end - start <= HOUR for start, end in d["day"]["bins"])
    assert (d["all"]["unit"], d["all"]["step"]) == ("hour", False), \
        "ALERT ACTIVITY takes bars of minutes for alerts of 16 hours"
    assert d["all"]["bins"] == [[t, t + HOUR] for t in range(d["all"]["from"], d["all"]["to"], HOUR)]


# --- The drilldown of the Alerts tab ------------------------------------------------

# What the drilldown tests look at: the steps (as data and by name), the
# version of the path, the filters of the tab and what the table lists (the
# ids of its rows, up to 100 of them); and the parts of the charts they click
DRILL_LOOK = r"""
    const at = (day, hour = 0) => new Date(2026, 6, day, hour).getTime();     // July, local time of the zone
    const holder = $('alerts-active-filters');
    const drill = () => {
        const ids = $('alerts-rows').querySelectorAll('tr.alerts-row')
            .map(row => /openAlertDetailById\("(\w+)"\)/.exec(row.getAttribute('onclick'))[1]);
        return {
            labels: alertsDrilldown.map(alertsStepLabel), steps: JSON.parse(JSON.stringify(alertsDrilldown)),
            version: alertsDrillVersion,
            pressed: document.querySelectorAll('#tab-alerts .alerts-sev-chip')
                .filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.dataset.severity),
            engine: $('alerts-filter-engine').value, text: $('alerts-filter-text').value, filter: { ...alertsExtraFilter },
            chips: holder.querySelectorAll('.alerts-filter-chip').map(c => c.getAttribute('data-filter')),
            count: $('alerts-count').textContent, rows: ids.length, ids: ids.length > 100 ? null : ids,
        };
    };
    const seg = (id, key) => $(id).querySelectorAll('.chart-seg').find(s => s.getAttribute('data-key') === key);
    const legendName = (id, key) => $(id).querySelectorAll('.chart-legend-row')
        .find(row => row.getAttribute('data-key') === key).querySelector('.chart-legend-name');
    const dayBar = day => $('alerts-time-chart').querySelectorAll('.chart-bin')
        .find(g => Number(g.getAttribute('data-bin-start')) === at(day)).querySelector('.chart-bar');
    const node = id => $('alerts-flow-chart').querySelectorAll('.sankey-node').find(g => g.getAttribute('data-sankey-node') === id);
    const band = (source, target) => $('alerts-flow-chart').querySelectorAll('.sankey-link')
        .find(p => p.getAttribute('data-source') === source && p.getAttribute('data-target') === target);
"""

NO_EXTRA = {"from": None, "to": None, "category": None, "rule": None, "process": None}


def _drill_script(script):
    return _alert_charts_script(DRILL_LOOK + script)


def _listed(view):
    return int(view["count"].split(" of ")[0])


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "Asia/Kolkata"])
def test_drilldown_steps_back_and_jump(zone):
    """Each click on a chart that changes the filters is a step of the
    drilldown, which holds the kinds of filter it changed with their values
    before and after it: the bar of 27 Jul, then 10:00-12:00 of that day,
    then the rule Run Key are named "27 Jul", "27 Jul 10:00–12:00" and
    "rule: Run Key". BACK takes the last one back, to exactly the count and
    rows before it; a jump to a step takes back the later ones, the newest
    first; -1 takes back every one. A click that changes nothing (the same
    slice again, its legend row, an engine or a range in another form) is no
    step; a band whose engine is chosen already is a step of its rule, one
    from an engine not chosen yet a step of both, which BACK takes back
    together. An engine given with blanks around it is the engine of that
    name. The severities of a step stand in the order of the chips. Each
    change of the steps, and only that, counts up the version of the path."""
    script = _drill_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        const r = { start: drill(), values: alertsDrillValues() };
        // OVER TIME: the bar of 27 Jul, then 10:00-12:00 of that day, then the rule node Run Key
        click(dayBar(27)); r.day = drill();
        r.ten = drillAlerts({ from: at(27, 10), to: at(27, 12) }); r.window = drill();
        // The same range as text and as a Date, or one of its bounds alone: no step
        r.same = [drillAlerts({ from: String(at(27, 10)), to: new Date(at(27, 12)) }), drillAlerts({ from: at(27, 10) }), drill()];
        // A bound alone sets that bound, the other stays
        r.partial = [drillAlerts({ to: at(27, 11) }), drill()];
        alertsDrillBack();
        _applyAlertsChartFilter({ rule: 'Run Key' }); r.rule = drill();
        r.sameRule = [drillAlerts({ rule: ' run key ' }), drill()];
        alertsDrillBack(); r.back = drill();
        alertsDrillTo(0); r.toDay = drill();
        alertsDrillTo(-1); r.all = drill();
        r.nothingBack = (alertsDrillBack(), alertsDrillTo(-1), drill());
        // Severities no chip names press nothing: no step
        r.noChip = [drillAlerts({ severities: ['warning', 'High!'] }), drill()];
        // SEVERITY: the slice of high is a step HIGH; the slice again, its legend row, high in capitals: none
        click(seg('alerts-severity-chart', 'high')); r.high = drill();
        click(seg('alerts-severity-chart', 'high'));
        click(legendName('alerts-severity-chart', 'high'));
        r.highAgain = [drillAlerts({ severities: ['HIGH', 'high'] }), drill()];
        // ENGINE: the slice of sigma is a step Sigma, in its first spelling; again, or in capitals: none
        click(seg('alerts-engine-chart', 'sigma')); r.sigma = drill();
        click(seg('alerts-engine-chart', 'sigma'));
        click(legendName('alerts-engine-chart', 'sigma'));
        r.sigmaAgain = [drillAlerts({ engine: ' SIGMA ' }), drill()];
        // FLOW: a band from Sigma, the engine chosen already, to Run Key is a step of the rule alone
        click(band('engine:Sigma', 'rule:Run Key')); r.band = drill();
        // Severities in another order and case, in the order of the chips; BACK sets those before, HIGH stays
        r.reordered = [drillAlerts({ severities: ['low', 'CRITICAL'] }), drill()];
        alertsDrillBack(); r.reorderedBack = drill();
        // A jump to a step takes back the later ones, the newest first: MEDIUM (from HIGH) before HIGH (from none)
        drillAlerts({ severities: ['medium'] });
        alertsDrillTo(0); r.toHigh = drill();
        drillAlerts({ severities: ['medium'] });
        alertsDrillTo(-1); r.none = drill();
        // FLOW: a band from Sigma to Run Key with no engine chosen is one step of both; BACK takes both back
        const engines = () => $('alerts-filter-engine').children.map(o => o.value);
        click(dayBar(27)); r.dayAgain = { ...drill(), offered: engines() };
        click(band('engine:Sigma', 'rule:Run Key')); r.bandBoth = drill();
        alertsDrillBack(); r.bandBothBack = drill();
        // An engine with blanks around it: the engine of that name in the spelling the choice offers, no choice of
        // its own (it would filter by the blanks too, and list nothing)
        alertsDrillTo(-1);
        r.blanks = [drillAlerts({ engine: ' Sigma ' }), { ...drill(), offered: engines(),
                    listed: filterAlerts(alerts, { engine: 'sigma' }).length }];
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone) + _alerts_prelude())
    none = {"range": {"from": None, "to": None}}
    start, day, window, rule = r["start"], r["day"], r["window"], r["rule"]
    assert (start["labels"], start["count"]) == ([], "2345 of 2345")
    assert r["values"] == {"range": {"from": None, "to": None}, "severities": [], "engine": "", "category": None,
                           "rule": None, "process": None}
    # The values of each step, of the kinds it changed only
    first = {"from": day["filter"]["from"], "to": day["filter"]["to"]}
    ten = {"from": window["filter"]["from"], "to": window["filter"]["to"]}
    assert day["labels"] == ["27 Jul"] and day["chips"] == ["range"]
    assert day["steps"] == [{"dashboard": False, "before": none, "after": {"range": first}}]
    assert r["ten"] is True and window["labels"] == ["27 Jul", "27 Jul 10:00\u201312:00"]
    assert window["steps"][1] == {"dashboard": False, "before": {"range": first}, "after": {"range": ten}}
    assert ten["to"] - ten["from"] == 2 * 3600000 and first["from"] <= ten["from"] < ten["to"] <= first["to"]
    assert r["same"] == [False, False, window], "a range in another form, or one bound alone, made a step"
    partial = r["partial"]
    assert partial[0] is True and partial[1]["labels"][-1] == "27 Jul 10:00\u201311:00"
    assert partial[1]["steps"][-1]["after"] == {"range": {"from": ten["from"], "to": ten["from"] + 3600000}}
    assert rule["labels"] == ["27 Jul", "27 Jul 10:00\u201312:00", "rule: Run Key"]
    assert rule["steps"][2] == {"dashboard": False, "before": {"rule": None}, "after": {"rule": "Run Key"}}
    assert _listed(day) > _listed(window) > _listed(rule) > 0, (day["count"], window["count"], rule["count"])
    assert r["sameRule"] == [False, rule], "a rule in other capitals and blanks made a step"
    # BACK: exactly the count and rows of the step before
    back = r["back"]
    assert back["labels"] == ["27 Jul", "27 Jul 10:00\u201312:00"] and back["filter"]["rule"] is None
    assert (back["count"], back["ids"], back["filter"], back["chips"]) == \
        (window["count"], window["ids"], window["filter"], window["chips"]), "BACK does not show what the step before did"
    to_day = r["toDay"]
    assert to_day["labels"] == ["27 Jul"]
    assert (to_day["count"], to_day["rows"], to_day["ids"], to_day["filter"]) == \
        (day["count"], day["rows"], day["ids"], day["filter"])
    everything = r["all"]
    assert (everything["labels"], everything["steps"], everything["filter"], everything["chips"], everything["count"]) == \
        ([], [], NO_EXTRA, [], "2345 of 2345")
    assert r["nothingBack"] == everything, "BACK without a step changed something"
    assert r["noChip"] == [False, everything], "severities no chip names made a step that changes nothing"
    # SEVERITY and ENGINE: named HIGH and Sigma (the first spelling of the engine), each once
    high, sigma, band = r["high"], r["sigma"], r["band"]
    assert (high["labels"], high["pressed"]) == (["HIGH"], ["high"])
    assert high["steps"] == [{"dashboard": False, "before": {"severities": []}, "after": {"severities": ["high"]}}]
    assert r["highAgain"] == [False, high], "the same severity again made a step"
    assert (sigma["labels"], sigma["engine"]) == (["HIGH", "Sigma"], "Sigma")
    assert sigma["steps"][1] == {"dashboard": False, "before": {"engine": ""}, "after": {"engine": "Sigma"}}
    assert r["sigmaAgain"] == [False, sigma], "the same engine again made a step"
    assert band["labels"] == ["HIGH", "Sigma", "rule: Run Key"] and band["engine"] == "Sigma"
    assert band["steps"][2] == {"dashboard": False, "before": {"rule": None}, "after": {"rule": "Run Key"}}, \
        "the step of a band holds the engine it did not change"
    made, reordered = r["reordered"]
    assert made is True and reordered["labels"][-1] == "CRITICAL + LOW"
    assert reordered["steps"][-1] == {"dashboard": False, "before": {"severities": ["high"]},
                                      "after": {"severities": ["critical", "low"]}}
    after_back = r["reorderedBack"]
    assert (after_back["labels"], after_back["pressed"]) == (band["labels"], ["high"]), \
        "BACK set the severities by the handler of the chips, which forgot the step HIGH"
    to_high = r["toHigh"]
    assert (to_high["labels"], to_high["pressed"], to_high["engine"], to_high["filter"]) == (["HIGH"], ["high"], "", NO_EXTRA)
    assert (to_high["count"], to_high["rows"]) == (high["count"], high["rows"])
    assert (r["none"]["labels"], r["none"]["pressed"], r["none"]["engine"], r["none"]["filter"], r["none"]["count"]) == \
        ([], [], "", NO_EXTRA, "2345 of 2345"), "the steps were taken back the oldest first"
    # A step of two kinds (a band from an engine not chosen yet): BACK sets both as they were
    day_again, both, both_back = r["dayAgain"], r["bandBoth"], r["bandBothBack"]
    assert both["labels"] == ["27 Jul", "Sigma \u00b7 rule: Run Key"]
    assert (both["engine"], both["filter"]["rule"]) == ("Sigma", "Run Key")
    assert both["steps"][1] == {"dashboard": False, "before": {"engine": "", "rule": None},
                                "after": {"engine": "Sigma", "rule": "Run Key"}}
    assert 0 < _listed(both) < _listed(day_again) <= 100
    assert (both_back["labels"], both_back["engine"], both_back["filter"]["rule"]) == (["27 Jul"], "", None), \
        "BACK of a step of an engine and a rule left one of them set"
    assert (both_back["count"], both_back["ids"], both_back["filter"], both_back["chips"]) == \
        (day_again["count"], day_again["ids"], day_again["filter"], day_again["chips"])
    made, blanks = r["blanks"]
    assert made is True and (blanks["labels"], blanks["engine"]) == (["Sigma"], "Sigma")
    assert blanks["steps"][-1]["after"] == {"engine": "Sigma"}
    assert blanks["offered"] == day_again["offered"], \
        f"an engine with blanks around it became a choice of its own: {blanks['offered']}"
    assert blanks["count"] == f"{blanks['listed']} of 2345" and blanks["listed"] > 0
    # The version counts every change of the steps, and nothing else
    changes = [start, day, window, rule, back, to_day, everything]
    assert all(a["version"] < b["version"] for a, b in zip(changes, changes[1:])), [v["version"] for v in changes]
    assert partial[1]["version"] > window["version"] and rule["version"] > partial[1]["version"] + 1
    assert r["nothingBack"]["version"] == everything["version"]
    assert everything["version"] < high["version"] < sigma["version"] < band["version"] < reordered["version"] \
        < after_back["version"] < to_high["version"] < r["none"]["version"]


@needs_node
def test_drilldown_leaves_own_settings_alone():
    """What is set by hand in the filter bar is no step, and BACK never takes
    it back: a search typed after a step stays after BACK; a severity chip
    switched after a step of SEVERITY, the engine chosen after a step of
    ENGINE and the × of the range chip after two steps of OVER TIME make the
    steps forget that kind of filter, and a step left without one drops out
    of the path; BACK then skips it. A step of two kinds stays with the one
    left: the band Sigma → Run Key, then the engine chosen by hand, leaves
    "rule: Run Key" (as the README says), and BACK takes the rule back, not
    the engine. The render of the click by hand already finds the path that
    is left, and its version is another (what shows the path draws it
    again)."""
    script = _drill_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        // The path each render of the tab finds
        const seen = [], render = renderAlertsTab;
        globalThis.renderAlertsTab = () => { seen.push(alertsDrilldown.map(alertsStepLabel)); render(); };
        const drawn = () => seen[seen.length - 1];
        renderAlertsTab();
        const r = {};
        // The search typed after a step stays when BACK takes the step back
        click(dayBar(27));
        $('alerts-filter-text').value = 'run key'; renderAlertsTab();
        r.search = drill();
        alertsDrillBack(); r.searchBack = { ...drill(), listed: filterAlerts(alerts, { text: 'run key' }).length };
        // A severity chip switched after a step of SEVERITY: that step drops out, BACK skips it
        openAlertsTab({});
        click(dayBar(27)); click(seg('alerts-severity-chart', 'high')); r.severityStep = drill();
        click(document.querySelector('#tab-alerts .alerts-sev-chip[data-severity="medium"]'));
        r.chip = { ...drill(), drawn: drawn() };
        alertsDrillBack(); r.chipBack = drill();
        // The engine chosen after a step of ENGINE: the step drops out
        openAlertsTab({});
        click(seg('alerts-engine-chart', 'sigma')); r.engineStep = drill();
        const select = $('alerts-filter-engine');
        select.value = 'Yara'; dispatch('change', select);
        r.engineByHand = { ...drill(), drawn: drawn(), listed: filterAlerts(alerts, { engine: 'Yara' }).length };
        alertsDrillBack(); r.engineBack = drill();
        // Two ranges and a rule, then the × of the range chip: the rule is left; BACK takes it off, no range comes back
        openAlertsTab({});
        click(dayBar(27)); drillAlerts({ from: at(27, 10), to: at(27, 12) });
        click(node('rule:Run Key').querySelector('text'));
        r.three = drill();
        click(holder.querySelector('.alerts-filter-chip[data-filter="range"]'));
        r.cut = { ...drill(), drawn: drawn(), listed: filterAlerts(alerts, { rule: 'Run Key' }).length };
        alertsDrillBack(); r.cutBack = drill();
        // The band Sigma → Run Key with no engine chosen, one step of both; then the engine chosen by hand: the step
        // forgets the engine and stays as the rule's; BACK takes the rule back, the engine chosen by hand stays
        openAlertsTab({});
        click(band('engine:Sigma', 'rule:Run Key')); r.band = drill();
        select.value = 'Yara'; dispatch('change', select);
        r.bandByHand = { ...drill(), drawn: drawn() };
        alertsDrillBack(); r.bandBack = drill();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    assert (r["search"]["labels"], r["search"]["text"]) == (["27 Jul"], "run key")
    back = r["searchBack"]
    assert (back["labels"], back["text"], back["filter"]) == ([], "run key", NO_EXTRA), "BACK took the search back"
    assert back["count"] == f"{back['listed']} of 2345" and back["listed"] > 0
    # The severity chip: the step HIGH drops out, before the tab is drawn; BACK skips it
    assert r["severityStep"]["labels"] == ["27 Jul", "HIGH"]
    chip = r["chip"]
    assert (chip["labels"], chip["pressed"]) == (["27 Jul"], ["high", "medium"]), "the path names a step no longer in effect"
    assert chip["drawn"] == ["27 Jul"], "the tab was drawn before the steps forgot the severities"
    assert chip["version"] > r["severityStep"]["version"], "a step dropped by a chip set by hand left the version as it was"
    chip_back = r["chipBack"]
    assert (chip_back["labels"], chip_back["filter"], chip_back["pressed"]) == ([], NO_EXTRA, ["high", "medium"]), \
        "BACK undid the severities set by hand"
    # The engine choice: the step Sigma drops out
    assert (r["engineStep"]["labels"], r["engineStep"]["engine"]) == (["Sigma"], "Sigma")
    by_hand = r["engineByHand"]
    assert (by_hand["labels"], by_hand["engine"], by_hand["drawn"]) == ([], "Yara", []), \
        "the engine chosen by hand left the step of the engine in the path"
    assert by_hand["count"] == f"{by_hand['listed']} of 2345" and by_hand["listed"] > 0
    assert by_hand["version"] > r["engineStep"]["version"], "a step dropped by the engine chosen by hand left the version"
    assert r["engineBack"] == {k: v for k, v in by_hand.items() if k not in ("drawn", "listed")}, \
        "BACK without a step changed something"
    # The × of the range: both range steps drop out, the rule's is left; BACK takes the rule off, no range returns
    assert r["three"]["labels"] == ["27 Jul", "27 Jul 10:00\u201312:00", "rule: Run Key"]
    cut = r["cut"]
    assert cut["labels"] == ["rule: Run Key"] and cut["drawn"] == ["rule: Run Key"]
    assert cut["version"] > r["three"]["version"], "steps dropped by the × of a chip left the version as it was"
    assert cut["steps"] == [{"dashboard": False, "before": {"rule": None}, "after": {"rule": "Run Key"}}]
    assert (cut["filter"], cut["chips"]) == ({**NO_EXTRA, "rule": "Run Key"}, ["rule"])
    assert cut["count"] == f"{cut['listed']} of 2345"
    cut_back = r["cutBack"]
    assert (cut_back["labels"], cut_back["filter"], cut_back["chips"], cut_back["count"]) == \
        ([], NO_EXTRA, [], "2345 of 2345"), "BACK brought back the range taken off by hand"
    # The band of an engine and a rule: the engine chosen by hand leaves the step the rule's
    band, band_by_hand, band_back = r["band"], r["bandByHand"], r["bandBack"]
    assert (band["labels"], band["engine"], band["filter"]["rule"]) == (["Sigma \u00b7 rule: Run Key"], "Sigma", "Run Key")
    assert (band_by_hand["labels"], band_by_hand["drawn"], band_by_hand["engine"]) == \
        (["rule: Run Key"], ["rule: Run Key"], "Yara"), \
        "the engine chosen by hand took the band's step out of the path, or left the engine in it"
    assert band_by_hand["steps"] == [{"dashboard": False, "before": {"rule": None}, "after": {"rule": "Run Key"}}]
    assert (band_back["labels"], band_back["engine"], band_back["filter"]) == ([], "Yara", NO_EXTRA), \
        "BACK of the band's step undid the engine chosen by hand, or kept the rule"


@needs_node
def test_dashboard_jump_starts_a_new_path():
    """A jump from the dashboard with a filter replaces the path by one step
    named after what it set, from no filter: "Dashboard: CRITICAL + HIGH",
    "Dashboard: 14 Jul – 20 Jul · category: registry". BACK then shows every
    alert and stays in the Alerts tab; what the jump cleared (the search, a
    severity chip, the engine) stays cleared. The same jump twice is one
    step, and a path drawn anew; a jump without a filter (TOTAL ALERTS)
    leaves no step."""
    script = _drill_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        const r = {};
        // Two steps, a search, a severity chip and an engine of one's own; then the dashboard's tag "high"
        // (critical and high)
        click(dayBar(27)); _applyAlertsChartFilter({ rule: 'Run Key' });
        $('alerts-filter-text').value = 'run'; renderAlertsTab();
        click(document.querySelector('#tab-alerts .alerts-sev-chip[data-severity="medium"]'));
        const select = $('alerts-filter-engine');
        select.value = 'Yara'; dispatch('change', select);
        r.before = drill();
        state.activeTab = 'dashboard';
        openAlertsTab({ severities: ['critical', 'high'] });
        r.jump = { ...drill(), tab: state.activeTab, listed: filterAlerts(alerts, { severities: ['critical', 'high'] }).length };
        alertsDrillBack(); r.back = { ...drill(), tab: state.activeTab };
        // A range and a category of the dashboard, twice
        state.activeTab = 'dashboard';
        openAlertsTab({ category: 'registry', from: at(14), to: at(21) }); r.category = drill();
        openAlertsTab({ category: 'registry', from: at(14), to: at(21) }); r.twice = drill();
        r.range = { from: at(14), to: at(21) };
        // ALL (no range), an engine in its first spelling, a severity no chip names, TOTAL ALERTS
        openAlertsTab({ category: 'registry', from: null, to: null }); r.noRange = drill();
        openAlertsTab({ engine: 'yara', severities: ['High'] }); r.engine = drill();
        openAlertsTab({ severities: ['warning'] }); r.noChip = drill();
        openAlertsTab({ severities: ['high'] }); openAlertsTab({}); r.total = drill();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    before, jump, back = r["before"], r["jump"], r["back"]
    assert (before["labels"], before["text"], before["pressed"], before["engine"]) == \
        (["27 Jul", "rule: Run Key"], "run", ["medium"], "Yara")
    assert jump["labels"] == ["Dashboard: CRITICAL + HIGH"], "the jump added to the old path"
    assert jump["steps"] == [{"dashboard": True, "before": {"severities": []}, "after": {"severities": ["critical", "high"]}}], \
        "the step of a jump holds the filters before it, not none"
    assert (jump["pressed"], jump["text"], jump["engine"], jump["filter"], jump["tab"]) == \
        (["critical", "high"], "", "", NO_EXTRA, "alerts")
    assert jump["count"] == f"{jump['listed']} of 2345" and jump["version"] > before["version"]
    assert (back["labels"], back["pressed"], back["tab"], back["text"], back["engine"], back["filter"], back["count"]) == \
        ([], [], "alerts", "", "", NO_EXTRA, "2345 of 2345"), "BACK after a jump does not show every alert in the tab"
    rng = r["range"]
    category, twice = r["category"], r["twice"]
    assert category["labels"] == ["Dashboard: 14 Jul \u2013 20 Jul \u00b7 category: registry"]
    assert category["steps"] == [{"dashboard": True, "before": {"range": {"from": None, "to": None}, "category": None},
                                  "after": {"range": rng, "category": "registry"}}]
    assert (twice["labels"], twice["steps"]) == (category["labels"], category["steps"]), "the same jump twice is no one step"
    assert twice["version"] > category["version"], "the same jump again does not draw the path anew"
    assert r["noRange"]["labels"] == ["Dashboard: category: registry"]
    assert r["noRange"]["steps"][0]["after"] == {"category": "registry"}, "ALL, no range, is a range of the step"
    assert r["engine"]["labels"] == ["Dashboard: HIGH \u00b7 Yara"]
    assert r["engine"]["steps"][0]["after"] == {"severities": ["high"], "engine": "Yara"}
    assert (r["noChip"]["labels"], r["noChip"]["pressed"]) == ([], [])
    total = r["total"]
    assert (total["labels"], total["steps"], total["count"]) == ([], [], "2345 of 2345")
    assert total["version"] > r["noChip"]["version"]


@needs_node
def test_alerts_bars_take_a_range_drawn_across_them():
    """A range drawn across the bars of OVER TIME is a step of the drilldown,
    the events as Chrome sends them (see
    test_dashboard_bars_take_a_range_drawn_across_them). Drawn from bar 2 to
    bar 5 (marked once moved by 5 px), it is one step from the start of bar 2
    to the end of bar 5: the table lists what those four bars counted, the
    bars divide that range anew, and the click of the release is no second
    step. A press that does not move is a step to the bar it pressed, also
    when it ends on the next bar and Chrome sends its click to the <svg>. A
    range of bars without alerts sets nothing; with a bar of alerts among
    them it is a step. New alerts while a range is drawn leave the bars and
    the mark as they are (the table counts them); once the press is over,
    OVER TIME shows them, also after a cancelled one, and a range released
    then is that of the bars it was drawn across. The bars held for a press
    are drawn after the task of its end, not within it: a still press during
    new alerts keeps the bar it pressed on the page, so Chrome sends it the
    click (to a bar drawn anew under the pointer it sends none). A range
    drawn across the dashboard's bars is no step of the Alerts tab, nor does
    it hold OVER TIME still."""
    script = _drill_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        globalThis.ResizeObserver = class { observe() {} };
        globalThis.requestAnimationFrame = fn => fn();
        document.createElementNS = (ns, tag) => Object.assign(document.createElement(tag), { ns });
        document.querySelector('#alerts-time-card .chart-card-head').rect = { width: 700 };
        initAlertsTab();
        renderAlertsTab();
        const view = $('alerts-time-chart');
        const svg = () => view.querySelector('svg');
        // The bars on screen, [start, end, total] each, placed at x 100 to 800
        const shown = () => view.querySelectorAll('.chart-bin').map(g => ['data-bin-start', 'data-bin-end', 'data-total']
            .map(a => Number(g.getAttribute(a))));
        let n = 0, slot = 0;
        const place = () => {
            svg().rect = { left: 100, top: 50, width: 700, height: 104, right: 800, bottom: 154 };
            n = shown().length;
            slot = 700 / n;
            return shown();
        };
        const xOf = i => 100 + (i + 0.5) * slot;
        const hit = i => view.querySelectorAll('.chart-hit')[i];
        const mark = () => { const m = view.querySelector('.chart-brush'); return m && [Number(m.getAttribute('x')), Number(m.getAttribute('width'))]; };
        const brushing = () => view.classList.contains('is-brushing');
        // Chrome's pointer capture: the pointer's events and the click after its release go to the element holding it
        let captured = null;
        Element.prototype.setPointerCapture = function () { captured = this; };
        Element.prototype.releasePointerCapture = function () { if (captured === this) captured = null; };
        const chain = el => { const list = []; for (let e = el; e; e = e.parentNode) list.push(e); return list; };
        const common = (a, b) => chain(a).find(e => chain(b).includes(e)) || null;
        // What is under the pointer at clientX: the hit area of a bar, or the card beside the bars
        const under = x => { const i = Math.floor((x - 100) / slot); return i >= 0 && i < n ? hit(i) : $('alerts-time-card'); };
        const send = (type, x) => dispatch(type, captured || under(x),
            { clientX: x, clientY: 100, button: 0, buttons: /up|cancel/.test(type) ? 0 : 1, pointerId: 7 });
        // The release at x and the click Chrome sends after it: to the element holding the capture, else to the
        // nearest common ancestor of the press's target (`down`) and the release's; none when the press's target
        // is gone, drawn anew during the release (Chrome 157 on the VM then sends no click to the page). That
        // element is returned.
        const lift = (x, down) => {
            const up = captured || under(x);
            send('pointerup', x);
            const target = captured || (down.isConnected ? common(down, up) : null);
            captured = null;
            if (target) dispatch('click', target, { clientX: x, clientY: 100, button: 0 });
            return target;
        };
        // A press at x0, moves to each x of xs, the release at the last one
        const gesture = (x0, xs = []) => {
            const down = under(x0);
            send('pointerdown', x0);
            xs.forEach(x => send('pointermove', x));
            return lift(xs.length ? xs[xs.length - 1] : x0, down);
        };
        let bins = place();
        const r = { n, start: drill() };
        // From bar 2 to bar 5; moved by 3 px it draws nothing yet
        const down = under(xOf(2));
        send('pointerdown', xOf(2)); send('pointermove', xOf(2) + 3);
        r.small = [mark(), captured === null];
        send('pointermove', xOf(4)); send('pointermove', xOf(5));
        r.marked = { mark: mark(), slot, capture: captured && captured.id, brushing: brushing() };
        const target = lift(xOf(5), down);
        r.drag = { ...drill(), want: [bins[2][0], bins[5][1]], label: chartRangeLabel(bins[2][0], bins[5][1]),
                   sum: bins.slice(2, 6).reduce((sum, bin) => sum + bin[2], 0), bars: shown(), mark: mark(),
                   brushing: brushing(), clickTarget: target && target.id };
        // A press on a bar that moves but by 4 px, onto the next bar: Chrome sends its click to the parent the two bars
        // share, the <svg> (in the test DOM, which nests what follows a self-closing tag, it would be a grid line)
        alertsDrillTo(-1);
        bins = place();
        const full = bins.findIndex((bin, i) => bin[2] > 0 && i + 1 < bins.length);
        const edge = 100 + (full + 1) * slot;
        send('pointerdown', edge - 2); send('pointermove', edge + 2);
        r.slipped = under(edge + 2) !== under(edge - 2);
        send('pointerup', edge + 2);
        captured = null;
        const chart = svg();
        dispatch('click', chart, { clientX: edge + 2, clientY: 100, button: 0 });
        r.still = { ...drill(), inBar: !!chart.closest('[data-bin-start]'), want: [bins[full][0], bins[full][1]],
                    total: bins[full][2] };
        // A range of bars without alerts (before the first alert) sets nothing; with a bar of alerts it is a step
        alertsDrillTo(-1);
        r.wide = { from: t0 - 3 * DAY, to: t0 + DAY };
        setAlertsFilters(r.wide);
        bins = place();
        const before = drill();
        gesture(xOf(0), [xOf(2)]);
        r.empty = { totals: bins.map(bin => bin[2]), before, after: drill() };
        gesture(xOf(1), [xOf(3)]);
        r.oneFull = { ...drill(), want: [bins[1][0], bins[3][1]], total: bins[3][2] };
        // New alerts while a range is drawn: the bars and the mark stay, the table counts them; a cancelled press
        // leaves OVER TIME showing them once the task of its end is over (a click of it would still reach the bars)
        alertsDrillTo(-1);
        setAlertsFilters({ from: null, to: null });
        bins = place();
        const drawn = svg();
        const late = { id: 'late', timestamp: new Date(bins[3][0] + HOUR).toISOString(), severity: 'high', engine: 'Sigma',
                       rule_name: 'Run Key', process_name: 'p.exe' };
        send('pointerdown', xOf(1)); send('pointermove', xOf(4));
        state.alerts = [...alerts, late];
        renderAlertsTab();
        r.polled = { kept: svg() === drawn, mark: mark(), slot, count: $('alerts-count').textContent };
        send('pointercancel', xOf(4));
        captured = null;
        r.polled.sameTask = svg() === drawn;
        settle().then(() => {
            r.cancelled = { ...drill(), redrawn: svg() !== drawn, mark: mark(), brushing: brushing(),
                            totals: shown().map(bin => bin[2]), before: bins.map(bin => bin[2]) };
            // ... and a range released after new alerts came is that of the bars it was drawn across
            bins = place();
            const later = { ...late, id: 'later', timestamp: new Date(bins[2][0] + 2 * HOUR).toISOString() };
            const pressed = under(xOf(2));
            send('pointerdown', xOf(2)); send('pointermove', xOf(3));
            state.alerts = [...alerts, late, later];
            renderAlertsTab();
            lift(xOf(3), pressed);
            r.released = { ...drill(), want: [bins[2][0], bins[3][1]], sum: bins[2][2] + bins[3][2] + 1,
                           bars: shown().reduce((sum, bin) => sum + bin[2], 0) };
            return settle();
        }).then(() => {
            // A press on a bar that does not move while new alerts come: its click reaches the bars it pressed (they
            // are drawn anew after it), a step to that bar
            alertsDrillTo(-1);
            bins = place();
            const one = bins.findIndex(bin => bin[2] > 0);
            const pressed = under(xOf(one));
            send('pointerdown', xOf(one));
            state.alerts = [...alerts, late, { ...late, id: 'polled' }];
            renderAlertsTab();
            const clicked = lift(xOf(one), pressed);
            r.stillPolled = { ...drill(), clicked: clicked && clicked.tagName.toLowerCase(), want: [bins[one][0], bins[one][1]],
                              total: bins[one][2] };
            return settle();
        }).then(() => {
            r.stillPolledLater = { steps: drill().steps, held: _alertsChartsDrawn.timeHeld };
            console.log(JSON.stringify(r));
        });
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    none = {"range": {"from": None, "to": None}}

    def step(before, view):
        return [{"dashboard": False, "before": before, "after": {"range": {"from": view["want"][0], "to": view["want"][1]}}}]
    start = r["start"]
    assert r["n"] >= 20 and (start["labels"], start["count"]) == ([], "2345 of 2345")
    assert r["small"] == [None, True], "a press moved by 3 px drew a range or took the capture"
    marked = r["marked"]
    assert marked["mark"] and abs(marked["mark"][0] - 2 * marked["slot"]) < 0.02 \
        and abs(marked["mark"][1] - 4 * marked["slot"]) < 0.02, f"the mark is not over bars 2 to 5: {marked}"
    assert (marked["capture"], marked["brushing"]) == ("alerts-time-chart", True), marked
    drag = r["drag"]
    assert drag["steps"] == step(none, drag), f"a range drawn from bar 2 to bar 5 made the steps {drag['steps']}"
    assert (drag["labels"], drag["chips"]) == ([drag["label"]], ["range"])
    assert drag["count"] == f"{drag['sum']} of 2345" and drag["sum"] > 0, "the table lists other alerts than the bars counted"
    bars = drag["bars"]
    assert (bars[0][0], bars[-1][1], sum(total for *_, total in bars)) == (*drag["want"], drag["sum"]), \
        "the bars do not divide the range drawn anew"
    assert drag["version"] == start["version"] + 1, "the click of the release made a step of its own"
    assert (drag["mark"], drag["brushing"], drag["clickTarget"]) == (None, False, "alerts-time-chart")
    still = r["still"]
    assert r["slipped"] and still["inBar"] is False
    assert still["steps"] == step(none, still), \
        f"a press that did not move and ended on the next bar (its click on the <svg>) made the steps {still['steps']}"
    assert still["count"] == f"{still['total']} of 2345" and still["total"] > 0
    empty = r["empty"]
    assert empty["totals"][:3] == [0, 0, 0] and empty["totals"][3] > 0, empty["totals"]
    assert empty["after"] == empty["before"], "a range of bars without alerts set something"
    one = r["oneFull"]
    assert one["steps"] == step({"range": r["wide"]}, one) and one["count"] == f"{one['total']} of 2345", one["steps"]
    polled, cancelled = r["polled"], r["cancelled"]
    assert polled["kept"] and polled["mark"] and abs(polled["mark"][1] - 4 * polled["slot"]) < 0.02, \
        "new alerts drew OVER TIME again while a range was drawn across it"
    assert polled["count"] == "2346 of 2346", "the table did not count the new alerts meanwhile"
    assert polled["sameTask"], "OVER TIME was drawn anew within the task of the press's end, before its click"
    assert cancelled["redrawn"] and (cancelled["mark"], cancelled["brushing"], cancelled["steps"]) == (None, False, []), \
        "OVER TIME does not show the new alerts after a cancelled range"
    assert cancelled["totals"] == [total + (i == 3) for i, total in enumerate(cancelled["before"])]
    released = r["released"]
    assert released["steps"] == step(none, released), released["steps"]
    assert released["count"] == f"{released['sum']} of 2347" == f"{released['bars']} of 2347", \
        "after a range released past new alerts the bars count other alerts than the table"
    polled_still = r["stillPolled"]
    assert polled_still["clicked"] is not None, \
        "a press that did not move while new alerts came lost its click (the bars drawn anew under it)"
    assert polled_still["steps"] == step(none, polled_still) and polled_still["count"] == f"{polled_still['total']} of 2347", \
        polled_still["steps"]
    assert r["stillPolledLater"] == {"steps": polled_still["steps"], "held": False}, \
        "the bars held for the press were not drawn after it, or its step was lost"

    # A range drawn across ALERT ACTIVITY: OVER TIME is drawn meanwhile (a poll), and the Alerts tab takes no step
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        globalThis.ResizeObserver = class { observe() {} };
        globalThis.requestAnimationFrame = fn => fn();
        document.createElementNS = (ns, tag) => Object.assign(document.createElement(tag), { ns });
        document.querySelector('#dashboard-alerts-card .dashboard-bars-area').rect = { left: 0, top: 0, width: 700, height: 220 };
        initAlertsTab();
        initDashboardCharts();
        renderAlertsTab();
        setDashboardRange('7d');
        const dash = $('dashboard-alerts-chart');
        dash.querySelector('svg').rect = { left: 100, top: 50, width: 700, height: 220, right: 800, bottom: 270 };
        const bins = look().bins, slot = 700 / bins.length, xOf = i => 100 + (i + 0.5) * slot;
        let captured = null;
        Element.prototype.setPointerCapture = function () { captured = this; };
        Element.prototype.releasePointerCapture = function () { if (captured === this) captured = null; };
        const send = (type, x) => dispatch(type, captured || dash.querySelectorAll('.chart-hit')[Math.floor((x - 100) / slot)],
            { clientX: x, clientY: 120, button: 0, buttons: /up|cancel/.test(type) ? 0 : 1, pointerId: 7 });
        const tab = () => ({ steps: JSON.parse(JSON.stringify(alertsDrilldown)), version: alertsDrillVersion,
                             filter: { ...alertsExtraFilter }, count: $('alerts-count').textContent });
        const r = { before: tab() };
        send('pointerdown', xOf(2)); send('pointermove', xOf(5));
        const over = $('alerts-time-chart').querySelector('svg');
        state.alerts = [...alerts];
        renderAlertsTab();
        r.during = [barsBrushActive(DASHBOARD_BARS_BRUSH), $('alerts-time-chart').querySelector('svg') !== over];
        const up = captured;
        send('pointerup', xOf(5));
        captured = null;
        dispatch('click', up || dash, { clientX: xOf(5), clientY: 120, button: 0 });
        r.after = { ...tab(), range: { ...dashboardRange }, want: [bins[2][0], bins[5][1]] };
        console.log(JSON.stringify(r));
    """)
    d = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    assert d["during"] == [True, True], "a range drawn across the dashboard's bars held OVER TIME still, or none was drawn"
    after = d["after"]
    assert {key: after[key] for key in d["before"]} == d["before"], "a range drawn across ALERT ACTIVITY was a step"
    assert (after["range"]["preset"], after["range"]["from"], after["range"]["to"]) == ("custom", *after["want"])


@needs_node
def test_a_press_on_bars_held_back_begins_nothing():
    """New alerts during a press on OVER TIME are counted, but the bars are
    drawn only after the task that ends the press: until then the bars on
    screen are not those counted. A second press within that task (another
    finger, a pen) begins nothing, so it neither marks nor narrows by bars
    that are not on screen; once the task is over, the new bars are drawn
    and take a press again. A second press that began before the new alerts
    came keeps its bars and its mark through them, and through the redraw
    put off by the press before it; released, it narrows by the bars it was
    drawn across, and OVER TIME shows the new alerts."""
    script = _drill_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        globalThis.ResizeObserver = class { observe() {} };
        globalThis.requestAnimationFrame = fn => fn();
        document.createElementNS = (ns, tag) => Object.assign(document.createElement(tag), { ns });
        document.querySelector('#alerts-time-card .chart-card-head').rect = { width: 700 };
        initAlertsTab();
        renderAlertsTab();
        const view = $('alerts-time-chart');
        const svg = () => view.querySelector('svg');
        const shown = () => view.querySelectorAll('.chart-bin').map(g => ['data-bin-start', 'data-bin-end', 'data-total']
            .map(a => Number(g.getAttribute(a))));
        // The bars on screen, placed at x 100 to 800
        let n = 0, slot = 0;
        const place = () => {
            svg().rect = { left: 100, top: 50, width: 700, height: 104, right: 800, bottom: 154 };
            n = shown().length;
            slot = 700 / n;
            return shown();
        };
        const xOf = i => 100 + (i + 0.5) * slot;
        const mark = () => { const m = view.querySelector('.chart-brush'); return m && [Number(m.getAttribute('x')), Number(m.getAttribute('width'))]; };
        // Chrome's pointer capture (see test_alerts_bars_take_a_range_drawn_across_them); the click of a release
        // without it goes to the bars' <svg>, the parent of the bars it began and ended on
        let captured = null;
        Element.prototype.setPointerCapture = function () { captured = this; };
        Element.prototype.releasePointerCapture = function () { if (captured === this) captured = null; };
        const under = x => { const i = Math.floor((x - 100) / slot); return i >= 0 && i < n ? view.querySelectorAll('.chart-hit')[i] : $('alerts-time-card'); };
        const send = (type, x) => dispatch(type, captured || under(x),
            { clientX: x, clientY: 100, button: 0, buttons: /up|cancel/.test(type) ? 0 : 1, pointerId: 7 });
        const lift = x => {
            const target = captured || svg();
            send('pointerup', x);
            captured = null;
            dispatch('click', target, { clientX: x, clientY: 100, button: 0 });
        };
        const cancel = x => { send('pointercancel', x); captured = null; };
        // New alerts ten days after the last one: other bars than those on screen
        const last = Math.max(...alerts.map(a => Date.parse(a.timestamp)).filter(Number.isFinite));
        const late = id => ({ id, timestamp: new Date(last + 10 * DAY).toISOString(), severity: 'high', engine: 'Sigma',
                              rule_name: 'Run Key', process_name: 'p.exe' });
        let bins = place(), drawn = svg();
        const r = { n };
        // A press drawing across bars 1 to 4 while new alerts come: they are counted, the bars on screen stay
        send('pointerdown', xOf(1)); send('pointermove', xOf(4));
        state.alerts = [...alerts, late('late')];
        renderAlertsTab();
        r.held = { kept: svg() === drawn, held: _alertsChartsDrawn.timeHeld, counted: _alertsChartsDrawn.time.bins.length,
                   bins: ALERTS_BARS_BRUSH.bins().length, count: $('alerts-count').textContent };
        // It is cancelled; in the same task a second press draws across bars 2 to 5 and is released
        cancel(xOf(4));
        send('pointerdown', xOf(2)); send('pointermove', xOf(5));
        r.second = { kept: svg() === drawn, mark: mark(), active: barsBrushActive(ALERTS_BARS_BRUSH),
                     brushing: view.classList.contains('is-brushing'), captured: captured !== null };
        lift(xOf(5));
        r.secondUp = drill();
        settle().then(() => {
            r.after = { redrawn: svg() !== drawn, n: shown().length, held: _alertsChartsDrawn.timeHeld };
            alertsDrillTo(-1);          // (no step to take back, unless the second press made one)
            // The new bars take a press again
            bins = place();
            send('pointerdown', xOf(2)); send('pointermove', xOf(5));
            r.again = { mark: mark(), slot };
            lift(xOf(5));
            r.againStep = { ...drill(), want: [bins[2][0], bins[5][1]] };
            // A press, its end, and in the same task a second press, during which new alerts come: that press
            // keeps its bars and its mark through the redraw the first one put off
            alertsDrillTo(-1);
            bins = place();
            drawn = svg();
            send('pointerdown', xOf(1)); send('pointermove', xOf(3));
            cancel(xOf(3));
            send('pointerdown', xOf(2)); send('pointermove', xOf(5));
            state.alerts = [...alerts, late('late'), late('later')];
            renderAlertsTab();
            return settle();
        }).then(() => {
            r.through = { kept: svg() === drawn, mark: mark(), slot, held: _alertsChartsDrawn.timeHeld,
                          active: barsBrushActive(ALERTS_BARS_BRUSH) };
            lift(xOf(5));
            r.released = { ...drill(), want: [bins[2][0], bins[5][1]], redrawn: svg() !== drawn,
                           bars: shown().reduce((sum, bin) => sum + bin[2], 0) };
            console.log(JSON.stringify(r));
        });
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    held = r["held"]
    assert held["kept"] and held["held"] and held["counted"] != r["n"], held
    assert held["count"] == "2346 of 2346", "the table did not count the new alerts"
    assert held["bins"] == 0, "the bars held back are offered to a press, though others are on screen"
    second = r["second"]
    assert second["kept"] and (second["mark"], second["active"], second["brushing"], second["captured"]) == \
        (None, False, False, False), f"a press on bars held back marked bars that are not on screen: {second}"
    assert r["secondUp"]["steps"] == [], "a press on bars held back narrowed by bars that are not on screen"
    assert r["after"] == {"redrawn": True, "n": r["held"]["counted"], "held": False}, \
        "the bars held back were not drawn once the task of the press's end was over"
    again = r["again"]
    assert again["mark"] and abs(again["mark"][0] - 2 * again["slot"]) < 0.02 and abs(again["mark"][1] - 4 * again["slot"]) < 0.02
    step = r["againStep"]
    assert step["steps"] == [{"dashboard": False, "before": {"range": {"from": None, "to": None}},
                              "after": {"range": {"from": step["want"][0], "to": step["want"][1]}}}]
    through = r["through"]
    assert through["kept"] and through["held"] and through["active"], \
        "the redraw a press put off was done during the press after it"
    assert through["mark"] and abs(through["mark"][0] - 2 * through["slot"]) < 0.02 \
        and abs(through["mark"][1] - 4 * through["slot"]) < 0.02, f"the mark of the second press is gone: {through}"
    released = r["released"]
    assert released["redrawn"], "OVER TIME does not show the new alerts after the release"
    assert released["steps"] == [{"dashboard": False, "before": {"range": {"from": None, "to": None}},
                                  "after": {"range": {"from": released["want"][0], "to": released["want"][1]}}}]
    assert released["count"] == f"{released['bars']} of 2347", "the bars count other alerts than the table"


@needs_node
def test_alerts_over_time_hint_and_info():
    """Under the bars of OVER TIME stands how to use them, as under ALERT
    ACTIVITY of the dashboard: "Drag across the bars to narrow the range ·
    click a bar to show only its period", on the line of the note of the
    alerts in no bar (before it). Without bars there is no hint: no alert
    matches, none has a time, there are none. The (i) of OVER TIME tells of
    drawing a range and of BACK. The bars select no text while a range is
    drawn across them and let a finger scroll the page; both themes style
    the line under them."""
    script = _alert_charts_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        const time = $('alerts-time-chart');
        const look = () => ({
            parts: time.children.map(c => [c.tagName.toLowerCase(), c.getAttribute('class')]),
            line: (time.querySelector('.alerts-chart-note') || { children: [] }).children
                .map(c => [c.getAttribute('class'), c.textContent, c.getAttribute('title')]),
            hintParts: (time.querySelector('.alerts-time-hint') || { children: [] }).children.map(c => c.textContent),
        });
        const untimed = alerts.filter(a => Number.isNaN(Date.parse(a.timestamp)));
        renderAlertsTab();
        const r = { all: { ...look(), untimed: untimed.length } };
        openAlertsTab({ process: 'nothing like it' });
        r.none = look();
        state.alerts = untimed;
        openAlertsTab({});
        r.untimed = { ...look(), untimed: untimed.length };
        state.alerts = [];
        renderAlertsTab();
        r.noAlerts = look();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    hint = "Drag across the bars to narrow the range \u00b7 click a bar to show only its period"
    missed = ["alerts-time-missed", f"{r['all']['untimed']} without time",
              "Alerts without a readable time or with one no clock can have had (before 2000, more than a day ahead) "
              "are in no bar; SEVERITY, ENGINE and FLOW count them"]
    every = r["all"]
    assert every["parts"] == [["svg", "chart-svg chart-bars"], ["div", "alerts-chart-note"]], \
        f"no line under the bars: {every['parts']}"
    assert every["line"] == [["alerts-time-hint", hint, None], missed], \
        f"the line under the bars does not say how to use them, then what is in no bar: {every['line']}"
    assert (r["none"]["parts"], r["none"]["line"]) == ([["div", "chart-empty"]], []), "a hint without bars"
    assert r["untimed"]["parts"] == [["div", "chart-empty"], ["div", "alerts-chart-note"]] and r["untimed"]["line"] == [missed], \
        "alerts without a time alone: a hint without bars, or no note of them"
    assert r["noAlerts"]["parts"] == [["div", "chart-empty"]]
    html = _read(INDEX_HTML)
    card = _element_markup(html, html.index('<div class="chart-card" id="alerts-time-card">'))
    info = re.search(r'<h3 class="chart-card-title" data-info="([^"]*)">OVER TIME</h3>', card)
    assert info and "Drag across the bars" in info.group(1), "the (i) of OVER TIME does not tell of drawing a range"
    assert info.group(1) == ("The alerts of the current filters per period, stacked by severity; alerts without a time "
                             "are noted below the bars. Drag across the bars or click a bar to narrow the tab to that "
                             "period, BACK above the charts goes back a step."), info.group(1)
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    bars = rules.get("#alerts-time-chart", "")
    assert re.search(r"(?:^|;)\s*user-select:\s*none", bars) and re.search(r"(?:^|;)\s*touch-action:\s*pan-y", bars), \
        "a range drawn across OVER TIME selects text, or a finger cannot draw one"
    line = rules.get(".alerts-chart-note", "")
    assert all(re.search(r"(?:^|;)\s*%s" % decl, line) for decl in (r"display:\s*flex", r"flex-wrap:\s*wrap",
                                                                    r"justify-content:\s*space-between")), \
        "the hint and the note of the alerts in no bar do not share the line under the bars"
    # On a narrow card (Classic at 1280 px) the hint breaks after its "·", not inside a phrase ("click a / bar"); on
    # one narrower than a half (below about 1220 px), that half wraps inside the card instead of running into ENGINE
    assert every["hintParts"] == ["Drag across the bars to narrow the range \u00b7", "click a bar to show only its period"], \
        every["hintParts"]
    half = rules.get(".alerts-time-hint span", "")
    assert re.search(r"(?:^|;)\s*display:\s*inline-block", half), "the hint breaks inside a phrase on a narrow card"
    assert not re.search(r"white-space:\s*nowrap", half), "a half of the hint wider than the card runs into the next card"
    assert _painted(rules, _cls("alerts-chart-note"), "color") and '[data-theme="cyberpunk"] .alerts-chart-note' in theme


# --- The drilldown bar of the Alerts tab ------------------------------------------

# What the drilldown bar shows: hidden or not, the texts of its path as seen
# (without the separators, and without the text for screen readers only,
# .visually-hidden), the parts of its path (tag, attributes, text as seen)
# and its count; the parts a click may hit, and where the keyboard focus is.
# How the focus came to an element: keyFocus from the keyboard (it then
# matches :focus-visible, as long as it is focused and in the page),
# mouseFocus by a click of the mouse (it does not); noFocusVisible() makes a
# browser that does not know the selector (matches throws).
DRILL_BAR_LOOK = r"""
    const drillBar = $('alerts-drill'), pathOf = () => $('alerts-drill-path');
    const back = drillBar.querySelector('[data-drill="back"]');
    const seen = node => node.nodeType === 3 ? node.textContent
        : node.classList.contains('visually-hidden') ? '' : node.childNodes.map(seen).join('');
    const bar = () => ({
        hidden: drillBar.hidden,
        path: pathOf().children.filter(el => !el.classList.contains('alerts-drill-sep')).map(seen),
        parts: pathOf().children.map(el => [el.tagName.toLowerCase(), { ...el.attrs }, seen(el)]),
        count: $('alerts-drill-count').textContent,
    });
    const stepAt = i => pathOf().querySelector(`[data-drill-step="${i}"]`);
    const focused = () => {
        const el = document.activeElement;
        return !el ? null : el === back ? 'back' : el.id || el.getAttribute('data-drill-step') || el.tagName.toLowerCase();
    };
    const look = () => ({ bar: bar(), labels: alertsDrilldown.map(alertsStepLabel), version: alertsDrillVersion,
                          table: $('alerts-count').textContent, filter: { ...alertsExtraFilter }, focus: focused() });
    const fromKeys = new Set(), plainMatches = Element.prototype.matches;
    let knowsFocusVisible = true;
    Element.prototype.matches = function (selector) {
        if (selector !== ':focus-visible') return plainMatches.call(this, selector);
        if (!knowsFocusVisible) throw new SyntaxError(`'${selector}' is not a valid selector`);
        return document.activeElement === this && this.isConnected && fromKeys.has(this);
    };
    const keyFocus = el => { fromKeys.add(el); el.focus(); };
    const mouseFocus = el => { fromKeys.delete(el); el.focus(); };
    const noFocusVisible = () => { knowsFocusVisible = false; };
"""

DRILL_INFO = ("Each click on a chart and each range drawn across OVER TIME that changes a filter is a step here. BACK goes "
              "back one step, a step goes back to it, ALL ALERTS takes every step off.")
SEP = ["span", {"class": "alerts-drill-sep", "aria-hidden": "true"}, "\u203a"]


def _drill_bar_script(script):
    return _drill_script(DRILL_BAR_LOOK + script)


def _drill_step(i, label, current=False):
    """A step of the path as DRILL_BAR_LOOK gives it: a button that jumps back
    to it, or the current step (no button)."""
    if current:
        return ["span", {"class": "alerts-drill-step is-current", "aria-current": "step", "title": label}, label]
    return ["button", {"type": "button", "class": "alerts-drill-step", "data-drill-step": str(i), "title": label}, label]


ALL_ALERTS = ["button", {"type": "button", "class": "alerts-drill-step", "data-drill-step": "-1"}, "ALL ALERTS"]


def _joined(*parts):
    """The parts of a path with › between them."""
    return [part for i, p in enumerate(parts) for part in ([SEP, p] if i else [p])]


@needs_node
def test_drilldown_bar_shows_the_path():
    """Between the head of the tab and its charts stands the drilldown bar,
    hidden while there is no step: ‹ BACK, DRILLDOWN with its (i), the path
    and the count. The path begins with ALL ALERTS and ends with the current
    step, which is no button; the steps between are buttons that jump back
    to them, › between them; each step's title has its name in full. Of more
    steps than three, the older ones fall together into "…", whose title
    names them. The count is that of the table, with separators. A name from
    the data (markup, a quote, 300 characters) stays text. New alerts change
    the count and keep the path, its very buttons (one in focus keeps it).
    The path is drawn again whenever the steps changed, also when the
    filters did not: a jump from the dashboard to the range a bar set makes
    the step "14 Jul" "Dashboard: 14 Jul"; a severity chip switched by hand
    takes the step of SEVERITY out of it at once. The (i) of the tab tells
    of the steps and BACK."""
    html = _read(INDEX_HTML)
    tab = _Elements(html).by_id("tab-alerts")
    nav = tab["children"][1]
    assert (nav["tag"], nav["attrs"]) == ("nav", {"class": "alerts-drill", "id": "alerts-drill", "aria-label": "Drilldown",
                                                  "hidden": "", "onclick": "onAlertsDrillClick(event)"}), \
        "no drilldown bar between the head of the tab and its charts"
    # BACK's ‹ stands in a span of its own, hidden from screen readers:
    # test_drilldown_bar_names_where_back_goes_and_the_folded_steps
    assert [(c["tag"], c["attrs"], c.get("text", "")) for c in nav["children"]] == [
        ("button", {"type": "button", "class": "alerts-drill-back", "data-drill": "back"}, " BACK"),
        ("span", {"class": "alerts-drill-label", "data-info": DRILL_INFO}, "DRILLDOWN"),
        ("span", {"class": "alerts-drill-path", "id": "alerts-drill-path"}, ""),
        ("span", {"class": "alerts-drill-count", "id": "alerts-drill-count"}, ""),
    ]
    head = tab["children"][0]
    heading = next(c for c in head["children"] if c["tag"] == "h2")["attrs"]["data-info"]
    assert len(heading) <= 300 and "BACK" in heading and "OVER TIME" in heading and "as a chip" not in heading, \
        f"the (i) of the tab does not tell of the steps of the drilldown and BACK: {heading}"

    script = _drill_bar_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        const r = { start: bar() };
        // Two steps: the bar of 14 Jul, then 10:00-12:00 of that day
        click(dayBar(14)); drillAlerts({ from: at(14, 10), to: at(14, 12) });
        r.two = look();
        // Five: then HIGH, Sigma and the rule Run Key; the two oldest fall together into "…"
        drillAlerts({ severities: ['high'] }); drillAlerts({ engine: 'sigma' }); drillAlerts({ rule: 'Run Key' });
        r.five = look();
        // New alerts: the count follows them, the path stays as it is, its very nodes
        const nodes = pathOf().children;
        state.alerts = [...alerts, { id: 'new', timestamp: new Date(at(14, 11)).toISOString(), severity: 'high',
                                     engine: 'Sigma', rule_name: 'Run Key', process_name: 'x.exe' }];
        renderAlertsTab();
        r.polled = { ...look(), same: pathOf().children.length === nodes.length
                                      && pathOf().children.every((el, i) => el === nodes[i]) };
        state.alerts = alerts;
        renderAlertsTab();
        // Names from the data stay text, in full in their titles (one of 300 characters too)
        alertsDrillTo(-1);
        const LONG = ('A' + QUOTE + EVIL).repeat(20).slice(0, 299) + 'Z';
        drillAlerts({ rule: EVIL }); drillAlerts({ process: QUOTE }); drillAlerts({ category: LONG });
        r.hostile = { ...look(), markup: ['img', 'b', 'script'].map(tag => drillBar.querySelectorAll(tag).length) };
        // ... also where they fall together into "…"
        drillAlerts({ severities: ['high'] }); drillAlerts({ engine: 'sigma' });
        r.hostileMore = { ...look(), markup: ['img', 'b', 'script'].map(tag => drillBar.querySelectorAll(tag).length) };
        // The steps change, the filters do not: a jump from the dashboard to the range the bar of 14 Jul set
        alertsDrillTo(-1);
        click(dayBar(14));
        r.day = look();
        const row = $('alerts-rows').firstElementChild, range = { ...alertsExtraFilter };
        state.activeTab = 'dashboard';
        openAlertsTab({ from: range.from, to: range.to });
        r.jump = { ...look(), sameRows: $('alerts-rows').firstElementChild === row };
        // A severity chip switched by hand: the step of SEVERITY leaves the path at once
        click(seg('alerts-severity-chart', 'high')); r.high = look();
        click(document.querySelector('#tab-alerts .alerts-sev-chip[data-severity="medium"]')); r.chip = look();
        alertsDrillTo(-1); r.end = look();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    assert r["start"] == {"hidden": True, "path": [], "parts": [], "count": "2,345 of 2,345 alerts"}, \
        "the bar shows without a step"

    def count(look):
        shown, total = look["table"].split(" of ")
        return f"{int(shown):,} of {int(total):,} alerts"
    two = r["two"]
    assert two["labels"] == ["14 Jul", "14 Jul 10:00\u201312:00"]
    assert (two["bar"]["hidden"], two["bar"]["path"]) == (False, ["ALL ALERTS", "14 Jul", "14 Jul 10:00\u201312:00"])
    assert two["bar"]["parts"] == _joined(ALL_ALERTS, _drill_step(0, "14 Jul"), _drill_step(1, "14 Jul 10:00\u201312:00", True)), \
        two["bar"]["parts"]
    assert two["bar"]["count"] == count(two) and 0 < int(two["table"].split(" of ")[0]) < 2345
    five = r["five"]
    s = five["labels"]
    assert s == ["14 Jul", "14 Jul 10:00\u201312:00", "HIGH", "Sigma", "rule: Run Key"]
    assert five["bar"]["path"] == ["ALL ALERTS", "\u2026", s[2], s[3], s[4]]
    more = ["span", {"class": "alerts-drill-more", "title": f"{s[0]} \u203a {s[1]}"}, "\u2026"]
    assert five["bar"]["parts"] == _joined(ALL_ALERTS, more, _drill_step(2, s[2]), _drill_step(3, s[3]),
                                           _drill_step(4, s[4], True)), five["bar"]["parts"]
    assert five["bar"]["count"] == count(five)
    polled = r["polled"]
    assert polled["same"] and (polled["labels"], polled["bar"]["parts"]) == (five["labels"], five["bar"]["parts"]), \
        "new alerts drew the path anew (a step in focus loses it) or changed it"
    assert polled["table"] == f"{int(five['table'].split(' of ')[0]) + 1} of 2346" and polled["bar"]["count"] == count(polled)
    hostile = r["hostile"]
    long = ("A" + QUOTE + EVIL) * 20
    long = long[:299] + "Z"
    names = [f"rule: {EVIL}", f"process: {QUOTE}", f"category: {long}"]
    assert hostile["labels"] == names and len(long) == 300
    assert hostile["markup"] == [0, 0, 0], "a name from the data became markup in the path"
    assert hostile["bar"]["path"] == ["ALL ALERTS", *names]
    assert hostile["bar"]["parts"] == _joined(ALL_ALERTS, _drill_step(0, names[0]), _drill_step(1, names[1]),
                                              _drill_step(2, names[2], True)), "a name left its text or its title"
    more_hostile = r["hostileMore"]
    folded = ["span", {"class": "alerts-drill-more", "title": f"{names[0]} \u203a {names[1]}"}, "\u2026"]
    assert more_hostile["markup"] == [0, 0, 0] and more_hostile["bar"]["parts"] == _joined(
        ALL_ALERTS, folded, _drill_step(2, names[2]), _drill_step(3, "HIGH"), _drill_step(4, "Sigma", True)), \
        "a name left the title of \u2026"
    # The same filters, other steps: the path drawn again though the table was not
    jump = r["jump"]
    assert r["day"]["bar"]["path"] == ["ALL ALERTS", "14 Jul"]
    assert jump["sameRows"] and jump["filter"] == r["day"]["filter"], "the jump changed the filters or drew the table again"
    assert jump["labels"] == ["Dashboard: 14 Jul"] and jump["bar"]["path"] == ["ALL ALERTS", "Dashboard: 14 Jul"], \
        "the path still names the step the jump replaced"
    assert jump["bar"]["count"] == r["day"]["bar"]["count"]
    assert r["high"]["bar"]["path"] == ["ALL ALERTS", "Dashboard: 14 Jul", "HIGH"]
    assert r["chip"]["bar"]["path"] == ["ALL ALERTS", "Dashboard: 14 Jul"] and r["chip"]["bar"]["count"] == count(r["chip"]), \
        "the path still names the step a chip switched by hand replaced"
    assert (r["end"]["bar"]["hidden"], r["end"]["bar"]["path"]) == (True, [])


@needs_node
def test_drilldown_bar_names_where_back_goes_and_the_folded_steps():
    """For screen readers: the ‹ of BACK is hidden from them, so BACK reads
    as "BACK"; its title and its name say where it goes, "Back to" the step
    before the last ("Back to all alerts" from the only step), and follow
    the steps (BACK, a step a filter set by hand drops; new alerts leave
    them as they are). The "…" of the folded steps names them in a text for
    screen readers only (.visually-hidden: out of sight and of the layout,
    with no colour of its own) beside its title, while the bar shows "…"
    alone. A click on the ‹ is a click on BACK. Names from the data
    (markup, a quote, 300 characters) stay text."""
    back = next(c for c in _Elements(_read(INDEX_HTML)).by_id("alerts-drill")["children"]
                if c["attrs"].get("data-drill") == "back")
    assert (back.get("text", ""), [(c["tag"], c["attrs"], c.get("text", "")) for c in back["children"]]) == \
        (" BACK", [("span", {"aria-hidden": "true"}, "\u2039")]), "a screen reader reads the \u2039 of BACK"
    hidden = _rules(STYLE_CSS).get(".visually-hidden", "")
    props = ("position", "width", "height", "margin", "padding", "overflow", "clip", "clip-path", "white-space", "border")
    assert [_declared(hidden, p) for p in props] == \
        ["absolute", "1px", "1px", "-1px", "0", "hidden", "rect(0, 0, 0, 0)", "inset(50%)", "nowrap", "0"], \
        f"the text for screen readers only takes room or shows: {hidden}"
    assert not re.search(r"(?:^|;)\s*(?:color|background|fill|stroke|box-shadow|text-shadow)", hidden), hidden

    script = _drill_bar_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        // BACK's title and name; the text for screen readers only in the path, by the element that holds it; the
        // parts of "…" (text, or tag, attributes and text)
        const backOf = () => ({ title: back.getAttribute('title'), label: back.getAttribute('aria-label') });
        const unseen = () => pathOf().querySelectorAll('.visually-hidden').map(el => [el.parentElement.className, el.textContent]);
        const more = () => {
            const el = pathOf().querySelector('.alerts-drill-more');
            return el && el.childNodes.map(n => n.nodeType === 3 ? n.textContent : [n.tagName.toLowerCase(), { ...n.attrs }, n.textContent]);
        };
        const read = () => ({ ...look(), back: backOf(), unseen: unseen(), more: more(),
                              markup: ['img', 'b', 'script'].map(tag => drillBar.querySelectorAll(tag).length) });
        const r = {};
        // One step: BACK goes back to all alerts
        click(dayBar(14)); r.one = read();
        // Three: BACK goes back to the second; nothing folds
        drillAlerts({ from: at(14, 10), to: at(14, 12) }); drillAlerts({ severities: ['high'] }); r.three = read();
        // A click on the ‹ of BACK: two steps left, BACK goes back to the first; new alerts leave that as it is
        click(back.querySelector('[aria-hidden="true"]') || back); r.two = read();
        state.alerts = [...alerts, { id: 'new', timestamp: new Date(at(14, 11)).toISOString(), severity: 'high',
                                     engine: 'Sigma', rule_name: 'Run Key', process_name: 'x.exe' }];
        renderAlertsTab(); r.polled = read();
        state.alerts = alerts; renderAlertsTab();
        // Names from the data: three steps of them, then five, the two oldest folded into "…"
        alertsDrillTo(-1);
        const LONG = ('A' + QUOTE + EVIL).repeat(20).slice(0, 299) + 'Z';
        drillAlerts({ rule: EVIL }); drillAlerts({ process: QUOTE }); drillAlerts({ category: LONG }); r.hostile = read();
        drillAlerts({ severities: ['high'] }); drillAlerts({ engine: 'sigma' }); r.five = read();
        // The engine chosen by hand: the step Sigma drops out; BACK and "…" follow
        const select = $('alerts-filter-engine');
        select.value = 'Yara'; dispatch('change', select); r.byHand = read();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())

    def to(name):
        return {"title": f"Back to {name}", "label": f"Back to {name}"}
    one, three, two = r["one"], r["three"], r["two"]
    assert (one["labels"], one["back"]) == (["14 Jul"], to("all alerts")), f"BACK of the only step: {one['back']}"
    assert three["labels"] == ["14 Jul", "14 Jul 10:00\u201312:00", "HIGH"]
    assert three["back"] == to("14 Jul 10:00\u201312:00"), f"BACK does not name the step it goes back to: {three['back']}"
    assert (two["labels"], two["back"]) == (["14 Jul", "14 Jul 10:00\u201312:00"], to("14 Jul")), \
        f"a click on the \u2039 is no BACK, or BACK's title stays as it was: {two['labels']}, {two['back']}"
    assert (r["polled"]["back"], r["polled"]["version"]) == (two["back"], two["version"])
    assert (one["unseen"], three["unseen"], two["unseen"], three["more"]) == ([], [], [], None), \
        "text for screen readers only without a step folded"
    long = (("A" + QUOTE + EVIL) * 20)[:299] + "Z"
    names = [f"rule: {EVIL}", f"process: {QUOTE}", f"category: {long}"]
    hostile = r["hostile"]
    assert hostile["labels"] == names and hostile["back"] == to(names[1]) and hostile["markup"] == [0, 0, 0], \
        f"a name from the data left BACK's title or became markup: {hostile['back']}"
    five, folded = r["five"], f"{names[0]} \u203a {names[1]}"
    assert five["back"] == to("HIGH") and five["markup"] == [0, 0, 0]
    assert five["more"] == ["\u2026", ["span", {"class": "visually-hidden"}, folded]], \
        f"the \u2026 does not name the folded steps for screen readers: {five['more']}"
    assert five["unseen"] == [["alerts-drill-more", folded]], five["unseen"]
    assert five["bar"]["path"] == ["ALL ALERTS", "\u2026", names[2], "HIGH", "Sigma"]
    assert five["bar"]["parts"][2] == ["span", {"class": "alerts-drill-more", "title": folded}, "\u2026"], \
        "the \u2026 lost its title"
    by_hand = r["byHand"]
    assert (by_hand["labels"], by_hand["back"]) == ([*names, "HIGH"], to(names[2])), \
        f"BACK still names a step a filter set by hand dropped: {by_hand['back']}"
    assert by_hand["unseen"] == [["alerts-drill-more", names[0]]], by_hand["unseen"]


@needs_node
def test_drilldown_bar_clicks():
    """A click in the drilldown bar, one handler for the bar reading the
    number of the step from its data- attribute: BACK takes the last step
    back, a step jumps back to the state after it (the later ones taken
    back), ALL ALERTS takes every step back; ›, DRILLDOWN, "…", the current
    step, the count and the bar itself do nothing. The keyboard focus stays
    where it was if it can: on BACK while steps are left; a step in focus
    drawn anew hands it to BACK; when the bar goes, the focus moves on to the
    search box (after a click of the mouse it does not:
    test_drilldown_bar_moves_on_keyboard_focus_only). New alerts leave a step
    in focus as it is."""
    script = _drill_bar_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        click(dayBar(14)); drillAlerts({ from: at(14, 10), to: at(14, 12) });
        const r = { two: look() };
        drillAlerts({ severities: ['high'] }); r.three = look();
        // BACK from the keyboard: a step less, the focus stays on it
        keyFocus(back); click(back); r.back = look();
        // A step: the state after it; the step in focus is drawn anew, the focus goes to BACK
        drillAlerts({ severities: ['high'] });
        keyFocus(stepAt(0)); click(stepAt(0)); r.toFirst = look();
        // New alerts while a step is in focus: the path stays, the focus with it
        drillAlerts({ from: at(14, 10), to: at(14, 12) });
        const kept = stepAt(0);
        keyFocus(kept);
        state.alerts = [...alerts, { id: 'new', timestamp: new Date(at(14, 11)).toISOString(), severity: 'high',
                                     engine: 'Sigma', rule_name: 'Run Key', process_name: 'x.exe' }];
        renderAlertsTab();
        r.polled = { ...look(), kept: document.activeElement === kept && kept.isConnected };
        state.alerts = alerts;
        renderAlertsTab();
        // ›, DRILLDOWN, the current step, the count, the path and the bar itself: nothing
        const before = look();
        const parts = [pathOf().querySelector('.alerts-drill-sep'), drillBar.querySelector('.alerts-drill-label'),
                       pathOf().querySelector('[aria-current="step"]'), $('alerts-drill-count'), pathOf(), drillBar];
        parts.forEach(el => click(el));
        r.nothing = { before, after: look(), hit: parts.map(el => !!el) };
        // "…" (five steps): nothing either
        drillAlerts({ severities: ['high'] }); drillAlerts({ engine: 'sigma' }); drillAlerts({ rule: 'Run Key' });
        const five = look();
        click(pathOf().querySelector('.alerts-drill-more'));
        r.more = { before: five, after: look() };
        // ALL ALERTS from the keyboard: no step left, the bar hidden, the focus on the search box
        keyFocus(stepAt(-1)); click(stepAt(-1)); r.all = look();
        // BACK of the only step, from the keyboard: the same
        click(dayBar(14)); keyFocus(back); click(back); r.lastBack = look();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    two, three, back = r["two"], r["three"], r["back"]
    assert three["labels"] == ["14 Jul", "14 Jul 10:00\u201312:00", "HIGH"]
    assert (back["labels"], back["table"], back["filter"], back["bar"]["path"]) == \
        (two["labels"], two["table"], two["filter"], ["ALL ALERTS", "14 Jul", "14 Jul 10:00\u201312:00"]), \
        "BACK does not take the last step back"
    assert back["focus"] == "back" and not back["bar"]["hidden"], "BACK lost the focus while steps are left"
    to_first = r["toFirst"]
    assert (to_first["labels"], to_first["bar"]["path"]) == (["14 Jul"], ["ALL ALERTS", "14 Jul"]), \
        "a click on the first step does not leave that step alone"
    assert to_first["focus"] == "back", f"the focus on a step drawn anew got lost: {to_first['focus']}"
    polled = r["polled"]
    assert polled["kept"] and polled["labels"] == ["14 Jul", "14 Jul 10:00\u201312:00"], \
        "new alerts took the focus off a step"
    nothing = r["nothing"]
    assert all(nothing["hit"]) and nothing["after"] == nothing["before"], \
        f"a click on a separator, DRILLDOWN, the current step or the count changed something: {nothing}"
    assert r["more"]["after"] == r["more"]["before"] and "\u2026" in r["more"]["before"]["bar"]["path"]
    for name in ("all", "lastBack"):
        gone = r[name]
        assert (gone["labels"], gone["filter"], gone["table"], gone["bar"]["hidden"]) == ([], NO_EXTRA, "2345 of 2345", True), \
            f"{name}: steps left, or the bar still shows"
        assert gone["focus"] == "alerts-filter-text", f"{name}: the focus left with the bar ({gone['focus']})"
    assert r["all"]["version"] > r["more"]["after"]["version"]


@needs_node
def test_drilldown_bar_moves_on_keyboard_focus_only():
    """The bar goes with the focus in it (ALL ALERTS, BACK of the only step):
    a focus that came from the keyboard (:focus-visible) moves on to the
    search box; after a click of the mouse the focus stays where the browser
    leaves it, so the search box neither lights up nor opens a touch
    keyboard. A browser that does not know :focus-visible counts as the
    keyboard. A focus outside the bar stays where it is when the bar goes:
    the chip MEDIUM switched from the keyboard takes the only step (MEDIUM)
    off."""
    script = _drill_bar_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        renderAlertsTab();
        const r = {};
        const twoSteps = () => { click(dayBar(14)); drillAlerts({ from: at(14, 10), to: at(14, 12) }); };
        // ALL ALERTS from the keyboard, then by the mouse
        twoSteps();
        let all = stepAt(-1);
        keyFocus(all); click(all); r.allKeys = look();
        twoSteps();
        all = stepAt(-1);
        mouseFocus(all); click(all); r.allMouse = { ...look(), left: document.activeElement === all };
        // BACK of the only step from the keyboard, then by the mouse
        click(dayBar(14)); keyFocus(back); click(back); r.backKeys = look();
        click(dayBar(14)); mouseFocus(back); click(back); r.backMouse = { ...look(), left: document.activeElement === back };
        // The focus outside the bar: on the chip MEDIUM, which takes the only step (MEDIUM) off
        click(seg('alerts-severity-chart', 'medium')); r.medium = look();
        const chip = document.querySelector('#tab-alerts .alerts-sev-chip[data-severity="medium"]');
        keyFocus(chip); click(chip);
        r.chip = { ...look(), left: document.activeElement === chip, pressed: chip.getAttribute('aria-pressed') };
        // A browser without :focus-visible (the selector throws): ALL ALERTS as from the keyboard
        noFocusVisible();
        twoSteps();
        all = stepAt(-1);
        all.focus(); click(all); r.unknown = look();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    for name in ("allKeys", "allMouse", "backKeys", "backMouse", "unknown"):
        gone = r[name]
        assert (gone["labels"], gone["filter"], gone["table"], gone["bar"]["hidden"]) == ([], NO_EXTRA, "2345 of 2345", True), \
            f"{name}: steps left, or the bar still shows"
    for name in ("allKeys", "backKeys", "unknown"):
        assert r[name]["focus"] == "alerts-filter-text", f"{name}: the keyboard focus left with the bar ({r[name]['focus']})"
    assert (r["allMouse"]["focus"], r["allMouse"]["left"]) == ("-1", True), \
        f"a click of the mouse on ALL ALERTS moved the focus on to {r['allMouse']['focus']}"
    assert (r["backMouse"]["focus"], r["backMouse"]["left"]) == ("back", True), \
        f"a click of the mouse on BACK moved the focus on to {r['backMouse']['focus']}"
    assert r["medium"]["labels"] == ["MEDIUM"] and not r["medium"]["bar"]["hidden"]
    chip = r["chip"]
    assert (chip["labels"], chip["bar"]["hidden"], chip["pressed"]) == ([], True, "false")
    assert chip["left"], f"the bar took the focus off the chip MEDIUM ({chip['focus']})"


@needs_node
def test_drilldown_bar_stands_at_the_top():
    """While the tab scrolls, the drilldown bar stands at its top, opaque in
    both themes and over the layer of the filter bar, which stands right
    under it, the table head under both (--alerts-path-height: the bar's
    border box, which initAlertsTab keeps on the tab, 0 px while it is
    hidden). The bar keeps one line, a step at most 28 characters with an
    ellipsis; it takes no room while hidden and does not shrink into the
    tab. BACK is filled like the main buttons of the theme. The Sysmon tab's
    filter bar stays at the top of its tab. The list starts right under both
    bars: scrolled down, a filter change starts it there, whether the change
    shows the bar, keeps it or hides it; scrolled above it, nothing moves."""
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    drill = rules.get(".alerts-drill", "")
    assert re.search(r"position:\s*sticky", drill) and _declared(drill, "top") == "0", "the drilldown bar scrolls away"

    def layer(body):
        return int(re.search(r"z-index:\s*(\d+)", body).group(1))
    assert layer(drill) > layer(rules.get(".alerts-filters", "")) > layer(rules.get(".alerts-table thead th", "")), \
        "the filter bar or the table head passes over the drilldown bar"
    assert _declared(drill, "flex") in ("none", "0 0 auto"), "the bar shrinks into the tab"
    assert (_declared(drill, "white-space"), _declared(drill, "overflow")) == ("nowrap", "hidden"), "the bar takes a second line"
    step = rules.get(".alerts-drill-step", "")
    assert (_declared(step, "max-width"), _declared(step, "overflow"), _declared(step, "text-overflow"),
            _declared(step, "white-space")) == ("28ch", "hidden", "ellipsis", "nowrap"), "a long name widens the path"
    assert _declared(rules.get(".alerts-drill[hidden]", ""), "display") == "none", "the bar takes room without a step"
    cyberpunk = theme.get('[data-theme="cyberpunk"] .alerts-drill', "")
    for name, palette, value in (("Classic", _resolve(_root_values()), _background(drill)),
                                 ("Cyberpunk", _cyberpunk_palette(), _background(cyberpunk) or _background(drill))):
        colour = re.sub(r"var\(\s*(--[\w-]+)\s*\)", lambda m: palette[m.group(1)], value or "")
        assert re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", colour), f"{name}: the rows show through the bar ({value})"
    for selector, body in theme.items():
        if re.search(r"\.alerts-drill$", selector):
            assert not re.search(r"(?:^|;)\s*(?:position|top|z-index|overflow(?:-[xy])?|white-space|flex)\s*:", body), selector
    # BACK: filled, as a main button of the theme (Classic's in its accent blue, Cyberpunk's in magenta)
    back, primary = rules.get(".alerts-drill-back", ""), rules.get(".btn-primary", "")
    assert [_declared(back, p) for p in ("background", "color")] == [_declared(primary, p) for p in ("background", "color")] \
        and _declared(primary, "border-color") in (_declared(back, "border") or ""), "BACK does not look like a main button"
    cp_back, cp_primary = theme.get('[data-theme="cyberpunk"] .alerts-drill-back', ""), \
        theme.get('[data-theme="cyberpunk"] .btn-primary', "")
    assert [_declared(cp_back, p) for p in ("background", "color")] == [_declared(cp_primary, p) for p in ("background", "color")] \
        == ["var(--cp-magenta)", "var(--cp-on-magenta)"], "BACK is not filled in magenta in Cyberpunk"
    assert _declared(rules.get(".sysmon-filters", ""), "top") == "0", "the Sysmon tab's filter bar moved"

    script = _drill_bar_script(r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'alerts' };
        const tab = $('tab-alerts'), filters = document.querySelector('#tab-alerts .alerts-filters');
        // initAlertsTab keeps the bar's border box on the tab
        const resizers = [];
        globalThis.ResizeObserver = class {
            constructor(callback) { this.callback = callback; resizers.push(this); }
            observe(el, options) { this.el = el; this.options = options; }
        };
        globalThis.requestAnimationFrame = fn => fn();
        globalThis.redrawAlertsChartsOnResize = () => {};
        tab.style.setProperty = (name, value) => { tab.style[name] = value; };
        $('alerts-table').tHead.style.setProperty = () => {};
        initAlertsTab();
        const watch = resizers.find(o => o.el === drillBar);
        const r = { observed: watch ? [watch.options || null] : null };
        drillBar.rect = { top: 0, height: 41.5 };
        if (watch) watch.callback([]);
        r.height = tab.style['--alerts-path-height'];
        // The layout: the tab 56 px below the top of the window; its head 90 px high, the drilldown bar 14 px below
        // it (40 px high; no room while hidden), the charts (500 px), the filter bar (60 px), then the table. The bars
        // stand at the top of the tab once what is above them has scrolled away.
        const HEAD = 90, GAP = 14, PATH = 40, CHARTS = 500, BAR = 60;
        const pathHeight = () => (drillBar.hidden ? 0 : PATH);
        const above = () => HEAD + (drillBar.hidden ? 0 : GAP + PATH);
        tab.getBoundingClientRect = () => ({ top: 56, height: 800, width: 0 });
        drillBar.getBoundingClientRect = () => (drillBar.hidden ? { top: 0, height: 0, width: 0 }
            : { top: 56 + Math.max(0, HEAD + GAP - tab.scrollTop), height: PATH, width: 0 });
        filters.getBoundingClientRect = () => ({ top: 56 + Math.max(pathHeight(), above() + CHARTS - tab.scrollTop), height: BAR,
                                                 width: 0 });
        $('alerts-table-wrap').getBoundingClientRect = () => ({ top: 56 + above() + CHARTS + BAR - tab.scrollTop, width: 0 });
        // Where the list begins, from the top of the tab, and how high the bars standing over it are
        const where = () => ({ scroll: tab.scrollTop, list: $('alerts-table-wrap').getBoundingClientRect().top - 56,
                               bars: pathHeight() + BAR, hidden: drillBar.hidden });
        renderAlertsTab();
        r.hiddenTop = _alertsListTop(tab);
        // Scrolled down the list, the first step: the bar shows, the list starts right under both bars
        tab.scrollTop = 3000;
        click(dayBar(14));
        r.shown = where();
        r.shownTop = _alertsListTop(tab);
        // ... a step more (the bar stays), then ALL ALERTS (the bar goes): right under the bars there are
        tab.scrollTop = 3000;
        click(seg('alerts-severity-chart', 'high'));
        r.kept = where();
        tab.scrollTop = 3000;
        click(stepAt(-1));
        r.gone = where();
        // Scrolled above the list: nothing moves
        tab.scrollTop = 30;
        click(dayBar(14));
        r.above = where();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(ALERTS_TAB_FUNCTIONS, script, SORT_DOM + _alerts_prelude())
    assert r["observed"] == [{"box": "border-box"}] and r["height"] == "41.5px", \
        f"the tab does not keep the drilldown bar's height, border included: {r}"
    assert (r["hiddenTop"], r["shownTop"]) == (90 + 500 + 60 - 60, 90 + 14 + 40 + 500 + 60 - 100), \
        "the list does not start right under both bars (40 px and 60 px)"
    for name in ("shown", "kept", "gone"):
        assert r[name]["scroll"] < 3000 and r[name]["list"] == r[name]["bars"], \
            f"{name}: after a filter change the first row is not right under the bars: {r[name]}"
    assert (r["shown"]["hidden"], r["kept"]["hidden"], r["gone"]["hidden"]) == (False, False, True)
    assert r["above"]["scroll"] == 30, "a filter change moved a tab scrolled above its list"


def _px(value):
    """A length in px (0 for 0), None for anything else."""
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)px|-?0", (value or "").strip())
    return float(m.group(1) or 0) if m else None


def _side(body, prop, side):
    """The value a rule body gives one side (top, right, bottom, left) of a
    box property (padding, margin): its last declaration, the longhand or
    the shorthand of one to four values."""
    sides, value = ["top", "right", "bottom", "left"], None
    for name, given in re.findall(r"(?:^|;)\s*(%s(?:-(?:top|right|bottom|left))?)\s*:\s*([^;]+)" % re.escape(prop), body or ""):
        if name == prop:
            v = given.split()
            value = {1: v * 4, 2: v * 2, 3: v + v[1:2], 4: v}[len(v)][sides.index(side)]
        elif name == f"{prop}-{side}":
            value = given.strip()
    return value


def _shrink(body):
    """The flex-shrink a rule body gives: its own declaration or the second
    number of flex (None for none)."""
    found = re.findall(r"(?:^|;)\s*(flex-shrink|flex)\s*:\s*([^;]+)", body or "")
    if not found:
        return None
    name, value = found[-1]
    return float(value.split()[1] if name == "flex" else value)


def test_drilldown_bar_steps_keep_their_underline_and_give_way_in_turn():
    """A step a click goes back to is underlined. Its box cuts a long name
    with an ellipsis and with it all that passes its edge, so it leaves the
    underline room below the text (padding, taken back by a negative margin:
    the bar keeps its height); the path, which cuts what passes its own edge,
    leaves that room and the focus ring around it room below the steps (in
    both themes). Where the path does not fit, the steps between ALL ALERTS
    and the current one give way first, so far ahead that the current one
    keeps every pixel while they can (its share of the shrinking, its width
    of at most 28ch, some 200 px, by the ratio of the two, stays below
    1/128 px, the precision of the layout: below that the current step
    would lose its last letter to an ellipsis); then the current one, down
    to 8 characters, cut with an ellipsis instead of at the path's edge.
    ALL ALERTS stays whole."""
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    step = rules.get(".alerts-drill-step", "")
    assert "underline" in (_declared(step, "text-decoration") or "") and _declared(step, "overflow") == "hidden"
    offset, room = _px(_declared(step, "text-underline-offset")), _px(_side(step, "padding", "bottom"))
    assert room is not None and room >= offset + 1, \
        f"the underline ({offset} px below the text) lies outside the box of a step, which cuts it off (room: {room})"
    assert _px(_side(step, "margin", "bottom")) == -room, "the room for the underline makes the drilldown bar higher"
    assert _px(_side(step, "padding", "top")) == 0, "the text of a step moved down"

    def ring(body):
        width = re.match(r"(\d+(?:\.\d+)?px)", _declared(body, "outline") or "")
        return _px(width.group(1)) + _px(_declared(body, "outline-offset"))
    reach = max(ring(rules.get(".alerts-drill-step:focus-visible", "")),
                ring(theme.get('[data-theme="cyberpunk"] .alerts-drill-step:focus-visible', "")))
    path = rules.get(".alerts-drill-path", "")
    below = _px(_side(path, "padding", "bottom"))
    assert _declared(path, "overflow") == "hidden" and below is not None and below >= room + reach, \
        f"the focus ring of a step is cut off below it ({room} + {reach} px, room: {below})"
    assert _px(_side(path, "margin", "bottom")) == -below and _px(_side(path, "padding", "top")) >= reach \
        and _px(_side(path, "margin", "top")) == -_px(_side(path, "padding", "top")), \
        "the path makes the drilldown bar higher, or cuts the focus ring above the steps"
    for selector, body in theme.items():
        if re.search(r"\.alerts-drill-(?:step|path)$", selector):
            assert not re.search(r"(?:^|;)\s*(?:padding|margin|overflow|flex|text-underline-offset)(?:-[a-z]+)?\s*:", body), \
                selector
    first = rules.get('.alerts-drill-step[data-drill-step="-1"]', "")
    current = rules.get(".alerts-drill-step.is-current", "")
    between, last = _shrink(step), _shrink(current)
    assert _shrink(first) == 0, "ALL ALERTS gives way"
    assert last and last > 0 and _declared(current, "min-width") == "8ch", \
        "the current step is cut at the path's edge without an ellipsis, or shrinks to nothing"
    assert between / last >= 128 * 200, \
        f"the current step gives way while a step between it and ALL ALERTS still can ({between} : {last})"


# --- The charts of the dashboard ------------------------------------------------

DASHBOARD_JS = list(dict.fromkeys(["renderDashboard", "onTileKey"] + NEWEST_ALERTS_FUNCTIONS + ALERTS_TAB_FUNCTIONS
                                  + DASHBOARD_CHART_FUNCTIONS))


def _dashboard_prelude(zone="UTC"):
    # The range drawn across bars comes with the Alerts tab's prelude (BARS_BRUSH_*), declared once
    return (SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone) + _alerts_prelude() + "\n"
            + "\n".join(_const_source(name) for name in DASHBOARD_CHART_CONSTS))


# 640 alerts over 95 days up to 10 Nov 2026 15:30 UTC ("now"), times in UTC and
# with an offset; severities in any case, Sigma's informational, the server's
# unknown, none and one no chip names (warning); ten categories as a list or
# as text in any case, hostile ones (EVIL, QUOTE) among the six most frequent,
# four rare ones (dns, file, module, wmi) for "other categories", and alerts
# without one ("other"). Then times no clock can have had (1970, 1601, 9999),
# two alerts without a time and one two hours ahead of now.
DASHBOARD_FIXTURE = r"""
    const DAY = 86400000, HOUR = 3600000;
    const T = Date.UTC(2026, 10, 10, 15, 30);
    let now = T;
    Date.now = () => now;
    const CATEGORY_PLAN = [[['registry'], 9], ['process', 5], [['Registry'], 3], [EVIL, 4], [QUOTE, 3], ['api', 2],
                           [undefined, 2], ['file', 1], [['module'], 1], ['dns', 1], [['wmi'], 1]];
    const CATEGORIES = CATEGORY_PLAN.flatMap(([category, n]) => Array(n).fill(category));
    const SEVERITIES = ['medium', 'high', 'Medium', 'critical', 'low', 'High', 'informational', 'unknown', 'Warning', ''];
    const alerts = Array.from({ length: 640 }, (_, i) => {
        const t = T - ((i * 7919) % 95) * DAY - (i % 24) * HOUR - (i % 50) * 60000;
        return { id: 'd' + i, severity: SEVERITIES[i % SEVERITIES.length], category: CATEGORIES[(i * 7) % CATEGORIES.length],
                 timestamp: i % 2 ? new Date(t).toISOString() : new Date(t + 2 * HOUR).toISOString().replace('Z', '+02:00'),
                 engine: 'Sigma', rule_name: 'rule ' + (i % 7), process_name: 'p.exe', pid: 1000 + i };
    });
    alerts.push({ id: 'y1970', timestamp: '1970-01-01T00:00:00Z', severity: 'high', category: ['registry'] },
                { id: 'y1601', timestamp: '1601-01-01T00:00:00Z', severity: 'high', category: ['registry'] },
                { id: 'y9999', timestamp: '9999-12-31T23:59:59Z', severity: 'high', category: ['registry'] },
                { id: 'nat', timestamp: 'not a time', severity: 'low', category: 'process' },
                { id: 'none', severity: 'low', category: 'process' },
                { id: 'ahead', timestamp: new Date(T + 2 * HOUR).toISOString(), severity: 'critical', category: 'api' });
    const processes = { 1: { first_seen: new Date(T - 3 * DAY).toISOString() }, 2: { first_seen: new Date(T).toISOString() } };
"""

# What the dashboard shows: the range, the switch, the bars, the donuts with
# their legends and middles, the chip of a range drawn across the bars, the
# hints, the table views; and what filterAlerts lists for the range
DASHBOARD_LOOK = r"""
    document.body.innerHTML = DASHBOARD_MARKUP + ALERTS_MARKUP;
    const $ = id => document.getElementById(id);
    $('tab-alerts').scrollTop = 0;
    globalThis.switchTab = name => {
        state.activeTab = name;
        if (name === 'alerts') renderAlertsTab();
        if (name === 'dashboard') renderDashboardCharts();
    };
    const num = text => Number(String(text).replace(/,/g, ''));
    const hint = el => (el.querySelector('.chart-empty') || { textContent: null }).textContent;
    const tableOf = id => {
        const table = $(id).querySelector('table');
        const rows = table ? table.tBodies[0].rows : [];
        return table && {
            id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
            head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
            rows: rows.filter(row => !row.hasAttribute('data-sort-skip'))
                .map(row => row.cells.map(c => [c.textContent.trim(), c.getAttribute('data-sort-value')])),
            notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()),
        };
    };
    const donut = id => ({
        segments: $(id).querySelectorAll('.chart-seg').map(s => [s.getAttribute('data-key'), Number(s.getAttribute('data-value')),
                                                                s.classList.contains('chart-inert')]),
        colors: Object.fromEntries($(id).querySelectorAll('.chart-seg')
            .map(s => [s.getAttribute('data-key'), (s.getAttribute('style') || '').replace(/^stroke:/, '')])),
        legend: $(id).querySelectorAll('.chart-legend-row').map(row => [row.getAttribute('data-key'),
            row.querySelector('.chart-legend-name').textContent, num(row.querySelector('.chart-legend-count').textContent),
            row.querySelector('.chart-legend-pct').textContent, row.classList.contains('chart-inert')]),
        center: $(id).querySelectorAll('text').map(t => t.textContent),
        empty: hint($(id)),
    });
    const look = () => {
        const view = $('dashboard-alerts-chart'), svg = view.querySelector('svg'), selection = view.querySelector('.chart-selection');
        const chip = $('dashboard-range-chip');
        return {
            range: { ...dashboardRange }, bars: { ...dashboardBarsRange },
            pressed: document.querySelectorAll('#dashboard-alerts-card .chart-range-btn')
                .filter(b => b.getAttribute('aria-pressed') === 'true').map(b => b.getAttribute('data-range')),
            bins: view.querySelectorAll('.chart-bin').map(g => [Number(g.getAttribute('data-bin-start')),
                Number(g.getAttribute('data-bin-end')), Number(g.getAttribute('data-total'))]),
            inertBins: view.querySelectorAll('.chart-bin').filter(g => g.classList.contains('chart-inert')).length,
            size: svg ? [Number(svg.getAttribute('width')), Number(svg.getAttribute('height'))] : null,
            selection: selection ? [Number(selection.getAttribute('x')), Number(selection.getAttribute('width'))] : null,
            note: $('dashboard-alerts-note').textContent.replace(/\s+/g, ' ').trim(),
            severity: donut('dashboard-severity-chart'), category: donut('dashboard-category-chart'),
            chip: { hidden: chip.hidden, text: chip.textContent.replace(/\s+/g, ' ').trim(),
                    title: (chip.querySelector('button') || { getAttribute: () => null }).getAttribute('title') },
            hints: ['dashboard-alerts-chart', 'dashboard-severity-chart', 'dashboard-category-chart'].map(id => hint($(id))),
            tables: { alerts: tableOf('dashboard-alerts-table'), severity: tableOf('dashboard-severity-table'),
                      category: tableOf('dashboard-category-table') },
            listed: filterAlerts(state.alerts, { from: dashboardRange.from, to: dashboardRange.to }).length,
            inBars: filterAlerts(state.alerts, { from: dashboardBarsRange.from }).length,
        };
    };
"""


def _dashboard_script(script):
    return ((DASHBOARD_FIXTURE + DASHBOARD_LOOK + script)
            .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE))
            .replace("DASHBOARD_MARKUP", json.dumps(_tab_markup("dashboard")))
            .replace("ALERTS_MARKUP", json.dumps(_tab_markup("alerts"))))


def _total(items):
    return sum(item[1] for item in items)


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "America/New_York"])
def test_dashboard_range_presets_and_default(zone):
    """The switch 24H / 7D / 30D / ALL sets the range of the dashboard, ALL
    when the page loads: a preset runs from now minus its span on (new
    alerts are in it), the bars span it up to now by hours or days, the
    donuts count what the Alerts tab lists for it. ALL spans the alerts, not
    the years between a clock set to 1970 and one set to 9999 (a note counts
    those). A range drawn across the bars narrows the donuts and shows as a
    chip; its × takes it off. A range without alerts shows a hint."""
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const r = { start: { range: { ...dashboardRange }, bars: { ...dashboardBarsRange } }, T };
        renderDashboard();
        r.all = look();
        for (const preset of ['7d', '24h', '30d', 'all', 'bogus']) { setDashboardRange(preset); r[preset] = look(); }
        // The start of a preset is set as it is chosen, also while the dashboard is hidden
        state.activeTab = 'alerts';
        setDashboardRange('30d');
        r.hidden = { ...dashboardRange };
        state.activeTab = 'dashboard';
        // A range drawn across the bars of 7D: the donuts count it, the bars stay, a chip names it
        setDashboardRange('7d');
        const week = look().bins;
        setDashboardRange('custom', week[2][0], week[4][1]);
        r.custom = { ...look(), from: week[2][0], to: week[4][1], label: chartRangeLabel(week[2][0], week[4][1]) };
        for (const [from, to] of [[week[2][0], week[2][0]], [NaN, week[4][1]], [week[4][1], week[2][0]], ['x', null]])
            setDashboardRange('custom', from, to);
        r.badCustom = { ...dashboardRange };
        // New alerts leave the chip as it is (and the keyboard focus on it); its × gives the focus to the switch
        const chipButton = $('dashboard-range-chip').querySelector('button');
        chipButton.focus();
        state.alerts = [...alerts]; renderDashboardCharts();
        r.chipKept = $('dashboard-range-chip').querySelector('button') === chipButton && document.activeElement === chipButton;
        click($('dashboard-range-chip').querySelector('.alerts-filter-chip-x'));
        r.chipOff = { ...look(), focus: document.activeElement && document.activeElement.getAttribute('data-range') };
        // A range without alerts, no alerts at all
        state.alerts = alerts.filter(a => a.id !== 'y9999');
        now = T + 100 * DAY;
        setDashboardRange('24h');
        r.empty = look();
        state.alerts = []; renderDashboardCharts();
        r.none = look();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude(zone))
    DAY, HOUR, T = 86400000, 3600000, r["T"]
    ahead = T + 2 * HOUR                                  # the alert two hours ahead
    assert r["start"] == {"range": {"preset": "all", "from": None, "to": None}, "bars": {"preset": "all", "from": None}}
    every = 646
    view = r["all"]
    assert view["pressed"] == ["all"]
    assert _total(view["severity"]["segments"]) == _total(view["category"]["segments"]) == view["listed"] == every
    # ALL: the bars span the 95 days of plausible times by days, and count those
    bins = view["bins"]
    assert 95 <= len(bins) <= 97 and all(end - start <= DAY + HOUR for start, end, _ in bins), \
        f"one alert of 1970 or 9999 squeezes the bars: {len(bins)} bins"
    assert sum(total for *_, total in bins) == every - 5, "the bars do not count the plausible alerts"
    assert bins[-1][1] > ahead >= bins[-1][0]
    assert "2 without time \u00b7 3 with implausible time" in view["note"], view["note"]
    assert view["tables"]["alerts"]["notes"] == ["2 without time", "3 with implausible time"]
    # The presets: from now minus their span on, the bars up to now (and the alert ahead of it)
    for preset, span, step in (("7d", 7 * DAY, DAY), ("24h", DAY, HOUR), ("30d", 30 * DAY, DAY)):
        view = r[preset]
        assert view["range"] == {"preset": preset, "from": T - span, "to": None}, preset
        assert view["bars"] == {"preset": preset, "from": T - span} and view["pressed"] == [preset]
        bins = view["bins"]
        assert bins[0][0] == T - span and bins[-1][1] == ahead + 1, f"{preset}: the bars do not span the range up to now"
        assert all(end - start <= step + HOUR for start, end, _ in bins) and len(bins) >= span // step, preset
        assert all(b[0] == a[1] for a, b in zip(bins, bins[1:])), f"{preset}: gaps between the bars"
        # 9999 is in a range that runs on: the donuts count it, the bars note it
        assert _total(view["severity"]["segments"]) == _total(view["category"]["segments"]) == view["listed"], preset
        assert sum(total for *_, total in bins) == view["inBars"] - 1 and view["listed"] == view["inBars"], preset
        assert "1 with implausible time" in view["note"] and "without time" not in view["note"], view["note"]
    assert r["all"]["range"] == r["bogus"]["range"] == {"preset": "all", "from": None, "to": None}
    assert r["bogus"]["pressed"] == ["all"]
    assert r["hidden"] == {"preset": "30d", "from": T - 30 * DAY, "to": None}
    # A range drawn across the bars
    custom = r["custom"]
    assert custom["range"] == {"preset": "custom", "from": custom["from"], "to": custom["to"]}
    assert custom["bars"] == {"preset": "7d", "from": T - 7 * DAY}, "the bars follow the range drawn across them"
    assert custom["pressed"] == [], "a preset shows as pressed while the donuts count the range drawn across the bars"
    assert custom["bins"] == r["7d"]["bins"]
    width = custom["size"][0]
    slot = width / len(custom["bins"])
    assert custom["selection"] and abs(custom["selection"][0] - 2 * slot) < 0.02 and abs(custom["selection"][1] - 3 * slot) < 0.02, \
        f"the range is not marked over its bars: {custom['selection']} (slot {slot})"
    assert _total(custom["severity"]["segments"]) == _total(custom["category"]["segments"]) == custom["listed"] > 0
    assert custom["listed"] < r["7d"]["listed"]
    assert custom["chip"] == {"hidden": False, "text": "\u00d7 " + custom["label"], "title": custom["chip"]["title"]}
    assert custom["chip"]["title"].startswith("Remove the range ") and custom["chip"]["title"].endswith(": back to 7D"), \
        custom["chip"]["title"]
    assert r["badCustom"] == custom["range"], "an empty, reversed or broken range was taken"
    assert r["chipKept"], "new alerts wrote the chip again: the chip in focus lost it"
    off = r["chipOff"]
    assert off["range"] == {"preset": "7d", "from": T - 7 * DAY, "to": None} and off["chip"]["hidden"] and off["chip"]["text"] == ""
    assert off["selection"] is None and off["pressed"] == ["7d"] and off["focus"] == "7d"
    # No alerts in the range, none at all
    for name, text in (("empty", "No alerts in this range"), ("none", "No alerts yet")):
        view = r[name]
        assert view["hints"] == [text] * 3, view["hints"]
        assert not view["bins"] and not view["severity"]["segments"] and not view["category"]["segments"]
        assert all(table["notes"] == [text + "."] and not table["rows"] for table in view["tables"].values()), view["tables"]
        assert "Drag" not in view["note"], "the hint to drag across bars that are not there"


@needs_node
def test_dashboard_charts_skip_unchanged_inputs():
    """The dashboard renders every 10 s and with new alerts: its charts count
    again only when the alerts, the process list or the range changed (each
    part for its own inputs), and draw again only what changed; nothing while
    another tab is open, and then it holds none of the lists it counted (tens
    of MB of alerts). A preset follows the clock by the minute, ALL does not,
    nor do the bars under a range drawn across them; the sparklines count
    again on a new day."""
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const calls = {};
        for (const name of ['alertSeverityBins', 'alertsSeverityItems', 'dashboardCategoryItems', '_dashboardSparkCounts']) {
            const real = globalThis[name];
            globalThis[name] = (...args) => { calls[name] = (calls[name] || 0) + 1; return real(...args); };
        }
        let draws = 0;
        const html = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        for (const id of ['dashboard-alerts-chart', 'dashboard-alerts-table', 'dashboard-severity-chart', 'dashboard-severity-table',
                          'dashboard-category-chart', 'dashboard-category-table'])
            Object.defineProperty($(id), 'innerHTML', { configurable: true, set(v) { draws++; html.set.call(this, v); } });
        const sparks = () => ['alerts', 'processes'].map(kind => {
            const line = $(`dashboard-${kind}-spark`).querySelector('polyline');
            return line ? line.getAttribute('points').split(' ').length : 0;
        });
        // What the counts hold on to: the lists of state they were counted from
        const holds = () => Object.values(_dashboardMemo).flatMap(m => (m ? m.inputs : []))
            .filter(input => input !== null && typeof input === 'object');
        const r = { steps: [] };
        const step = (label, run) => {
            for (const key of Object.keys(calls)) delete calls[key];
            draws = 0;
            run();
            r.steps.push([label, { ...calls }, draws, sparks()]);
        };
        step('first', () => renderDashboard());
        step('again', () => renderDashboardCharts());
        step('poll', () => renderDashboard());                // the tiles are written again: their sparklines back, nothing counted
        const before = $('dashboard-processes-spark').querySelector('polyline').getAttribute('points');
        step('processes', () => { state.processes = { ...processes, 3: { first_seen: new Date(T).toISOString() } }; renderDashboardCharts(); });
        r.processesLine = before !== $('dashboard-processes-spark').querySelector('polyline').getAttribute('points');
        step('alerts', () => { state.alerts = [...alerts]; renderDashboardCharts(); });
        step('preset', () => setDashboardRange('7d'));
        step('same', () => renderDashboard());
        step('half a minute', () => { now = T + 30000; renderDashboardCharts(); });
        step('a minute', () => { now = T + 61000; renderDashboardCharts(); });
        r.followed = [{ ...dashboardBarsRange }, { ...dashboardRange }];
        step('custom', () => setDashboardRange('custom', T - 3 * DAY, T - DAY));
        step('two minutes', () => { now = T + 125000; renderDashboardCharts(); });
        r.held = [{ ...dashboardBarsRange }, { ...dashboardRange }];
        // Hidden while new alerts and a new process list come (as _refreshAlertsOnce does it): no list is held
        const shownLists = holds();
        step('hidden', () => {
            state.activeTab = 'alerts';
            state.alerts = [...alerts];
            state.processes = { ...processes };
            releaseDashboardCounts();
            renderDashboard();
        });
        r.lists = { shown: shownLists.length, hidden: holds().length };
        step('shown', () => { state.activeTab = 'dashboard'; renderDashboardCharts(); });
        r.lists.again = [holds().includes(state.alerts), holds().includes(state.processes)];
        step('all', () => setDashboardRange('all'));
        step('an hour', () => { now = T + 125000 + 3600000; renderDashboardCharts(); });
        step('a day', () => { now = T + 86400000; renderDashboardCharts(); });
        r.T = T;
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    every = {"alertSeverityBins": 1, "alertsSeverityItems": 1, "dashboardCategoryItems": 1, "_dashboardSparkCounts": 1}
    charts = {"alertSeverityBins": 1, "alertsSeverityItems": 1, "dashboardCategoryItems": 1}
    expected = [
        ("first", every, 6), ("again", {}, 0), ("poll", {}, 0), ("processes", {"_dashboardSparkCounts": 1}, 0),
        ("alerts", every, 6), ("preset", charts, 6), ("same", {}, 0),
        ("half a minute", {}, 0), ("a minute", charts, 6),
        ("custom", {"alertsSeverityItems": 1, "dashboardCategoryItems": 1}, 6), ("two minutes", {}, 0),
        ("hidden", {}, 0), ("shown", every, 6), ("all", charts, 6), ("an hour", {}, 0),
        ("a day", {"_dashboardSparkCounts": 1}, 0),
    ]
    assert [step[:3] for step in r["steps"]] == [list(e) for e in expected], \
        "\n".join(f"{got[:3]} expected {list(want)}" for got, want in zip(r["steps"], expected) if got[:3] != list(want))
    # Each step leaves the sparklines in their tiles, 45 days each
    hidden = [step[0] for step in r["steps"]].index("hidden")
    assert all(step[3] == [45, 45] for i, step in enumerate(r["steps"]) if i != hidden), r["steps"]
    assert r["processesLine"], "a new process list did not draw the sparkline of PROCESSES TRACKED again"
    T, DAY = r["T"], 86400000
    bars, rng = r["followed"]
    assert bars == {"preset": "7d", "from": T + 61000 - 7 * DAY} and rng == {"preset": "7d", "from": T + 61000 - 7 * DAY, "to": None}, \
        "7D stays where it was a minute ago"
    bars, rng = r["held"]
    assert bars == {"preset": "7d", "from": T + 61000 - 7 * DAY}, "the bars under a drawn range follow the clock away from it"
    assert rng == {"preset": "custom", "from": T - 3 * DAY, "to": T - DAY}, "the range drawn moved with the clock"
    # The counts hold the lists of state while the dashboard is shown, none while it is hidden, the new ones when shown again
    assert r["lists"]["shown"] == 4 and r["lists"]["hidden"] == 0, \
        "the hidden dashboard keeps the old lists of alerts and processes alive"
    assert r["lists"]["again"] == [True, True]
    js = _strip_js_comments(_read(APP_JS))
    assert re.search(r"tabName === 'dashboard'\)\s*\{?\s*renderDashboardCharts\(\)", _function_source("switchTab")), \
        "the dashboard is not drawn when it is shown again"
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    assert re.search(r"^\s*initDashboardCharts\(\);", js[start:js.index("\n});", start)], re.M), "not set up at start-up"
    assert "renderDashboardCharts();" in _strip_js_comments(_function_source("renderDashboard"))
    assert re.search(r"else\s+releaseDashboardCounts\(\)", _strip_js_comments(_function_source("_refreshAlertsOnce"))), \
        "new alerts while the dashboard is hidden do not let go of its lists"


@needs_node
def test_dashboard_donut_click_opens_filtered_alerts():
    """A segment or legend row of SEVERITY or CATEGORY opens the Alerts tab
    filtered by its severity or category within the range of the dashboard,
    a bar of ALERT ACTIVITY at its period: the filter shows as chips there,
    and the table counts what the part counted. "other categories" (several
    categories), a severity no chip names and a bar without alerts open
    nothing and show no pointer. Names from the data stay text."""
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const opened = [];
        const realOpen = openAlertsTab;
        globalThis.openAlertsTab = filter => { opened.push(JSON.parse(JSON.stringify(filter))); realOpen(filter); };
        const part = (id, cls, key) => $(id).querySelectorAll(cls).find(el => el.getAttribute('data-key') === key);
        const tab = () => ({
            tab: state.activeTab, count: Number($('alerts-count').textContent.split(' of ')[0]),
            chips: $('alerts-active-filters').querySelectorAll('.alerts-filter-chip').map(c => c.textContent.replace(/\s+/g, ' ').trim()),
            pressed: document.querySelectorAll('#tab-alerts .alerts-sev-chip').filter(c => c.getAttribute('aria-pressed') === 'true')
                .map(c => c.dataset.severity),
        });
        const r = {};
        const trip = (label, el, value) => {
            opened.length = 0;
            click(el);
            r[label] = { opened: [...opened], value, ...tab(), markup: ['img', 'script'].map(t => document.querySelectorAll(t).length) };
            switchTab('dashboard');
        };
        const segment = (chart, key) => {
            const el = part(`dashboard-${chart}-chart`, '.chart-seg', key);
            return [el, Number(el.getAttribute('data-value'))];
        };
        const legend = (chart, key) => {
            const el = part(`dashboard-${chart}-chart`, '.chart-legend-row', key);
            return [el.querySelector('.chart-legend-name'), num(el.querySelector('.chart-legend-count').textContent)];
        };
        renderDashboard();
        setDashboardRange('30d');
        r.range = { ...dashboardRange };
        r.view = look();
        trip('registry', ...segment('category', 'registry'));
        trip('registryRow', ...legend('category', 'registry'));
        trip('uncategorised', ...segment('category', 'other'));
        trip('evil', ...segment('category', EVIL));
        trip('quote', ...legend('category', QUOTE));
        trip('bucket', ...segment('category', ''));
        trip('bucketRow', ...legend('category', ''));
        trip('high', ...segment('severity', 'high'));
        trip('info', ...legend('severity', 'info'));
        trip('warning', ...segment('severity', 'warning'));
        r.rangeLabel = chartRangeLabel(dashboardRange.from, null);
        // ALL: no range filter; a range drawn across the bars: that range
        setDashboardRange('all');
        trip('all', ...segment('category', 'registry'));
        setDashboardRange('custom', T - 20 * DAY, T - 10 * DAY);
        trip('custom', ...segment('severity', 'medium'));
        r.customLabel = chartRangeLabel(T - 20 * DAY, T - 10 * DAY);
        // A category keeps its colour in a range where it is the only one (the alert ahead of now: api)
        setDashboardRange('custom', T + HOUR, T + 3 * HOUR);
        r.onlyApi = look().category.colors;
        // ALERT ACTIVITY of 24H: a bar with alerts at its period, one without nothing
        setDashboardRange('24h');
        const bins = $('dashboard-alerts-chart').querySelectorAll('.chart-bin');
        const full = bins.find(g => Number(g.getAttribute('data-total')) > 0), empty = bins.find(g => g.getAttribute('data-total') === '0');
        r.bin = [Number(full.getAttribute('data-bin-start')), Number(full.getAttribute('data-bin-end'))];
        r.binLabel = chartRangeLabel(...r.bin);
        trip('bar', full.querySelector('.chart-bar'), Number(full.getAttribute('data-total')));
        trip('emptyBar', empty.querySelector('.chart-hit'), 0);
        r.inert = { empty: empty.classList.contains('chart-inert'), full: full.classList.contains('chart-inert') };
        r.T = T;
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    rng, view = r["range"], r["view"]
    within = {"from": rng["from"], "to": None}
    category = view["category"]
    # Six categories on their own, the rest as "other categories" (key '', muted, no pointer)
    keys = [key for key, *_ in category["segments"]]
    assert keys[:-1] and keys[-1] == "" and len(keys) == 7, keys
    assert [row[1] for row in category["legend"]][-1] == "other categories" and "other" in keys, \
        "the rest is labelled like the category other (alerts without one)"
    assert [key for key, _, inert in category["segments"] if inert] == [""]
    assert [row[0] for row in category["legend"] if row[4]] == [""]
    assert category["colors"][""] == "var(--text-muted)" and len(set(category["colors"].values())) == 7
    assert r["onlyApi"] == {"api": category["colors"]["api"]}, "a category changes its colour with the range"
    assert [key for key, _, inert in view["severity"]["segments"] if inert] == ["warning"]
    for label, filter_ in (("registry", {"category": "registry"}), ("registryRow", {"category": "registry"}),
                           ("uncategorised", {"category": "other"}), ("evil", {"category": EVIL}),
                           ("quote", {"category": QUOTE}), ("high", {"severities": ["high"]}),
                           ("info", {"severities": ["info"]})):
        trip = r[label]
        assert trip["opened"] == [{**filter_, **within}], f"{label}: {trip['opened']}"
        assert trip["tab"] == "alerts" and trip["count"] == trip["value"] > 0, \
            f"{label}: the Alerts tab lists {trip['count']}, the dashboard counted {trip['value']}"
        assert trip["chips"][0] == "\u00d7 " + r["rangeLabel"], trip["chips"]
        assert trip["markup"] == [0, 0], "a category name became markup"
    assert r["registry"]["chips"] == ["\u00d7 " + r["rangeLabel"], "\u00d7 category: registry"]
    assert r["evil"]["chips"] == ["\u00d7 " + r["rangeLabel"], "\u00d7 category: " + EVIL]
    assert r["high"]["pressed"] == ["high"] and r["info"]["pressed"] == ["info"]
    for label in ("bucket", "bucketRow", "warning", "emptyBar"):
        assert r[label]["opened"] == [] and r[label]["tab"] == "dashboard", f"{label} opened {r[label]['opened']}"
    assert r["all"]["opened"] == [{"category": "registry", "from": None, "to": None}]
    assert r["all"]["count"] == r["all"]["value"] == 243 and r["all"]["chips"] == ["\u00d7 category: registry"]
    T, DAY = r["T"], 86400000
    assert r["custom"]["opened"] == [{"severities": ["medium"], "from": T - 20 * DAY, "to": T - 10 * DAY}]
    assert r["custom"]["count"] == r["custom"]["value"] > 0 and r["custom"]["chips"] == ["\u00d7 " + r["customLabel"]]
    assert r["bar"]["opened"] == [{"from": r["bin"][0], "to": r["bin"][1]}]
    assert r["bar"]["count"] == r["bar"]["value"] > 0 and r["bar"]["chips"] == ["\u00d7 " + r["binLabel"]]
    assert r["inert"] == {"empty": True, "full": False}


@needs_node
def test_dashboard_bars_take_a_range_drawn_across_them():
    """The events of a press as Chrome sends them: while an element holds the
    pointer's capture, the pointer's events and the click after the release
    go to it (Pointer Events 3), else the click goes to the nearest common
    ancestor of the press's and the release's targets. A press on a bar that
    does not move (by less than 5 px) opens that bar, also when it ends on
    the next bar. Moved by 5 px or more it draws a range: the bars take the
    capture, the range is marked from the bar pressed to the bar under the
    pointer (either way, held to the bars at the ends), the bars are kept
    while it is drawn; released, it is the range of the donuts, and its click
    opens nothing. A cancelled press, another button or another pointer sets
    nothing; a press released elsewhere on the page ends all the same. The
    bars are drawn again for a new size of their card."""
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const resizers = [], frames = [];
        globalThis.ResizeObserver = class {
            constructor(callback) { this.callback = callback; resizers.push(this); }
            observe(el) { this.el = el; }
        };
        globalThis.requestAnimationFrame = fn => frames.push(fn);
        document.createElementNS = (ns, tag) => Object.assign(document.createElement(tag), { ns });
        const opened = [];
        globalThis.openAlertsTab = filter => opened.push(filter);
        const area = document.querySelector('#dashboard-alerts-card .dashboard-bars-area');
        area.rect = { left: 0, top: 0, width: 700, height: 220 };
        initDashboardCharts();
        setDashboardRange('7d');
        const view = $('dashboard-alerts-chart');
        const svg = () => view.querySelector('svg');
        const place = () => { svg().rect = { left: 100, top: 50, width: 700, height: 220, right: 800, bottom: 270 }; };
        place();
        const bins = look().bins, slot = 700 / bins.length;
        const at = i => 100 + (i + 0.5) * slot;
        const hit = i => view.querySelectorAll('.chart-hit')[i];
        const mark = () => { const m = view.querySelector('.chart-brush'); return m && ['x', 'width', 'y', 'height'].map(a => Number(m.getAttribute(a))); };
        // Chrome's pointer capture: the pointer's events and the click after its release go to the element holding it;
        // the release ends it
        let captured = null;
        Element.prototype.setPointerCapture = function () { captured = this; };
        Element.prototype.releasePointerCapture = function () { if (captured === this) captured = null; };
        Element.prototype.hasPointerCapture = function () { return captured === this; };
        const chain = el => { const list = []; for (let e = el; e; e = e.parentNode) list.push(e); return list; };
        const common = (a, b) => chain(a).find(e => chain(b).includes(e)) || null;
        // What is under the pointer at clientX: the hit area of a bar, or the card beside the bars
        const under = x => { const i = Math.floor((x - 100) / slot); return i >= 0 && i < bins.length ? hit(i) : $('dashboard-alerts-card'); };
        const send = (type, x, extra = {}) => dispatch(type, captured || under(x), { clientX: x, clientY: 120, button: 0, pointerId: 7, ...extra });
        // A press at x0, moves to each x of xs, the release at the last x (x0 without moves), and the click Chrome
        // sends after a release of the main button (legacy: to the element under the pointer, as a browser without
        // pointer capture would)
        const gesture = (x0, xs = [], extra = {}) => {
            place();
            const x1 = xs.length ? xs[xs.length - 1] : x0;
            const down = under(x0);
            send('pointerdown', x0, extra);
            xs.forEach(x => send('pointermove', x, extra));
            const up = under(x1);
            send('pointerup', x1, extra);
            const target = extra.legacy ? under(x1) : captured || common(down, up);
            captured = null;
            if (!extra.button && target) dispatch('click', target, { clientX: x1, clientY: 120, button: 0 });
            return target;
        };
        const r = { slot, bins: bins.length, observed: resizers.map(o => o.el === area) };
        // A press on a bar that does not move opens it: still, after a wiggle of 3 px, and when it ends on the next bar
        const full = view.querySelectorAll('.chart-bin').findIndex(g => Number(g.getAttribute('data-total')) > 0);
        const period = i => ({ from: bins[i][0], to: bins[i][1] });
        const before = { ...dashboardRange };
        const still = gesture(at(full));
        r.still = { opened: opened.splice(0), want: [period(full)], target: still.getAttribute('class'), range: { ...dashboardRange }, before };
        gesture(at(full), [at(full) + 3]);
        r.wiggle = opened.splice(0);
        const edge = 100 + (full + 1) * slot;
        const slipped = gesture(edge - 2, [edge + 2]);
        r.slipped = { opened: opened.splice(0), inBar: !!slipped.closest('[data-bin-start]'), target: slipped.tagName,
                      next: Number(view.querySelectorAll('.chart-bin')[full + 1].getAttribute('data-total')) };
        // Pressed at bar 2, moved by 3 px: no range, no capture yet; then to bar 5: a range, the bars hold the capture
        place();
        send('pointerdown', at(2));
        send('pointermove', at(2) + 3);
        r.small = [mark(), captured === null];
        send('pointermove', at(5));
        r.marked = mark();
        r.markNs = view.querySelector('.chart-brush').ns;
        r.capture = captured && captured.id;
        // A poll while the range is drawn: the bars stay (the mark with them), nor does a new size draw them
        const drawn = svg();
        state.alerts = [...alerts];
        renderDashboardCharts();
        area.rect = { left: 0, top: 0, width: 690, height: 210 };
        redrawDashboardChartsOnResize();
        r.kept = svg() === drawn && !!mark();
        area.rect = { left: 0, top: 0, width: 700, height: 220 };
        send('pointerup', at(5));
        const target = captured;
        captured = null;
        dispatch('click', target, { clientX: at(5), clientY: 120, button: 0 });
        r.drawn = { range: { ...dashboardRange }, expected: [bins[2][0], bins[5][1]], opened: opened.splice(0), mark: mark(),
                    selection: look().selection, chip: look().chip.hidden, clickTarget: target.id };
        // Right to left, past the left end of the bars; past the right end
        gesture(at(4), [at(4) - 10, 20]);
        r.leftwards = [{ ...dashboardRange }, [bins[0][0], bins[4][1]], opened.splice(0)];
        // A range of one bar, its click sent to that bar (a browser without pointer capture): it opens nothing either
        r.bin3 = Number(view.querySelectorAll('.chart-bin')[3].getAttribute('data-total'));
        gesture(at(3) - 20, [at(3) + 20], { legacy: true });
        r.oneBar = [{ ...dashboardRange }, [bins[3][0], bins[3][1]], opened.splice(0)];
        place();
        send('pointerdown', at(6)); send('pointermove', at(6) + 10); send('pointermove', 2000);
        r.rightMark = mark();
        send('pointerup', 2000);
        dispatch('click', captured, { clientX: 2000, clientY: 120, button: 0 });
        captured = null;
        r.rightwards = [{ ...dashboardRange }, [bins[6][0], bins[bins.length - 1][1]], opened.splice(0)];
        // Cancelled, another button, a second pointer: nothing
        setDashboardRange('7d');
        const seven = { ...dashboardRange };
        place();
        send('pointerdown', at(1)); send('pointermove', at(4)); send('pointercancel', at(4));
        captured = null;
        r.cancelled = [{ ...dashboardRange }, mark()];
        gesture(at(1), [at(4)], { button: 2 });
        r.otherButton = [{ ...dashboardRange }, mark(), opened.splice(0)];
        place();
        send('pointerdown', at(1)); send('pointermove', at(4), { pointerId: 8 }); send('pointerup', at(4), { pointerId: 8 });
        r.otherPointer = [{ ...dashboardRange }, mark()];
        send('pointerup', at(1));
        r.later = { ...dashboardRange };
        r.seven = seven;
        // A press released elsewhere on the page (no capture: the release goes there) ends: the next poll draws the bars
        settle().then(() => {
            place();
            send('pointerdown', at(full + 1));
            dispatch('pointerup', $('dashboard-grid'), { clientX: 900, clientY: 700, button: 0, pointerId: 7 });
            const s = svg();
            state.alerts = [...alerts];
            renderDashboardCharts();
            r.releasedElsewhere = svg() !== s;
            return settle();
        }).then(() => {
            // No click came after that release: a click later (a script's, no press) opens the bar it is on
            place();
            click(hit(full));
            r.afterElsewhere = opened.splice(0);
            // A new size of the card: drawn again in the next frame, not for the same size, not while hidden
            area.rect = { width: 520, height: 300 };
            resizers[0].callback([]);
            r.resizeQueued = [look().size, frames.length];
            frames.splice(0).forEach(fn => fn());
            r.resized = look().size;
            const same = svg();
            redrawDashboardChartsOnResize();
            area.rect = { width: 0, height: 0 };
            redrawDashboardChartsOnResize();
            r.keptSize = svg() === same;
            // After the task of a release that drew a range: a click without a press (a script's) opens its bar, and so does a press
            area.rect = { left: 0, top: 0, width: 700, height: 220 };
            setDashboardRange('7d');
            gesture(at(1), [at(4)]);
            r.afterDrag = opened.splice(0);
            return settle();
        }).then(() => {
            place();
            click(hit(full));
            r.clickLater = { opened: opened.splice(0), want: [period(full)], range: { ...dashboardRange } };
            gesture(at(full));
            r.pressLater = opened.splice(0);
            console.log(JSON.stringify(r));
        });
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    slot = r["slot"]
    assert r["observed"] == [True]
    still = r["still"]
    assert still["opened"] == still["want"], \
        f"a press on a bar that did not move opened {still['opened']} (its click went to {still['target']})"
    assert still["range"] == still["before"], "a press that did not move set a range"
    assert r["wiggle"] == still["want"], "a press moved by 3 px did not open its bar"
    # The click goes to the parent the two bars share (the <svg> in Chrome), outside every bar
    assert r["slipped"]["inBar"] is False and r["slipped"]["opened"] == still["want"], \
        f"a press that ended on the next bar opened {r['slipped']['opened']} instead of the bar pressed ({r['slipped']})"
    assert r["small"] == [None, True], "a press moved by 3 px drew a range or took the capture"
    x, width, y, height = r["marked"]
    assert abs(x - 2 * slot) < 0.02 and abs(width - 4 * slot) < 0.02, f"the mark is not over bars 2 to 5: {r['marked']}"
    assert y > 0 and height > 100 and r["markNs"] == "http://www.w3.org/2000/svg"
    assert r["capture"] == "dashboard-alerts-chart", "a range being drawn does not hold the pointer's capture"
    assert r["kept"], "a poll or a new size drew the bars again while a range was drawn across them"
    drawn = r["drawn"]
    assert drawn["range"] == {"preset": "custom", "from": drawn["expected"][0], "to": drawn["expected"][1]}
    assert drawn["clickTarget"] == "dashboard-alerts-chart" and drawn["opened"] == [], \
        "the click of the press that drew a range opened a bar"
    assert drawn["mark"] is None and drawn["selection"] and abs(drawn["selection"][0] - 2 * slot) < 0.02 and not drawn["chip"]
    for name in ("leftwards", "rightwards", "oneBar"):
        got, want, opened = r[name]
        assert (got["preset"], got["from"], got["to"]) == ("custom", *want) and opened == [], name
    assert r["bin3"] > 0, "the fixture has no alerts in the bar the one-bar range is drawn on"
    assert abs(r["rightMark"][0] + r["rightMark"][1] - r["bins"] * slot) < 0.02, "the mark runs past the last bar"
    for name in ("cancelled", "otherPointer"):
        assert r[name][0] == r["seven"] and r[name][1] is None, name
    assert r["otherButton"] == [r["seven"], None, []], "another button drew a range or opened a bar"
    assert r["later"] == r["seven"], "a release without a move drew a range"
    assert r["releasedElsewhere"], "a press released elsewhere on the page holds the bars still"
    assert r["afterElsewhere"] == [{"from": r["clickLater"]["want"][0]["from"], "to": r["clickLater"]["want"][0]["to"]}], \
        "a script's click after a release without a click opened the bar of that press"
    assert r["resizeQueued"] == [[700, 220], 1] and r["resized"] == [520, 300], "not drawn for the new size in the next frame"
    assert r["keptSize"], "drawn again for the same size or while hidden"
    assert r["afterDrag"] == [], "the click of a drag opened a bar"
    later = r["clickLater"]
    assert later["range"]["preset"] == "custom" and later["opened"] == later["want"], \
        "a click after the press that drew a range opened nothing"
    assert r["pressLater"] == later["want"], "a press on a bar after a drawn range opened nothing"


@needs_node
def test_a_range_being_drawn_ends_when_its_button_is_gone():
    """A press whose main button goes up where the bars never hear of it
    (macOS opens the context menu on Ctrl+click, the release goes to the
    menu) draws nothing more: a move without the main button, or the context
    menu, drops the range being drawn with its mark and the pointer's
    capture, as a cancelled press; the next press draws again."""
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        globalThis.ResizeObserver = class { observe() {} };
        globalThis.requestAnimationFrame = fn => fn();
        document.createElementNS = (ns, tag) => Object.assign(document.createElement(tag), { ns });
        const opened = [];
        globalThis.openAlertsTab = filter => opened.push(filter);
        document.querySelector('#dashboard-alerts-card .dashboard-bars-area').rect = { left: 0, top: 0, width: 700, height: 220 };
        initDashboardCharts();
        setDashboardRange('7d');
        const view = $('dashboard-alerts-chart');
        const place = () => { view.querySelector('svg').rect = { left: 100, top: 50, width: 700, height: 220, right: 800, bottom: 270 }; };
        place();
        const n = look().bins.length, slot = 700 / n, at = i => 100 + (i + 0.5) * slot;
        let captured = null;
        const released = [];
        Element.prototype.setPointerCapture = function () { captured = this; };
        Element.prototype.releasePointerCapture = function (id) { released.push(id); if (captured === this) captured = null; };
        const hit = i => view.querySelectorAll('.chart-hit')[i];
        const under = x => hit(Math.max(0, Math.min(n - 1, Math.floor((x - 100) / slot))));
        const send = (type, x, extra = {}) => dispatch(type, captured || under(x),
                                                       { clientX: x, clientY: 120, button: 0, buttons: 1, pointerId: 7, ...extra });
        const mark = () => !!view.querySelector('.chart-brush');
        const seven = { ...dashboardRange };
        const r = { seven };
        // Pressed and moved across bars, then a move without the main button: the range is dropped
        send('pointerdown', at(1)); send('pointermove', at(4));
        r.drawing = [mark(), captured === view, view.classList.contains('is-brushing')];
        send('pointermove', at(6), { buttons: 0 });
        r.lost = [mark(), captured, view.classList.contains('is-brushing'), { ...dashboardRange }, released.splice(0)];
        send('pointermove', at(7), { buttons: 0 }); send('pointerup', at(7), { buttons: 0 });
        r.after = [mark(), { ...dashboardRange }, opened.splice(0)];
        // Ctrl+click on macOS: the press and its moves, then the context menu instead of a release
        place();
        send('pointerdown', at(2), { ctrlKey: true }); send('pointermove', at(5), { ctrlKey: true });
        dispatch('contextmenu', captured || under(at(5)), { clientX: at(5), clientY: 120, button: 0, buttons: 1 });
        r.menu = [mark(), captured, { ...dashboardRange }, released.splice(0)];
        send('pointermove', at(7));
        r.menuAfter = [mark(), { ...dashboardRange }];
        // The context menu of a press that did not move: nothing drawn, no bar opened
        place();
        send('pointerdown', at(3));
        dispatch('contextmenu', under(at(3)), { clientX: at(3), clientY: 120, button: 0 });
        send('pointermove', at(6));
        r.stillMenu = [mark(), { ...dashboardRange }, opened.splice(0)];
        // The next press draws a range again
        place();
        send('pointerdown', at(1)); send('pointermove', at(3)); send('pointerup', at(3));
        dispatch('click', captured || view, { clientX: at(3), clientY: 120, button: 0 });
        captured = null;
        r.next = [{ ...dashboardRange }, look().bins[1][0], look().bins[3][1], opened.splice(0)];
        const js = initBarsBrush.toString();
        r.listens = /addEventListener\('contextmenu', onBarsBrushCancel, true\)/.test(js);
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    seven = r["seven"]
    assert r["drawing"] == [True, True, True]
    assert r["lost"] == [False, None, False, seven, [7]], "a move without the main button kept drawing the range"
    assert r["after"] == [False, seven, []]
    assert r["menu"] == [False, None, seven, [7]], "the context menu left the range being drawn"
    assert r["menuAfter"] == [False, seven], "a move after the context menu drew a range"
    assert r["stillMenu"] == [False, seven, []]
    rng, start, end, opened = r["next"]
    assert (rng["preset"], rng["from"], rng["to"], opened) == ("custom", start, end, []), r["next"]
    assert r["listens"], "the context menu is not listened for"


@needs_node
def test_bars_brush_serves_two_charts_apart():
    """Two charts of bars take a range drawn across them through the same
    code (initBarsBrush), each apart from the other; the events as Chrome
    sends them (see test_dashboard_bars_take_a_range_drawn_across_them). A
    drag on one is a range of that one only, over the bars it showed when
    pressed: its mark and the pointer's capture on its own bars, only its
    bars held still while it lasts (barsBrushActive), also when it runs on
    over the other's; its click stands for nothing on either chart, and it
    is the only click that does. A press that does not move stands for the
    bar it pressed on its own chart, wherever the click goes, and for nothing
    on the other; a bar without alerts for nothing. However a press ends
    (released, cancelled, the context menu, a move without the main button,
    released elsewhere on the page, after another pointer's release, a
    second finger's press), its chart is told once, when no press holds the
    bars, and before it hears of a range drawn; a second finger's press on
    bars its chart draws again then begins
    nothing. The page listens once for the moves and the end of a press,
    each chart once for a press, however often they were set up (the
    dashboard's ALERT ACTIVITY as well)."""
    script = _dashboard_script(r"""
        document.createElementNS = (ns, tag) => Object.assign(document.createElement(tag), { ns });
        // Two charts of bars side by side: A with 8 bars at x 100 to 800, B with 10 at x 900 to 1600
        const holder = document.createElement('div');
        holder.innerHTML = '<div id="bars-page"><div id="bars-a"></div><div id="bars-b"></div></div>';
        document.body.appendChild(holder.firstElementChild);
        const binsOf = totals => totals.map((total, i) => ({ start: T + i * HOUR, end: T + (i + 1) * HOUR, total,
                                                             counts: { high: total } }));
        const drawn = { A: binsOf([1, 2, 3, 4, 5, 6, 7, 8]), B: binsOf([2, 0, 3, 0, 1, 1, 1, 1, 1, 1]) };
        const left = { A: 100, B: 900 }, slot = { A: 700 / 8, B: 700 / 10 };
        const view = name => $(`bars-${name.toLowerCase()}`);
        for (const name of ['A', 'B']) view(name).innerHTML = stackedBarsSvg(drawn[name], { width: 700, height: 220 });
        const place = () => ['A', 'B'].forEach(name => {
            view(name).querySelector('svg').rect = { left: left[name], top: 50, width: 700, height: 220,
                                                     right: left[name] + 700, bottom: 270 };
        });
        const at = (name, i) => left[name] + (i + 0.5) * slot[name];
        const hit = (name, i) => view(name).querySelectorAll('.chart-hit')[i];
        // What is under the pointer at clientX: the hit area of a bar of either chart, or the page around them
        const under = x => {
            const name = ['A', 'B'].find(k => x >= left[k] && x < left[k] + 700);
            return name ? hit(name, Math.floor((x - left[name]) / slot[name])) : $('bars-page');
        };
        const period = (name, i) => ({ from: drawn[name][i].start, to: drawn[name][i].end });
        // The hosts and what they are told: [chart, 'range', first, last, the totals of its bins] or [chart, 'stop'],
        // each with whether a press holds the bars of A and of B then
        const told = [], calls = { A: 0, B: 0 };
        const active = () => [barsBrushActive(A), barsBrushActive(B)];
        const host = name => ({
            view: `bars-${name.toLowerCase()}`,
            bins: () => { calls[name]++; return drawn[name]; },
            onRange: (first, last, bins) => told.push([name, 'range', first, last, bins.map(bin => bin.total), active()]),
            onStop: () => told.push([name, 'stop', active()]),
        });
        const A = host('A'), B = host('B');
        const take = () => told.splice(0);
        // Each chart's click as its onclick takes it
        const clicks = [];
        view('A').addEventListener('click', event => clicks.push(['A', barsClickPeriod(event, A)]));
        view('B').addEventListener('click', event => clicks.push(['B', barsClickPeriod(event, B)]));
        // Chrome's pointer capture: the pointer's events and the click after its release go to the element holding
        // it; the release ends it
        let captured = null;
        const released = [];
        Element.prototype.setPointerCapture = function () { captured = this; };
        Element.prototype.releasePointerCapture = function (id) { released.push([this.id, id]); if (captured === this) captured = null; };
        const capture = () => captured && captured.id;
        const chain = el => { const list = []; for (let e = el; e; e = e.parentNode) list.push(e); return list; };
        const common = (a, b) => chain(a).find(e => chain(b).includes(e)) || null;
        const send = (type, x, extra = {}) => dispatch(type, captured || under(x),
            { clientX: x, clientY: 120, button: 0, buttons: /up|cancel/.test(type) ? 0 : 1, pointerId: 7, ...extra });
        // A press at x; its release at x, which gives the element Chrome sends the click after it to: the one
        // holding the capture, else the nearest common ancestor of the press's and the release's targets
        let down = null;
        const press = (x, extra = {}) => { place(); down = under(x); send('pointerdown', x, extra); };
        const lift = (x, extra = {}) => {
            const up = captured || under(x);
            send('pointerup', x, extra);
            const target = captured || common(down, up);
            captured = null;
            return target;
        };
        const clickAt = (target, x) => dispatch('click', target, { clientX: x, clientY: 120, button: 0 });
        const mark = name => {
            const m = view(name).querySelector('.chart-brush');
            return m && [Number(m.getAttribute('x')), Number(m.getAttribute('width'))];
        };
        const brushing = () => ['A', 'B'].map(name => view(name).classList.contains('is-brushing'));
        // Both set up twice, beside the dashboard's ALERT ACTIVITY
        initDashboardCharts();
        for (const h of [A, B, A, B]) initBarsBrush(h);
        const r = {
            page: document.listeners.map(l => [l.type, l.fn.name, l.capture]),
            presses: ['dashboard-alerts-chart', 'bars-a', 'bars-b'].map(id => $(id).listeners.filter(l => l.type === 'pointerdown').length),
        };
        // A drag on A from bar 2 to bar 5; its host counts its bars again meanwhile (bins() gives other ones)
        r.idle = active();
        press(at('A', 2));
        r.pressed = active();
        const shown = drawn.A;
        drawn.A = binsOf([8, 7, 6, 5, 4, 3, 2, 1]);
        send('pointermove', at('A', 2) + 3);
        r.small = [active(), capture(), mark('A')];
        send('pointermove', at('A', 4));
        send('pointermove', at('A', 5));
        r.drawing = [active(), capture(), mark('A'), mark('B'), brushing()];
        const dragClick = clickAt(lift(at('A', 5)), at('A', 5));
        r.drag = { told: take(), clicks: clicks.splice(0), target: dragClick.target.id, forB: barsClickPeriod(dragClick, B),
                   calls: { ...calls }, after: [active(), mark('A'), brushing()] };
        drawn.A = shown;
        // That click was the only one the drag took: a click on a bar of A (a script's) stands for that bar
        click(hit('A', 6));
        r.clickAfter = [clicks.splice(0), [['A', period('A', 6)]]];
        // A press on bar 2 of B that does not move but by 4 px, onto bar 3 (no alerts): Chrome sends its click to
        // the parent the two bars share. It stands for bar 2 of B, on A for nothing (before B took it and after).
        const edge = left.B + 3 * slot.B;
        press(edge - 2);
        send('pointermove', edge + 2);
        r.stillActive = active();
        const target = lift(edge + 2);
        const early = barsClickPeriod({ type: 'click', target }, A);
        const stillClick = clickAt(target, edge + 2);
        r.still = { told: take(), clicks: clicks.splice(0), want: [['B', period('B', 2)]],
                    inBar: !!target.closest('[data-bin-start]'), forA: [early, barsClickPeriod(stillClick, A)] };
        // A click without a press on a bar of B (a script's): that bar on B, nothing on A
        const scripted = click(hit('B', 2));
        r.scripted = [clicks.splice(0), [['B', period('B', 2)]], barsClickPeriod(scripted, A)];
        // A drag on B from bar 6 leftwards, on over the bars of A: a range of B from its first bar
        press(at('B', 6));
        send('pointermove', at('B', 6) - 10);
        send('pointermove', 300);
        r.overA = [capture(), mark('A'), !!mark('B'), active()];
        clickAt(lift(300), 300);
        r.leftwards = { told: take(), clicks: clicks.splice(0) };
        // A press on a bar without alerts, and a click on one: nothing
        press(at('B', 3));
        clickAt(lift(at('B', 3)), at('B', 3));
        click(hit('B', 1));
        r.empty = { told: take(), clicks: clicks.splice(0) };
        // However a press ends, its chart is told once
        const ends = r.ends = {};
        press(at('A', 1)); send('pointermove', at('A', 4)); send('pointercancel', at('A', 4));
        captured = null;
        ends.cancelled = [take(), mark('A'), brushing()];
        press(at('B', 2)); send('pointercancel', at('B', 2));
        ends.cancelledStill = [take()];
        press(at('B', 2)); send('pointermove', at('B', 5));
        dispatch('contextmenu', captured || under(at('B', 5)), { clientX: at('B', 5), clientY: 120, button: 0, buttons: 1 });
        ends.menu = [take(), mark('B'), capture(), released.splice(0)];
        press(at('A', 1)); send('pointermove', at('A', 4)); send('pointermove', at('A', 6), { buttons: 0 });
        ends.buttonGone = [take(), mark('A'), capture(), released.splice(0)];
        press(at('A', 3));
        const outside = lift(850);
        clickAt(outside, 850);
        ends.elsewhere = [take(), outside.id, clicks.splice(0)];
        press(at('B', 0)); send('pointerup', at('B', 0), { pointerId: 8 });
        ends.otherPointer = [take(), active()];
        clickAt(lift(at('B', 0)), at('B', 0));
        ends.ownPointer = [take(), clicks.splice(0), [['B', period('B', 0)]]];
        press(at('A', 2), { button: 2 }); send('pointerup', at('A', 2), { button: 2 });
        ends.otherButton = [take(), active()];
        // A second finger's press on B while the first draws on A: the first press ends, its moves and its
        // release are not heard any more; the second is a press on B of its own
        press(at('A', 1)); send('pointermove', at('A', 4));
        place();
        down = under(at('B', 0));
        dispatch('pointerdown', down, { clientX: at('B', 0), clientY: 120, button: 0, buttons: 1, pointerId: 8 });
        ends.secondFinger = [take(), mark('A'), brushing(), capture(), released.splice(0), active()];
        send('pointermove', at('A', 6)); send('pointerup', at('A', 6));
        ends.firstLifted = [take(), active()];
        clickAt(lift(at('B', 0), { pointerId: 8 }), at('B', 0));
        ends.secondLifted = [take(), clicks.splice(0), [['B', period('B', 0)]]];
        // ... on the same chart, whose host draws its bars again when told: the second finger's press is on bars no
        // longer shown, it begins nothing
        const onStop = B.onStop;
        B.onStop = () => { onStop(); view('B').innerHTML = stackedBarsSvg(drawn.B, { width: 700, height: 220 }); };
        press(at('B', 4)); send('pointermove', at('B', 7));
        const stale = under(at('B', 2));
        dispatch('pointerdown', stale, { clientX: at('B', 2), clientY: 120, button: 0, buttons: 1, pointerId: 8 });
        B.onStop = onStop;
        ends.redrawn = [take(), stale.isConnected, active(), released.splice(0)];
        place();
        send('pointermove', at('B', 6), { pointerId: 8 }); send('pointerup', at('B', 6), { pointerId: 8 });
        ends.redrawnLifted = [take(), active()];
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())

    def told(calls):
        """The ranges [chart, first, last, totals of its bins] and the charts
        told that a press is over, of the hosts' calls; each call made while
        no press held the bars of either chart."""
        assert all(call[-1] == [False, False] for call in calls), f"a chart was told while a press held the bars: {calls}"
        return ([[call[0], *call[2:-1]] for call in calls if call[1] == "range"],
                [call[0] for call in calls if call[1] == "stop"])

    assert sorted(r["page"]) == [["contextmenu", "onBarsBrushCancel", True], ["pointercancel", "onBarsBrushEnd", True],
                                 ["pointermove", "onBarsBrushMove", True], ["pointerup", "onBarsBrushEnd", True]], \
        f"the page does not listen once for the moves and the end of a press: {r['page']}"
    assert r["presses"] == [1, 1, 1], "a chart set up twice takes each press twice"
    # A drag on A from bar 2 to bar 5
    assert r["idle"] == [False, False] and r["pressed"] == [True, False]
    assert r["small"] == [[True, False], None, None], "a move by 3 px drew a range or took the capture"
    held, capture, mark_a, mark_b, brushing = r["drawing"]
    assert held == [True, False], "a drag on A held the bars of B, or not those of A"
    assert capture == "bars-a" and mark_b is None and brushing == [True, False], r["drawing"]
    assert abs(mark_a[0] - 2 * 87.5) < 0.02 and abs(mark_a[1] - 4 * 87.5) < 0.02, f"the mark is not over bars 2 to 5 of A: {mark_a}"
    drag = r["drag"]
    assert told(drag["told"]) == ([["A", 2, 5, [1, 2, 3, 4, 5, 6, 7, 8]]], ["A"]), \
        f"a drag on A from bar 2 to bar 5 told {drag['told']}"
    assert [call[1] for call in drag["told"]] == ["stop", "range"], \
        f"released, A heard of the range before it was told that the press is over: {drag['told']}"
    assert drag["calls"] == {"A": 1, "B": 0}, "the bars were read again while the range was drawn"
    assert drag["clicks"] == [["A", None]] and drag["target"] == "bars-a" and drag["forB"] is None, \
        "the click of the drag stood for a bar"
    assert drag["after"] == [[False, False], None, [False, False]]
    assert r["clickAfter"][0] == r["clickAfter"][1], "the drag took a later click as well"
    # A press on B that did not move
    still = r["still"]
    assert r["stillActive"] == [False, True]
    assert still["inBar"] is False and still["clicks"] == still["want"], \
        f"a press on bar 2 of B that slipped onto bar 3 stood for {still['clicks']}"
    assert still["forA"] == [None, None], "the click of a press on B stood for a bar of A"
    assert told(still["told"]) == ([], ["B"])
    assert r["scripted"][0] == r["scripted"][1] and r["scripted"][2] is None, \
        f"a click on a bar of B stood for {r['scripted'][2]} on A"
    # A drag on B that ran on over A
    assert r["overA"] == ["bars-b", None, True, [False, True]], "a drag on B marked or held the bars of A"
    assert told(r["leftwards"]["told"]) == ([["B", 0, 6, [2, 0, 3, 0, 1, 1, 1, 1, 1, 1]]], ["B"]), r["leftwards"]
    assert [call[1] for call in r["leftwards"]["told"]] == ["stop", "range"], r["leftwards"]
    assert r["leftwards"]["clicks"] == [["B", None]]
    assert told(r["empty"]["told"]) == ([], ["B"]) and r["empty"]["clicks"] == [["B", None], ["B", None]], \
        "a bar without alerts stood for its period"
    # However a press ended, its chart was told once
    ends = r["ends"]
    for name, chart in (("cancelled", "A"), ("cancelledStill", "B"), ("menu", "B"), ("buttonGone", "A"),
                        ("elsewhere", "A"), ("ownPointer", "B"), ("secondFinger", "A"), ("secondLifted", "B"),
                        ("redrawn", "B")):
        assert told(ends[name][0]) == ([], [chart]), f"{name}: {ends[name][0]}"
    for name in ("otherPointer", "otherButton", "firstLifted", "redrawnLifted"):
        assert told(ends[name][0]) == ([], []), f"{name}: {ends[name][0]}"
    assert ends["cancelled"][1:] == [None, [False, False]]
    assert ends["menu"][1:] == [None, None, [["bars-b", 7]]], "the context menu left the range being drawn on B"
    assert ends["buttonGone"][1:] == [None, None, [["bars-a", 7]]], "a move without the main button kept drawing on A"
    assert ends["elsewhere"][1:] == ["bars-page", []]
    assert ends["otherPointer"][1] == [False, True] and ends["otherButton"][1] == [False, False]
    assert ends["ownPointer"][1] == ends["ownPointer"][2]
    assert ends["secondFinger"][1:] == [None, [False, False], None, [["bars-a", 7]], [False, True]], \
        f"a second finger's press on B left the press on A: {ends['secondFinger']}"
    assert ends["firstLifted"][1] == [False, True], "the first finger's release ended the second finger's press"
    assert ends["secondLifted"][1] == ends["secondLifted"][2]
    assert ends["redrawn"][1:] == [False, [False, False], [["bars-b", 7]]], \
        f"a press on bars drawn again under it began a range: {ends['redrawn']}"
    assert ends["redrawnLifted"][1] == [False, False]


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "America/New_York"])
def test_dashboard_sparklines_count_the_last_45_days(zone):
    """TOTAL ALERTS: the alerts per local day of the last 45 days, today
    included; PROCESSES TRACKED: the processes first seen per day. The other
    tiles have none; a click on a sparkline clicks its tile."""
    script = _dashboard_script(r"""
        const at = (...a) => new Date(...a).getTime();       // local time of the zone
        now = at(2026, 10, 10, 15, 30);
        const days = [at(2026, 10, 10, 10), at(2026, 10, 10, 0, 0, 0, 1), at(2026, 10, 9, 23, 59, 59, 999), at(2026, 8, 27),
                      at(2026, 8, 26, 23, 59), at(2026, 10, 11, 0, 30)];
        const spread = [...days.map((t, i) => ({ id: 's' + i, severity: 'low', timestamp: new Date(t).toISOString() })),
                        { id: 'x', timestamp: 'not a time' }, { id: 'y', timestamp: '9999-01-01T00:00:00Z' }];
        const seen = { a: { first_seen: new Date(at(2026, 10, 10, 8)).toISOString() }, b: { first_seen: new Date(at(2026, 9, 31, 12)).toISOString() },
                       c: { first_seen: new Date(at(2026, 9, 31, 1)).toISOString() }, d: { first_seen: new Date(at(2026, 9, 31, 23, 59)).toISOString() },
                       e: { first_seen: new Date(at(2026, 8, 1)).toISOString() }, f: {}, g: { first_seen: 'garbage' } };
        globalThis.state = { alerts: spread, processes: seen, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const calls = [];
        globalThis.openAlertsTab = filter => calls.push(['alerts', filter]);
        globalThis.revealProcessList = () => calls.push(['processes']);
        renderDashboard();
        const counts = _dashboardSparkCounts(spread, seen, now);
        const spark = kind => {
            const slot = $(`dashboard-${kind}-spark`);
            return { points: slot.querySelector('polyline').getAttribute('points').split(' ').length, title: slot.getAttribute('title'),
                     label: slot.querySelector('.stat-spark-label').textContent, color: slot.querySelector('polyline').getAttribute('style'),
                     hidden: slot.getAttribute('aria-hidden') };
        };
        const r = { counts, alerts: spark('alerts'), processes: spark('processes'),
                    slots: document.querySelectorAll('#dashboard-stats .stat-spark').map(s => s.closest('.stat-card').getAttribute('data-tile')) };
        click($('dashboard-alerts-spark').querySelector('polyline'));
        click($('dashboard-processes-spark').querySelector('.stat-spark-label'));
        r.clicks = calls;
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude(zone))
    alerts, processes = r["counts"]["alerts"], r["counts"]["processes"]
    assert len(alerts) == len(processes) == 45
    assert alerts[44] == 2 and alerts[43] == 1 and alerts[0] == 1 and sum(alerts) == 4, \
        f"not the alerts per local day of the last 45 days: {alerts}"
    assert processes[44] == 1 and processes[34] == 3 and sum(processes) == 4, processes
    assert r["alerts"]["points"] == r["processes"]["points"] == 45
    assert r["alerts"]["title"] == "Alerts per day over the last 45 days: 4 in all"
    assert r["processes"]["title"] == "Processes first seen per day over the last 45 days: 4 in all"
    assert r["alerts"]["label"] == r["processes"]["label"] == "45 days"
    assert "var(--accent-pink)" in r["alerts"]["color"] and "var(--accent-cyan)" in r["processes"]["color"]
    assert r["alerts"]["hidden"] == r["processes"]["hidden"] == "true"
    assert r["slots"] == ["alerts", "processes"], "a tile without a history has a sparkline"
    assert r["clicks"] == [["alerts", {}], ["processes"]], "a click on a sparkline does not open its tile's view"


@needs_node
def test_dashboard_charts_have_info_and_table():
    """Between the tiles and the service cards: ALERT ACTIVITY with its
    switch 24H / 7D / 30D / ALL, SEVERITY and CATEGORY, each with its (i) and
    its CHART / TABLE switch; each table view is sortable and shows the
    numbers of its chart. Both themes style the new parts."""
    body = _Elements(_read(INDEX_HTML)).by_id("tab-dashboard")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def by_id(node, element_id):
        found = find(node, lambda e: e["attrs"].get("id") == element_id)
        assert len(found) == 1, element_id
        return found[0]

    def text(node):
        return node.get("text", "") + "".join(text(c) for c in node["children"])

    parts = find(body, lambda e: "dashboard-body" in e["attrs"].get("class", "").split())[0]["children"]
    assert [c["attrs"].get("id") or c["attrs"].get("class") for c in parts] == \
        ["dashboard-stats", "dashboard-charts", "dashboard-grid", "dashboard-activity"], "the charts are not above the service cards"
    charts = by_id(body, "dashboard-charts")
    cards = find(charts, lambda e: "chart-card" in e["attrs"].get("class", "").split())
    assert [c["attrs"].get("id") for c in cards] == ["dashboard-alerts-card", "dashboard-severity-card", "dashboard-category-card"]
    for card, (kind, title) in zip(cards, {"alerts": "ALERT ACTIVITY", "severity": "SEVERITY", "category": "CATEGORY"}.items()):
        view = f"dashboard-{kind}"
        heading = find(card, lambda e: "chart-card-title" in e["attrs"].get("class", "").split())
        assert len(heading) == 1 and text(heading[0]).strip() == title, kind
        assert heading[0]["attrs"].get("data-info", "").strip(), f"{kind}: no (i)"
        assert by_id(card, f"{view}-toggle") is not None
        chart, table = by_id(card, f"{view}-chart"), by_id(card, f"{view}-table")
        assert (chart["attrs"].get("data-view-of"), chart["attrs"].get("data-view"), "hidden" in chart["attrs"]) == (view, "chart", False)
        assert (table["attrs"].get("data-view-of"), table["attrs"].get("data-view"), "hidden" in table["attrs"]) == (view, "table", True)
        assert "chart-clickable" in chart["attrs"].get("class", "").split()
        assert chart["attrs"].get("onclick") == f"onDashboardChartClick(event, '{kind}')"
    note = by_id(cards[0], "dashboard-alerts-note")
    assert (note["attrs"].get("data-view-of"), note["attrs"].get("data-view")) == ("dashboard-alerts", "chart"), \
        "the note under the bars shows beside their table"
    buttons = find(cards[0], lambda e: "chart-range-btn" in e["attrs"].get("class", "").split())
    assert [(text(b).strip(), b["attrs"].get("data-range"), b["attrs"].get("onclick"), b["attrs"].get("aria-pressed"), b["tag"])
            for b in buttons] == [(label, value, f"setDashboardRange('{value}')", "true" if value == "all" else "false", "button")
                                  for label, value in (("24H", "24h"), ("7D", "7d"), ("30D", "30d"), ("ALL", "all"))]
    assert "hidden" in by_id(cards[0], "dashboard-range-chip")["attrs"]
    assert "viewToggleHtml(" in _function_source("renderDashboardCharts")
    source = "\n".join(_strip_js_comments(_function_source(name)) for name in DASHBOARD_CHART_FUNCTIONS)
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"

    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        document.querySelector('#dashboard-alerts-card .dashboard-bars-area').rect = { width: 640, height: 230 };
        renderDashboard();
        setDashboardRange('30d');
        const r = { view: look() };
        const toggle = kind => $(`dashboard-${kind}-toggle`).querySelector('.view-toggle');
        r.toggles = ['alerts', 'severity', 'category'].map(kind => [toggle(kind).getAttribute('data-view-toggle'), toggle(kind).textContent]);
        r.badges = $('dashboard-severity-table').querySelectorAll('.event-severity').map(s => [s.textContent, s.className]);
        // TABLE: the table in place of the chart, the note with the chart, kept on the next refresh
        click(toggle('alerts')); click(toggle('category'));
        state.alerts = [...alerts]; renderDashboard();
        r.tables = ['alerts', 'severity', 'category'].map(kind => [$(`dashboard-${kind}-chart`).hidden,
                                                                    $(`dashboard-${kind}-table`).hidden, toggle(kind).textContent]);
        r.noteHidden = $('dashboard-alerts-note').hidden;
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    view = r["view"]
    assert r["toggles"] == [["dashboard-alerts", "TABLE"], ["dashboard-severity", "TABLE"], ["dashboard-category", "TABLE"]]
    tables = view["tables"]
    assert {kind: t["id"] for kind, t in tables.items()} == {kind: f"dashboard-{kind}" for kind in ("alerts", "severity", "category")}
    assert all(t["sortable"] for t in tables.values())
    assert view["size"] == [640, 230], "the bars are not drawn for the size of their card"
    # SEVERITY and CATEGORY: one row per legend row, with its count and share
    assert tables["severity"]["head"] == ["Severity", "Count", "Share"]
    assert tables["category"]["head"] == ["Category", "Count", "Share"]
    for kind in ("severity", "category"):
        assert [[row[0][0], int(row[1][1]), row[2][0]] for row in tables[kind]["rows"]] == \
            [[key if kind == "severity" else label, count, share] for key, label, count, share, _ in view[kind]["legend"]], kind
    assert [row[1] for row in view["severity"]["legend"]] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING"]
    assert r["badges"][-1] == ["warning", "event-severity "] and r["badges"][0] == ["critical", "event-severity critical"]
    # The middles: the alerts of the range, the kinds of category
    assert view["severity"]["center"] == [f"{view['listed']:,}", "ALERTS"]
    assert view["category"]["center"][1] == "KINDS" and int(view["category"]["center"][0]) >= 7
    # ALERT ACTIVITY: a row per bar with alerts, by severity, its total, then the severities no chip names
    assert tables["alerts"]["head"] == ["Period", "Critical", "High", "Medium", "Low", "Info", "Total", "Other"]
    bars = [(start, total) for start, _, total in view["bins"] if total]
    assert [(int(row[0][1]), int(row[6][1])) for row in tables["alerts"]["rows"]] == bars
    assert all(sum(int(cell[1]) for cell in row[1:6] + row[7:]) == int(row[6][1]) for row in tables["alerts"]["rows"])
    assert tables["alerts"]["notes"] == ["1 with implausible time"]
    assert r["tables"] == [[True, False, "CHART"], [False, True, "TABLE"], [True, False, "CHART"]]
    assert r["noteHidden"] is True, "the note of the bars shows beside their table"
    # Both themes
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    assert re.search(r"grid-template-columns:[^;]*\b2fr\b", rules.get(".dashboard-charts", "")), "ALERT ACTIVITY is not the wide card"
    assert _painted(rules, r"\.chart-range-btn\[aria-pressed=\"true\"\]", "color"), "the preset in effect is not marked"
    assert re.search(r"position:\s*absolute", rules.get(".dashboard-bars-view", "")), "the bars take room of their own"
    assert re.search(r"overflow(?:-y)?:\s*auto", rules.get(".dashboard-bars-table", "")), "a long table stretches the dashboard"
    assert re.search(r"display:\s*none", rules.get(".dashboard-range-chip[hidden]", ""))
    for cls in ("stat-spark", "stat-spark-label", "dashboard-bars-note", "chart-range-btn", "dashboard-donuts"):
        assert any(re.search(_cls(cls), s) for s in rules), f".{cls} has no rule in style.css"
    for selector in ('[data-theme="cyberpunk"] .chart-range-btn[aria-pressed="true"]', '[data-theme="cyberpunk"] .stat-spark'):
        assert selector in theme, f"{selector} has no Cyberpunk rule"


@needs_node
def test_a_drawn_range_presses_no_preset_and_stays_on_the_bars():
    """While the donuts count a range drawn across the bars, no preset is
    pressed (none is what they count); the chip names the preset its × goes
    back to. The range holds the bars where they are: the preset under it
    does not follow the clock, so the range stays marked over its bars and
    the donuts count what the mark shows; × goes back to the preset from now
    on. A range the bars no longer reach (the alerts under it are gone) is
    taken off: no chip, no mark, the donuts of the preset."""
    script = _dashboard_script(r"""
        globalThis.state = { alerts, processes, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        renderDashboard();
        setDashboardRange('7d');
        const week = look().bins;
        setDashboardRange('custom', week[2][0], week[4][1]);
        const r = { T, drawn: look() };
        // Two days and five minutes later
        now = T + 2 * DAY + 5 * 60000;
        renderDashboardCharts();
        r.later = look();
        click($('dashboard-range-chip').querySelector('.alerts-filter-chip-x'));
        r.back = { ...look(), now };
        // ALL with a range across its first days, then the alerts before the 30th day are gone
        setDashboardRange('all');
        const days = look().bins;
        setDashboardRange('custom', days[0][0], days[5][1]);
        r.allDrawn = look();
        state.alerts = alerts.filter(a => Date.parse(a.timestamp) >= days[30][0]);
        renderDashboardCharts();
        r.gone = { ...look(), every: state.alerts.length };
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS, script, _dashboard_prelude())
    T, DAY = r["T"], 86400000
    drawn, later, back = r["drawn"], r["later"], r["back"]
    assert drawn["pressed"] == [] and later["pressed"] == [], "a preset shows as pressed while the donuts count a drawn range"
    assert drawn["chip"]["title"].endswith(": back to 7D") and not drawn["chip"]["hidden"]
    assert later["bars"] == drawn["bars"] == {"preset": "7d", "from": T - 7 * DAY}, "the bars under a drawn range follow the clock"
    assert later["range"] == drawn["range"] and later["bins"] == drawn["bins"] and later["selection"] == drawn["selection"], \
        "the drawn range slid along its bars"
    assert later["chip"] == drawn["chip"]
    assert later["severity"]["segments"] == drawn["severity"]["segments"] and later["listed"] == drawn["listed"] > 0
    assert back["range"] == {"preset": "7d", "from": back["now"] - 7 * DAY, "to": None}, "× did not go back to 7D from now on"
    assert back["bars"] == {"preset": "7d", "from": back["now"] - 7 * DAY} and back["pressed"] == ["7d"]
    assert back["chip"]["hidden"] and back["selection"] is None
    assert r["allDrawn"]["range"]["preset"] == "custom" and r["allDrawn"]["pressed"] == []
    gone = r["gone"]
    assert gone["range"] == {"preset": "all", "from": None, "to": None}, \
        f"a range the bars no longer reach stayed: {gone['range']}"
    assert gone["chip"]["hidden"] and gone["selection"] is None and gone["pressed"] == ["all"]
    assert _total(gone["severity"]["segments"]) == _total(gone["category"]["segments"]) == gone["listed"] == gone["every"]


@needs_node
def test_a_hidden_dashboard_lets_go_of_the_lists_it_counted():
    """New alerts and a new process list while another tab is open
    (_refreshAlertsOnce), or "Clear all" of the Tracing tab: the dashboard's
    counts hold on to neither the old lists nor the new ones, so tens of MB
    of alerts are not kept twice; shown again, it counts the lists of then."""
    script = _dashboard_script(r"""
        require('v8').setFlagsFromString('--expose-gc');
        const gc = require('vm').runInNewContext('gc');
        for (const f of ['renderRtraceConsole', 'renderProcessList']) globalThis[f] = () => {};
        // Lists only the state of the page holds, as the server's replies are
        globalThis.state = { alerts: alerts.map(a => ({ ...a })), processes: { ...processes }, serviceStatus: {},
                             rustinelInfo: {}, activeTab: 'dashboard' };
        let old = { alerts: new WeakRef(state.alerts), processes: new WeakRef(state.processes) };
        renderDashboard();
        const r = { counted: Object.values(_dashboardMemo).filter(Boolean).length };
        state.activeTab = 'alerts';
        state.alerts = alerts.map(a => ({ ...a }));
        state.processes = { ...processes };
        releaseDashboardCounts();
        const _total = items => items.reduce((sum, item) => sum + item[1], 0);
        setTimeout(() => {
            gc();
            r.freed = [old.alerts.deref() === undefined, old.processes.deref() === undefined];
            r.held = Object.values(_dashboardMemo).filter(Boolean).length;
            state.activeTab = 'dashboard';
            renderDashboardCharts();
            r.shown = [_dashboardMemo.bars.inputs[0] === state.alerts, _dashboardMemo.sparks.inputs[1] === state.processes,
                       _total(look().severity.segments) === state.alerts.length];
            // "Clear all" in the Tracing tab: the lists counted go with it
            old = { alerts: new WeakRef(state.alerts), processes: new WeakRef(state.processes) };
            state.activeTab = 'tracing';
            clearAllTracing();
            setTimeout(() => {
                gc();
                r.cleared = [old.alerts.deref() === undefined, old.processes.deref() === undefined,
                             Object.values(_dashboardMemo).filter(Boolean).length];
                console.log(JSON.stringify(r));
            }, 0);
        }, 0);
    """)
    r = _run_node(DASHBOARD_JS + ["clearAllTracing"], script, _dashboard_prelude())
    assert r["counted"] == 3 and r["held"] == 0, "the hidden dashboard still holds counts of the old lists"
    assert r["freed"] == [True, True], "the old lists of alerts and processes stay alive while the dashboard is hidden"
    assert r["shown"] == [True, True, True], "shown again, the dashboard did not count the new lists"
    assert r["cleared"] == [True, True, 0], "the lists cleared in the Tracing tab stay alive in the dashboard's counts"


@needs_node
def test_clearing_the_stopped_processes_counts_the_processes_again():
    """"Clear stopped" in the Tracing tab takes the stopped processes out of
    the process list it has (the same object): the dashboard lets go of its
    counts, and shown again PROCESSES TRACKED counts the processes left."""
    script = _dashboard_script(r"""
        for (const f of ['renderRtraceConsole', 'renderProcessList']) globalThis[f] = () => {};
        const seen = new Date(T - DAY).toISOString();
        const tracked = { a: { key: 'a', first_seen: seen }, b: { key: 'b', first_seen: seen, exit_time: seen },
                          c: { key: 'c', first_seen: seen, exit_time: seen } };
        globalThis.state = { alerts, processes: tracked, serviceStatus: {}, rustinelInfo: {}, activeTab: 'dashboard' };
        const title = () => $('dashboard-processes-spark').getAttribute('title');
        renderDashboard();
        const r = { before: title() };
        state.activeTab = 'tracing';
        clearStoppedProcesses();
        r.held = Object.values(_dashboardMemo).filter(Boolean).length;
        r.same = state.processes === tracked && Object.keys(state.processes);
        state.activeTab = 'dashboard';
        renderDashboardCharts();
        r.after = title();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(DASHBOARD_JS + ["clearStoppedProcesses", "procKey"], script, _dashboard_prelude())
    assert r["before"] == "Processes first seen per day over the last 45 days: 3 in all"
    assert r["same"] == ["a"] and r["held"] == 0, "the dashboard holds counts of the process list cleared in place"
    assert r["after"] == "Processes first seen per day over the last 45 days: 1 in all", \
        "PROCESSES TRACKED still counts the stopped processes taken out of the list"


# --- The charts of the Sysmon tab -------------------------------------------------

# The Sysmon tab of index.html in the test DOM (SORT_DOM: markup is parsed,
# clicks run the inline handlers)
SYSMON_TAB_DOM = r"""
    document.body.innerHTML = MARKUP;
    const $ = id => document.getElementById(id);
    $('tab-sysmon').scrollTop = 0;
    globalThis.showToast = () => {};
"""

# 333 events of 17 minutes up to 19:47:55 on 10 Nov 2026 (+01:00), newest
# first as the server lists them, none in two minutes of it: twelve kinds of
# event, images in any case and with blanks (python.exe), without one,
# hostile (EVIL, QUOTE) and four rare ones for "other images"; times in UTC
# and with an offset, a few without a time or with one of 1970.
SYSMON_FIXTURE = r"""
    const SEC = 1000;
    const T = Date.UTC(2026, 10, 10, 18, 47, 55, 252);
    Date.now = () => T + 5 * 60000;
    const TYPES = [[17, 'PipeCreated'], [18, 'PipeConnected'], [17, 'PipeCreated'], [18, 'PipeConnected'], [1, 'ProcessCreate'],
                   [18, 'PipeConnected'], [17, 'PipeCreated'], [11, 'FileCreate'], [3, 'NetworkConnect'], [22, 'DNSQuery'],
                   [13, 'RegistryEvent'], [5, 'ProcessTerminate']];
    const IMAGES = ['C:\\Python312\\python.exe', 'C:\\Python312\\python.exe', 'C:\\Python312\\PYTHON.EXE ',
                    'C:\\Windows\\System32\\wevtutil.exe', 'C:\\Windows\\System32\\wevtutil.exe', 'C:\\x\\' + EVIL,
                    'C:\\x\\' + EVIL, 'C:\\x\\' + QUOTE, 'C:\\x\\' + QUOTE, '', '', 'C:\\Windows\\System32\\svchost.exe',
                    'C:\\x\\beacon.exe', 'C:\\x\\a.exe', 'C:\\x\\b.exe', 'C:\\x\\c.exe'];
    const timeOf = ev => { const t = Date.parse(ev.timestamp); return Number.isNaN(t) ? -1 : t; };
    const events = Array.from({ length: 333 }, (_, i) => {
        const [event_id, type] = TYPES[i % TYPES.length];
        const s = (i * 7919) % 900, back = s < 300 ? s : s + 120;
        // One event right on the edge of two half minutes (19:40:00.000)
        const t = i === 1 ? Date.UTC(2026, 10, 10, 18, 40) : T - back * SEC - (i % 7) * 113;
        const timestamp = i % 61 === 9 ? 'not a time' : i % 67 === 3 ? undefined : i % 89 === 11 ? '1970-01-01T00:00:00+00:00'
            : i % 2 ? new Date(t).toISOString() : new Date(t + 3600000).toISOString().replace('Z', '+01:00');
        return { record: 'e' + i, timestamp, event_id, type, pid: String(1000 + (i % 40)), image: IMAGES[(i * 5) % IMAGES.length],
                 commandline: event_id === 1 ? 'python -c pass ' + i : '', user: 'NT AUTHORITY\\SYSTEM' };
    }).sort((a, b) => timeOf(b) - timeOf(a));
"""

# What the tab shows: the bars with their counts, the legend, the Sankey, the
# notes and hints, the table views, the rows of the table (by the events'
# records), its note, the chips, and the filters the charts set
SYSMON_LOOK = r"""
    const num = text => Number(String(text).replace(/,/g, ''));
    const hint = el => (el.querySelector('.chart-empty') || { textContent: null }).textContent;
    const paint = el => (el ? el.getAttribute('style') || '' : '').replace(/^(?:fill|background):/, '');
    const tableOf = id => {
        const table = $(id).querySelector('table');
        const rows = table ? table.tBodies[0].rows : [];
        return table && {
            id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
            head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
            rows: rows.filter(row => !row.hasAttribute('data-sort-skip'))
                .map(row => row.cells.map(c => [c.textContent.trim(), c.getAttribute('data-sort-value')])),
            notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()),
        };
    };
    const size = svg => (svg ? [Number(svg.getAttribute('width')), Number(svg.getAttribute('height'))] : null);
    const look = () => {
        const time = $('sysmon-time-chart'), flow = $('sysmon-flow-chart'), table = $('sysmon-table');
        const note = time.querySelector('.sysmon-chart-note'), selection = time.querySelector('.chart-selection');
        const fills = new Map();
        time.querySelectorAll('.chart-bar').forEach(b => {
            if (!fills.has(b.getAttribute('data-key'))) fills.set(b.getAttribute('data-key'), new Set());
            fills.get(b.getAttribute('data-key')).add(paint(b));
        });
        return {
            bins: time.querySelectorAll('.chart-bin').map(g => [Number(g.getAttribute('data-bin-start')), Number(g.getAttribute('data-bin-end')),
                Number(g.getAttribute('data-total')),
                Object.fromEntries(g.querySelectorAll('.chart-bar').map(b => [b.getAttribute('data-key'), Number(b.getAttribute('data-count'))]))]),
            inertBins: time.querySelectorAll('.chart-bin').map(g => g.classList.contains('chart-inert')),
            barFills: Object.fromEntries([...fills].map(([key, set]) => [key, [...set].join(' ')])),
            legend: time.querySelectorAll('.chart-legend-row').map(row => [row.getAttribute('data-key'),
                row.querySelector('.chart-legend-name').textContent, num(row.querySelector('.chart-legend-count').textContent),
                row.classList.contains('chart-inert'), paint(row.querySelector('.chart-legend-swatch'))]),
            selection: selection ? ['x', 'width'].map(a => Number(selection.getAttribute(a))) : null,
            svgSize: size(time.querySelector('svg')), flowSize: size(flow.querySelector('svg')),
            note: note ? note.textContent.trim() : null, timeEmpty: hint(time),
            nodes: flow.querySelectorAll('.sankey-node').map(g => [g.getAttribute('data-sankey-node'), Number(g.getAttribute('data-value')),
                g.classList.contains('chart-inert'), paint(g.querySelector('.sankey-bar')), g.querySelector('title').textContent]),
            bands: flow.querySelectorAll('.sankey-link').map(p => [p.getAttribute('data-source'), p.getAttribute('data-target'),
                Number(p.getAttribute('data-value')), p.classList.contains('chart-inert')]),
            flowEmpty: hint(flow),
            tables: { time: tableOf('sysmon-time-table'), flow: tableOf('sysmon-flow-table') },
            rows: table.querySelectorAll('tbody tr').map(tr => sysmonEvents[Number(/showSysmonDetailAt\((\d+)\)/.exec(tr.getAttribute('onclick'))[1])].record),
            info: (table.querySelector('.sysmon-search-info') || { textContent: null }).textContent,
            message: (table.querySelector('.empty-state') || { textContent: null }).textContent,
            chips: $('sysmon-active-filters').querySelectorAll('.alerts-filter-chip').map(c => c.textContent.replace(/\s+/g, ' ').trim()),
            chipsHidden: $('sysmon-active-filters').hidden,
            window: { ...sysmonTimeWindow }, flowFilter: { ...sysmonFlowFilter },
        };
    };
"""


def _sysmon_script(script):
    return ((SYSMON_TAB_DOM + SYSMON_FIXTURE + SYSMON_LOOK + script)
            .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE))
            .replace("MARKUP", json.dumps(_tab_markup("sysmon"))))


def _sysmon_js(zone="UTC"):
    return SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone) + _sysmon_prelude()


def _in_no_bar(note):
    """The events a note under EVENTS OVER TIME (or a row of its table) counts as in no bar."""
    return sum(int(n.replace(",", "")) for n in re.findall(r"([\d,]+) (?:without time|with implausible time)", note or ""))


def _sysmon_totals(view):
    """The rows of the table, and what each chart and table view adds up to."""
    tables = view["tables"]
    return len(view["rows"]), {
        "bars + note": sum(total for _, _, total, _ in view["bins"]) + _in_no_bar(view["note"]),
        "legend": sum(row[2] for row in view["legend"]),
        "out of the images": sum(v for s, _, v, _ in view["bands"] if s.startswith("image:") or s == "other images"),
        "into the types": sum(v for _, t, v, _ in view["bands"] if t.startswith("type:")),
        "image nodes": sum(v for node, v, *_ in view["nodes"] if node.startswith("image:") or node == "other images"),
        "type nodes": sum(v for node, v, *_ in view["nodes"] if node.startswith("type:")),
        "time table + notes": sum(int(row[1][1]) for row in tables["time"]["rows"])
        + sum(_in_no_bar(note) for note in tables["time"]["notes"]),
        "flow table": sum(int(row[2][1]) for row in tables["flow"]["rows"]),
    }


SYSMON_TYPES = ["PipeCreated", "PipeConnected", "ProcessCreate", "FileCreate", "NetworkConnect", "DNSQuery", "RegistryEvent",
                "ProcessTerminate"]
NO_SYSMON_FILTER = {"image": None, "type": None}
NO_WINDOW = {"from": None, "to": None}


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "Asia/Kolkata"])
def test_sysmon_charts_count_loaded_events(zone):
    """EVENTS OVER TIME and PROCESS → EVENT TYPE count the events the table
    lists: the bars with the note of the events without a time (or with one
    no clock can have had), the legend, the flow out of the images and into
    the event types, and their table views add up to the rows of the table,
    also with the search, the EID filters and a filter a chart set. Each bar
    and node counts what its filter lists. An image in any case and without
    the blanks around it is one node, the six most frequent stand on their
    own, the rest is "other images". An event type keeps its colour, a theme
    variable, whatever else is loaded."""
    script = _sysmon_script(r"""
        sysmonEvents = events;
        renderSysmonTable();
        const r = { all: look(), events: events.length, edge: Date.UTC(2026, 10, 10, 18, 40) };
        const view = (name, listed) => { r[name] = { ...look(), listed }; };
        $('sysmon-search').value = 'PYTHON'; renderSysmonTable();
        view('search', filterSysmonEvents(events, { text: 'python' }).length);
        $('sysmon-search').value = ''; $('sysmon-filter-eid').value = '17, 18'; renderSysmonTable();
        view('eid', events.filter(ev => ev.event_id === 17 || ev.event_id === 18).length);
        $('sysmon-filter-eid').value = ''; $('sysmon-filter-wineid').value = '4688'; renderSysmonTable();
        view('winEid', events.filter(ev => [1, 8, 25].includes(ev.event_id)).length);
        $('sysmon-filter-wineid').value = '';
        setSysmonFilters({ image: 'PYTHON.exe' });
        view('image', events.filter(ev => String(ev.image).split('\\').pop().trim().toLowerCase() === 'python.exe').length);
        setSysmonFilters({ image: null, type: 'pipecreated' });
        view('type', events.filter(ev => ev.type === 'PipeCreated').length);
        setSysmonFilters({ type: null });
        // What each node and bar counts, and what its filter lists
        r.trips = r.all.nodes.filter(([id]) => Object.keys(_sysmonFlowFilter(id)).length)
            .map(([id, value]) => [id, value, filterSysmonEvents(events, _sysmonFlowFilter(id)).length]);
        r.binTrips = r.all.bins.map(([from, to, total]) => [total, filterSysmonEvents(events, { from, to }).length]);
        // An event type keeps its colour whatever else is loaded
        sysmonEvents = events.filter(ev => ev.type === 'FileCreate' || ev.type === 'ProcessTerminate');
        renderSysmonTable();
        r.few = look();
        console.log(JSON.stringify(r));
    """)
    r = _run_node(SYSMON_TAB_FUNCTIONS, script, _sysmon_js(zone))
    assert r["events"] == 333 and len(r["all"]["rows"]) == 333
    for name in ("all", "search", "eid", "winEid", "image", "type", "few"):
        rows, totals = _sysmon_totals(r[name])
        assert rows and all(total == rows for total in totals.values()), \
            f"{name}: the charts count other events than the table lists ({rows}): {totals}"
        if "listed" in r[name]:
            assert rows == r[name]["listed"], f"{name}: the table lists {rows}, the filter {r[name]['listed']}"
    assert r["all"]["note"] == "10 without time \u00b7 4 with implausible time"
    assert r["all"]["tables"]["time"]["notes"] == ["10 without time", "4 with implausible time"]
    # 17 minutes in half minutes, not one bar per hour
    bins = r["all"]["bins"]
    assert 34 <= len(bins) <= 36 and all(end - start <= 30000 for start, end, *_ in bins), \
        f"the bars are no half minutes: {len(bins)} bins"
    assert r["edge"] in [start for start, *_ in bins], "the fixture's event on the edge of two bars lies on no edge"
    # Six images on their own, the rest "other images" (no filter, no pointer); python.exe in any case is one node
    nodes = r["all"]["nodes"]
    images = [node for node, *_ in nodes if node.startswith("image:")]
    assert len(images) == 6 and [node for node, *_ in nodes if not node.startswith(("image:", "type:"))] == ["other images"]
    assert sum(1 for node in images if node.strip().lower() == "image:python.exe") == 1, images
    assert [node for node, _, inert, *_ in nodes if inert] == ["other images"]
    assert all(inert == (source == "other images") for source, _, _, inert in r["all"]["bands"])
    assert any(inert for *_, inert in r["all"]["bands"]) and not all(inert for *_, inert in r["all"]["bands"])
    assert sorted(node[5:] for node, *_ in nodes if node.startswith("type:")) == sorted(SYSMON_TYPES)
    for name, trips in (("nodes", r["trips"]), ("bars", r["binTrips"])):
        assert trips and all(t[-2] == t[-1] for t in trips), f"{name}: a part counts other events than its filter lists: {trips}"
    assert len(r["trips"]) == 6 + 8
    assert not any(r["all"]["inertBins"][i] for i, b in enumerate(r["all"]["bins"]) if b[2] > 0)
    assert any(r["all"]["inertBins"]), "the fixture has no bar without events"
    # Colours by type: theme variables, the same for the bars, the legend and the Sankey, and after another load
    colours = {row[0]: row[4] for row in r["all"]["legend"]}
    assert sorted(colours) == sorted(SYSMON_TYPES)
    assert all(re.fullmatch(r"var\(--[\w-]+\)", c) for c in colours.values()) and len(set(colours.values())) == len(colours), colours
    assert r["all"]["barFills"] == colours
    assert {node[5:]: fill for node, _, _, fill, _ in nodes if node.startswith("type:")} == colours
    assert {row[0]: row[4] for row in r["few"]["legend"]} == {k: colours[k] for k in ("FileCreate", "ProcessTerminate")}
    assert colours["ProcessCreate"] == "var(--accent-cyan)", "ProcessCreate is not in the colour of its badge"
    # The legend by count; the time table: a row per bar with events, its total, then the types in the legend's order
    legend = r["all"]["legend"]
    assert [row[2] for row in legend] == sorted((row[2] for row in legend), reverse=True)
    time = r["all"]["tables"]["time"]
    assert time["head"] == ["Period", "Total"] + [row[1] for row in legend]
    bars = [(start, total, counts) for start, _, total, counts in r["all"]["bins"] if total]
    assert [[int(cell[1]) for cell in row[:2]] for row in time["rows"]] == [[start, total] for start, total, _ in bars]
    assert [[int(cell[1]) for cell in row[2:]] for row in time["rows"]] == \
        [[counts.get(row[0], 0) for row in legend] for *_, counts in bars]
    assert r["all"]["tables"]["flow"]["head"] == ["Image", "Event type", "Count"]


@needs_node
def test_sysmon_time_window_filters_the_table():
    """A click on a bar of EVENTS OVER TIME sets the time window of its
    period: the table lists only its events, a chip "× HH:MM:SS – HH:MM:SS"
    in the filter bar names it (a poll keeps it, and its focus) and its ×
    takes it off. The charts still count every event of the filters (they
    show where to click next) and mark the window. Shift+click widens the
    window to another bar; a bar without events sets nothing. New events
    keep the window while they reach it, and drop it when they no longer do."""
    script = _sysmon_script(r"""
        (async () => {
            let reply = events;
            globalThis.fetch = async url => ({ ok: true, status: 200,
                json: async () => (String(url).startsWith('/api/sysmon/stats') ? { online: true, stats: [] } : reply) });
            sysmonEvents = events;
            renderSysmonTable();
            const r = { all: look() };
            const full = () => $('sysmon-time-chart').querySelectorAll('.chart-bin').filter(g => Number(g.getAttribute('data-total')) > 0);
            const period = g => ['data-bin-start', 'data-bin-end', 'data-total'].map(a => Number(g.getAttribute(a)));
            const within = (from, to) => events.filter(ev => timeOf(ev) >= from && timeOf(ev) < to).map(ev => ev.record);
            const [start, end, total] = period(full()[5]);
            click(full()[5].querySelector('.chart-bar'));
            r.clicked = { ...look(), start, end, total, listed: within(start, end), label: _sysmonWindowLabel(start, end),
                          index: r.all.bins.findIndex(b => b[0] === start) };
            // Shift+click on a later bar: from the first to the end of that one
            const [, laterEnd] = period(full()[9]);
            dispatch('click', full()[9].querySelector('.chart-hit'), { shiftKey: true });
            r.widened = { ...look(), from: start, to: laterEnd, listed: within(start, laterEnd) };
            // A click on another bar: its period only
            const [s2, e2] = period(full()[2]);
            click(full()[2].querySelector('.chart-hit'));
            r.other = { ...look(), from: s2, to: e2, listed: within(s2, e2) };
            // A bar without events sets nothing
            const empty = $('sysmon-time-chart').querySelectorAll('.chart-bin').find(g => g.getAttribute('data-total') === '0');
            r.emptyInert = empty.classList.contains('chart-inert');
            click(empty.querySelector('.chart-hit'));
            r.empty = look();
            // With the search: the table lists the events of both, the charts those of the search
            $('sysmon-search').value = 'python'; renderSysmonTable();
            r.search = { ...look(), listed: filterSysmonEvents(events, { text: 'python', from: s2, to: e2 }).map(ev => ev.record),
                         charted: filterSysmonEvents(events, { text: 'python' }).length };
            $('sysmon-search').value = ''; renderSysmonTable();
            // From the keyboard: the chip's × hands the focus on to the search box
            const chip = $('sysmon-active-filters').querySelector('.alerts-filter-chip');
            r.chipAttrs = [chip.getAttribute('data-filter'), chip.getAttribute('title'), chip.getAttribute('onclick'),
                           chip.getAttribute('aria-label')];
            chip.focus();
            // A poll that brings the same events keeps the chip, and so its focus
            await refreshSysmon();
            r.chipKept = $('sysmon-active-filters').querySelector('.alerts-filter-chip') === chip && document.activeElement === chip;
            click(chip);
            r.removed = { ...look(), focus: document.activeElement && document.activeElement.id };
            // New events that reach the window keep it, also when none lies in it; later ones drop it
            click(full()[2].querySelector('.chart-hit'));
            reply = events.filter((ev, i) => i % 2 === 0);
            await refreshSysmon(); r.kept = { ...look(), listed: within(s2, e2).filter(id => reply.some(ev => ev.record === id)) };
            reply = events.filter(ev => !(timeOf(ev) >= s2 && timeOf(ev) < e2));
            await refreshSysmon(); r.gap = look();
            reply = events.filter(ev => timeOf(ev) >= e2 + 60000);
            await refreshSysmon(); r.later = { ...look(), loaded: reply.length };
            r.s2 = s2; r.e2 = e2;
            console.log(JSON.stringify(r));
        })();
    """)
    r = _run_node(SYSMON_TAB_FUNCTIONS, script, _sysmon_js())
    base = r["all"]
    assert base["chips"] == [] and base["chipsHidden"] and base["window"] == NO_WINDOW and base["selection"] is None
    c = r["clicked"]
    assert c["window"] == {"from": c["start"], "to": c["end"]}
    assert re.fullmatch(r"\d\d:\d\d:\d\d \u2013 \d\d:\d\d:\d\d", c["label"]), c["label"]
    assert c["chips"] == ["\u00d7 " + c["label"]] and not c["chipsHidden"]
    assert sorted(c["rows"]) == sorted(c["listed"]) and len(c["rows"]) == c["total"] > 0, \
        "the table lists other events than the bar counted"
    assert c["info"] == f"Showing {c['total']} of 333 events ({c['total']}/333)"
    # The charts still count every event, the bars mark the window over its bar
    assert c["bins"] == base["bins"] and c["nodes"] == base["nodes"] and c["legend"] == base["legend"]
    slot = c["svgSize"][0] / len(c["bins"])
    assert abs(c["selection"][0] - c["index"] * slot) < 0.02 and abs(c["selection"][1] - slot) < 0.02, c["selection"]
    w = r["widened"]
    assert w["window"] == {"from": w["from"], "to": w["to"]} and sorted(w["rows"]) == sorted(w["listed"])
    assert len(w["rows"]) > len(c["rows"]) and len(w["chips"]) == 1
    o = r["other"]
    assert o["window"] == {"from": o["from"], "to": o["to"]} and sorted(o["rows"]) == sorted(o["listed"])
    assert r["emptyInert"] and r["empty"]["window"] == o["window"], "a bar without events set a window"
    s = r["search"]
    assert sorted(s["rows"]) == sorted(s["listed"]) and s["rows"], "the search and the window do not both filter the table"
    _, totals = _sysmon_totals({**s, "rows": []})
    assert all(total == s["charted"] for total in totals.values()), f"the charts count the window: {totals}"
    window_title = r["chipAttrs"][1]
    assert r["chipAttrs"][0] == "window" and r["chipAttrs"][2] == 'removeSysmonFilter("window")'
    assert re.fullmatch(r"Remove the time window 2026-11-10 \d\d:\d\d:\d\d \u2013 2026-11-10 \d\d:\d\d:\d\d "
                        r"\(end not included\)", window_title), window_title
    assert r["chipAttrs"][3] == window_title
    assert r["chipKept"], "a poll with the same chart filters wrote the chips again: the focus got lost"
    gone = r["removed"]
    assert gone["window"] == NO_WINDOW and gone["chips"] == [] and gone["chipsHidden"] and len(gone["rows"]) == 333
    assert gone["focus"] == "sysmon-search", "the focus got lost with the chip"
    assert gone["info"] is None
    kept = r["kept"]
    assert kept["window"] == {"from": r["s2"], "to": r["e2"]} and len(kept["chips"]) == 1
    assert sorted(kept["rows"]) == sorted(kept["listed"])
    gap = r["gap"]
    assert gap["window"] == {"from": r["s2"], "to": r["e2"]}, "new events around the window dropped it"
    assert gap["rows"] == [] and gap["message"].startswith("No events matching time window "), gap["message"]
    later = r["later"]
    assert later["window"] == NO_WINDOW and later["chips"] == [], "a window the new events no longer reach stays"
    assert len(later["rows"]) == later["loaded"] > 0


@needs_node
def test_sysmon_sankey_clicks_set_image_and_type_filters():
    """A node of PROCESS → EVENT TYPE sets its image or its event type as a
    filter, a band both of its ends, a legend row of EVENTS OVER TIME its
    type: a chip names each, its × takes it off, and the table and both
    charts then count what the part counted. "other images" and its bands
    set nothing; the image "(unknown)" lists the events without one. Image
    names from the sample stay text in the nodes, the chips and the tables."""
    script = _sysmon_script(r"""
        sysmonEvents = events;
        renderSysmonTable();
        const all = look();
        const r = { all };
        const node = id => $('sysmon-flow-chart').querySelectorAll('.sankey-node').find(g => g.getAttribute('data-sankey-node') === id);
        const band = test => $('sysmon-flow-chart').querySelectorAll('.sankey-link')
            .find(p => test(p.getAttribute('data-source'), p.getAttribute('data-target')));
        const value = id => all.nodes.find(n => n[0] === id)[1];
        const python = all.nodes.map(n => n[0]).find(id => id.trim().toLowerCase() === 'image:python.exe');
        click(node(python).querySelector('text'));
        r.python = { ...look(), expected: value(python), name: python.slice('image:'.length) };
        click($('sysmon-active-filters').querySelector('.alerts-filter-chip'));
        r.pythonOff = look();
        click(node('type:PipeCreated').querySelector('rect'));
        r.type = { ...look(), expected: value('type:PipeCreated') };
        setSysmonFilters({ type: null });
        const both = band((s, t) => s === python && t === 'type:PipeConnected');
        r.band = { expected: Number(both.getAttribute('data-value')) };
        click(both);
        Object.assign(r.band, look());
        setSysmonFilters({ image: null, type: null });
        // "other images" and its bands: nothing
        click(node('other images'));
        click(band(s => s === 'other images'));
        r.other = look();
        // The image "(unknown)": the events without one
        click(node('image:(unknown)'));
        r.unknown = { ...look(), expected: events.filter(ev => !String(ev.image || '').split('\\').pop().trim()).length };
        setSysmonFilters({ image: null });
        // A legend row of EVENTS OVER TIME: its type
        click($('sysmon-time-chart').querySelectorAll('.chart-legend-row').find(row => row.getAttribute('data-key') === 'ProcessCreate')
            .querySelector('.chart-legend-name'));
        r.legend = { ...look(), expected: events.filter(ev => ev.type === 'ProcessCreate').length };
        setSysmonFilters({ type: null });
        // Names from the sample: text, the filter takes them whole
        click(node('image:' + EVIL));
        r.evil = { ...look(), markup: ['img', 'script', 'b'].map(t => $('tab-sysmon').querySelectorAll(t).length),
                   expected: events.filter(ev => String(ev.image).endsWith(EVIL)).length,
                   values: $('sysmon-active-filters').querySelectorAll('.alerts-filter-chip-value').map(v => v.textContent),
                   attrs: $('sysmon-active-filters').querySelectorAll('.alerts-filter-chip').map(c => Object.keys(c.attrs).sort().join(' ')),
                   titles: $('sysmon-active-filters').querySelectorAll('.alerts-filter-chip').map(c => c.getAttribute('title')) };
        click(node('type:PipeConnected'));
        r.both = look();
        click($('sysmon-active-filters').querySelectorAll('.alerts-filter-chip').find(c => c.getAttribute('data-filter') === 'image'));
        r.typeLeft = look();
        r.quote = all.nodes.find(n => n[0] === 'image:' + QUOTE);
        r.flowImages = all.tables.flow.rows.map(row => row[0][0]);
        console.log(JSON.stringify(r));
    """)
    r = _run_node(SYSMON_TAB_FUNCTIONS, script, _sysmon_js())

    def exact(view):
        rows, totals = _sysmon_totals(view)
        assert all(total == rows for total in totals.values()), totals
        return rows

    p = r["python"]
    assert p["flowFilter"] == {"image": p["name"], "type": None} and p["chips"] == ["\u00d7 image: " + p["name"]]
    assert exact(p) == p["expected"] > 0, "the table lists other events than the node counted"
    assert [node for node, *_ in p["nodes"] if not node.startswith("type:")] == ["image:" + p["name"]], \
        "the Sankey does not show the image of the filter"
    assert r["pythonOff"]["flowFilter"] == NO_SYSMON_FILTER and len(r["pythonOff"]["rows"]) == 333
    t = r["type"]
    assert t["flowFilter"] == {"image": None, "type": "PipeCreated"} and t["chips"] == ["\u00d7 type: PipeCreated"]
    assert exact(t) == t["expected"] > 0 and list(t["barFills"]) == ["PipeCreated"]
    b = r["band"]
    assert b["flowFilter"] == {"image": p["name"], "type": "PipeConnected"}
    assert b["chips"] == ["\u00d7 image: " + p["name"], "\u00d7 type: PipeConnected"] and exact(b) == b["expected"] > 0
    o = r["other"]
    assert o["flowFilter"] == NO_SYSMON_FILTER and o["chips"] == [] and len(o["rows"]) == 333, \
        "a click on other images set a filter"
    u = r["unknown"]
    assert u["flowFilter"] == {"image": "(unknown)", "type": None} and u["chips"] == ["\u00d7 image: (unknown)"]
    assert exact(u) == u["expected"] > 0, "the image (unknown) does not list the events without one"
    leg = r["legend"]
    assert leg["flowFilter"] == {"image": None, "type": "ProcessCreate"} and exact(leg) == leg["expected"] > 0
    e = r["evil"]
    assert e["markup"] == [0, 0, 0] and e["values"] == [EVIL] and e["flowFilter"]["image"] == EVIL
    assert e["titles"] == [f"Remove the image filter: {EVIL}"]
    assert set(e["attrs"]) == {"aria-label class data-filter onclick title type"}, "a name left its attribute"
    assert exact(e) == e["expected"] > 0
    assert r["both"]["chips"] == [f"\u00d7 image: {EVIL}", "\u00d7 type: PipeConnected"]
    assert r["typeLeft"]["chips"] == ["\u00d7 type: PipeConnected"] and r["typeLeft"]["flowFilter"]["image"] is None
    assert r["quote"][4].startswith(QUOTE + ": "), "a name with a quote is cut short in its tooltip"
    assert EVIL in r["flowImages"] and QUOTE in r["flowImages"]


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "Asia/Kolkata"])
def test_sysmon_time_window_label_names_its_clock_times(zone):
    """The chip of a time window names its local clock times with their
    seconds (hours 00-23, never 24:00), and the dates when the window does
    not lie within one day or covers a whole one (a bar of a day)."""
    r = _run_node(["_sysmonWindowLabel", "_chartPeriodStart", "_chartPeriodNext", "_chartDate", "_chartClock"], r"""
        const at = (...a) => new Date(...a).getTime();
        console.log(JSON.stringify([
            _sysmonWindowLabel(at(2026, 10, 10, 19, 32), at(2026, 10, 10, 19, 32, 30)),
            _sysmonWindowLabel(at(2026, 10, 10, 23, 59, 30), at(2026, 10, 11)),
            _sysmonWindowLabel(at(2026, 10, 10, 0, 0, 5), at(2026, 10, 10, 0, 0, 6)),
            _sysmonWindowLabel(at(2026, 10, 10, 23), at(2026, 10, 11, 1)),
            _sysmonWindowLabel(at(2026, 10, 10), at(2026, 10, 11)),
            _sysmonWindowLabel(at(2026, 9, 25), at(2026, 9, 26)),
        ]));
    """, _prelude(zone))
    assert r == ["19:32:00 \u2013 19:32:30", "23:59:30 \u2013 00:00:00", "00:00:05 \u2013 00:00:06",
                 "10 Nov 23:00:00 \u2013 11 Nov 01:00:00", "10 Nov 00:00:00 \u2013 11 Nov 00:00:00",
                 "25 Oct 00:00:00 \u2013 26 Oct 00:00:00"], r


@needs_node
def test_sysmon_charts_say_why_they_are_empty():
    """While the first events load, the charts say so; without Sysmon (the
    server's error, a query that fails or goes unanswered) they say "Sysmon
    not available", without events "No Sysmon events", and "No events match
    the filters" when the filters leave none; their tables the same. A query
    that failed holds no events, so the tab asks again when it is opened."""
    script = _sysmon_script(r"""
        (async () => {
            let reply = { status: 200, body: [] };
            const r = {};
            globalThis.fetch = async url => {
                if (String(url).startsWith('/api/sysmon/stats')) return { ok: true, status: 200, json: async () => ({ online: true, stats: [] }) };
                r.loading = r.loading || [look().timeEmpty, look().flowEmpty];
                r.loadingTables = r.loadingTables || Object.values(look().tables).map(t => t.notes[0]);
                if (reply.unreachable) throw new Error('Failed to fetch');
                return { ok: reply.status === 200, status: reply.status, json: async () => reply.body };
            };
            await refreshSysmon(); r.none = look();
            reply = { status: 200, body: [{ error: 'Sysmon not available locally and VM (192.168.64.4) unreachable.' }] };
            await refreshSysmon(); r.error = look();
            reply = { status: 500, body: null };
            await refreshSysmon(); r.failed = { ...look(), loaded: sysmonEvents.length };
            reply = { unreachable: true };
            await refreshSysmon(); r.unreachable = { ...look(), loaded: sysmonEvents.length };
            reply = { status: 200, body: events };
            await refreshSysmon(); r.back = look();
            $('sysmon-search').value = 'nothing like it'; renderSysmonTable(); r.noMatch = look();
            console.log(JSON.stringify(r));
        })();
    """)
    r = _run_node(SYSMON_TAB_FUNCTIONS, script, _sysmon_js())
    assert r["loading"] == ["Loading Sysmon events\u2026"] * 2, r["loading"]
    assert r["loadingTables"] == ["Loading Sysmon events\u2026"] * 2, "the hint of a table view ends in …."
    for name, text, message in (
            ("none", "No Sysmon events", "No Sysmon events found"),
            ("error", "Sysmon not available", "Error: Sysmon not available locally and VM (192.168.64.4) unreachable."),
            ("failed", "Sysmon not available", "Failed to load Sysmon events."),
            ("unreachable", "Sysmon not available", "Connection error: Failed to fetch"),
            ("noMatch", "No events match the filters", 'No events matching "nothing like it" (333 total)')):
        view = r[name]
        assert view["timeEmpty"] == view["flowEmpty"] == text, (name, view["timeEmpty"], view["flowEmpty"])
        assert not view["bins"] and not view["nodes"] and not view["legend"] and view["note"] is None, name
        assert all(not table["rows"] and table["notes"] == [text + "."] for table in view["tables"].values()), \
            (name, view["tables"])
        assert view["message"] == message, (name, view["message"])
    assert r["failed"]["loaded"] == r["unreachable"]["loaded"] == 0, "a failed query keeps events: the tab does not ask again"
    assert len(r["back"]["rows"]) == 333 and r["back"]["bins"] and r["back"]["timeEmpty"] is None


@needs_node
def test_sysmon_charts_have_info_and_table():
    """Above the filter bar: EVENTS OVER TIME and PROCESS → EVENT TYPE side
    by side, each with its (i) and its CHART / TABLE switch, each table view
    sortable with the numbers of its chart. LINEAR draws the Sankey in true
    proportions (square roots by default) until the page is reloaded. Both
    are drawn for the width of their card, as high as the Sankey needs, and
    again when a width changes, not while hidden."""
    tab = _Elements(_read(INDEX_HTML)).by_id("tab-sysmon")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def by_id(node, element_id):
        found = find(node, lambda e: e["attrs"].get("id") == element_id)
        assert len(found) == 1, element_id
        return found[0]

    def text(node):
        return node.get("text", "") + "".join(text(c) for c in node["children"])

    parts = [c["attrs"].get("id") or c["attrs"].get("class") for c in tab["children"]]
    assert parts == ["content-header", "sysmon-charts", "sysmon-filters", "sysmon-correlation-panel", "sysmon-stats",
                     "sysmon-table"], "the charts are not above the filter bar, or the filters not in a bar of their own"
    charts = by_id(tab, "sysmon-charts")
    cards = find(charts, lambda e: "chart-card" in e["attrs"].get("class", "").split())
    assert [c["attrs"].get("id") for c in cards] == ["sysmon-time-card", "sysmon-flow-card"]
    for card, (kind, title) in zip(cards, {"time": "EVENTS OVER TIME", "flow": "PROCESS \u2192 EVENT TYPE"}.items()):
        view = f"sysmon-{kind}"
        heading = find(card, lambda e: "chart-card-title" in e["attrs"].get("class", "").split())
        assert len(heading) == 1 and text(heading[0]).strip() == title, kind
        assert heading[0]["attrs"].get("data-info", "").strip(), f"{kind}: no (i)"
        assert by_id(card, f"{view}-toggle") is not None
        chart, table = by_id(card, f"{view}-chart"), by_id(card, f"{view}-table")
        assert (chart["attrs"].get("data-view-of"), chart["attrs"].get("data-view"), "hidden" in chart["attrs"]) == \
            (view, "chart", False)
        assert (table["attrs"].get("data-view-of"), table["attrs"].get("data-view"), "hidden" in table["attrs"]) == \
            (view, "table", True)
        assert "chart-clickable" in chart["attrs"].get("class", "").split()
        assert chart["attrs"].get("onclick") == f"onSysmonChartClick(event, '{kind}')"
    linear = by_id(cards[1], "sysmon-flow-linear")
    assert (linear["tag"], text(linear).strip(), linear["attrs"].get("aria-pressed"), linear["attrs"].get("onclick"),
            linear["attrs"].get("data-view-of"), linear["attrs"].get("data-view")) == \
        ("button", "LINEAR", "false", "toggleSysmonFlowScale()", "sysmon-flow", "chart")
    # The filter bar holds the controls of the tab (none left in its head) and the chips of the chart filters
    bar = find(tab, lambda e: "sysmon-filters" in e["attrs"].get("class", "").split())[0]
    controls = [e["attrs"]["id"] for e in find(bar, lambda e: e["tag"] in ("input", "select"))]
    assert controls == ["sysmon-search", "sysmon-filter-type", "sysmon-filter-eid", "sysmon-filter-wineid",
                        "sysmon-filter-pid", "sysmon-max-events"]
    assert [text(b).strip() for b in find(bar, lambda e: e["tag"] == "button")] == ["Refresh", "Correlate"]
    head = find(tab, lambda e: "content-header" in e["attrs"].get("class", "").split())[0]
    assert not find(head, lambda e: e["tag"] in ("input", "select", "button"))
    chips = by_id(bar, "sysmon-active-filters")
    assert "hidden" in chips["attrs"] and chips["attrs"].get("role") == "group" and chips["attrs"].get("aria-label")
    assert "viewToggleHtml(" in _function_source("renderSysmonCharts")
    names = [f for f in SYSMON_TAB_FUNCTIONS if "ysmon" in f and f not in ("refreshSysmon", "renderSysmonTable")]
    source = "\n".join(_strip_js_comments(_function_source(name)) for name in names)
    source += "\n".join(_const_source(c) for c in ("SYSMON_TYPE_COLORS", "SYSMON_OTHER_COLORS"))
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"

    script = _sysmon_script(r"""
        sysmonEvents = events;
        const head = kind => document.querySelector(`#sysmon-${kind}-card .chart-card-head`);
        $('sysmon-time-plot').rect = { width: 680 }; head('flow').rect = { width: 600 };
        renderSysmonTable();
        const r = { view: look() };
        const areas = () => document.querySelectorAll('#tab-sysmon .sysmon-chart-area').map(a => a.style.height);
        r.areas = areas();
        const toggle = kind => $(`sysmon-${kind}-toggle`).querySelector('.view-toggle');
        r.toggles = ['time', 'flow'].map(kind => [toggle(kind).getAttribute('data-view-toggle'), toggle(kind).textContent]);
        const node = id => $('sysmon-flow-chart').querySelectorAll('.sankey-node').find(g => g.getAttribute('data-sankey-node') === id);
        const heights = () => ['type:PipeConnected', 'type:FileCreate'].map(id => Number(node(id).querySelector('.sankey-bar').getAttribute('height')));
        const values = ['type:PipeConnected', 'type:FileCreate'].map(id => Number(node(id).getAttribute('data-value')));
        r.values = values;
        r.sqrt = heights();
        const linear = $('sysmon-flow-linear');
        click(linear);
        r.linear = { heights: heights(), pressed: linear.getAttribute('aria-pressed') };
        renderSysmonTable();
        r.refreshed = { heights: heights(), pressed: linear.getAttribute('aria-pressed') };
        click(linear);
        r.back = { heights: heights(), pressed: linear.getAttribute('aria-pressed') };
        // New widths: drawn again; the same widths or a hidden tab (0): left as they are
        $('sysmon-time-plot').rect = { width: 500 }; head('flow').rect = { width: 420 };
        redrawSysmonChartsOnResize();
        r.resized = [look().svgSize[0], look().flowSize[0]];
        // The event types keep the room for their names in a narrow card
        r.typeLabels = $('sysmon-flow-chart').querySelectorAll('.sankey-node').filter(g => g.getAttribute('data-sankey-node').startsWith('type:'))
            .map(g => [g.getAttribute('data-sankey-node').slice(5), g.querySelector('.sankey-label').childNodes[0].textContent.trim()]);
        const drawn = [$('sysmon-time-chart').querySelector('svg'), $('sysmon-flow-chart').querySelector('svg')];
        redrawSysmonChartsOnResize();
        $('sysmon-time-plot').rect = { width: 0 }; head('flow').rect = { width: 0 };
        redrawSysmonChartsOnResize();
        r.kept = [$('sysmon-time-chart').querySelector('svg') === drawn[0], $('sysmon-flow-chart').querySelector('svg') === drawn[1]];
        // After no events the legend comes back beside the plot: the bars get the width that leaves them
        sysmonEvents = [];
        renderSysmonTable();
        const plot = $('sysmon-time-plot'), legendBox = $('sysmon-time-legend');
        plot.getBoundingClientRect = () => ({ width: legendBox.firstElementChild ? 520 : 680 });
        sysmonEvents = events;
        renderSysmonTable();
        r.afterEmpty = look().svgSize[0];
        delete plot.getBoundingClientRect;
        // TABLE: the table in place of the chart, kept on the next render; LINEAR goes with the chart
        click(toggle('time')); click(toggle('flow'));
        renderSysmonTable();
        r.tables = ['time', 'flow'].map(kind => [$(`sysmon-${kind}-chart`).hidden, $(`sysmon-${kind}-table`).hidden,
                                                  toggle(kind).textContent]);
        r.linearHidden = linear.hidden;
        console.log(JSON.stringify(r));
    """)
    r = _run_node(SYSMON_TAB_FUNCTIONS, script, _sysmon_js())
    view = r["view"]
    assert r["toggles"] == [["sysmon-time", "TABLE"], ["sysmon-flow", "TABLE"]], "a card without its CHART / TABLE switch"
    tables = view["tables"]
    assert {kind: t["id"] for kind, t in tables.items()} == {"time": "sysmon-time", "flow": "sysmon-flow"}
    assert all(t["sortable"] for t in tables.values())
    titles = {node: title.rsplit(": ", 1)[0] for node, _, _, _, title in view["nodes"]}
    assert sorted([row[0][0], row[1][0], int(row[2][1])] for row in tables["flow"]["rows"]) == \
        sorted([titles[s], titles[t], v] for s, t, v, _ in view["bands"]), "the flow table does not list the bands"
    # Drawn for the width of their card, as high as the Sankey needs (8 types: 32 px each and room)
    assert view["svgSize"][0] == 680 and view["flowSize"][0] == 600, "not drawn for the width of the card"
    assert r["areas"] == ["280px", "280px"] and view["flowSize"][1] == 280 and view["svgSize"][1] <= 280, r["areas"]
    assert r["resized"] == [500, 420] and r["kept"] == [True, True], "drawn again for the same width, or while hidden"
    assert r["afterEmpty"] == 520, "the bars were drawn for the plot's width before the legend took its room beside it"
    assert len(r["typeLabels"]) == 8 and all(name == label for name, label in r["typeLabels"]), \
        f"an event type's name is cut in a narrow card: {r['typeLabels']}"
    # LINEAR: PipeConnected and FileCreate by their square roots, then in true proportions
    ratio = r["values"][0] / r["values"][1]
    assert abs(r["sqrt"][0] / r["sqrt"][1] - ratio ** 0.5) < 0.05 and r["linear"]["pressed"] == "true"
    assert abs(r["linear"]["heights"][0] / r["linear"]["heights"][1] - ratio) < 0.05, "LINEAR does not show true proportions"
    assert r["refreshed"] == r["linear"], "LINEAR is lost on the next render"
    assert abs(r["back"]["heights"][0] / r["back"]["heights"][1] - ratio ** 0.5) < 0.05 and r["back"]["pressed"] == "false"
    assert r["tables"] == [[True, False, "CHART"], [True, False, "CHART"]]
    assert r["linearHidden"] is True, "LINEAR shows beside the table, where it changes nothing"
    # Both themes
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    assert re.search(r"grid-template-columns:[^;]*fr", rules.get(".sysmon-charts", "")), "the cards are not side by side"
    assert re.search(r"(?:^|;)\s*flex:\s*0 0 auto", rules.get(".sysmon-charts", "")), "the charts shrink into the tab"
    assert re.search(r"position:\s*absolute", rules.get(".sysmon-chart-view", "")), "a table view stretches its card"
    assert re.search(r"overflow(?:-y)?:\s*auto", rules.get(".sysmon-chart-table", ""))
    assert re.search(r"background:\s*transparent", rules.get(".sysmon-chart-table::-webkit-scrollbar-corner", "")), \
        "where a table view scrolls both ways, its corner is the browser's white"
    assert re.search(r"user-select:\s*none", rules.get(".sysmon-time-view", "")), "Shift+click selects the text of the bars"
    assert _painted(rules, _cls("sysmon-chart-note"), "color")
    for selector in ('[data-theme="cyberpunk"] .sysmon-charts', '[data-theme="cyberpunk"] .sysmon-chart-note'):
        assert selector in theme, f"{selector} has no Cyberpunk rule"


@needs_node
def test_the_sysmon_tab_scrolls_as_a_whole_under_a_standing_filter_bar():
    """As the Alerts tab: the tab scrolls as a whole and the table has none
    of its own; the filter bar with the chips of the chart filters stands at
    the top of the tab, opaque in both themes, the table head right under
    it, whatever the bar's height (a ResizeObserver on its border box). The
    same filters keep the place in the list, other ones start at its top
    (the first row right under the bar); above that, nothing moves. LitterBox
    keeps its own table head (the same table class). A table wider than the
    tab scrolls sideways with it instead of being cut off."""
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    assert re.search(r"(?:^|;)\s*overflow-y:\s*auto", rules.get("#tab-sysmon", "")), "the tab does not scroll"
    assert re.search(r"(?:^|;)\s*overflow-x:\s*auto", rules.get("#tab-sysmon", "")), \
        "a table wider than the tab is cut off at its edge"
    wrap = rules.get("#sysmon-table", "")
    assert re.search(r"(?:^|;)\s*overflow:\s*visible", wrap) and re.search(r"(?:^|;)\s*flex:\s*1 0 auto", wrap), \
        "the table scrolls on its own, or shrinks into the tab"
    bar = rules.get(".sysmon-filters", "")
    assert re.search(r"position:\s*sticky", bar) and re.search(r"(?:^|;)\s*top:\s*0\s*(?:;|$)", bar), "the filter bar scrolls away"
    head = rules.get("#sysmon-table .sysmon-events-table thead th", "")
    assert re.search(r"top:\s*var\(--sysmon-bar-height\)", head), "the table head does not stand under the filter bar"
    assert "--sysmon-bar-height" not in rules.get(".sysmon-events-table thead th", ""), "LitterBox's head moved too"

    def layer(body):
        return int(re.search(r"z-index:\s*(\d+)", body).group(1))
    assert layer(bar) > layer(head), "the table head passes over the filter bar"
    assert "--sysmon-bar-height" in _root_values()
    cyberpunk_bar = theme.get('[data-theme="cyberpunk"] .sysmon-filters', "")
    for name, palette, value in (("Classic", _resolve(_root_values()), _background(bar)),
                                 ("Cyberpunk", _cyberpunk_palette(), _background(cyberpunk_bar) or _background(bar))):
        colour = re.sub(r"var\(\s*(--[\w-]+)\s*\)", lambda m: palette[m.group(1)], value or "")
        assert re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", colour), f"{name}: the rows show through the bar ({value})"
    for selector, body in theme.items():
        if re.search(r"\.sysmon-filters$|#tab-sysmon$|#sysmon-table$", selector):
            assert not re.search(r"(?:^|;)\s*(?:position|top|overflow(?:-[xy])?)\s*:", body), selector

    r = _run_node(["initSysmonTab", "_followBarHeight"], r"""
        const resizers = [], frames = [];
        let redraws = 0;
        globalThis.ResizeObserver = class {
            constructor(callback) { this.callback = callback; resizers.push(this); }
            observe(el, options) { (this.els = this.els || []).push([el, options]); }
        };
        globalThis.requestAnimationFrame = fn => frames.push(fn);
        globalThis.redrawSysmonChartsOnResize = () => redraws++;
        document.body.innerHTML = MARKUP;
        const bar = document.querySelector('#tab-sysmon .sysmon-filters'), table = document.getElementById('sysmon-table');
        table.style.setProperty = (name, value) => { table.style[name] = value; };
        bar.rect = { top: 0, height: 45.5 };
        initSysmonTab();
        const r = { observed: resizers.map(o => o.els.map(([el, options]) => [el.id || el.className, options || null])) };
        resizers[0].callback([]); r.first = table.style['--sysmon-bar-height'];
        bar.rect = { top: 0, height: 79 };
        resizers[0].callback([]); r.chips = table.style['--sysmon-bar-height'];
        resizers[1].callback([]); r.resized = [redraws, frames.length];
        frames.splice(0).forEach(fn => fn()); r.drawn = redraws;
        document.body.innerHTML = '';
        try { initSysmonTab(); r.noTab = 'ok'; } catch (e) { r.noTab = e.message; }
        document.body.innerHTML = MARKUP;
        delete globalThis.ResizeObserver;
        try { initSysmonTab(); r.noObserver = 'ok'; } catch (e) { r.noObserver = e.message; }
        console.log(JSON.stringify(r));
    """.replace("MARKUP", json.dumps(_tab_markup("sysmon"))), SORT_DOM)
    assert r["observed"] == [[["sysmon-filters", {"box": "border-box"}]], [["sysmon-charts", None], ["sysmon-time-plot", None]]], \
        r["observed"]
    assert (r["first"], r["chips"]) == ("45.5px", "79px")
    assert r["resized"] == [0, 1] and r["drawn"] == 1, "the charts are drawn again inside the observer, or not at all"
    assert r["noTab"] == "ok" and r["noObserver"] == "ok"
    js = _strip_js_comments(_read(APP_JS))
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    assert re.search(r"^\s*initSysmonTab\(\);", js[start:js.index("\n});", start)], re.M), "not set up at start-up"

    # The place in the list: the tab 56 px below the top of the window, its head and charts 300 px, then the
    # filter bar (50 px; it stands at the top of the tab once they scrolled away), then the table
    script = _sysmon_script(r"""
        (async () => {
            const tab = $('tab-sysmon'), bar = document.querySelector('#tab-sysmon .sysmon-filters'), table = $('sysmon-table');
            tab.getBoundingClientRect = () => ({ top: 56, width: 0 });
            bar.getBoundingClientRect = () => ({ top: 56 + Math.max(0, 300 - tab.scrollTop), height: 50, width: 0 });
            table.getBoundingClientRect = () => ({ top: 56 + 350 - tab.scrollTop, width: 0 });
            globalThis.fetch = async url => ({ ok: true, status: 200,
                json: async () => (String(url).startsWith('/api/sysmon/stats') ? { online: true, stats: [] } : [...events]) });
            sysmonEvents = events; renderSysmonTable();
            const r = {};
            tab.scrollTop = 1200; renderSysmonTable(); r.same = tab.scrollTop;
            await refreshSysmon(); r.refreshed = tab.scrollTop;
            $('sysmon-search').value = 'python'; filterSysmonLocal(); r.search = tab.scrollTop;
            tab.scrollTop = 1200;
            click($('sysmon-time-chart').querySelectorAll('.chart-bin').find(g => Number(g.getAttribute('data-total')) > 0).querySelector('.chart-hit'));
            r.bar = tab.scrollTop;
            tab.scrollTop = 100;
            click($('sysmon-active-filters').querySelector('.alerts-filter-chip'));
            r.above = tab.scrollTop;
            console.log(JSON.stringify(r));
        })();
    """)
    r = _run_node(SYSMON_TAB_FUNCTIONS, script, _sysmon_js())
    assert r == {"same": 1200, "refreshed": 1200, "search": 300, "bar": 300, "above": 100}, \
        f"{r}: the same filters do not keep the place, or other ones do not start at the top of the list"


def _lab(colour):
    """A colour #rgb / #rrggbb in CIE L*a*b* (D65): distances there are about
    as far apart as the eye sees the colours."""
    def linear(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (linear(c) for c in _hex_rgb(colour))
    xyz = ((0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047, 0.2126 * r + 0.7152 * g + 0.0722 * b,
           (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883)
    fx, fy, fz = (t ** (1 / 3) if t > (6 / 29) ** 3 else t / (3 * (6 / 29) ** 2) + 4 / 29 for t in xyz)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def _lch(colour):
    """A colour #rgb / #rrggbb in CIE LCh: lightness, chroma, hue in degrees."""
    lightness, a, b = _lab(colour)
    return lightness, math.hypot(a, b), math.degrees(math.atan2(b, a)) % 360


def _de2000(colour1, colour2):
    """The CIEDE2000 difference of two colours #rgb / #rrggbb (Sharma, Wu and
    Dalal's formulae): about 1 where the eye just tells them apart."""
    (l1, a1, b1), (l2, a2, b2) = _lab(colour1), _lab(colour2)
    mean = (math.hypot(a1, b1) + math.hypot(a2, b2)) / 2
    g = 0.5 * (1 - math.sqrt(mean ** 7 / (mean ** 7 + 25 ** 7)))
    a1, a2 = a1 * (1 + g), a2 * (1 + g)
    c1, c2 = math.hypot(a1, b1), math.hypot(a2, b2)
    h1, h2 = math.degrees(math.atan2(b1, a1)) % 360, math.degrees(math.atan2(b2, a2)) % 360
    dh = 0 if c1 * c2 == 0 else h2 - h1 if abs(h2 - h1) <= 180 else h2 - h1 - 360 if h2 > h1 else h2 - h1 + 360
    dl, dc, dhh = l2 - l1, c2 - c1, 2 * math.sqrt(c1 * c2) * math.sin(math.radians(dh / 2))
    lm, cm = (l1 + l2) / 2, (c1 + c2) / 2
    hm = (h1 + h2 if c1 * c2 == 0 else (h1 + h2) / 2 if abs(h1 - h2) <= 180
          else (h1 + h2 + 360) / 2 if h1 + h2 < 360 else (h1 + h2 - 360) / 2)
    t = (1 - 0.17 * math.cos(math.radians(hm - 30)) + 0.24 * math.cos(math.radians(2 * hm))
         + 0.32 * math.cos(math.radians(3 * hm + 6)) - 0.20 * math.cos(math.radians(4 * hm - 63)))
    sl = 1 + 0.015 * (lm - 50) ** 2 / math.sqrt(20 + (lm - 50) ** 2)
    sc, sh = 1 + 0.045 * cm, 1 + 0.015 * cm * t
    rt = -2 * math.sqrt(cm ** 7 / (cm ** 7 + 25 ** 7)) * math.sin(math.radians(60 * math.exp(-((hm - 275) / 25) ** 2)))
    return math.sqrt((dl / sl) ** 2 + (dc / sc) ** 2 + (dhh / sh) ** 2 + rt * (dc / sc) * (dhh / sh))


def _hue_gap(h1, h2):
    gap = abs(h1 - h2) % 360
    return min(gap, 360 - gap)


@needs_node
def test_sysmon_other_type_colours_keep_off_the_hues_of_the_known_types():
    """The colours other event types get by their names (Event_23, ...) are
    hues no known type has, not lighter or darker steps of one: in both
    themes each lies at least 20° of hue (CIE LCh) from every type colour
    with a hue (a chroma of 15 or more; ImageLoad's slate grey has none) and
    at least ΔE2000 10 from every type colour and from each other.
    PipeConnected keeps off the hues of the other types as well (it was
    nearly the amber of ProcessAccess)."""
    assert abs(_de2000("#ff0000", "#ff0000")) < 1e-9 and 40 < _de2000("#ff0000", "#00ff00") < 100
    r = _run_node([], "console.log(JSON.stringify({ fixed: SYSMON_TYPE_COLORS, other: SYSMON_OTHER_COLORS }));",
                  "\n".join(_const_source(c) for c in ("SYSMON_TYPE_COLORS", "SYSMON_OTHER_COLORS")))
    assert len(r["other"]) >= 4 and len(set(r["other"])) == len(r["other"]), r["other"]
    problems = []
    for theme, palette in (("Classic", _resolve(_root_values())), ("Cyberpunk", _cyberpunk_palette())):
        def hex_of(colour):
            m = re.fullmatch(r"var\((--[\w-]+)\)", colour)
            assert m and m.group(1) in palette, f"{colour} is no theme variable"
            return palette[m.group(1)]
        fixed = {name: hex_of(colour) for name, colour in r["fixed"].items()}
        other = {f"{colour} (other #{i})": hex_of(colour) for i, colour in enumerate(r["other"])}
        for name, colour in {**other, "pipeconnected": fixed["pipeconnected"]}.items():
            for known, value in fixed.items():
                if known == name:
                    continue
                _, chroma, hue = _lch(value)
                if chroma >= 15 and _hue_gap(_lch(colour)[2], hue) < 20:
                    problems.append(f"{theme}: {name} is {_hue_gap(_lch(colour)[2], hue):.1f}\u00b0 from the hue of {known}")
                if _de2000(colour, value) < 10:
                    problems.append(f"{theme}: {name} looks like {known} (\u0394E2000 {_de2000(colour, value):.1f})")
        names = sorted(other)
        problems += [f"{theme}: {a} looks like {b} (\u0394E2000 {_de2000(other[a], other[b]):.1f})"
                     for i, a in enumerate(names) for b in names[i + 1:] if _de2000(other[a], other[b]) < 10]
    assert not problems, "\n".join(problems)


@needs_node
def test_the_sysmon_type_colours_keep_apart_from_each_other():
    """The colours of the known event types are told apart in both themes:
    every two at least ΔE2000 10 apart, and two of a clear hue (a chroma of
    30 or more) at least 20° of hue apart, so none is a lighter or darker
    step of another (ProcessTerminate was a darker step of CreateRemoteThread's
    red; a process that ends is no alarm). A grey the theme tints
    (Cyberpunk's are lavender: ImageLoad's has a chroma of 20) differs from a
    colour of its hue by its chroma, which ΔE2000 measures. CreateRemoteThread
    stays red, the alarm it is."""
    r = _run_node([], "console.log(JSON.stringify(SYSMON_TYPE_COLORS));", _const_source("SYSMON_TYPE_COLORS"))
    problems = []
    for theme, palette in (("Classic", _resolve(_root_values())), ("Cyberpunk", _cyberpunk_palette())):
        hexes = {name: palette[re.fullmatch(r"var\((--[\w-]+)\)", colour).group(1)] for name, colour in r.items()}
        names = sorted(hexes)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                (_, chroma_a, hue_a), (_, chroma_b, hue_b) = _lch(hexes[a]), _lch(hexes[b])
                if _de2000(hexes[a], hexes[b]) < 10:
                    problems.append(f"{theme}: {a} looks like {b} (\u0394E2000 {_de2000(hexes[a], hexes[b]):.1f})")
                if min(chroma_a, chroma_b) >= 30 and _hue_gap(hue_a, hue_b) < 20:
                    problems.append(f"{theme}: {a} and {b} share a hue ({_hue_gap(hue_a, hue_b):.1f}\u00b0 apart)")
        _, chroma, hue = _lch(hexes["createremotethread"])
        if chroma < 30 or _hue_gap(hue, _lch(palette["--severity-critical"])[2]) >= 20:
            problems.append(f"{theme}: CreateRemoteThread is no longer red")
    assert len(r) >= 11 and not problems, "\n".join(problems)


# --- SCORE HISTORY of the ThreatScan tab -------------------------------------------

# The scan history (list and chart) with the parts it shares with the other charts
SCORE_HISTORY_FUNCTIONS = list(dict.fromkeys([
    "renderUnifiedHistory", "_histStatus", "_histTime", "_histScoreKind", "_histPercent", "renderHistoryDetail",
    "renderRawToggle", "formatSize", "toggleHistoryDetail", "loadScanHistory", "renderScoreHistory", "scoreHistoryScans",
    "_scanScore", "scoreHistoryGroup", "_scanVerdict", "_drawScoreHistory", "_scoreHistoryTitle", "_scoreHistoryLegend",
    "_scoreHistoryTableHtml", "_scoreHistoryWidth", "redrawScoreHistoryOnResize", "initScoreHistory",
    "onScoreHistoryClick", "revealHistoryEntry", "revealElement", "escapeHtml", "jsArg", "isTableView",
    "viewToggleHtml", "cardViewAttrs", "toggleCardView"] + CHART_FUNCTIONS))
SCORE_HISTORY_CONSTS = ["SCAN_HISTORY_CONTAINERS", "EVIDENCE_SCORE_TOOLS", "SCORE_HISTORY_THRESHOLDS", "SCORE_HISTORY_GROUPS",
                        "SCORE_HISTORY_MAX", "cardViewState"] + CHART_CONSTS


def _score_js(zone="UTC"):
    return (SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone)
            + "\n".join(_const_source(c) for c in SCORE_HISTORY_CONSTS) + "\nlet _scoreHistoryDrawn = null;\n")


# The ThreatScan tab of index.html in the test DOM (clicks run the inline
# handlers), and three scans as /api/scan/history lists them, the newest
# first: a Process Dump without a score, an Exit Capture of a file with a
# hostile name, an Aether scan (times without an offset, as the server writes
# them; as there, a suspicious scan is detected as well)
SCORE_HISTORY_FIXTURE = r"""
    document.body.innerHTML = MARKUP;
    const $ = id => document.getElementById(id);
    const scan = (id, timestamp, tool, filename, verdict, score) => ({ id, timestamp, tool, filename, sha256: '',
        size: null, status: 'ok', verdict, score, detected: verdict === 'detected' || verdict === 'suspicious',
        clean: verdict === 'clean', result: {} });
    const history = [
        scan('c3', '2026-11-05T11:37:25.629792', 'Process Dump', 'PID 3376', 'dumped', null),
        scan('c2', '2026-11-05T11:36:39.219904', 'Exit Capture', EVIL, 'detected', 6.54),
        scan('c1', '2026-11-05T11:33:36.492076', 'Aether', 'PID 9664', 'suspicious', 2.24),
    ];
"""

# What the card shows: the points, the axis, the threshold lines, the texts
# of the SVG, its hint, the legend, the table view, and the entries of the list
SCORE_HISTORY_LOOK = r"""
    const paint = el => (el ? el.getAttribute('style') || '' : '').replace(/^(?:fill|background):/, '');
    const look = () => {
        const plot = $('score-history-plot'), svg = plot.querySelector('svg');
        const table = $('score-history-table').querySelector('table'), rows = table ? table.tBodies[0].rows : [];
        return {
            points: plot.querySelectorAll('circle.chart-point').map(c => ({ key: c.getAttribute('data-key'),
                cx: Number(c.getAttribute('cx')), cy: Number(c.getAttribute('cy')), color: paint(c),
                title: c.querySelector('title').textContent })),
            axis: svg ? Number(svg.querySelector('line.chart-axis').getAttribute('y1')) : null,
            thresholds: svg ? svg.querySelectorAll('line.chart-threshold').map(l => [Number(l.getAttribute('y1')),
                l.getAttribute('stroke-dasharray')]) : [],
            texts: svg ? svg.querySelectorAll('text').map(t => t.textContent) : [],
            width: svg ? Number(svg.getAttribute('width')) : null,
            empty: (plot.querySelector('.chart-empty') || { textContent: null }).textContent,
            low: $('score-history-area').classList.contains('is-empty'),
            legend: $('score-history-legend').querySelectorAll('.chart-legend-row').map(row => [row.getAttribute('data-key'),
                row.querySelector('.chart-legend-name').textContent, Number(row.querySelector('.chart-legend-count').textContent),
                paint(row.querySelector('.chart-legend-swatch'))]),
            table: table && {
                id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
                head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
                rows: rows.filter(row => !row.hasAttribute('data-sort-skip')).map(row => row.cells.map(c =>
                    [c.textContent.trim(), c.getAttribute('data-sort-value'), c.getAttribute('title')])),
                notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()),
            },
            entries: $('threatscan-history-list').querySelectorAll('.scan-history-entry').map(e =>
                [e.getAttribute('data-history-index'), e.querySelector('.scan-history-tool').textContent]),
            markup: ['img', 'script'].map(t => $('tab-threatscan').querySelectorAll(t).length),
        };
    };
"""


def _score_script(script):
    return ((SCORE_HISTORY_FIXTURE + SCORE_HISTORY_LOOK + script)
            .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE))
            .replace("MARKUP", json.dumps(_tab_markup("threatscan"))))


LOW, MEDIUM, CRITICAL, MUTED = "var(--severity-low)", "var(--severity-medium)", "var(--severity-critical)", "var(--text-muted)"


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "Asia/Kolkata"])
def test_score_history_points_and_no_score_lane(zone):
    """SCORE HISTORY above the list of the scan history: a point per scan, the
    oldest on the left, at the height of its score; a scan without one
    (Process Dump) in the lane "no score" under the axis. Dashed lines mark
    SUSPICIOUS 2 and MALICIOUS 6; a point has the colour of its verdict, its
    tooltip names tool, file, score, verdict and time, and the legend counts
    the verdicts. A file name from the sample stays text."""
    r = _run_node(SCORE_HISTORY_FUNCTIONS, _score_script(r"""
        renderUnifiedHistory(history);
        console.log(JSON.stringify(look()));
    """), _score_js(zone))
    points, axis = r["points"], r["axis"]
    assert [p["key"] for p in points] == ["2", "1", "0"], "the points are not in the order the scans ran"
    assert [p["cx"] for p in points] == sorted({p["cx"] for p in points}), "the oldest scan is not on the left"
    aether, exit_capture, dump = points
    assert dump["cy"] > axis, "a scan without a score is not in the lane under the axis"
    (y6, dash6), (y2, dash2) = sorted(r["thresholds"])          # the line of 6 lies higher (a smaller y)
    assert dash6 and dash2, "a threshold is not dashed"
    assert exit_capture["cy"] < y6 < aether["cy"] < y2 < axis, "the points are not placed by their scores"
    assert abs((axis - aether["cy"]) / (axis - y2) - 2.24 / 2) < 0.01 and abs((axis - y6) / (axis - y2) - 3) < 0.01
    assert {"SUSPICIOUS 2", "MALICIOUS 6", "no score"} <= set(r["texts"])
    assert [p["color"] for p in points] == [MEDIUM, CRITICAL, MUTED]
    assert [p["title"] for p in points] == [
        "Aether \u00b7 PID 9664\nscore 2.24 \u00b7 suspicious\n05/11/2026, 11:33:36",
        f"Exit Capture \u00b7 {EVIL}\nscore 6.54 \u00b7 detected\n05/11/2026, 11:36:39",
        "Process Dump \u00b7 PID 3376\nno score \u00b7 dumped\n05/11/2026, 11:37:25"]
    assert r["markup"] == [0, 0], "a file name from the sample became markup"
    assert r["legend"] == [["suspicious", "suspicious", 1, MEDIUM], ["detected", "detected / malicious", 1, CRITICAL],
                           ["other", "no verdict", 1, MUTED]]
    # The list, newest first as before: each entry knows the point that leads to it
    assert r["entries"] == [["0", "Process Dump"], ["1", "Exit Capture"], ["2", "Aether"]]


@needs_node
def test_score_history_colours_and_scale():
    """The colour is the verdict's in any case: clean and benign in the low
    colour, suspicious in the medium one, detected and malicious in the
    critical one, any other (unknown, dumped, analyzed, none) muted, as the
    legend counts them. Only the evidence score of a memory scan (Aether,
    Exit Capture) stands on the axis, a number written as text too, anything
    else is none; a negative one sits on the axis. EMBER2024's probability
    and another tool's score lie in the lane: the tooltip and the table name
    the probability, which sorts after the evidence scores. The scale reaches
    a tenth above the highest score or MALICIOUS 6, and no further than 10: a
    score far above sits at the top edge instead of pressing the others under
    the lines. Without any score every scan is in the lane, and the lines
    still show."""
    r = _run_node(SCORE_HISTORY_FUNCTIONS, _score_script(r"""
        const r = {};
        const verdicts = ['clean', 'Benign', 'SUSPICIOUS', 'detected', 'Malicious', 'unknown', 'dumped', 'analyzed', '', null, ' clean '];
        renderUnifiedHistory(verdicts.map((verdict, i) => scan('v' + i, '2026-11-05T10:00:00', 'Aether', 'PID ' + i, verdict, 1)));
        r.verdicts = look();
        renderUnifiedHistory([scan('e1', '2026-10-20T12:59:09.836671', 'EMBER2024', 'shortlived.exe', 'benign', 0.338656),
                              scan('e2', '2026-10-20T12:30:00', 'EMBER2024', 'evil.exe', 'malicious', 0.97),
                              scan('k1', '2026-10-20T12:10:00', 'capa', 'shortlived.exe', 'analyzed', 5),
                              scan('s1', '2026-10-20T12:00:00', 'Aether', 'PID 1', 'suspicious', '2.5'),
                              scan('s2', '2026-10-20T11:00:00', 'Aether', 'PID 2', 'unknown', 'n/a'),
                              scan('s3', '2026-10-20T10:00:00', 'exit capture', 'PID 3', 'clean', -1), ...history]);
        r.mixed = look();
        renderUnifiedHistory([scan('big', '2026-11-06T09:00:00', 'Exit Capture', 'PID 1', 'detected', 40), ...history]);
        r.outlier = look();
        renderUnifiedHistory(history.map(entry => ({ ...entry, score: null })));
        r.unscored = look();
        console.log(JSON.stringify(r));
    """), _score_js())
    colours = {p["key"]: p["color"] for p in r["verdicts"]["points"]}
    assert colours == {"0": LOW, "1": LOW, "2": MEDIUM, "3": CRITICAL, "4": CRITICAL, "5": MUTED, "6": MUTED, "7": MUTED,
                       "8": MUTED, "9": MUTED, "10": LOW}, colours
    assert r["verdicts"]["legend"] == [["clean", "clean / benign", 3, LOW], ["suspicious", "suspicious", 1, MEDIUM],
                                       ["detected", "detected / malicious", 2, CRITICAL], ["other", "no verdict", 5, MUTED]]
    mixed = r["mixed"]
    by_tool = {p["title"].split("\n")[0]: p for p in mixed["points"]}
    axis, y2 = mixed["axis"], max(y for y, _ in mixed["thresholds"])
    height = lambda p: (axis - p["cy"]) / (axis - y2) * 2      # noqa: E731 -- the score a point is drawn at
    ember, evil = by_tool["EMBER2024 \u00b7 shortlived.exe"], by_tool["EMBER2024 \u00b7 evil.exe"]
    assert ember["cy"] > axis and evil["cy"] > axis, "EMBER2024's probability is drawn as an evidence score"
    assert ember["color"] == LOW and evil["color"] == CRITICAL
    assert ember["title"] == "EMBER2024 \u00b7 shortlived.exe\nprobability 33.9% \u00b7 benign\n20/10/2026, 12:59:09"
    assert evil["title"].split("\n")[1] == "probability 97.0% \u00b7 malicious"
    capa = by_tool["capa \u00b7 shortlived.exe"]
    assert capa["cy"] > axis and capa["title"].split("\n")[1] == "no score \u00b7 analyzed", \
        "a score of a tool that is no memory scan is drawn as an evidence score"
    assert abs(height(by_tool["Aether \u00b7 PID 1"]) - 2.5) < 0.01, "a score written as text is no score"
    assert by_tool["Aether \u00b7 PID 2"]["cy"] > axis and by_tool["Aether \u00b7 PID 2"]["title"].split("\n")[1] == "no score \u00b7 unknown"
    assert abs(by_tool["exit capture \u00b7 PID 3"]["cy"] - axis) < 0.01, "a negative score (of a tool in lower case) is not on the axis"
    # The table: an evidence score sorts by its value; EMBER2024's probability and none come after them (no sort value)
    cells = {(row[1][0], row[2][0]): row[3][:2] for row in mixed["table"]["rows"]}
    assert cells[("EMBER2024", "shortlived.exe")] == ["33.9%", ""] and cells[("EMBER2024", "evil.exe")] == ["97.0%", ""]
    assert cells[("capa", "shortlived.exe")] == ["\u2014", ""] and cells[("Aether", "PID 1")] == ["2.5", "2.5"]
    assert cells[("Exit Capture", EVIL)] == ["6.54", "6.54"]
    # A tenth above the highest score (6.54); a score of 40 where 10 would be, the lines where they were
    outlier = r["outlier"]
    big = next(p for p in outlier["points"] if p["title"].startswith("Exit Capture \u00b7 PID 1"))
    y6 = min(y for y, _ in outlier["thresholds"])
    assert abs((outlier["axis"] - big["cy"]) / (outlier["axis"] - y6) - 10 / 6) < 0.01, "a score above 10 squeezes the scale"
    assert big["title"].split("\n")[1] == "score 40 \u00b7 detected"
    top = outlier["axis"] - big["cy"]                           # the height of the plot, where 10 is
    exit_capture = next(p for p in r["mixed"]["points"] if p["title"].startswith("Exit Capture \u00b7 <"))
    assert abs((r["mixed"]["axis"] - exit_capture["cy"]) / top - 1 / 1.1) < 0.01, "the scale does not end a tenth above"
    unscored = r["unscored"]
    assert unscored["points"] and all(p["cy"] > unscored["axis"] for p in unscored["points"])
    assert len(unscored["thresholds"]) == 2 and "no score" in unscored["texts"]


@needs_node
def test_the_scan_history_names_a_suspicious_memory_scan_as_the_chart_does():
    """The list agrees with SCORE HISTORY: a memory scan the server found
    suspicious (it sets detected for it as well) reads SUSPICIOUS with its
    score, in the chart's colour of suspicious, not DETECTED in red. Every
    other label stays as it was, EMBER2024 with its probability."""
    r = _run_node(SCORE_HISTORY_FUNCTIONS, _score_script(r"""
        const entry = (tool, verdict, score, more) => ({ tool, verdict, score, status: 'ok', ...more });
        const cases = [
            entry('Aether', 'suspicious', 2.24, { detected: true, clean: false }),
            entry('Exit Capture', 'Suspicious', 2.24, { detected: true, clean: false }),
            entry('Exit Capture', 'detected', 6.54, { detected: true, clean: false }),
            entry('Aether', 'clean', 0.24, { detected: false, clean: true }),
            entry('Aether', 'unknown', 0, {}),
            entry('EMBER2024', 'malicious', 0.97, { detected: true, clean: false }),
            entry('EMBER2024', 'benign', 0.338656, { detected: false, clean: true }),
            entry('ThreatCheck', 'detected', null, { detected: true, clean: false }),
            entry('DefenderCheck', 'clean', null, { detected: false, clean: true }),
            entry('Process Dump', 'dumped', null, {}),
            entry('Process Dump', 'detected', null, { detected: true, clean: false }),
            entry('capa', 'analyzed', null, {}),
            entry('Aether', 'suspicious', 2.24, { detected: true, status: 'timeout' }),
            entry('Aether', 'unknown', null, { status: 'error' }),
        ];
        renderUnifiedHistory(history);
        console.log(JSON.stringify({
            labels: cases.map(e => [_histStatus(e).cls, _histStatus(e).text]),
            list: $('threatscan-history-list').querySelectorAll('.scan-history-entry').map(e =>
                [e.getAttribute('class'), e.querySelector('.scan-history-status').textContent]),
            points: look().points.map(p => [p.key, p.color]),
        }));
    """), _score_js())
    assert r["labels"] == [
        ["history-suspicious", "SUSPICIOUS score 2.24"], ["history-suspicious", "SUSPICIOUS score 2.24"],
        ["history-detected", "DETECTED score 6.54"], ["history-clean", "CLEAN score 0.24"], ["history-unknown", "UNKNOWN"],
        ["history-detected", "MALICIOUS 97.0%"], ["history-clean", "BENIGN 33.9%"], ["history-detected", "DETECTED"],
        ["history-clean", "CLEAN"], ["history-unknown", "DUMPED"], ["history-detected", "DETECTED"],
        ["history-unknown", "ANALYZED"], ["history-unknown", "TIMEOUT"], ["history-unknown", "ERROR"]], r["labels"]
    assert r["list"] == [["scan-history-entry history-unknown", "DUMPED"],
                         ["scan-history-entry history-detected", "DETECTED score 6.54"],
                         ["scan-history-entry history-suspicious", "SUSPICIOUS score 2.24"]]
    assert dict(r["points"]) == {"0": MUTED, "1": CRITICAL, "2": MEDIUM}
    rules = _rules(STYLE_CSS)
    assert re.search(r"border-left-color:\s*var\(--severity-medium\)", rules.get(".scan-history-entry.history-suspicious", ""))
    assert re.search(r"(?:^|;)\s*color:\s*var\(--severity-medium\)", rules.get(".history-suspicious .scan-history-status", "")), \
        "the label of a suspicious scan is not in the chart's colour of suspicious"


@needs_node
def test_score_history_click_shows_the_scan_in_the_list():
    """A click on a point (or on its tooltip) opens its entry of the list, as
    a click on the entry does (an open one stays open, the others as they
    are), scrolls it into the middle of the view and marks it for 1.5 s, a
    point in the lane as well; a click beside the points does nothing. After
    a new scan each point leads to its entry in the new list."""
    r = _run_node(SCORE_HISTORY_FUNCTIONS, _score_script(r"""
        const scrolled = [], timers = [];
        Element.prototype.scrollIntoView = function (options) { scrolled.push([this.getAttribute('data-history-index'), options]); };
        globalThis.setTimeout = (fn, ms) => { timers.push([fn, ms]); return timers.length; };
        globalThis.clearTimeout = () => {};
        // As the browser reads it: each entry's detail closed by its inline style
        const render = list => {
            renderUnifiedHistory(list);
            $('threatscan-history-list').querySelectorAll('.scan-history-detail').forEach(panel => {
                panel.style.display = /display:\s*none/.test(panel.getAttribute('style') || '') ? 'none' : '';
            });
        };
        render(history);
        const points = () => $('score-history-plot').querySelectorAll('circle.chart-point');
        const point = key => points().find(c => c.getAttribute('data-key') === key);
        const entries = () => $('threatscan-history-list').querySelectorAll('.scan-history-entry');
        const marked = () => entries().filter(e => e.classList.contains('reveal-flash')).map(e => e.getAttribute('data-history-index'));
        const open = () => entries().filter(e => e.nextElementSibling.style.display === 'block')
            .map(e => [e.getAttribute('data-history-index'), e.querySelector('.scan-history-more').textContent]);
        const r = {};
        click(point('1'));
        r.first = { scrolled: scrolled.splice(0), marked: marked(), timers: timers.map(t => t[1]), open: open() };
        timers.splice(0).forEach(([fn]) => fn());
        r.later = marked();
        click(point('1'));
        r.again = { scrolled: scrolled.splice(0), open: open() };
        timers.splice(0).forEach(([fn]) => fn());
        click(point('0').querySelector('title'));
        r.lane = { scrolled: scrolled.splice(0), marked: marked(), open: open() };
        timers.splice(0).forEach(([fn]) => fn());
        click($('score-history-plot').querySelector('line.chart-axis'));
        click($('score-history-plot').querySelector('svg'));
        r.beside = { scrolled: scrolled.splice(0), marked: marked(), open: open() };
        // A new scan comes first in the list: the Exit Capture is its third entry now
        render([scan('c4', '2026-11-05T11:40:00', 'Aether', 'PID 1', 'clean', 0.24), ...history]);
        const exit = points().find(c => c.querySelector('title').textContent.startsWith('Exit Capture'));
        click(exit);
        r.after = { key: exit.getAttribute('data-key'), scrolled: scrolled.splice(0), marked: marked(), open: open(),
                    tool: entries()[2].querySelector('.scan-history-tool').textContent };
        console.log(JSON.stringify(r));
    """), _score_js())
    centre, down = {"behavior": "smooth", "block": "center"}, "\u25be"
    assert r["first"] == {"scrolled": [["1", centre]], "marked": ["1"], "timers": [1500], "open": [["1", down]]}, \
        "a point did not open its scan's entry"
    assert r["later"] == [], "the mark stays"
    assert r["again"] == {"scrolled": [["1", centre]], "open": [["1", down]]}, "a second click closed the entry"
    assert r["lane"] == {"scrolled": [["0", centre]], "marked": ["0"], "open": [["0", down], ["1", down]]}
    assert r["beside"] == {"scrolled": [], "marked": [], "open": [["0", down], ["1", down]]}, \
        "a click beside the points scrolled the list"
    assert r["after"] == {"key": "2", "scrolled": [["2", centre]], "marked": ["2"], "open": [["2", down]],
                          "tool": "Exit Capture"}


@needs_node
def test_score_history_card_has_info_and_table():
    """The card sits right above the list of the scan history, with its (i)
    and its CHART / TABLE switch; the table view lists every scan in the
    order of the chart (time, tool, file, score or "—", verdict), sortable,
    with the numbers of the tooltips. Without scans the card says "No scans
    yet", without a history it could load "Scan history not available" (a
    reload that fails keeps what it shows). The chart is drawn for the width
    of its plot, and again when that changes, not while hidden; the table
    stays as it is then."""
    tab = _Elements(_read(INDEX_HTML)).by_id("tab-threatscan")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def by_id(node, element_id):
        found = find(node, lambda e: e["attrs"].get("id") == element_id)
        assert len(found) == 1, element_id
        return found[0]

    def text(node):
        return node.get("text", "") + "".join(text(c) for c in node["children"])

    section = find(tab, lambda e: e["attrs"].get("class") == "scanner-history")[0]
    assert [c["attrs"].get("id") or c["attrs"].get("class") for c in section["children"]] == \
        ["scanner-history-header", "score-history-card", "threatscan-history-list"], "the card is not right above the list"
    card = by_id(section, "score-history-card")
    assert "chart-card" in card["attrs"]["class"].split()
    heading = find(card, lambda e: "chart-card-title" in e["attrs"].get("class", "").split())
    assert len(heading) == 1 and text(heading[0]).strip() == "SCORE HISTORY" and heading[0]["attrs"].get("data-info", "").strip()
    assert "\u201cno score\u201d" in heading[0]["attrs"]["data-info"] and "Exit Capture" in heading[0]["attrs"]["data-info"], \
        "the (i) does not say which scans stand on the axis and which lie in the lane \u201cno score\u201d"
    assert "view-toggle-slot" in by_id(card, "score-history-toggle")["attrs"]["class"].split()
    chart, table = by_id(card, "score-history-chart"), by_id(card, "score-history-table")
    assert (chart["attrs"].get("data-view-of"), chart["attrs"].get("data-view"), "hidden" in chart["attrs"]) == \
        ("score-history", "chart", False)
    assert (table["attrs"].get("data-view-of"), table["attrs"].get("data-view"), "hidden" in table["attrs"]) == \
        ("score-history", "table", True)
    plot = by_id(chart, "score-history-plot")
    assert "chart-clickable" in plot["attrs"]["class"].split() and plot["attrs"].get("onclick") == "onScoreHistoryClick(event)"
    assert by_id(chart, "score-history-legend") is not None
    source = "\n".join(_strip_js_comments(_function_source(name)) for name in SCORE_HISTORY_FUNCTIONS
                       if "core" in name or name in ("_scanVerdict", "_histTime", "revealHistoryEntry", "revealElement"))
    source += "\n".join(_const_source(c) for c in ("SCORE_HISTORY_THRESHOLDS", "SCORE_HISTORY_GROUPS"))
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"

    r = _run_node(SCORE_HISTORY_FUNCTIONS, _score_script(r"""
        (async () => {
            $('score-history-plot').rect = { width: 700 };
            renderUnifiedHistory(history);
            const toggle = () => $('score-history-toggle').querySelector('.view-toggle');
            const r = { view: look(), times: history.map(entry => String(Date.parse(entry.timestamp))).reverse(),
                        toggle: [toggle().getAttribute('data-view-toggle'), toggle().textContent] };
            const button = toggle();
            renderUnifiedHistory(history);
            r.toggleKept = toggle() === button;
            // A new width: drawn again, the table left as it is; the same width or a hidden plot (0): nothing
            const tableNode = $('score-history-table').querySelector('table');
            $('score-history-plot').rect = { width: 480 };
            redrawScoreHistoryOnResize();
            r.resized = [look().width, $('score-history-table').querySelector('table') === tableNode];
            const svg = $('score-history-plot').querySelector('svg');
            redrawScoreHistoryOnResize();
            $('score-history-plot').rect = { width: 0 };
            redrawScoreHistoryOnResize();
            r.kept = $('score-history-plot').querySelector('svg') === svg;
            // TABLE: the table in place of the chart, kept on the next render
            click(toggle());
            renderUnifiedHistory(history);
            r.tableView = [$('score-history-chart').hidden, $('score-history-table').hidden, toggle().textContent];
            click(toggle());
            // A name with a quote stays inside its attribute
            renderUnifiedHistory([scan('q1', '2026-11-05T11:38:00', QUOTE, QUOTE, 'suspicious', 3), ...history]);
            const quoted = $('score-history-table').querySelector('table').tBodies[0].rows.find(row => row.cells[1].textContent === QUOTE);
            r.quoted = [quoted.cells[2].getAttribute('title'), Object.keys(quoted.cells[2].attrs).sort(), quoted.cells[2].textContent,
                        $('score-history-plot').querySelectorAll('circle.chart-point').map(c => c.querySelector('title').textContent)
                            .filter(t => t.includes(QUOTE))];
            // After an empty history the legend comes back beside the plot: the points get the width that leaves
            renderUnifiedHistory([]);
            const plot = $('score-history-plot'), legendBox = $('score-history-legend');
            plot.getBoundingClientRect = () => ({ width: legendBox.firstElementChild ? 468 : 700 });
            renderUnifiedHistory(history);
            r.afterEmpty = look().width;
            delete plot.getBoundingClientRect;
            renderUnifiedHistory([]);
            r.none = look();
            // A history that cannot be loaded: said while nothing was drawn; a reload that fails keeps the chart
            _scoreHistoryDrawn = null;
            $('score-history-plot').innerHTML = '';
            globalThis.fetch = async () => { throw new Error('Failed to fetch'); };
            await loadScanHistory();
            r.failed = look();
            globalThis.fetch = async () => ({ json: async () => ({ count: 3, history }) });
            await loadScanHistory();
            globalThis.fetch = async () => { throw new Error('Failed to fetch'); };
            await loadScanHistory();
            r.failedAgain = look();
            console.log(JSON.stringify(r));
        })();
    """), _score_js())
    view = r["view"]
    assert r["toggle"] == ["score-history", "TABLE"] and r["toggleKept"], "a card without its CHART / TABLE switch"
    t = view["table"]
    assert t["id"] == "score-history" and t["sortable"] and t["head"] == ["Time", "Tool", "File", "Score", "Verdict"]
    dash = "\u2014"
    assert [[cell[0] for cell in row] for row in t["rows"]] == [
        ["05/11/2026, 11:33:36", "Aether", "PID 9664", "2.24", "suspicious"],
        ["05/11/2026, 11:36:39", "Exit Capture", EVIL, "6.54", "detected"],
        ["05/11/2026, 11:37:25", "Process Dump", "PID 3376", dash, "dumped"]], "the table lists other scans than the chart"
    assert [row[0][1] for row in t["rows"]] == r["times"], "the time does not sort by its value"
    assert [row[3][1] for row in t["rows"]] == ["2.24", "6.54", ""], "a scan without a score does not sort last"
    assert t["rows"][1][2][2] == EVIL, "the file's title is cut or markup"
    assert [p["title"].split("\n")[1].split(" \u00b7 ")[0] for p in view["points"]] == \
        [f"score {row[3][0]}" if row[3][0] != dash else "no score" for row in t["rows"]], "the tooltips show other numbers"
    assert view["markup"] == [0, 0] and not view["low"]
    assert view["width"] == 700 and r["resized"] == [480, True] and r["kept"], \
        "not drawn for the width of the plot, drawn again for the same width or while hidden, or the table rewritten"
    assert r["tableView"] == [True, False, "CHART"]
    assert r["quoted"] == [QUOTE, ["class", "title"], QUOTE,
                           [f"{QUOTE} \u00b7 {QUOTE}\nno score \u00b7 suspicious\n05/11/2026, 11:38:00"]], "a quote left its attribute"
    assert r["afterEmpty"] == 468, "the points were drawn for the plot's width before the legend took its room beside it"
    none = r["none"]
    assert none["empty"] == "No scans yet" and none["points"] == [] and none["legend"] == [] and none["low"]
    assert none["table"]["rows"] == [] and none["table"]["notes"] == ["No scans yet."]
    assert r["failed"]["empty"] == "Scan history not available" and r["failed"]["table"]["notes"] == ["Scan history not available."]
    assert len(r["failedAgain"]["points"]) == 3, "a reload that failed took the chart away"

    # Drawn again in the next frame when the plot's width changes; set up at start-up
    r = _run_node(["initScoreHistory"], r"""
        const resizers = [], frames = [];
        let redraws = 0;
        globalThis.ResizeObserver = class {
            constructor(callback) { this.callback = callback; resizers.push(this); }
            observe(el, options) { (this.els = this.els || []).push([el.id, options || null]); }
        };
        globalThis.requestAnimationFrame = fn => frames.push(fn);
        globalThis.redrawScoreHistoryOnResize = () => redraws++;
        document.body.innerHTML = MARKUP;
        initScoreHistory();
        const r = { observed: resizers.map(o => o.els) };
        resizers[0].callback([]); r.inside = [redraws, frames.length];
        frames.splice(0).forEach(fn => fn()); r.drawn = redraws;
        document.body.innerHTML = '';
        try { initScoreHistory(); r.noCard = 'ok'; } catch (e) { r.noCard = e.message; }
        document.body.innerHTML = MARKUP;
        delete globalThis.ResizeObserver;
        try { initScoreHistory(); r.noObserver = 'ok'; } catch (e) { r.noObserver = e.message; }
        console.log(JSON.stringify(r));
    """.replace("MARKUP", json.dumps(_tab_markup("threatscan"))), SORT_DOM)
    assert r["observed"] == [[["score-history-plot", None]]]
    assert r["inside"] == [0, 1] and r["drawn"] == 1, "drawn inside the observer, or not at all"
    assert r["noCard"] == "ok" and r["noObserver"] == "ok"
    js = _strip_js_comments(_read(APP_JS))
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    assert re.search(r"^\s*initScoreHistory\(\);", js[start:js.index("\n});", start)], re.M), "not set up at start-up"
    # The chart and its table view over the same area, lower without scans; the mark of an entry lasts 1.5 s
    rules = _rules(STYLE_CSS)
    assert re.search(r"position:\s*relative", rules.get(".score-history-area", "")) and \
        re.search(r"(?:^|;)\s*height:", rules.get(".score-history-area", ""))
    assert re.search(r"(?:^|;)\s*height:", rules.get(".score-history-area.is-empty", "")), "an empty card is as high as a chart"
    for selector in (".score-history-view", ".score-history-table"):
        assert re.search(r"position:\s*absolute", rules.get(selector, "")), f"{selector} stretches the card"
    assert re.search(r"overflow(?:-y)?:\s*auto", rules.get(".score-history-table", ""))
    assert re.search(r"background:\s*transparent", rules.get(".score-history-table::-webkit-scrollbar-corner", ""))
    assert re.search(r"position:\s*sticky", rules.get(".score-history-table .view-table th", ""))
    assert re.search(r"min-width:\s*0", rules.get(".score-history-plot", "")), "a long legend pushes the plot out of the card"
    assert re.search(r"animation-duration:\s*1\.5s", rules.get(".scan-history-entry.reveal-flash", "")), \
        "the mark of an entry does not last as long as revealHistoryEntry keeps it"


# --- VERDICT HISTORY of the Submit tab ---------------------------------------------

# The chart above the submission history, and the parts of the list and the charts it uses
SUBMISSION_VERDICT_OWN = [
    "renderSubmissionVerdicts", "submissionVerdictItems", "_submissionVerdict", "submissionVerdictGroup",
    "_drawSubmissionVerdicts", "_submissionVerdictTitle", "_submissionVerdictLegend", "_submissionVerdictsTableHtml",
    "_submissionVerdictsWidth", "redrawSubmissionVerdictsOnResize", "initSubmissionVerdicts",
    "onSubmissionVerdictsClick", "submissionResultArgs", "noteDetonationVerdict", "_submissionTime"]
SUBMISSION_VERDICT_FUNCTIONS = list(dict.fromkeys(SUBMISSION_VERDICT_OWN + [
    "refreshSubmissions", "_scanScore", "formatSize", "sortTimeValue", "sortNumberValue", "escapeHtml", "jsArg",
    "isTableView", "viewToggleHtml", "cardViewAttrs", "toggleCardView"] + CHART_FUNCTIONS))
SUBMISSION_VERDICT_CONSTS = ["SUBMISSION_VERDICT_THRESHOLDS", "SUBMISSION_VERDICT_GROUPS", "SUBMISSION_VERDICT_MAX",
                             "_verdictHistoryAsked", "cardViewState"] + CHART_CONSTS


def _verdicts_js(zone="UTC"):
    return (SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone)
            + "\n".join(_const_source(c) for c in SUBMISSION_VERDICT_CONSTS) + "\nlet _submissionVerdictsDrawn = null;\n")


# The Submit tab of index.html in the test DOM (clicks run the inline
# handlers), with the Submit tab open, and /api/submissions as the server
# lists it, the newest first: beaconsim (MALICIOUS 4; it went to LitterBox,
# whose hash it kept), injectsim (SUSPICIOUS 2; LitterBox failed, no hash)
# and an older submission with a hostile name and no verdict kept. fetch
# serves server.list (or fails); viewDetonationResult records what it opens.
SUBMISSION_VERDICT_FIXTURE = r"""
    document.body.innerHTML = MARKUP;
    const $ = id => document.getElementById(id);
    globalThis.state = { activeTab: 'submit' };
    const sub = (id, timestamp, filename, sha256, agent_pid, verdict, more) => ({ id, timestamp, filename, sha256,
        size: 4096, target: 'agent', agent_status: 'success', agent_pid, agent_result: null, litterbox_status: null,
        litterbox_hash: null, ioc_feed: null, verdict, file_path: null, ...more });
    const submissions = [
        sub('s3', '2026-11-05T11:37:11.943234', 'beaconsim.exe', 'b'.repeat(64), 3376, { label: 'MALICIOUS', score: 4 },
            { target: 'both', litterbox_status: 'success', litterbox_hash: 'f'.repeat(64) }),
        sub('s2', '2026-11-05T11:36:31.807781', 'injectsim.exe', 'd'.repeat(64), 10392, { label: 'SUSPICIOUS', score: 2 },
            { target: 'both', litterbox_status: 'failed' }),
        sub('s1', '2026-11-05T11:33:23.858017', EVIL, 'e'.repeat(64), 9664, null),
    ];
    const server = { list: submissions, ok: true, fails: false };
    const fetched = [];
    globalThis.fetch = async url => {
        fetched.push(url);
        if (server.fails) throw new Error('Failed to fetch');
        return { ok: server.ok, json: async () => JSON.parse(JSON.stringify(server.list)) };
    };
    const opened = [];
    globalThis.viewDetonationResult = (...args) => { opened.push(args); };
    const before = ['img', 'script'].map(t => $('tab-submit').querySelectorAll(t).length);
"""

# What the card shows: the bars (each with the empty part of its slot that
# takes a click too), the axis, the threshold lines, the texts of the SVG, its
# hint, the legend, the table view, and the list of the submissions under it
SUBMISSION_VERDICT_LOOK = r"""
    const paint = el => (el ? el.getAttribute('style') || '' : '').replace(/^(?:fill|background):/, '');
    const num = (el, name) => Number(el.getAttribute(name));
    const look = () => {
        const plot = $('submission-verdicts-plot'), svg = plot.querySelector('svg');
        const table = $('submission-verdicts-table').querySelector('table'), rows = table ? table.tBodies[0].rows : [];
        return {
            bars: plot.querySelectorAll('g.chart-slot').map(g => {
                const bar = g.querySelector('rect.chart-bar'), hit = g.querySelector('rect.chart-hit');
                return { key: g.getAttribute('data-key'), x: num(bar, 'x'), y: num(bar, 'y'), height: num(bar, 'height'),
                         color: paint(bar), title: g.querySelector('title').textContent,
                         hit: [num(hit, 'x'), num(hit, 'y'), num(hit, 'width'), num(hit, 'height')] };
            }),
            axis: svg ? num(svg.querySelector('line.chart-axis'), 'y1') : null,
            thresholds: svg ? svg.querySelectorAll('line.chart-threshold').map(l => [num(l, 'y1'), l.getAttribute('stroke-dasharray')]) : [],
            texts: svg ? svg.querySelectorAll('text').map(t => t.textContent) : [],
            width: svg ? num(svg, 'width') : null,
            empty: (plot.querySelector('.chart-empty') || { textContent: null }).textContent,
            low: $('submission-verdicts-area').classList.contains('is-empty'),
            legend: $('submission-verdicts-legend').querySelectorAll('.chart-legend-row').map(row => [row.getAttribute('data-key'),
                row.querySelector('.chart-legend-name').textContent, Number(row.querySelector('.chart-legend-count').textContent),
                paint(row.querySelector('.chart-legend-swatch'))]),
            table: table && {
                id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
                head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
                rows: rows.filter(row => !row.hasAttribute('data-sort-skip')).map(row => row.cells.map(c =>
                    [c.textContent.trim(), c.getAttribute('data-sort-value'), c.getAttribute('title')])),
                notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()),
            },
            list: $('submissions-list').querySelectorAll('tbody tr').map(row => row.cells[1].textContent),
            listText: $('submissions-list').textContent.trim(),
            markup: ['img', 'script'].map(t => $('tab-submit').querySelectorAll(t).length),
        };
    };
"""


def _verdicts_script(script):
    return ((SUBMISSION_VERDICT_FIXTURE + SUBMISSION_VERDICT_LOOK + script)
            .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE))
            .replace("MARKUP", json.dumps(_tab_markup("submit"))))


DIM = "var(--text-dim)"


@needs_node
@pytest.mark.parametrize("zone", ["UTC", "Europe/Berlin", "Asia/Kolkata"])
def test_submission_verdict_bars(zone):
    """VERDICT HISTORY above the list of the submissions: a bar per
    submission, the oldest on the left, as high as the score of the verdict
    kept on it and in that verdict's colour; one without a kept verdict is a
    grey stub on the axis, "not evaluated". Dashed lines mark the scores at
    which the verdict turns SUSPICIOUS (1) and MALICIOUS (3); a tooltip names
    file, verdict, score and time, the legend counts the verdicts, and a file
    name from the sample stays text. The list under it is as before."""
    r = _run_node(SUBMISSION_VERDICT_FUNCTIONS, _verdicts_script(r"""
        (async () => {
            await refreshSubmissions();
            console.log(JSON.stringify({ ...look(), before, fetched }));
        })();
    """), _verdicts_js(zone))
    bars, axis = r["bars"], r["axis"]
    assert [b["key"] for b in bars] == ["2", "1", "0"], "the bars are not in the order of the submissions"
    assert [b["x"] for b in bars] == sorted({b["x"] for b in bars}), "the oldest submission is not on the left"
    old, inject, beacon = bars
    assert all(abs(b["y"] + b["height"] - axis) < 0.01 for b in bars), "a bar does not stand on the axis"
    (y3, dash3), (y1, dash1) = sorted(r["thresholds"])            # the line of 3 lies higher (a smaller y)
    assert dash3 and dash1, "a threshold is not dashed"
    assert {"SUSPICIOUS 1", "MALICIOUS 3"} <= set(r["texts"]), r["texts"]
    assert abs(inject["height"] / (axis - y1) - 2) < 0.01 and abs((axis - y3) / (axis - y1) - 3) < 0.01
    assert abs(beacon["height"] / inject["height"] - 2) < 0.01, "a bar is not as high as its score"
    assert beacon["y"] < y3 < inject["y"] < y1, "a bar does not stand against the lines as its verdict does"
    assert 0 < old["height"] <= 3, "a submission without a verdict is no stub on the axis"
    assert [b["color"] for b in bars] == [DIM, MEDIUM, CRITICAL]
    assert [b["title"] for b in bars] == [
        f"{EVIL} \u00b7 not evaluated \u00b7 05 Nov, 11:33:23",
        "injectsim.exe \u00b7 SUSPICIOUS \u00b7 score 2 \u00b7 05 Nov, 11:36:31",
        "beaconsim.exe \u00b7 MALICIOUS \u00b7 score 4 \u00b7 05 Nov, 11:37:11"]
    # A bar takes a click over the whole height of its slot, a stub too
    assert all(b["hit"][1] < y3 and abs(b["hit"][1] + b["hit"][3] - axis) < 0.01 for b in bars)
    assert all(b["hit"][0] <= b["x"] and b["hit"][0] + b["hit"][2] > b["x"] for b in bars)
    assert r["legend"] == [["suspicious", "suspicious", 1, MEDIUM], ["malicious", "malicious", 1, CRITICAL],
                           ["none", "not evaluated", 1, DIM]]
    assert r["markup"] == r["before"], "a file name from the sample became markup"
    assert r["list"] == ["beaconsim.exe", "injectsim.exe", EVIL] and r["fetched"] == ["/api/submissions"]


@needs_node
def test_submission_verdict_bars_colours_and_scale():
    """The colour is the verdict's in any case: CLEAN low, SUSPICIOUS medium,
    MALICIOUS critical, another label muted; none kept (no verdict, an empty
    one, one without a label) the grey of "not evaluated", as the legend
    counts them. A verdict of 0, or one without a score (its tooltip says
    so), is a stub on the axis in its colour; a score written as text counts.
    The scale reaches a tenth above the highest score or MALICIOUS 3, and no
    further than 10: a score of 13 sits at the top edge."""
    r = _run_node(SUBMISSION_VERDICT_FUNCTIONS, _verdicts_script(r"""
        (async () => {
            const r = {};
            const verdicts = [{ label: 'CLEAN', score: 0 }, { label: 'clean', score: 0 }, { label: 'Suspicious', score: 1 },
                              { label: ' MALICIOUS ', score: 3 }, { label: 'NOT OBSERVED', score: 0 }, { label: 'MALICIOUS' },
                              'MALICIOUS', null, {}, { label: '', score: 2 }, { score: 5 }, { label: 'SUSPICIOUS', score: '2' }];
            server.list = verdicts.map((verdict, i) => sub('v' + i, '2026-11-05T10:00:00', 'f' + i + '.exe', 'a'.repeat(64), 100 + i, verdict));
            await refreshSubmissions();
            r.verdicts = look();
            server.list = [sub('big', '2026-11-06T09:00:00', 'big.exe', 'c'.repeat(64), 1, { label: 'MALICIOUS', score: 13 }),
                           sub('half', '2026-11-06T08:00:00', 'half.exe', 'c'.repeat(64), 2, { label: 'MALICIOUS', score: 5 }),
                           ...submissions];
            await refreshSubmissions();
            r.outlier = look();
            server.list = [sub('low', '2026-11-06T09:00:00', 'low.exe', 'c'.repeat(64), 1, { label: 'SUSPICIOUS', score: 2 })];
            await refreshSubmissions();
            r.low = look();
            server.list = submissions.map(s => ({ ...s, verdict: null }));
            await refreshSubmissions();
            r.none = look();
            console.log(JSON.stringify(r));
        })();
    """), _verdicts_js())
    view = r["verdicts"]
    by_key = {b["key"]: b for b in view["bars"]}
    assert [b["key"] for b in view["bars"]] == [str(i) for i in range(11, -1, -1)]
    assert {k: b["color"] for k, b in by_key.items()} == {
        "0": LOW, "1": LOW, "2": MEDIUM, "3": CRITICAL, "4": MUTED, "5": CRITICAL, "6": CRITICAL, "7": DIM, "8": DIM,
        "9": DIM, "10": DIM, "11": MEDIUM}
    assert view["legend"] == [["clean", "clean", 2, LOW], ["suspicious", "suspicious", 2, MEDIUM],
                              ["malicious", "malicious", 3, CRITICAL], ["other", "other verdict", 1, MUTED],
                              ["none", "not evaluated", 4, DIM]]
    titles = {k: b["title"].split(" \u00b7 ")[1:-1] for k, b in by_key.items()}
    assert titles == {"0": ["CLEAN", "score 0"], "1": ["clean", "score 0"], "2": ["Suspicious", "score 1"],
                      "3": ["MALICIOUS", "score 3"], "4": ["NOT OBSERVED", "score 0"], "5": ["MALICIOUS", "no score"],
                      "6": ["MALICIOUS", "no score"], "7": ["not evaluated"], "8": ["not evaluated"],
                      "9": ["not evaluated"], "10": ["not evaluated"], "11": ["SUSPICIOUS", "score 2"]}, titles
    stubs = {k for k, b in by_key.items() if b["height"] <= 3}
    assert stubs == {"0", "1", "4", "5", "6", "7", "8", "9", "10"} and all(by_key[k]["height"] > 0 for k in stubs), \
        "a verdict of 0 or without a score is not a stub on the axis"
    one = by_key["2"]["height"]
    assert abs(by_key["3"]["height"] / one - 3) < 0.01 and abs(by_key["11"]["height"] / one - 2) < 0.01
    plot_h = by_key["2"]["hit"][3]
    assert abs(one / plot_h - 1 / 3.3) < 0.01, "the scale does not end a tenth above MALICIOUS 3"
    cells = {row[1][0]: [row[2][0], row[3][0], row[3][1]] for row in view["table"]["rows"]}
    assert cells["f0.exe"] == ["CLEAN", "0", "0"] and cells["f5.exe"] == ["MALICIOUS", "\u2014", ""]
    assert cells["f7.exe"] == ["not evaluated", "\u2014", ""] and cells["f10.exe"] == ["not evaluated", "\u2014", ""]
    assert cells["f11.exe"] == ["SUSPICIOUS", "2", "2"]
    # 13 where 10 is, 5 at half of it, the lines where they were
    outlier = {b["title"].split(" \u00b7 ")[0]: b for b in r["outlier"]["bars"]}
    big, half = outlier["big.exe"], outlier["half.exe"]
    assert abs(big["y"] - big["hit"][1]) < 0.01 and big["title"].split(" \u00b7 ")[2] == "score 13", \
        "a score above 10 does not reach the top"
    assert abs(half["height"] / half["hit"][3] - 0.5) < 0.01, "a score above 10 squeezes the scale"
    y3 = min(y for y, _ in r["outlier"]["thresholds"])
    assert abs((r["outlier"]["axis"] - y3) / half["hit"][3] - 0.3) < 0.01
    # Only low scores: the scale still reaches above MALICIOUS 3, whose line stays
    low = r["low"]
    assert len(low["thresholds"]) == 2 and {"SUSPICIOUS 1", "MALICIOUS 3"} <= set(low["texts"]), "a threshold line went missing"
    assert abs(low["bars"][0]["height"] / low["bars"][0]["hit"][3] - 2 / 3.3) < 0.01
    none = r["none"]
    assert none["bars"] and all(b["color"] == DIM and b["height"] <= 3 for b in none["bars"])
    assert len(none["thresholds"]) == 2 and none["legend"] == [["none", "not evaluated", 3, DIM]]


@needs_node
def test_submission_verdict_bar_opens_its_results():
    """A click on a bar (the bar, its tooltip or the empty part of its slot)
    opens its submission's results as its Results button in the list does:
    with LitterBox's hash when the sample went there (else the sample's), with
    none when it did not. A click beside the bars does nothing, and a
    submission without a hash and a PID has no results. After a new
    submission each bar still opens its own."""
    r = _run_node(SUBMISSION_VERDICT_FUNCTIONS, _verdicts_script(r"""
        (async () => {
            server.list = [...submissions, sub('s0', '2026-11-05T11:00:00', 'nothing.exe', '', null, null)];
            await refreshSubmissions();
            const bars = () => $('submission-verdicts-plot').querySelectorAll('g.chart-slot');
            const bar = key => bars().find(g => g.getAttribute('data-key') === key);
            const r = {};
            click(bar('0').querySelector('rect.chart-bar'));
            click(bar('1').querySelector('title'));
            click(bar('2').querySelector('rect.chart-hit'));
            click(bar('3').querySelector('rect.chart-bar'));
            r.bars = opened.splice(0);
            click($('submission-verdicts-plot').querySelector('line.chart-axis'));
            click($('submission-verdicts-plot').querySelector('svg'));
            click($('submission-verdicts-plot'));
            r.beside = opened.splice(0);
            $('submissions-list').querySelectorAll('button.btn-lb-results').forEach(button => click(button));
            r.buttons = opened.splice(0);
            // A new submission comes first in the list: injectsim's bar has the place 2 now
            server.list = [sub('s4', '2026-11-05T12:00:00', 'new.exe', 'c'.repeat(64), 4444, null), ...server.list];
            await refreshSubmissions();
            const inject = bars().find(g => g.querySelector('title').textContent.startsWith('injectsim.exe'));
            click(inject.querySelector('rect.chart-bar'));
            r.after = { key: inject.getAttribute('data-key'), opened: opened.splice(0) };
            console.log(JSON.stringify(r));
        })();
    """), _verdicts_js())
    beacon = ["f" * 64, "b" * 64, "3376", "beaconsim.exe"]
    inject = ["d" * 64, "d" * 64, "10392", "injectsim.exe"]
    old = ["", "e" * 64, "9664", EVIL]
    assert r["bars"] == [beacon, inject, old], "a bar opened other results than its submission's"
    assert r["beside"] == [], "a click beside the bars opened results"
    assert r["buttons"] == [beacon, inject, old], "the Results buttons of the list open other results than the bars"
    assert r["after"] == {"key": "2", "opened": [inject]}


@needs_node
def test_a_results_view_brings_its_verdict_into_the_history():
    """The server keeps the verdict a view of the results computes on the
    submission of its run (of the sample with this PID; without a PID one
    that ran without): while the Submit tab is open, its history loads
    again when it shows another verdict there, once for each verdict (a
    server that could not keep it lists the old one after every poll), and
    only then (not for each poll of an unchanged verdict, a PID none of the
    sample's submissions ran as, another sample, a response without a
    verdict, or in another tab)."""
    r = _run_node(SUBMISSION_VERDICT_FUNCTIONS, _verdicts_script(r"""
        (async () => {
            const A = 'a'.repeat(64), C = 'c'.repeat(64);
            server.list = [sub('n', '2026-11-05T12:00:00', 'evil.exe', A, 5000, { label: 'MALICIOUS', score: 4 }),
                           sub('o', '2026-11-05T11:00:00', 'evil.exe', A, 4242, { label: 'SUSPICIOUS', score: 2 }),
                           sub('x', '2026-11-05T10:00:00', 'x.exe', C, 4242, null),
                           sub('l', '2026-11-05T09:00:00', 'evil.exe', A, null, null, { target: 'litterbox' })];
            const r = {};
            const loads = async (sha, pid, verdict) => { noteDetonationVerdict(sha, pid, verdict); await settle(); return fetched.splice(0).length; };
            r.undrawn = await loads(A, 4242, { label: 'CLEAN', score: 0 });
            await refreshSubmissions();
            fetched.splice(0);
            r.calls = [
                await loads(A, 4242, { label: 'SUSPICIOUS', score: 2, reasons: ['x'] }),
                await loads(A, '4242', { label: 'MALICIOUS', score: 4, reasons: [] }),
                await loads(A.toUpperCase(), 5000, { label: 'MALICIOUS', score: 4 }),
                await loads(A, 9999, { label: 'MALICIOUS', score: 6 }),
                await loads(C, 4242, { label: 'CLEAN', score: 0 }),
                await loads('f'.repeat(64), 4242, { label: 'CLEAN', score: 0 }),
                await loads(A, 4242, null),
                await loads(A, 4242, { reasons: [] }),
                await loads('', 4242, { label: 'CLEAN', score: 0 }),
                await loads(A, '', { label: 'CLEAN', score: 0 }),
                await loads(C, '', { label: 'CLEAN', score: 0 }),
            ];
            // A server that could not keep a verdict (a file it cannot write) lists the old one after each poll:
            // the history loads once for each verdict it has not shown, not on every poll
            r.unkept = [
                await loads(A, 4242, { label: 'MALICIOUS', score: 4 }),
                await loads(A, 4242, { label: 'CLEAN', score: 0 }),
                await loads(A, 4242, { label: 'CLEAN', score: 0 }),
                await loads(A, '4242', { label: 'CLEAN', score: 0, reasons: ['again'] }),
                await loads(A, 4242, { label: 'MALICIOUS', score: 3 }),
            ];
            // Kept after all: the history shows it, nothing more to load
            server.list = server.list.map(s => (s.id === 'o' ? { ...s, verdict: { label: 'MALICIOUS', score: 3 } } : s));
            await refreshSubmissions();
            fetched.splice(0);
            r.keptLater = await loads(A, 4242, { label: 'MALICIOUS', score: 3 });
            state.activeTab = 'dashboard';
            r.otherTab = await loads(C, 4242, { label: 'CLEAN', score: 0 });
            console.log(JSON.stringify(r));
        })();
    """), _verdicts_js())
    assert r["undrawn"] == 0, "the history loaded before the Submit tab drew it"
    # as kept; another verdict for this PID; the newest run as kept (hash in any case); a PID no run of the sample
    # had (kept nowhere); one not evaluated yet; no submission of the sample; no verdict; no label; no sample; without
    # a PID the run without one, not evaluated yet; without a PID for a sample that only ran with one (kept nowhere)
    assert r["calls"] == [0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0], r["calls"]
    # the verdict already asked for; another; the same again (twice); yet another
    assert r["unkept"] == [0, 1, 0, 0, 1], f"a verdict the server could not keep loaded the history on every poll: {r['unkept']}"
    assert r["keptLater"] == 0
    assert r["otherTab"] == 0, "the history loaded while another tab was open"
    for name in ("viewDetonationResult", "pollDetonationResults"):
        assert "noteDetonationVerdict(" in _function_source(name), f"{name} does not bring its verdict into the history"


def test_verdict_history_lines_are_where_the_verdict_changes(tdc):
    """The dashed lines of VERDICT HISTORY mark the scores at which app.py's
    verdict turns SUSPICIOUS and MALICIOUS: its own scale of points for EDR
    alerts, LitterBox and the memory evidence, not the evidence score's 2 and 6."""
    source = _const_source("SUBMISSION_VERDICT_THRESHOLDS")
    lines = [(int(y), label) for y, label in re.findall(r"\{\s*y:\s*(\d+),\s*label:\s*'(\w+)'\s*\}", source)]
    assert lines == [(1, "SUSPICIOUS"), (3, "MALICIOUS")], source
    alert = lambda severity: make_alert(1, 7, "2026-11-05T10:00:00Z", r"C:\x\a.exe", severity=severity)  # noqa: E731
    verdicts = {0: tdc._compute_verdict({}, []), 1: tdc._compute_verdict({}, [alert("low")]),
                2: tdc._compute_verdict({}, [alert("high")]), 3: tdc._compute_verdict({}, [alert("critical")])}
    assert {n: (v["score"], v["label"]) for n, v in verdicts.items()} == {
        0: (0, "CLEAN"), 1: (1, "SUSPICIOUS"), 2: (2, "SUSPICIOUS"), 3: (3, "MALICIOUS")}
    for y, label in lines:
        assert verdicts[y]["label"] == label and verdicts[y - 1]["label"] != label, (y, label)


@needs_node
def test_submission_verdict_card_has_info_and_table():
    """The card sits between the head of the submission history and its list,
    with its (i) and its CHART / TABLE switch; the table view lists every
    submission in the order of the chart (time, file, verdict, score or "—"),
    sortable, with the numbers of the tooltips. Without submissions the card
    says "No submissions yet", without a list it could load "Submissions not
    available", as the list says it. The chart is drawn for the width of its
    plot, and again when that changes, not while hidden; the table stays as
    it is then."""
    tab = _Elements(_read(INDEX_HTML)).by_id("tab-submit")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def by_id(node, element_id):
        found = find(node, lambda e: e["attrs"].get("id") == element_id)
        assert len(found) == 1, element_id
        return found[0]

    def text(node):
        return node.get("text", "") + "".join(text(c) for c in node["children"])

    section = find(tab, lambda e: e["attrs"].get("class") == "submissions-history")[0]
    assert [c["attrs"].get("id") or c["attrs"].get("class") for c in section["children"]] == \
        ["submissions-header", "submission-verdicts-card", "submissions-list"], "the card is not right above the list"
    card = by_id(section, "submission-verdicts-card")
    assert "chart-card" in card["attrs"]["class"].split()
    heading = find(card, lambda e: "chart-card-title" in e["attrs"].get("class", "").split())
    assert len(heading) == 1 and text(heading[0]).strip() == "VERDICT HISTORY"
    info = heading[0]["attrs"].get("data-info", "")
    assert "\u201cnot evaluated\u201d" in info and "SUSPICIOUS (1)" in info and "MALICIOUS (3)" in info, \
        "the (i) does not name the lines or the grey bars"
    assert "view-toggle-slot" in by_id(card, "submission-verdicts-toggle")["attrs"]["class"].split()
    chart, table = by_id(card, "submission-verdicts-chart"), by_id(card, "submission-verdicts-table")
    assert (chart["attrs"].get("data-view-of"), chart["attrs"].get("data-view"), "hidden" in chart["attrs"]) == \
        ("submission-verdicts", "chart", False)
    assert (table["attrs"].get("data-view-of"), table["attrs"].get("data-view"), "hidden" in table["attrs"]) == \
        ("submission-verdicts", "table", True)
    plot = by_id(chart, "submission-verdicts-plot")
    assert "chart-clickable" in plot["attrs"]["class"].split() and \
        plot["attrs"].get("onclick") == "onSubmissionVerdictsClick(event)"
    assert by_id(chart, "submission-verdicts-legend") is not None
    source = "\n".join(_strip_js_comments(_function_source(name)) for name in SUBMISSION_VERDICT_OWN)
    source += "\n".join(_const_source(c) for c in ("SUBMISSION_VERDICT_THRESHOLDS", "SUBMISSION_VERDICT_GROUPS"))
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"

    r = _run_node(SUBMISSION_VERDICT_FUNCTIONS, _verdicts_script(r"""
        (async () => {
            $('submission-verdicts-plot').rect = { width: 700 };
            await refreshSubmissions();
            const toggle = () => $('submission-verdicts-toggle').querySelector('.view-toggle');
            const r = { view: look(), times: submissions.map(s => String(Date.parse(s.timestamp))).reverse(),
                        toggle: [toggle().getAttribute('data-view-toggle'), toggle().textContent] };
            const button = toggle();
            await refreshSubmissions();
            r.toggleKept = toggle() === button;
            // A new width: drawn again, the table left as it is; the same width or a hidden plot (0): nothing
            const tableNode = $('submission-verdicts-table').querySelector('table');
            $('submission-verdicts-plot').rect = { width: 480 };
            redrawSubmissionVerdictsOnResize();
            r.resized = [look().width, $('submission-verdicts-table').querySelector('table') === tableNode];
            const svg = $('submission-verdicts-plot').querySelector('svg');
            redrawSubmissionVerdictsOnResize();
            $('submission-verdicts-plot').rect = { width: 0 };
            redrawSubmissionVerdictsOnResize();
            r.kept = $('submission-verdicts-plot').querySelector('svg') === svg;
            // TABLE: the table in place of the chart, kept on the next render
            click(toggle());
            await refreshSubmissions();
            r.tableView = [$('submission-verdicts-chart').hidden, $('submission-verdicts-table').hidden, toggle().textContent];
            click(toggle());
            // A name with a quote stays inside its attribute
            server.list = [sub('q', '2026-11-05T11:38:00', QUOTE, 'c'.repeat(64), 1, { label: 'SUSPICIOUS', score: 2 }), ...submissions];
            await refreshSubmissions();
            const quoted = $('submission-verdicts-table').querySelector('table').tBodies[0].rows.find(row => row.cells[1].textContent === QUOTE);
            r.quoted = [quoted.cells[1].getAttribute('title'), Object.keys(quoted.cells[1].attrs).sort(),
                        look().bars.map(b => b.title).filter(t => t.includes(QUOTE))];
            // No submissions; after that the legend comes back beside the plot: the bars get the width that leaves
            server.list = [];
            await refreshSubmissions();
            r.none = look();
            const plot = $('submission-verdicts-plot'), legendBox = $('submission-verdicts-legend');
            plot.getBoundingClientRect = () => ({ width: legendBox.firstElementChild ? 468 : 700 });
            server.list = submissions;
            await refreshSubmissions();
            r.afterEmpty = look().width;
            delete plot.getBoundingClientRect;
            // A list that cannot be loaded: the card says so, as the list does (each time after a drawn chart)
            server.ok = false;
            await refreshSubmissions();
            r.failed = look();
            server.ok = true;
            await refreshSubmissions();
            server.fails = true;
            await refreshSubmissions();
            r.unreachable = look();
            console.log(JSON.stringify(r));
        })();
    """), _verdicts_js())
    view = r["view"]
    assert r["toggle"] == ["submission-verdicts", "TABLE"] and r["toggleKept"], "a card without its CHART / TABLE switch"
    t = view["table"]
    assert t["id"] == "submission-verdicts" and t["sortable"] and t["head"] == ["Time", "File", "Verdict", "Score"]
    dash = "\u2014"
    assert [[cell[0] for cell in row] for row in t["rows"]] == [
        ["05 Nov, 11:33:23", EVIL, "not evaluated", dash],
        ["05 Nov, 11:36:31", "injectsim.exe", "SUSPICIOUS", "2"],
        ["05 Nov, 11:37:11", "beaconsim.exe", "MALICIOUS", "4"]], "the table lists other submissions than the chart"
    assert [row[0][1] for row in t["rows"]] == r["times"], "the time does not sort by its value"
    assert [row[3][1] for row in t["rows"]] == ["", "2", "4"], "a submission without a score does not sort last"
    assert t["rows"][0][1][2] == EVIL, "the file's title is cut or markup"
    assert [(b["title"].split(" \u00b7 ")[1:-1] + [dash])[1].replace("score ", "") for b in view["bars"]] == \
        [row[3][0] for row in t["rows"]], "the tooltips show other numbers than the table"
    assert view["markup"] == [0, 0] and not view["low"]
    assert view["width"] == 700 and r["resized"] == [480, True] and r["kept"], \
        "not drawn for the width of the plot, drawn again for the same width or while hidden, or the table rewritten"
    assert r["tableView"] == [True, False, "CHART"]
    assert r["quoted"] == [QUOTE, ["class", "title"],
                           [f"{QUOTE} \u00b7 SUSPICIOUS \u00b7 score 2 \u00b7 05 Nov, 11:38:00"]], "a quote left its attribute"
    none = r["none"]
    assert none["empty"] == "No submissions yet" and none["bars"] == [] and none["legend"] == [] and none["low"]
    assert none["table"]["rows"] == [] and none["table"]["notes"] == ["No submissions yet."]
    assert none["listText"] == "No samples submitted yet. Use the form above to detonate a sample."
    assert r["afterEmpty"] == 468, "the bars were drawn for the plot's width before the legend took its room beside it"
    failed, unreachable = r["failed"], r["unreachable"]
    assert failed["empty"] == "Submissions not available" and failed["bars"] == [] and failed["low"]
    assert failed["table"]["notes"] == ["Submissions not available."] and failed["listText"] == "Failed to load submissions."
    assert unreachable["empty"] == "Submissions not available" and unreachable["bars"] == [] and \
        unreachable["listText"] == "Error: Failed to fetch"

    # Drawn again in the next frame when the plot's width changes; set up at start-up
    r = _run_node(["initSubmissionVerdicts"], r"""
        const resizers = [], frames = [];
        let redraws = 0;
        globalThis.ResizeObserver = class {
            constructor(callback) { this.callback = callback; resizers.push(this); }
            observe(el, options) { (this.els = this.els || []).push([el.id, options || null]); }
        };
        globalThis.requestAnimationFrame = fn => frames.push(fn);
        globalThis.redrawSubmissionVerdictsOnResize = () => redraws++;
        document.body.innerHTML = MARKUP;
        initSubmissionVerdicts();
        const r = { observed: resizers.map(o => o.els) };
        resizers[0].callback([]); r.inside = [redraws, frames.length];
        frames.splice(0).forEach(fn => fn()); r.drawn = redraws;
        document.body.innerHTML = '';
        try { initSubmissionVerdicts(); r.noCard = 'ok'; } catch (e) { r.noCard = e.message; }
        document.body.innerHTML = MARKUP;
        delete globalThis.ResizeObserver;
        try { initSubmissionVerdicts(); r.noObserver = 'ok'; } catch (e) { r.noObserver = e.message; }
        console.log(JSON.stringify(r));
    """.replace("MARKUP", json.dumps(_tab_markup("submit"))), SORT_DOM)
    assert r["observed"] == [[["submission-verdicts-plot", None]]]
    assert r["inside"] == [0, 1] and r["drawn"] == 1, "drawn inside the observer, or not at all"
    assert r["noCard"] == "ok" and r["noObserver"] == "ok"
    js = _strip_js_comments(_read(APP_JS))
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    assert re.search(r"^\s*initSubmissionVerdicts\(\);", js[start:js.index("\n});", start)], re.M), "not set up at start-up"
    # The chart and its table view over the same area, lower without submissions; a bar's slot takes the pointer
    rules = _rules(STYLE_CSS)
    assert re.search(r"margin:", rules.get(".submission-verdicts-card", "")), "the card is not set in from the edges as the list's head"
    assert re.search(r"position:\s*relative", rules.get(".submission-verdicts-area", "")) and \
        re.search(r"(?:^|;)\s*height:", rules.get(".submission-verdicts-area", ""))
    assert re.search(r"(?:^|;)\s*height:", rules.get(".submission-verdicts-area.is-empty", "")), "an empty card is as high as a chart"
    for selector in (".submission-verdicts-view", ".submission-verdicts-table"):
        assert re.search(r"position:\s*absolute", rules.get(selector, "")), f"{selector} stretches the card"
    assert re.search(r"overflow(?:-y)?:\s*auto", rules.get(".submission-verdicts-table", ""))
    assert re.search(r"background:\s*transparent", rules.get(".submission-verdicts-table::-webkit-scrollbar-corner", ""))
    assert re.search(r"position:\s*sticky", rules.get(".submission-verdicts-table .view-table th", ""))
    assert re.search(r"min-width:\s*0", rules.get(".submission-verdicts-plot", "")), "a long legend pushes the plot out of the card"
    assert re.search(r"cursor:\s*pointer", rules.get(".chart-clickable .chart-slot", "")), "a bar does not show it takes a click"
    assert re.search(r"fill:\s*rgba\(var\(--", rules.get(".chart-slot:hover .chart-hit", "")), "the slot under the pointer is not marked"


# --- ACTIVITY MIX in the detail of a graph node -------------------------------------

# The donut of a process node's detail, and the parts of the detail and the charts it uses
GRAPH_MIX_OWN = ["activityMix", "graphActivityMixHtml"]
GRAPH_MIX_FUNCTIONS = list(dict.fromkeys(GRAPH_MIX_OWN + [
    "showGraphDetail", "_alertsShareTableHtml", "severitySortValue", "escapeHtml", "jsArg", "cssToken",
    "isTableView", "viewToggleHtml", "cardViewAttrs", "toggleCardView"] + CHART_FUNCTIONS))
GRAPH_MIX_CONSTS = ["ACTIVITY_MIX_KINDS", "cardViewState"] + CHART_CONSTS
GRAPH_KIND_COLOURS = {"network": "var(--graph-network)", "dns": "var(--graph-dns)", "file": "var(--graph-file)",
                      "registry": "var(--graph-registry)", "pipe": "var(--graph-pipe)", "injection": "var(--accent-red)"}

# A /api/process-graph payload as the server writes it: two instances of PID
# 1112, "1112@1789000000" (an earlier process that had the PID) and "1112"
# (its newest holder), and svchost.exe (836). The network, DNS, file,
# registry and pipe entries carry the instance's key and the PID (one network
# entry the PID only: the graph gives it to the PID's newest holder); an
# injection carries both of its ends.
GRAPH_MIX_FIXTURE = r"""
    const OLD = '1112@1789000000', NEW = '1112';
    const at = s => `2026-11-05T11:37:${String(s).padStart(2, '0')}.120000+01:00`;
    const net = (key, ip, port, s) => ({ pid: key.split('@')[0], key, dst_ip: ip, dst_port: String(port), dst_hostname: '',
                                         protocol: 'tcp', timestamp: at(s) });
    const payload = {
        root_pid: NEW, truncated: false, node_count: 3, pipes_truncated: false, processes: {},
        network: [net(OLD, '192.168.64.1', 8769, 1), net(OLD, '192.168.64.1', 8769, 3), net(OLD, '192.168.64.1', 8769, 5),
                  net(NEW, '13.107.4.52', 443, 7), net('836', '192.168.64.4', 135, 8),
                  { pid: '1112', dst_ip: '10.0.0.1', dst_port: '80', dst_hostname: '', protocol: 'tcp', timestamp: at(9) }],
        dns: [{ pid: '1112', key: OLD, query: 'c2.example', result: '192.168.64.1;', timestamp: at(2) },
              { pid: '1112', key: NEW, query: 'WIN-T6JBL58QBH8', result: '::ffff:192.168.64.4;', timestamp: at(8) }],
        files: [{ pid: '1112', key: OLD, target: 'C:\\Users\\Public\\beacon.dat', timestamp: at(4) },
                { pid: '1112', key: OLD, target: 'C:\\Users\\Public\\beacon.log', timestamp: at(6) }],
        registry: [{ pid: '836', key: '836', target: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\x\\Start',
                     details: 'DWORD (0x00000002)', timestamp: at(9) }],
        pipes: [{ key: NEW, pid: '1112', pipe: '\\msagent_7d6e15', action: 'created', family: 'Cobalt Strike', timestamp: at(10) },
                { key: NEW, pid: '1112', pipe: '\\msagent_7d6e15', action: 'connected', family: 'Cobalt Strike', timestamp: at(11) },
                { key: '836', pid: '836', pipe: '\\msagent_7d6e15', action: 'connected', family: 'Cobalt Strike', timestamp: at(12) }],
        injections: [{ source_pid: '1112', target_pid: '836', source_key: OLD, target_key: '836',
                       target_image: 'C:\\Windows\\System32\\svchost.exe', timestamp: at(13) },
                     { source_pid: '836', target_pid: '1112', source_key: '836', target_key: NEW,
                       target_image: 'C:\\Users\\Public\\Downloads\\pipesim.exe', timestamp: at(14) }],
    };
"""


def _graph_mix_prelude():
    return "\n".join(_const_source(c) for c in GRAPH_MIX_CONSTS)


@needs_node
def test_activity_mix_counts_this_instance_only():
    """ACTIVITY MIX counts what one process instance did by Sysmon in the
    graph data: the entries of its key in the network, DNS, file, registry,
    pipe and injection lists (an injection belongs to the process that made
    it), in a fixed order and in the colours of the graph's nodes. Another
    process that had the same PID counts apart; an entry with only the PID
    belongs to the PID's newest holder, as the graph draws its edge. Nothing
    for an unknown key or without data."""
    r = _run_node(GRAPH_MIX_FUNCTIONS, GRAPH_MIX_FIXTURE + r"""
        console.log(JSON.stringify({
            old: activityMix(payload, OLD), new: activityMix(payload, NEW), svchost: activityMix(payload, '836'),
            number: activityMix(payload, 1112),
            none: [activityMix(payload, 'nope'), activityMix(payload, ''), activityMix(payload, null), activityMix(null, OLD),
                   activityMix({}, OLD), activityMix({ network: 'x', dns: null, files: [null, 7, 'a'] }, OLD)],
            sizes: Object.fromEntries(ACTIVITY_MIX_KINDS.map(kind => [kind.key, (payload[kind.list] || []).length])),
        }));
    """, _graph_mix_prelude())
    labels = {"network": "Network", "dns": "DNS", "file": "File", "registry": "Registry", "pipe": "Named pipes",
              "injection": "Injection"}

    def mix(**values):
        return [{"key": k, "label": labels[k], "value": v, "color": GRAPH_KIND_COLOURS[k]} for k, v in values.items()]
    assert r["old"] == mix(network=3, dns=1, file=2, injection=1), "the earlier process of PID 1112 counts entries of others"
    assert r["new"] == mix(network=2, dns=1, pipe=2), \
        "the newest holder of PID 1112 counts entries of the earlier process, or an injection made into it"
    assert r["svchost"] == mix(network=1, registry=1, pipe=1, injection=1)
    assert r["number"] == r["new"]
    assert r["none"] == [[]] * 6
    # Each entry counts for exactly one instance
    totals = {k: sum(item["value"] for who in ("old", "new", "svchost") for item in r[who] if item["key"] == k)
              for k in labels}
    assert totals == r["sizes"], (totals, r["sizes"])


# The detail panel of the Graph tab, a node of each process as buildGraph
# makes them (beaconsim.exe is the earlier holder of PID 1112, pipesim.exe the
# newest, quiet.exe did nothing Sysmon saw), the graph data of the fixture
GRAPH_MIX_DOM = r"""
    document.body.innerHTML = MARKUP;
    const $ = id => document.getElementById(id);
    globalThis.loadGraphSysmonSections = () => {};
    const procNode = (key, label, activity) => ({ id: 'proc_' + key, type: 'process', key, pid: key.split('@')[0], label,
        image: 'C:\\Users\\Public\\Downloads\\' + label, cmdline: '', user: '', threats: activity.threats || 0,
        severity: 'unknown', children: [], parentPid: null, parentOsPid: null, activity, firstSeen: '2026-11-05T10:37:01Z',
        exited: true, detonated: true, detonationSources: [], isRoot: false, isAncestor: false, depth: 0,
        alertsCount: activity.threats || 0, scans: [], scanVerdict: 'unknown' });
    const quiet = { threats: 0, network: 0, dns: 0, file: 0, registry: 0, injection: 0 };
    const nodes = [procNode(OLD, 'beaconsim.exe', { ...quiet, threats: 3, file: 2 }), procNode(NEW, 'pipesim.exe', quiet),
                   procNode('900', 'quiet.exe', { ...quiet, threats: 1 })];
    globalThis.graphState = { nodes, edges: [], data: payload };
"""

# What the detail shows of the node: its parts in their order, the Activity
# grid, and ACTIVITY MIX with its views, its threats and its table
GRAPH_MIX_LOOK = r"""
    const paint = el => (el ? el.getAttribute('style') || '' : '').replace(/^(?:fill|stroke|background):/, '');
    const look = () => {
        const body = $('graph-detail-body'), mix = $('graph-activity-mix');
        const chart = mix.querySelector('[data-view-of="graph-activity-mix"][data-view="chart"]');
        const tableView = mix.querySelector('[data-view-of="graph-activity-mix"][data-view="table"]');
        const table = tableView.querySelector('table'), rows = table.tBodies[0].rows;
        const title = mix.querySelector('[data-info]');
        return {
            order: body.children.map(el => el.id || el.className),
            heading: body.children.map(el => el.textContent.trim()),
            grid: body.querySelectorAll('.gd-activity-cell').map(cell => cell.textContent.trim()),
            title: title.textContent.trim(), info: title.getAttribute('data-info'),
            toggle: mix.querySelectorAll('.view-toggle').map(b => [b.getAttribute('data-view-toggle'), b.textContent]),
            hidden: [chart.hidden, tableView.hidden],
            segments: chart.querySelectorAll('.chart-seg').map(s => [s.getAttribute('data-key'), Number(s.getAttribute('data-value')), paint(s)]),
            centre: chart.querySelectorAll('text').map(t => t.textContent),
            legend: chart.querySelectorAll('.chart-legend-row').map(row => [row.getAttribute('data-key'),
                row.querySelector('.chart-legend-name').textContent, Number(row.querySelector('.chart-legend-count').textContent),
                paint(row.querySelector('.chart-legend-swatch'))]),
            empty: (chart.querySelector('.chart-empty') || { textContent: null }).textContent,
            table: { id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
                     head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
                     rows: rows.filter(row => !row.hasAttribute('data-sort-skip'))
                         .map(row => row.cells.map(c => [c.textContent.trim(), c.getAttribute('data-sort-value')])),
                     notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()) },
            threats: { text: mix.querySelector('.gd-mix-threats').textContent.replace(/\s+/g, ' ').trim(),
                       number: mix.querySelector('.gd-mix-threats-num').textContent,
                       marked: mix.querySelector('.gd-mix-threats').classList.contains('has-threats') },
            clickable: mix.querySelectorAll('.chart-clickable').length,
        };
    };
"""


@needs_node
def test_activity_mix_card_in_the_graph_detail():
    """The detail of a process node keeps its Activity grid (its alerts by
    category) and shows ACTIVITY MIX right under it: the donut of what the
    instance did by Sysmon beside its legend, with its (i) and CHART / TABLE;
    the table view lists the same numbers, sortable, and stays chosen for
    the next node. The alerts (Threats) are a number of their own, not part
    of the ring. Without Sysmon activity, or without graph data, both views
    say so."""
    r = _run_node(GRAPH_MIX_FUNCTIONS, (GRAPH_MIX_FIXTURE + GRAPH_MIX_DOM + GRAPH_MIX_LOOK + r"""
        const r = {};
        showGraphDetail(nodes[0]); r.old = look();
        showGraphDetail(nodes[1]); r.new = look();
        click($('graph-activity-mix').querySelector('.view-toggle'));
        r.switched = look().hidden;
        showGraphDetail(nodes[0]); r.kept = [look().hidden, look().toggle];
        toggleCardView('graph-activity-mix');
        showGraphDetail(nodes[2]); r.quiet = look();
        graphState.data = null;
        showGraphDetail(nodes[0]); r.noData = look();
        console.log(JSON.stringify(r));
    """).replace("MARKUP", json.dumps(_tab_markup("graph"))), SORT_DOM + _graph_mix_prelude())
    old = r["old"]
    i = old["order"].index("gd-activity-grid")
    assert old["heading"][i - 1].startswith("Activity") and old["order"][i + 1] == "graph-activity-mix", \
        f"ACTIVITY MIX is not right under the Activity grid: {old['order']}"
    assert old["grid"] == ["3Threats", "0Network", "0DNS", "2File", "0Registry", "0Injection"], "the Activity grid changed"
    assert old["title"] == "ACTIVITY MIX" and "Sysmon" in old["info"] and "Threats" in old["info"] and \
        "not part of the ring" in old["info"], old["info"]
    assert old["toggle"] == [["graph-activity-mix", "TABLE"]] and old["hidden"] == [False, True], "no CHART / TABLE switch"
    ring = [["network", 3, GRAPH_KIND_COLOURS["network"]], ["dns", 1, GRAPH_KIND_COLOURS["dns"]],
            ["file", 2, GRAPH_KIND_COLOURS["file"]], ["injection", 1, GRAPH_KIND_COLOURS["injection"]]]
    assert old["segments"] == ring, "the ring shows other numbers than the instance's Sysmon activity"
    assert old["centre"] == ["7", "EVENTS"]
    assert old["legend"] == [["network", "Network", 3, ring[0][2]], ["dns", "DNS", 1, ring[1][2]],
                             ["file", "File", 2, ring[2][2]], ["injection", "Injection", 1, ring[3][2]]]
    assert old["threats"] == {"text": "Threats 3 \u00b7 alerts, not part of the ring", "number": "3", "marked": True}, \
        "the alerts are not a number of their own beside the ring"
    assert old["clickable"] == 0, "the ring looks as if a click on it did something"
    t = old["table"]
    assert t["id"] == "graph-activity-mix" and t["sortable"] and t["head"] == ["Kind", "Count", "Share"]
    assert [[c[0] for c in row] for row in t["rows"]] == [["Network", "3", "42.9%"], ["DNS", "1", "14.3%"],
                                                           ["File", "2", "28.6%"], ["Injection", "1", "14.3%"]], \
        "the table shows other numbers than the ring"
    assert [row[1][1] for row in t["rows"]] == ["3", "1", "2", "1"] and t["notes"] == []
    new = r["new"]
    assert new["segments"] == [["network", 2, GRAPH_KIND_COLOURS["network"]], ["dns", 1, GRAPH_KIND_COLOURS["dns"]],
                               ["pipe", 2, GRAPH_KIND_COLOURS["pipe"]]] and new["centre"] == ["5", "EVENTS"]
    assert new["threats"] == {"text": "Threats 0 \u00b7 alerts, not part of the ring", "number": "0", "marked": False}
    assert r["switched"] == [True, False], "TABLE does not show the table"
    assert r["kept"] == [[True, False], [["graph-activity-mix", "CHART"]]], "TABLE was lost on the next node"
    for empty in (r["quiet"], r["noData"]):
        assert empty["segments"] == [] and empty["legend"] == [] and empty["empty"] == "No Sysmon activity for this process"
        assert empty["table"]["rows"] == [] and empty["table"]["notes"] == ["No Sysmon activity for this process."]
    assert r["quiet"]["threats"]["number"] == "1" and r["quiet"]["threats"]["marked"], "the threats left with the ring"
    # Colours: variables of the theme only (those of the graph's nodes)
    source = "\n".join(_strip_js_comments(_function_source(n)) for n in GRAPH_MIX_OWN) + _const_source("ACTIVITY_MIX_KINDS")
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"
    defined = set(_root_values())
    assert all(re.fullmatch(r"var\((--[\w-]+)\)", c).group(1) in defined for c in GRAPH_KIND_COLOURS.values())
    assert "graphActivityMixHtml(node)" in _function_source("showGraphDetail")
    rules = _rules(STYLE_CSS)
    assert re.search(r"display:\s*flex", rules.get(".gd-mix-head", "")), "the switch is not on the line of the title"
    assert re.search(r"margin-left:\s*auto", rules.get(".gd-mix-head .view-toggle", "")), "the switch is not on the right"
    assert re.search(r"color:\s*var\(--severity-critical\)", rules.get(".gd-mix-threats.has-threats .gd-mix-threats-num", "")), \
        "a process with alerts does not show its threats in the colour of critical"
    assert _painted(rules, _cls("gd-mix-threats"), "color")


# --- VERDICT FLOW of the detonation results ----------------------------------------

# The flow, its card, and the parts of the charts and the cards it uses
VERDICT_FLOW_OWN = ["detonationFindings", "detonationFlow", "_verdictFlowKind", "_verdictFlowColors", "verdictFlowHtml",
                    "drawVerdictFlow", "_drawVerdictFlowSvg", "_verdictFlowWidth", "toggleVerdictFlowScale",
                    "redrawVerdictFlowsOnResize"]
VERDICT_FLOW_FUNCTIONS = list(dict.fromkeys(VERDICT_FLOW_OWN + [
    "alertProcessName", "_alertsNameKey", "submissionVerdictGroup", "_flowTableHtml", "_pressFlowScale", "escapeHtml",
    "jsArg", "isTableView", "viewToggleHtml", "cardViewAttrs", "toggleCardView"] + CHART_FUNCTIONS))
VERDICT_FLOW_CONSTS = ["VERDICT_FLOW_KINDS", "VERDICT_FLOW_LITTERBOX_MIN", "VERDICT_FLOW_SOURCES", "verdictFlowView",
                       "_verdictFlowDrawn", "SUBMISSION_VERDICT_GROUPS", "cardViewState"] + CHART_CONSTS
# The two results views around the card: the panels of the Submit tab, the detail panel
RESULT_VIEW_FUNCTIONS = list(dict.fromkeys(VERDICT_FLOW_FUNCTIONS + [
    "renderDetonationPanels", "viewDetonationResult", "_detRawButton", "renderMemoryEvidence", "evidenceClassLabel",
    "confidenceClass", "renderExitCaptureBlock", "renderNetworkBeaconingBlock", "renderNamedPipesBlock", "pipesIsGone",
    "pipesCanonical", "pipeProcLabel", "formatTime", "formatSize", "cssToken", "severitySortValue", "sortTimeValue",
    "sortNumberValue", "pushDetailHistory", "setDetailHeader", "setDetailBody", "showDetail"]))
FLOW_KINDS = ["kind:edr", "kind:memory", "kind:exit", "kind:network", "kind:pipes"]
FLOW_KIND_SOURCES = {"exit-capture": "kind:exit", "sysmon-network": "kind:network", "sysmon-pipes": "kind:pipes"}


def _verdict_flow_js(zone="UTC"):
    return (SORT_DOM + "process.env.TZ = %s;\n" % json.dumps(zone)
            + "\n".join(_const_source(c) for c in VERDICT_FLOW_CONSTS)
            + "\nlet _verdictFlowObserver = null;\nlet _detRawPayloads = [];\n" + _const_source("ALERT_SEVERITIES") + "\n"
            + _const_source("PIPE_FLAG_LABELS") + "\nconst pipesState = { gone: new Set() };\n")


# The results of a detonation of pipesim.exe as /api/detonation/results
# returns them (the fields of a real one): 53 EDR alerts matched, of which the
# server lists the first 50 (processes in any case, with blanks, by image
# only, without any); the memory evidence of all sources (MALICIOUS 15.8):
# named pipes, network beaconing, Process Dump (no process name), Aether and
# the exit capture with two findings each capped as repeats of their kind
# (weight 0), and two findings the host baseline suppressed; the named pipes
# (two pipes, three findings) and the network rhythm (one finding).
VERDICT_FLOW_FIXTURE = r"""
    const SHA = '5757afc204173094'.repeat(4);
    const NAMES = [...Array(30).fill(['pipesim.exe', '']), ...Array(4).fill(['PIPESIM.EXE ', '']),
                   ...Array(6).fill(['', 'C:\\Windows\\System32\\rundll32.exe']), ['', ''], ['', ''],
                   ...Array(3).fill(['conhost.exe', '']), ['cmd.exe', ''], ['cmd.exe', ''], ['svchost.exe', ''],
                   ['taskhostw.exe', ''], ['dllhost.exe', '']];
    const alert = ([process_name, process_image], i) => ({ category: ['process'], command_line: '', detonated: true,
        engine: i % 3 ? 'Yara' : 'fibratus', id: 'a' + i, parent_command_line: '', parent_name: '', parent_pid: null,
        pid: 9664, process_image, process_name, raw: {}, raw_trimmed: true, rule_description: '',
        rule_name: 'Windows_Trojan_CobaltStrike_' + i, severity: ['Critical', 'high', 'medium', 'low'][i % 4], tags: [],
        timestamp: `2026-11-05T10:33:${String(24 + i % 30).padStart(2, '0')}Z`, user: '' });
    const finding = (source, kind, score, more) => ({ address: null, base_weight: Math.max(score, 0.2), baseline: 'new',
        confidence: 1.0, detail: kind, evidence: 'string', factors: { corroboration: 1.0, persistence: 1.0 },
        key: (source + kind + score).replace(/\W/g, '').slice(0, 16), kind, label: kind, needs_corroboration: false,
        process: 'pipesim.exe', raw_score: score || 0.2, raw_severity: '', score, source, ...more });
    const capped = rank => ({ saturation: { group_cap: 4.0, group_size: 6, rank } });
    const pipeFindings = [
        finding('sysmon-pipes', 'pipe_c2_default', 4.0, { pipe: '\\msagent_7d6e15', family: 'Cobalt Strike',
                                                          image_path: 'C:\\Users\\Public\\Downloads\\pipesim.exe' }),
        finding('sysmon-pipes', 'pipe_cross_process', 1.5, { pipe: '\\msagent_7d6e15', corroborated_by: ['aether', 'exit-capture'] }),
        finding('sysmon-pipes', 'pipe_random_name', 0.8, { pipe: '\\msagent_7d6e15' })];
    const netFinding = finding('sysmon-network', 'c2_beaconing', 3.0, { endpoint: '192.168.64.1:8769', connections: 7,
                                                                       mean_interval_s: 2.01, cov: 0.004 });
    const results = {
        sha256: SHA, pid: '9664', ready: { static: true, dynamic: true, fibratus: true }, litterbox_online: false,
        edr_status: { fibratus_online: true, rustinel_online: true }, ioc_feed: { status: 'exists' },
        fibratus_alerts: NAMES.map(alert), fibratus_alert_count: 53,
        memory_evidence: {
            label: 'MALICIOUS', score: 15.8, thresholds: { suspicious: 2.0, malicious: 6.0 },
            findings: [pipeFindings[0], netFinding, finding('process-dump', 'dumped_code_chunk', 2.5, { process: '' }),
                       finding('aether', 'memory_signature', 2.0, capped(1)), finding('exit-capture', 'memory_signature', 2.0, capped(2)),
                       pipeFindings[1], pipeFindings[2],
                       finding('aether', 'memory_signature', 0.0, capped(3)), finding('aether', 'memory_signature', 0.0, capped(5)),
                       finding('exit-capture', 'memory_signature', 0.0, capped(4)),
                       finding('exit-capture', 'memory_signature', 0.0, capped(6))],
            suppressed: [finding('aether', 'heap_api_table', 0.0, { baseline: 'known', process: 'explorer.exe' }),
                         finding('hunt-sleeping-beacons', 'sleeping_beacon', 0.0, { baseline: 'known' })],
            suppressed_count: 2, by_evidence: { behavioral: 4.5, string: 4.8, structural: 6.5 }, reasons: [],
            sources: ['aether', 'exit-capture', 'hunt-sleeping-beacons', 'process-dump', 'sysmon-network', 'sysmon-pipes'],
            sources_present: ['aether', 'process_dump', 'hunt_sleeping_beacons', 'exit_capture_result', 'network_beaconing',
                              'named_pipes'],
        },
        named_pipes: { available: true, truncated: false, evidence_findings: pipeFindings, pipes: [
            { pipe: '\\msagent_7d6e15', created_by: ['9664?'], connected_by: ['1672', '3296'], family: 'Cobalt Strike',
              flags: ['c2_default', 'cross_process', 'random_name'], first_seen: '2026-11-05T11:33:23.893781+01:00',
              last_seen: '2026-11-05T11:33:27.666959+01:00', note: 'Default SMB Beacon pipe (msagent_##)' },
            { pipe: '\\PSHost.134072384.9664.DefaultAppDomain.pipesim', created_by: ['9664?'], connected_by: [], family: null,
              flags: [], first_seen: '2026-11-05T11:33:24.100000+01:00', last_seen: '2026-11-05T11:33:24.100000+01:00' }] },
        network_beaconing: { available: true, connections: 7, endpoints: ['192.168.64.1:8769'], evidence_findings: [netFinding] },
        verdict: { label: 'MALICIOUS', score: 9, reasons: ['14 critical EDR alert(s)', '39 high/medium EDR alert(s)',
            'Named pipe matches a known C2 / tool default in pipesim.exe (sysmon-pipes; confidence 1.00)'] },
    };
    // What the results views say for each kind: the alerts they count, the memory findings by source
    const memory = [...results.memory_evidence.findings, ...results.memory_evidence.suppressed];
    const viewNumbers = () => ({ alerts: results.fibratus_alert_count, listed: results.fibratus_alerts.length,
        network: results.network_beaconing.evidence_findings.length, pipes: results.named_pipes.evidence_findings.length,
        sources: memory.map(f => f.source) });
"""


def _flow_values(flow):
    """The links of a flow by their ends, and what goes into and out of each node."""
    links = {(link["source"], link["target"]): link["value"] for link in flow["links"]}
    into = {n: sum(v for (_, t), v in links.items() if t == n) for column in flow["columns"] for n in column}
    out = {n: sum(v for (s, _), v in links.items() if s == n) for column in flow["columns"] for n in column}
    return links, into, out


@needs_node
def test_detonation_flow_sums_match_results():
    """VERDICT FLOW: each finding of the results flows once, from its process
    (left) through its kind (middle) to whether the verdict counted it
    (right). The kinds show the numbers of the results views: every EDR
    alert the server matched (also those beyond the 50 it lists, under
    "(not listed)"), the findings of the memory evidence by their source
    (exit capture, network beaconing and named pipes apart from live memory).
    Every EDR alert counts; a memory finding counts while the evidence
    reaches SUSPICIOUS and it keeps a weight, so the counted ones make up the
    evidence score. Processes in any case, the six with the most findings on
    their own. Empty results draw no flow, the card says "No findings"."""
    r = _run_node(VERDICT_FLOW_FUNCTIONS, VERDICT_FLOW_FIXTURE + r"""
        const ev = results.memory_evidence;
        const flags = detonationFindings(results).slice(-memory.length).map(f => f.counted);
        const r = {
            flow: detonationFlow(results), view: viewNumbers(),
            countedScore: memory.reduce((sum, f, i) => sum + (flags[i] ? f.score : 0), 0),
            weak: detonationFlow({ ...results, memory_evidence: { ...ev, label: 'CLEAN', score: 1.2 } }),
            noLabel: detonationFlow({ ...results, verdict: null }).labels['verdict:counted'],
            counts: ['many', NaN, Infinity, -5, null, 50, 49].map(count =>
                _flowValues(detonationFlow({ ...results, fibratus_alert_count: count }))),
            odd: detonationFlow({ verdict: { label: 'SUSPICIOUS' }, fibratus_alerts: [null, 7, 'x', { process_name: 'a.exe' }],
                memory_evidence: { score: 3, thresholds: { suspicious: 2 }, findings: [null, 'x', { source: '__proto__', score: 1, process: 'b.exe' },
                    { source: 'constructor', score: 2, process: 'b.exe' }, { source: 'toString', score: 0, process: 'B.EXE' }],
                    suppressed: 'nope' } }),
            empty: [detonationFlow({}), detonationFlow(null), detonationFlow({ verdict: { label: 'CLEAN', score: 0, reasons: [] },
                fibratus_alerts: [], fibratus_alert_count: 0, memory_evidence: { label: 'CLEAN', score: 0, findings: [], suppressed: [] },
                named_pipes: results.named_pipes && { ...results.named_pipes, evidence_findings: [] },
                network_beaconing: { available: true, connections: 2, endpoints: ['10.0.0.1:443'], evidence_findings: [] } })],
        };
        // A card of empty results says so, in its chart and in its table
        document.body.innerHTML = '<div id="det-results-panels"></div>';
        document.getElementById('det-results-panels').innerHTML = verdictFlowHtml({ verdict: { label: 'CLEAN', score: 0, reasons: [] } }, 'det');
        drawVerdictFlow('det');
        r.emptyCard = [(document.querySelector('#det-verdict-flow-chart .chart-empty') || { textContent: null }).textContent,
                       document.getElementById('det-verdict-flow-chart').querySelectorAll('svg').length,
                       document.querySelector('#det-verdict-flow-table tbody').textContent.trim()];
        console.log(JSON.stringify(r));
    """.replace("_flowValues", "(flow => flow.links.filter(l => l.source === 'kind:edr').reduce((s, l) => s + l.value, 0))"),
        _verdict_flow_js())
    flow = r["flow"]
    links, into, out = _flow_values(flow)
    assert flow["columns"][1] == FLOW_KINDS and flow["columns"][2] == ["verdict:counted", "verdict:not counted"]
    assert [flow["labels"][k] for k in FLOW_KINDS] == ["EDR alerts", "live memory", "exit capture", "network beaconing",
                                                       "named pipes"]
    assert flow["labels"]["verdict:counted"] == "counted (MALICIOUS)" and flow["labels"]["verdict:not counted"] == "not counted"
    # The kinds: each a number of the results views, a finding in exactly one of them
    view = r["view"]
    by_kind = {k: 0 for k in FLOW_KINDS}
    by_kind["kind:edr"] = view["alerts"]
    for source in view["sources"]:
        by_kind[FLOW_KIND_SOURCES.get(source, "kind:memory")] += 1
    assert by_kind["kind:network"] == view["network"] and by_kind["kind:pipes"] == view["pipes"]
    assert {k: into[k] for k in FLOW_KINDS} == {k: out[k] for k in FLOW_KINDS} == by_kind == \
        {"kind:edr": 53, "kind:memory": 6, "kind:exit": 3, "kind:network": 1, "kind:pipes": 3}, (into, out, by_kind)
    total = view["alerts"] + len(view["sources"])
    left = flow["columns"][0]
    assert sum(out[p] for p in left) == sum(into[k] for k in FLOW_KINDS) == sum(out[k] for k in FLOW_KINDS) == \
        sum(into[v] for v in flow["columns"][2]) == total == 66, "the columns do not add up to the findings"
    # What the verdict counted: every alert, the memory findings with a weight (the evidence reaches SUSPICIOUS)
    assert {pair: v for pair, v in links.items() if pair[0].startswith("kind:")} == {
        ("kind:edr", "verdict:counted"): 53, ("kind:memory", "verdict:counted"): 2, ("kind:memory", "verdict:not counted"): 4,
        ("kind:exit", "verdict:counted"): 1, ("kind:exit", "verdict:not counted"): 2, ("kind:network", "verdict:counted"): 1,
        ("kind:pipes", "verdict:counted"): 3}
    assert into["verdict:counted"] == 60 and into["verdict:not counted"] == 6
    assert abs(r["countedScore"] - 15.8) < 1e-9, "the counted memory findings do not make up the evidence score"
    # The processes: in any case and without blanks, by image when they have no name; six on their own
    assert left == ["process:pipesim.exe", "process:rundll32.exe", "process:(not listed)", "process:(unknown)",
                    "process:conhost.exe", "process:cmd.exe", "other processes"], left
    assert [out[p] for p in left] == [45, 6, 3, 3, 3, 2, 4]
    assert [flow["labels"][p] for p in left] == ["pipesim.exe", "rundll32.exe", "(not listed)", "(unknown)", "conhost.exe",
                                                 "cmd.exe", "other processes"]
    assert links[("process:(not listed)", "kind:edr")] == 3 and links[("process:(unknown)", "kind:memory")] == 1
    assert links[("other processes", "kind:memory")] == 1, "the suppressed finding of explorer.exe is lost"
    # Below SUSPICIOUS no memory finding counts ("weak memory findings only"); every alert still does
    w_links, w_into, _ = _flow_values(r["weak"])
    assert w_into["verdict:counted"] == 53 and w_into["verdict:not counted"] == 13
    assert all(t == "verdict:not counted" for (s, t) in w_links if s in FLOW_KINDS[1:])
    assert r["noLabel"] == "counted"
    # The alerts the server counted beyond those it lists; a count that is no number adds none
    assert r["counts"] == [50, 50, 50, 50, 50, 50, 50], r["counts"]
    odd_links, odd_into, odd_out = _flow_values(r["odd"])
    assert r["odd"]["columns"] == [["process:b.exe", "process:a.exe"], ["kind:edr", "kind:memory"],
                                   ["verdict:counted", "verdict:not counted"]], r["odd"]["columns"]
    assert odd_out["kind:memory"] == 3 and odd_into["verdict:not counted"] == 1 and odd_into["verdict:counted"] == 3
    for empty in r["empty"]:
        assert empty["columns"] == [[], [], []] and empty["links"] == [], empty
    assert r["emptyCard"] == ["No findings", 0, "No findings."], r["emptyCard"]


@needs_node
def test_verdict_flow_shows_the_litterbox_score_that_counted():
    """When the LitterBox score added points to the verdict (4 of 10 or more,
    as app.py's _compute_verdict counts it), VERDICT FLOW shows it: from
    "(sample file)", a node of its own whatever the processes, through the
    kind "LitterBox score" (first, where its band crosses none) to counted. A
    verdict LitterBox alone made MALICIOUS shows that instead of "No
    findings"; a lower score, one that is no number, or none adds nothing.
    The columns still add up, the processes stay as they were."""
    r = _run_node(VERDICT_FLOW_FUNCTIONS, VERDICT_FLOW_FIXTURE + r"""
        const only = score => ({ verdict: { label: score >= 7 ? 'MALICIOUS' : 'SUSPICIOUS', score: score >= 7 ? 3 : 1,
                                            reasons: [`LitterBox score ${score}/10`] }, litterbox_info: { score } });
        const scored = { ...results, litterbox_info: { score: 9.5 } };
        const r = {
            alone: detonationFlow(only(8)), four: detonationFlow(only(4)),
            none: [3.9, '8', null, true, NaN].map(score => detonationFlow({ ...only(score), verdict: { label: 'CLEAN', score: 0 } })),
            missing: [detonationFlow({ verdict: { label: 'CLEAN' }, litterbox_info: null }),
                      detonationFlow({ verdict: { label: 'CLEAN' }, litterbox_info: 'x' })],
            before: detonationFlow(results), all: detonationFlow(scored), colors: _verdictFlowColors(detonationFlow(scored), 'MALICIOUS'),
        };
        document.body.innerHTML = '<div id="det-results-panels"></div>';
        document.getElementById('det-results-panels').innerHTML = verdictFlowHtml(only(8), 'det');
        drawVerdictFlow('det');
        r.card = [(document.querySelector('#det-verdict-flow-chart .chart-empty') || { textContent: null }).textContent,
                  document.getElementById('det-verdict-flow-chart').querySelectorAll('.sankey-node').map(g => g.getAttribute('data-sankey-node')),
                  document.querySelector('#det-verdict-flow-table tbody').rows.map(row => row.cells.map(c => c.textContent.trim()))];
        console.log(JSON.stringify(r));
    """, _verdict_flow_js())
    alone = r["alone"]
    assert alone["columns"] == [["sample file"], ["kind:litterbox"], ["verdict:counted"]], alone["columns"]
    assert _flow_values(alone)[0] == {("sample file", "kind:litterbox"): 1, ("kind:litterbox", "verdict:counted"): 1}
    assert [alone["labels"][k] for k in ("sample file", "kind:litterbox", "verdict:counted")] == \
        ["(sample file)", "LitterBox score", "counted (MALICIOUS)"]
    four = r["four"]
    assert four["labels"]["verdict:counted"] == "counted (SUSPICIOUS)" and _flow_values(four)[0] == _flow_values(alone)[0]
    for flow in r["none"] + r["missing"]:
        assert flow["columns"] == [[], [], []] and flow["links"] == [], "a LitterBox score that added no points is in the flow"
    full, before = r["all"], r["before"]
    links, into, out = _flow_values(full)
    assert full["columns"][1] == ["kind:litterbox"] + FLOW_KINDS
    assert full["columns"][0] == ["sample file"] + before["columns"][0], "the LitterBox score took a process's place"
    assert out["sample file"] == into["kind:litterbox"] == links[("kind:litterbox", "verdict:counted")] == 1
    assert sum(out[p] for p in full["columns"][0]) == sum(into[v] for v in full["columns"][2]) == 66 + 1
    assert into["verdict:counted"] == 60 + 1 and into["verdict:not counted"] == 6
    colors = r["colors"]
    assert (colors["sample file"], colors["kind:litterbox"]) == ("var(--text-secondary)", "var(--accent-pink)")
    assert colors["process:pipesim.exe"] == _verdict_flow_colour_of_first_process(), "the processes changed their colours"
    empty, nodes, rows = r["card"]
    assert empty is None and nodes == ["sample file", "kind:litterbox", "verdict:counted"], \
        "a verdict LitterBox alone made shows no findings"
    assert sorted(rows) == [["(sample file)", "LitterBox score", "1"], ["LitterBox score", "counted (MALICIOUS)", "1"]]


def _verdict_flow_colour_of_first_process():
    """The colour VERDICT FLOW gives its first process: the first of the palette."""
    return re.search(r"'(var\(--[\w-]+\))'", _const_source("CHART_PALETTE")).group(1)


@needs_node
def test_the_litterbox_score_in_verdict_flow_is_the_one_the_verdict_counts(tdc):
    """VERDICT FLOW shows the LitterBox score exactly when app.py's
    _compute_verdict adds points for it: a number of 4 or more (of 10)."""
    scores = [0, 3, 3.9, 4, 6.5, 7, 10, "8", True, None]
    r = _run_node(VERDICT_FLOW_FUNCTIONS, r"""
        console.log(JSON.stringify(SCORES.map(score => detonationFindings({ litterbox_info: { score } })
            .some(f => f.kind === 'litterbox' && f.counted))));
    """.replace("SCORES", json.dumps(scores)), _verdict_flow_js())
    counted = [tdc._compute_verdict({"litterbox_info": {"score": score}}, [])["score"] > 0 for score in scores]
    assert r == counted == [False, False, False, True, True, True, True, False, False, False], (r, counted)


class _Reply:
    """A reply of LitterBox as _fetch_many returns it."""
    def __init__(self, body):
        self.status_code, self._body, self.text = 200, body, json.dumps(body)

    def json(self):
        return self._body


@needs_node
@pytest.mark.parametrize("score", [8, 3])
def test_verdict_flow_of_a_verdict_litterbox_alone_made(tdc, client, monkeypatch, score):
    """/api/detonation/results of a sample LitterBox scored, without an EDR
    alert or a memory scan: at 8 of 10 the verdict is MALICIOUS from that
    score alone, and VERDICT FLOW shows it counted; at 3 the verdict is
    CLEAN without a reason, and the flow has no findings."""
    sha = "ab" * 32
    monkeypatch.setattr(tdc, "_litterbox_online", lambda: True)
    monkeypatch.setattr(tdc, "_fetch_many", lambda specs: {
        name: _Reply({"score": score, "filename": "evil.exe"} if name == "lb_info" else {}) for name in specs if name.startswith("lb_")})
    monkeypatch.setattr(tdc, "_is_fibratus_running", lambda: False)
    monkeypatch.setattr(tdc, "_is_rustinel_running", lambda: False)
    d = client.get(f"/api/detonation/results?sha256={sha}&filename=evil.exe").get_json()
    r = _run_node(VERDICT_FLOW_FUNCTIONS, "console.log(JSON.stringify(detonationFlow(RESULTS)));".replace("RESULTS", json.dumps(d)),
                  _verdict_flow_js())
    if score == 8:
        assert d["verdict"] == {"label": "MALICIOUS", "score": 3, "reasons": ["LitterBox score 8/10"]}, d["verdict"]
        assert r["columns"] == [["sample file"], ["kind:litterbox"], ["verdict:counted"]]
        assert r["labels"]["verdict:counted"] == "counted (MALICIOUS)"
    else:
        assert d["verdict"] == {"label": "CLEAN", "score": 0, "reasons": []}, d["verdict"]
        assert r["columns"] == [[], [], []] and r["links"] == []


def _detonation_payload(tdc, client, monkeypatch, weak):
    """/api/detonation/results of beaconsim.exe (PID 4242) as the server builds
    it from its sources: 53 EDR alerts; Aether (a heap table the host baseline
    knows, a high-risk signature, a weak one), a Process Dump chunk, the exit
    capture, network beaconing and two pipe findings. Weak: one weak Aether
    signature and no alerts."""
    from memory_evidence import MemoryFinding
    me, sha, image = tdc.memory_evidence, "ab" * 32, r"C:\Users\Public\Downloads\beaconsim.exe"
    for name, value in (("_fetch_many", {}), ("_litterbox_online", False), ("_is_fibratus_running", False),
                        ("_is_rustinel_running", False)):
        monkeypatch.setattr(tdc, name, lambda *args, value=value: value)
    weak_signature = MemoryFinding(source="aether", kind="memory_signature", process=image, detail="STRINGS: kernel32.dll",
                                   identity=("STRINGS", "kernel32.dll"), weight=0.2)
    store = tdc._beacon_results_cache
    if weak:
        store.put("aether", {"observed": True, "evidence_findings": [weak_signature]}, pid="4242", sha256=sha)
        monkeypatch.setattr(tdc, "_network_beaconing_for_pid", lambda pid: {"available": True, "connections": 0,
                                                                             "endpoints": [], "evidence_findings": []})
        monkeypatch.setattr(tdc, "_pipe_activity_for", lambda pid, sha256=None: {"available": True, "truncated": False,
                                                                                  "pipes": [], "evidence_findings": []})
    else:
        tdc._store_alerts([make_alert(i, 4242, f"2026-11-05T10:37:{i % 60:02d}Z", image,
                                      severity=("critical", "high", "medium", "low")[i % 4]) for i in range(53)])
        heap = MemoryFinding(source="aether", kind="heap_api_table", process=image, detail="5 ptrs across 3 modules",
                             identity=(64, "beaconsim.exe,kernel32.dll,ws2_32.dll"))
        tdc._memory_baseline.add([heap])
        signature = MemoryFinding(source="aether", kind="memory_signature", process=image,
                                  detail=r"C2_TCP: \\.\pipe\msagent_", identity=("C2_TCP", r"\\.\pipe\msagent_"),
                                  weight=2.0, extra={"risk_score": 8, "needs_corroboration": False})
        store.put("aether", {"observed": True, "evidence_findings": [heap, signature, weak_signature]}, pid="4242", sha256=sha)
        store.put("processdump", {"dumps": [{"kind": "codechunk", "filename": "chunk_0x1a0000.bin", "sha256": "cd" * 32,
                                             "size": 4096, "base_address": "0x1a0000"}]}, pid="4242", sha256=sha)
        store.put("exitcapture", {"observed": True, "captured": True, "artifacts": [], "evidence_findings": [
            MemoryFinding(source="exit-capture", kind="reflective_pe", process=image, detail="1 PE header(s) in private memory",
                          identity=("pe", 1))]}, pid="4242", sha256=sha)
        beacons = me.beaconing_from_connections([(1000.0 + 2 * i, "192.168.64.1", 8769) for i in range(7)], process=image)
        monkeypatch.setattr(tdc, "_network_beaconing_for_pid", lambda pid: {
            "available": True, "connections": 7, "endpoints": ["192.168.64.1:8769"], "evidence_findings": beacons})
        pipes = [MemoryFinding(source="sysmon-pipes", kind=kind, process=image, detail=r"\msagent_7d6e15",
                               identity=(r"\msagent_##",), weight=weight)
                 for kind, weight in (("pipe_c2_default", 4.0), ("pipe_cross_process", None))]
        monkeypatch.setattr(tdc, "_pipe_activity_for", lambda pid, sha256=None: {
            "available": True, "truncated": False, "evidence_findings": pipes,
            "pipes": [{"pipe": r"\msagent_7d6e15", "created_by": ["4242?"], "connected_by": ["1672"], "family": "Cobalt Strike",
                       "flags": ["c2_default", "cross_process"]}]})
    d = client.get(f"/api/detonation/results?pid=4242&sha256={sha}&filename=beaconsim.exe").get_json()
    return json.loads(json.dumps(d))


@needs_node
@pytest.mark.parametrize("weak", [False, True])
def test_verdict_flow_counts_what_the_verdict_counts(tdc, client, monkeypatch, weak):
    """The flow of results as app.py builds them (its memory evidence model
    and _compute_verdict): each kind is the number the results show, the
    counted memory findings are the ones with a weight once the evidence
    reaches SUSPICIOUS (they make up its score), the one the host baseline
    knows does not count; below SUSPICIOUS (the verdict says "not counted")
    none does, and the flow of a CLEAN verdict has no "counted"."""
    d = _detonation_payload(tdc, client, monkeypatch, weak)
    ev = d["memory_evidence"]
    memory = ev["findings"] + ev["suppressed"]
    r = _run_node(VERDICT_FLOW_FUNCTIONS, r"""
        const results = RESULTS;
        console.log(JSON.stringify({ flow: detonationFlow(results), found: detonationFindings(results) }));
    """.replace("RESULTS", json.dumps(d)), _verdict_flow_js())
    links, into, out = _flow_values(r["flow"])
    kinds = {k: 0 for k in FLOW_KINDS}
    kinds["kind:edr"] = d["fibratus_alert_count"]
    for f in memory:
        kinds[FLOW_KIND_SOURCES.get(f["source"], "kind:memory")] += 1
    assert kinds["kind:network"] == len(d["network_beaconing"]["evidence_findings"])
    assert kinds["kind:pipes"] == len(d["named_pipes"]["evidence_findings"])
    assert {k: into.get(k, 0) for k in FLOW_KINDS} == {k: out.get(k, 0) for k in FLOW_KINDS} == kinds
    flags = [f["counted"] for f in r["found"][-len(memory):]] if memory else []
    reached = ev["score"] >= ev["thresholds"]["suspicious"]
    assert flags == [reached and f["score"] > 0 for f in ev["findings"]] + [False] * len(ev["suppressed"])
    if weak:
        assert not reached and d["verdict"]["label"] == "CLEAN" and memory
        assert any("not counted" in reason for reason in d["verdict"]["reasons"]), d["verdict"]["reasons"]
        assert r["flow"]["columns"][2] == ["verdict:not counted"] and into["verdict:not counted"] == len(memory)
        return
    assert d["fibratus_alert_count"] == 53 and len(d["fibratus_alerts"]) == 50, "the server no longer lists 50 alerts"
    assert ev["suppressed_count"] == 1 and kinds == {"kind:edr": 53, "kind:memory": 4, "kind:exit": 1, "kind:network": 1,
                                                     "kind:pipes": 2}, kinds
    assert abs(sum(f["score"] for f, counted in zip(memory, flags) if counted) - ev["score"]) < 0.01, \
        "the counted memory findings do not make up the evidence score"
    assert r["flow"]["labels"]["verdict:counted"] == f"counted ({d['verdict']['label']})" and d["verdict"]["label"] == "MALICIOUS"
    assert into["verdict:counted"] == 53 + sum(flags) and into["verdict:not counted"] == len(memory) - sum(flags)
    assert links[("process:(not listed)", "kind:edr")] == 3 and links[("process:(unknown)", "kind:memory")] == 1


# The Submit tab with the panels of a detonation's results, and the detail
# panel; both views open at once. The card heads are as wide as the test
# says (widths), a ResizeObserver records what it observes, fetch serves the
# results.
RESULT_VIEWS_DOM = r"""
    document.body.innerHTML = MARKUP;
    const $ = id => document.getElementById(id);
    Element.prototype.insertAdjacentHTML = function (where, html) {
        if (where !== 'beforeend') throw new Error('insertAdjacentHTML ' + where + ' not supported by the test DOM');
        [...parseHTML(html)].forEach(n => this.appendChild(n));
    };
    $('submit-result').innerHTML = '<div class="det-results"><div class="det-panels" id="det-results-panels"></div></div>';
    globalThis.state = { processes: {}, detailHistory: [], detailOpen: false, activeTab: 'submit' };
    globalThis.noteDetonationVerdict = () => {};
    const widths = { 'det-verdict-flow-card': 700, 'detail-verdict-flow-card': 560 };
    const rectOf = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function () {
        const card = this.classList.contains('chart-card-head') ? this.closest('.verdict-flow-card') : null;
        return card ? { width: widths[card.id] || 0 } : rectOf.call(this);
    };
    const observed = new Set();
    let resizers = 0;
    globalThis.ResizeObserver = class {
        constructor(callback) { resizers++; this.callback = callback; }
        observe(el) { observed.add(el); }
        unobserve(el) { observed.delete(el); }
    };
    globalThis.requestAnimationFrame = fn => fn();
    let served = results;
    globalThis.fetch = async () => ({ ok: true, json: async () => JSON.parse(JSON.stringify(served)) });
    const before = ['img', 'script'].map(t => document.querySelectorAll(t).length);
"""

# What the card of a view (scope 'det' or 'detail') shows
RESULT_VIEWS_LOOK = r"""
    const paint = el => (el ? el.getAttribute('style') || '' : '').replace(/^(?:fill|background):/, '');
    const look = scope => {
        const card = $(`${scope}-verdict-flow-card`);
        if (!card) return null;
        const chart = $(`${scope}-verdict-flow-chart`), tableView = $(`${scope}-verdict-flow-table`);
        const svg = chart.querySelector('svg'), table = tableView.querySelector('table'), rows = table.tBodies[0].rows;
        const linear = $(`${scope}-verdict-flow-linear`), title = card.querySelector('.chart-card-title');
        return {
            title: title.textContent.trim(), info: title.getAttribute('data-info'),
            linear: [linear.textContent, linear.getAttribute('aria-pressed'), linear.hidden],
            toggle: card.querySelectorAll('.view-toggle[data-view-toggle]').map(b => [b.getAttribute('data-view-toggle'), b.textContent]),
            hidden: [chart.hidden, tableView.hidden],
            clickable: card.querySelectorAll('.chart-clickable').length + chart.querySelectorAll('[onclick]').length
                + (chart.hasAttribute('onclick') ? 1 : 0),
            width: svg ? Number(svg.getAttribute('width')) : null,
            svg,
            nodes: chart.querySelectorAll('.sankey-node').map(g => [g.getAttribute('data-sankey-node'), Number(g.getAttribute('data-value')),
                Number(g.querySelector('.sankey-bar').getAttribute('height')), paint(g.querySelector('.sankey-bar')),
                g.querySelector('title').textContent]),
            bands: chart.querySelectorAll('.sankey-link').map(p => [p.getAttribute('data-source'), p.getAttribute('data-target'),
                Number(p.getAttribute('data-value')), p.querySelector('title').textContent]),
            empty: (chart.querySelector('.chart-empty') || { textContent: null }).textContent,
            table: { id: table.getAttribute('data-sort-id'), sortable: table.hasAttribute('data-sortable'),
                     head: table.tHead.rows[0].cells.map(c => c.textContent.trim()),
                     rows: rows.filter(row => !row.hasAttribute('data-sort-skip'))
                         .map(row => row.cells.map(c => [c.textContent.trim(), c.getAttribute('data-sort-value'), c.getAttribute('title')])),
                     notes: rows.filter(row => row.hasAttribute('data-sort-skip')).map(row => row.textContent.trim()) },
        };
    };
    const plain = view => view && Object.fromEntries(Object.entries(view).filter(([k]) => k !== 'svg'));
    const height = (view, id) => view.nodes.find(n => n[0] === id)[2];
    const duplicateIds = () => {
        const seen = new Map();
        for (const el of document.documentElement.walk()) if (el.id) seen.set(el.id, (seen.get(el.id) || 0) + 1);
        return [...seen].filter(([, n]) => n > 1).map(([id]) => id);
    };
    const parts = holder => holder.children.map(el => el.id || el.className.trim());
"""


def _result_views_script(script):
    detail = _read(INDEX_HTML)
    markup = _tab_markup("submit") + _element_markup(detail, detail.index('<div id="detail-panel"'))
    return ((VERDICT_FLOW_FIXTURE + RESULT_VIEWS_DOM + RESULT_VIEWS_LOOK + script)
            .replace("EVIL", json.dumps(EVIL)).replace("QUOTE", json.dumps(QUOTE)).replace("MARKUP", json.dumps(markup)))


@needs_node
def test_verdict_flow_card_in_both_result_views():
    """The Submit tab's results and the detail panel draw VERDICT FLOW with
    the same function, under the verdict (before the tabs, before LIVE
    MEMORY): a card with its (i), LINEAR and CHART / TABLE, the Sankey of
    detonationFlow for the width of the card, a sortable table of its bands
    (source, target, count). Both open at once share no element id, sort
    order, LINEAR or TABLE; a poll keeps what was chosen. The flow sets no
    filter (nothing looks clickable). A process name from the sample stays
    text; results without findings say so, results without a verdict draw
    no card."""
    r = _run_node(RESULT_VIEW_FUNCTIONS, _result_views_script(r"""
        (async () => {
            renderDetonationPanels(results);
            await viewDetonationResult('', SHA, '9664', 'pipesim.exe');
            const flow = detonationFlow(results);
            const r = { det: plain(look('det')), detail: plain(look('detail')), flow, duplicates: duplicateIds(),
                        submitParts: parts($('det-results-panels')), detailParts: parts($('detail-body')),
                        observed: [resizers, observed.size] };
            // LINEAR in the Submit tab only; a poll renders the panels again and keeps it
            const ratio = view => height(view, 'kind:edr') / height(view, 'kind:network');
            r.sqrt = [ratio(look('det')), ratio(look('detail'))];
            click($('det-verdict-flow-linear'));
            r.linear = [ratio(look('det')), ratio(look('detail')), look('det').linear, look('detail').linear];
            renderDetonationPanels(results);
            r.polled = [ratio(look('det')), look('det').linear, observed.size];
            click($('det-verdict-flow-linear'));
            r.back = [ratio(look('det')), look('det').linear];
            // TABLE in the Submit tab only, kept by a poll; LINEAR goes with the chart
            click($('det-verdict-flow-card').querySelector('.view-toggle[data-view-toggle]'));
            renderDetonationPanels(results);
            r.table = [look('det').hidden, look('det').linear[2], look('detail').hidden];
            toggleCardView('det-verdict-flow');
            // New widths: drawn again where the width changed; the same width or a hidden card (0): left as it is
            const svgs = [look('det').svg, look('detail').svg];
            widths['det-verdict-flow-card'] = 520;
            redrawVerdictFlowsOnResize();
            r.resized = [look('det').width, look('detail').width, look('detail').svg === svgs[1]];
            widths['det-verdict-flow-card'] = 0;
            const drawn = look('det').svg;
            redrawVerdictFlowsOnResize();
            r.hiddenKept = look('det').svg === drawn;
            // A click on a node or a band sets nothing and changes nothing
            const state0 = JSON.stringify([verdictFlowView, cardViewState]), svg0 = look('det').svg;
            click($('det-verdict-flow-chart').querySelector('.sankey-node'));
            click($('det-verdict-flow-chart').querySelector('.sankey-link'));
            r.clicked = look('det').svg === svg0 && JSON.stringify([verdictFlowView, cardViewState]) === state0;
            // Process names from the sample
            const hostile = { ...results, fibratus_alerts: [{ ...results.fibratus_alerts[0], process_name: EVIL },
                                                             { ...results.fibratus_alerts[1], process_name: QUOTE }],
                              fibratus_alert_count: 2, memory_evidence: undefined };
            widths['det-verdict-flow-card'] = 700;
            renderDetonationPanels(hostile);
            r.hostile = { view: plain(look('det')), markup: ['img', 'script'].map(t => document.querySelectorAll(t).length),
                          ids: $('det-verdict-flow-chart').querySelectorAll('.sankey-node').map(g => g.getAttribute('data-sankey-node')) };
            // No findings; no verdict
            renderDetonationPanels({ ...results, fibratus_alerts: [], fibratus_alert_count: 0, memory_evidence: undefined,
                                     named_pipes: undefined, network_beaconing: undefined, verdict: { label: 'CLEAN', score: 0, reasons: [] } });
            r.none = plain(look('det'));
            renderDetonationPanels({ ...results, verdict: undefined });
            served = { ...results, verdict: undefined };
            await viewDetonationResult('', SHA, '9664', 'pipesim.exe');
            r.unjudged = [plain(look('det')), plain(look('detail')), _verdictFlowDrawn.det, _verdictFlowDrawn.detail, observed.size];
            r.before = before;
            console.log(JSON.stringify(r));
        })();
    """), _verdict_flow_js())
    flow, det, detail = r["flow"], r["det"], r["detail"]
    assert r["duplicates"] == [], f"the two results views share element ids: {r['duplicates']}"
    assert r["submitParts"][:3] == ["det-verdict det-verdict-malicious", "det-ioc-badge", "det-verdict-flow-card"] and \
        r["submitParts"][3] == "det-tabs", f"not under the verdict, before the tabs: {r['submitParts']}"
    i = r["detailParts"].index("detail-verdict-flow-card")
    assert r["detailParts"][i - 1].startswith("det-ioc-badge") and r["detailParts"][i - 2].startswith("det-verdict ") and \
        r["detailParts"][i + 1] == "detail-section", f"not under the banner, before LIVE MEMORY: {r['detailParts']}"
    ids = [n for column in flow["columns"] for n in column]
    _, into, out = _flow_values(flow)
    for scope, view, width in (("det", det, 700), ("detail", detail, 560)):
        assert view["title"] == "VERDICT FLOW", scope
        for word in ("counted", "baseline", "SUSPICIOUS", "(not listed)", "pipe findings", "LINEAR", "LitterBox score",
                     "(sample file)"):
            assert word in view["info"], f"{scope}: the (i) does not explain {word}"
        assert view["linear"] == ["LINEAR", "false", False] and view["toggle"] == [[f"{scope}-verdict-flow", "TABLE"]]
        assert view["hidden"] == [False, True] and view["clickable"] == 0, f"{scope}: the flow looks clickable"
        assert view["width"] == width, f"{scope}: not drawn for the width of its card"
        assert [n[0] for n in view["nodes"]] == ids and all(n[1] == max(into[n[0]], out[n[0]]) for n in view["nodes"])
        assert sorted(b[:3] for b in view["bands"]) == sorted([l["source"], l["target"], l["value"]] for l in flow["links"])
        t = view["table"]
        assert t["id"] == f"{scope}-verdict-flow" and t["sortable"] and t["head"] == ["Source", "Target", "Count"]
        assert sorted([row[0][0], row[1][0], int(row[2][1])] for row in t["rows"]) == \
            sorted([flow["labels"][l["source"]], flow["labels"][l["target"]], l["value"]] for l in flow["links"]), \
            f"{scope}: the table lists other numbers than the bands"
        colours = {n[0]: n[3] for n in view["nodes"]}
        assert colours["verdict:counted"] == "var(--severity-critical)" and colours["verdict:not counted"] == "var(--text-muted)"
        assert colours["other processes"] == "var(--text-muted)" and colours["kind:network"] == "var(--graph-network)"
        assert all(c.startswith("var(--") for c in colours.values()), colours
    assert ("process:pipesim.exe", "kind:edr") in {(b[0], b[1]) for b in det["bands"]}
    assert "pipesim.exe \u2192 EDR alerts: 34" in [b[3] for b in det["bands"]]
    assert r["observed"] == [1, 2], "the cards are not watched for a new width, or each by an observer of its own"
    # LINEAR: square roots, then true proportions in that view only; a poll keeps it
    assert all(abs(x - 53 ** 0.5) < 0.05 for x in r["sqrt"]), r["sqrt"]
    assert abs(r["linear"][0] - 53) < 0.05 and abs(r["linear"][1] - 53 ** 0.5) < 0.05, r["linear"]
    assert r["linear"][2][1] == "true" and r["linear"][3][1] == "false"
    assert abs(r["polled"][0] - 53) < 0.05 and r["polled"][1][1] == "true", "a poll lost LINEAR"
    assert r["polled"][2] == 2, "the card of an earlier poll is still observed"
    assert abs(r["back"][0] - 53 ** 0.5) < 0.05 and r["back"][1][1] == "false"
    assert r["table"] == [[True, False], True, [False, True]], "TABLE was lost on a poll, went to the other view, or LINEAR shows beside it"
    assert r["resized"] == [520, 560, True] and r["hiddenKept"], "drawn again for the same width, or while hidden"
    assert r["clicked"], "a click on the flow changed it"
    hostile = r["hostile"]
    assert hostile["markup"] == r["before"], "a process name from the sample became markup"
    assert {"process:" + EVIL, "process:" + QUOTE} <= set(hostile["ids"]), hostile["ids"]
    assert {f"{EVIL} \u2192 EDR alerts: 1", f"{QUOTE} \u2192 EDR alerts: 1"} <= {b[3] for b in hostile["view"]["bands"]}
    cells = {row[0][0]: row[0][2] for row in hostile["view"]["table"]["rows"]}
    assert cells.get(EVIL) == EVIL and cells.get(QUOTE) == QUOTE, "a name in the table is cut or left its attribute"
    none = r["none"]
    assert none["nodes"] == [] and none["empty"] == "No findings" and none["table"]["notes"] == ["No findings."]
    assert r["unjudged"] == [None, None, None, None, 0], "results without a verdict draw a card, or one stays observed"
    for name in ("renderDetonationPanels", "viewDetonationResult"):
        source = _function_source(name)
        assert source.count("verdictFlowHtml(") == 1 and source.count("drawVerdictFlow(") == 1, name
    assert "'det')" in _function_source("renderDetonationPanels") and "'detail')" in _function_source("viewDetonationResult")
    source = "\n".join(_strip_js_comments(_function_source(n)) for n in VERDICT_FLOW_OWN)
    source += "\n".join(_const_source(c) for c in ("VERDICT_FLOW_KINDS", "VERDICT_FLOW_SOURCES"))
    assert not LITERAL_COLOR.findall(source) and not NAMED_COLOUR.search(source), "a colour that is no theme variable"
    rules = _rules(STYLE_CSS)
    assert re.search(r"margin:", rules.get(".verdict-flow-card", "")), "the card sticks to the verdict"
    assert re.search(r"min-width:\s*0", rules.get(".verdict-flow-view", ""))
    assert re.search(r"overflow(?:-y)?:\s*auto", rules.get(".verdict-flow-table", "")) and \
        re.search(r"max-height:", rules.get(".verdict-flow-table", "")), "a long table stretches the results"
    assert re.search(r"position:\s*sticky", rules.get(".verdict-flow-table .view-table th", ""))
    assert re.search(r"max-width:\s*none", rules.get(".verdict-flow-table .view-table td:nth-child(2)", "")), \
        "the table cuts the names of the kinds and of the verdict"
    assert re.search(r"background:\s*transparent", rules.get(".verdict-flow-table::-webkit-scrollbar-corner", ""))


@needs_node
def test_the_results_stay_when_polling_gives_up():
    """After its last poll (an EDR that is online but matched no alert keeps
    the results from being ready) the Submit tab keeps the results it drew,
    VERDICT FLOW with them, and says once that polling is complete, as it
    does when all results are in; it does not replace them with that note."""
    r = _run_node(RESULT_VIEW_FUNCTIONS + ["pollDetonationResults", "endDetonationPolling"], _result_views_script(r"""
        renderDetonationPanels(results);
        let fetched = 0;
        globalThis.fetch = async () => { fetched++; return { json: async () => results }; };
        pollDetonationResults(SHA, '9664', '', 'pipesim.exe', 30);
        pollDetonationResults(SHA, '9664', '', 'pipesim.exe', 31);
        console.log(JSON.stringify({ card: !!$('det-verdict-flow-card'),
            svg: !!($('det-verdict-flow-chart') && $('det-verdict-flow-chart').querySelector('svg')),
            parts: parts($('det-results-panels')), fetched,
            notes: $('det-results-panels').querySelectorAll('.det-poll-done').map(n => n.textContent) }));
    """), _verdict_flow_js() + "\nlet _detonationPollTimer = null;\nlet _detonationPollGen = 0;\n")
    assert r["card"] and r["svg"], "the last poll took VERDICT FLOW away"
    assert r["parts"][:4] == ["det-verdict det-verdict-malicious", "det-ioc-badge", "det-verdict-flow-card", "det-tabs"] and \
        r["parts"][-1] == "det-poll-done", r["parts"]
    assert r["notes"] == ["Polling complete. Results shown above reflect final state."] and r["fetched"] == 0


@needs_node
def test_polling_ends_without_a_spinner():
    """A detonation whose results never came (no poll was answered: the
    server out of reach, or an error page instead of JSON) kept its spinner
    turning after polling had ended, under a note that pointed at results
    above. Now polling ends with one note and no spinner: that no results
    were received. Results that come after failed polls take the spinner's
    place; the note under them says which services are offline."""
    r = _run_node(RESULT_VIEW_FUNCTIONS + ["renderDetonationResults", "pollDetonationResults", "endDetonationPolling"],
                  _result_views_script(r"""
        (async () => {
            const realTimeout = setTimeout, tick = () => new Promise(resolve => realTimeout(resolve, 0));
            // The polls 5 s apart, run one after the other as soon as the last one is done
            const timers = [];
            globalThis.setTimeout = fn => timers.push(fn);
            globalThis.clearTimeout = () => {};
            const detonate = async answer => {
                let fetched = 0;
                globalThis.fetch = () => answer(++fetched);
                const submit = $('submit-result');
                renderDetonationResults({ file_info: { agent_pid: 9664, sha256: SHA, name: 'pipesim.exe' }, agent: { status: 200 } }, submit);
                const spinning = submit.querySelectorAll('.det-panel-loading').length;
                for (let i = 0; i < 100; i++) {
                    await tick();
                    if (!timers.length) break;
                    timers.shift()();
                }
                const panels = $('det-results-panels');
                return { spinning, fetched, left: timers.length, parts: parts(panels),
                         spinners: submit.querySelectorAll('.loading-spinner').length + submit.querySelectorAll('.det-panel-loading').length,
                         notes: panels.querySelectorAll('.det-poll-done').map(n => n.textContent) };
            };
            const unreachable = () => Promise.reject(new TypeError('Failed to fetch'));
            const errorPage = async () => ({ json: async () => { throw new SyntaxError("Unexpected token '<'"); } });
            const offline = { ready: { static: true, dynamic: true, fibratus: true }, litterbox_online: false,
                              edr_status: { fibratus_online: false, rustinel_online: false } };
            console.log(JSON.stringify({
                unreachable: await detonate(unreachable),
                errorPage: await detonate(errorPage),
                late: await detonate(n => n <= 3 ? unreachable() : Promise.resolve({ json: async () => JSON.parse(JSON.stringify(results)) })),
                offline: await detonate(async () => ({ json: async () => offline })),
            }));
        })();
    """), _verdict_flow_js() + "\nlet _detonationPollTimer = null;\nlet _detonationPollGen = 0;\n")
    for case in ("unreachable", "errorPage"):
        assert r[case]["spinning"] == 1 and r[case]["fetched"] == 30 and r[case]["left"] == 0, r[case]
        assert r[case]["spinners"] == 0, f"{case}: the spinner turns on after polling ended"
        assert r[case]["parts"] == ["det-poll-done"] and r[case]["notes"] == ["Polling complete. No results were received."], r[case]
    # LitterBox offline: done at the first answer, three polls after the two it waits at least
    late = r["late"]
    assert late["fetched"] == 4 and late["spinners"] == 0 and late["left"] == 0, late
    assert late["parts"][:3] == ["det-verdict det-verdict-malicious", "det-ioc-badge", "det-verdict-flow-card"] and \
        late["parts"][-1] == "det-poll-done", late["parts"]
    assert late["notes"] == ["Polling complete. LitterBox offline — static/dynamic analysis unavailable."]
    assert r["offline"]["fetched"] == 2 and r["offline"]["spinners"] == 0 and r["offline"]["parts"] == ["det-tabs", "det-poll-done"]
    assert r["offline"]["notes"] == ["Polling complete. All analysis services offline — no results available."]
