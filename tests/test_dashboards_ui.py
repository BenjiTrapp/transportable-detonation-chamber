"""Own dashboards on the Dashboard tab (block "Own dashboard pages" of
static/js/app.js, .dashboard-pages and .dashboard-own of #tab-dashboard).

Regressions covered:
  * the page row losing SERVICES, putting + NEW anywhere but last, or showing
    both bodies at once; a stored page that is gone leaving the tab empty
  * a dashboard or tile name from the file (an analyst types it, a sample's
    text can reach it through a query) arriving as markup
  * the tiles of a page searching all at once, which is eight searches over
    10,000 matches on the VM that also detonates
  * a tile that keeps "Queued" after its run was taken over, or draws an
    answer that belongs to the page before it
  * an error of one tile wiping the numbers of the others, or hiding in a
    toast instead of standing on the tile
  * a tile whose saved form no longer fits the columns drawing an empty box
    instead of its table and the reason
  * a table tile drawing more than 20 rows of raw log text, or a picture tile
    asking for 200 rows and silently showing a part of its groups
  * the ⋯ writing more than one field, or working from a list another browser
    tab has changed in the meantime
  * the Refresh button of the header computing tiles on SERVICES, or the 10 s
    poll computing them at all
"""

import json
import re

from test_frontend import SOURCE, _function_source, _run_node, needs_node
from test_logs_ui import ALL_FUNCTIONS as LOGS_FUNCTIONS, ELEMENT_IDS as LOGS_IDS, LOGS_CONSTS, LOGS_LETS, _rule_bodies
from test_theme import (CHART_CONSTS, DASHBOARD_CHART_CONSTS, DASHBOARD_CHART_FUNCTIONS, INDEX_HTML, LITERAL_COLOR,
                        STYLE_CSS, THEME_CSS, _const_source, _css_blocks, _Elements, _read, _strip_comments)

# The functions of the pages and the tiles, which build on the LOGS tab (the
# shape of a result, its forms, its chart and its table) and on switchTab
DASHBOARD_IDS = ["dashboard-pages", "dashboard-body", "dashboard-own", "dashboard-own-head", "dashboard-panels",
                 "tab-dashboard", "tab-logs"]
# Written by JS into the head of the page, so the markup test must not look for it
OWN_IDS = ["dashboard-own-time"]
ALL_FUNCTIONS = list(dict.fromkeys(LOGS_FUNCTIONS + DASHBOARD_CHART_FUNCTIONS + ["switchTab", "refreshDashboard"]))
ALL_IDS = list(dict.fromkeys(LOGS_IDS + DASHBOARD_IDS + OWN_IDS))

PRELUDE = "\n".join(_const_source(name) for name in CHART_CONSTS + LOGS_CONSTS + DASHBOARD_CHART_CONSTS) \
    + "\n" + "\n".join(LOGS_LETS) + r"""
const classes = () => {
    const set = new Set();
    return { add: c => set.add(c), remove: c => set.delete(c), contains: c => set.has(c), toggle: c => set.add(c) };
};
const els = {};
// A card of a tile is replaced in its place (outerHTML); `cardWrites` holds
// every such replacement, so a test can see that one card was drawn and the
// others were not. The ids of the cards are added by the test that wants the
// single-card path — without them renderPanelCard draws the whole page, which
// is what the other tests read.
const cardWrites = [];
const makeEl = id => {
    const el = { id, innerHTML: '', textContent: '', value: '', hidden: false, title: '', style: {}, attrs: {},
        listeners: {}, scrollLeft: 0, classList: classes(), caret: null, focused: 0, disabled: false, _outer: '',
        setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
        focus() { this.focused++; }, setSelectionRange(from, to) { this.caret = [from, to]; },
        contains: () => false, getBoundingClientRect: () => ({ width: 1200 }), querySelectorAll: () => [] };
    Object.defineProperty(el, 'outerHTML', {
        get() { return el._outer; },
        set(value) { el._outer = value; cardWrites.push([id, value]); },
    });
    return el;
};
for (const id of %s) {
    els[id] = makeEl(id);
}
globalThis.document = { hidden: false, getElementById: id => els[id] || null, addEventListener() {},
    querySelector: () => ({ classList: classes() }), querySelectorAll: () => [] };
globalThis.state = { activeTab: 'dashboard' };
const store = {};
globalThis.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; } };
globalThis.tableSortState = {};
globalThis.barsBrushActive = () => false;
globalThis.barsClickPeriod = () => null;
globalThis.initBarsBrush = () => {};
globalThis._alertsChartInert = () => {};
// Enough of the other layers: the tab bar, the service cards and the toasts
globalThis.updateTabOverflow = () => {};
globalThis.renderDashboard = () => {};
globalThis.updateServiceStatus = () => {};
globalThis.releaseDashboardCounts = () => {};
globalThis.viewToggleHtml = () => '';
const toasts = [];
globalThis.showToast = (...args) => { toasts.push(args); };
// Enough of the other layers for handleGlobalKeydown: none of them is open
globalThis.TOPBAR_MENUS = {};
globalThis.isTopbarMenuOpen = () => false;
globalThis.closeTopbarMenus = () => {};
globalThis.isDrawerOpen = () => false;
globalThis.closeDrawer = () => {};
globalThis.closeDetail = () => {};
globalThis.closeInfoPopover = () => ({ focus() {} });
// What the analyst answers in a prompt / a confirm; `asked` holds every question
const asked = [];
let answerPrompt = null, answerConfirm = true;
globalThis.prompt = (text, value) => { asked.push(['prompt', text, value]); return answerPrompt; };
globalThis.confirm = text => { asked.push(['confirm', text]); return answerConfirm; };

const reply = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
const board = (id, name, panels) => ({ id, name, created: '2026-11-16T09:00:00Z', panels: panels || [] });
const panel = (id, name, query, form, earliest = '-24h', latest = '') =>
    ({ id, name, query, form, earliest, latest, created: '2026-11-16T09:00:00Z' });
const table = (columns, rows, extra = {}) => ({ type: 'table', events: [], columns, rows, count: rows.length,
    matched: rows.length, truncated: false, histogram: { bins: [], span_s: 60 }, fields: [], took_ms: 1.5, ...extra });
const timechart = (columns, rows, extra = {}) => ({ ...table(columns, rows), type: 'timechart', ...extra });
const events = (list, extra = {}) => ({ type: 'events', events: list, columns: null, rows: [], count: list.length,
    matched: list.length, truncated: false, histogram: { bins: [], span_s: 60 }, fields: [], took_ms: 3.2, ...extra });

// The server: `boards` is what GET /api/dashboards answers, `answers` what a
// search answers per query ({status, data}), `writes` every write and `reads`
// every read of the list. With `hold` on, every search waits at a gate the
// test opens, so a test can see how many run at once.
let boards = [], answers = {}, writeAnswer = null, listAnswer = null, hold = false;
const reads = [], writes = [], searches = [], gates = [];
let openNow = 0, peak = 0;
const release = () => { while (gates.length) gates.shift()(); };
globalThis.fetch = async (url, opts) => {
    const method = (opts && opts.method) || 'GET';
    if (url.startsWith('/api/logs/search')) {
        searches.push(url);
        const q = new URL('http://x' + url).searchParams.get('q');
        openNow++;
        peak = Math.max(peak, openNow);
        if (hold) {
            await new Promise((go, stop) => {
                gates.push(go);
                const signal = opts && opts.signal;
                if (signal) signal.addEventListener('abort', () => {
                    const err = new Error('aborted');
                    err.name = 'AbortError';
                    stop(err);
                });
            }).finally(() => { openNow--; });
        } else {
            openNow--;
        }
        const found = answers[q] || { status: 200, data: events([]) };
        return reply(found.data, found.status);
    }
    if (url.startsWith('/api/dashboards')) {
        if (method === 'GET') {
            reads.push(url);
            return listAnswer ? reply(listAnswer.data, listAnswer.status) : reply({ dashboards: boards });
        }
        writes.push({ url, method, body: opts && opts.body ? JSON.parse(opts.body) : null });
        if (writeAnswer) return reply(writeAnswer.data, writeAnswer.status);
        if (method === 'POST') {
            const made = board('d-new' + writes.length, (opts && JSON.parse(opts.body).name) || '', []);
            boards = [...boards, made];
            return reply({ dashboard: made }, 201);
        }
        return reply({ deleted: true });
    }
    if (url.startsWith('/api/logs/sources')) return reply([]);
    return reply({});
};
const tick = (n = 1) => new Promise(go => { let left = n; const step = () => (left-- > 0 ? Promise.resolve().then(step) : go()); step(); });
const limits = () => searches.map(u => new URL('http://x' + u).searchParams.get('limit'));
const queries = () => searches.map(u => new URL('http://x' + u).searchParams.get('q'));
const panels = () => els['dashboard-panels'].innerHTML;
const pageRow = () => els['dashboard-pages'].innerHTML;
""" % json.dumps(ALL_IDS)


def _run(script):
    return _run_node(ALL_FUNCTIONS, "(async () => {\n" + script + "\n})();", PRELUDE)


HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(1)>"
ALLOWED_TAGS = {"div", "button", "span", "pre", "mark", "code", "ul", "li", "strong", "table", "thead", "tbody", "tr",
                "th", "td", "h3", "svg", "g", "rect", "path", "circle", "text", "line", "polyline", "title", "tspan"}


def _tags(html):
    return set(re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", html))


def _handlers(markup):
    """Every on*="..." of a piece of markup. Nothing but the calls of the page
    may stand there: a value from the file reaching a handler would run."""
    return set(re.findall(r'\bon[a-z]+="([^"]*)"', markup))


# --- Markup -----------------------------------------------------------------------

def test_the_pages_and_the_own_page_sit_in_the_dashboard_tab():
    html = _read(INDEX_HTML)
    tab = _Elements(html).by_id("tab-dashboard")
    assert tab

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def cls(node, name):
        return name in node["attrs"].get("class", "").split()

    # The row of pages stands between the header and the two bodies; no second
    # .content-header comes with it (the tab count stays at 12)
    parts = [c["attrs"].get("id") or c["attrs"].get("class") for c in tab["children"]]
    assert parts == ["content-header", "dashboard-pages", "dashboard-body", "dashboard-own"], parts
    assert len(find(tab, lambda e: cls(e, "content-header"))) == 1
    # The children of .dashboard-body are the ones tests/test_charts.py pins
    body = find(tab, lambda e: cls(e, "dashboard-body"))[0]
    assert [c["attrs"].get("id") or c["attrs"].get("class") for c in body["children"]] == \
        ["dashboard-stats", "dashboard-charts", "dashboard-grid", "tool-updates", "dashboard-activity"]
    own = find(tab, lambda e: cls(e, "dashboard-own"))[0]
    assert "hidden" in own["attrs"], "the own page stands open over SERVICES"
    ids = {n["attrs"]["id"] for n in find(tab, lambda e: "id" in e["attrs"])}
    assert set(DASHBOARD_IDS) - {"tab-dashboard", "tab-logs"} <= ids, set(DASHBOARD_IDS) - ids
    # The Refresh button of the header computes the tiles of an own page; the
    # 10 s poll calls refreshDashboard() without that, so nothing recomputes alone
    header = find(tab, lambda e: cls(e, "content-header"))[0]
    refresh = [b for b in find(header, lambda e: e["tag"] == "button") if "refreshDashboard" in b["attrs"].get("onclick", "")]
    assert len(refresh) == 1 and refresh[0]["attrs"]["onclick"] == "refreshDashboard({ panels: true })", refresh
    poll = _function_source("refreshDashboard")
    assert "panels" in poll and "loadPanels(" in poll, "the header Refresh does not compute the tiles"
    assert re.search(r"refreshDashboard\(\); refreshUpdates\(\); \} \}, 10000\)", SOURCE), \
        "the 10 s poll must call refreshDashboard without the tiles"
    assert "dashboardTabShown()" in _function_source("switchTab")
    guide = html[html.index('id="help-usage"'):html.index('id="help-api"')]
    assert "SERVICES" in guide and "tile" in guide


# --- The page row -----------------------------------------------------------------

@needs_node
def test_the_page_bar_switches_and_remembers():
    r = _run(r"""
        boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', []),
            board('d-bbbbbbbbbbbb', %s, [panel('p-1', 'Ports', 'source=firewall | top dst_port', 'pie')])];
        const out = {};
        await loadDashboardPages();
        out.row = pageRow();
        out.labels = [...pageRow().matchAll(/>([^<]+)<\/button>/g)].map(m => m[1]);
        out.start = [dashboardPages.page, els['dashboard-body'].hidden, els['dashboard-own'].hidden];
        out.toOwn = [setDashboardPage('d-bbbbbbbbbbbb'), dashboardPages.page, store['tdc.dashboard.page'],
            els['dashboard-body'].hidden, els['dashboard-own'].hidden];
        out.head = els['dashboard-own-head'].innerHTML;
        out.pressed = [...pageRow().matchAll(/data-dashboard-page="([^"]*)"[^>]*aria-pressed="true"/g)].map(m => m[1]);
        out.back = [setDashboardPage('services'), dashboardPages.page, store['tdc.dashboard.page'],
            els['dashboard-body'].hidden, els['dashboard-own'].hidden];
        // an unknown id is SERVICES, and so is the one of a dashboard that is gone
        out.unknown = [setDashboardPage('d-nope'), dashboardPages.page];
        store['tdc.dashboard.page'] = 'd-bbbbbbbbbbbb';
        dashboardPageRead = false;
        await loadDashboardPages();
        out.stored = dashboardPages.page;
        boards = [boards[0]];
        await loadDashboardPages();
        out.gone = [dashboardPages.page, els['dashboard-body'].hidden, store['tdc.dashboard.page']];
        console.log(JSON.stringify(out));""" % json.dumps(HOSTILE))
    assert r["labels"][0] == "SERVICES" and r["labels"][-1] == "+ NEW", r["labels"]
    assert r["labels"][1] == "Beacon hunt" and len(r["labels"]) == 4, r["labels"]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r["row"] and "<script" not in r["row"]
    assert not (_tags(r["row"]) - ALLOWED_TAGS), _tags(r["row"])
    assert _handlers(r["row"]) <= {"addDashboard()"} | {f"setDashboardPage(&quot;{page}&quot;)"
                                                        for page in ("services", "d-aaaaaaaaaaaa", "d-bbbbbbbbbbbb")}, \
        _handlers(r["row"])
    assert r["start"] == ["services", False, True], "SERVICES does not start on screen"
    assert r["toOwn"] == [True, "d-bbbbbbbbbbbb", "d-bbbbbbbbbbbb", True, False]
    assert r["pressed"] == ["d-bbbbbbbbbbbb"], "more than one page is marked"
    assert "&lt;script&gt;" in r["head"] and "<script" not in r["head"], "the head of the page is not escaped"
    assert r["back"] == [True, "services", "services", False, True]
    assert r["unknown"] == [False, "services"], "an unknown id did not fall back"
    assert r["stored"] == "d-bbbbbbbbbbbb", "the page of the last visit does not come back"
    assert r["gone"] == ["services", False, "services"], "a dashboard that is gone leaves the tab on its page"


@needs_node
def test_the_button_of_the_open_page_computes_nothing():
    """The page buttons behave like tabs, where a click on the open one does
    nothing. setDashboardPage used to stop and re-queue every tile, which is
    up to twelve searches over 10,000 matches for a page that is on screen."""
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        out.first = [searches.length, ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state)];
        // the page that is open, clicked again
        searches.length = 0;
        out.same = [setDashboardPage('d-aaaaaaaaaaaa'), searches.length, dashboardQueue.length,
            ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state), dashboardPages.page,
            (panels().match(/<svg/g) || []).length];
        // the click that lands while the tiles run leaves the run alone
        hold = true;
        refreshDashboard({ panels: true });
        await tick(20);
        const running = searches.length;
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        out.during = [searches.length - running, dashboardPages.loading];
        hold = false;
        release();
        await tick(80);
        // another page still computes, and so does the way back
        searches.length = 0;
        out.other = [setDashboardPage('services'), searches.length];
        await tick(20);
        out.toOwn = setDashboardPage('d-aaaaaaaaaaaa');
        await tick(80);
        out.again = searches.length;
        console.log(JSON.stringify(out));""")
    assert r["first"] == [3, ["ready", "ready", "ready"]]
    assert r["same"][0] is True and r["same"][4] == "d-aaaaaaaaaaaa"
    assert r["same"][1] == 0, f"the open page was computed again: {r['same'][1]} searches"
    assert r["same"][2] == 0 and r["same"][3] == ["ready", "ready", "ready"], "the tiles were queued again"
    assert r["same"][5] == 2, "the charts left the screen"
    assert r["during"] == [0, True], "a click on the open page took over the run"
    assert r["other"] == [True, 0] and r["toOwn"] is True
    assert r["again"] == 3, "the page that was opened again did not compute its tiles"


@needs_node
def test_a_new_dashboard_and_the_cap_of_ten():
    r = _run(r"""
        const out = {};
        boards = [];
        await loadDashboardPages();
        answerPrompt = '  Fresh board  ';
        out.made = await addDashboard();
        out.writes = writes.map(w => [w.url, w.method, w.body]);
        out.page = dashboardPages.page;
        out.names = dashboardPages.list.map(d => d.name);
        // a name the store would refuse never leaves the browser
        writes.length = 0;
        answerPrompt = '   ';
        out.blank = [await addDashboard(), writes.length];
        answerPrompt = null;
        out.cancel = [await addDashboard(), writes.length];
        // ten dashboards: + NEW is locked and asks nothing
        boards = Array.from({ length: 10 }, (_, i) => board('d-' + i, 'D' + i, []));
        await loadDashboardPages();
        asked.length = 0;
        out.full = [await addDashboard(), writes.length, asked.length];
        out.newPick = /id="dashboard-page-new"[^>]*/.exec(pageRow())[0];
        console.log(JSON.stringify(out));""")
    assert r["made"] is True
    assert r["writes"] == [["/api/dashboards", "POST", {"name": "Fresh board"}]], r["writes"]
    assert r["page"] == "d-new1", "the new dashboard does not open"
    assert r["names"] == ["Fresh board"]
    assert r["blank"] == [False, 0] and r["cancel"] == [False, 0]
    assert r["full"] == [False, 0, 0], "an eleventh dashboard was asked of the server"
    assert 'aria-disabled="true"' in r["newPick"] and "10 dashboards" in r["newPick"], r["newPick"]


# --- Computing the tiles ----------------------------------------------------------

THREE = r"""
    boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', [
        panel('p-1', 'Rows', 'source=access | table time, user, path', 'table'),
        panel('p-2', 'Ports', 'source=firewall | top dst_port', 'pie'),
        panel('p-3', 'Over time', '* | timechart span=5m count by source', 'line')])];
    answers['source=access | table time, user, path'] = { status: 200,
        data: table(['time', 'user', 'path'], Array.from({ length: 40 }, (_, i) => ['2026-11-16T09:00:00Z', 'u' + i, '/p' + i])) };
    answers['source=firewall | top dst_port'] = { status: 200, data: table(['dst_port', 'count'], [['443', 9], ['22', 4]]) };
    answers['* | timechart span=5m count by source'] = { status: 200,
        data: timechart(['_time', 'dns'], [['2026-11-16T09:00:00Z', 2], ['2026-11-16T09:05:00Z', 3]]) };
"""


@needs_node
def test_the_panels_load_one_after_the_other():
    r = _run(THREE + r"""
        const out = {};
        hold = true;
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        out.first = { searches: searches.length, open: openNow,
            states: ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state), body: panels() };
        release();
        await tick(20);
        out.second = { searches: searches.length, states: ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state) };
        release();
        await tick(20);
        release();
        await tick(30);
        out.done = { searches: searches.length, peak, states: ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state),
            queries: queries(), limits: limits(), loading: dashboardPages.loading };
        out.body = panels();
        console.log(JSON.stringify(out));""")
    assert r["first"]["searches"] == 1 and r["first"]["open"] == 1, "more than one tile searched at once"
    assert r["first"]["states"] == ["loading", "queued", "queued"], r["first"]["states"]
    assert r["first"]["body"].count("Queued") == 2 and "Loading" in r["first"]["body"], r["first"]["body"][:400]
    assert r["second"]["searches"] == 2, "the second tile started before the first had answered"
    assert r["second"]["states"] == ["ready", "loading", "queued"]
    assert r["done"]["searches"] == 3 and r["done"]["peak"] == 1, "the tiles did not run one after the other"
    assert r["done"]["states"] == ["ready", "ready", "ready"]
    assert r["done"]["loading"] is False
    assert r["done"]["queries"] == ["source=access | table time, user, path", "source=firewall | top dst_port",
                                    "* | timechart span=5m count by source"], "the tiles ran out of order"
    # 200 for the table tile, 1000 for every picture (the groups of a chart)
    assert r["done"]["limits"] == ["200", "1000", "1000"], r["done"]["limits"]
    assert "Queued" not in r["body"] and "Loading" not in r["body"]
    # A table tile shows at most 20 of the 40 rows it got (plus its head row)
    rows = re.findall(r"<tr", r["body"])
    assert len(rows) == 21, f"a table tile drew {len(rows) - 1} rows"


@needs_node
def test_one_panel_refreshes_alone_and_an_error_stays_local():
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        out.all = { searches: searches.length, body: panels() };
        // ↻ of one tile: one request, for that tile's search
        searches.length = 0;
        out.one = [await refreshPanel('p-2'), searches.length, queries()];
        // that tile is refused: its message stands on it, the others keep their numbers
        searches.length = 0;
        answers['source=firewall | top dst_port'] = { status: 400,
            data: { error: 'unknown command: topp', pos: 24 } };
        await refreshPanel('p-2');
        await tick(20);
        out.refused = { state: panelState('p-2').state, error: panelState('p-2').error, body: panels(),
            toasts: toasts.length, others: ['p-1', 'p-3'].map(id => panelState(id).state) };
        // the clock of every tile says how old its numbers are
        out.times = [...panels().matchAll(/class="dashboard-panel-time"[^>]*>([^<]*)</g)].map(m => m[1]);
        out.pageClock = els['dashboard-own-time'].textContent;
        // a table tile offers no "Show up to 1000": that button raises the page
        // of the LOGS tab, and a click on it here would do nothing
        out.more = panels().includes('data-logs-more');
        // Refresh of the header computes the tiles of an own page, none on SERVICES
        searches.length = 0;
        await refreshDashboard({ panels: true });
        await tick(60);
        out.header = searches.length;
        searches.length = 0;
        setDashboardPage('services');
        await tick(20);
        out.switched = searches.length;
        await refreshDashboard({ panels: true });
        await tick(20);
        out.services = searches.length;
        // the poll (refreshDashboard without an argument) computes nothing
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        searches.length = 0;
        await refreshDashboard();
        await tick(20);
        out.poll = searches.length;
        console.log(JSON.stringify(out));""")
    assert r["all"]["searches"] == 3
    assert r["one"][0] >= 1 and r["one"][1] == 1, "↻ of one tile sent more than one request"
    assert r["one"][2] == ["source=firewall | top dst_port"]
    assert r["refused"]["state"] == "error" and r["refused"]["error"] == "unknown command: topp"
    assert "unknown command: topp" in r["refused"]["body"], "the message of the server is not on the tile"
    assert r["refused"]["toasts"] == 0, "a refused tile belongs on the tile, not in a toast"
    assert r["refused"]["others"] == ["ready", "ready"], "a refused tile took the others with it"
    assert len(r["refused"]["body"].split("dashboard-panel")) > 3, "the other tiles are gone"
    assert len(r["times"]) == 3 and all(re.fullmatch(r"\d\d:\d\d:\d\d", t) for t in r["times"]), r["times"]
    assert re.fullmatch(r"\d\d:\d\d:\d\d", r["pageClock"]), f"the clock of the page stands at {r['pageClock']}"
    assert r["more"] is False, "a table tile offers the page button of the LOGS tab"
    assert r["header"] == 3, "the Refresh of the header did not compute every tile"
    assert r["switched"] == 0, "SERVICES computed tiles"
    assert r["services"] == 0, "the Refresh of the header computed tiles on SERVICES"
    assert r["poll"] == 0, "the 10 s poll computed the tiles"


@needs_node
def test_a_form_that_no_longer_fits_falls_back_to_the_table():
    r = _run(r"""
        boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', [
            panel('p-1', 'Ports', 'source=firewall | table a, b, c', 'pie'),
            panel('p-2', 'Fine', 'source=firewall | top dst_port', 'pie'),
            panel('p-3', 'Over time', '* | timechart span=5m count by source', 'pie')])];
        answers['source=firewall | table a, b, c'] = { status: 200,
            data: table(['a', 'b', 'c'], [['x', 'y', 'z'], ['p', 'q', 'r']]) };
        answers['source=firewall | top dst_port'] = { status: 200, data: table(['dst_port', 'count'], [['443', 9]]) };
        answers['* | timechart span=5m count by source'] = { status: 200,
            data: timechart(['_time', 'dns'], [['2026-11-16T09:00:00Z', 2]]) };
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(80);
        const out = { body: panels() };
        out.note = [...panels().matchAll(/class="dashboard-panel-why"[^>]*>([^<]*)</g)].map(m => m[1]);
        // an empty answer in the saved form says so instead of drawing nothing
        answers['source=firewall | top dst_port'] = { status: 200, data: table(['dst_port', 'count'], []) };
        await refreshPanel('p-2');
        await tick(20);
        out.empty = panels();
        console.log(JSON.stringify(out));""")
    assert len(r["note"]) == 2, r["note"]
    # The line reads as a sentence for every reason a form can be locked with:
    # the spec's wording is "saved as <form>, which needs <condition>"
    for note in r["note"]:
        assert note.startswith("saved as pie, which needs "), note
    assert "name column" in r["note"][0] and "number column" in r["note"][0], r["note"][0]
    assert "periods" in r["note"][1] and "line or as bars" in r["note"][1], r["note"][1]
    # The tile still shows what it has: the table of the columns that came back
    assert "<table" in r["body"] and ">a</th>" in r["body"]
    assert "No events in this range" in r["empty"] and "No rows to draw" not in r["empty"], r["empty"][:400]


@needs_node
def test_switching_away_aborts_what_is_running():
    r = _run(THREE + r"""
        const out = {};
        hold = true;
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        out.running = [searches.length, openNow, dashboardPages.loading];
        // the page is left: the request on its way is abandoned
        setDashboardPage('services');
        await tick(20);
        out.left = [dashboardPages.loading, dashboardQueue.length, openNow];
        release();
        await tick(30);
        out.after = [searches.length, panelState('p-1').state, panelState('p-1').result === null];
        // and the same for a tab change while the tiles run
        logsReady = true;
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        out.again = [searches.length, dashboardPages.loading];
        switchTab('logs');
        await tick(20);
        out.gone = [dashboardPages.loading, dashboardQueue.length];
        release();
        await tick(30);
        out.quiet = [panelState('p-1').state, panelState('p-1').result === null];
        // A tile that was abandoned must not stay on "Loading…": nothing is
        // on its way for it any more, so it is waiting for its turn again
        out.states = ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state);
        console.log(JSON.stringify(out));""")
    assert r["running"] == [1, 1, True]
    assert r["left"] == [False, 0, 0], "the page that was left still has a run"
    assert r["after"][0] == 1, "the page that was left started another search"
    assert r["after"][1] != "loading", "the tile that was abandoned is still said to be loading"
    assert r["after"][2] is True, "an answer of the page before drew on the page after it"
    assert r["again"][0] == 2 and r["again"][1] is True
    assert r["gone"] == [False, 0], "a tab change left the tiles running"
    assert r["quiet"][1] is True, "an answer that came after the tab change drew something"
    assert "loading" not in r["states"], f"a tile is left waiting for an answer nobody asked for: {r['states']}"


@needs_node
def test_a_tile_that_was_aborted_runs_again():
    """A tile whose request was abandoned (a page or a tab that was left) keeps
    its turn: coming back to the page, the Refresh of the header and the tile's
    own ↻ all have to compute it. Skipping the tile that is on its way must not
    skip one that nothing is on its way for."""
    r = _run(THREE + r"""
        const out = {};
        hold = true;
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        out.running = [searches.length, panelState('p-1').state];
        switchTab('logs');          // leaves the tab, so the request is abandoned
        await tick(20);
        release();
        await tick(30);
        out.left = panelState('p-1').state;
        // back on the page: every tile computes, the abandoned one first
        hold = false;
        searches.length = 0;
        state.activeTab = 'dashboard';
        await dashboardTabShown();
        await tick(60);
        out.back = [searches.length, ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state),
            queries()[0]];
        // the ↻ of a tile that was abandoned alone
        hold = true;
        searches.length = 0;
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        switchTab('logs');
        await tick(20);
        release();
        await tick(30);
        hold = false;
        state.activeTab = 'dashboard';
        dashboardPages.page = 'd-aaaaaaaaaaaa';
        searches.length = 0;
        out.one = [await refreshPanel('p-1'), searches.length, panelState('p-1').state];
        // and the Refresh of the header picks it up as well
        hold = true;
        searches.length = 0;
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        setDashboardPage('services');
        await tick(20);
        release();
        await tick(30);
        hold = false;
        setDashboardPage('d-aaaaaaaaaaaa');
        searches.length = 0;
        await refreshDashboard({ panels: true });
        await tick(60);
        out.header = [searches.length, ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state)];
        console.log(JSON.stringify(out));""")
    assert r["running"] == [1, "loading"]
    assert r["left"] != "loading", "the tile keeps waiting for an answer that was abandoned"
    assert r["back"][0] == 3, f"coming back to the page computed {r['back'][0]} of 3 tiles"
    assert r["back"][1] == ["ready", "ready", "ready"], r["back"][1]
    assert r["back"][2] == "source=access | table time, user, path"
    assert r["one"][1] == 1 and r["one"][2] == "ready", f"the ↻ of an abandoned tile: {r['one']}"
    assert r["header"][0] == 3 and r["header"][1] == ["ready", "ready", "ready"], r["header"]


@needs_node
def test_a_tile_whose_columns_changed_forgets_its_order():
    """Every table of one sort id takes the order of a click on it, and the
    card-controls observer re-applies the stored order to each table it sees.
    A tile that comes back with other columns must not be sorted by a column
    index that meant something else."""
    r = _run(r"""
        boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', [
            panel('p-1', 'Rows', 'source=access | table a, b, c', 'table')])];
        answers['source=access | table a, b, c'] = { status: 200,
            data: table(['a', 'b', 'c'], [['x', 'y', 'z']]) };
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        const id = 'logs-tile-p-1';
        tableSortState[id] = { col: 2, dir: 'desc' };
        // the same columns again: the order the analyst chose holds
        await refreshPanel('p-1');
        await tick(30);
        out.kept = JSON.stringify(tableSortState[id] || null);
        // other columns: the order means nothing in them
        answers['source=access | table a, b, c'] = { status: 200, data: table(['a', 'b'], [['x', 'y']]) };
        await refreshPanel('p-1');
        await tick(30);
        out.dropped = JSON.stringify(tableSortState[id] || null);
        out.logs = JSON.stringify(tableSortState['logs-result'] || null);
        console.log(JSON.stringify(out));""")
    assert r["kept"] == '{"col":2,"dir":"desc"}', "the same columns threw the order away"
    assert r["dropped"] == "null", "a tile keeps an order of columns it no longer has"
    assert r["logs"] == "null", "a tile reached into the sort state of the LOGS tab"


# --- The menus --------------------------------------------------------------------

@needs_node
def test_the_panel_menu_does_what_it_says():
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        // the ⋯ opens and closes, and only one of them is open
        out.shut = panels().includes('dashboard-panel-menu');
        togglePanelMenu('p-2');
        out.open = [panelState('p-2').menu, panels().match(/class="dashboard-panel-menu"[^>]*>/g)];
        togglePanelMenu('p-3');
        out.one = ['p-1', 'p-2', 'p-3'].map(id => panelState(id).menu);
        out.entries = [...panels().matchAll(/class="dashboard-panel-item"[^>]*onclick="panelMenu\(&quot;p-3&quot;, &quot;([^&]+)&quot;\)"[^>]*>([^<]*)</g)]
            .map(m => [m[1], m[2]]);
        // Change form offers exactly the forms the columns of the answer carry
        out.forms = ['p-2', 'p-3'].map(id => {
            const at = dashboardPanelOf(id);
            const card = panelCardHtml(at.panel, dashboardPanelView(at));
            return [...card.matchAll(/data-panel-form="([a-z]+)"[^>]*?aria-disabled="(true|false)"/g)]
                .map(m => m[1] + ':' + m[2]).join(' ');
        });
        // Open in LOGS: the tab, the query and the range of the tile
        out.opened = await panelMenu('p-2', 'open');
        out.logs = [state.activeTab, logsState.query, logsState.earliest, logsState.latest,
            panelState('p-2').menu, queries()[queries().length - 1]];
        // Rename: exactly one PATCH with exactly the name
        writes.length = 0;
        reads.length = 0;
        answerPrompt = ' Dropped ports ';
        await panelMenu('p-2', 'rename');
        out.rename = [writes.map(w => [w.url, w.method, w.body]), reads.length];
        // a name the store would refuse never leaves the browser
        writes.length = 0;
        answerPrompt = '';
        out.blank = [await panelMenu('p-2', 'rename'), writes.length];
        answerPrompt = null;
        out.cancel = [await panelMenu('p-2', 'rename'), writes.length];
        // Change form: one PATCH with the form, and that tile computes again
        writes.length = 0;
        searches.length = 0;
        answerPrompt = 'x';
        await panelMenu('p-2', 'form-bars');
        await tick(30);
        out.form = [writes.map(w => [w.url, w.method, w.body]), queries()];
        // Move up and down: one PATCH with the direction
        writes.length = 0;
        await panelMenu('p-2', 'up');
        await panelMenu('p-2', 'down');
        out.move = writes.map(w => [w.url, w.method, w.body]);
        // Delete: one question, then the DELETE, then the list again
        writes.length = 0;
        reads.length = 0;
        asked.length = 0;
        answerConfirm = false;
        out.kept = [await panelMenu('p-2', 'delete'), writes.length, asked.length];
        answerConfirm = true;
        boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', boards[0].panels.filter(p => p.id !== 'p-2'))];
        await panelMenu('p-2', 'delete');
        out.deleted = [writes.map(w => [w.url, w.method]), reads.length, asked.map(a => a[1]),
            dashboardPages.list[0].panels.length];
        out.unknown = await panelMenu('p-gone', 'delete');
        console.log(JSON.stringify(out));""")
    assert r["shut"] is True, "the ⋯ menus stand open on the page"
    assert r["open"][0] is True and len(r["open"][1]) == 3, r["open"]
    assert r["one"] == [False, False, True], "two tile menus were open at once"
    assert [e[0] for e in r["entries"]] == ["open", "rename", "up", "down", "delete"], r["entries"]
    assert [e[1] for e in r["entries"]] == ["Open in LOGS", "Rename", "Move up", "Move down", "Delete"], r["entries"]
    assert r["opened"] is True
    assert r["logs"][:4] == ["logs", "source=firewall | top dst_port", "-24h", ""]
    assert r["logs"][4] is False, "the menu stayed open behind the tab change"
    assert r["logs"][5] == "source=firewall | top dst_port", "the LOGS tab did not search the tile's query"
    assert r["rename"][0] == [["/api/dashboards/d-aaaaaaaaaaaa/panels/p-2", "PATCH", {"name": "Dropped ports"}]]
    assert r["rename"][1] == 1, "a write does not read the list again"
    assert r["blank"] == [False, 0] and r["cancel"] == [False, 0]
    assert r["form"][0] == [["/api/dashboards/d-aaaaaaaaaaaa/panels/p-2", "PATCH", {"form": "bars"}]]
    assert r["form"][1] == ["source=firewall | top dst_port"], "another form does not compute the tile again"
    # aria-disabled="true" is a form the columns cannot carry: a table of
    # dst_port / count has no line and no sankey, a timechart no pie and no sankey
    assert r["forms"][0] == "table:false pie:false bars:false line:true sankey:true", r["forms"][0]
    assert r["forms"][1] == "table:false pie:true bars:false line:false sankey:true", r["forms"][1]
    assert r["move"] == [["/api/dashboards/d-aaaaaaaaaaaa/panels/p-2", "PATCH", {"move": "up"}],
                         ["/api/dashboards/d-aaaaaaaaaaaa/panels/p-2", "PATCH", {"move": "down"}]]
    assert r["kept"] == [False, 0, 1], "Delete wrote without asking"
    assert r["deleted"][0] == [["/api/dashboards/d-aaaaaaaaaaaa/panels/p-2", "DELETE"]]
    assert r["deleted"][1] == 1 and r["deleted"][3] == 2, "the list was not read again after the delete"
    assert "Ports" in r["deleted"][2][0], r["deleted"][2]
    assert r["unknown"] is False


@needs_node
def test_open_in_logs_searches_once_and_in_the_form_of_the_tile():
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        // The LOGS tab has never been shown: it sets itself up on this visit,
        // and the tile's query is the one search that runs — not the last
        // search of the tab before it
        searches.length = 0;
        out.opened = await panelMenu('p-2', 'open');
        await tick(30);
        out.fresh = [logsReady, queries(), logsState.query, logsView, limits()];
        // and with the tab set up: the same, in the form the tile was saved with
        searches.length = 0;
        await panelMenu('p-3', 'open');
        await tick(30);
        out.again = [queries(), logsState.earliest, logsView, limits()];
        console.log(JSON.stringify(out));""")
    assert r["opened"] is True and r["fresh"][0] is True
    assert r["fresh"][1] == ["source=firewall | top dst_port"], \
        f"Open in LOGS ran {len(r['fresh'][1])} searches: {r['fresh'][1]}"
    assert r["fresh"][2] == "source=firewall | top dst_port"
    assert r["fresh"][3] == {"view": "visualization", "form": "pie"}, "a pie tile did not open as a pie"
    assert r["fresh"][4] == ["1000"], "the search of a picture asked for the rows of a table"
    assert r["again"][0] == ["* | timechart span=5m count by source"], r["again"][0]
    assert r["again"][1] == "-24h" and r["again"][2] == {"view": "visualization", "form": "line"}
    assert r["again"][3] == ["1000"]


@needs_node
def test_a_tile_that_is_gone_takes_its_numbers_with_it():
    """A record of panelState holds a whole result — up to 1000 rows: a tile
    or a dashboard deleted in another browser tab must not leave one behind
    for the life of the page."""
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        out.held = [...dashboardPanelState.keys()].sort();
        // another browser tab deleted one tile
        boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', boards[0].panels.filter(p => p.id !== 'p-2'))];
        await loadDashboardPages();
        out.pruned = [...dashboardPanelState.keys()].sort();
        // a list that could not be read is no answer about the tiles
        listAnswer = { status: 500, data: { error: 'nope' } };
        await loadDashboardPages();
        out.kept = [...dashboardPanelState.keys()].sort();
        // and the whole dashboard
        listAnswer = null;
        boards = [];
        await loadDashboardPages();
        out.gone = [dashboardPanelState.size, dashboardPages.page];
        console.log(JSON.stringify(out));""")
    assert r["held"] == ["p-1", "p-2", "p-3"]
    assert r["pruned"] == ["p-1", "p-3"], "the record of a deleted tile stays, with its rows"
    assert r["kept"] == ["p-1", "p-3"], "a list that could not be read threw the numbers away"
    assert r["gone"] == [0, "services"]


@needs_node
def test_a_tile_that_computes_again_keeps_its_numbers_on_screen():
    """panelBodyHtml used to read the state before the result: the Refresh of
    the header blanked every chart of the page for the whole run, although the
    numbers were still in panelState."""
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        const svgs = () => (panels().match(/<svg/g) || []).length;
        out.drawn = [svgs(), panels().includes('<table')];
        // the Refresh of the header: every tile is queued again, and what they
        // have stays on screen with a word that it is being computed
        hold = true;
        refreshDashboard({ panels: true });
        await tick(20);
        out.running = [svgs(), panels().includes('<table'), ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state)];
        out.said = [...panels().matchAll(/class="dashboard-panel-wait[^"]*"[^>]*>([^<]*)</g)].map(m => m[1]);
        hold = false;
        release();
        await tick(80);
        out.back = [svgs(), ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state)];
        // a tile that has nothing yet still says what it is waiting for
        dashboardPanelState.delete('p-2');
        renderOwnDashboard();
        out.empty = panels().includes('Queued') || panels().includes('Loading');
        console.log(JSON.stringify(out));""")
    assert r["drawn"] == [2, True], f"the page drew {r['drawn']}"
    assert r["running"][:2] == [2, True], "the tiles went blank while they computed again"
    assert r["running"][2] != ["ready", "ready", "ready"], "nothing was queued again"
    assert r["said"] and all(s.strip() in ("Queued", "Loading…") for s in r["said"]), r["said"]
    assert r["back"] == [2, ["ready", "ready", "ready"]]
    assert r["empty"] is True, "a tile without numbers says nothing about its turn"


@needs_node
def test_a_form_the_tile_cannot_draw_is_not_written():
    """The greyed switches of Change form carry aria-disabled, which no
    pointer honours: a click used to PATCH a form the tile can never draw and
    pay a search for it."""
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        writes.length = 0;
        searches.length = 0;
        // the greyed PIE of a timechart tile, the greyed SANKEY of a table of
        // two columns, and a form that is no form at all
        out.locked = [await panelMenu('p-3', 'form-pie'), await panelMenu('p-2', 'form-sankey'),
            await panelMenu('p-3', 'form-nope')];
        out.quiet = [writes.length, searches.length, dashboardPanelOf('p-3').panel.form];
        // the form the columns do carry is written, and that tile computes again
        out.taken = [await panelMenu('p-3', 'form-bars'), writes.map(w => w.body)];
        await tick(30);
        out.after = queries();
        // a tile that has not computed yet offers all five and takes one
        dashboardPanelState.delete('p-1');
        writes.length = 0;
        out.first = [await panelMenu('p-1', 'form-pie'), writes.map(w => w.body)];
        console.log(JSON.stringify(out));""")
    assert r["locked"] == [False, False, False], "a form the columns cannot carry was taken"
    assert r["quiet"] == [0, 0, "line"], f"the refused switches wrote or searched: {r['quiet']}"
    assert r["taken"] == [True, [{"form": "bars"}]]
    assert r["after"] == ["* | timechart span=5m count by source"], "the tile did not compute again"
    assert r["first"] == [True, [{"form": "pie"}]], "a tile without an answer locked its forms"


@needs_node
def test_escape_closes_the_menu_of_a_tile_and_of_a_page():
    r = _run(THREE + r"""
        const out = {};
        // as the template has them: the dialog and the menu of the LOGS tab shut
        els['logs-save'].classList.add('hidden');
        els['logs-menu'].hidden = true;
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        togglePanelMenu('p-2');
        out.tile = [panelState('p-2').menu, panels().includes('dashboard-panel-menu')];
        handleGlobalKeydown({ key: 'Escape' });
        out.shut = panelState('p-2').menu;
        // and the ⋯ beside the name of the page
        toggleDashboardMenu();
        out.page = dashboardOwnMenu;
        handleGlobalKeydown({ key: 'Escape' });
        out.pageShut = dashboardOwnMenu;
        console.log(JSON.stringify(out));""")
    assert r["tile"] == [True, True], "the menu did not open"
    assert r["shut"] is False, "Escape left the ⋯ menu of a tile open"
    assert r["page"] is True and r["pageShut"] is False, "Escape left the ⋯ of the page open"


@needs_node
def test_the_dashboard_menu_renames_and_deletes():
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        out.shut = els['dashboard-own-head'].innerHTML.includes('hidden');
        toggleDashboardMenu();
        out.head = els['dashboard-own-head'].innerHTML;
        out.entries = [...out.head.matchAll(/class="dashboard-menu-item"[^>]*onclick="([^"]*)"[^>]*>([^<]*)</g)]
            .map(m => [m[1], m[2]]);
        // Rename: one PATCH with the name, then the list again
        writes.length = 0;
        reads.length = 0;
        answerPrompt = ' Beacon chase ';
        out.renamed = await renameDashboard('d-aaaaaaaaaaaa');
        out.rename = [writes.map(w => [w.url, w.method, w.body]), reads.length, dashboardOwnMenu];
        // Delete: the question names the tiles, and a no writes nothing
        writes.length = 0;
        asked.length = 0;
        answerConfirm = false;
        out.kept = [await deleteDashboard('d-aaaaaaaaaaaa'), writes.length, asked.map(a => a[1])];
        answerConfirm = true;
        boards = [];
        out.gone = await deleteDashboard('d-aaaaaaaaaaaa');
        out.after = [writes.map(w => [w.url, w.method]), dashboardPages.page, dashboardPages.list.length,
            els['dashboard-body'].hidden];
        out.unknown = [await renameDashboard('d-nope'), await deleteDashboard('d-nope'), writes.length];
        // one tile reads as one tile
        boards = [board('d-cccccccccccc', 'One', [panel('p-9', 'Only', 'a | top b', 'pie')])];
        await loadDashboardPages();
        asked.length = 0;
        answerConfirm = false;
        await deleteDashboard('d-cccccccccccc');
        out.single = asked[0][1];
        console.log(JSON.stringify(out));""")
    assert r["shut"] is True, "the ⋯ of the dashboard stands open"
    assert [e[1] for e in r["entries"]] == ["Rename", "Delete"], r["entries"]
    assert [e[0] for e in r["entries"]] == ['renameDashboard(&quot;d-aaaaaaaaaaaa&quot;)',
                                            'deleteDashboard(&quot;d-aaaaaaaaaaaa&quot;)'], r["entries"]
    assert r["renamed"] is True
    assert r["rename"][0] == [["/api/dashboards/d-aaaaaaaaaaaa", "PATCH", {"name": "Beacon chase"}]]
    assert r["rename"][1] == 1 and r["rename"][2] is False, "the menu stayed open after the rename"
    assert r["kept"] == [False, 0, ["Delete 'Beacon hunt' and its 3 tiles?"]], r["kept"]
    assert r["gone"] is True
    assert r["after"][0] == [["/api/dashboards/d-aaaaaaaaaaaa", "DELETE"]]
    assert r["after"][1] == "services" and r["after"][2] == 0 and r["after"][3] is False
    assert r["unknown"] == [False, False, 1], "a dashboard that is not there was written to"
    assert r["single"] == "Delete 'One' and its 1 tile?", r["single"]


@needs_node
def test_hostile_names_and_queries_stay_text_on_a_tile():
    r = _run(r"""
        const hostile = %s;
        boards = [board('d-aaaaaaaaaaaa', hostile, [
            panel('p-1', hostile, hostile + ' | stats count by tool', 'pie'),
            panel('p-2', 'x', 'a | stats count by b', 'line')])];
        answers[hostile + ' | stats count by tool'] = { status: 200,
            data: table([hostile, 'count'], [[hostile, 3], ['x'.repeat(30000), 2]]) };
        answers['a | stats count by b'] = { status: 400, data: { error: hostile } };
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        togglePanelMenu('p-1');
        console.log(JSON.stringify({ row: pageRow(), head: els['dashboard-own-head'].innerHTML, body: panels(),
            card: panelCardHtml(boards[0].panels[0], panelState('p-1')) }));""" % json.dumps(HOSTILE))
    for name, markup in r.items():
        assert not (_tags(markup) - ALLOWED_TAGS), (name, _tags(markup) - ALLOWED_TAGS)
        assert "<script" not in markup and "<img" not in markup, name
        assert "x" * 1000 not in markup, f"{name}: a 30,000-character value drawn in full"
        # Only the calls of the page may stand in a handler, and only with an
        # id of the file (which is d-/p- plus hex) or a literal in them
        allowed = re.compile(r"(?:addDashboard|toggleDashboardMenu)\(\)"
                             r"|(?:setDashboardPage|renameDashboard|deleteDashboard|refreshPanel|togglePanelMenu)"
                             r"\(&quot;[\w-]*&quot;\)"
                             r"|panelMenu\(&quot;[\w-]*&quot;, &quot;[a-z-]+&quot;\)")
        assert all(allowed.fullmatch(h) for h in _handlers(markup)), (name, _handlers(markup))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r["body"]
    assert "&lt;script&gt;" in r["row"] and "&lt;script&gt;" in r["head"]


# --- Look -------------------------------------------------------------------------

@needs_node
def test_a_tile_is_drawn_for_the_room_it_has():
    """The style sheet puts two tiles in a row from 1100 px of window width.
    A chart drawn for more room than its tile has pushes its legend out of the
    card (the legend keeps a column of its own and does not scale with the
    svg), so the width here has to follow the same number — and a window that
    changes draws the tiles again, without computing anything."""
    r = _run(THREE + r"""
        const out = {};
        els['dashboard-panels'].getBoundingClientRect = () => ({ width: 1020 });
        globalThis.window = { innerWidth: 1280 };
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        out.wide = [dashboardPanelWidth('pie'), dashboardPanelWidth('table'), dashboardPanelWidth('line')];
        out.drawn = dashboardDrawnWidth;
        // a narrow window: one column, so every tile has the whole row
        globalThis.window = { innerWidth: 1000 };
        out.narrow = [dashboardPanelWidth('pie'), dashboardPanelWidth('table')];
        // the window changed: the tiles again, and no search
        searches.length = 0;
        els['dashboard-panels'].getBoundingClientRect = () => ({ width: 700 });
        out.redrawn = [redrawPanelsOnResize(), dashboardDrawnWidth, searches.length];
        out.again = redrawPanelsOnResize();
        // nothing to draw again on SERVICES
        setDashboardPage('services');
        els['dashboard-panels'].getBoundingClientRect = () => ({ width: 900 });
        out.services = redrawPanelsOnResize();
        console.log(JSON.stringify(out));""")
    assert r["wide"][0] == 490 and r["wide"][1] == 992 and r["wide"][2] == 992, r["wide"]
    assert r["drawn"] == 1020, r["drawn"]
    assert r["narrow"] == [992, 992], "a narrow window still halves the room of a pie"
    assert r["redrawn"] == [True, 700, 0], "a window that changed did not draw the tiles again, or computed them"
    assert r["again"] is False, "the same width draws again (an endless loop with a ResizeObserver)"
    assert r["services"] is False, "SERVICES has no tiles to draw"


@needs_node
def test_each_table_tile_sorts_on_its_own():
    """Every table of one data-sort-id takes the order of a click on any of
    them (sortTableBy), and the card-controls observer re-applies a stored
    order to each table it sees. With the id of the LOGS tab on every tile, a
    click on one tile reordered the other, and an order left over from the
    LOGS tab was applied to a tile whose search never returned it."""
    r = _run(r"""
        boards = [board('d-aaaaaaaaaaaa', 'Beacon hunt', [
            panel('p-1', 'Access rows', 'source=access | table time, user, path', 'table'),
            panel('p-2', 'Agents', 'source=access | table user, path, agent', 'table'),
            panel('p-3', 'Was a pie', 'source=access | table a, b, c', 'pie')])];
        answers['source=access | table time, user, path'] = { status: 200,
            data: table(['time', 'user', 'path'], [['2026-11-16T09:00:00Z', 'u0', '/a']]) };
        answers['source=access | table user, path, agent'] = { status: 200,
            data: table(['user', 'path', 'agent'], [['u0', '/a', 'curl']]) };
        answers['source=access | table a, b, c'] = { status: 200,
            data: table(['a', 'b', 'c'], [['x', 'y', 'z']], { count: 1621 }) };
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        const body = panels();
        const out = { ids: [...body.matchAll(/data-sort-id="([^"]*)"/g)].map(m => m[1]) };
        // the LOGS tab keeps its own id, and a tile never carries it
        out.logs = [...logsTableHtml(table(['a', 'count'], [['x', 1]])).matchAll(/data-sort-id="([^"]*)"/g)].map(m => m[1]);
        out.opt = logsTableHtml(table(['a', 'count'], [['x', 1]]), { sortId: 'logs-tile-p-9' })
            .includes('data-sort-id="logs-tile-p-9"');
        // a tile that fell back to the table keeps its warning line
        out.fallback = /class="dashboard-panel-why"[^>]*>([^<]*)</.exec(body.slice(body.indexOf('Was a pie')))[1];
        out.note = body.slice(body.indexOf('Was a pie')).includes('only 1 of 1,621 groups shown');
        console.log(JSON.stringify(out));""")
    assert len(r["ids"]) == 3, r["ids"]
    assert len(set(r["ids"])) == 3, f"two table tiles share one sort state: {r['ids']}"
    assert all(i.startswith("logs-tile-") for i in r["ids"]), r["ids"]
    assert "logs-result" not in r["ids"], "a tile sorts under the id of the LOGS tab"
    assert r["logs"] == ["logs-result"], "the result of the LOGS tab lost its sort id"
    assert r["opt"] is True
    assert r["fallback"].startswith("saved as pie, which needs ")
    assert r["note"] is True, "a tile that fell back to the table lost its warning line"


@needs_node
def test_a_list_that_could_not_be_read_keeps_the_page():
    """The fallback to SERVICES is for a dashboard the store does not have any
    more, not for a GET that failed: one blip used to empty the row, overwrite
    tdc.dashboard.page with 'services' and abandon the tiles that were running."""
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        out.before = [dashboardPages.page, dashboardPages.list.length, store['tdc.dashboard.page'],
            panelState('p-2').state];
        // the store cannot be read: nothing of what is known is thrown away
        listAnswer = { status: 500, data: { error: 'The dashboards could not be saved; see the web UI log.' } };
        out.failed = await loadDashboardPages();
        out.after = [dashboardPages.page, dashboardPages.list.length, store['tdc.dashboard.page'],
            panelState('p-2').state, els['dashboard-body'].hidden, els['dashboard-own'].hidden];
        out.row = pageRow().includes('data-dashboard-page="d-aaaaaaaaaaaa"');
        out.toast = toasts.map(t => [t[0], t[1]]);
        // a dashboard that is really gone still falls back
        listAnswer = null;
        boards = [];
        out.gone = [await loadDashboardPages(), dashboardPages.page, store['tdc.dashboard.page']];
        console.log(JSON.stringify(out));""")
    assert r["before"] == ["d-aaaaaaaaaaaa", 1, "d-aaaaaaaaaaaa", "ready"]
    assert r["failed"] is False
    assert r["after"][:4] == ["d-aaaaaaaaaaaa", 1, "d-aaaaaaaaaaaa", "ready"], \
        "a failed read threw the list, the page or the numbers away"
    assert r["after"][4] is True and r["after"][5] is False, "the own page went off screen"
    assert r["row"] is True, "the page is gone from the row"
    assert r["toast"] and r["toast"][-1][0] == "error", r["toast"]
    assert r["gone"] == [True, "services", "services"], "a dashboard that is gone no longer falls back"


@needs_node
def test_the_tile_on_its_way_is_not_searched_twice():
    """Refresh of the header during a run marked the tile that was waiting for
    its answer `queued` and pushed it back: its own answer then landed as a
    result and the tile was searched a second time."""
    r = _run(THREE + r"""
        const out = {};
        hold = true;
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(20);
        out.running = [searches.length, panelState('p-1').state];
        // the header Refresh while the first tile is on its way
        await loadPanels();
        out.queued = [dashboardQueue.length, dashboardQueue.includes('p-1'), panelState('p-1').state];
        release();
        await tick(30);
        out.first = [panelState('p-1').state, searches.length];
        hold = false;
        release();
        await tick(60);
        out.all = [searches.length, queries().filter(q => q === 'source=access | table time, user, path').length];
        console.log(JSON.stringify(out));""")
    assert r["running"] == [1, "loading"]
    assert r["queued"][1] is False, "the tile on its way was queued again"
    assert r["queued"][2] == "loading", "the tile on its way was set back to Queued"
    assert r["first"][0] == "ready" and r["first"][1] == 2
    assert r["all"][1] == 1, f"the first tile was searched {r['all'][1]} times"
    assert r["all"][0] == 3, r["all"]


@needs_node
def test_one_card_is_drawn_in_its_place():
    """A tile that changed replaces its own card: twelve tiles must not redraw
    twelve charts for one answer."""
    r = _run(THREE + r"""
        const out = {};
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        const before = panels();
        // the card of one tile exists now, as it does in a browser
        els['dashboard-panel-p-2'] = makeEl('dashboard-panel-p-2');
        cardWrites.length = 0;
        answers['source=firewall | top dst_port'] = { status: 200,
            data: table(['dst_port', 'count'], [['8443', 77]]) };
        await refreshPanel('p-2');
        await tick(30);
        out.writes = cardWrites.map(w => w[0]);
        out.page = panels() === before;
        out.card = els['dashboard-panel-p-2'].outerHTML;
        // a tile without a card of its own still draws, through the page
        delete els['dashboard-panel-p-2'];
        cardWrites.length = 0;
        await refreshPanel('p-3');
        await tick(30);
        out.fallbackWrites = cardWrites.length;
        out.fallbackPage = panels() !== before;
        console.log(JSON.stringify(out));""")
    assert r["writes"], "the card of the tile was never replaced"
    assert set(r["writes"]) == {"dashboard-panel-p-2"}, r["writes"]
    assert r["page"] is True, "one tile's answer redrew the whole page"
    assert 'id="dashboard-panel-p-2"' in r["card"] and ">Ports<" in r["card"]
    assert "8443" in r["card"], "the card that was put in its place holds the old numbers"
    assert r["fallbackWrites"] == 0 and r["fallbackPage"] is True, \
        "a tile without a card of its own does not draw at all"


@needs_node
def test_a_refused_write_says_so_and_reads_the_list_again():
    r = _run(THREE + r"""
        const out = {};
        answerPrompt = 'Another name';
        await loadDashboardPages();
        setDashboardPage('d-aaaaaaaaaaaa');
        await tick(60);
        const run = async (what, answer) => {
            writeAnswer = answer;
            toasts.length = 0;
            writes.length = 0;
            reads.length = 0;
            const ok = await what();
            return [ok, writes.length, reads.length, toasts.map(t => [t[0], t[1], t[2]])];
        };
        // a value the store refuses
        out.refused = await run(() => panelMenu('p-2', 'rename'),
            { status: 400, data: { error: 'name must be 1 to 60 characters' } });
        // the tile is gone from under us: the list again, so the page is right
        out.gone = await run(() => panelMenu('p-2', 'delete'),
            { status: 404, data: { error: 'Panel not found.' } });
        // a tool update is running
        out.maintenance = await run(() => renameDashboard('d-aaaaaaaaaaaa'),
            { status: 503, data: { error: 'Maintenance: tool updates are running.', maintenance: true } });
        // the write could not be saved
        out.broken = await run(() => panelMenu('p-2', 'up'),
            { status: 500, data: { error: 'The dashboards could not be saved; see the web UI log.' } });
        // + NEW that is refused makes no page and does not switch
        out.fresh = await run(() => addDashboard(), { status: 400, data: { error: 'at most 10 dashboards' } });
        out.page = dashboardPages.page;
        // the numbers of the tiles survive every one of them
        out.states = ['p-1', 'p-2', 'p-3'].map(id => panelState(id).state);
        writeAnswer = null;
        console.log(JSON.stringify(out));""")
    for name in ("refused", "gone", "maintenance", "broken", "fresh"):
        ok, written, read, toast = r[name]
        assert ok is False, f"{name}: a refused write answered true"
        assert written == 1, f"{name}: {written} writes"
        assert read == 1, f"{name}: the list was not read again ({read} reads)"
        assert len(toast) == 1 and toast[0][0] == "error", f"{name}: {toast}"
    assert "name must be 1 to 60 characters" in r["refused"][3][0][2]
    assert "Panel not found." in r["gone"][3][0][2]
    assert "a tool update is running" in r["maintenance"][3][0][2], r["maintenance"][3]
    assert "could not be saved" in r["broken"][3][0][2]
    assert "at most 10 dashboards" in r["fresh"][3][0][2]
    assert r["page"] == "d-aaaaaaaaaaaa", "a refused + NEW switched the page"
    assert r["states"] == ["ready", "ready", "ready"], "a refused write threw the numbers away"


def _media_rules(path, width):
    """selector -> body for the top-level rules inside @media (max-width: Npx)."""
    out = {}
    for prelude, body in _css_blocks(_strip_comments(_read(path))):
        if body is None or not prelude.startswith("@media") or f"{width}px" not in prelude:
            continue
        for inner, rule in _css_blocks(body):
            if rule is not None:
                out[inner.strip()] = out.get(inner.strip(), "") + rule
    return out


def test_both_themes_style_the_pages_and_the_tiles():
    classic, theme = _rule_bodies(STYLE_CSS), _rule_bodies(THEME_CSS)
    for cls in ("dashboard-pages", "dashboard-page", "dashboard-own", "dashboard-own-head", "dashboard-own-title",
                "dashboard-panels", "dashboard-panel", "dashboard-panel-head", "dashboard-panel-title",
                "dashboard-panel-tool", "dashboard-panel-time", "dashboard-panel-range", "dashboard-panel-body",
                "dashboard-panel-foot", "dashboard-panel-query", "dashboard-panel-wait", "dashboard-panel-error",
                "dashboard-panel-why", "dashboard-menu", "dashboard-menu-item", "dashboard-panel-menu",
                "dashboard-panel-item"):
        assert f".{cls}" in classic, f"style.css has no rule for .{cls}"
        assert f'[data-theme="cyberpunk"] .{cls}' in theme, f"Cyberpunk has no rule for .{cls}"
    # .dashboard-body is display: flex, so hidden alone would not hide it
    assert re.search(r"display:\s*none", classic.get(".dashboard-body[hidden]", "")), \
        "SERVICES stays on screen under an own dashboard"
    assert re.search(r"display:\s*none", classic.get(".dashboard-own[hidden]", "")), \
        "an own dashboard stays on screen under SERVICES"
    grid = classic[".dashboard-panels"]
    assert re.search(r"grid-template-columns:\s*repeat\(2", grid), "the tiles are not in two columns"
    # Table, line and sankey take the whole row; under 1100 px everything does
    assert re.search(r"grid-column:\s*1\s*/\s*-1", classic.get(".dashboard-panel-wide", "")), \
        "a table, a line or a sankey does not take the whole row"
    narrow = _media_rules(STYLE_CSS, 1100)
    assert re.search(r"grid-template-columns:\s*minmax\(0", narrow.get(".dashboard-panels", "")), \
        "the grid stays two columns under 1100 px"
    for name, bodies in (("style.css", classic), ("theme-cyberpunk.css", theme)):
        for base in ("dashboard-page", "dashboard-panel-tool"):
            hovers = [s for s in bodies if f".{base}" in s and s.rstrip().endswith(":hover")]
            assert hovers, f"{name}: .{base} has no hover rule"
            assert [s for s in hovers if "aria-disabled" in s], \
                f"{name}: nothing keeps a locked .{base} dim under the pointer"
        for selector, body in bodies.items():
            if ".dashboard-page" in selector or ".dashboard-own" in selector or ".dashboard-panel" in selector \
                    or ".dashboard-menu" in selector:
                assert not LITERAL_COLOR.search(body), f"{name}: a colour literal in {selector}"
    assert '.dashboard-page[aria-pressed="true"]' in classic, "the open page is not marked"
    assert '.dashboard-page[aria-disabled="true"]' in classic


def test_the_dashboard_pages_raised_the_asset_versions():
    html = _read(INDEX_HTML)
    assert "style.css?v=74" not in html and "theme-cyberpunk.css?v=33" not in html and "app.js?v=107" not in html, \
        "asset versions not raised"
    # the final fix wave: the line over the numbers of a tile that computes again
    assert "style.css?v=75" not in html, "style.css changed, its version did not"
