"""The LOGS tab (block LOGS of static/js/app.js, #tab-logs of index.html).

Regressions covered:
  * a script block, a tool name or any other log text (all of it is written by
    a sample or the VM) reaching the page as markup: in a row, a field, a
    chip, the error line, the layer behind the search box or a table cell
  * the search term highlight producing any tag but <mark>
  * a value a click adds to the search that breaks the query (a quote in it,
    a backslash at its end) or is added after a pipe; a source chip that adds
    a second source
  * an old response overwriting a newer one (or its error showing)
  * a rejected query without the place of the mistake marked, or its message
    left standing after the next search worked
  * more than ten last searches kept, or a blocked storage stopping a search
  * a result of stats / table / top / timechart shown as a list of events and
    the other way round; a table that keeps the order of the last one
  * a range drawn across the bars that does not become earliest and latest
  * LIVE searching in a hidden tab or a hidden browser tab
  * the tab button before Sysmon, a tab without its (i), a help guide without
    the entry
  * a command of the COMMANDS card that replaces the query instead of adding
    to it, searches on its own, or reaches the page as markup; a card that
    scrolls away with the results or forgets whether it was open
  * a result tab or a form switch that offers what the columns cannot carry,
    locks without a reason, or loses the chosen view on the next search
  * the percent column of `top f` drawn instead of its count; `stats … by
    status`, whose group values are numbers too, read as a number column
  * a chart drawn from 200 rows of 5,312 groups without a word about it, or a
    warning line whose click does not add `| sort -count | head 20`
  * a group value from a log (a tool name, a path, a script block) reaching a
    chart as markup, or a 30,000-character value drawn in full
  * SAVE open for a result that has no form, a dialog that asks the server for
    the dashboards twice, or a dashboard name from the file reaching it as markup
  * a tile saved with another form or another range than the one on screen, a
    "+ New" that writes the tile before its dashboard, or a save refused by the
    server that closes the dialog or hides its reason in a toast
"""

import json
import re

from test_frontend import SOURCE, _function_source, _run_node, needs_node
from test_theme import (CHART_CONSTS, CHART_FUNCTIONS, INDEX_HTML, LITERAL_COLOR, STYLE_CSS, THEME_CSS, _const_source,
                        _css_blocks, _Elements, _read, _selectors, _strip_comments)

LOGS_FUNCTION_NAME = re.compile(
    r"^(?:async )?function ((?:logs|runLogs|renderLogs|onLogs|submitLogs|toggleLogs|closeLogs|openLogs|refreshLogs"
    r"|initLogs|setLogs)\w*)\(",
    re.M)
LOGS_FUNCTIONS = list(dict.fromkeys(LOGS_FUNCTION_NAME.findall(SOURCE)))
LOGS_CONSTS = ["LOGS_RANGES", "LOGS_DEFAULT_RANGE", "LOGS_RECENT_KEY", "LOGS_RANGE_KEY", "LOGS_LAST_KEY", "LOGS_RECENT_MAX",
               "LOGS_LIVE_MS", "LOGS_PAGE", "LOGS_RAW_FULL_LIMIT", "LOGS_PAGE_MAX", "LOGS_EXAMPLES", "LOGS_SOURCE_COLORS",
               "LOGS_COMMANDS_KEY", "LOGS_COMMANDS_GROUP_KEY", "LOGS_COMMANDS_WIDE", "LOGS_COMMANDS",
               "LOGS_VIEWS", "LOGS_FORMS", "LOGS_NUMBER_COLUMN", "LOGS_CHART_TOP", "LOGS_CHART_OTHER",
               "LOGS_CHART_NAME_MAX", "LOGS_SORT_PIPE", "LOGS_LOCKED", "LOGS_VIEW_HINTS", "LOGS_FORM_HINTS",
               "LOGS_TOKEN", "LOGS_BARS_BRUSH", "LOGS_RANGE_MS", "LOGS_RANGE_UNITS", "LOGS_NAME_MAX",
               "LOGS_DASH_MAX", "LOGS_TILE_MAX", "LOGS_SAVE_WORD", "LOGS_SAVE_HINT", "LOGS_SAVE_FOCUS",
               "LOGS_SAVE_LOCKED"]
LOGS_LETS = re.findall(r"^let logs\w+ = [^\n]*?;(?=[ \t]*(?://[^\n]*)?$)", SOURCE, re.M)
OTHER_FUNCTIONS = CHART_FUNCTIONS + ["escapeHtml", "jsArg", "cssToken", "formatAlertTime", "filterChipHtml",
                                     "chartRangeLabel", "handleGlobalKeydown"]
ALL_FUNCTIONS = list(dict.fromkeys(LOGS_FUNCTIONS + OTHER_FUNCTIONS))

ELEMENT_IDS = ["logs-query", "logs-hl", "logs-results", "logs-summary", "logs-histogram", "logs-legend",
               "logs-field-list", "logs-fields-count", "logs-sources", "logs-error", "logs-range", "logs-live",
               "logs-menu", "logs-menu-btn", "logs-syntax", "logs-commands", "logs-commands-list",
               "logs-commands-toggle", "logs-result-head", "logs-tabs", "logs-forms",
               "logs-tab-events", "logs-tab-statistics", "logs-tab-visualization",
               "logs-form-table", "logs-form-pie", "logs-form-bars", "logs-form-line", "logs-form-sankey",
               "logs-save-btn", "logs-save", "logs-save-body"]
# The fields of the save dialog: JS writes them into #logs-save-body, so they
# are no element of the template and the markup test does not look for them
SAVE_IDS = ["logs-save-title", "logs-save-name", "logs-save-new", "logs-save-error", "logs-save-go"]

PRELUDE = "\n".join(_const_source(name) for name in CHART_CONSTS + LOGS_CONSTS) + "\n" + "\n".join(LOGS_LETS) + r"""
const classes = () => {
    const set = new Set();
    return { add: c => set.add(c), remove: c => set.delete(c), contains: c => set.has(c) };
};
const els = {};
for (const id of %s) {
    els[id] = { id, innerHTML: '', textContent: '', value: '', hidden: false, title: '', style: {}, attrs: {}, listeners: {},
        scrollLeft: 0, classList: classes(), caret: null, focused: 0,
        setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
        focus() { this.focused++; }, setSelectionRange(from, to) { this.caret = [from, to]; },
        getBoundingClientRect: () => ({ width: 640 }), querySelectorAll: () => [] };
}
globalThis.document = { hidden: false, getElementById: id => els[id] || null, addEventListener() {} };
globalThis.state = { activeTab: 'logs' };
const store = {};
globalThis.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } };
globalThis.tableSortState = {};
globalThis.barsBrushActive = () => false;
globalThis.barsClickPeriod = () => null;
globalThis.initBarsBrush = () => {};
globalThis._alertsChartInert = () => {};
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
globalThis.closeDashboardMenus = () => false;   // no ⋯ menu of the Dashboard tab is open
const intervals = [], cleared = [];
globalThis.setInterval = (fn, ms) => { intervals.push(ms); return intervals.length; };
globalThis.clearInterval = id => cleared.push(id);
const calls = [];
const reply = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
const ev = (id, message, extra = {}) => ({ id, time: '2026-11-14T10:00:00.123Z', source: 'powershell', message, fields: {}, ...extra });
const events = (list, extra = {}) => ({ type: 'events', events: list, columns: null, rows: [], count: list.length, matched: list.length,
    truncated: false, histogram: { bins: [], span_s: 60 }, fields: [], took_ms: 3.2, ...extra });
const table = (columns, rows, extra = {}) => ({ type: 'table', events: [], columns, rows, count: rows.length,
    matched: rows.length, truncated: false, histogram: { bins: [], span_s: 60 }, fields: [], took_ms: 1.5, ...extra });
const timechart = (columns, rows, extra = {}) => ({ ...table(columns, rows), type: 'timechart', ...extra });
// The dashboards of the server: `dashboards` is what the GET answers, `reads`
// holds every GET of the list, `posted` every write. `listAnswer` refuses the
// GET, `saveAnswer` the next write, `tileAnswer` only a write of a tile
// ({status, data} each).
let dashboards = [];
let saveAnswer = null, listAnswer = null, tileAnswer = null;
const posted = [], reads = [];
globalThis.fetch = async (url, opts) => {
    calls.push(url);
    const method = (opts && opts.method) || 'GET';
    if (url.startsWith('/api/dashboards')) {
        if (method === 'GET') {
            reads.push(url);
            return listAnswer ? reply(listAnswer.data, listAnswer.status) : reply({ dashboards });
        }
        const body = JSON.parse((opts && opts.body) || 'null');
        posted.push({ url, method, body });
        if (url.endsWith('/panels')) {
            const refuse = tileAnswer || saveAnswer;
            return refuse ? reply(refuse.data, refuse.status)
                : reply({ panel: { id: 'p-' + posted.length, ...body } }, 201);
        }
        if (saveAnswer) return reply(saveAnswer.data, saveAnswer.status);
        const made = { id: 'd-new' + posted.length, name: body.name, created: '2026-11-16T09:00:00Z', panels: [] };
        dashboards = [...dashboards, made];
        return reply({ dashboard: made }, 201);
    }
    return url.startsWith('/api/logs/sources') ? reply([]) : reply(events([]));
};
const query = url => new URL('http://x' + url).searchParams;
const searches = () => calls.filter(u => u.startsWith('/api/logs/search'));
""" % json.dumps(ELEMENT_IDS + SAVE_IDS)


def _run(script):
    return _run_node(ALL_FUNCTIONS, "(async () => {\n" + script + "\n})();", PRELUDE)


# --- Markup ---------------------------------------------------------------------

def test_the_tab_the_button_and_the_help_entry_exist():
    html = _read(INDEX_HTML)
    nav = re.search(r'<nav class="sidebar-tabs">(.*?)</nav>', html, re.S).group(1)
    tabs = re.findall(r'data-tab="([^"]+)"', nav)
    assert tabs.index("logs") == tabs.index("sysmon") + 1, tabs
    assert re.search(r'data-tab="logs">LOGS</button>', html)
    tab = _Elements(html).by_id("tab-logs")
    assert tab and "tab-content" in tab["attrs"]["class"].split()

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    header = find(tab, lambda e: "content-header" in e["attrs"].get("class", "").split())
    assert len(header) == 1 and find(header[0], lambda e: e["tag"] == "h2" and "data-info" in e["attrs"])
    ids = {n["attrs"]["id"] for n in find(tab, lambda e: "id" in e["attrs"])}
    assert set(ELEMENT_IDS) | {"logs-fields-filter"} <= ids, (set(ELEMENT_IDS) | {"logs-fields-filter"}) - ids
    guide = html[html.index('id="help-usage"'):html.index('id="help-api"')]
    names = re.findall(r"<h4>([^<]+)</h4>", guide)
    assert names.index("LOGS") == names.index("Sysmon") + 1, names


def test_every_logs_function_and_constant_is_found():
    for name in ["runLogsSearch", "renderLogsResult", "logsHighlight", "logsAddFilter", "renderLogsSources", "initLogs"]:
        assert name in LOGS_FUNCTIONS, name
    assert re.search(r"^async function runLogsSearch\(", SOURCE, re.M)
    assert re.search(r"^let logsState = \{", SOURCE, re.M) and len(LOGS_LETS) >= 10, LOGS_LETS
    assert re.search(r"tabName === 'logs'\)\s*\{\s*logsTabShown\(\)", _function_source("switchTab"))


# --- Safety ---------------------------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(1)>"
ALLOWED_TAGS = {"div", "button", "span", "pre", "mark", "code", "ul", "li", "strong", "table", "thead", "tbody", "tr",
                "th", "td"}


def _tags(html):
    return set(re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", html))


@needs_node
def test_a_script_block_is_text_everywhere():
    r = _run(r"""
        const hostile = %s + ' Invoke-Expression';
        const bad = ev('id"><script>1</script>', hostile, { source: 'x"><b>', time: '2026-11-14T10:00:00Z',
            fields: { tool: '<b>t</b>', list: ['<i>a', 'b'], nested: { u: '<u>' }, 'k<s>': 'v' } });
        logsSetQuery('Invoke');
        logsState.openIds.add(String(bad.id));
        const top = [{ value: '<u>v', count: 1 }];
        renderLogsResult(events([bad], { fields: [{ name: 'f<s>', count: 1, top }] }));
        const list = els['logs-results'].innerHTML;
        logsFieldsOpen.add('f<s>');
        renderLogsFields([{ name: 'f<s>', count: 1, top }]);
        renderLogsSources([{ source: 'p"><b>', count: 1, status: 'ok"><i>', hint: '<b>hint</b>', last_time: '<s>' }]);
        renderLogsError({ error: '<b>bad</b>', pos: 2 }, '<i>q<u>');
        logsSetQuery('source=<img src=x> | stats count by "<b>"');
        renderLogsResultBody({ type: 'table', events: [], columns: ['<b>c'], rows: [['<i>v'], [3], [null]], count: 3, matched: 3,
            truncated: false, histogram: { bins: [] }, fields: [], took_ms: 1 });
        console.log(JSON.stringify({ list, fields: els['logs-field-list'].innerHTML, sources: els['logs-sources'].innerHTML,
            error: els['logs-error'].innerHTML, layer: els['logs-hl'].innerHTML, table: els['logs-results'].innerHTML,
            menu: logsMenuHtml() }));""" % json.dumps(HOSTILE))
    for name, markup in r.items():
        assert not (_tags(markup) - ALLOWED_TAGS), (name, _tags(markup))
        assert "<script" not in markup and "<img" not in markup and "<b>" not in markup and "<i>" not in markup, name
        assert not re.search(r"<[a-z][^>]*\bonerror", markup), name
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r["list"]
    assert 'data-logs-toggle="id&quot;&gt;&lt;script&gt;1&lt;/script&gt;"' in r["list"]
    assert "<mark>Invoke</mark>-Expression" in r["list"], "the search word is not marked"
    assert "&lt;b&gt;t&lt;/b&gt;" in r["list"] and "&lt;i&gt;a" in r["list"]
    assert 'class="logs-src logs-src-xb"' in r["list"], "a source name in a class attribute"
    assert 'data-status="oki"' in r["sources"] and "&lt;b&gt;hint&lt;/b&gt;" in r["sources"]
    assert "&lt;b&gt;bad&lt;/b&gt;" in r["error"]
    assert "lq-op" in r["layer"] and "lq-pipe" in r["layer"] and "lq-cmd" in r["layer"] and "&lt;" in r["layer"]
    assert "&lt;i&gt;v" in r["table"] and "&lt;b&gt;c" in r["table"]


@needs_node
def test_highlight_makes_only_marks():
    r = _run(r"""
        const out = (text, terms) => logsHighlight(text, terms);
        console.log(JSON.stringify({
            plain: out('a <b> & "c"', []), mark: out('Invoke-Expression and invoke-expression', ['invoke-expression']),
            overlap: out('abcdef', ['abc', 'cde', 'bc']), tag: out('x <script>alert(1)</script>', ['script', '<script>', 'alert']),
            none: out(null, ['a']), nothing: out('abc', ['', null, undefined]), lone: out('İstanbul İ', ['i̇']),
            many: out('a'.repeat(5000), ['a']).split('<mark>').length,
        }));""")
    assert r["plain"] == "a &lt;b&gt; &amp; &quot;c&quot;"
    assert r["mark"] == "<mark>Invoke-Expression</mark> and <mark>invoke-expression</mark>"
    assert r["overlap"] == "<mark>abcde</mark>f"
    assert _tags(r["tag"]) == {"mark"} and "&lt;" in r["tag"] and "<script" not in r["tag"]
    assert r["none"] == "" and r["nothing"] == "abc" and r["lone"] == "İstanbul İ"
    assert r["many"] <= 201, "a text of one letter marks without a limit"


@needs_node
def test_query_terms_skip_fields_operators_and_what_is_excluded():
    r = _run(r"""
        console.log(JSON.stringify({
            a: logsQueryTerms('source=powershell "Invoke-Expression" foo* NOT bad status!=200 | stats count by tool'),
            b: logsQueryTerms('(user=alice OR user="bob smith") AND earliest=-1h x>5 "a\\"b"'),
            c: logsQueryTerms('*'), d: logsQueryTerms(''), e: logsQueryTerms(null),
            many: logsQueryTerms(Array.from({ length: 40 }, (_, i) => 'w' + i).join(' ')).length,
        }));""")
    assert r["a"] == ["Invoke-Expression", "foo"]
    assert r["b"] == ["alice", "bob smith", 'a"b']
    assert r["c"] == [] and r["d"] == [] and r["e"] == []
    assert r["many"] == 20


@needs_node
def test_the_query_layer_colours_the_parts():
    r = _run(r"""
        console.log(JSON.stringify(logsQueryHtml('source=dns NOT a>1 "x y" | stats count by q | head 5')));""")
    for cls in ("lq-field", "lq-op", "lq-bool", "lq-str", "lq-pipe", "lq-cmd", "lq-kw"):
        assert cls in r, cls
    assert re.sub(r"<[^>]+>", "", r) == 'source=dns NOT a&gt;1 &quot;x y&quot; | stats count by q | head 5'


# --- The query ------------------------------------------------------------------

@needs_node
def test_adding_a_filter_escapes_and_stays_before_the_pipe():
    r = _run(r"""
        const out = [];
        for (const [text, field, value] of [['*', 'path', 'a"b'], ['source=dns | top query', 'query', 'x'],
                ['  ', 'f', 'v'], ['a "b | c" | head 3', 'f', 'C:\\dir\\'], ['x', 'bad name', 'v'], ['x', 'a"b', 'v'],
                ['x', 'f', 'a\\"b']]) {
            logsSetQuery(text);
            const ok = logsAddFilter(field, value);
            out.push([ok, logsState.query]);
        }
        console.log(JSON.stringify({ out, sent: searches().map(u => query(u).get('q')) }));""")
    assert r["out"][0] == [True, 'path="a\\"b"']
    assert r["out"][1] == [True, 'source=dns query="x" | top query']
    assert r["out"][2] == [True, 'f="v"']
    assert r["out"][3] == [True, 'a "b | c" f="C:\\dir\\*" | head 3']
    assert r["out"][4] == [False, "x"] and r["out"][5] == [False, "x"]
    assert r["out"][6] == [True, r'x f="a\\"b"']
    assert r["sent"][0] == 'path="a\\"b"' and len(r["sent"]) == 5, "the search did not run with the new query"


@needs_node
def test_a_source_chip_takes_the_place_of_the_source_of_the_search():
    r = _run(r"""
        const out = [];
        for (const text of ['*', 'source=dns x | stats count', 'foo', '(source="dns" OR a) | head 2', 'SOURCE = dns']) {
            logsSetQuery(text);
            logsAddSource('mcp');
            out.push(logsState.query);
        }
        logsSetQuery('x');
        out.push(logsAddSource('a b'));
        console.log(JSON.stringify(out));""")
    assert r == ["source=mcp", "source=mcp x | stats count", "foo source=mcp", "(source=mcp OR a) | head 2",
                 "source=mcp", False]


@needs_node
def test_the_last_ten_searches_are_kept_newest_first():
    r = _run(r"""
        for (let i = 0; i < 15; i++) logsRemember('q' + i);
        const list = logsRecent();
        logsRemember('q10'); logsRemember('*'); logsRemember('   ');
        const again = logsRecent();
        localStorage.setItem = () => { throw new Error('blocked'); };
        let blocked = 'ok';
        try { logsRemember('z'); } catch (e) { blocked = 'threw'; }
        store[LOGS_RECENT_KEY] = '{not json';
        const broken = logsRecent();
        store[LOGS_RECENT_KEY] = JSON.stringify(['a', 3, '', null, 'b']);
        console.log(JSON.stringify({ list, again, blocked, broken, mixed: logsRecent() }));""")
    assert r["list"] == [f"q{i}" for i in range(14, 4, -1)]
    assert r["again"][0] == "q10" and len(r["again"]) == 10 and "*" not in r["again"] and len(set(r["again"])) == 10
    assert r["blocked"] == "ok" and r["broken"] == [] and r["mixed"] == ["a", "b"]


@needs_node
def test_the_constants_the_brief_names():
    r = _run(r"""
        console.log(JSON.stringify({ ranges: LOGS_RANGES, examples: LOGS_EXAMPLES.map(e => e.query),
            labels: LOGS_EXAMPLES.every(e => e.label && e.query), wide: LOGS_COMMANDS_WIDE,
            keys: [LOGS_COMMANDS_KEY, LOGS_COMMANDS_GROUP_KEY] }));""")
    assert r["ranges"] == ["15m", "1h", "4h", "24h", "7d", "All"]
    for query in ["source=powershell", "source=mcp | stats count by tool", "source=access NOT poll=true",
                  "source=netflow | sort -count | head 20", "source=dns | top query", "source=firewall action=DROP",
                  "* | timechart span=5m count by source"]:
        assert query in r["examples"], query
    assert r["labels"] and r["wide"] == 1100
    assert r["keys"][0] == "tdc.logs.commands" and r["keys"][1].startswith("tdc.logs.commands")
    assert "LOGS_SYNTAX_HINT" not in SOURCE, "the cheat sheet lives in LOGS_COMMANDS now"


# --- The search -----------------------------------------------------------------

@needs_node
def test_a_rejected_query_marks_the_place_of_the_mistake():
    r = _run(r"""
        globalThis.fetch = async () => reply({ error: 'Expected a value after =', pos: 8 }, 400);
        logsState.query = 'source= <b> | x';
        await runLogsSearch();
        const marked = els['logs-error'].innerHTML, shown = els['logs-error'].hidden, invalid = els['logs-query'].attrs['aria-invalid'];
        globalThis.fetch = async () => reply({ error: 'boom', pos: 99 }, 400);
        logsState.query = 'ab';
        await runLogsSearch();
        const past = els['logs-error'].innerHTML;
        globalThis.fetch = async () => reply({ error: 'The search failed; see the web UI log.' }, 500);
        await runLogsSearch();
        const plain = els['logs-error'].innerHTML;
        globalThis.fetch = async () => { throw new Error('offline'); };
        await runLogsSearch();
        const offline = els['logs-error'].innerHTML;
        globalThis.fetch = async () => reply(events([ev('1', 'ok')]));
        await runLogsSearch();
        console.log(JSON.stringify({ marked, shown, invalid, past, plain, offline, after: els['logs-error'].innerHTML,
            hiddenAfter: els['logs-error'].hidden, invalidAfter: els['logs-query'].attrs['aria-invalid'] }));""")
    assert 'source= <mark class="logs-error-pos">&lt;</mark>b&gt; | x</code>' in r["marked"]
    assert "Expected a value after =" in r["marked"] and r["shown"] is False and r["invalid"] == "true"
    assert '<mark class="logs-error-pos"> </mark>' in r["past"], "a position past the end marks nothing"
    assert "logs-error-query" not in r["plain"] and "web UI log" in r["plain"]
    assert "offline" in r["offline"]
    assert r["after"] == "" and r["hiddenAfter"] is True and r["invalidAfter"] == "false"


@needs_node
def test_the_error_mark_is_the_character_at_pos():
    r = _run(r"""
        console.log(JSON.stringify([
            logsErrorHtml({ error: 'e', pos: 3 }, 'abcdefg'),
            logsErrorHtml({ error: 'e', pos: 1 }, '😀x😀'),
            logsErrorHtml({ error: 'e', pos: 120 }, 'a'.repeat(200)),
            logsErrorHtml({ error: 'e' }, 'abc'),
        ]));""")
    assert '<code class="logs-error-query">abc<mark class="logs-error-pos">d</mark>efg</code>' in r[0]
    assert '<mark class="logs-error-pos">x</mark>' in r[1] and "😀" in r[1]
    assert "…" in r[2] and r[2].count("a") < 140
    assert "<code" not in r[3]


@needs_node
def test_an_old_response_is_dropped():
    r = _run(r"""
        const pending = [];
        globalThis.fetch = url => new Promise(resolve => pending.push({ url, resolve }));
        logsState.query = 'first';
        const first = runLogsSearch();
        logsState.query = 'second';
        const second = runLogsSearch();
        pending[1].resolve(reply(events([ev('b', 'NEW')])));
        await second;
        pending[0].resolve(reply(events([ev('a', 'OLD')])));
        const dropped = await first;
        const afterOld = els['logs-results'].innerHTML;
        // an old error does not show either
        logsState.query = 'third';
        const third = runLogsSearch();
        logsState.query = 'fourth';
        const fourth = runLogsSearch();
        pending[3].resolve(reply(events([ev('c', 'NEWER')])));
        await fourth;
        pending[2].resolve(reply({ error: 'stale', pos: 0 }, 400));
        await third;
        console.log(JSON.stringify({ dropped, afterOld, message: logsState.result.events[0].message, error: els['logs-error'].innerHTML,
            loading: els['logs-results'].classList.contains('is-loading') }));""")
    assert r["dropped"] is None and "NEW" in r["afterOld"] and "OLD" not in r["afterOld"]
    assert r["message"] == "NEWER" and r["error"] == "" and r["loading"] is False


@needs_node
def test_the_request_carries_the_query_the_range_and_the_limit():
    r = _run(r"""
        logsState.query = 'source=dns "a b"';
        await runLogsSearch();
        logsSetRange('All');
        logsState.query = '   ';
        logsState.earliest = '2026-11-14T10:00:00Z'; logsState.latest = '2026-11-14T11:00:00Z';
        await runLogsSearch();
        console.log(JSON.stringify({ seen: searches().map(u => Object.fromEntries(query(u))), raw: searches()[1] }));""")
    assert r["seen"][0] == {"q": 'source=dns "a b"', "earliest": "-24h", "limit": "200"}
    assert r["seen"][1]["earliest"] == "" and "earliest=&limit" in r["raw"], "'All' must send an empty earliest"
    assert r["seen"][2] == {"q": "*", "earliest": "2026-11-14T10:00:00Z", "limit": "200", "latest": "2026-11-14T11:00:00Z"}


@needs_node
def test_events_make_a_list_and_stats_a_sortable_table():
    r = _run(r"""
        const flow = [ev('1', 'first message', { time: '2026-11-14T10:00:00.123Z' }), ev('2', 'second', { source: 'access' })];
        renderLogsResult(events(flow, { count: 5 }));
        const list = els['logs-results'].innerHTML, summary = els['logs-summary'].innerHTML;
        const table = { type: 'table', events: [], columns: ['tool', 'count', '_time'], rows: [['tdc_status', 12, '2026-11-14T10:00:00Z'],
            ['tdc_logs_search', 3, null]], count: 2, matched: 20, truncated: false, histogram: { bins: [] }, fields: [], took_ms: 1 };
        renderLogsResult(table);
        const t = els['logs-results'].innerHTML, tSummary = els['logs-summary'].innerHTML;
        logsState.openIds.add('1');
        renderLogsResult(events(flow));
        const open = els['logs-results'].innerHTML;
        console.log(JSON.stringify({ list, summary, t, tSummary, open,
            time: formatAlertTime('2026-11-14T10:00:00.123Z'), none: logsEventsHtml([], [], events([])) }));""")
    assert r["list"].count('class="logs-event"') == 2 and "<table" not in r["list"]
    assert f'<span class="logs-time" title="2026-11-14T10:00:00.123Z">{r["time"]}</span>' in r["list"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", r["time"])
    assert "first message" in r["list"] and "logs-src-access" in r["list"]
    assert "Show up to 1000" in r["list"] and "5</strong> events" in r["summary"] and "first 2 shown" in r["summary"]
    assert '<table class="logs-table" data-sortable data-sort-id="logs-result">' in r["t"]
    assert "<th>tool</th><th>count</th><th>_time</th>" in r["t"] and "logs-event" not in r["t"]
    assert 'data-sort-value="12"' in r["t"] and 'data-sort-value="2026-11-14T10:00:00Z"' in r["t"]
    assert "2 rows" in r["tSummary"].replace("</strong>", "") and "from 20 events" in r["tSummary"]
    assert 'class="logs-event is-open"' in r["open"] and '<pre class="logs-raw">first message</pre>' in r["open"]
    assert 'aria-expanded="true"' in r["open"] and "logs-detail-key" in r["open"]
    assert "No events match" in r["none"]


@needs_node
def test_a_click_unfolds_an_event_and_a_value_adds_a_filter():
    r = _run(r"""
        const flow = [ev('7', 'hello world', { fields: { tool: 'tdc_status', status: 200 } })];
        logsSetQuery('hello');
        renderLogsResult(events(flow));
        const hit = (selector, attrs) => ({ target: { closest: sel => (sel === selector ? { getAttribute: k => attrs[k] ?? null } : null) } });
        onLogsClick(hit('[data-logs-toggle]', { 'data-logs-toggle': '7' }));
        const opened = [...logsState.openIds], html = els['logs-results'].innerHTML;
        onLogsClick(hit('[data-logs-toggle]', { 'data-logs-toggle': '7' }));
        const closed = [...logsState.openIds];
        onLogsClick(hit('[data-logs-value]', { 'data-field': 'tool', 'data-value': 'tdc_status' }));
        const before = logsFieldsOpen.has('source');
        onLogsClick(hit('[data-logs-field]', { 'data-logs-field': 'source' }));
        console.log(JSON.stringify({ opened, closed, html, query: logsState.query, before, after: logsFieldsOpen.has('source') }));""")
    assert r["opened"] == ["7"] and r["closed"] == []
    assert 'data-field="tool" data-value="tdc_status"' in r["html"] and 'data-field="status" data-value="200"' in r["html"]
    assert "<mark>hello</mark> world" in r["html"]
    assert r["query"] == 'hello tool="tdc_status"'
    assert r["before"] is True and r["after"] is False


@needs_node
def test_the_fields_bar_lists_top_values_of_open_fields():
    r = _run(r"""
        const fields = [{ name: 'source', count: 10, top: [{ value: 'powershell', count: 7 }, { value: 'access', count: 3 }] },
                        { name: 'tool', count: 4, top: [{ value: 'tdc_status', count: 4 }] }];
        renderLogsResult(events([], { fields }));
        const first = els['logs-field-list'].innerHTML, count = els['logs-fields-count'].textContent;
        onLogsFieldFilter('TO');
        const filtered = els['logs-field-list'].innerHTML;
        onLogsFieldFilter('zzz');
        console.log(JSON.stringify({ first, count, filtered, none: els['logs-field-list'].innerHTML }));""")
    assert r["count"] == "2"
    assert 'data-logs-field="source" aria-expanded="true"' in r["first"] and 'data-logs-field="tool" aria-expanded="false"' in r["first"]
    assert 'data-value="powershell"' in r["first"] and "--share:70%" in r["first"] and 'data-value="tdc_status"' not in r["first"]
    assert 'data-logs-field="tool"' in r["filtered"] and 'data-logs-field="source"' not in r["filtered"]
    assert "No field matches." in r["none"]


@needs_node
def test_the_source_chips_show_the_hint_and_search_their_source():
    r = _run(r"""
        renderLogsSources([
            { source: 'powershell', count: 0, last_time: null, status: 'unavailable', hint: 'Windows event logs are only available on the VM.' },
            { source: 'access', count: 1234, last_time: '2026-11-14T10:00:00Z', status: 'ok', hint: '' },
            { source: 'dns', count: 0, last_time: null, status: 'empty', hint: '' },
        ]);
        logsSetQuery('x | head 3');
        renderLogsSources(logsSources);
        const plain = els['logs-sources'].innerHTML;
        logsSetQuery('source="access" foo');
        renderLogsSources(logsSources);
        console.log(JSON.stringify({ plain, active: els['logs-sources'].innerHTML }));""")
    html = r["plain"]
    assert 'title="Windows event logs are only available on the VM."' in html
    assert 'data-status="unavailable"' in html and 'data-status="ok"' in html and 'data-status="empty"' in html
    assert 'logs-source-count">1,234<' in html and 'onclick="logsAddSource(&quot;powershell&quot;)"' in html
    assert "last event" in html and "dns: empty" in html
    assert "is-active" not in html
    assert re.search(r'logs-source-access is-active" aria-pressed="true"', r["active"])
    assert r["active"].count("is-active") == 1


# --- Range, bars, live ------------------------------------------------------------

@needs_node
def test_the_range_buttons_and_a_zoom_set_earliest_and_latest():
    r = _run(r"""
        const out = {};
        out.bad = logsSetRange('2d');
        logsSetRange('7d'); out.week = [logsState.earliest, logsState.latest, logsRangeLabel(logsState.earliest, logsState.latest)];
        logsSetRange('All'); out.all = [logsState.earliest, logsRangeLabel('', '')];
        out.htmlAll = els['logs-range'].innerHTML;
        logsSetRange('1h');
        const t0 = Date.UTC(2026, 10, 14, 10, 0, 0), t1 = Date.UTC(2026, 10, 14, 10, 30, 0);
        out.noZoom = [logsZoom(t1, t0), logsZoom(NaN, t1), logsState.earliest];
        logsZoom(t0, t1);
        out.zoom = [logsState.earliest, logsState.latest, logsRangeLabel(logsState.earliest, logsState.latest)];
        out.zoomHtml = els['logs-range'].innerHTML;
        out.params = Object.fromEntries(query(searches().pop()));
        logsSetRange(logsBase);
        out.back = [logsState.earliest, logsState.latest];
        out.stored = store[LOGS_RANGE_KEY];
        console.log(JSON.stringify(out));""")
    assert r["bad"] is False and r["week"] == ["-7d", "", "7d"] and r["all"] == ["", "All"]
    assert 'data-range="All" aria-pressed="true"' in r["htmlAll"] and 'data-range="24h" aria-pressed="false"' in r["htmlAll"]
    assert r["noZoom"] == [False, False, "-1h"]
    assert r["zoom"] == ["2026-11-14T10:00:00Z", "2026-11-14T10:30:00Z", ""]
    assert 'aria-pressed="true"' not in r["zoomHtml"] and "alerts-filter-chip" in r["zoomHtml"]
    assert "logsSetRange(&quot;1h&quot;)" in r["zoomHtml"], "the chip does not go back to the range it zoomed from"
    assert r["params"]["earliest"] == "2026-11-14T10:00:00Z" and r["params"]["latest"] == "2026-11-14T10:30:00Z"
    assert r["back"] == ["-1h", ""] and r["stored"] == "1h"


@needs_node
def test_the_histogram_stacks_the_sources_and_a_range_across_it_zooms():
    r = _run(r"""
        const histogram = { span_s: 300, bins: [
            { start: '2026-11-14T10:00:00Z', end: '2026-11-14T10:05:00Z', counts: { powershell: 2, access: 1 } },
            { start: '2026-11-14T10:05:00Z', end: '2026-11-14T10:10:00Z', counts: {} },
            { start: '2026-11-14T10:10:00Z', end: '2026-11-14T10:15:00Z', counts: { 'x"><b>': 4, mcp: 3 } },
        ] };
        renderLogsResult(events([ev('1', 'm')], { histogram }));
        const svg = els['logs-histogram'].innerHTML, legend = els['logs-legend'].innerHTML;
        const bins = LOGS_BARS_BRUSH.bins();
        LOGS_BARS_BRUSH.onRange(0, 2, bins);
        const zoom = [logsState.earliest, logsState.latest];
        renderLogsResult(events([], { histogram: { bins: [], span_s: 0 } }));
        console.log(JSON.stringify({ svg, legend, bins: bins.map(b => [b.start, b.end, b.total]), zoom, empty: els['logs-histogram'].innerHTML,
            emptyLegend: els['logs-legend'].innerHTML, drawn: logsDrawn.bins.length }));""")
    assert r["svg"].count("data-bin-start=") == 3 and "var(--accent-cyan)" in r["svg"] and "var(--accent-green)" in r["svg"]
    assert "<b>" not in r["svg"] and "<b>" not in r["legend"]
    assert r["legend"].index("powershell") < r["legend"].index("access") < r["legend"].index("mcp")
    assert re.search(r'powershell <span class="logs-legend-count">2<', r["legend"])
    assert r["bins"][0] == [1794650400000, 1794650700000, 3] and r["bins"][2][2] == 7
    assert r["zoom"] == ["2026-11-14T10:00:00Z", "2026-11-14T10:15:00Z"]
    assert "No events in this range" in r["empty"] and r["emptyLegend"] == "" and r["drawn"] == 0


@needs_node
def test_a_timechart_opens_as_a_line_and_keeps_its_table():
    r = _run(r"""
        const rows = [['2026-11-14T10:00:00Z', 2, 0], ['2026-11-14T10:05:00Z', 1, 3], ['2026-11-14T10:10:00Z', 0, 1]];
        const result = timechart(['_time', 'access', 'mcp'], rows, { count: 3, matched: 7 });
        renderLogsResult(result);
        const line = els['logs-results'].innerHTML;
        setLogsForm('bars');
        const bars = els['logs-results'].innerHTML;
        setLogsView('statistics');
        const shown = els['logs-results'].innerHTML;
        tableSortState['logs-result'] = { col: 2, dir: 'asc' };
        renderLogsResultBody({ ...result, columns: ['_time', 'a'], rows: [['2026-11-14T10:00:00Z', 1]] });
        console.log(JSON.stringify({ line, bars, table: shown, reset: tableSortState['logs-result'] === undefined }));""")
    assert r["line"].count('class="chart-line"') == 2 and "logs-legend-item" in r["line"]
    assert r["bars"].count("data-bin-start=") == 3 and "logs-legend-item" in r["bars"]
    assert "<table" in r["table"] and "chart-line" not in r["table"] and "data-bin-start=" not in r["table"]
    assert r["reset"] is True


@needs_node
def test_live_searches_only_while_the_tab_is_on_screen():
    r = _run(r"""
        const out = {};
        out.off = logsLiveTick();
        toggleLogsLive();
        out.on = [logsState.live, els['logs-live'].attrs['aria-pressed'], intervals];
        out.firstTick = searches().length;
        document.hidden = true; out.hidden = logsLiveTick(); document.hidden = false;
        state.activeTab = 'dashboard'; out.elsewhere = logsLiveTick(); state.activeTab = 'logs';
        globalThis.barsBrushActive = () => true; out.pressing = logsLiveTick(); globalThis.barsBrushActive = () => false;
        out.ticks = logsLiveTick();
        await new Promise(r => setTimeout(r, 0));
        out.searches = searches().length;
        out.remembered = store[LOGS_RECENT_KEY] === undefined;
        toggleLogsLive();
        out.stopped = [logsState.live, cleared.length, els['logs-live'].attrs['aria-pressed']];
        console.log(JSON.stringify(out));""")
    assert r["off"] is False and r["on"] == [True, "true", [10000]] and r["firstTick"] == 1
    assert r["hidden"] is False and r["elsewhere"] is False and r["pressing"] is False and r["ticks"] is True
    assert r["searches"] == 2, "a hidden tab or a press on the bars searched"
    assert r["remembered"], "a live search went into the last searches"
    assert r["stopped"] == [False, 1, "false"]


@needs_node
def test_a_live_search_that_changes_nothing_leaves_the_list_alone():
    r = _run(r"""
        const flow = events([ev('1', 'same')]);
        globalThis.fetch = async () => reply(JSON.parse(JSON.stringify(flow)));
        await runLogsSearch({ silent: true });
        els['logs-results'].innerHTML = 'MARK';
        await runLogsSearch({ silent: true });
        const same = els['logs-results'].innerHTML;
        flow.events.push(ev('2', 'new')); flow.count = 2;
        await runLogsSearch({ silent: true });
        console.log(JSON.stringify({ same, changed: els['logs-results'].innerHTML.includes('new') }));""")
    assert r == {"same": "MARK", "changed": True}


@needs_node
def test_the_tab_opens_with_the_last_search_and_range():
    r = _run(r"""
        store[LOGS_RECENT_KEY] = JSON.stringify(['source=dns | top query', 'older']);
        store[LOGS_RANGE_KEY] = '4h';
        initLogs();
        initLogs();
        await new Promise(r => setTimeout(r, 0));
        const first = searches().map(u => Object.fromEntries(query(u)));
        const input = els['logs-query'];
        logsTabShown();
        await new Promise(r => setTimeout(r, 0));
        input.value = 'source=mcp';
        let prevented = false;
        input.listeners.keydown[0]({ key: 'Enter', preventDefault: () => { prevented = true; } });
        await new Promise(r => setTimeout(r, 0));
        console.log(JSON.stringify({ first, sources: calls.filter(u => u.startsWith('/api/logs/sources')).length,
            expanded: els['logs-syntax'].attrs['aria-expanded'], range: els['logs-range'].innerHTML,
            total: searches().length, prevented,
            last: Object.fromEntries(query(searches().pop())), recent: logsRecent(), layer: els['logs-hl'].innerHTML }));""")
    assert r["first"] == [{"q": "source=dns | top query", "earliest": "-4h", "limit": "200"}]
    assert r["sources"] == 2 and r["expanded"] == "true" and r["total"] == 3
    assert 'data-range="4h" aria-pressed="true"' in r["range"] and r["prevented"]
    assert r["last"]["q"] == "source=mcp" and r["recent"][0] == "source=mcp"
    assert "lq-field" in r["layer"]


@needs_node
def test_the_menu_lists_recent_searches_and_the_examples():
    r = _run(r"""
        els['logs-menu'].hidden = true;
        logsRemember('source=dns "<b>"');
        toggleLogsMenu();
        const open = [els['logs-menu'].hidden, els['logs-menu-btn'].attrs['aria-expanded'], els['logs-menu'].innerHTML];
        const item = { getAttribute: () => 'source=dns | top query' };
        onLogsMenuClick({ target: { closest: () => item } });
        await new Promise(r => setTimeout(r, 0));
        console.log(JSON.stringify({ open, closed: els['logs-menu'].hidden, query: logsState.query,
            sent: query(searches().pop()).get('q') }));""")
    assert r["open"][0] is False and r["open"][1] == "true"
    assert "RECENT" in r["open"][2] and "EXAMPLES" in r["open"][2] and "<b>" not in r["open"][2]
    assert "Access without polling" in r["open"][2]
    assert r["closed"] is True and r["query"] == "source=dns | top query" and r["sent"] == r["query"]


# --- The commands card ------------------------------------------------------------

COMMAND_KINDS = {"term", "pipe", "source"}
PIPE_NAMES = ["head", "tail", "sort", "dedup", "table", "fields", "stats", "top", "rare", "timechart"]


def _esc(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


@needs_node
def test_commands_card_lists_every_group_and_stays_text():
    r = _run(r"""
        const html = logsCommandsHtml();
        LOGS_COMMANDS[0].items.push({ text: '<img src=x>', hint: 'an <img src=x> stays text', kind: 'term' });
        const hostile = logsCommandsHtml();
        LOGS_COMMANDS[0].items.pop();
        logsCommandsGroup = 'PIPES';
        const piped = logsCommandsHtml();
        logsCommandsGroup = '';
        console.log(JSON.stringify({ groups: LOGS_COMMANDS.map(g => g.group), html, hostile, piped, shut: logsCommandsHtml(),
            items: LOGS_COMMANDS.map(g => g.items.map(i => [i.text, i.hint, i.kind])) }));""")
    assert r["groups"] == ["SEARCH", "PIPES", "TIME", "SOURCES"]
    groups = dict(zip(r["groups"], r["items"]))
    html = r["html"]
    for name, items in groups.items():
        assert f">{name}<" in html, name
        assert len(items) >= 2, name
        for text, hint, kind in items:
            assert kind in COMMAND_KINDS, (text, kind)
            assert text.strip() and hint.strip() and len(hint) <= 60, (text, hint)
            assert f'data-logs-cmd="{_esc(text)}"' in html, text
            assert f'data-logs-kind="{kind}"' in html, (text, kind)
            assert _esc(hint) in html, hint
    assert [text for text, _, kind in groups["PIPES"] if not kind == "pipe"] == []
    for pipe in PIPE_NAMES:
        assert any(re.fullmatch(r"\| %s\b.*" % pipe, text) for text, _, _ in groups["PIPES"]), pipe
    for word in ('word', '"a phrase"', "field=value", "field!=value", "field>5", "AND", "OR", "NOT", "( )", "*"):
        assert any(text == word for text, _, _ in groups["SEARCH"]), word
    assert [text for text, _, _ in groups["TIME"]] == ["earliest=-15m", "latest=now"]
    assert [text for text, _, kind in groups["SOURCES"]] == [f"source={s}" for s in SIX_SOURCES]
    assert {kind for _, _, kind in groups["SOURCES"]} == {"source"}
    # one group open at a time, the remembered one
    assert html.count('aria-expanded="true"') == 1 and 'data-logs-cmd-head="SEARCH" aria-expanded="true"' in html
    assert 'data-logs-cmd-head="PIPES" aria-expanded="true"' in r["piped"]
    assert 'aria-expanded="true"' not in r["shut"], "every group can be closed"
    # the rows carry their data, not an inline handler
    assert not re.search(r'\bon[a-z]+="', html), "an inline handler in the card"
    assert _tags(r["hostile"]) <= ALLOWED_TAGS, _tags(r["hostile"])
    assert "<img" not in r["hostile"] and "&lt;img src=x&gt;" in r["hostile"]


def test_the_info_of_the_commands_card_names_the_group_that_replaces():
    """A click adds the command to the box — in four groups out of five. A
    SOURCES row takes the place of the source the query has and searches, as a
    source chip does. The README and the help guide say so; the (i) of the
    card promised the opposite for it."""
    html = _read(INDEX_HTML)
    info = re.search(r'data-info="([^"]*)">COMMANDS</h3>', html)
    assert info, "the COMMANDS card has no (i)"
    text = info.group(1)
    assert "instead of replacing what is there" in text, text
    assert re.search(r"source row\b", text) and "searches" in text, \
        f"the (i) does not say that a source row replaces the source and searches: {text}"
    guide = html[html.index('id="help-usage"'):html.index('id="help-api"')]
    assert "only a source row replaces the source and searches" in guide
    # The LOGS section of the README moved into the guide (docs/logs.md)
    assert "A source row is the exception" in _read("docs/logs.md")


@needs_node
def test_escape_closes_the_menu_beside_the_search_box():
    """handleGlobalKeydown handled the info popover, the save dialog and the
    help modal and then fell through: an open ⋯ menu stayed open."""
    r = _run(r"""
        const out = {};
        els['logs-save'].classList.add('hidden');
        toggleLogsMenu(true);
        out.open = [els['logs-menu'].hidden, els['logs-menu-btn'].attrs['aria-expanded']];
        handleGlobalKeydown({ key: 'Escape' });
        out.closed = [els['logs-menu'].hidden, els['logs-menu-btn'].attrs['aria-expanded'],
            els['logs-menu-btn'].focused];
        // and with nothing open the key goes on to the layers under it
        handleGlobalKeydown({ key: 'Escape' });
        out.again = els['logs-menu'].hidden;
        console.log(JSON.stringify(out));""")
    assert r["open"] == [False, "true"], "the menu did not open"
    assert r["closed"][:2] == [True, "false"], "Escape left the ⋯ menu of the LOGS tab open"
    assert r["closed"][2] >= 1, "the focus stayed on a hidden menu"
    assert r["again"] is True


@needs_node
def test_a_command_is_inserted_not_substituted():
    r = _run(r"""
        const out = {};
        const caret = () => els['logs-query'].caret;
        logsSetQuery('source=dns foo');
        out.pipe = [logsInsertCommand('| stats count by ', 'pipe'), logsState.query, caret()];
        logsSetQuery('a | head 5');
        out.term = [logsInsertCommand('field=', 'term'), logsState.query, caret()];
        logsSetQuery('');
        out.empty = [logsInsertCommand('| head 20', 'pipe'), logsState.query, caret()];
        logsSetQuery('*');
        out.star = [logsInsertCommand('field=value', 'term'), logsState.query, caret()];
        // a query that already ends in a pipe does not grow a second one
        logsSetQuery('a |');
        out.dangling = [logsInsertCommand('| head 20', 'pipe'), logsState.query, caret()];
        logsSetQuery('a | head 5 |  ');
        out.dangling2 = [logsInsertCommand('| top field', 'pipe'), logsState.query];
        logsSetQuery('a "b |"');
        out.quoted = [logsInsertCommand('| head 20', 'pipe'), logsState.query];
        out.focused = els['logs-query'].focused;
        out.noSearch = searches().length;
        els['logs-query'].caret = null;
        logsSetQuery('source=dns x');
        out.source = [logsInsertCommand('source=firewall', 'source'), logsState.query, searches().length, caret()];
        logsSetQuery('keep me');
        out.unknown = [logsInsertCommand('| head 5', 'wat'), logsState.query];
        out.blank = [logsInsertCommand('   ', 'pipe'), logsState.query];
        out.nothing = [logsInsertCommand(null, 'term'), logsState.query];
        out.caretAfterNothing = caret();
        console.log(JSON.stringify(out));""")
    assert r["pipe"] == [True, "source=dns foo | stats count by ", [32, 32]], "a pipe goes behind the whole query"
    assert r["term"] == [True, "a field= | head 5", [8, 8]], "a term goes where the search part ends"
    assert r["empty"] == [True, "* | head 20", [11, 11]]
    assert r["star"] == [True, "field=value", [11, 11]]
    assert r["dangling"] == [True, "a | head 20", [11, 11]], "a dangling pipe made an invalid query"
    assert r["dangling2"] == [True, "a | head 5 | top field"]
    assert r["quoted"] == [True, 'a "b |" | head 20'], "a pipe inside a string is not a dangling pipe"
    assert r["focused"] == 7, "the search box did not take the focus"
    assert r["noSearch"] == 0, "a command searched on its own"
    assert r["source"] == [True, "source=firewall x", 1, None], "a source goes through logsAddSource, which searches"
    assert r["unknown"] == [False, "keep me"], "an unknown kind changes nothing"
    assert r["blank"] == [False, "keep me"] and r["nothing"] == [False, "keep me"]
    assert r["caretAfterNothing"] is None, "a command that does nothing moved the caret"


@needs_node
def test_the_question_button_toggles_the_card():
    r = _run(r"""
        const out = {};
        const shut = () => els['logs-commands'].classList.contains('is-shut');
        const expanded = () => [els['logs-syntax'].attrs['aria-expanded'], els['logs-commands-toggle'].attrs['aria-expanded']];
        els['logs-commands'].classList.add('is-shut');
        out.opened = [toggleLogsCommands(), shut(), expanded(), store[LOGS_COMMANDS_KEY],
            els['logs-commands-list'].innerHTML.includes('data-logs-cmd=')];
        out.closed = [toggleLogsCommands(), shut(), expanded(), store[LOGS_COMMANDS_KEY]];
        out.forced = [toggleLogsCommands(false), toggleLogsCommands(true), shut(), logsCommandsOpen()];
        // the card is never taken out of the page: only the list folds away
        out.stays = els['logs-commands'].hidden;
        // the state comes back when the tab is set up, and setting it up remembers nothing
        toggleLogsCommands(false);
        delete store[LOGS_COMMANDS_KEY];
        logsReady = false;
        initLogs();
        await new Promise(r => setTimeout(r, 0));
        out.restored = [shut(), expanded(), LOGS_COMMANDS_KEY in store];
        toggleLogsCommands(false);
        logsReady = false;
        initLogs();
        await new Promise(r => setTimeout(r, 0));
        out.restoredShut = [shut(), expanded()];
        // the head of the card opens and closes it too
        const card = { target: { closest: sel => (sel === '[data-logs-cmd-card]' ? { getAttribute: () => 'COMMANDS' } : null) } };
        onLogsCommandsClick(card);
        out.byHead = [shut(), store[LOGS_COMMANDS_KEY]];
        onLogsCommandsClick(card);
        out.byHeadAgain = [shut(), store[LOGS_COMMANDS_KEY]];
        toggleLogsCommands(true);
        // a group opens on a click and is remembered; a second click shuts it
        const head = name => ({ target: { closest: sel => (sel === '[data-logs-cmd-head]' ? { getAttribute: () => name } : null) } });
        onLogsCommandsClick(head('PIPES'));
        out.group = [logsCommandsGroup, store[LOGS_COMMANDS_GROUP_KEY],
            els['logs-commands-list'].innerHTML.includes('data-logs-cmd-head="PIPES" aria-expanded="true"')];
        onLogsCommandsClick(head('PIPES'));
        out.shutGroup = logsCommandsGroup;
        onLogsCommandsClick(head('nope'));
        out.bogus = logsCommandsGroup;
        // a click on a row inserts, it does not search
        logsSetQuery('x');
        const searchesBefore = searches().length;
        onLogsCommandsClick({ target: { closest: sel => (sel === '[data-logs-cmd]'
            ? { getAttribute: k => (k === 'data-logs-cmd' ? '| top field' : 'pipe') } : null) } });
        out.inserted = [logsState.query, searches().length - searchesBefore];
        onLogsCommandsClick({ target: { closest: () => null } });
        onLogsCommandsClick({});
        out.quiet = logsState.query;
        // a blocked storage breaks nothing
        localStorage.setItem = () => { throw new Error('blocked'); };
        let blocked = 'ok';
        try { toggleLogsCommands(false); onLogsCommandsClick(head('TIME')); } catch (e) { blocked = 'threw'; }
        out.blocked = [blocked, shut(), logsCommandsGroup];
        store[LOGS_COMMANDS_KEY] = 'junk';
        out.junk = logsCommandsOpen();
        // a window too narrow for the column starts the card closed
        delete store[LOGS_COMMANDS_KEY];
        globalThis.window = { innerWidth: LOGS_COMMANDS_WIDE - 100 };
        out.narrow = logsCommandsOpen();
        globalThis.window.innerWidth = LOGS_COMMANDS_WIDE + 100;
        out.wide = logsCommandsOpen();
        localStorage.getItem = () => { throw new Error('blocked'); };
        let read = 'ok';
        try { out.narrowBlocked = logsCommandsOpen(); } catch (e) { read = 'threw'; }
        globalThis.window.innerWidth = 800;
        out.readBlocked = [read, logsCommandsOpen()];
        console.log(JSON.stringify(out));""")
    assert r["opened"] == [True, False, ["true", "true"], "1", True]
    assert r["closed"] == [False, True, ["false", "false"], "0"]
    assert r["forced"] == [False, True, False, True]
    assert r["stays"] is False, "the collapsed card keeps its head on the page"
    assert r["restored"] == [False, ["true", "true"], False], "setting the tab up must not remember a state"
    assert r["restoredShut"] == [True, ["false", "false"]], "the card forgot that it was closed"
    assert r["byHead"] == [False, "1"] and r["byHeadAgain"] == [True, "0"], "the head does not open and close the card"
    assert r["group"] == ["PIPES", "PIPES", True] and r["shutGroup"] == "" and r["bogus"] == ""
    assert r["inserted"] == ["x | top field", 0], "the row searched on its own"
    assert r["quiet"] == "x | top field"
    assert r["blocked"] == ["ok", True, "TIME"]
    assert r["junk"] is True, "a value the card never wrote falls back to the default"
    assert r["narrow"] is False and r["wide"] is True, "the width decides on a first visit"
    assert r["narrowBlocked"] is True and r["readBlocked"] == ["ok", False], "a blocked storage read breaks the width rule"


def _rule_bodies(path):
    """selector -> everything the top-level rules of the sheet set for it."""
    bodies = {}
    for prelude, body in _css_blocks(_strip_comments(_read(path))):
        if body is None or prelude.startswith("@"):
            continue
        for selector in _selectors(prelude):
            bodies[selector.strip()] = bodies.get(selector.strip(), "") + body
    return bodies


def test_both_themes_style_the_commands_card():
    classic, theme = _rule_bodies(STYLE_CSS), _rule_bodies(THEME_CSS)
    for cls in ("logs-commands", "logs-commands-head", "logs-commands-toggle", "logs-cmd-group", "logs-cmd-head",
                "logs-cmd", "logs-cmd-text", "logs-cmd-hint"):
        assert f".{cls}" in classic, f"style.css has no rule for .{cls}"
        assert f'[data-theme="cyberpunk"] .{cls}' in theme, f"Cyberpunk has no rule for .{cls}"
    card = classic[".logs-commands"]
    assert re.search(r"position:\s*sticky", card), "the card does not stay while the results scroll"
    assert re.search(r"top:\s*(0|var\(--logs-bar-height\))", card), "the card has no top to stay at"
    # Collapsed the card is one line high: only the list folds away, the head stays
    assert re.search(r"display:\s*none", classic.get(".logs-commands.is-shut .logs-commands-list", "")), \
        "the collapsed card does not fold its list away"
    gone = [selector for selector, body in classic.items()
            if re.fullmatch(r"\.logs-commands(\.is-shut)?(\[hidden\])?", selector)
            and re.search(r"display:\s*none", body)]
    assert not gone, f"the collapsed card is taken off the page by {gone}"
    for name, bodies in (("style.css", classic), ("theme-cyberpunk.css", theme)):
        for selector, body in bodies.items():
            if "logs-cmd" in selector or "logs-commands" in selector:
                assert not LITERAL_COLOR.search(body), f"{name}: a colour literal in {selector}"
    # under 1100 px the card lies over the results, not in the column
    narrow = "".join(body for prelude, body in _css_blocks(_strip_comments(_read(STYLE_CSS)))
                     if body and re.match(r"@media\b", prelude) and re.search(r"max-width:\s*1100px", prelude))
    assert narrow, "style.css has no @media (max-width: 1100px) block"
    order = {}
    for prelude, body in _css_blocks(narrow):
        for selector in (_selectors(prelude) if body else []):
            m = re.search(r"(?:^|[;{\s])order:\s*(-?\d+)", body)
            if m:
                order[selector.strip()] = int(m.group(1))
    assert ".logs-commands" in order and ".logs-main" in order, order
    assert order[".logs-commands"] < order[".logs-main"] < order.get(".logs-fields", 99), order
    assert re.search(r"grid-template-columns:\s*minmax\(0, 1fr\)", narrow), \
        "the card takes the whole width instead of a column beside the results"


def test_the_commands_card_raised_the_asset_versions():
    html = _read(INDEX_HTML)
    assert "style.css?v=70" not in html and "theme-cyberpunk.css?v=28" not in html and "app.js?v=101" not in html, \
        "asset versions not raised"


# --- The result tabs and the form switches -----------------------------------------

# Every tag the charts of the result area may bring, next to the ones a list or a table brings
CHART_TAGS = ALLOWED_TAGS | {"svg", "g", "rect", "path", "circle", "polyline", "polygon", "line", "text", "tspan",
                             "title"}


def _bare_tags(html):
    """The markup with every "..." attribute value emptied: what is left are the
    tags themselves, so a hostile value inside an attribute cannot read as one."""
    return re.sub(r'"[^"]*"', '""', html)


def test_the_result_head_sits_over_the_result():
    html = _read(INDEX_HTML)
    main = re.search(r'<div class="logs-main">(.*?)<div class="logs-results"', html, re.S)
    assert main, "the tabs and the form switches do not stand over the result"
    head = main.group(1)
    assert 'role="tablist"' in head and 'id="logs-tabs"' in head and 'id="logs-forms"' in head
    for view, label in (("events", "EVENTS"), ("statistics", "STATISTICS"), ("visualization", "VISUALIZATION")):
        assert f'id="logs-tab-{view}"' in head and f'data-logs-view="{view}"' in head, view
        assert f">{label}</button>" in head, label
        assert f"setLogsView(&#39;{view}&#39;)" in head or f"setLogsView('{view}')" in head, view
    assert head.count('role="tab"') == 3
    for form in ("table", "pie", "bars", "line", "sankey"):
        assert f'id="logs-form-{form}"' in head and f'data-logs-form="{form}"' in head, form
        assert f"setLogsForm(&#39;{form}&#39;)" in head or f"setLogsForm('{form}')" in head, form
    assert ">TABLE</button>" in head and ">SANKEY</button>" in head


@needs_node
def test_result_shape_finds_the_name_and_the_number_column():
    r = _run(r"""
        const shape = (columns, rows, extra) => logsResultShape(table(columns, rows, extra));
        console.log(JSON.stringify({
            count: shape(['f', 'count'], [['a', 3], ['b', 1]]),
            top: shape(['f', 'count', 'percent'], [['a', 3, 75], ['b', 1, 25]]),
            status: shape(['status', 'count'], [[200, 12], [404, 3]]),
            text: shape(['a', 'b', 'c'], [['x', 'y', 'z']]),
            pair: shape(['a', 'b', 'count'], [['x', 'y', 2]]),
            time: logsResultShape(timechart(['_time', 'powershell', 'access'], [['2026-11-14T10:00:00Z', 2, 1]])),
            empty: shape(['f', 'count'], []),
            emptyText: shape(['a', 'b'], []),
            emptyAvg: shape(['tool', 'avg(ms)'], []),
            emptySum: [shape(['f', 'sum(bytes)'], []).value, shape(['f', 'dc(user)'], []).value,
                shape(['f', 'min(x)'], []).value, shape(['f', 'max(x)'], []).value, shape(['f', 'percent'], []).value],
            gaps: shape(['f', 'count'], [['a', null], ['b', 2], ['c', '']]),
            mixed: shape(['f', 'n'], [['a', 1], ['b', 'x']]),
            blank: shape(['f', 'n'], [['a', null], ['b', '']]),
            bool: shape(['f', 'n'], [['a', true]]),
            later: shape(['a', 'b', 'c', 'count'], [['x', 'y', 'z', 4]]),
            events: logsResultShape(events([], { count: 5 })),
            none: logsResultShape(null),
            cut: shape(['f', 'count'], [['a', 3]], { count: 5312, truncated: true }),
        }));""")
    assert r["count"]["label"] == 0 and r["count"]["value"] == 1 and r["count"]["labels"] == [0]
    assert r["top"]["value"] == 1, "top f must carry its count, not its percent"
    assert r["status"]["value"] == 1, "column 0 stays the name even when it holds numbers"
    assert r["text"]["value"] is None and r["text"]["labels"] == [0]
    assert r["pair"] == {"type": "table", "label": 0, "value": 2, "labels": [0, 1], "rows": 1, "count": 1,
                         "truncated": False}
    assert r["time"]["type"] == "timechart" and r["time"]["labels"] == [0] and r["time"]["value"] == 1
    assert r["empty"]["value"] == 1 and r["empty"]["rows"] == 0, "an empty answer must lock nothing"
    assert r["emptyText"]["value"] is None, "without rows only an aggregation counts as a number column"
    assert r["emptyAvg"]["value"] == 1 and r["emptySum"] == [1, 1, 1, 1, 1]
    assert r["gaps"]["value"] == 1, "an empty cell is no text"
    assert r["mixed"]["value"] is None and r["blank"]["value"] is None and r["bool"]["value"] is None
    assert r["later"] == {"type": "table", "label": 0, "value": 3, "labels": [0, 1, 2], "rows": 1, "count": 1,
                          "truncated": False}
    assert r["events"] == {"type": "events", "label": None, "value": None, "labels": [], "rows": 0, "count": 5,
                           "truncated": False}
    assert r["none"]["type"] == "events" and r["none"]["value"] is None
    assert r["cut"]["count"] == 5312 and r["cut"]["rows"] == 1 and r["cut"]["truncated"] is True


@needs_node
def test_the_tabs_lock_with_a_reason_and_pick_a_default():
    r = _run(r"""
        const tabs = () => Object.fromEntries(LOGS_VIEWS.map(v => [v, [els['logs-tab-' + v].attrs['aria-selected'],
            els['logs-tab-' + v].attrs['aria-disabled'], els['logs-tab-' + v].attrs['title']]]));
        const out = {};
        renderLogsResult(events([ev('1', 'a message')]));
        out.events = [tabs(), logsView, els['logs-forms'].hidden, els['logs-results'].innerHTML.includes('logs-event')];
        renderLogsResult(table(['tool', 'count'], [['a', 3]]));
        out.table = [tabs(), logsView, els['logs-forms'].hidden, els['logs-results'].innerHTML.includes('<table')];
        renderLogsResult(timechart(['_time', 'a'], [['2026-11-14T10:00:00Z', 2], ['2026-11-14T10:05:00Z', 3]]));
        out.time = [tabs(), logsView, els['logs-results'].innerHTML.includes('chart-line')];
        // the chosen tab holds while the columns stay the same
        setLogsView('statistics');
        renderLogsResult(timechart(['_time', 'a'], [['2026-11-14T10:00:00Z', 9], ['2026-11-14T10:05:00Z', 1]]));
        out.held = [logsView.view, els['logs-results'].innerHTML.includes('<table')];
        // a tab that becomes unusable falls back to the first usable one
        setLogsView('visualization');
        renderLogsResult(events([ev('2', 'another')]));
        out.fell = [logsView, els['logs-tab-events'].attrs['aria-selected']];
        // other columns open their own default again
        renderLogsResult(table(['tool', 'count'], [['a', 3]]));
        out.again = logsView.view;
        renderLogsResult(table(['a', 'b', 'c'], [['x', 'y', 'z']]));
        out.textOnly = [tabs(), logsView, setLogsView('visualization'), setLogsView('nope'), logsView.view];
        console.log(JSON.stringify(out));""")
    pipe = "needs a pipe such as | stats count by field"
    made = "the pipes made a table; remove them to see events"
    assert r["events"][0]["events"][:2] == ["true", "false"]
    assert r["events"][0]["statistics"][1] == "true" and r["events"][0]["statistics"][2] == pipe
    assert r["events"][0]["visualization"][1] == "true" and r["events"][0]["visualization"][2] == pipe
    assert r["events"][1] == {"view": "events", "form": ""} and r["events"][2] is True and r["events"][3] is True
    assert r["table"][0]["statistics"][:2] == ["true", "false"] and r["table"][0]["events"][1] == "true"
    assert r["table"][0]["events"][2] == made
    assert r["table"][1] == {"view": "statistics", "form": "table"} and r["table"][2] is False and r["table"][3] is True
    assert r["time"][0]["visualization"][:2] == ["true", "false"] and r["time"][0]["events"][1] == "true"
    assert r["time"][1] == {"view": "visualization", "form": "line"} and r["time"][2] is True
    assert r["held"] == ["statistics", True], "the tab did not hold over the same columns"
    assert r["fell"] == [{"view": "events", "form": ""}, "true"]
    assert r["again"] == "statistics", "other columns must open their own default"
    assert r["textOnly"][0]["visualization"][1] == "true"
    assert r["textOnly"][0]["visualization"][2] == "needs one name column and one number column"
    assert r["textOnly"][1] == {"view": "statistics", "form": "table"}
    assert r["textOnly"][2] is False and r["textOnly"][3] is False and r["textOnly"][4] == "statistics"


@needs_node
def test_the_form_switches_match_the_columns():
    r = _run(r"""
        const of = result => {
            renderLogsResult(result);
            return { state: Object.fromEntries(LOGS_FORMS.map(f => [f, [els['logs-form-' + f].attrs['aria-pressed'],
                els['logs-form-' + f].attrs['aria-disabled'], els['logs-form-' + f].attrs['title']]])),
                forms: logsFormsFor(logsResultShape(result)) };
        };
        const out = {
            count: of(table(['f', 'count'], [['a', 3]])),
            pair: of(table(['a', 'b', 'count'], [['x', 'y', 2]])),
            text: of(table(['a', 'b', 'c'], [['x', 'y', 'z']])),
            none: of(events([ev('1', 'm')])),
        };
        out.time = of(timechart(['_time', 'a'], [['2026-11-14T10:00:00Z', 2]]));
        out.picked = [setLogsForm('pie'), logsView.view, logsView.form, setLogsForm('sankey'),
            setLogsForm('bars'), logsView.form, els['logs-form-bars'].attrs['aria-pressed'],
            els['logs-form-line'].attrs['aria-pressed']];
        out.toTable = [setLogsForm('table'), logsView, els['logs-results'].innerHTML.includes('<table')];
        out.bogus = [setLogsForm('nope'), logsView.form];
        console.log(JSON.stringify(out));""")
    columns = "needs one name column and one number column"
    assert r["count"]["forms"]["table"] is True and r["count"]["forms"]["pie"] is True
    assert r["count"]["forms"]["bars"] is True and r["count"]["forms"]["sankey"] is False
    assert r["count"]["forms"]["line"] is False
    assert r["count"]["forms"]["why"]["line"].startswith("needs a timechart")
    assert "| stats count by a, b" in r["count"]["forms"]["why"]["sankey"]
    assert r["pair"]["forms"]["sankey"] is True and "sankey" not in r["pair"]["forms"]["why"]
    assert r["text"]["forms"] == {"table": True, "pie": False, "bars": False, "line": False, "sankey": False,
                                  "why": {"pie": columns, "bars": columns,
                                          "line": r["count"]["forms"]["why"]["line"],
                                          "sankey": r["count"]["forms"]["why"]["sankey"]}}
    assert r["text"]["state"]["pie"][1] == "true" and r["text"]["state"]["pie"][2] == columns
    assert r["none"]["forms"]["pie"] is False and r["none"]["forms"]["why"]["pie"].startswith("needs a pipe")
    assert r["time"]["forms"]["line"] is True and r["time"]["forms"]["bars"] is True
    assert r["time"]["forms"]["pie"] is False and r["time"]["forms"]["sankey"] is False
    assert r["time"]["forms"]["why"]["pie"].startswith("needs "), r["time"]["forms"]["why"]["pie"]
    assert "line or as bars" in r["time"]["forms"]["why"]["pie"]
    assert r["time"]["state"]["line"][0] == "true" and r["time"]["state"]["pie"][1] == "true"
    # A tile reads the reason of a form as "saved as <form>, which <reason>":
    # every one of them has to carry that sentence (the spec's wording)
    for case in ("count", "pair", "text", "none", "time"):
        for form, why in r[case]["forms"]["why"].items():
            assert why.startswith("needs "), (case, form, why)
    assert r["picked"][:3] == [False, "visualization", "line"], "a form the columns cannot carry was taken"
    assert r["picked"][3] is False and r["picked"][4] is True and r["picked"][5] == "bars"
    assert r["picked"][6] == "true" and r["picked"][7] == "false"
    assert r["toTable"] == [True, {"view": "statistics", "form": "table"}, True]
    assert r["bogus"] == [False, "table"]


@needs_node
def test_each_form_draws_its_chart():
    r = _run(r"""
        const groups = n => Array.from({ length: n }, (_, i) => ['g' + i, n - i]);
        const two = table(['f', 'count'], [['a', 3], ['b', 1]]);
        const time = timechart(['_time', 'a', 'b'], [['2026-11-14T10:00:00Z', 2, 1], ['2026-11-14T10:05:00Z', 1, 4]]);
        console.log(JSON.stringify({
            pie: logsChartHtml(two, 'pie'),
            bars: logsChartHtml(two, 'bars'),
            stacked: logsChartHtml(time, 'bars'),
            line: logsChartHtml(time, 'line'),
            sankey: logsChartHtml(table(['src', 'dst', 'count'], [['a', 'x', 3], ['b', 'y', 2], ['a', 'y', 1]]), 'sankey'),
            wrong: [logsChartHtml(two, 'line'), logsChartHtml(table(['a', 'b', 'c'], [['x', 'y', 'z']]), 'pie'),
                logsChartHtml(events([ev('1', 'm')]), 'pie'), logsChartHtml(two, 'table'),
                logsChartHtml(two, 'nope'), logsChartHtml(null, 'pie'), logsChartHtml(two, undefined)],
            many: logsChartHtml(table(['f', 'count'], groups(14)), 'pie'),
            thirteen: logsChartHtml(table(['f', 'count'], groups(13)), 'bars'),
            sum: logsChartHtml(table(['f', 'count'], [['a', 1], ['a', 2], ['b', 4]]), 'pie'),
            emptyRows: logsChartHtml(table(['f', 'count'], []), 'pie'),
            emptyTime: logsChartHtml(timechart(['_time', 'a'], [['2026-11-14T10:00:00Z', 0], ['2026-11-14T10:05:00Z', 0]]), 'line'),
            sankeyMany: logsChartHtml(table(['a', 'b', 'count'],
                Array.from({ length: 40 }, (_, i) => ['a' + i, 'b' + (i % 20), 40 - i])), 'sankey'),
            wide: logsChartHtml(time, 'line', { width: 300, height: 90 }),
        }));""")
    assert '<svg class="chart-svg chart-pie"' in r["pie"] and 'class="chart-legend"' in r["pie"]
    assert r["pie"].count('class="chart-seg chart-slice"') == 2 and "chart-split" in r["pie"]
    assert '<svg class="chart-svg chart-bars"' in r["bars"] and 'class="chart-legend"' in r["bars"]
    assert r["bars"].count('class="chart-bar"') == 2 and r["bars"].count('class="chart-slot"') == 2
    assert '<svg class="chart-svg chart-bars"' in r["stacked"] and r["stacked"].count("data-bin-start=") == 2
    assert "logs-legend-item" in r["stacked"] and "chart-slot" not in r["stacked"]
    assert r["line"].count('class="chart-line"') == 2 and 'class="chart-svg chart-lines"' in r["line"]
    assert "logs-legend-item" in r["line"] and "data-bin-start=" not in r["line"]
    assert '<svg class="chart-svg chart-sankey"' in r["sankey"]
    assert r["sankey"].count("data-sankey-node=") == 4 and r["sankey"].count("data-sankey-link=") == 3
    assert r["sankey"].count('data-sankey-node="0:') == 2 and r["sankey"].count('data-sankey-node="1:') == 2
    assert r["wrong"] == ["", "", "", "", "", "", ""], "a form that does not fit the result drew something"
    assert r["many"].count('class="chart-seg chart-slice"') == 13 and r["many"].count("other") >= 1
    # topWithOther keeps a thirteenth group rather than hiding a single one behind "other"
    assert r["thirteen"].count('class="chart-bar"') == 13 and "other" not in r["thirteen"]
    assert r["sum"].count('class="chart-seg chart-slice"') == 2 and 'data-value="4"' in r["sum"]
    assert "chart-empty" in r["emptyRows"] and "chart-svg" not in r["emptyRows"]
    assert "chart-empty" in r["emptyTime"], "a timechart of only zeros says so instead of drawing the axis"
    assert r["sankeyMany"].count("data-sankey-node=") == 26 and "other" in r["sankeyMany"]
    assert 'width="300"' in r["wide"] and 'height="90"' in r["wide"]


@needs_node
def test_a_chart_form_asks_for_a_thousand_rows_and_warns_when_it_is_short():
    r = _run(r"""
        const out = {};
        const rows = Array.from({ length: 1000 }, (_, i) => ['g' + i, 1000 - i]);
        const big = table(['query', 'count'], rows, { count: 5312, matched: 40000 });
        globalThis.fetch = async url => { calls.push(url); return url.startsWith('/api/logs/sources') ? reply([]) : reply(big); };
        logsSetQuery('source=dns | stats count by query');
        await submitLogsSearch();
        out.statistics = [logsView, query(searches().pop()).get('limit')];
        out.form = [setLogsForm('pie'), logsView];
        await new Promise(r => setTimeout(r, 0));
        out.asked = query(searches().pop()).get('limit');
        out.note = els['logs-results'].innerHTML;
        const before = searches().length;
        setLogsForm('bars');
        await new Promise(r => setTimeout(r, 0));
        out.second = searches().length - before;
        // a new search without a pipe can only be events: it stays at 200 rows
        logsSetQuery('source=dns');
        const was = logsView.form;
        const at = searches().length;
        await submitLogsSearch();
        out.noPipe = [was, query(searches()[at]).get('limit')];
        logsSetQuery('source=dns | stats count by query');
        out.back = setLogsView('statistics');
        await runLogsSearch();
        out.table = query(searches().pop()).get('limit');
        // a result that holds every group of its search needs no second search for a chart
        const whole = table(['f', 'count'], [['a', 3], ['b', 1]]);
        globalThis.fetch = async url => { calls.push(url); return url.startsWith('/api/logs/sources') ? reply([]) : reply(whole); };
        await submitLogsSearch();
        const complete = searches().length;
        setLogsForm('pie');
        await new Promise(r => setTimeout(r, 0));
        out.whole = [searches().length - complete, els['logs-results'].innerHTML.includes('logs-trunc')];
        globalThis.fetch = async url => { calls.push(url); return url.startsWith('/api/logs/sources') ? reply([]) : reply(big); };
        logsSetQuery('source=dns | stats count by query');
        await submitLogsSearch();
        setLogsForm('pie');
        await new Promise(r => setTimeout(r, 0));
        const sent = searches().length;
        onLogsClick({ target: { closest: sel => (sel === '[data-logs-sort]' ? { getAttribute: () => null } : null) } });
        await new Promise(r => setTimeout(r, 0));
        out.clicked = [logsState.query, query(searches().pop()).get('q'), searches().length > sent,
            query(searches().pop()).get('limit')];
        out.quiet = logsTruncNoteHtml(logsResultShape(table(['f', 'count'], [['a', 1]])));
        out.truncated = logsTruncNoteHtml(logsResultShape(table(['f', 'count'], [['a', 1]], { truncated: true })));
        out.short = logsTruncNoteHtml(logsResultShape(table(['f', 'count'], [['a', 1]], { count: 5312 })));
        out.pipeAgain = [logsAddSortPipe(), logsState.query];
        console.log(JSON.stringify(out));""")
    assert r["statistics"] == [{"view": "statistics", "form": "table"}, "200"]
    assert r["form"] == [True, {"view": "visualization", "form": "pie"}]
    assert r["asked"] == "1000", "a chart must ask for every group the server gives"
    assert "1,000" in r["note"] and "5,312" in r["note"] and "groups shown" in r["note"]
    assert "| sort -count | head 20" in r["note"] and "logs-trunc" in r["note"] and "data-logs-sort" in r["note"]
    assert r["second"] == 0, "another chart form searched again for rows it already had"
    assert r["noPipe"] == ["bars", "200"], "a search that cannot be a chart asked for 1000 rows"
    assert r["back"] is True and r["table"] == "200", "the table must ask for 200 rows again"
    assert r["whole"] == [0, False], "a complete result searched again for rows it had"
    assert r["clicked"][0] == "source=dns | stats count by query | sort -count | head 20"
    assert r["clicked"][1] == r["clicked"][0] and r["clicked"][2] is True
    assert r["clicked"][3] == "1000", "the search of the warning line keeps the rows of the chart"
    assert r["quiet"] == "" and "10,000" in r["truncated"] and "5,312" in r["short"]
    assert r["pipeAgain"][0] is True and r["pipeAgain"][1].count("| sort -count | head 20") == 1, \
        "the pipe was added a second time"


@needs_node
def test_hostile_values_stay_text_in_every_form():
    r = _run(r"""
        const bad = '</text><script>alert(1)</script>';
        const long = 'x'.repeat(30000);
        const rows = [[bad, 5], [long, 4], ['<img src=x onerror=alert(1)>', 3], [null, 2], [{ a: '<b>' }, 1]];
        const started = Date.now();
        const out = { forms: {} };
        for (const form of ['pie', 'bars']) out.forms[form] = logsChartHtml(table(['f<s>', 'count'], rows), form);
        out.forms.sankey = logsChartHtml(table(['a', 'b', 'count'], rows.map(([v, n]) => [v, bad, n])), 'sankey');
        out.forms.line = logsChartHtml(timechart(['_time', bad, long], [['2026-11-14T10:00:00Z', 2, 1],
            ['2026-11-14T10:05:00Z', 1, 2]]), 'line');
        out.forms.stacked = logsChartHtml(timechart(['_time', bad, long], [['2026-11-14T10:00:00Z', 2, 1],
            ['2026-11-14T10:05:00Z', 1, 2]]), 'bars');
        renderLogsResult(table(['f<s>', 'count'], rows, { count: 9999 }));
        setLogsForm('pie');
        out.forms.view = els['logs-results'].innerHTML;
        out.ms = Date.now() - started;
        out.sizes = Object.fromEntries(Object.entries(out.forms).map(([k, v]) => [k, v.length]));
        out.proto = logsChartHtml(table(['f', 'count'], [['__proto__', 3], ['constructor', 2]]), 'pie');
        console.log(JSON.stringify(out));""")
    for name, markup in r["forms"].items():
        assert "<script" not in markup and "<img" not in markup and "<b>" not in markup, name
        assert not re.search(r"<[a-z][^>]*\bon[a-z]+\s*=", _bare_tags(markup)), name
        assert not (_tags(markup) - CHART_TAGS), (name, _tags(markup))
        assert markup.count("x" * 1000) == 0, f"{name} draws a value of 30,000 characters in full"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r["forms"]["pie"]
    assert "&lt;img src=x onerror=alert(1)&gt;" in r["forms"]["pie"]
    assert "(none)" in r["forms"]["pie"], "a group without a value needs a name of its own"
    assert r["ms"] < 1000, f"the charts took {r['ms']} ms"
    assert r["proto"].count('class="chart-seg chart-slice"') == 2


@needs_node
def test_the_warning_line_fits_the_result():
    r = _run(r"""
        const out = {};
        const rows = Array.from({ length: 15 }, (_, i) => ['g' + i, 15 - i]);
        const shape = result => logsResultShape(result);
        logsSetQuery('source=dns | stats count by query');
        out.groups = logsTruncNoteHtml(shape(table(['query', 'count'], rows, { count: 5312 })));
        out.cut = logsTruncNoteHtml(shape(table(['query', 'count'], rows, { truncated: true })));
        // a timechart has no groups to sort and no count field to sort by
        const time = timechart(['_time', 'a'], [['2026-11-14T10:00:00Z', 2]], { truncated: true });
        out.time = logsTruncNoteHtml(shape(time));
        out.timeMore = logsTruncNoteHtml(shape(timechart(['_time', 'a'], [['2026-11-14T10:00:00Z', 2]], { count: 999 })));
        logsSetQuery('* | timechart span=5m count by source');
        renderLogsResult(time);
        out.drawn = els['logs-results'].innerHTML;
        // the pipe is already in the query: the line says so without offering it again
        logsSetQuery('source=dns | stats count by query | sort -count | head 20');
        out.already = logsTruncNoteHtml(shape(table(['query', 'count'], rows, { count: 5312 })));
        out.dangling = logsTruncNoteHtml(shape(table(['query', 'count'], rows, { count: 5312 })), 'a | sort -count | head 20 |');
        out.other = logsTruncNoteHtml(shape(table(['query', 'count'], rows, { count: 5312 })), 'a | head 20');
        out.events = [logsTruncNoteHtml(shape(events([ev('1', 'm')], { count: 5312 }))),
            logsTruncNoteHtml(shape(events([], { truncated: true }))), logsTruncNoteHtml(null)];
        console.log(JSON.stringify(out));""")
    assert '<button type="button" class="logs-trunc" data-logs-sort' in r["groups"]
    assert "only 15 of 5,312 groups shown" in r["groups"] and "| sort -count | head 20" in r["groups"]
    assert "10,000" in r["cut"] and "data-logs-sort" in r["cut"]
    for name in ("time", "timeMore", "already", "dangling"):
        assert "<button" not in r[name] and "data-logs-sort" not in r[name], name
        assert "sort -count" not in r[name], name
        assert 'class="logs-trunc"' in r[name], name
    assert "10,000 matches" in r["time"] and "periods shown" in r["timeMore"]
    assert "only 15 of 5,312 groups shown" in r["already"]
    assert "data-logs-sort" in r["other"], "another pipe at the end is no sort pipe"
    assert "logs-trunc" in r["drawn"] and "data-logs-sort" not in r["drawn"], \
        "the chart of a timechart offers the sort pipe"
    assert r["events"] == ["", "", ""], "an answer without columns has no groups to count"


@needs_node
def test_a_table_keeps_its_sort_order_while_the_events_view_shows():
    r = _run(r"""
        const stats = table(['tool', 'count'], [['a', 3], ['b', 1]]);
        renderLogsResult(stats);
        tableSortState['logs-result'] = { col: 1, dir: 'asc' };
        renderLogsResult(events([ev('1', 'a message')]));
        const afterEvents = JSON.stringify(tableSortState['logs-result'] || null);
        renderLogsResult(stats);
        const back = JSON.stringify(tableSortState['logs-result'] || null);
        renderLogsResult(table(['tool', 'count', 'percent'], [['a', 3, 75]]));
        console.log(JSON.stringify({ afterEvents, back, other: tableSortState['logs-result'] === undefined }));""")
    assert r["afterEvents"] == '{"col":1,"dir":"asc"}', "the events view threw the order of the table away"
    assert r["back"] == '{"col":1,"dir":"asc"}', "the same table came back without its order"
    assert r["other"] is True, "another table kept the order of the last one"


@needs_node
def test_the_limit_fits_the_result_the_query_will_bring():
    r = _run(r"""
        const out = {};
        // 288 periods of five minutes, as the tab's default 24 h brings them;
        // the server slices in ascending time, so a short limit drops the newest
        const at = i => new Date(Date.UTC(2026, 10, 16, 0, i * 5)).toISOString();
        const periods = Array.from({ length: 288 }, (_, i) => [at(i), i + 1]);
        const groups = Array.from({ length: 5312 }, (_, i) => ['g' + i, 5312 - i]);
        const answer = (rows, kind) => {
            const cut = rows.slice(0, Number(kind.limit));
            const body = { count: rows.length, matched: 40312 };
            return kind.time ? timechart(['_time', 'dns'], cut, body) : table(['query', 'count'], cut, body);
        };
        globalThis.fetch = async url => {
            calls.push(url);
            if (url.startsWith('/api/logs/sources')) return reply([]);
            const params = query(url);
            return reply(answer(/timechart/.test(params.get('q')) ? periods : groups,
                { limit: params.get('limit'), time: /timechart/.test(params.get('q')) }));
        };
        // a timechart typed into the box: its first search already asks for
        // every period, and the chart holds all of them
        logsSetQuery('* | timechart span=5m count by source');
        await submitLogsSearch();
        await new Promise(go => setTimeout(go, 0));
        out.first = [query(searches()[0]).get('limit'), logsAsked, logsView, searches().length];
        out.note = els['logs-results'].innerHTML.includes('periods shown');
        out.points = (els['logs-results'].innerHTML.match(/<circle|L\d/g) || []).length > 0;
        out.rows = logsState.result.rows.length;
        // and the mirror: after the chart a table query takes the page again
        logsSetQuery('source=dns | stats count by query');
        await submitLogsSearch();
        await new Promise(go => setTimeout(go, 0));
        out.stats = [query(searches().pop()).get('limit'), logsAsked, logsView.view, logsState.result.rows.length,
            searches().length];
        // LIVE and a second Enter on the same query keep the form's limit
        const before = searches().length;
        setLogsForm('pie');
        await new Promise(go => setTimeout(go, 0));
        await runLogsSearch({ silent: true });
        await new Promise(go => setTimeout(go, 0));
        out.live = [query(searches().pop()).get('limit'), searches().length - before];
        console.log(JSON.stringify(out));""")
    assert r["first"][0] == "1000", "the first search of a timechart asks for the rows of a table"
    assert r["first"][1] == 1000 and r["first"][2] == {"view": "visualization", "form": "line"}
    assert r["first"][3] == 1, f"the timechart was searched {r['first'][3]} times"
    assert r["rows"] == 288 and r["points"] is True
    assert r["note"] is False, "the chart drops periods and says so instead of asking for them"
    assert r["stats"][:3] == ["200", 200, "statistics"], "a table query took the limit of the chart before it"
    assert r["stats"][3] == 200 and r["stats"][4] == 2, "the table query searched twice"
    assert r["live"] == ["1000", 2], "the chosen form was searched for twice or lost its rows"


@needs_node
def test_the_rows_in_hand_are_not_fetched_twice():
    r = _run(r"""
        const out = {};
        const rows = Array.from({ length: LOGS_PAGE_MAX }, (_, i) => ['g' + i, LOGS_PAGE_MAX - i]);
        const big = table(['query', 'count'], rows, { count: 5312, matched: 40312 });
        globalThis.fetch = async url => { calls.push(url); return url.startsWith('/api/logs/sources') ? reply([]) : reply(big); };
        logsSetQuery('source=dns | stats count by query');
        await submitLogsSearch();
        setLogsForm('pie');
        await new Promise(r => setTimeout(r, 0));
        out.first = [query(searches().pop()).get('limit'), logsAsked];
        const before = searches().length;
        setLogsView('statistics');
        out.table = els['logs-results'].innerHTML;
        setLogsForm('pie');
        await new Promise(r => setTimeout(r, 0));
        setLogsForm('bars');
        await new Promise(r => setTimeout(r, 0));
        out.again = searches().length - before;
        // a short page still fetches the rows a chart needs
        const small = table(['query', 'count'], rows.slice(0, 15), { count: 5312, matched: 40312 });
        globalThis.fetch = async url => { calls.push(url); return url.startsWith('/api/logs/sources') ? reply([]) : reply(small); };
        setLogsView('statistics');
        await submitLogsSearch();
        out.short = [logsAsked, els['logs-results'].innerHTML.includes('Show up to')];
        const third = searches().length;
        setLogsForm('pie');
        await new Promise(r => setTimeout(r, 0));
        out.fetched = [searches().length - third, logsAsked];
        console.log(JSON.stringify(out));""")
    assert r["first"] == ["1000", 1000]
    assert r["again"] == 0, "the rows of the last request were fetched a second time"
    assert "Show up to" not in r["table"], "the table offers more rows than the server gives"
    assert r["short"] == [200, True], "a page of 200 rows must still offer the 1000"
    assert r["fetched"] == [1, 1000]


@needs_node
def test_a_timechart_keeps_its_form_when_a_series_comes_and_goes():
    r = _run(r"""
        const at = ['2026-11-14T10:00:00Z', '2026-11-14T10:05:00Z'];
        renderLogsResult(timechart(['_time', 'access', 'mcp'], [[at[0], 2, 1], [at[1], 1, 4]]));
        const first = logsView.form;
        setLogsForm('bars');
        // a LIVE tick brings a source more, and one less
        renderLogsResult(timechart(['_time', 'access', 'mcp', 'dns'], [[at[0], 2, 1, 1], [at[1], 1, 4, 2]]));
        const more = logsView.form;
        renderLogsResult(timechart(['_time', 'access'], [[at[0], 2], [at[1], 1]]));
        const less = logsView.form;
        // a table is another result: it opens in its own default again
        renderLogsResult(table(['tool', 'count'], [['a', 3]]));
        const other = [logsView.view, logsView.form];
        renderLogsResult(timechart(['_time', 'access'], [[at[0], 2], [at[1], 1]]));
        console.log(JSON.stringify({ first, more, less, other, back: [logsView.view, logsView.form] }));""")
    assert r["first"] == "line"
    assert r["more"] == "bars" and r["less"] == "bars", "a series more or less dropped the chosen form"
    assert r["other"] == ["statistics", "table"]
    assert r["back"] == ["visualization", "line"], "a timechart after a table opens in its own default"


def test_both_themes_style_the_result_tabs():
    classic, theme = _rule_bodies(STYLE_CSS), _rule_bodies(THEME_CSS)
    for cls in ("logs-result-head", "logs-tabs", "logs-tab", "logs-forms", "logs-form", "logs-chart-card",
                "logs-chart", "logs-trunc", "chart-line"):
        assert f".{cls}" in classic, f"style.css has no rule for .{cls}"
        assert f'[data-theme="cyberpunk"] .{cls}' in theme, f"Cyberpunk has no rule for .{cls}"
    for selector in ('.logs-tab[aria-selected="true"]', '.logs-tab[aria-disabled="true"]',
                     '.logs-form[aria-pressed="true"]', '.logs-form[aria-disabled="true"]'):
        assert selector in classic, f"style.css tells no {selector} apart"
    assert re.search(r"cursor:\s*(default|not-allowed)", classic['.logs-tab[aria-disabled="true"]']), \
        "a locked tab looks like a button one can press"
    # Only the warning line that takes a click looks like one
    assert re.search(r"cursor:\s*pointer", classic.get("button.logs-trunc", "")), \
        "the warning line of a timechart, which is plain text, looks clickable"
    assert not re.search(r"cursor:\s*pointer", classic[".logs-trunc"])
    for name, bodies in (("style.css", classic), ("theme-cyberpunk.css", theme)):
        for selector, body in bodies.items():
            if re.search(r"\.(logs-tab|logs-form|logs-result-head|logs-chart|logs-trunc|chart-line)", selector):
                assert not LITERAL_COLOR.search(body), f"{name}: a colour literal in {selector}"


def test_the_result_tabs_raised_the_asset_versions():
    html = _read(INDEX_HTML)
    assert "style.css?v=72" not in html and "app.js?v=104" not in html, "asset versions not raised"
    assert "style.css?v=71" not in html and "theme-cyberpunk.css?v=29" not in html and "app.js?v=103" not in html, \
        "asset versions not raised"


# --- SAVE: the result as a tile on a dashboard --------------------------------------

def test_the_save_button_stands_in_the_tab_row_and_the_dialog_sits_in_the_tab():
    html = _read(INDEX_HTML)
    head = re.search(r'<div class="logs-result-head" id="logs-result-head">(.*?)</div>\s*<div class="logs-results"',
                     html, re.S)
    assert head, "the tab row is not over the result any more"
    row = head.group(1)
    assert 'id="logs-save-btn"' in row and ">SAVE</button>" in row
    assert "openLogsSave()" in row
    assert row.index('id="logs-save-btn"') > row.index('id="logs-forms"'), "SAVE belongs at the end of the row"
    # The dialog follows the one modal of the house: a backdrop that closes it
    # and the content beside it. It lives in #tab-logs, so it goes away with the tab.
    dialog = _Elements(html).by_id("logs-save")
    assert dialog, "no #logs-save dialog"
    assert dialog["attrs"]["role"] == "dialog" and dialog["attrs"]["aria-modal"] == "true"
    assert "hidden" in dialog["attrs"]["class"].split(), "the dialog stands open on the page"
    assert dialog["attrs"].get("aria-labelledby") == "logs-save-title"
    tab = _Elements(html).by_id("tab-logs")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    assert find(tab, lambda e: e["attrs"].get("id") == "logs-save"), "the dialog is not inside the LOGS tab"
    inner = html[html.index('<div class="logs-save hidden"'):html.index("</body>")]
    inner = inner[:inner.index("<!--") if "<!--" in inner else len(inner)]
    assert 'class="logs-save-backdrop" onclick="closeLogsSave()"' in inner, "no backdrop that closes the dialog"
    assert 'id="logs-save-body"' in inner and 'id="logs-save-title"' in inner
    assert inner.count("closeLogsSave()") >= 2, "the dialog has no close button beside its backdrop"
    # The button ships locked, so its title must be the reason, not the hint
    button = re.search(r'<button[^>]*id="logs-save-btn"[^>]*>', html).group(0)
    assert 'aria-disabled="true"' in button and "needs a pipe such as" in button, button


@needs_node
def test_save_is_locked_without_a_pipe_and_open_with_one():
    r = _run(r"""
        const btn = () => [els['logs-save-btn'].attrs['aria-disabled'], els['logs-save-btn'].attrs['title']];
        els['logs-save'].classList.add('hidden');       // as the template has it
        const out = {};
        logsSetQuery('source=dns');
        renderLogsResult(events([ev('1', 'a message')]));
        out.locked = btn();
        out.lockedOpen = [openLogsSave(), logsSave.open, els['logs-save'].classList.contains('hidden'),
            els['logs-save-body'].innerHTML];
        logsSetQuery('source=dns | top query');
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        out.open = btn();
        out.opened = [openLogsSave(), logsSave.open, els['logs-save'].classList.contains('hidden')];
        await new Promise(r => setTimeout(r, 0));
        out.body = els['logs-save-body'].innerHTML.length > 0;
        out.closed = [closeLogsSave(), logsSave.open, els['logs-save'].classList.contains('hidden'),
            els['logs-save-body'].innerHTML];
        // a result the view has no form for locks it again
        renderLogsResult(events([ev('2', 'another')]));
        out.again = btn();
        console.log(JSON.stringify(out));""")
    assert r["locked"][0] == "true" and r["locked"][1] == "needs a pipe such as | stats count by field"
    assert r["lockedOpen"] == [False, False, True, ""], "the dialog opened without a form to save"
    assert r["open"][0] == "false" and r["open"][1] and "dashboard" in r["open"][1].lower()
    assert r["opened"] == [True, True, False]
    assert r["body"] is True
    assert r["closed"] == [True, False, True, ""], "closing left the dialog or its fields behind"
    assert r["again"][0] == "true"


@needs_node
def test_the_dialog_shows_the_dashboards_and_prefills_the_name():
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] },
            { id: 'd-bbbbbbbbbbbb', name: '<script>alert(1)</script>', created: '',
              panels: Array.from({ length: 12 }, (_, i) => ({ id: 'p-' + i })) }];
        logsSetQuery('source=firewall action=DROP | stats count by dst_port');
        renderLogsResult(table(['dst_port', 'count'], [['443', 9], ['22', 4]]));
        setLogsForm('pie');
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        const out = { body: els['logs-save-body'].innerHTML, gets: reads.length,
            pick: logsSave.dashboard, dashboards: logsSave.dashboards.length,
            focused: els['logs-save-name'].focused, value: els['logs-save-name'].value };
        // the name the dialog starts from
        const name = (q, shape) => logsSaveName(q, shape);
        out.names = {
            by: name('source=firewall action=DROP | stats count by dst_port'),
            two: name('* | stats count by src_ip, dest_ip'),
            spaced: name('* | stats count by src_ip dest_ip'),
            top: name('source=dns | top 5 query'),
            rare: name('source=dns | rare query'),
            quoted: name('* | top "my field"'),
            last: name('* | stats count by tool | sort -count | head 20'),
            table: name('source=powershell | table time, user, path'),
            star: name('* | stats count'),
            string: name('message="sorted by name" | stats count by tool'),
            fallback: name('message="sorted by name" | table time'),
            time: name('source=dns | timechart span=5m count by source', { type: 'timechart' }),
            timeLong: name('* | stats count by ' + 'b'.repeat(80), { type: 'timechart' }),
            control: name('a\tb | table time'),
            long: name('* | stats count by ' + 'b'.repeat(80)),
            empty: [name(''), name(null)],
        };
        console.log(JSON.stringify(out));""")
    body = r["body"]
    assert r["gets"] == 1, "the dialog asked for the dashboards more than once"
    assert r["dashboards"] == 2 and r["pick"] == "d-aaaaaaaaaaaa", "the first dashboard with room is chosen"
    assert "Beacon hunt" in body and "logsSavePick(&quot;d-aaaaaaaaaaaa&quot;)" in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body and "<script" not in body
    handlers = set(re.findall(r'on[a-z]+="([^"]*)"', body))
    assert all(re.fullmatch(r"(?:closeLogsSave|submitLogsSave)\(\)|logsSave(?:Pick|Fixed)\((?:&quot;[\w-]*&quot;|true|false)\)", h)
               for h in handlers), handlers
    assert not (_tags(body) - ALLOWED_TAGS - {"input", "label"}), _tags(body)
    assert "+ New" in body and 'id="logs-save-new"' in body and 'id="logs-save-name"' in body
    assert 'value="dst_port"' in body and r["value"] == "dst_port", "the name is not prefilled"
    assert r["focused"] >= 1, "the focus does not start in the name field"
    full = re.search(r'data-logs-dash="d-bbbbbbbbbbbb"[^>]*', body).group(0)
    assert 'aria-disabled="true"' in full and "at most 12 tiles" in full, full
    assert ">PIE<" in body, "the dialog does not say which form it saves"
    assert r["names"] == {
        "by": "dst_port", "two": "src_ip, dest_ip", "spaced": "src_ip, dest_ip", "top": "query", "rare": "query",
        "quoted": "my field", "last": "tool", "table": "source=powershell", "star": "*", "string": "tool",
        "fallback": "message=sorted", "time": "source over time", "timeLong": "b" * 60, "control": "a",
        "long": "b" * 60, "empty": ["", ""],
    }


@needs_node
def test_saving_posts_exactly_the_chosen_form_and_range():
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        logsSetQuery('source=firewall action=DROP | stats count by dst_port');
        logsState.earliest = '-24h';
        logsState.latest = '';
        renderLogsResult(table(['dst_port', 'count'], [['443', 9]]));
        setLogsForm('pie');
        const out = {};
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        els['logs-save-name'].value = 'Dropped ports';
        out.relative = await submitLogsSave();
        out.posted = posted.map(p => [p.url, p.method, p.body]);
        out.closed = [logsSave.open, els['logs-save'].classList.contains('hidden')];
        out.toast = toasts.slice();
        // the same result with the window frozen: earliest and latest in UTC
        posted.length = 0;
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        out.ranges = els['logs-save-body'].innerHTML;
        logsSaveFixed(true);
        els['logs-save-name'].value = 'Dropped ports';
        out.fixedOk = await submitLogsSave();
        out.fixed = posted.map(p => p.body);
        out.span = Date.parse(posted[0].body.latest) - Date.parse(posted[0].body.earliest);
        // a window the tab is zoomed into has no relative range
        posted.length = 0;
        logsState.earliest = '2026-11-14T00:00:00Z';
        logsState.latest = '2026-11-15T00:00:00Z';
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        out.zoomed = [logsSave.fixed, els['logs-save-body'].innerHTML.includes('logsSaveFixed(false)')];
        els['logs-save-name'].value = 'A window';
        await submitLogsSave();
        out.window = posted.map(p => p.body);
        // + New: the dashboard first, then the tile on it
        posted.length = 0;
        logsState.earliest = '-24h';
        logsState.latest = '';
        renderLogsResult(timechart(['_time', 'dns'], [['2026-11-14T10:00:00Z', 2], ['2026-11-14T10:05:00Z', 1]]));
        logsSetQuery('* | timechart span=5m count by source');
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        logsSavePick('');
        els['logs-save-new'].value = 'Fresh board';
        els['logs-save-name'].value = 'Over time';
        out.newOk = await submitLogsSave();
        out.new = posted.map(p => [p.url, p.method, p.body]);
        out.list = logsSave.dashboards.map(d => d.name);
        out.titles = toasts.map(t => t[1]);
        console.log(JSON.stringify(out));""")
    assert r["relative"] is True
    assert r["posted"] == [["/api/dashboards/d-aaaaaaaaaaaa/panels", "POST",
                            {"name": "Dropped ports", "query": "source=firewall action=DROP | stats count by dst_port",
                             "form": "pie", "earliest": "-24h", "latest": ""}]]
    assert r["closed"] == [False, True], "the dialog stayed open after a save that worked"
    assert r["toast"] and r["toast"][0][0] == "success" and "Beacon hunt" in " ".join(r["toast"][0][1:])
    # showToast throttles on type + title for 15 s, so the title has to name
    # the tile: one dashboard built from four searches gave one toast
    assert "Dropped ports" in r["titles"][0], r["titles"]
    assert len(set(r["titles"])) == 3, f"the toasts of four tiles cannot be told apart: {r['titles']}"
    assert "last 24 h" in r["ranges"], "the relative range is not named as the tab names it"
    frozen = r["fixed"][0]
    assert frozen["form"] == "pie" and frozen["name"] == "Dropped ports"
    for key in ("earliest", "latest"):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", frozen[key]), frozen
    span = r["span"] / 1000
    assert 86395 <= span <= 86405, span
    assert r["zoomed"] == [True, False], "a zoomed window still offered a relative range"
    assert r["window"][0]["earliest"] == "2026-11-14T00:00:00Z"
    assert r["window"][0]["latest"] == "2026-11-15T00:00:00Z"
    assert r["newOk"] is True
    assert r["new"] == [["/api/dashboards", "POST", {"name": "Fresh board"}],
                        ["/api/dashboards/d-new1/panels", "POST",
                         {"name": "Over time", "query": "* | timechart span=5m count by source", "form": "line",
                          "earliest": "-24h", "latest": ""}]]
    assert r["list"] == ["Beacon hunt", "Fresh board"], "the new dashboard is not in the list of the dialog"


@needs_node
def test_a_dialog_opened_again_between_the_two_posts_gets_no_second_switch():
    """A "+ New" writes the dashboard and then the tile. A dialog closed and
    opened again in between has read the list itself: the dashboard of the
    first post would be a second switch for the same id."""
    r = _run(r"""
        const out = {};
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        logsSetQuery('source=dns | stats count by query');
        renderLogsResult(table(['query', 'count'], [['a', 3]]));
        setLogsForm('pie');
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        logsSavePick('');
        els['logs-save-new'].value = 'Fresh board';
        els['logs-save-name'].value = 'Queries';
        // the analyst closes the dialog and opens it again while the dashboard
        // is being written: the second opening reads the list of the server,
        // which holds the new dashboard already
        const real = globalThis.fetch;
        globalThis.fetch = async (url, opts) => {
            const method = (opts && opts.method) || 'GET';
            if (url === '/api/dashboards' && method === 'POST') {
                const resp = await real(url, opts);
                closeLogsSave();
                openLogsSave();
                await new Promise(go => setTimeout(go, 0));
                return resp;
            }
            return real(url, opts);
        };
        out.saved = await submitLogsSave();
        globalThis.fetch = real;
        out.ids = logsSave.dashboards.map(d => d.id);
        renderLogsSave();
        out.body = els['logs-save-body'].innerHTML;
        console.log(JSON.stringify(out));""")
    assert r["saved"] is True, "the tile was not written"
    assert r["ids"].count("d-new1") == 1, f"a dashboard stands twice in the dialog: {r['ids']}"
    assert r["body"].count("logsSavePick(&quot;d-new1&quot;)") == 1, "two switches for the same dashboard"


@needs_node
def test_the_dialog_reports_a_refused_save():
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        logsSetQuery('source=dns | stats count by query');
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        const out = {};
        const line = () => [els['logs-save-error'].innerHTML, els['logs-save-error'].hidden];
        const open = async () => { openLogsSave(); await new Promise(r => setTimeout(r, 0));
            els['logs-save-name'].value = 'Queries'; };
        await open();
        // a tool update is running: the dialog stays open and says so
        saveAnswer = { status: 503, data: { error: 'Maintenance: tool updates are running.', maintenance: true } };
        out.maintenance = [await submitLogsSave(), line(), logsSave.open,
            els['logs-save'].classList.contains('hidden'), toasts.length];
        // a refused value: the sentence of the server, in the dialog
        saveAnswer = { status: 400, data: { error: 'at most 12 tiles per dashboard' } };
        out.refused = [await submitLogsSave(), line(), toasts.length];
        saveAnswer = { status: 400, data: { error: '<script>alert(1)</script>' } };
        out.hostile = [await submitLogsSave(), line()];
        // the dashboard is gone: its text, and the list is read again
        const before = reads.length;
        saveAnswer = { status: 404, data: { error: 'Dashboard not found.' } };
        dashboards = [];
        out.gone = [await submitLogsSave(), line(), reads.length - before];
        // the error line does not survive the next opening
        saveAnswer = null;
        closeLogsSave();
        await open();
        out.fresh = line();
        // an empty name is refused before anything is written
        posted.length = 0;
        els['logs-save-name'].value = '   ';
        out.noName = [await submitLogsSave(), line()[0], posted.length];
        els['logs-save-name'].value = 'Queries';
        logsSavePick('');
        els['logs-save-new'].value = '';
        out.noBoard = [await submitLogsSave(), line()[0], posted.length];
        // Escape closes the dialog, and the keys of the page work without it
        els['logs-save-new'].value = 'Fresh';
        handleGlobalKeydown({ key: 'Escape' });
        out.escape = [logsSave.open, els['logs-save'].classList.contains('hidden')];
        handleGlobalKeydown({ key: 'Escape' });
        out.escapeAgain = logsSave.open;
        console.log(JSON.stringify(out));""")
    assert r["maintenance"][0] is False
    assert "a tool update is running" in r["maintenance"][1][0] and r["maintenance"][1][1] is False
    assert r["maintenance"][2] is True and r["maintenance"][3] is False, "the dialog closed over a refused save"
    assert r["maintenance"][4] == 0, "a refused save belongs in the dialog, not in a toast"
    assert r["refused"][0] is False and r["refused"][1][0] == "at most 12 tiles per dashboard"
    assert r["refused"][2] == 0
    assert r["hostile"][0] is False and "<script" not in r["hostile"][1][0]
    assert "&lt;script&gt;" in r["hostile"][1][0]
    assert r["gone"][0] is False and "Dashboard not found." in r["gone"][1][0] and r["gone"][2] == 1, \
        "a dashboard that is gone must be read again"
    assert r["fresh"] == ["", True], "the reason of the last refusal stood in a fresh dialog"
    assert r["noName"][0] is False and r["noName"][2] == 0 and "name" in r["noName"][1].lower()
    assert r["noBoard"][0] is False and r["noBoard"][2] == 0 and "dashboard" in r["noBoard"][1].lower()
    assert r["escape"] == [False, True] and r["escapeAgain"] is False


@needs_node
def test_enter_saves_and_the_tab_key_stays_in_the_dialog():
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        logsSetQuery('source=dns | stats count by query');
        logsState.earliest = '-1h';
        logsState.latest = '';
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        const out = {};
        // Enter in a field is the SAVE button
        els['logs-save-name'].value = 'Queries';
        out.enter = onLogsSaveKeydown({ key: 'Enter', target: { tagName: 'INPUT' } });
        await new Promise(r => setTimeout(r, 0));
        out.posted = posted.map(p => [p.url, p.body.name, p.body.earliest]);
        out.closed = logsSave.open;
        // Tab at the last element goes back to the first one, and the other way round
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        const stop = () => { out.stopped = (out.stopped || 0) + 1; };
        const first = { hidden: false, disabled: false, getAttribute: () => 'false', focus() { out.to = 'first'; } };
        const last = { hidden: false, disabled: false, getAttribute: () => 'false', focus() { out.to = 'last'; } };
        els['logs-save'].querySelectorAll = () => [first, last];
        document.activeElement = last;
        out.forward = onLogsSaveKeydown({ key: 'Tab', preventDefault: stop });
        out.toForward = out.to;
        document.activeElement = first;
        out.back = onLogsSaveKeydown({ key: 'Tab', shiftKey: true, preventDefault: stop });
        out.toBack = out.to;
        // in the middle of the row Tab does what it always does
        document.activeElement = first;
        out.middle = onLogsSaveKeydown({ key: 'Tab', preventDefault: stop });
        out.other = onLogsSaveKeydown({ key: 'x', target: { tagName: 'INPUT' } });
        closeLogsSave();
        out.shut = onLogsSaveKeydown({ key: 'Enter', target: { tagName: 'INPUT' } });
        console.log(JSON.stringify(out));""")
    assert r["enter"] is True and r["closed"] is False, "Enter did not save"
    assert r["posted"] == [["/api/dashboards/d-aaaaaaaaaaaa/panels", "Queries", "-1h"]]
    assert r["forward"] is True and r["toForward"] == "first"
    assert r["back"] is True and r["toBack"] == "last"
    assert r["stopped"] == 2, "the dialog let the focus leave it"
    assert r["middle"] is False and r["other"] is False
    assert r["shut"] is False, "the keys of the dialog still work while it is shut"


@needs_node
def test_a_refused_tile_after_a_new_dashboard_leaves_one_dashboard():
    """The dashboard of "+ New" is written first. When the tile is refused, the
    dialog has to show the new dashboard as the chosen one: a row that still
    says "+ New" invites a second click, and that used to make a second
    dashboard of the same name."""
    r = _run(r"""
        dashboards = [];
        logsSetQuery('source=dns | stats count by query');
        logsState.earliest = '-24h';
        logsState.latest = '';
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        els['logs-save-name'].value = 'Queries';
        els['logs-save-new'].value = 'Fresh board';
        tileAnswer = { status: 400, data: { error: 'at most 12 tiles per dashboard' } };
        const out = {};
        out.refused = await submitLogsSave();
        out.posted = posted.map(p => [p.url, p.body.name]);
        out.state = [logsSave.open, logsSave.dashboard, logsSave.dashboards.map(d => d.name)];
        out.error = els['logs-save-error'].innerHTML;
        out.body = els['logs-save-body'].innerHTML;
        out.kept = [els['logs-save-name'].value, els['logs-save-new'].value];
        // the second try writes the tile, not another dashboard
        tileAnswer = null;
        out.second = await submitLogsSave();
        out.after = posted.map(p => p.url);
        out.toasts = toasts.length;
        console.log(JSON.stringify(out));""")
    assert r["refused"] is False and r["state"][0] is True, "the dialog closed over a refused tile"
    assert r["posted"] == [["/api/dashboards", "Fresh board"], ["/api/dashboards/d-new1/panels", "Queries"]]
    assert r["state"][1] == "d-new1" and r["state"][2] == ["Fresh board"]
    assert r["error"] == "at most 12 tiles per dashboard"
    assert 'data-logs-dash="d-new1" aria-pressed="true"' in r["body"], "the new dashboard is not the chosen switch"
    assert 'data-logs-dash="" aria-pressed="false"' in r["body"], '"+ New" is still pressed'
    assert r["kept"] == ["Queries", "Fresh board"], "the names that were typed are gone"
    assert r["second"] is True
    assert r["after"] == ["/api/dashboards", "/api/dashboards/d-new1/panels", "/api/dashboards/d-new1/panels"], \
        "the second try made another dashboard"
    assert r["toasts"] == 1


@needs_node
def test_only_one_save_is_on_its_way_at_a_time():
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        logsSetQuery('source=dns | stats count by query');
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        const out = {};
        // every tile write waits at a gate the test opens
        const real = globalThis.fetch, gates = [];
        let tries = 0;
        globalThis.fetch = async (url, opts) => {
            if (url.endsWith('/panels')) {
                tries++;
                await new Promise(go => gates.push(go));
            }
            return real(url, opts);
        };
        const release = () => { while (gates.length) gates.shift()(); };
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        els['logs-save-name'].value = 'Queries';
        const first = submitLogsSave();
        await new Promise(r => setTimeout(r, 0));
        out.busy = [await submitLogsSave(), els['logs-save-go'].disabled, els['logs-save-error'].innerHTML, tries];
        release();
        out.first = [await first, logsSave.open, posted.length, els['logs-save-go'].disabled];
        // the dialog closed and opened again while a save is on its way
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        els['logs-save-name'].value = 'Second';
        const again = submitLogsSave();
        await new Promise(r => setTimeout(r, 0));
        closeLogsSave();
        out.reopened = openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        els['logs-save-name'].value = 'Third';
        out.afterClose = [await submitLogsSave(), tries, els['logs-save-go'].disabled];
        release();
        out.stale = [await again, logsSave.open, posted.length, toasts.length, els['logs-save-go'].disabled];
        globalThis.fetch = real;
        console.log(JSON.stringify(out));""")
    assert r["busy"][0] is False, "a second save went out while the first was on its way"
    assert r["busy"][1] is True and "on its way" in r["busy"][2]
    assert r["busy"][3] == 1, "the second save reached the server"
    assert r["first"] == [True, False, 1, False], "the save that worked did not close the dialog"
    assert r["reopened"] is True
    assert r["afterClose"] == [False, 2, True], \
        "a dialog opened while a save was on its way let a second write through"
    assert r["stale"][0] is True and r["stale"][1] is True, \
        "the save of the dialog that was closed closed the new one as well"
    assert r["stale"][2] == 2 and r["stale"][3] == 2, "the tile that was written says nothing"
    assert r["stale"][4] is False, "SAVE stayed locked after the save that was on its way"


@needs_node
def test_the_dialog_keeps_the_focus_while_the_list_arrives():
    """The dialog opened, put the focus in the name field and then wrote the fields again when
    GET /api/dashboards answered - which in a browser takes the focused field off the page and
    leaves the focus on the body, so what was typed next went nowhere."""
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        // A browser drops the focus of a node it removes, and the fresh field
        // it draws instead starts without a selection: writing the body of the
        // dialog leaves the focus on the page's body and the caret at 0.
        const bodyEl = { id: 'body' };
        document.activeElement = bodyEl;
        for (const id of ['logs-save-name', 'logs-save-new', 'logs-save-go']) {
            const el = els[id], focus = el.focus.bind(el);
            el.focus = () => { focus(); document.activeElement = el; };
            el.selectionStart = 0;
            el.selectionEnd = 0;
            el.setSelectionRange = (from, to) => {
                el.caret = [from, to];
                el.selectionStart = from;
                el.selectionEnd = to;
            };
        }
        const body = els['logs-save-body'];
        let html = '';
        Object.defineProperty(body, 'innerHTML', {
            get: () => html,
            set(value) {
                html = value;
                document.activeElement = bodyEl;
                for (const id of ['logs-save-name', 'logs-save-new']) {
                    els[id].caret = null;
                    els[id].selectionStart = 0;
                    els[id].selectionEnd = 0;
                }
            },
        });
        logsSetQuery('source=dns | stats count by query');
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        openLogsSave();
        const out = { opened: document.activeElement.id, caret: els['logs-save-name'].caret };
        await new Promise(r => setTimeout(r, 0));
        out.listed = document.activeElement.id;
        out.caretListed = els['logs-save-name'].caret;
        // What was typed survives the list, and so does the field it was typed
        // in, with the caret where it stood
        els['logs-save-name'].value = 'Queries';
        els['logs-save-name'].setSelectionRange(7, 7);
        logsSaveDashboards();
        await new Promise(r => setTimeout(r, 0));
        out.again = document.activeElement.id;
        out.value = els['logs-save-name'].value;
        out.caretAgain = els['logs-save-name'].caret;
        console.log(JSON.stringify(out));""")
    assert r["opened"] == "logs-save-name", "the focus does not start in the name field"
    assert r["caret"] == [0, len("query")], "the prefilled name is not there to be typed over"
    assert r["listed"] == "logs-save-name", "the field lost the focus when the dashboards arrived"
    assert r["caretListed"] == [0, len("query")], "the list took the selection off the prefilled name"
    assert r["again"] == "logs-save-name" and r["value"] == "Queries"
    assert r["caretAgain"] == [7, 7], "a re-render moved the caret of the name that was typed"


@needs_node
def test_the_focus_follows_the_switch_that_was_pressed():
    r = _run(r"""
        dashboards = [{ id: 'd-aaaaaaaaaaaa', name: 'Beacon hunt', created: '', panels: [] }];
        logsSetQuery('source=dns | stats count by query');
        logsState.earliest = '-24h';
        logsState.latest = '';
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        const out = { focused: [], body: els['logs-save-body'].innerHTML };
        // the switches of the body, which the re-render replaces
        els['logs-save-body'].querySelectorAll = sel => {
            const attr = sel.replace(/[[\]]/g, '');
            const values = attr === 'data-logs-dash' ? ['d-aaaaaaaaaaaa', ''] : ['relative', 'fixed'];
            return values.map(value => ({ getAttribute: () => value,
                focus() { out.focused.push(attr + '=' + value); } }));
        };
        logsSavePick('');
        logsSavePick('d-aaaaaaaaaaaa');
        logsSaveFixed(true);
        logsSaveFixed(false);
        console.log(JSON.stringify(out));""")
    assert 'data-logs-range="relative"' in r["body"] and 'data-logs-range="fixed"' in r["body"], \
        "the range switches cannot be found again after a re-render"
    assert r["focused"] == ["data-logs-dash=", "data-logs-dash=d-aaaaaaaaaaaa",
                            "data-logs-range=fixed", "data-logs-range=relative"]


@needs_node
def test_a_dashboard_that_cannot_be_read_and_one_that_has_no_room():
    r = _run(r"""
        const line = () => els['logs-save-error'].innerHTML;
        logsSetQuery('source=dns | stats count by query');
        renderLogsResult(table(['query', 'count'], [['a.example', 3]]));
        setLogsForm('pie');
        const out = {};
        // ten dashboards, every one of them full: no request, and what to do
        dashboards = Array.from({ length: 10 }, (_, i) => ({ id: 'd-' + i, name: 'D' + i, created: '',
            panels: Array.from({ length: 12 }, (_, j) => ({ id: 'p-' + i + '-' + j })) }));
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        els['logs-save-name'].value = 'Queries';
        out.full = [await submitLogsSave(), line(), posted.length, logsSave.dashboard];
        out.newPick = /data-logs-dash=""[^>]*/.exec(els['logs-save-body'].innerHTML)[0];
        closeLogsSave();
        // a list that could not be read is no list: only "+ New" is offered
        listAnswer = { status: 500, data: { error: 'The dashboards could not be saved; see the web UI log.' } };
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        out.unread = [logsSave.dashboards.length, logsSave.dashboard, line(),
            els['logs-save-body'].innerHTML.includes('data-logs-dash="d-0"')];
        // and it comes back on the next opening
        closeLogsSave();
        listAnswer = null;
        openLogsSave();
        await new Promise(r => setTimeout(r, 0));
        out.back = [logsSave.dashboards.length, line()];
        console.log(JSON.stringify(out));""")
    assert r["full"][0] is False and r["full"][2] == 0, "a dashboard too many was asked of the server"
    assert "10 dashboards" in r["full"][1] and "delete" in r["full"][1], r["full"][1]
    assert "tile" in r["full"][1], "the reason does not say that a tile would do"
    assert r["full"][3] == "", "a full dashboard was chosen"
    assert 'aria-disabled="true"' in r["newPick"]
    assert r["unread"][0] == 0 and r["unread"][1] == "" and r["unread"][3] is False, \
        "the list of the last opening stands under a message that it could not be read"
    assert "could not be saved" in r["unread"][2] or "could not be read" in r["unread"][2]
    assert r["back"] == [10, ""], "the list does not come back"


def test_both_themes_style_the_save_dialog():
    classic, theme = _rule_bodies(STYLE_CSS), _rule_bodies(THEME_CSS)
    # The box that centres the dialog is layout only, as .help-modal is: the
    # theme paints the backdrop and the content, not that box
    assert ".logs-save" in classic, "style.css has no rule for .logs-save"
    for cls in ("logs-save-btn", "logs-save-backdrop", "logs-save-content", "logs-save-head",
                "logs-save-field", "logs-save-label", "logs-save-picks", "logs-save-pick", "logs-save-error",
                "logs-save-actions"):
        assert f".{cls}" in classic, f"style.css has no rule for .{cls}"
        assert f'[data-theme="cyberpunk"] .{cls}' in theme, f"Cyberpunk has no rule for .{cls}"
    assert re.search(r"display:\s*none", classic.get(".logs-save.hidden", "")), "the dialog shows before it is opened"
    assert re.search(r"position:\s*fixed", classic[".logs-save"]), "the dialog does not stand over the page"
    for selector in ('.logs-save-pick[aria-pressed="true"]', '.logs-save-pick[aria-disabled="true"]',
                     '.logs-save-btn[aria-disabled="true"]'):
        assert selector in classic, f"style.css tells no {selector} apart"
    assert re.search(r"cursor:\s*(default|not-allowed)", classic['.logs-save-btn[aria-disabled="true"]']), \
        "a locked SAVE looks like a button one can press"
    # A locked SAVE or switch must not light up under the pointer: either the
    # hover rule skips it or a :hover rule of its own puts it back
    for name, bodies in (("style.css", classic), ("theme-cyberpunk.css", theme)):
        for base in ("logs-save-btn", "logs-save-pick"):
            hovers = [s for s in bodies if f".{base}" in s and s.rstrip().endswith(":hover")]
            assert hovers, f"{name}: .{base} has no hover rule"
            assert [s for s in hovers if "aria-disabled" in s], \
                f"{name}: nothing keeps a locked .{base} dim under the pointer"
    # 1280x800: the dialog may never be taller than the window
    assert re.search(r"max-height:\s*8\d(vh|%)", classic[".logs-save-content"]), "the dialog can grow past the window"
    assert re.search(r"overflow(-y)?:\s*auto", classic[".logs-save-content"] + classic.get(".logs-save-body", ""))
    for name, bodies in (("style.css", classic), ("theme-cyberpunk.css", theme)):
        for selector, body in bodies.items():
            if ".logs-save" in selector:
                assert not LITERAL_COLOR.search(body), f"{name}: a colour literal in {selector}"


def test_the_save_dialog_raised_the_asset_versions():
    html = _read(INDEX_HTML)
    assert "style.css?v=73" not in html and "theme-cyberpunk.css?v=31" not in html and "app.js?v=105" not in html, \
        "asset versions not raised"
    # the fix round after the review, which touched the theme and app.js
    assert "theme-cyberpunk.css?v=32" not in html and "app.js?v=106" not in html, "asset versions not raised"


def test_the_focus_fix_raised_the_asset_version():
    """The dialog keeping its focus through a re-render changed app.js."""
    assert "app.js?v=110" not in _read(INDEX_HTML), "app.js changed, its version did not"
    assert "app.js?v=111" not in _read(INDEX_HTML), "app.js changed again, its version did not"
    assert "app.js?v=112" not in _read(INDEX_HTML), "the caret of the restored field changed app.js"
    # the help entries of the Dashboard and LOGS tabs changed with the review's findings
    assert "app.js?v=113" not in _read(INDEX_HTML), "the help of index.html changed, its version did not"


def test_the_final_fix_wave_raised_the_asset_version():
    """The limit a search asks for and Open in LOGS changed app.js."""
    assert "app.js?v=114" not in _read(INDEX_HTML), "app.js changed, its version did not"


# --- Look -----------------------------------------------------------------------

def test_both_themes_style_the_tab():
    classic, theme = _read(STYLE_CSS), _read(THEME_CSS)
    for cls in ("logs-bar", "logs-input", "logs-hl", "logs-source", "logs-event-row", "logs-field-head", "logs-raw",
                "logs-table", "logs-error", "logs-live", "logs-menu", "logs-value", "logs-src"):
        assert re.search(r"\.%s\b" % cls, classic), f"style.css has no rule for .{cls}"
        assert re.search(r'\[data-theme="cyberpunk"\][^{]*\.%s\b' % cls, theme), f"Cyberpunk has no rule for .{cls}"
    assert "@keyframes logs-live-pulse" in classic and "@keyframes logs-live-pulse" not in theme


SIX_SOURCES = ["powershell", "access", "mcp", "netflow", "dns", "firewall"]


def test_a_generic_rule_never_overrides_the_colour_of_a_source():
    """.logs-source and .logs-src used to reset --logs-src after the rules of
    the sources, which have the same specificity: every chip and badge was grey."""
    for path in (STYLE_CSS, THEME_CSS):
        order = []     # (selector, sets the colour) in the order of the sheet
        for prelude, body in _css_blocks(_strip_comments(_read(path))):
            if body is None or prelude.startswith("@"):
                continue
            sets = bool(re.search(r"--logs-src(?:-rgb)?\s*:", body))
            order += [(selector.strip(), sets) for selector in _selectors(prelude)]
        for kind in ("src", "source"):
            per = [i for i, (sel, sets) in enumerate(order) if sets and re.search(r"\.logs-%s-(%s)$" % (kind, "|".join(SIX_SOURCES)), sel)]
            if path == STYLE_CSS:
                assert len(per) == 6, (kind, [order[i][0] for i in per])
            generic = [i for i, (sel, sets) in enumerate(order)
                       if sets and re.search(r"\.logs-%s$" % kind, sel)]
            late = [order[i][0] for i in generic if per and i > min(per)]
            assert not late, f"{path}: {late} set the source colour after the rules of the sources"
            # the sources set it more specifically than any later generic rule could undo
            assert not generic or all(i < min(per) for i in generic), (path, kind)


@needs_node
def test_the_tab_reopens_with_the_last_query_even_a_bare_star():
    r = _run(r"""
        store[LOGS_RECENT_KEY] = JSON.stringify(['source=dns']);
        logsSetQuery('*');
        await submitLogsSearch();
        const stored = store['tdc.logs.last'];
        logsSetQuery('source=mcp');
        await submitLogsSearch();
        logsSetQuery('*');
        await submitLogsSearch();
        // a live search does not change what is restored
        logsState.query = 'other';
        await runLogsSearch({ silent: true });
        const last = store['tdc.logs.last'];
        logsState.query = '*'; logsReady = false;
        initLogs();
        await new Promise(r => setTimeout(r, 0));
        const input = els['logs-query'].value;
        // without a stored last query the newest recent one comes back
        delete store['tdc.logs.last']; logsReady = false;
        initLogs();
        console.log(JSON.stringify({ stored, last, input, fallback: els['logs-query'].value }));""")
    assert r == {"stored": "*", "last": "*", "input": "*", "fallback": "source=mcp"}


@needs_node
def test_a_cut_event_loads_in_full_when_it_is_unfolded_and_stays_escaped():
    r = _run(r"""
        const full = { id: 'powershell-9', time: '2026-11-14T10:00:00.123Z', source: 'powershell', message: '<script>FULL</script> ' + 'x'.repeat(30000),
            fields: { payload: '<b>whole payload</b>' } };
        const base = globalThis.fetch;
        globalThis.fetch = async url => {
            calls.push(url);
            if (url === '/api/logs/event/powershell-9') return reply(full);
            if (url.startsWith('/api/logs/event/')) return reply({ error: 'gone' }, 404);
            return base(url);
        };
        const cut = ev('powershell-9', 'cut message', { fields: { payload: 'cut payload' }, truncated_fields: true });
        const gone = ev('powershell-10', 'other cut', { truncated_fields: true });
        const short = ev('powershell-11', 'short message');
        renderLogsResult(events([cut, gone, short]));
        const hit = id => ({ target: { closest: sel => (sel === '[data-logs-toggle]' ? { getAttribute: () => id } : null) } });
        onLogsClick(hit('powershell-11'));
        onLogsClick(hit('powershell-9'));
        const loading = els['logs-results'].innerHTML;
        await new Promise(r => setTimeout(r, 0));
        const loaded = els['logs-results'].innerHTML;
        onLogsClick(hit('powershell-10'));
        await new Promise(r => setTimeout(r, 0));
        const missing = els['logs-results'].innerHTML;
        onLogsClick(hit('powershell-9'));
        onLogsClick(hit('powershell-9'));
        await new Promise(r => setTimeout(r, 0));
        console.log(JSON.stringify({ calls: calls.filter(u => u.startsWith('/api/logs/event/')), loading, loaded, missing }));""")
    assert r["calls"] == ["/api/logs/event/powershell-9", "/api/logs/event/powershell-10"], "short events and a second unfold fetch nothing"
    assert "cut message" in r["loading"] and "Loading the full event" in r["loading"]
    assert "&lt;script&gt;FULL&lt;/script&gt;" in r["loaded"] and "<script>" not in r["loaded"]
    assert "&lt;b&gt;whole payload&lt;/b&gt;" in r["loaded"] and "cut payload" not in r["loaded"]
    assert "more characters are not shown" not in r["loaded"], "the whole event is shown after the load"
    assert "no longer in the store" in r["missing"]
