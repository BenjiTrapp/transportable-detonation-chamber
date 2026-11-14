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
"""

import json
import re

from test_frontend import SOURCE, _function_source, _run_node, needs_node
from test_theme import (CHART_CONSTS, CHART_FUNCTIONS, INDEX_HTML, STYLE_CSS, THEME_CSS, _const_source, _css_blocks,
                        _Elements, _read, _selectors, _strip_comments)

LOGS_FUNCTION_NAME = re.compile(
    r"^(?:async )?function ((?:logs|runLogs|renderLogs|onLogs|submitLogs|toggleLogs|closeLogs|refreshLogs|initLogs)\w*)\(", re.M)
LOGS_FUNCTIONS = list(dict.fromkeys(LOGS_FUNCTION_NAME.findall(SOURCE)))
LOGS_CONSTS = ["LOGS_RANGES", "LOGS_DEFAULT_RANGE", "LOGS_RECENT_KEY", "LOGS_RANGE_KEY", "LOGS_LAST_KEY", "LOGS_RECENT_MAX",
               "LOGS_LIVE_MS", "LOGS_PAGE", "LOGS_RAW_FULL_LIMIT", "LOGS_PAGE_MAX", "LOGS_EXAMPLES", "LOGS_SOURCE_COLORS", "LOGS_SYNTAX_HINT",
               "LOGS_TOKEN", "LOGS_BARS_BRUSH"]
LOGS_LETS = re.findall(r"^let logs\w+ = [^\n]*?;(?=[ \t]*(?://[^\n]*)?$)", SOURCE, re.M)
OTHER_FUNCTIONS = CHART_FUNCTIONS + ["escapeHtml", "jsArg", "cssToken", "formatAlertTime", "filterChipHtml",
                                     "chartRangeLabel"]
ALL_FUNCTIONS = list(dict.fromkeys(LOGS_FUNCTIONS + OTHER_FUNCTIONS))

ELEMENT_IDS = ["logs-query", "logs-hl", "logs-results", "logs-summary", "logs-histogram", "logs-legend",
               "logs-field-list", "logs-fields-count", "logs-sources", "logs-error", "logs-range", "logs-live",
               "logs-menu", "logs-menu-btn", "logs-syntax"]

PRELUDE = "\n".join(_const_source(name) for name in CHART_CONSTS + LOGS_CONSTS) + "\n" + "\n".join(LOGS_LETS) + r"""
const classes = () => {
    const set = new Set();
    return { add: c => set.add(c), remove: c => set.delete(c), contains: c => set.has(c) };
};
const els = {};
for (const id of %s) {
    els[id] = { id, innerHTML: '', textContent: '', value: '', hidden: false, title: '', style: {}, attrs: {}, listeners: {},
        scrollLeft: 0, classList: classes(),
        setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
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
const intervals = [], cleared = [];
globalThis.setInterval = (fn, ms) => { intervals.push(ms); return intervals.length; };
globalThis.clearInterval = id => cleared.push(id);
const calls = [];
const reply = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
const ev = (id, message, extra = {}) => ({ id, time: '2026-11-14T10:00:00.123Z', source: 'powershell', message, fields: {}, ...extra });
const events = (list, extra = {}) => ({ type: 'events', events: list, columns: null, rows: [], count: list.length, matched: list.length,
    truncated: false, histogram: { bins: [], span_s: 60 }, fields: [], took_ms: 3.2, ...extra });
globalThis.fetch = async url => {
    calls.push(url);
    return url.startsWith('/api/logs/sources') ? reply([]) : reply(events([]));
};
const query = url => new URL('http://x' + url).searchParams;
const searches = () => calls.filter(u => u.startsWith('/api/logs/search'));
""" % json.dumps(ELEMENT_IDS)


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
            labels: LOGS_EXAMPLES.every(e => e.label && e.query), hint: LOGS_SYNTAX_HINT }));""")
    assert r["ranges"] == ["15m", "1h", "4h", "24h", "7d", "All"]
    for query in ["source=powershell", "source=mcp | stats count by tool", "source=access NOT poll=true",
                  "source=netflow | sort -count | head 20", "source=dns | top query", "source=firewall action=DROP",
                  "* | timechart span=5m count by source"]:
        assert query in r["examples"], query
    assert r["labels"] and "stats" in r["hint"] and "timechart" in r["hint"]


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
def test_a_timechart_has_a_chart_and_a_table():
    r = _run(r"""
        const rows = [['2026-11-14T10:00:00Z', 2, 0], ['2026-11-14T10:05:00Z', 1, 3], ['2026-11-14T10:10:00Z', 0, 1]];
        const result = { type: 'timechart', events: [], columns: ['_time', 'access', 'mcp'], rows, count: 3, matched: 7, truncated: false,
            histogram: { bins: [], span_s: 300 }, fields: [], took_ms: 2 };
        renderLogsResultBody(result);
        const html = els['logs-results'].innerHTML;
        tableSortState['logs-result'] = { col: 2, dir: 'asc' };
        renderLogsResultBody({ ...result, columns: ['_time', 'a'], rows: [['2026-11-14T10:00:00Z', 1]] });
        console.log(JSON.stringify({ html, reset: tableSortState['logs-result'] === undefined }));""")
    assert r["html"].count("data-bin-start=") == 3 and "<table" in r["html"] and "TIMECHART" in r["html"]
    assert "logs-legend-item" in r["html"] and r["reset"] is True


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
            title: els['logs-syntax'].title, range: els['logs-range'].innerHTML, total: searches().length, prevented,
            last: Object.fromEntries(query(searches().pop())), recent: logsRecent(), layer: els['logs-hl'].innerHTML }));""")
    assert r["first"] == [{"q": "source=dns | top query", "earliest": "-4h", "limit": "200"}]
    assert r["sources"] == 2 and "Pipes:" in r["title"] and r["total"] == 3
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
