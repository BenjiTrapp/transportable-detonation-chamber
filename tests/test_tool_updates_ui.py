"""The "Tool Updates" section of the dashboard and the maintenance banner
(block TOOL UPDATES of static/js/app.js).

Regressions covered:
  * a tool name, version or log (they come from the tools and the network) taken as markup
  * "Update all" counting pinned tools, or enabled while a run is on or nothing is to do
  * an Update button where it does nothing (a tool that needs a reboot) or none where it helps
  * a pinned tool installed without asking, a refused question that still sends the request
  * a banner shown while only checking, or with the wrong tool number
  * a status without a readable label
  * a refused request (409, 503) that shows nothing
  * markup in the wrong place: the section outside the dashboard, the banner inside a tab
"""

import html
import json
import re

from test_frontend import _function_source, _run_node, needs_node
from test_theme import INDEX_HTML, _Elements, _const_source, _read

UPDATE_FUNCTIONS = [
    "updateStatusLabel", "updateRowHtml", "updatesHtml", "renderUpdates", "renderMaintenanceBanner",
    "updatesIsPinned", "updatesSummary", "scheduleUpdatesPoll", "refreshUpdates", "checkUpdates", "updatesPost", "applyUpdates",
    "updateOne", "updateAll", "toggleUpdateLog", "escapeHtml", "jsArg", "cssToken", "skullButtonSvg",
    "updateAllButtonHtml",
]
STATUSES = ["up_to_date", "update_available", "pinned_update", "unknown", "not_installed", "offline", "error",
            "queued", "updating", "updated", "failed", "reboot_required"]
HOSTILE = "<img src=x onerror=alert(1)>"

PRELUDE = _const_source("UPDATE_STATUS_LABELS") + r"""
const UPDATES_POLL_MS = 3000;
let updatesState = null;
let updatesPollTimer = null;
let updatesOpenLogs = new Set();
let updatesRendered = null;
let updatesSeq = 0;
const classes = () => {
    const set = new Set();
    return { add: c => set.add(c), remove: c => set.delete(c), toggle: (c, on) => { on ? set.add(c) : set.delete(c); },
             contains: c => set.has(c), has: c => set.has(c), list: () => [...set] };
};
const els = {};
for (const id of ['tool-updates', 'tool-updates-body', 'maintenance-banner', 'maintenance-text',
                  'maintenance-progress-bar']) {
    els[id] = { id, innerHTML: '', textContent: '', hidden: false, style: {}, classList: classes() };
}
els['maintenance-banner'].hidden = true;
globalThis.document = { hidden: false, getElementById: id => els[id] || null, body: { classList: classes() } };
const calls = [];
const toasts = [];
globalThis.showToast = (type, title, detail) => toasts.push({ type, title, detail });
globalThis.setTimeout = (fn, ms) => { calls.push(['timeout', ms]); return 1; };
globalThis.clearTimeout = () => {};
const tool = (id, status, extra = {}) => ({ id, name: id.toUpperCase(), kind: 'github', installed: '1.0',
    available: '2.0', status, pinned: null, detail: '', log: [], updated_at: null, ...extra });
const state = (tools, extra = {}) => ({ mode: 'idle', checked_at: null, tools,
    progress: { done: 0, total: 0, current: null }, last_run: null, ...extra });
"""


def _run(script):
    return _run_node(UPDATE_FUNCTIONS, script, PRELUDE)


def _all_button(html):
    return re.search(r'<button[^>]*id="updates-all"[^>]*>', html).group(0)


@needs_node
def test_update_all_count_excludes_pinned():
    r = _run(r"""
        renderUpdates(state([tool('a', 'update_available'), tool('b', 'update_available'),
                             tool('c', 'pinned_update', { pinned: '1.0' }), tool('d', 'up_to_date')]));
        const all = els['tool-updates-body'].innerHTML;
        renderUpdates(state([tool('c', 'pinned_update', { pinned: '1.0' })]));
        const none = els['tool-updates-body'].innerHTML;
        renderUpdates(state([tool('a', 'update_available')], { mode: 'checking' }));
        const busy = els['tool-updates-body'].innerHTML;
        console.log(JSON.stringify({ all, none, busy }));
    """)
    assert 'aria-label="Update all (2)"' in _all_button(r["all"]) and "disabled" not in _all_button(r["all"])
    assert 'aria-label="Update all (0)"' in _all_button(r["none"]) and "disabled" in _all_button(r["none"])
    assert 'aria-label="Update all (1)"' in _all_button(r["busy"]) and "disabled" in _all_button(r["busy"])


@needs_node
def test_update_all_uses_skull_button():
    r = _run(r"""
        const out = {};
        renderUpdates(state([tool('a', 'update_available'), tool('b', 'update_available')]));
        out.two = els['tool-updates-body'].innerHTML;
        renderUpdates(state([]));
        out.zero = els['tool-updates-body'].innerHTML;
        renderUpdates(state([tool('a', 'update_available')], { mode: 'updating' }));
        out.busy = els['tool-updates-body'].innerHTML;
        console.log(JSON.stringify(out));
    """)
    two, zero, busy = _all_button(r["two"]), _all_button(r["zero"]), _all_button(r["busy"])
    assert 'class="btn-skull"' in two and 'aria-label="Update all (2)"' in two and "disabled" not in two
    assert "UPDATE ALL" in r["two"] and '<span class="btn-skull-badge">2</span>' in r["two"]
    assert "<svg" in r["two"] and 'id="tdc-skull-' in r["two"]
    assert "disabled" in zero and 'title="No updates to install"' in zero
    assert "disabled" in busy and 'title="An update check or install is running"' in busy


@needs_node
def test_skull_svg_has_no_colour_literals():
    r = _run(r"""
        console.log(JSON.stringify({ a: skullButtonSvg(), b: skullButtonSvg('-dlg') }));
    """)
    for svg in r.values():
        assert svg.startswith("<svg") and svg.endswith("</svg>") and 'aria-hidden="true"' in svg
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", svg.replace("url(#tdc-skull-", "url(")), svg
        assert not re.search(r"rgba?\(|hsla?\(", svg)
        for attr, value in re.findall(r'\b(fill|stroke|stop-color)="([^"]*)"', svg):
            assert value == "none" or value.startswith(("var(--skull-", "url(#tdc-skull-")), (attr, value)
        for value in re.findall(r"stop-color:\s*([^;\"]*)", svg):
            assert value.startswith("var(--skull-"), value
        ids = re.findall(r'\bid="([^"]*)"', svg)
        assert ids and all(i.startswith("tdc-skull-") for i in ids)
        for ref in re.findall(r"url\(#([^)]*)\)", svg):
            assert ref in ids, ref
    assert not set(re.findall(r'\bid="([^"]*)"', r["a"])) & set(re.findall(r'\bid="([^"]*)"', r["b"])), \
        "the dialog's skull must not share gradient ids with the button's"


@needs_node
def test_header_says_when_it_was_checked_and_blocks_checks_while_busy():
    r = _run(r"""
        renderUpdates(state([]));
        const never = els['tool-updates-body'].innerHTML;
        renderUpdates(state([], { checked_at: '2026-11-13T10:00:00+00:00' }));
        const checked = els['tool-updates-body'].innerHTML;
        renderUpdates(state([], { mode: 'updating' }));
        const busy = els['tool-updates-body'].innerHTML;
        console.log(JSON.stringify({ never, checked, busy }));
    """)
    assert "Never checked" in r["never"] and "Check for updates" in r["never"]
    assert "Last checked" in r["checked"] and "Never checked" not in r["checked"]
    check = re.search(r'<button[^>]*id="updates-check"[^>]*>', r["busy"]).group(0)
    assert "disabled" in check
    assert "disabled" not in re.search(r'<button[^>]*id="updates-check"[^>]*>', r["never"]).group(0)


@needs_node
def test_tool_names_are_escaped():
    r = _run(r"""
        const bad = tool('x', 'failed', { name: '<img src=x onerror=alert(1)>', installed: '<b>1', available: '<i>2',
            kind: '<u>k', detail: '<s>d', log: ['</pre><script>alert(2)</script>'], pinned: '"><svg onload=1>' });
        updatesOpenLogs.add('x');
        renderUpdates(state([bad]));
        console.log(JSON.stringify({ html: els['tool-updates-body'].innerHTML }));
    """)
    html = r["html"]
    # the skull button is the one <svg> of the section; a hostile one never gets in
    assert "<img" not in html and "<script" not in html and "<svg onload" not in html
    assert html.count("<svg") == 1
    assert "<b>" not in html and "<i>" not in html and "<u>" not in html and "<s>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;/pre&gt;&lt;script&gt;" in html
    assert html.count("</pre>") == 1, "the log leaves its <pre>"


@needs_node
def test_inline_handlers_only_get_quoted_ids():
    hostile = "a');alert(1);('\"<"
    r = _run("""
        renderUpdates(state([tool(%s, 'update_available')]));
        console.log(JSON.stringify({ html: els['tool-updates-body'].innerHTML }));
    """ % json.dumps(hostile))
    handlers = re.findall(r'\bon\w+="([^"]*)"', r["html"])
    with_id = [h for h in handlers if "(" in h and not h.endswith("()")]
    assert len(with_id) == 2, handlers
    for handler in with_id:
        assert "<" not in handler
        argument = html.unescape(handler)
        literal = argument[argument.index("(") + 1:argument.rindex(")")].split(", ")[-1]
        assert json.loads(literal) == hostile, "the id is not one JSON string"


@needs_node
def test_update_button_only_where_an_update_can_be_installed():
    r = _run(r"""
        const out = {};
        for (const status of %s) {
            renderUpdates(state([tool('t', status, { pinned: status === 'pinned_update' ? '1.0' : null })]));
            const html = els['tool-updates-body'].innerHTML;
            out[status] = /<button[^>]*class="[^"]*updates-row-btn/.test(html);
        }
        console.log(JSON.stringify(out));
    """ % STATUSES)
    assert [s for s, shown in r.items() if shown] == ["update_available", "pinned_update", "failed"]


@needs_node
def test_a_row_opens_its_log():
    r = _run(r"""
        const t = tool('x', 'failed', { log: ['line one', 'line two'] });
        updatesState = state([t]);
        renderUpdates(updatesState);
        const closed = els['tool-updates-body'].innerHTML;
        toggleUpdateLog({ target: { closest: () => null } }, 'x');
        const open = els['tool-updates-body'].innerHTML;
        toggleUpdateLog({ target: { closest: () => null } }, 'x');
        const closedAgain = els['tool-updates-body'].innerHTML;
        // a click on the row's own button does not open the log
        toggleUpdateLog({ target: { closest: () => ({}) } }, 'x');
        console.log(JSON.stringify({ closed, open, closedAgain, still: els['tool-updates-body'].innerHTML }));
    """)
    assert "line one" not in r["closed"]
    assert "line one\nline two" in r["open"] and "<pre" in r["open"] and "data-sort-detail" in r["open"]
    assert r["closedAgain"] == r["closed"] and r["still"] == r["closed"]


@needs_node
def test_a_log_row_is_kept_across_a_redraw_of_the_same_state():
    """The poll draws every 10 s: a state that did not change is not drawn again (a click
    or a selection in the log would be lost)."""
    r = _run(r"""
        const s = state([tool('x', 'update_available')]);
        renderUpdates(s);
        let writes = 0;
        const el = els['tool-updates-body'];
        let html = el.innerHTML;
        Object.defineProperty(el, 'innerHTML', { get: () => html, set: v => { writes++; html = v; } });
        renderUpdates(JSON.parse(JSON.stringify(s)));
        console.log(JSON.stringify({ writes }));
    """)
    assert r["writes"] == 0


@needs_node
def test_banner_only_while_updating():
    r = _run(r"""
        const banner = els['maintenance-banner'], text = els['maintenance-text'];
        const out = {};
        renderMaintenanceBanner(state([], { mode: 'checking' }));
        out.checking = { hidden: banner.hidden, body: document.body.classList.has('maintenance-active') };
        renderMaintenanceBanner(state([], { mode: 'updating', progress: { done: 2, total: 5, current: 'LitterBox' } }));
        out.updating = { hidden: banner.hidden, body: document.body.classList.has('maintenance-active'),
                         text: text.textContent, width: els['maintenance-progress-bar'].style.width };
        renderMaintenanceBanner(state([], { mode: 'updating', progress: { done: 5, total: 5, current: null } }));
        out.last = text.textContent;
        renderMaintenanceBanner(state([], { mode: 'idle' }));
        out.idle = { hidden: banner.hidden, body: document.body.classList.has('maintenance-active') };
        renderMaintenanceBanner(null);
        out.none = { hidden: banner.hidden, body: document.body.classList.has('maintenance-active') };
        console.log(JSON.stringify(out));
    """)
    assert r["checking"] == {"hidden": True, "body": False}
    assert r["updating"]["hidden"] is False and r["updating"]["body"] is True
    assert r["updating"]["text"] == ("MAINTENANCE — Updating tools (3/5: LitterBox). "
                                     "Detonations, scans and uploads are paused.")
    assert r["updating"]["width"] == "40%"
    assert "(5/5)" in r["last"] and "5/5:" not in r["last"]
    assert r["idle"] == {"hidden": True, "body": False} and r["none"] == {"hidden": True, "body": False}


@needs_node
def test_a_missing_part_does_not_stop_the_updates():
    r = _run(r"""
        delete els['tool-updates-body']; delete els['tool-updates'];
        delete els['maintenance-banner']; delete els['maintenance-text']; delete els['maintenance-progress-bar'];
        const s = state([tool('a', 'update_available')], { mode: 'updating', progress: { done: 0, total: 1, current: 'a' } });
        const failed = [];
        for (const f of [renderUpdates, renderMaintenanceBanner]) {
            try { f(s); } catch (e) { failed.push(f.name + ': ' + e.message); }
        }
        console.log(JSON.stringify(failed));
    """)
    assert r == []


@needs_node
def test_status_labels_cover_all_statuses():
    r = _run(r"""
        console.log(JSON.stringify(Object.fromEntries(%s.map(s => [s, updateStatusLabel(s)])
            .concat([['weird', updateStatusLabel('weird')], ['none', updateStatusLabel(null)]]))));
    """ % STATUSES)
    for status in STATUSES:
        assert r[status].strip() and r[status] != status, status
    assert len(set(r[s] for s in STATUSES)) == len(STATUSES)
    assert r["pinned_update"] == "Pinned – newer available" and r["reboot_required"] == "Reboot required"
    assert isinstance(r["weird"], str) and isinstance(r["none"], str)


@needs_node
def test_every_status_has_a_badge_colour_in_both_sheets():
    """A badge class for each status: colours from variables in style.css, a Cyberpunk look in its own sheet."""
    from test_theme import STYLE_CSS, THEME_CSS
    css, cyber = _read(STYLE_CSS), _read(THEME_CSS)
    for status in STATUSES:
        assert f".updates-status-{status.replace('_', '-')}" in css, status
    assert ".maintenance-banner" in css and '[data-theme="cyberpunk"] .maintenance-banner' in cyber
    assert '[data-theme="cyberpunk"] .updates-table' in cyber


def _fetch_prelude(responses, confirm_answer=True):
    """fetch answers from `responses` (by url), tdcConfirm records its questions."""
    import json
    return PRELUDE + f"""
const requests = [];
const questions = [];
const responses = {json.dumps(responses)};
globalThis.fetch = async (url, opts = {{}}) => {{
    requests.push({{ url, method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : null }});
    const r = responses[url] || {{ status: 200, body: {{}} }};
    return {{ ok: r.status < 400, status: r.status, json: async () => r.body }};
}};
globalThis.confirm = () => {{ throw new Error('native confirm() used'); }};
globalThis.tdcConfirm = async opts => {{ questions.push(opts); return {'true' if confirm_answer else 'false'}; }};
globalThis.refreshUpdates = async () => {{ requests.push({{ refresh: true }}); }};
"""


def _run_with(responses, script, confirm_answer=True):
    return _run_node(UPDATE_FUNCTIONS, script, _fetch_prelude(responses, confirm_answer))


@needs_node
def test_a_pinned_tool_asks_before_it_is_installed():
    r = _run_with({"/api/updates/apply": {"status": 202, "body": {"started": True, "tools": ["c"]}}}, r"""
        updatesState = state([tool('c', 'pinned_update', { name: 'Ghidra', pinned: '11.0', available: '11.3' }),
                              tool('a', 'update_available')]);
        (async () => {
            await applyUpdates(['c'], false);
            await applyUpdates(['a'], false);
            console.log(JSON.stringify({ questions, requests }));
        })();
    """)
    assert [(q["title"], q["message"], q["confirmLabel"], q["danger"]) for q in r["questions"]] == [
        ("Ghidra is pinned", "Ghidra is pinned to 11.0 for compatibility. Install 11.3 anyway?", "Install anyway", True)]
    posts = [q for q in r["requests"] if q.get("method") == "POST"]
    assert posts[0]["body"] == {"tools": ["c"], "include_pinned": True}
    assert posts[1]["body"] == {"tools": ["a"], "include_pinned": False}


@needs_node
def test_a_choco_package_asks_with_its_own_detail_and_a_choco_pin_goes_to_the_server():
    r = _run_with({"/api/updates/apply": {"status": 409, "body": {"error": "php is pinned in Chocolatey."}}}, r"""
        updatesState = state([
            tool('py', 'pinned_update', { kind: 'choco', name: 'python312', pinned: '3.12.1', available: '3.12.2',
                                          detail: 'The web UI runs on this Python.' }),
            tool('php', 'pinned_update', { kind: 'choco', name: 'php', pinned: '8.2.1', available: '8.3.0',
                                           choco_pinned: true, detail: 'Pinned in Chocolatey' })]);
        (async () => {
            await applyUpdates(['py'], false);
            await applyUpdates(['php'], false);
            console.log(JSON.stringify({ questions, requests }));
        })();
    """)
    assert [(q["title"], q["message"]) for q in r["questions"]] == [
        ("python312 is pinned", "python312: The web UI runs on this Python. Install 3.12.2 anyway?")]
    posts = [q for q in r["requests"] if q.get("method") == "POST"]
    assert [p["body"] for p in posts] == [{"tools": ["py"], "include_pinned": True},
                                          {"tools": ["php"], "include_pinned": True}]


@needs_node
def test_a_refused_question_sends_nothing():
    r = _run_with({}, r"""
        updatesState = state([tool('c', 'pinned_update', { name: 'Ghidra', pinned: '11.0', available: '11.3' }),
                              tool('a', 'update_available'), tool('b', 'update_available')]);
        (async () => {
            await applyUpdates(['c'], false);
            await applyUpdates('all', false);
            console.log(JSON.stringify({ questions, requests }));
        })();
    """, confirm_answer=False)
    assert r["requests"] == []
    ask = r["questions"][1]
    assert ask["title"] == "Install 2 updates?"
    assert ask["message"] == "Detonations, scans and uploads are paused while they run."
    assert ask["confirmLabel"] == "Install" and ask["danger"] is True
    assert [i["name"] for i in ask["items"]] == ["A", "B"]
    assert ask["items"][0] == {"name": "A", "from": "1.0", "to": "2.0"}


@needs_node
def test_update_all_sends_all_without_pinned_tools():
    r = _run_with({"/api/updates/apply": {"status": 202, "body": {"started": True, "tools": ["a", "b"]}}}, r"""
        updatesState = state([tool('a', 'update_available'), tool('b', 'update_available'),
                              tool('c', 'pinned_update', { pinned: '1.0' })]);
        (async () => {
            await updateAll();
            console.log(JSON.stringify({ questions, requests, toasts }));
        })();
    """)
    posts = [q for q in r["requests"] if q.get("method") == "POST"]
    assert posts == [{"url": "/api/updates/apply", "method": "POST",
                      "body": {"tools": "all", "include_pinned": False}}]
    assert {"refresh": True} in r["requests"]


@needs_node
def test_a_refused_request_shows_the_error():
    error = "Maintenance: tool updates are running. Detonations, scans and uploads are paused."
    r = _run_with({"/api/updates/apply": {"status": 409, "body": {"error": "Another run is active"}},
                   "/api/updates/check": {"status": 503, "body": {"error": error, "maintenance": True}}}, r"""
        updatesState = state([tool('a', 'update_available')]);
        (async () => {
            await applyUpdates(['a'], false);
            await checkUpdates();
            console.log(JSON.stringify({ toasts }));
        })();
    """)
    assert [(t["type"], t["detail"]) for t in r["toasts"]] == [("error", "Another run is active"), ("error", error)]


@needs_node
def test_a_network_error_shows_a_toast_and_does_not_throw():
    r = _run_node(UPDATE_FUNCTIONS, r"""
        globalThis.fetch = async () => { throw new Error('offline'); };
        globalThis.confirm = () => true;
        updatesState = state([tool('a', 'update_available')]);
        (async () => {
            await applyUpdates(['a'], false);
            await checkUpdates();
            await refreshUpdates();
            console.log(JSON.stringify({ toasts }));
        })();
    """, PRELUDE)
    assert [t["type"] for t in r["toasts"]] == ["error", "error"]


@needs_node
def test_check_starts_a_check_and_refreshes():
    r = _run_with({"/api/updates/check": {"status": 202, "body": {"started": True}}}, r"""
        (async () => {
            await checkUpdates();
            console.log(JSON.stringify({ requests }));
        })();
    """)
    assert r["requests"][0] == {"url": "/api/updates/check", "method": "POST", "body": None}
    assert {"refresh": True} in r["requests"]


@needs_node
def test_refresh_polls_fast_while_busy_and_reports_the_end_of_an_update():
    r = _run_node(UPDATE_FUNCTIONS, r"""
        const answers = [
            state([tool('a', 'updating')], { mode: 'updating', progress: { done: 0, total: 2, current: 'a' } }),
            state([tool('a', 'updated'), tool('b', 'failed')], { mode: 'idle',
                last_run: { started_at: 'x', finished_at: 'y', results: { a: 'updated', b: 'failed' } } }),
            state([tool('a', 'updated'), tool('b', 'failed')], { mode: 'idle',
                last_run: { started_at: 'x', finished_at: 'y', results: { a: 'updated', b: 'failed' } } }),
        ];
        globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => answers.shift() });
        (async () => {
            await refreshUpdates();
            const busyDelay = calls.filter(c => c[0] === 'timeout').map(c => c[1]);
            const bannerShown = els['maintenance-banner'].hidden === false;
            const toastsBusy = toasts.length;
            await refreshUpdates();
            const bannerGone = els['maintenance-banner'].hidden === true;
            const afterEnd = toasts.slice();
            const timeouts = calls.filter(c => c[0] === 'timeout').length;
            await refreshUpdates();
            console.log(JSON.stringify({ busyDelay, bannerShown, toastsBusy, bannerGone, afterEnd,
                                         again: toasts.length, timeouts, timeoutsAfter: calls.filter(c => c[0] === 'timeout').length }));
        })();
    """, PRELUDE)
    assert r["busyDelay"] == [3000] and r["bannerShown"] and r["toastsBusy"] == 0 and r["bannerGone"]
    assert len(r["afterEnd"]) == 1
    toast = r["afterEnd"][0]
    assert toast["type"] == "warning" and "1 updated, 1 failed" in (toast["title"] + toast["detail"])
    assert r["again"] == 1, "a second idle state reports no second run"
    assert r["timeoutsAfter"] == r["timeouts"], "an idle state goes on polling every 3 s"


@needs_node
def test_a_clean_update_run_reports_success():
    r = _run_node(UPDATE_FUNCTIONS, r"""
        updatesState = state([], { mode: 'updating' });
        const done = state([tool('a', 'updated'), tool('b', 'updated')], { last_run: { started_at: 'x',
            finished_at: 'y', results: { a: 'updated', b: 'updated' } } });
        globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => done });
        (async () => { await refreshUpdates(); console.log(JSON.stringify({ toasts })); })();
    """, PRELUDE)
    assert [t["type"] for t in r["toasts"]] == ["success"]
    assert "2 updated, 0 failed" in r["toasts"][0]["title"] + r["toasts"][0]["detail"]


@needs_node
def test_the_poll_does_not_run_while_the_page_is_hidden():
    r = _run_node(UPDATE_FUNCTIONS, r"""
        updatesState = state([], { mode: 'updating' });
        document.hidden = true;
        let fetched = 0;
        globalThis.fetch = async () => { fetched++; return { ok: true, status: 200, json: async () => state([]) }; };
        scheduleUpdatesPoll();
        console.log(JSON.stringify({ timers: calls.length, fetched }));
    """, PRELUDE)
    assert r == {"timers": 1, "fetched": 0}


@needs_node
def test_update_all_calls_tdcConfirm_not_native_confirm():
    """confirm() throws in the stub: the flow has to go through tdcConfirm."""
    r = _run_with({"/api/updates/apply": {"status": 202, "body": {"started": True, "tools": ["a"]}}}, r"""
        updatesState = state([tool('a', 'update_available'), tool('c', 'pinned_update', { pinned: '1.0' })]);
        (async () => {
            let error = null;
            try { await updateAll(); await applyUpdates(['c'], false); } catch (e) { error = e.message; }
            console.log(JSON.stringify({ error, asked: questions.length, requests }));
        })();
    """)
    assert r["error"] is None and r["asked"] == 2
    assert len([q for q in r["requests"] if q.get("method") == "POST"]) == 2


@needs_node
def test_singular_title():
    r = _run_with({"/api/updates/apply": {"status": 202, "body": {"started": True, "tools": ["a"]}}}, r"""
        updatesState = state([tool('a', 'update_available')]);
        (async () => { await updateAll(); console.log(JSON.stringify({ questions })); })();
    """)
    assert r["questions"][0]["title"] == "Install 1 update?"


# --- tdcConfirm -------------------------------------------------------------------

CONFIRM_FUNCTIONS = ["tdcConfirm", "skullButtonSvg"]
CONFIRM_PRELUDE = PRELUDE + r"""
let tdcConfirmClose = null;
class El {
    constructor(tag) {
        this.tag = tag; this.children = []; this.parent = null; this.attrs = {}; this.listeners = {};
        this.id = ''; this.className = ''; this._text = ''; this._html = ''; this.disabled = false;
        this.style = {}; this.type = ''; this.classList = classes();
    }
    get innerHTML() { return this._html; }
    set innerHTML(v) { this._html = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    set textContent(v) { this._text = String(v); this.children = []; }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    appendChild(c) { c.parent = this; this.children.push(c); return c; }
    remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
    focus() { document.activeElement = this; }
    get isConnected() { let n = this; while (n.parent) n = n.parent; return n === document.body; }
    click() { fire(this, 'click'); }
}
const fire = (el, type, extra = {}) => {
    const ev = { type, target: el, key: '', shiftKey: false, defaultPrevented: false,
                 preventDefault() { this.defaultPrevented = true; }, stopPropagation() {}, ...extra };
    for (const f of [...(el.listeners[type] || [])]) f(ev);
    return ev;
};
const walk = function* (n) { yield n; for (const c of n.children) yield* walk(c); };
const find = pred => { for (const n of walk(document.body)) if (pred(n)) return n; return null; };
const findAll = pred => [...walk(document.body)].filter(pred);
const press = (key, extra = {}) => fire(document, 'keydown', { key, target: document.activeElement, ...extra });
const trigger = new El('button');
globalThis.document = Object.assign(new El('document'), {
    body: new El('body'), activeElement: null, hidden: false,
    createElement: tag => new El(tag),
    getElementById: id => find(n => n.id === id),
});
document.body.appendChild(trigger);
trigger.focus();
const buttons = () => ({ cancel: find(n => n.className.includes('tdc-confirm-cancel')),
                         ok: find(n => n.className.includes('tdc-confirm-ok')) });
"""


def _confirm(script):
    return _run_node(CONFIRM_FUNCTIONS, script, CONFIRM_PRELUDE)


@needs_node
def test_confirm_builds_an_accessible_dialog_and_removes_it():
    r = _confirm(r"""
        (async () => {
            const p = tdcConfirm({ title: 'Install 2 updates?', message: 'Paused.', confirmLabel: 'Install',
                                   items: [{ name: 'A', from: '1', to: '2' }] });
            const dlg = find(n => n.attrs.role === 'dialog');
            const root = document.getElementById('tdc-confirm');
            const titleId = dlg && dlg.attrs['aria-labelledby'];
            const b = buttons();
            const open = { root: !!root, modal: dlg && dlg.attrs['aria-modal'],
                           title: titleId && document.getElementById(titleId).textContent,
                           focus: document.activeElement === b.cancel, cancel: b.cancel.textContent,
                           ok: b.ok.textContent, text: root.textContent };
            b.ok.click();
            const result = await p;
            console.log(JSON.stringify({ open, result, gone: document.getElementById('tdc-confirm') === null,
                                         back: document.activeElement === trigger,
                                         keydown: document.listeners.keydown.length }));
        })();
    """)
    assert r["open"]["root"] and r["open"]["modal"] == "true" and r["open"]["title"] == "Install 2 updates?"
    assert r["open"]["focus"] and r["open"]["cancel"] == "Cancel" and r["open"]["ok"] == "Install"
    assert "Paused." in r["open"]["text"] and "1" in r["open"]["text"] and "2" in r["open"]["text"]
    assert r["result"] is True and r["gone"] and r["back"] and r["keydown"] == 0


@needs_node
def test_confirm_resolves_false_on_escape_and_backdrop():
    r = _confirm(r"""
        (async () => {
            const out = {};
            let p = tdcConfirm({ title: 't', message: 'm' });
            press('Escape');
            out.escape = await p;
            p = tdcConfirm({ title: 't', message: 'm' });
            find(n => n.className.includes('tdc-confirm-backdrop')).click();
            out.backdrop = await p;
            p = tdcConfirm({ title: 't', message: 'm' });
            find(n => n.attrs.role === 'dialog').click();
            const stillOpen = document.getElementById('tdc-confirm') !== null;
            buttons().cancel.click();
            out.cancel = await p;
            out.stillOpenAfterDialogClick = stillOpen;
            out.gone = document.getElementById('tdc-confirm') === null;
            console.log(JSON.stringify(out));
        })();
    """)
    assert r == {"escape": False, "backdrop": False, "cancel": False, "stillOpenAfterDialogClick": True, "gone": True}


@needs_node
def test_confirm_resolves_true_on_confirm():
    r = _confirm(r"""
        (async () => {
            const out = {};
            let p = tdcConfirm({ title: 't', message: 'm' });
            buttons().ok.click();
            out.click = await p;
            p = tdcConfirm({ title: 't', message: 'm' });
            buttons().ok.focus();
            const ev = press('Enter');
            out.enter = await p;
            out.prevented = ev.defaultPrevented;
            p = tdcConfirm({ title: 't', message: 'm' });
            press('Enter');   // focus is on Cancel: Enter there is Cancel, not a confirmation
            buttons().cancel.click();
            out.enterOnCancel = await p;
            console.log(JSON.stringify(out));
        })();
    """)
    assert r["click"] is True and r["enter"] is True and r["enterOnCancel"] is False


@needs_node
def test_confirm_keeps_tab_inside_the_dialog():
    r = _confirm(r"""
        (async () => {
            const p = tdcConfirm({ title: 't', message: 'm' });
            const b = buttons();
            const seen = [];
            for (let i = 0; i < 3; i++) { press('Tab'); seen.push(document.activeElement === b.ok ? 'ok' : 'cancel'); }
            press('Tab', { shiftKey: true });
            seen.push(document.activeElement === b.ok ? 'ok' : 'cancel');
            document.activeElement = trigger;   // focus got out: Tab brings it back
            press('Tab');
            seen.push(document.activeElement === b.cancel || document.activeElement === b.ok ? 'in' : 'out');
            press('Escape');
            await p;
            console.log(JSON.stringify(seen));
        })();
    """)
    assert r == ["ok", "cancel", "ok", "cancel", "in"]


@needs_node
def test_confirm_escapes_items():
    r = _confirm(r"""
        (async () => {
            const p = tdcConfirm({ title: '<b>t</b>', message: '<i>m</i>', confirmLabel: '<u>go</u>',
                items: [{ name: '<img src=x onerror=alert(1)>', from: '<s>1', to: '"><svg onload=1>' }] });
            const root = document.getElementById('tdc-confirm');
            const markup = [...walk(root)].map(n => n.innerHTML).join('');
            const text = root.textContent;
            buttons().cancel.click();
            await p;
            console.log(JSON.stringify({ markup, text }));
        })();
    """)
    for hostile in ("<img", "<b>", "<i>", "<u>", "<s>", "<svg onload"):
        assert hostile not in r["markup"], hostile
    assert "<img src=x onerror=alert(1)>" in r["text"] and '"><svg onload=1>' in r["text"]
    assert "<b>t</b>" in r["text"] and "<u>go</u>" in r["text"]


@needs_node
def test_confirm_lists_at_most_12_items():
    r = _confirm(r"""
        (async () => {
            const items = Array.from({ length: 15 }, (_, i) => ({ name: 'tool' + i, from: '1', to: '2' }));
            let p = tdcConfirm({ title: 't', message: 'm', items });
            const li = findAll(n => n.tag === 'li').map(n => n.textContent);
            buttons().cancel.click(); await p;
            p = tdcConfirm({ title: 't', message: 'm', items: items.slice(0, 12) });
            const exact = findAll(n => n.tag === 'li').map(n => n.textContent);
            buttons().cancel.click(); await p;
            p = tdcConfirm({ title: 't', message: 'm' });
            const none = findAll(n => n.tag === 'li').length;
            buttons().cancel.click(); await p;
            console.log(JSON.stringify({ li, exact, none }));
        })();
    """)
    assert len(r["li"]) == 13 and r["li"][-1] == "+ 3 more"
    assert [t for t in r["li"][:12] if t.startswith("tool")] == r["li"][:12]
    assert len(r["exact"]) == 12 and not any("more" in t for t in r["exact"]) and r["none"] == 0


@needs_node
def test_confirm_shows_the_skull_only_when_dangerous():
    r = _confirm(r"""
        (async () => {
            const out = {};
            let p = tdcConfirm({ title: 't', message: 'm' });
            out.plain = findAll(n => n.innerHTML.includes('<svg')).length;
            out.plainClass = find(n => n.attrs.role === 'dialog').className;
            buttons().cancel.click(); await p;
            p = tdcConfirm({ title: 't', message: 'm', danger: true });
            out.danger = findAll(n => n.innerHTML.includes('<svg')).length;
            out.dangerClass = find(n => n.attrs.role === 'dialog').className;
            buttons().cancel.click(); await p;
            console.log(JSON.stringify(out));
        })();
    """)
    assert r["plain"] == 0 and r["danger"] == 1
    assert "danger" not in r["plainClass"] and "danger" in r["dangerClass"]


@needs_node
def test_a_second_confirm_resolves_the_first_with_false():
    r = _confirm(r"""
        (async () => {
            const first = tdcConfirm({ title: 'one', message: 'm' });
            const second = tdcConfirm({ title: 'two', message: 'm' });
            const roots = findAll(n => n.id === 'tdc-confirm').length;
            const titles = findAll(n => n.className.includes('tdc-confirm-title')).map(n => n.textContent);
            const firstResult = await first;
            buttons().ok.click();
            console.log(JSON.stringify({ firstResult, secondResult: await second, roots, titles,
                                         back: document.activeElement === trigger,
                                         keydown: document.listeners.keydown.length }));
        })();
    """)
    assert r["firstResult"] is False and r["secondResult"] is True
    assert r["roots"] == 1 and r["titles"] == ["two"] and r["back"] and r["keydown"] == 0


# --- Markup and wiring ---------------------------------------------------------

def _walk(node, ancestors=()):
    for child in node["children"]:
        yield child, ancestors
        yield from _walk(child, ancestors + (child,))


def test_markup_present():
    html = _read(INDEX_HTML)
    root = _Elements(html).root
    found = {child["attrs"].get("id"): (child, anc) for child, anc in _walk(root) if child["attrs"].get("id")}
    section, section_anc = found["tool-updates"]
    assert any(a["attrs"].get("id") == "tab-dashboard" for a in section_anc), "#tool-updates is not in the dashboard"
    banner, banner_anc = found["maintenance-banner"]
    assert not any("tab-content" in a["attrs"].get("class", "").split() for a in banner_anc), \
        "#maintenance-banner is inside a tab"
    for part in ("tool-updates-body", "maintenance-text", "maintenance-progress-bar"):
        assert part in found, part
    assert "hidden" in banner["attrs"]
    assert "data-info" in section["attrs"] or any("data-info" in c["attrs"] for c, _ in _walk(section))
    assert "Checks every installed tool for a newer version and installs it." in html


def test_the_banner_follows_the_top_bar():
    html = _read(INDEX_HTML)
    assert html.index('id="topbar"') < html.index('id="maintenance-banner"') < html.index('id="main-content"')


def test_the_help_mentions_tool_updates():
    html = _read(INDEX_HTML)
    usage = html[html.index('id="help-usage"'):]
    assert "Tool Updates" in usage


def test_the_poll_goes_with_the_dashboard_refresh():
    source = _read(__import__("test_frontend").APP_JS)
    assert re.search(r"setInterval\(\(\) => \{\s*if \(!document\.hidden\) \{[^}]*refreshUpdates\(\)", source)
    assert "refreshUpdates()" in _function_source("refreshAll")
    assert re.search(r"visibilitychange.*?refreshUpdates\(\)", source, re.S)
