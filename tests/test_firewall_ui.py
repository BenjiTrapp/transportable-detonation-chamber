"""The FIREWALL tab (block FIREWALL of static/js/app.js, #tab-firewall of index.html).

Regressions covered:
  * an image path, a host name, a URL, an AS name or a tag (all of it comes
    from the VM, much of it from the sample) reaching the page as markup, a
    link or a class name: in the tree, the map, LIST, ASN, the summary, the
    hints or the captures
  * a URL or a host shown live (http://, a dotted name) instead of defanged,
    and a javascript: or data: scheme surviving as one
  * a row or an arc not taking the colour of its most severe tag
  * a local address on the map, TDC's own processes mixed in with the sample's
  * a Deny switch or ISOLATED that can be pressed while a firewall profile is
    off (it would show "blocked" and block nothing)
  * the firewall log's numbers put on the process instead of the endpoint,
    byte figures in the summary (Part A has none)
  * an old response overwriting a newer one, LIVE polling a hidden tab
  * ISOLATED sending before the analyst confirmed it, its banner hiding what
    stays reachable or a way out a fetch left open
  * a blocked row that does not say the rule's protocol
  * a capture without its RIZIN, HEX and THREATSCAN buttons, or with anything
    that runs it
  * the tab button out of place, the tab without its (i) or its help entry
  * a decision toast that dismisses itself, falls to showToast's throttle,
    sends two answers for a double click, shows what was clicked instead of
    what was taken, claims a block that is not confirmed, a fetch at the
    deadline that the server will not do, or lets a decision vanish unanswered
"""

import json
import re
from html.parser import HTMLParser

from test_frontend import SOURCE, _function_source, _run_node, needs_node
from test_theme import INDEX_HTML, INFO_ATTR, STYLE_CSS, _const_source, _Elements, _read

FW_FUNCTION_NAME = re.compile(
    r"^(?:async )?function ((?:fw|renderFirewall|refreshFirewall|initFirewall|firewallTabShown|onFirewall|openLogsTab"
    r"|openFirewallTab|showDecisionToast)\w*)\(", re.M)
FW_FUNCTIONS = list(dict.fromkeys(FW_FUNCTION_NAME.findall(SOURCE)))
FW_CONSTS = list(dict.fromkeys(re.findall(r"^const (FW_\w+) = ", SOURCE, re.M)))
FW_LETS = re.findall(r"^let fw\w+ = [^\n]*?;(?=[ \t]*(?://[^\n]*)?$)", SOURCE, re.M)
WORLD_FUNCTIONS = ["_worldXY", "project", "_worldTone", "_worldArcPath", "_worldRingPath", "_worldText", "_worldTextWidth",
                   "_worldLabelBox", "worldMapSvg", "_chartCoord", "_chartEllipsis"]
OTHER_FUNCTIONS = WORLD_FUNCTIONS + ["escapeHtml", "jsArg", "cssToken", "formatAlertTime", "formatSize", "logsQuote", "sortTimeValue"]
ALL_FUNCTIONS = list(dict.fromkeys(FW_FUNCTIONS + OTHER_FUNCTIONS))

ELEMENT_IDS = ["tab-firewall", "firewall-tree", "firewall-view", "firewall-summary", "firewall-hints", "firewall-captures",
               "firewall-views", "firewall-range", "firewall-live", "firewall-ask-btn", "firewall-ask-menu",
               "firewall-isolated", "firewall-bands", "firewall-search", "firewall-count"]
# Elements of other tabs a firewall function writes to
OTHER_IDS = ["threatscan-filepath"]

LOADER = r"C:\Users\analyst\Desktop\loader.exe"
TDC_PYTHON = r"C:\tdc\webui\.venv\Scripts\python.exe"

PRELUDE = "\n".join(_const_source(name) for name in ["ALERT_SEVERITIES", "WORLD_BOX", "WORLD_CHAMBER_ID"] + FW_CONSTS) \
    + "\n" + "\n".join(FW_LETS) + r"""
const classes = () => {
    const set = new Set();
    return { add: c => set.add(c), remove: c => set.delete(c), contains: c => set.has(c),
        toggle: (c, on) => (on === undefined ? !set.has(c) : on) ? set.add(c) : set.delete(c) };
};
const els = {};
for (const id of %s) {
    els[id] = { focused: 0, focus() { this.focused++; }, id, innerHTML: '', textContent: '', value: '', hidden: false, disabled: false, title: '', style: {}, attrs: {},
        listeners: {}, classList: classes(),
        setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        removeAttribute(k) { delete this.attrs[k]; },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
        getBoundingClientRect: () => ({ width: 720 }), querySelectorAll: () => [] };
}
globalThis.document = { hidden: false, getElementById: id => els[id] || null, addEventListener() {} };
globalThis.state = { activeTab: 'firewall' };
const store = {};
globalThis.localStorage = { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } };
const intervals = [];
globalThis.setInterval = (fn, ms) => { intervals.push(ms); return intervals.length; };
globalThis.clearInterval = () => {};
const calls = [], toasts = [], confirms = [], opened = [];
globalThis.showToast = (type, title, detail) => toasts.push({ type, title, detail });
let confirmAnswer = false;
globalThis.tdcConfirm = async options => { confirms.push(options); return confirmAnswer; };
globalThis.switchTab = name => opened.push(['tab', name]);
globalThis.openInRizin = path => opened.push(['rizin', path]);
globalThis.hexOpenFile = path => opened.push(['hex', path]);
globalThis.threatscanResetDrop = () => opened.push(['reset']);
const reply = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
let answer = url => reply({});
globalThis.fetch = async (url, init) => {
    calls.push({ url, method: (init && init.method) || 'GET', body: init && init.body ? JSON.parse(init.body) : null });
    return answer(url, init);
};
const flow = (o = {}) => ({
    image: o.image ?? %s, pid: o.pid ?? 4242, protocol: o.protocol ?? 'tcp', src_ip: '10.0.2.15',
    dst_ip: o.dst ?? '203.0.113.7', dst_port: o.port ?? 443, count: o.count ?? 3,
    first_seen: '2026-11-16T10:00:00Z', last_seen: '2026-11-16T10:05:00Z', times: o.times ?? [1700000000, 1700000060],
    dst_hostname: o.hostname ?? null, fw_records: o.fw_records ?? 0, fw_allowed: 0, fw_dropped: o.fw_dropped ?? 0,
    endpoint_tags: o.fw_dropped ? ['dropped'] : [],
    geo: { scope: o.scope ?? 'public', cc: o.scope === 'local' ? null : 'NL', country: 'Netherlands',
           lat: o.scope === 'local' ? null : 52.1, lon: o.scope === 'local' ? null : 5.3,
           asn: o.asn ?? 64500, as_org: o.as_org ?? 'EXAMPLE-AS' },
    tags: o.tags ?? ['detonated'], severity: 'high', state: o.state ?? 'allowed', rule_id: o.rule_id ?? null,
    capture_ids: o.capture_ids ?? [], self: !!o.self,
});
const timers = [];
globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
globalThis.clearTimeout = id => { if (timers[id - 1]) timers[id - 1].fn = null; };
const runTimers = () => timers.splice(0).forEach(t => t.fn && t.fn());
// The tests' clock: days after every time of the fixtures (whose connections are then over), never the machine's
const CLOCK = Date.parse('2026-11-20T00:00:00Z');
Date.now = () => CLOCK;
""" % (json.dumps(ELEMENT_IDS + OTHER_IDS), json.dumps(LOADER))


def _run(script):
    return _run_node(ALL_FUNCTIONS, "(async () => {\n" + script + "\n})().catch(e => { console.error(e); process.exit(1); });",
                     PRELUDE)


def _flows_js(flows):
    return "[" + ", ".join("flow(%s)" % json.dumps(f) for f in flows) + "]"


def render_tree(flows, isolate=None, extra=""):
    return _run(r"""
        fwState.loaded = true;
        fwState.isolate = %s;
        fwState.rules = [];
        %s
        fwState.flows = %s;
        renderFirewallTree(fwState.flows);
        console.log(JSON.stringify(els['firewall-tree'].innerHTML));""" % (json.dumps(isolate), extra, _flows_js(flows)))


def render_map(flows):
    return _run(r"""
        fwState.loaded = true;
        fwState.flows = %s;
        renderFirewallMap(fwState.flows);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""" % _flows_js(flows))


def render_list(flows):
    return _run(r"""
        fwState.loaded = true;
        fwState.flows = %s;
        renderFirewallList(fwState.flows);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""" % _flows_js(flows))


SUMMARY = {"connections": 12, "events": 340, "blocked": 2, "pending": 1, "captures": 1,
           "top_processes": [{"image": LOADER, "flows": 4, "count": 200}],
           "top_endpoints": [{"dst_ip": "203.0.113.7", "dst_port": 443, "dst_hostname": "evil.example", "flows": 2, "count": 90}],
           "top_countries": [{"cc": "NL", "country": "Netherlands", "flows": 4, "count": 200}],
           "open_decisions": 1, "captures_total": 3, "rules_error": None, "isolated": False, "ask_mode": "detonation",
           "geo_available": True,
           "bytes_note": "Sysmon has no byte counts; the tab counts connections and firewall records."}


def render_summary(summary):
    return _run(r"""
        renderFirewallSummary(%s);
        console.log(JSON.stringify(els['firewall-summary'].innerHTML));""" % json.dumps(summary))


def capture(**o):
    base = {"id": "cap1", "sha256": "a3f1" * 16, "size": 73728, "url": "http://evil.example/stage2.bin",
            "dst_ip": "203.0.113.7", "dst_port": 80, "pid": 4242, "image": LOADER, "fetched_at": "2026-11-16T10:06:00Z",
            "origin": "fetch", "content_type": "application/octet-stream", "magic": "MZ", "executed": False,
            "path": r"C:\tdc\samples\a3\a3f1", "status": 200}
    base.update(o)
    return base


def render_captures(captures):
    return _run(r"""
        renderFirewallCaptures(%s);
        console.log(JSON.stringify(els['firewall-captures'].innerHTML));""" % json.dumps(captures))


def fw_defang(text):
    return _run("console.log(JSON.stringify(fwDefang(%s)));" % json.dumps(text))


def tone_of(tags):
    return _run("console.log(JSON.stringify(fwToneOf(%s)));" % json.dumps(tags))


HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(1)>\" onmouseover=\"x' autofocus data-pwned='"


def _parsed(markup):
    """The (tag, attribute names) of every element of the markup, as a browser would build them."""
    found = []

    class Parser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            found.append((tag, {name for name, _ in attrs}))

    Parser().feed(markup)
    return found


def _no_live_markup(markup, name=""):
    for tag, attrs in _parsed(markup):
        assert tag not in ("script", "img", "a", "b", "i", "iframe"), (name, tag)
        assert not any(a.startswith("on") or a in ("href", "src", "autofocus", "data-pwned") for a in attrs), (name, tag, attrs)


# --- Markup ---------------------------------------------------------------------

def _nav_tabs(html):
    nav = re.search(r'<nav class="sidebar-tabs">(.*?)</nav>', html, re.S).group(1)
    return re.findall(r'data-tab="([^"]+)"', nav)


def test_tab_button_sits_between_sysmon_and_logs():
    tabs = _nav_tabs(_read(INDEX_HTML))
    assert tabs[tabs.index("sysmon") + 1] == "firewall"
    assert tabs[tabs.index("firewall") + 1] == "logs"
    assert re.search(r'data-tab="firewall">FIREWALL</button>', _read(INDEX_HTML))


def test_the_tab_has_its_info_text_and_a_help_entry():
    html = _read(INDEX_HTML)
    tab = _Elements(html).by_id("tab-firewall")
    assert tab and "tab-content" in tab["attrs"]["class"].split()

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    header = find(tab, lambda e: "content-header" in e["attrs"].get("class", "").split())
    h2 = find(header[0], lambda e: e["tag"] == "h2" and "data-info" in e["attrs"]) if header else []
    assert len(header) == 1 and h2
    assert 0 < len(h2[0]["attrs"]["data-info"]) <= 300
    ids = {n["attrs"]["id"] for n in find(tab, lambda e: "id" in e["attrs"])}
    assert set(ELEMENT_IDS) - {"tab-firewall"} <= ids, (set(ELEMENT_IDS) - {"tab-firewall"}) - ids
    guide = html[html.index('id="help-usage"'):html.index('id="help-api"')]
    names = re.findall(r"<h4>([^<]+)</h4>", guide)
    assert names.index("FIREWALL") == names.index("Sysmon") + 1 and names.index("LOGS") == names.index("FIREWALL") + 1
    entry = guide[guide.index("<h4>FIREWALL</h4>"):guide.index("<h4>LOGS</h4>")]
    assert "tdc-unisolate.ps1" in entry and "MAP" in entry and "LIST" in entry and "ASN" in entry
    assert INFO_ATTR.search(_read(INDEX_HTML))


def test_every_firewall_function_and_constant_is_found():
    for name in ["initFirewall", "firewallTabShown", "refreshFirewall", "renderFirewallTree", "renderFirewallMap",
                 "renderFirewallList", "renderFirewallAsn", "renderFirewallSummary", "renderFirewallHints",
                 "renderFirewallCaptures", "fwDefang", "fwBlock", "fwUnblock", "fwToggleIsolated", "fwSetAsk", "fwSelect",
                 "onFirewallClick", "fwLiveTick", "openLogsTab", "openFirewallTab"]:
        assert name in FW_FUNCTIONS, name
    for name in ["FW_RANGES", "FW_DEFAULT_RANGE", "FW_ASK_MODES", "FW_TONES", "FW_VIEWS", "FW_LIVE_MS", "FW_HINTS"]:
        assert name in FW_CONSTS, name
    assert "const FW_VIEWS = ['map', 'list', 'asn', 'decisions'];" in SOURCE and "const FW_LIVE_MS = 5000;" in SOURCE
    assert re.search(r"^let fwState = \{", SOURCE, re.M) and re.search(r"^let fwSeq = 0;", SOURCE, re.M)
    assert re.search(r"tabName === 'firewall'\)\s*\{\s*firewallTabShown\(\)", _function_source("switchTab"))
    # One delegated handler, no inline handlers in the block
    block = SOURCE[SOURCE.index("// FIREWALL ("):SOURCE.index("// --- LitterBox Integration ---")]
    assert "onclick=" not in block and "onchange=" not in block and "oninput=" not in block


def test_no_byte_figures_in_the_tab_markup():
    tab = _read(INDEX_HTML)
    tab = tab[tab.index('id="tab-firewall"'):tab.index('id="tab-logs"')]
    assert not re.search(r"\b(MB|KB|bytes? (sent|received))\b", tab)


def test_the_map_tokens_live_in_root_and_the_animation_is_stilled():
    css = _read(STYLE_CSS)
    root = css[css.index(":root {"):css.index("}", css.index(":root {"))]
    for token in ("--fw-tone-critical", "--fw-tone-high", "--fw-tone-medium", "--fw-tone-low", "--fw-tone-info",
                  "--fw-land", "--fw-grat", "--fw-chamber"):
        assert token + ":" in root, token
    assert "/* --- FIREWALL tab (block FIREWALL of app.js) ---" in css


# --- Safety ---------------------------------------------------------------------

@needs_node
def test_malware_text_never_becomes_markup():
    out = render_tree([{"image": r"C:\x\<img src=x onerror=alert(1)>.exe", "hostname": "<script>a</script>evil.example",
                        "as_org": '"><b>ACME', "tags": ["detonated", '"><i>tag']}])
    # "onerror=" is there as escaped text; what must not be there is an element that carries it
    assert "<script>" not in out and "<img" not in out and "<b>" not in out and "<i>" not in out
    _no_live_markup(out)
    assert "&lt;script&gt;" in out and "&lt;img src=x onerror=alert(1)&gt;" in out


@needs_node
def test_every_view_keeps_hostile_text_as_text():
    r = _run(r"""
        const hostile = %s;
        fwState.loaded = true;
        fwState.flows = [flow({ image: 'C:\\' + hostile + '.exe', hostname: hostile + '.example', as_org: hostile,
                               tags: ['ioc', hostile] })];
        fwState.flows[0].geo.country = hostile;
        fwState.flows[0].geo.cc = hostile;
        const out = {};
        renderFirewallTree(fwState.flows); out.tree = els['firewall-tree'].innerHTML;
        renderFirewallMap(fwState.flows); out.map = els['firewall-view'].innerHTML;
        renderFirewallList(fwState.flows); out.list = els['firewall-view'].innerHTML;
        renderFirewallAsn(fwState.flows); out.asn = els['firewall-view'].innerHTML;
        fwSelected = 'f:' + fwFlowKey(fwState.flows[0]);
        renderFirewallHints(fwSelection()); out.hints = els['firewall-hints'].innerHTML;
        renderFirewallSummary({ connections: 1, events: 1, top_processes: [{ image: hostile, count: 1, flows: 1 }],
            top_endpoints: [{ dst_ip: hostile, dst_port: 1, dst_hostname: hostile, count: 1, flows: 1 }],
            top_countries: [{ cc: hostile, country: hostile, count: 1, flows: 1 }], bytes_note: hostile });
        out.summary = els['firewall-summary'].innerHTML;
        renderFirewallCaptures([{ id: hostile, sha256: hostile, size: 1, url: 'http://' + hostile, magic: hostile,
            fetched_at: hostile, path: 'C:\\' + hostile, image: hostile }]);
        out.captures = els['firewall-captures'].innerHTML;
        console.log(JSON.stringify(out));""" % json.dumps(HOSTILE))
    for name, markup in r.items():
        assert "<script" not in markup and "<img" not in markup, name
        _no_live_markup(markup, name)
        assert "<a " not in markup and "href=" not in markup, name
        # a class attribute holds only tokens
        for cls in re.findall(r'class="([^"]*)"', markup):
            assert re.fullmatch(r"[a-z0-9_ -]*", cls), (name, cls)


@needs_node
def test_urls_and_hosts_are_defanged_and_never_links():
    out = render_tree([{"hostname": "evil.example"}], extra=r"""
        fwState.pending = [{ id: 'dl-1', action: null, remaining: 20,
            finding: { pid: 4242, dst_ip: '203.0.113.7', dst_port: 443, url: 'http://evil.example/a.dll' } }];""")
    assert "hxxp://" in out and "evil[.]example" in out
    assert "http://" not in out and "evil.example" not in out
    assert "<a " not in out and "href=" not in out


@needs_node
def test_a_javascript_url_stays_text():
    assert "javascript:" not in fw_defang("javascript:alert(1)")
    assert "data:" not in fw_defang("data:text/html,<b>x</b>")
    assert fw_defang("https://a.b.example:8443/x.y?q=1.2") == "hxxps://a[.]b[.]example:8443/x.y?q=1.2"
    assert fw_defang("HTTP://Evil.Example/") == "HXXP://Evil[.]Example/"
    assert fw_defang("ftp://files.example/a") == "ftp[:]//files[.]example/a"
    assert fw_defang("cdn.evil.example") == "cdn[.]evil[.]example"
    assert fw_defang(None) == "" and fw_defang("") == ""
    assert "\u202e" not in fw_defang("evil\u202eexe.example")
    assert fw_defang("http:\\\\evil.example\\a") == "hxxp:\\\\evil[.]example\\a"
    assert fw_defang("http:evil.example") == "hxxp:evil[.]example"
    assert fw_defang("//evil.example/a") == "//evil[.]example/a"
    assert fw_defang("\\\\evil.example\\share") == "\\\\evil[.]example\\share"
    assert fw_defang("localhost:8080") == "localhost:8080"
    assert fw_defang("evil.example:8080/x.exe") == "evil[.]example:8080/x.exe"
    assert fw_defang("mailto:a@evil.example") == "mailto[:]a@evil[.]example"
    assert fw_defang("javascript:1/alert(1)") == "javascript[:]1/alert(1)"
    assert fw_defang("JavaScript:0") == "JavaScript[:]0" and fw_defang("data:1,x") == "data[:]1,x"
    assert fw_defang("localhost:8080/x") == "localhost:8080/x"


@needs_node
def test_a_long_host_is_cut_in_the_row_and_whole_in_its_title():
    out = render_tree([{"hostname": "a" * 2000 + ".example"}])
    shown = re.search(r'class="fw-ep-host">([^<]*)<', out).group(1)
    assert len(shown) <= 80 and shown.endswith("…")
    assert out.count("a" * 300) >= 1, "the full name is nowhere"
    assert "a" * 600 not in out, "a title without a limit"


# --- What the tree shows --------------------------------------------------------

@needs_node
def test_the_highest_tag_sets_the_tone():
    assert tone_of(["dropped", "ioc", "lolbin"]) == "critical"
    assert tone_of(["newborn"]) == "low"
    assert tone_of([]) == "info" and tone_of(["no-such-tag"]) == "info"
    assert tone_of(["tdc-anomaly", "rare-port"]) == "high"


@needs_node
def test_a_row_takes_the_tone_of_its_tags_and_the_endpoints_dropped_tag():
    out = render_tree([{"tags": ["beacon", "newborn"]}])
    assert "fw-proc fw-tone-critical" in out
    out = render_tree([{"tags": [], "fw_dropped": 2}], extra="fwOpen.set('p:' + %s + '|4242', true);" % json.dumps(LOADER))
    assert "fw-ep fw-tone-info" in out


@needs_node
def test_tdc_processes_sit_in_their_own_collapsed_group():
    out = render_tree([{"image": TDC_PYTHON, "self": True, "tags": ["tdc-anomaly"]}, {"image": LOADER}])
    tdc = out[out.index("fw-group-tdc"):]
    assert "fw-group-tdc" in out and 'data-fw-open="false"' in tdc[:200]
    assert "python.exe" not in tdc, "a collapsed group shows its processes"
    assert "fw-tone-high" in tdc[:600], "an anomaly inside the closed TDC group is not visible on its head"
    main = out[:out.index("fw-group-tdc")]
    assert "loader.exe" in main and "python.exe" not in main


@needs_node
def test_local_endpoints_have_their_own_group():
    out = render_tree([{"dst": "192.168.64.1", "scope": "local"}, {"dst": "203.0.113.7"}])
    assert "fw-group-local" in out
    assert out.index("fw-group-local") > out.index("203.0.113.7")


@needs_node
def test_detonated_processes_are_marked():
    out = render_tree([{"tags": ["detonated"]}])
    assert "is-detonated" in out and "DETONATED" in out


@needs_node
def test_deny_is_disabled_while_a_profile_is_off():
    out = render_tree([{}], {"profiles_off": ["Public"]})
    assert "disabled" in out and "Windows Firewall is off" in out
    on = render_tree([{}], {"profiles_off": []})
    assert "disabled" not in on


@needs_node
def test_tdcs_own_process_offers_no_block():
    out = render_tree([{"image": TDC_PYTHON, "self": True}], extra="fwOpen.set('tdc', true); fwOpen.set('p:' + %s + '|4242', true);"
                      % json.dumps(TDC_PYTHON))
    blocks = re.findall(r'<button[^>]*data-fw-block="(?:process|endpoint)"[^>]*>', out)
    assert len(blocks) == 2 and all(" disabled" in b and "TDC&#39;s own processes" in b for b in blocks), blocks


@needs_node
def test_a_blocked_row_names_the_protocol_of_its_rule():
    rule = {"rule_id": "TDC-FW-0123456789ab", "name": "TDC-FW-0123456789ab", "kind": "block", "action": "Block",
            "enabled": True, "image": LOADER, "ip": "203.0.113.7", "port": 443, "protocol": "tcp", "blocking": True}
    out = render_tree([{"protocol": "udp", "state": "blocked", "rule_id": rule["rule_id"]}],
                      extra="fwState.rules = %s;" % json.dumps([rule]))
    assert 'data-fw-unblock="TDC-FW-0123456789ab"' in out
    assert "TCP" in out and "is-mismatch" in out


@needs_node
def test_unreadable_rules_make_the_state_unknown():
    out = render_tree([{"state": "allowed"}], extra="fwState.rulesError = 'Access denied';")
    assert "is-unknown" in out and "ALLOW" not in out


@needs_node
def test_a_process_with_hundreds_of_endpoints_shows_a_page_of_them():
    out = _run(r"""
        fwState.loaded = true;
        fwState.flows = Array.from({ length: 400 }, (_, i) => flow({ dst: `198.51.${i >> 8}.${i & 255}`, tags: ['ioc'] }));
        renderFirewallTree(fwState.flows);
        const first = els['firewall-tree'].innerHTML;
        fwMore.add(%s + '|4242');
        renderFirewallTree(fwState.flows);
        console.log(JSON.stringify([first, els['firewall-tree'].innerHTML]));""" % json.dumps(LOADER))
    assert out[0].count('class="fw-ep ') == 50 and "data-fw-more" in out[0]
    assert out[1].count('class="fw-ep ') == 400


@needs_node
def test_a_long_tag_list_is_cut_to_a_few_chips():
    out = render_tree([{"tags": ["ioc", "beacon", "sigma", "detonated", "direct-ip", "download", "lolbin"]}])
    # detonated is the badge of its own; of the other six, three chips and +3
    assert "fw-tag-more" in out and "+3" in out and "DETONATED" in out


# --- Map, LIST, ASN ---------------------------------------------------------------

@needs_node
def test_local_endpoints_are_not_on_the_map():
    # the local address has a position: only its scope keeps it off the map
    out = _run(r"""
        fwState.loaded = true;
        const local = flow({ dst: '192.168.64.1', scope: 'local' });
        local.geo.lat = 52.1;
        local.geo.lon = 5.3;
        renderFirewallMap([local, flow({ dst: '1.2.3.4' })]);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""")
    ids = set(re.findall(r'data-fw-id="([^"]*)"', out))
    assert ids == {"@chamber", "a:1.2.3.4"}, ids


@needs_node
def test_the_map_says_when_it_has_no_geo_data():
    out = _run(r"""
        fwState.loaded = true;
        fwState.summary = { geo_available: false };
        renderFirewallMap([]);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""")
    assert "make geoip" in out


@needs_node
def test_the_map_draws_a_limited_number_of_destinations():
    out = _run(r"""
        fwState.loaded = true;
        const flows = Array.from({ length: 5000 }, (_, i) => flow({ dst: `198.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}` }));
        renderFirewallMap(flows);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""")
    assert out.count('class="fw-point ') <= 301 and "of 5,000" in out


@needs_node
def test_firewall_records_are_labelled_as_the_endpoint_s():
    out = render_list([{"fw_dropped": 3, "fw_records": 3}])
    assert "FW (endpoint)" in out
    assert "data-sortable" in out and 'data-sort-id="firewall-list"' in out


@needs_node
def test_asn_groups_addresses_of_one_organisation():
    out = _run(r"""
        fwState.loaded = true;
        const flows = ['198.51.100.1', '198.51.100.2', '203.0.113.9'].map((ip, i) => flow({ dst: ip, as_org: i < 2 ? 'BULLET-HOST' : 'OTHER', asn: i < 2 ? 1 : 2 }));
        flows.push(flow({ dst: '192.168.1.1', scope: 'local' }));
        renderFirewallAsn(flows);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""")
    row = out[out.index("BULLET-HOST"):]
    row = row[:row.index("</tr>")]
    assert 'data-fw-id="a:198.51.100.1"' in row and 'data-fw-id="a:198.51.100.2"' in row
    assert "192.168.1.1" not in out


# --- Summary, hints, captures --------------------------------------------------

@needs_node
def test_no_byte_columns_in_part_a():
    out = render_summary(SUMMARY)
    assert "MB" not in out and "sent" not in out.lower()
    assert "no byte counts" in out.lower()
    assert "340" in out and "loader.exe" in out and "evil[.]example" in out


@needs_node
def test_the_hints_are_ready_queries_for_the_selection():
    r = _run(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        fwState.loaded = true;
        fwState.flows = [flow({ image: 'C:\\x\\a"b.exe' })];
        fwRange = '4h';
        fwSelect('f:' + fwFlowKey(fwState.flows[0]));
        const html = els['firewall-hints'].innerHTML;
        const n = (html.match(/data-fw-hint=/g) || []).length;
        onFirewallClick({ target: { closest: sel => sel === '[data-fw-hint]' ? { getAttribute: () => '0', disabled: false } : null } });
        fwSelect('');
        const none = (els['firewall-hints'].innerHTML.match(/data-fw-hint=/g) || []).length;
        console.log(JSON.stringify({ n, none, calls: calls2, html }));""")
    assert 4 <= r["n"] <= 6 and r["none"] >= 3
    assert r["calls"][0][0] == 'dst_ip="203.0.113.7" | top image'
    # the endpoint's own connections, not the tab's range (Task 9)
    assert r["calls"][0][1:3] == ["2026-11-16T09:55:00Z", "2026-11-16T10:10:00Z"]
    assert 'image=&quot;C:\\x\\a\\&quot;b.exe&quot;' in r["html"]


@needs_node
def test_a_capture_opens_in_rizin_hex_and_threatscan():
    out = render_captures([capture(sha256="a3f1", path=r"C:\tdc\samples\a3\a3f1")])
    for label in ("RIZIN", "HEX", "THREATSCAN"):
        assert label in out
    assert "data-fw-open" in out and "executed" not in out.lower()
    assert "hxxp://evil[.]example/stage2.bin" in out and "MZ" in out and "72.0 KB" in out


@needs_node
def test_the_capture_buttons_open_its_path():
    r = _run(r"""
        fwState.captures = [{ id: 'c1', path: 'C:\\tdc\\samples\\a3\\a3f1', url: 'http://x.example/a' }];
        const button = kind => ({ closest: sel => sel === 'button[data-fw-open]'
            ? { getAttribute: k => (k === 'data-fw-open' ? kind : 'c1'), disabled: false } : null });
        for (const kind of ['rizin', 'hex', 'threatscan']) onFirewallClick({ target: button(kind) });
        console.log(JSON.stringify({ opened, value: els['threatscan-filepath'].value }));""")
    path = r"C:\tdc\samples\a3\a3f1"
    assert ["rizin", path] in r["opened"] and ["hex", path] in r["opened"] and ["tab", "threatscan"] in r["opened"]
    assert r["value"] == path and r["opened"].index(["reset"]) < r["opened"].index(["tab", "threatscan"])


# --- Fetching, LIVE -------------------------------------------------------------

@needs_node
def test_a_stale_response_does_not_overwrite_a_newer_one():
    r = _run(r"""
        const gates = [];
        answer = url => new Promise(resolve => gates.push({ url, resolve }));
        const first = refreshFirewall({ slow: false });
        const second = refreshFirewall({ slow: false });
        await Promise.resolve();
        const conn = gates.filter(g => g.url.startsWith('/api/firewall/connections'));
        const pend = gates.filter(g => g.url.startsWith('/api/firewall/pending'));
        conn[1].resolve(reply({ connections: [flow({ dst: '198.51.100.2' })], count: 1 }));
        pend[1].resolve(reply({ pending: [], history: [] }));
        gates.filter(g => g.url === '/api/firewall/isolate').forEach(g => g.resolve(reply({ isolated: false, profiles_off: [] })));
        await second;
        conn[0].resolve(reply({ connections: [flow({ dst: '198.51.100.1' })], count: 1 }));
        pend[0].resolve(reply({ pending: [], history: [] }));
        await first;
        console.log(JSON.stringify(fwState.flows.map(f => f.dst_ip)));""")
    assert r == ["198.51.100.2"]


@needs_node
def test_the_window_and_the_size_are_asked_for():
    r = _run(r"""
        answer = url => reply(url.startsWith('/api/firewall/connections') ? { connections: [], count: 0 } : {});
        fwRange = '15m';
        await refreshFirewall({ slow: true });
        const urls = calls.map(c => c.url);
        fwRange = 'All';
        calls.length = 0;
        await refreshFirewall({ slow: false });
        console.log(JSON.stringify({ urls, all: calls.map(c => c.url) }));""")
    conn = next(u for u in r["urls"] if u.startswith("/api/firewall/connections"))
    assert "since=" in conn and "max=" in conn
    assert any(u.startswith("/api/firewall/summary?since=") for u in r["urls"])
    assert {"/api/firewall/isolate", "/api/firewall/captures", "/api/firewall/rules"} <= set(r["urls"])
    light = sorted(u.split("?")[0] for u in r["all"])
    assert light == ["/api/firewall/connections", "/api/firewall/isolate", "/api/firewall/pending"], \
        "a light tick asks for more than the poll paths and ISOLATED's state, or not for ISOLATED's state"
    assert all("since=" not in u for u in r["all"])


@needs_node
def test_live_pauses_in_a_hidden_tab():
    def fw_live_tick_when(hidden, activeTab):
        return _run(r"""
            answer = () => reply({ connections: [], pending: [] });
            fwState.live = true;
            document.hidden = %s;
            state.activeTab = %s;
            const ran = fwLiveTick();
            console.log(JSON.stringify(ran ? 'ran' : 'skipped'));""" % (json.dumps(hidden), json.dumps(activeTab)))
    assert fw_live_tick_when(hidden=True, activeTab="firewall") == "skipped"
    assert fw_live_tick_when(hidden=False, activeTab="logs") == "skipped"
    assert fw_live_tick_when(hidden=False, activeTab="firewall") == "ran"


# --- Enforcement ----------------------------------------------------------------

def fw_toggle_isolated_clicks(confirm=False, isolate=None):
    return _run(r"""
        confirmAnswer = %s;
        fwState.isolate = %s;
        answer = url => reply(url === '/api/firewall/isolate' ? { isolated: true, state: { isolated: true, profiles_off: [] } } : {});
        await fwToggleIsolated();
        console.log(JSON.stringify({ confirm: confirms.length, post: calls.filter(c => c.method === 'POST').length,
            body: (calls.find(c => c.method === 'POST') || {}).body, options: confirms[0] || null }));"""
                % (json.dumps(confirm), json.dumps(isolate if isolate is not None else {"isolated": False, "profiles_off": []})))


@needs_node
def test_isolated_asks_before_it_cuts():
    calls = fw_toggle_isolated_clicks()
    assert calls["confirm"] == 1 and calls["post"] == 0      # declined: nothing sent
    done = fw_toggle_isolated_clicks(confirm=True)
    assert done["post"] == 1 and done["body"] == {"on": True}
    options = done["options"]
    assert options["danger"] is True
    assert "tdc-unisolate.ps1" in options["message"] and "loopback" in options["message"].lower()


@needs_node
def test_isolated_cannot_be_switched_on_while_a_profile_is_off():
    r = fw_toggle_isolated_clicks(confirm=True, isolate={"isolated": False, "profiles_off": ["Domain"]})
    assert r["post"] == 0 and r["confirm"] == 0


@needs_node
def test_the_isolated_banner_shows_the_residual_and_an_open_way_out():
    r = _run(r"""
        fwState.isolated = true;
        fwState.isolate = { isolated: true, profiles_off: [], isolated_since: '2026-11-16T10:00:00Z',
            residual: 'ISOLATED blocks every way out but loopback. <b>x</b>', fetches_in_flight: 1,
            fetch_paths_open: [{ rule_id: 'TDC-FW-ISO-fetch-0123456789ab', problem: 'Access <i>denied</i>', since: 1 }] };
        renderFirewallBands();
        renderFirewallHead();
        console.log(JSON.stringify({ bands: els['firewall-bands'].innerHTML, pressed: els['firewall-isolated'].attrs['aria-pressed'] }));""")
    assert "ISOLATED blocks every way out but loopback" in r["bands"] and "&lt;b&gt;" in r["bands"]
    assert "TDC-FW-ISO-fetch-0123456789ab" in r["bands"] and "fw-band-hole" in r["bands"]
    assert "&lt;i&gt;denied" in r["bands"] and "1 fetch" in r["bands"]
    assert r["pressed"] == "true"


@needs_node
def test_a_firewall_that_is_off_shows_a_red_band_and_disables_isolated():
    r = _run(r"""
        fwState.isolate = { isolated: false, profiles_off: ['Public', 'Private'] };
        renderFirewallBands();
        renderFirewallHead();
        const b = els['firewall-isolated'];
        console.log(JSON.stringify({ bands: els['firewall-bands'].innerHTML, disabled: b.disabled, title: b.title }));""")
    assert "fw-band-off" in r["bands"] and "Windows Firewall is off" in r["bands"] and "Public, Private" in r["bands"]
    assert r["disabled"] is True and "Windows Firewall is off" in r["title"]


@needs_node
def test_ask_off_and_unreadable_rules_are_said_in_the_head():
    r = _run(r"""
        fwState.askMode = 'off';
        fwState.rulesError = 'PowerShell <b>failed</b>';
        renderFirewallBands();
        renderFirewallHead();
        console.log(JSON.stringify({ bands: els['firewall-bands'].innerHTML, ask: els['firewall-ask-btn'].textContent }));""")
    assert "ASK is off" in r["bands"] and "&lt;b&gt;failed" in r["bands"]
    assert r["ask"].startswith("ASK: Off")


@needs_node
def test_block_and_unblock_send_what_the_routes_take():
    r = _run(r"""
        fwState.isolate = { isolated: false, profiles_off: [] };
        answer = (url, init) => reply(url === '/api/firewall/block' ? { rule_id: 'TDC-FW-0123456789ab', verified: true }
            : url === '/api/firewall/unblock' ? { removed: ['TDC-FW-0123456789ab'] } : { connections: [], pending: [] });
        const f = flow();
        await fwBlock('endpoint', f);
        await fwBlock('process', f);
        confirmAnswer = false;
        await fwBlock('endpoint_all', f);
        confirmAnswer = true;
        await fwBlock('endpoint_all', f);
        await fwUnblock('TDC-FW-0123456789ab');
        await fwSetAsk('off');
        await fwSetAsk('bogus');
        console.log(JSON.stringify(calls.filter(c => c.method === 'POST').map(c => [c.url, c.body])));""")
    assert r == [
        ["/api/firewall/block", {"scope": "endpoint", "image": LOADER, "ip": "203.0.113.7"}],
        ["/api/firewall/block", {"scope": "process", "image": LOADER}],
        ["/api/firewall/block", {"scope": "endpoint_all", "ip": "203.0.113.7"}],
        ["/api/firewall/unblock", {"rule_id": "TDC-FW-0123456789ab"}],
        ["/api/firewall/ask", {"mode": "off"}],
    ]


@needs_node
def test_a_refused_block_is_said_and_no_block_goes_out_while_the_firewall_is_off():
    r = _run(r"""
        fwState.isolate = { isolated: false, profiles_off: [] };
        answer = url => url === '/api/firewall/block' ? reply({ error: 'the rule could not be <b>verified</b>' }, 409) : reply({});
        const ok = await fwBlock('endpoint', flow());
        fwState.isolate = { isolated: false, profiles_off: ['Public'] };
        calls.length = 0;
        const off = await fwBlock('endpoint', flow());
        console.log(JSON.stringify({ ok, off, toasts, posts: calls.filter(c => c.method === 'POST').length }));""")
    assert r["ok"] is False and r["off"] is False and r["posts"] == 0
    assert any(t["type"] == "error" and "verified" in (t["detail"] or "") for t in r["toasts"])


@needs_node
def test_the_perspective_switches_exist():
    r = _run(r"""
        console.log(JSON.stringify([typeof openLogsTab, typeof openFirewallTab]));""")
    assert r == ["function", "function"]


# --- Fix round 1: never claim what is not known ------------------------------------

PROC_RULE = {"rule_id": "TDC-FW-aaaaaaaaaaaa", "name": "TDC-FW-aaaaaaaaaaaa", "kind": "block", "action": "Block",
             "enabled": True, "image": LOADER, "ip": None, "port": None, "protocol": None, "blocking": True}


def _process_switch(out):
    row = re.search(r'<div class="fw-proc-row">(.*?)</div>', out).group(1)
    return row[row.rindex("fw-num"):]


@needs_node
def test_a_process_switch_is_unknown_until_the_rules_are_read():
    blocked = {"state": "blocked", "rule_id": PROC_RULE["rule_id"]}
    loading = render_tree([blocked], extra="fwState.rules = null;")
    failed = render_tree([blocked], extra="fwState.rulesListError = 'HTTP <b>500</b>';")
    known = render_tree([blocked], extra="fwState.rules = %s;" % json.dumps([PROC_RULE]))
    for out in (loading, failed):
        switch = _process_switch(out)
        assert "ALLOW" not in switch and "is-unknown" in switch, switch
    assert "still being read" in _process_switch(loading)
    assert "could not be loaded" in _process_switch(failed) and "&lt;b&gt;500" in _process_switch(failed)
    assert 'data-fw-unblock="TDC-FW-aaaaaaaaaaaa"' in _process_switch(known)


@needs_node
def test_a_rule_list_that_fails_is_said_in_a_band():
    r = _run(r"""
        fwState.rulesListError = 'HTTP 500';
        renderFirewallBands();
        console.log(JSON.stringify(els['firewall-bands'].innerHTML));""")
    assert "could not be loaded" in r and "HTTP 500" in r


@needs_node
def test_blocked_without_a_rule_is_never_allow():
    out = render_tree([{"state": "blocked", "rule_id": None}])
    ep = out[out.index('class="fw-ep '):]
    assert "DENY" in ep and "ALLOW" not in ep[:ep.index("</div></div>")]
    cell = render_list([{"state": "blocked", "rule_id": None}])
    assert "DENY ?" in cell and ">ALLOW<" not in cell


@needs_node
def test_the_blocked_tile_is_unknown_while_the_rules_are_unreadable():
    out = _run(r"""
        fwState.rulesError = 'Access denied';
        renderFirewallSummary(%s);
        console.log(JSON.stringify(els['firewall-summary'].innerHTML));""" % json.dumps(dict(SUMMARY, blocked=0)))
    tile = out[out.index("BLOCKED"):]
    tile = tile[:tile.index("</div>")]
    assert ">?<" in tile and ">0<" not in tile and "rules unreadable" in tile


@needs_node
def test_a_route_that_fails_says_so_where_its_data_is():
    r = _run(r"""
        answer = url => url.startsWith('/api/firewall/connections') ? reply({ connections: [], count: 0 })
            : url.startsWith('/api/firewall/pending') ? reply({ pending: [] }) : reply({ error: 'boom <b>x</b>' }, 500);
        await refreshFirewall();
        console.log(JSON.stringify({ summary: els['firewall-summary'].innerHTML, captures: els['firewall-captures'].innerHTML,
            bands: els['firewall-bands'].innerHTML }));""")
    assert "summary could not be loaded" in r["summary"] and "Loading" not in r["summary"]
    assert "could not be loaded" in r["captures"] and "None yet" not in r["captures"] and "&lt;b&gt;x" in r["captures"]
    assert "state could not be read" in r["bands"] and "unknown" in r["bands"]


@needs_node
def test_before_anything_came_the_captures_are_not_none():
    out = render_captures(None)
    assert "None yet" not in out and "Loading" in out


@needs_node
def test_an_ipv6_endpoint_without_a_name_keeps_its_whole_suffix():
    out = render_tree([{"dst": "2001:db8::1", "port": 443}])
    assert re.search(r'class="fw-ep-addr">:443/TCP<', out), out[:2000]
    assert ">1]:443" not in out and "[2001:db8::1]:443/TCP" in out


@needs_node
def test_list_marks_a_rule_for_another_protocol():
    rule = dict(PROC_RULE, rule_id="TDC-FW-bbbbbbbbbbbb", ip="203.0.113.7", protocol="tcp")
    out = _run(r"""
        fwState.loaded = true;
        fwState.rules = %s;
        renderFirewallList([flow({ protocol: 'udp', state: 'blocked', rule_id: 'TDC-FW-bbbbbbbbbbbb' })]);
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""" % json.dumps([rule]))
    cell = re.search(r'<td class="fw-cell-state[^"]*"[^>]*>[^<]*</td>', out).group(0)
    assert "is-mismatch" in cell and "TCP" in cell and "UDP" in cell and "may still get through" in cell


@needs_node
def test_escape_closes_the_ask_menu():
    r = _run(r"""
        fwToggleAskMenu(true);
        const open = els['firewall-ask-menu'].hidden;
        const other = onFirewallKeydown({ key: 'Enter' });
        const closed = onFirewallKeydown({ key: 'Escape' });
        console.log(JSON.stringify({ open, other, closed, hidden: els['firewall-ask-menu'].hidden,
            focus: els['firewall-ask-btn'].focused, expanded: els['firewall-ask-btn'].attrs['aria-expanded'] }));""")
    assert r == {"open": False, "other": False, "closed": True, "hidden": True, "focus": 1, "expanded": "false"}


@needs_node
def test_the_filter_waits_for_the_typing_to_pause():
    r = _run(r"""
        fwState.loaded = true;
        fwState.rules = [];
        fwState.flows = [flow(), flow({ image: 'C:\\x\\other.exe', pid: 7 })];
        let draws = 0;
        const real = renderFirewallTree;
        globalThis.renderFirewallTree = f => { draws++; real(f); };
        for (const text of ['o', 'ot', 'oth', 'othe']) fwFilterSoon(text);
        const before = draws;
        runTimers();
        console.log(JSON.stringify({ before, after: draws, filter: fwFilter, ms: timers.length,
            tree: els['firewall-tree'].innerHTML.includes('loader.exe') }));""")
    assert r["before"] == 0 and r["after"] == 1 and r["filter"] == "othe" and r["tree"] is False


# --- Fix round 1: the perspective switch, KILL, TURN THE FIREWALL ON ------------------

@needs_node
def test_in_logs_is_one_click_away_on_the_selected_row_point_and_hints():
    r = _run(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        fwState.loaded = true;
        fwState.rules = [];
        fwState.flows = [flow()];
        fwRange = '24h';
        const key = fwFlowKey(fwState.flows[0]);
        fwSelect('a:203.0.113.7');
        const map = els['firewall-view'].innerHTML, hints = els['firewall-hints'].innerHTML;
        fwSelect('f:' + key);
        const tree = els['firewall-tree'].innerHTML;
        const click = sel => ({ target: { closest: s => (s === sel ? { getAttribute: () => null, disabled: false } : null) } });
        onFirewallClick(click('[data-fw-logs]'));
        fwSelect('p:' + %s + '|4242');
        const proc = els['firewall-tree'].innerHTML;
        onFirewallClick(click('[data-fw-logs]'));
        console.log(JSON.stringify({ map, hints, tree, proc, calls: calls2 }));""" % json.dumps(LOADER))
    assert re.search(r'class="fw-map-pin[^"]*"[^>]*>.*data-fw-logs', r["map"])
    assert "data-fw-logs" in r["hints"] and "in LOGS ▸" in r["hints"]
    assert r["tree"].count("data-fw-logs") == 1 and r["proc"].count("data-fw-logs") == 1
    # one run of the process: its PID with its image, as its window is that run's
    assert r["calls"][0][:3] == ['image="%s" pid="4242" dst_ip="203.0.113.7"' % LOADER, "2026-11-16T09:55:00Z", "2026-11-16T10:10:00Z"]
    assert r["calls"][0][3]["tab"] == "firewall"
    assert r["calls"][1][0] == 'image="%s" pid="4242"' % LOADER


@needs_node
def test_kill_sits_on_the_selected_process_and_asks_first():
    r = _run(r"""
        fwState.loaded = true;
        fwState.rules = [];
        fwState.flows = [flow(), flow({ image: %s, pid: 3300, self: true })];
        fwOpen.set('tdc', true);
        fwSelect('p:' + %s + '|4242');
        const row = els['firewall-tree'].innerHTML;
        fwSelect('p:' + %s + '|3300');
        const own = els['firewall-tree'].innerHTML;
        answer = url => reply(url === '/api/firewall/kill' ? { pid: 4242, killed: true } : { connections: [], pending: [] });
        confirmAnswer = false;
        await fwKill(fwState.flows[0]);
        const declined = calls.filter(c => c.method === 'POST').length;
        confirmAnswer = true;
        await fwKill(fwState.flows[0]);
        await fwKill(fwState.flows[1]);
        console.log(JSON.stringify({ row, own, declined, posts: calls.filter(c => c.method === 'POST').map(c => [c.url, c.body]),
            confirm: confirms[0] }));""" % (json.dumps(TDC_PYTHON), json.dumps(LOADER), json.dumps(TDC_PYTHON)))
    assert 'data-fw-kill="%s|4242"' % LOADER in r["row"]
    kill_own = re.search(r'<button[^>]*data-fw-kill="[^"]*3300"[^>]*>', r["own"]).group(0)
    assert " disabled" in kill_own
    assert r["declined"] == 0 and r["posts"] == [["/api/firewall/kill", {"pid": 4242}]]
    assert r["confirm"]["danger"] is True and "telemetry stops" in r["confirm"]["message"]


@needs_node
def test_the_red_band_offers_to_turn_the_firewall_on_and_asks_first():
    r = _run(r"""
        fwState.isolate = { isolated: false, profiles_off: ['Public'] };
        renderFirewallBands();
        const band = els['firewall-bands'].innerHTML;
        answer = url => reply(url === '/api/firewall/enable' ? { enabled: true, profiles_off: [], state: { isolated: false, profiles_off: [] } }
            : url === '/api/firewall/isolate' ? { isolated: false, profiles_off: [] } : { connections: [], pending: [] });
        confirmAnswer = false;
        await fwEnableFirewall();
        const declined = calls.filter(c => c.method === 'POST').length;
        confirmAnswer = true;
        const ok = await fwEnableFirewall();
        renderFirewallBands();
        console.log(JSON.stringify({ band, declined, ok, posts: calls.filter(c => c.method === 'POST').map(c => [c.url, c.body]),
            message: confirms[0].message, after: els['firewall-bands'].innerHTML }));""")
    assert 'data-fw-enable' in r["band"] and "TURN THE FIREWALL ON" in r["band"]
    assert r["declined"] == 0 and r["ok"] is True and r["posts"] == [["/api/firewall/enable", {}]]
    assert "what the malware sees" in r["message"] and "your call" in r["message"]
    assert "fw-band-off" not in r["after"]


@needs_node
def test_the_isolate_state_is_never_asked_twice_at_once():
    r = _run(r"""
        const gates = [];
        answer = url => new Promise(resolve => gates.push({ url, resolve }));
        refreshFirewall({ slow: false });
        refreshFirewall({ slow: false });
        await Promise.resolve();
        console.log(JSON.stringify(gates.filter(g => g.url === '/api/firewall/isolate').length));
        process.exit(0);""")
    assert r == 1


@needs_node
def test_the_bands_are_not_drawn_again_when_nothing_changed():
    r = _run(r"""
        fwState.isolate = { isolated: false, profiles_off: ['Public'] };
        renderFirewallBands();
        const host = els['firewall-bands'];
        let writes = 0, html = host.innerHTML;
        Object.defineProperty(host, 'innerHTML', { get: () => html, set: v => { writes++; html = v; } });
        renderFirewallBands();
        renderFirewallBands();
        fwState.isolate = { isolated: false, profiles_off: [] };
        renderFirewallBands();
        console.log(JSON.stringify(writes));""")
    assert r == 1



# --- Fix round 3 ---------------------------------------------------------------------

@needs_node
def test_a_get_of_the_state_older_than_an_isolated_post_does_not_overwrite_it():
    r = _run(r"""
        const gates = [];
        answer = (url, init) => (init && init.method === 'POST') ? reply({ isolated: true, state: { isolated: true, profiles_off: [] } })
            : new Promise(resolve => gates.push({ url, resolve }));
        fwState.isolate = { isolated: false, profiles_off: [] };
        refreshFirewall({ slow: false });               // a GET of the state and of the connections goes out
        confirmAnswer = true;
        const toggled = fwToggleIsolated();
        await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
        // the old answers arrive after the POST: both say "not isolated"
        gates.forEach(g => g.resolve(reply(g.url.startsWith('/api/firewall/connections') ? { connections: [], isolated: false }
            : g.url === '/api/firewall/isolate' ? { isolated: false, profiles_off: [] } : { pending: [] })));
        for (let i = 0; i < 20; i++) await Promise.resolve();
        console.log(JSON.stringify({ isolated: fwState.isolated, state: fwState.isolate.isolated }));
        process.exit(0);""")
    assert r == {"isolated": True, "state": True}


@needs_node
def test_a_blocked_row_says_no_list_could_be_read():
    out = render_tree([{"state": "blocked", "rule_id": "TDC-FW-cccccccccccc"}], extra="fwState.rulesListError = 'HTTP 500';")
    assert "no list of rules could be read" in out and "not in the list read" not in out


# --- The decision toast (Task 8) --------------------------------------------------------

# A stack host that holds real child elements, and a clock the tests set
DECISIONS = r"""
const esc = v => String(v).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const mk = tag => ({
    tagName: tag.toUpperCase(), id: '', className: '', innerHTML: '', textContent: '', attrs: {}, children: [], parentNode: null,
    listeners: {}, hidden: false,
    setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
    appendChild(c) { if (c.parentNode) c.remove(); c.parentNode = this; this.children.push(c); return c; },
    replaceChildren(...cs) { this.children.forEach(c => { c.parentNode = null; }); this.children = []; cs.forEach(c => this.appendChild(c)); },
    replaceWith(n) { const p = this.parentNode; if (!p) return; if (n.parentNode) n.remove(); p.children[p.children.indexOf(this)] = n; n.parentNode = p; this.parentNode = null; },
    remove() { const p = this.parentNode; if (p) { p.children.splice(p.children.indexOf(this), 1); this.parentNode = null; } },
    querySelector() { return null; },
    get outerHTML() { return `<${tag} class="${esc(this.className)}"${Object.entries(this.attrs).map(([k, v]) => ` ${k}="${esc(v)}"`).join('')}>${this.innerHTML}</${tag}>`; },
});
document.createElement = mk;
els['decision-toasts'] = mk('div');
const host = els['decision-toasts'];
const stack = () => host.children.map(c => c.outerHTML).join('');
let now = 1800000000000;
Date.now = () => now;
const pitem = (o = {}) => ({
    id: o.id ?? 'dl-000000000001',
    finding: { id: o.id ?? 'dl-000000000001', pid: o.pid ?? 4242, image: o.image ?? %s, url: o.url ?? 'http://evil.example/stage2.dll',
               dst_ip: o.dst ?? '203.0.113.7', dst_port: o.port ?? 80, source: o.source ?? 'powershell', in_detonation: true },
    deadline: '2026-11-16T10:00:30.000Z', created_at: '2026-11-16T10:00:00.000Z',
    resolved_at: o.resolved_at ?? null, action: o.action ?? null,
    result: o.result === undefined ? { block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } : o.result,
    remaining: o.remaining ?? 24,
});
const answerOf = (o = {}) => ({ pending: o.pending ?? [], history: o.history ?? [], ask_mode: o.ask_mode ?? 'detonation',
    decide_seconds: 30, server_time: o.server_time ?? '2026-11-16T10:00:06.000Z' });
const target = (selectors, attrs = {}) => ({ closest: s => (selectors[s] ? { disabled: false, getAttribute: k => (k in (selectors[s]) ? selectors[s][k] : null) } : null) });
""" % json.dumps(LOADER)


def _decisions(script):
    return _run(DECISIONS + script)


def decision_toast(o):
    item = {"remaining": o["deadline_in"]} if "deadline_in" in o else {}
    item.update({k: v for k, v in o.items() if k != "deadline_in"})
    return _decisions(r"""
        const el = showDecisionToast(pitem(%s));
        console.log(JSON.stringify(el ? el.outerHTML : null));""" % json.dumps(item))


def decision_toast_timers():
    return _decisions(r"""
        fwApplyPending(answerOf({ pending: [pitem()] }));
        const shown = host.children.length;
        // An hour later, with no answer from the server: the clock ran out, the toast is still there
        for (let i = 0; i < 3600; i++) { now += 1000; fwDecisionTick(); }
        if (shown !== 1 || host.children.length !== 1) throw new Error('the toast went: ' + shown + ' -> ' + host.children.length);
        console.log(JSON.stringify(timers.map(t => t.ms)));""")


def render_pending(items):
    return _decisions(r"""
        fwApplyPending(answerOf({ pending: [%s] }));
        console.log(JSON.stringify(stack()));""" % ", ".join("pitem(%s)" % json.dumps(i) for i in items))


def p(n):
    return {"id": "dl-%012d" % n, "remaining": 20 + n}


def decision_toasts_for_same_title(n):
    return _decisions(r"""
        for (let i = 1; i <= %d; i++) showDecisionToast(pitem({ id: 'dl-same-' + i }));
        console.log(JSON.stringify(host.children.filter(c => /\btoast-decision\b/.test(c.className)).length));""" % n)


def decide_clicks_sent_after_double_click():
    r = _decisions(r"""
        let release;
        answer = (url, init) => (init && init.method === 'POST') ? new Promise(resolve => { release = resolve; }) : reply({});
        fwApplyPending(answerOf({ pending: [pitem()] }));
        const click = () => onFirewallDecisionClick({ target: target({ '[data-fw-decide]': { 'data-fw-decide': 'block_fetch' },
            '[data-fw-decision]': { 'data-fw-decision': 'dl-000000000001' } }) });
        click();
        click();
        const disabled = stack().includes('disabled');
        release(reply({ id: 'dl-000000000001', action: 'block_fetch', won: true,
            item: pitem({ action: 'block_fetch', resolved_at: '2026-11-16T10:00:07.000Z', remaining: 0,
                result: { by: 'analyst', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } }) }));
        for (let i = 0; i < 10; i++) await Promise.resolve();
        click();
        console.log(JSON.stringify({ posts: calls.filter(c => c.method === 'POST').map(c => [c.url, c.body]), disabled }));""")
    assert r["disabled"], "the buttons stay pressable while the answer is out"
    assert r["posts"] == [["/api/firewall/decide", {"id": "dl-000000000001", "action": "block_fetch"}]], r["posts"]
    return len(r["posts"])


def absence_toast(o):
    r = _decisions(r"""
        const done = n => pitem({ id: 'dl-away-' + n, action: 'block_fetch', resolved_at: '2026-11-16T09:00:00.000Z', remaining: 0,
            result: { by: 'deadline', block: { rule_id: 'TDC-FW-0123456789ab', verified: true },
                      fetch: { capture_id: 'cap' + n, sha256: 'ab'.repeat(32), size: 4096, magic: 'MZ' } } });
        const history = Array.from({ length: %d }, (_, i) => done(i));
        fwApplyPending(answerOf({ history }));
        fwApplyPending(answerOf({ history, server_time: '2026-11-16T10:00:09.000Z' }));
        console.log(JSON.stringify({ toasts, away: host.children.filter(c => c.getAttribute('data-fw-decision') === '@away').map(c => c.outerHTML),
            all: host.children.length }));""" % o["captures"])
    assert r["toasts"] == [] and len(r["away"]) == 1 and r["all"] == 1, r
    return r["away"][0]


@needs_node
def test_a_decision_toast_never_dismisses_itself():
    assert decision_toast_timers() == []


@needs_node
def test_the_countdown_names_the_default_action():
    out = decision_toast({"deadline_in": 24})
    assert "0:24" in out and "FETCH" in out.upper()


@needs_node
def test_three_are_shown_and_the_rest_counted():
    out = render_pending([p(1), p(2), p(3), p(4), p(5)])
    assert out.count("toast-decision") == 3 and "+ 2 more" in out


@needs_node
def test_the_throttle_of_showToast_does_not_apply():
    assert decision_toasts_for_same_title(2) == 2


@needs_node
def test_the_url_in_a_toast_is_defanged_text():
    out = decision_toast({"url": "http://evil.example/a.dll"})
    assert "hxxp://evil[.]example/a.dll" in out and "<a " not in out


@needs_node
def test_answering_twice_sends_one_request():
    assert decide_clicks_sent_after_double_click() == 1


@needs_node
def test_an_absence_summary_is_announced_once():
    out = absence_toast({"captures": 3})
    assert "3" in out and "away" in out.lower()


def _toast_buttons(html):
    return {m.group(2): " disabled" in m.group(1) for m in re.finditer(r'(<button[^>]*data-fw-decide="(\w+)"[^>]*>)', html)}


@needs_node
def test_the_toast_offers_the_three_answers_and_in_logs():
    r = _decisions(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        const out = showDecisionToast(pitem()).outerHTML;
        onFirewallDecisionClick({ target: target({ '[data-fw-decide-logs]': {}, '[data-fw-decision]': { 'data-fw-decision': 'dl-000000000001' } }) });
        console.log(JSON.stringify({ out, calls: calls2 }));""")
    out = r["out"]
    assert _toast_buttons(out) == {"block_fetch": False, "block": False, "allow": False}
    assert out.index("CUT + FETCH") < out.index("CUT ONLY") < out.index("ALLOW") < out.index("in LOGS ▸")
    assert re.search(r'class="[^"]*is-primary[^"]*"[^>]*data-fw-decide="block_fetch"', out)
    assert "Download blocked" in out and "loader.exe" in out and "203.0.113.7:80" in out
    assert r["calls"][0][0] == 'image="%s" dst_ip="203.0.113.7"' % LOADER and r["calls"][0][3]["tab"] == "firewall"


@needs_node
def test_hostile_text_in_a_toast_stays_text():
    out = decision_toast({"url": "http://x.example/" + HOSTILE, "image": "C:\\" + HOSTILE + ".exe", "id": "dl-" + HOSTILE,
                          "source": HOSTILE, "result": {"block": {"verified": False, "problem": HOSTILE}}})
    inner = out[out.index(">") + 1:]
    _no_live_markup(inner, "toast")
    assert "&lt;script&gt;" in inner
    for _, attrs in _parsed(out):
        assert not any(a.startswith("on") for a in attrs)


@needs_node
def test_a_javascript_url_in_a_toast_is_inert():
    out = decision_toast({"url": "javascript:alert(document.cookie)"})
    assert "javascript[:]" in out and "javascript:" not in out


@needs_node
def test_a_block_that_is_not_confirmed_is_not_called_a_block():
    out = decision_toast({"result": {"block": {"rule_id": "TDC-FW-0123456789ab", "verified": False, "problem": "not read back"}}})
    assert "Download blocked" not in out and "NOT confirmed" in out and "not read back" in out
    pending = decision_toast({"result": None})
    assert "Download blocked" not in pending and "being set" in pending


@needs_node
def test_the_clock_counts_down_from_what_the_server_said_and_stands_as_a_receipt_at_zero():
    r = _decisions(r"""
        const clock = { textContent: '' };
        const real = mk;
        document.createElement = tag => Object.assign(real(tag), { querySelector: s => (s === '[data-fw-clock]' ? clock : null) });
        fwApplyPending(answerOf({ pending: [pitem({ remaining: 3 })] }));
        const first = stack();
        now += 1000; fwDecisionTick();
        const ticking = clock.textContent;
        const sameEl = host.children[0];
        now += 1000; fwDecisionTick();
        const kept = host.children[0] === sameEl;
        now += 1500; fwDecisionTick();
        const due = stack();
        // The sweep has not run yet: the server still lists it, with nothing left
        fwApplyPending(answerOf({ pending: [pitem({ remaining: 0 })], server_time: '2026-11-16T10:00:10.000Z' }));
        const still = stack();
        fwApplyPending(answerOf({ history: [pitem({ action: 'block_fetch', remaining: 0, resolved_at: '2026-11-16T10:00:10.500Z',
            result: { by: 'deadline', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } })], server_time: '2026-11-16T10:00:11.000Z' }));
        const receipt = stack();
        fwApplyPending(answerOf({ history: [pitem({ action: 'block_fetch', remaining: 0, resolved_at: '2026-11-16T10:00:10.500Z',
            result: { by: 'deadline', block: { rule_id: 'TDC-FW-0123456789ab', verified: true },
                      fetch: { capture_id: 'c1', sha256: 'ab'.repeat(32), size: 73728, magic: 'MZ' } } })], server_time: '2026-11-16T10:00:14.000Z' }));
        const fetched = stack();
        now += 600000; fwDecisionTick();
        console.log(JSON.stringify({ first, ticking, kept, due, still, receipt, fetched, after: host.children.length }));""")
    assert "0:03" in r["first"] and r["ticking"] == "0:02" and r["kept"], "the toast is drawn again every second"
    for key in ("due", "still"):
        assert "Time is up" in r[key] and all(_toast_buttons(r[key]).values()), key
    assert "CUT + FETCHED" in r["receipt"] and "deadline" in r["receipt"] and "fetching" in r["receipt"].lower()
    assert "MZ" in r["fetched"] and "72.0 KB" in r["fetched"] and "abababababab" in r["fetched"]
    assert r["after"] == 1, "a result taken by the deadline went on a timer"


@needs_node
def test_the_toast_shows_the_decision_taken_not_the_one_clicked():
    r = _decisions(r"""
        answer = (url, init) => reply(init && init.method === 'POST' ? { id: 'dl-000000000001', action: 'allow', won: false,
            item: pitem({ action: 'allow', remaining: 0, resolved_at: '2026-11-16T10:00:05.000Z',
                          result: { by: 'analyst', unblocked: true } }) } : {});
        fwApplyPending(answerOf({ pending: [pitem()] }));
        await fwDecide('dl-000000000001', 'block_fetch');
        console.log(JSON.stringify(stack()));""")
    assert "ALLOWED" in r and "CUT + FETCH" not in r and "Already answered" in r
    assert _toast_buttons(r) == {}


@needs_node
def test_a_refused_answer_keeps_the_decision_open_and_says_why():
    r = _decisions(r"""
        answer = (url, init) => reply(init && init.method === 'POST'
            ? { error: 'A block for every program stands on that endpoint, so TDC\'s own fetch would be cut off.' } : {}, init && init.method === 'POST' ? 409 : 200);
        fwApplyPending(answerOf({ pending: [pitem()] }));
        const ok = await fwDecide('dl-000000000001', 'block_fetch');
        const out = stack();
        console.log(JSON.stringify({ ok, out }));""")
    out = r["out"]
    assert r["ok"] is False and "Refused" in out and "every program" in out and "still open" in out
    assert _toast_buttons(out) == {"block": False, "allow": False} and "NO FETCH" in out
    assert "cannot fetch" in out and "fetches the file itself" not in out


@needs_node
def test_a_decision_answered_elsewhere_becomes_a_receipt():
    r = _decisions(r"""
        fwApplyPending(answerOf({ pending: [pitem()] }));
        fwApplyPending(answerOf({ history: [pitem({ action: 'allow', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z',
            result: { by: 'analyst', unblocked: false, reason: 'another decision for the same endpoint keeps it blocked' } })],
            server_time: '2026-11-16T10:00:08.000Z' }));
        console.log(JSON.stringify({ out: stack(), toasts }));""")
    assert "ALLOWED" in r["out"] and "elsewhere" in r["out"] and "Still blocked" in r["out"] and "keeps it blocked" in r["out"]
    assert r["toasts"] == []


@needs_node
def test_an_older_answer_does_not_reopen_a_decision():
    r = _decisions(r"""
        answer = (url, init) => reply(init && init.method === 'POST' ? { id: 'dl-000000000001', action: 'block', won: true,
            item: pitem({ action: 'block', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z',
                          result: { by: 'analyst', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } }) } : {});
        fwApplyPending(answerOf({ pending: [pitem()] }), ++fwPendingReq);
        const before = ++fwPendingReq;                   // a poll that went out before the answer
        await fwDecide('dl-000000000001', 'block');
        const applied = fwApplyPending(answerOf({ pending: [pitem({ remaining: 20 })] }), before);
        const stale = stack();
        fwApplyPending(answerOf({ pending: [pitem({ remaining: 20 })] }), ++fwPendingReq);
        console.log(JSON.stringify({ applied, stale, late: stack() }));""")
    assert r["applied"] is False
    for key in ("stale", "late"):
        assert "CUT ONLY" not in r[key] and "CUT" in r[key] and "The block stands" in r[key], key


@needs_node
def test_a_clock_set_back_on_the_vm_does_not_stop_the_toasts():
    out = _decisions(r"""
        fwApplyPending(answerOf({ server_time: '2026-11-16T10:00:00.000Z' }), ++fwPendingReq);
        // The VM went back to a snapshot: its clock is hours behind
        fwApplyPending(answerOf({ pending: [pitem({ id: 'dl-after-revert' })], server_time: '2026-11-16T07:00:00.000Z' }), ++fwPendingReq);
        console.log(JSON.stringify(stack()));""")
    assert 'data-fw-decision="dl-after-revert"' in out


@needs_node
def test_with_ask_off_the_toast_promises_no_default():
    out = _decisions(r"""
        fwApplyPending(answerOf({ pending: [pitem()], ask_mode: 'off' }));
        now += 60000; fwDecisionTick();
        console.log(JSON.stringify(stack()));""")
    assert "ASK is off" in out and "Time is up" not in out and "fetches the file" not in out
    assert _toast_buttons(out) == {"block_fetch": False, "block": False, "allow": False}


@needs_node
def test_the_more_line_opens_the_tab_and_the_next_decision_moves_up():
    r = _decisions(r"""
        answer = (url, init) => reply(init && init.method === 'POST' ? { id: 'dl-000000000001', action: 'block', won: true,
            item: pitem({ action: 'block', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z',
                          result: { by: 'analyst', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } }) } : {});
        fwApplyPending(answerOf({ pending: [1, 2, 3, 4].map(n => pitem({ id: 'dl-' + n, remaining: 20 + n })) }));
        onFirewallDecisionClick({ target: target({ '[data-fw-decide-more]': {} }) });
        const ids = () => host.children.map(c => c.getAttribute('data-fw-decision')).filter(Boolean);
        const before = ids();
        fwApplyPending(answerOf({ pending: [2, 3, 4].map(n => pitem({ id: 'dl-' + n, remaining: 20 + n })),
            history: [pitem({ id: 'dl-1', action: 'block', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z',
                              result: { by: 'analyst', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } })],
            server_time: '2026-11-16T10:00:08.000Z' }));
        console.log(JSON.stringify({ opened, view: fwView, before, after: ids(), out: stack() }));""")
    assert ["tab", "firewall"] in r["opened"] and r["view"] == "decisions"
    assert r["before"] == ["dl-1", "dl-2", "dl-3"]
    assert r["after"] == ["dl-2", "dl-3", "dl-4"] and "+ 1 more" in r["out"]


@needs_node
def test_the_poll_stands_down_while_hidden_and_never_runs_twice_at_once():
    r = _decisions(r"""
        const gates = [];
        answer = url => new Promise(resolve => gates.push({ url, resolve }));
        document.hidden = true;
        const hidden = fwPendingPoll();
        document.hidden = false;
        fwPendingPoll();
        fwPendingPoll();
        await Promise.resolve();
        const out = gates.length;
        gates[0].resolve(reply(answerOf({ pending: [pitem()] })));
        for (let i = 0; i < 10; i++) await Promise.resolve();
        // Hidden, the clock does not touch the page
        document.hidden = true;
        const ticked = fwDecisionTick();
        console.log(JSON.stringify({ hidden: await hidden, out, urls: gates.map(g => g.url), shown: host.children.length, ticked }));""")
    assert r["hidden"] is False and r["out"] == 1 and r["urls"] == ["/api/firewall/pending"]
    assert r["shown"] == 1 and r["ticked"] is False


@needs_node
def test_the_poll_runs_every_three_seconds_from_page_load():
    r = _decisions(r"""
        answer = () => reply(answerOf());
        fwInitDecisions();
        fwInitDecisions();
        for (let i = 0; i < 5; i++) await Promise.resolve();
        console.log(JSON.stringify({ intervals, urls: calls.map(c => c.url), listeners: (host.listeners.click || []).length }));""")
    assert r["intervals"].count(3000) == 1 and r["urls"] == ["/api/firewall/pending"] and r["listeners"] == 1
    assert "fwInitDecisions()" in _function_source_of_dom_ready()


def _function_source_of_dom_ready():
    start = SOURCE.index("document.addEventListener('DOMContentLoaded'")
    return SOURCE[start:SOURCE.index("\n});\n", start)]


@needs_node
def test_an_absence_summary_counts_only_what_nobody_saw():
    r = _decisions(r"""
        store['tdc.firewall.seen'] = '2026-11-16T09:30:00.000Z';
        const done = (id, at, result, action = 'block_fetch') => pitem({ id, action, resolved_at: at, remaining: 0, result });
        const block = { rule_id: 'TDC-FW-0123456789ab', verified: true };
        fwApplyPending(answerOf({ history: [
            done('old', '2026-11-16T09:00:00.000Z', { by: 'deadline', block, fetch: { capture_id: 'c0', size: 1, magic: 'MZ' } }),
            done('a', '2026-11-16T09:40:00.000Z', { by: 'deadline', block, fetch: { capture_id: 'c1', size: 1, magic: 'MZ' } }),
            done('b', '2026-11-16T09:41:00.000Z', { by: 'deadline', block, fetch: { error: 'timed out' } }),
            done('c', '2026-11-16T09:42:00.000Z', { by: 'analyst', block }, 'block'),
        ] }));
        console.log(JSON.stringify({ toasts, seen: store['tdc.firewall.seen'], stack: stack(), shown: host.children.length }));""")
    assert r["toasts"] == [] and r["shown"] == 1
    text = r["stack"]
    assert "1 sample secured" in text and "1 fetch failed" in text and "2 decisions" in text, text
    assert r["seen"] == "2026-11-16T10:00:06.000Z"


@needs_node
def test_a_decision_the_page_never_saw_open_still_shows_once_the_page_is_watching():
    r = _decisions(r"""
        fwApplyPending(answerOf({}));
        fwApplyPending(answerOf({ history: [pitem({ id: 'dl-fast', action: 'block_fetch', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z',
            result: { by: 'deadline', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } })], server_time: '2026-11-16T10:00:09.000Z' }));
        console.log(JSON.stringify({ out: stack(), toasts }));""")
    assert "CUT + FETCHED" in r["out"] and "deadline" in r["out"] and r["toasts"] == []


@needs_node
def test_the_tabs_own_pending_answer_feeds_the_toasts():
    r = _decisions(r"""
        answer = url => reply(url.startsWith('/api/firewall/pending') ? answerOf({ pending: [pitem()] }) : { connections: [] });
        await refreshFirewall({ slow: false });
        console.log(JSON.stringify(host.children.length));""")
    assert r == 1


def test_the_decision_toast_has_its_own_look_in_both_themes():
    css, layout = _read(STYLE_CSS), _read(STYLE_CSS.replace("style.css", "theme-layout.css"))
    assert re.search(r"\.toast\.toast-decision\s*\{", css) and re.search(r"\[data-theme\] \.toast\.toast-decision\s*\{", layout)
    motion = css[css.index("@media (prefers-reduced-motion: reduce)", css.index(".toast.toast-decision")):]
    assert ".toast-decision.is-new" in motion[:motion.index("\n}\n")]

    def rule(sheet, selector):
        m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", sheet)
        assert m, selector
        return re.sub(r"\s+", " ", m.group(1))

    base = rule(css, ".toast.toast-decision")
    assert "animation: none" in base and "border-left: 3px solid var(--severity-critical)" in base
    assert "animation: toastSlideIn" in rule(css, ".toast.toast-decision.is-new")
    container = rule(css, ".toast-container")
    assert "max-height: calc(100vh" in container and "overflow-y: auto" in container
    assert "border-left-color: var(--cp-red)" in rule(layout, "[data-theme] .toast.toast-decision")
    assert "border-left-color: var(--cp-cyan)" in rule(layout, "[data-theme] .toast.toast-decision.is-away")
    html = _read(INDEX_HTML)
    assert re.search(r'<div id="toast-container" class="toast-container">\s*<div id="decision-toasts"', html)


@needs_node
def test_the_server_saying_it_cannot_fetch_means_the_default_cuts_only():
    out = _decisions(r"""
        fwApplyPending(answerOf({ pending: [Object.assign(pitem(), { can_fetch: false })] }));
        const no = stack();
        fwApplyPending(answerOf({ pending: [Object.assign(pitem(), { can_fetch: null })] }));
        console.log(JSON.stringify({ no, unknown: stack() }));""")
    assert "cannot fetch" in out["no"] and "fetches the file itself" not in out["no"]
    assert _toast_buttons(out["no"]) == {"block": False, "allow": False} and "NO FETCH" in out["no"]
    assert "could not read its rules" in out["unknown"] and "CUT + FETCH" in out["unknown"]


# --- Task 8, fix round 1 -------------------------------------------------------------------

DEADLINE_DONE = r"""
const deadlineDone = (id, at, extra = {}) => pitem({ id, action: 'block_fetch', remaining: 0, resolved_at: at,
    result: Object.assign({ by: 'deadline', block: { rule_id: 'TDC-FW-0123456789ab', verified: true },
                            fetch: { capture_id: 'c-' + id, sha256: 'ab'.repeat(32), size: 4096, magic: 'MZ' } }, extra) });
"""


@needs_node
def test_a_result_nobody_answered_stays_on_a_visible_page_and_one_answered_here_fades():
    r = _decisions(DEADLINE_DONE + r"""
        fwApplyPending(answerOf({ pending: [pitem()] }));
        // Nobody at the screen: the deadline takes the default, the fetch comes in
        fwApplyPending(answerOf({ history: [deadlineDone('dl-000000000001', '2026-11-16T10:00:30.000Z')], server_time: '2026-11-16T10:00:35.000Z' }));
        for (let i = 0; i < 600; i++) { now += 1000; fwDecisionTick(); }
        const unattended = stack();
        // Closed with x, it goes
        onFirewallDecisionClick({ target: target({ '[data-fw-decide-close]': {}, '[data-fw-decision]': { 'data-fw-decision': 'dl-000000000001' } }) });
        const closed = host.children.length;
        // One answered here fades once read
        answer = (url, init) => reply({ id: 'dl-2', action: 'block', won: true, item: pitem({ id: 'dl-2', action: 'block', remaining: 0,
            resolved_at: '2026-11-16T10:11:00.000Z', result: { by: 'analyst', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } }) });
        fwApplyPending(answerOf({ pending: [pitem({ id: 'dl-2' })], server_time: '2026-11-16T10:10:40.000Z' }));
        await fwDecide('dl-2', 'block');
        for (let i = 0; i < 11; i++) { now += 1000; fwDecisionTick(); }
        console.log(JSON.stringify({ unattended, closed, mine: host.children.length }));""")
    assert "CUT + FETCHED" in r["unattended"] and "Taken by the deadline" in r["unattended"] and "MZ" in r["unattended"]
    assert r["closed"] == 0 and r["mine"] == 0


@needs_node
def test_the_away_summary_has_no_throttle_and_grows_until_it_is_closed():
    r = _decisions(DEADLINE_DONE + r"""
        fwApplyPending(answerOf({ history: [deadlineDone('a', '2026-11-16T09:00:00.000Z')] }));
        // Back from hidden twice within a few seconds, each time with something new
        fwPendingFirst = true;
        fwApplyPending(answerOf({ history: [deadlineDone('b', '2026-11-16T10:00:07.000Z'), deadlineDone('a', '2026-11-16T09:00:00.000Z')],
            server_time: '2026-11-16T10:00:08.000Z' }));
        const away = () => host.children.filter(c => c.getAttribute('data-fw-decision') === '@away');
        const two = away().map(c => c.outerHTML);
        for (let i = 0; i < 600; i++) { now += 1000; fwDecisionTick(); }
        const later = away().length;
        onFirewallDecisionClick({ target: target({ '[data-fw-decide-close]': {}, '[data-fw-decision]': { 'data-fw-decision': '@away' } }) });
        console.log(JSON.stringify({ toasts, two, later, closed: away().length }));""")
    assert r["toasts"] == [] and len(r["two"]) == 1 and "2 samples secured" in r["two"][0], r["two"]
    assert r["later"] == 1 and r["closed"] == 0
    assert "DECISIONS ▸" in r["two"][0] and "data-fw-decide-more" in r["two"][0]


@needs_node
def test_a_click_whose_answer_was_lost_is_not_called_somebody_elses():
    def run(taken):
        return _decisions(r"""
            answer = (url, init) => (init && init.method === 'POST') ? reply({ error: 'Internal Server Error' }, 500) : reply({});
            fwApplyPending(answerOf({ pending: [pitem()] }));
            await fwDecide('dl-000000000001', 'block');
            const between = stack();
            fwApplyPending(answerOf({ history: [pitem({ action: %s, remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z',
                result: { by: 'analyst', unblocked: true, block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } })],
                server_time: '2026-11-16T10:00:08.000Z' }));
            console.log(JSON.stringify({ between, after: stack() }));""" % json.dumps(taken))
    same = run("block")
    assert "Whether it was taken shows with the next update" in same["between"]
    assert "Probably your click" in same["after"] and "elsewhere" not in same["after"]
    other = run("allow")
    assert "Answered elsewhere" in other["after"] and "Probably your click" not in other["after"]


@needs_node
def test_a_hanging_click_shows_the_servers_default_when_a_poll_brings_it():
    out = _decisions(DEADLINE_DONE + r"""
        answer = (url, init) => (init && init.method === 'POST') ? new Promise(() => {}) : reply({});
        fwApplyPending(answerOf({ pending: [pitem({ remaining: 1 })] }), ++fwPendingReq);
        fwDecide('dl-000000000001', 'allow');
        await Promise.resolve();
        fwApplyPending(answerOf({ history: [deadlineDone('dl-000000000001', '2026-11-16T10:00:07.000Z')],
            server_time: '2026-11-16T10:00:08.000Z' }), ++fwPendingReq);
        console.log(JSON.stringify(stack()));
        process.exit(0);""")
    assert "CUT + FETCHED" in out and "still on its way" in out and "elsewhere" not in out
    assert _toast_buttons(out) == {}


@needs_node
def test_a_hanging_request_is_given_up_after_fifteen_seconds():
    r = _decisions(r"""
        answer = (url, init) => new Promise((resolve, reject) => init && init.signal
            ? init.signal.addEventListener('abort', () => reject(new Error('aborted'))) : null);
        const poll = fwPendingPoll();
        const busy = fwPendingBusy;
        const ms = timers.map(t => t.ms);
        runTimers();
        await poll;
        console.log(JSON.stringify({ busy, ms, after: fwPendingBusy, error: fwPendingError, again: fwPendingPoll() instanceof Promise && fwPendingBusy }));
        process.exit(0);""")
    assert r["busy"] is True and 15000 in r["ms"] and r["after"] is False
    assert "within 15 s" in r["error"] and r["again"] is True


@needs_node
def test_an_unconfirmed_block_is_not_said_to_be_kept():
    for result in ({"block": {"verified": False, "problem": "not read back"}}, None):
        out = decision_toast({"result": result})
        assert "TDC blocks it and fetches the file itself" in out and "keeps it cut" not in out, out
    off = _decisions(r"""
        fwApplyPending(answerOf({ pending: [pitem({ result: { block: { verified: false } } })], ask_mode: 'off' }));
        console.log(JSON.stringify(stack()));""")
    assert "stays cut" not in off and "no default" in off


@needs_node
def test_an_answer_without_a_list_marks_nothing_lost():
    out = _decisions(r"""
        fwApplyPending(answerOf({ pending: [pitem()] }));
        const ok = fwApplyPending({ error: 'odd', history: [] });
        const noHistory = fwApplyPending({ pending: [], server_time: '2026-11-16T10:00:09.000Z' });
        console.log(JSON.stringify({ ok, noHistory, out: stack() }));""")
    assert out["ok"] is False and out["noHistory"] is True
    assert "No longer listed" not in out["out"] and "without a list of open decisions" not in out["out"]
    assert "CUT + FETCH" in out["out"]


@needs_node
def test_an_answer_without_a_list_is_said_on_the_open_toasts():
    out = _decisions(r"""
        fwApplyPending(answerOf({ pending: [pitem()] }));
        fwApplyPending({ pending: 'nope' });
        console.log(JSON.stringify(stack()));""")
    assert "without a list of open decisions" in out and "No longer listed" not in out


@needs_node
def test_hostile_text_in_every_result_path_stays_text():
    r = _decisions(r"""
        const H = %s;
        answer = (url, init) => (init && init.method === 'POST') ? reply({ error: H }, 409) : reply({});
        fwApplyPending(answerOf({ pending: [pitem({ id: 'o' })] }));
        await fwDecide('o', 'block_fetch');
        const refused = stack();
        fwDismissResults();
        fwApplyPending(answerOf({ pending: [pitem({ id: 'o' })], history: [
            pitem({ id: 'r1', action: 'allow', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z', result: { by: 'deadline', unblocked: false, reason: H } }),
            pitem({ id: 'r2', action: 'block_fetch', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z', result: { by: 'deadline', block: { verified: true }, fetch: { error: H } } }),
            pitem({ id: 'r3', action: 'block_fetch', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z', result: { by: 'deadline', block: { verified: true }, fetch: { capture_id: 'c', size: 1, magic: H, sha256: H } } }),
            pitem({ id: 'r4', action: 'dropped', remaining: 0, resolved_at: '2026-11-16T10:00:07.000Z', result: { reason: H } }),
        ], server_time: '2026-11-16T10:00:08.000Z' }));
        fwReady = true; fwView = 'decisions'; renderFirewallDecisions();
        console.log(JSON.stringify({ refused, results: host.children.map(c => c.innerHTML), view: els['firewall-view'].innerHTML }));""" % json.dumps(HOSTILE))
    for name, markup in [("refused", r["refused"][r["refused"].index(">") + 1:])] + [("r", m) for m in r["results"]] + [("view", r["view"])]:
        _no_live_markup(markup, name)
    assert "&lt;script&gt;" in r["refused"] and all("&lt;script&gt;" in m for m in r["results"][1:3])
    assert r["view"].count("&lt;script&gt;") >= 4


@needs_node
def test_decisions_lists_the_open_and_the_decided_with_who_what_and_the_capture():
    r = _decisions(DEADLINE_DONE + r"""
        fwState.captures = [{ id: 'c-d1', path: 'C:\\tdc\\samples\\ab\\abab', sha256: 'ab'.repeat(32) }];
        fwApplyPending(answerOf({ pending: [pitem({ id: 'o1', url: 'http://open.example/a.exe' })], history: [
            deadlineDone('d1', '2026-11-16T10:00:05.000Z'),
            pitem({ id: 'a1', action: 'allow', remaining: 0, resolved_at: '2026-11-16T09:59:00.000Z', result: { by: 'analyst', unblocked: true } }),
            pitem({ id: 'b1', action: 'block', remaining: 0, resolved_at: '2026-11-16T09:58:00.000Z',
                    result: { by: 'analyst', block: { verified: false, problem: 'not read back' } } }),
        ] }));
        fwReady = true;
        fwSetView('decisions');
        const view = els['firewall-view'].innerHTML;
        answer = (url, init) => reply(init && init.method === 'POST' ? { id: 'o1', action: 'block', won: true,
            item: pitem({ id: 'o1', action: 'block', remaining: 0, resolved_at: '2026-11-16T10:00:09.000Z', result: { by: 'analyst', block: { verified: true } } }) } : {});
        const row = { 'data-fw-decision': 'o1' };
        await onFirewallClick({ target: target({ '[data-fw-decide]': { 'data-fw-decide': 'block' }, '[data-fw-decision]': row }) });
        for (let i = 0; i < 10; i++) await Promise.resolve();
        onFirewallClick({ target: target({ 'button[data-fw-open]': { 'data-fw-open': 'rizin', 'data-fw-capture': 'c-d1' } }) });
        console.log(JSON.stringify({ view, posts: calls.filter(c => c.method === 'POST').map(c => c.body), opened, after: els['firewall-view'].innerHTML }));""")
    view = r["view"]
    rows = re.findall(r'<tr class="fw-dec-row[^"]*" data-fw-decision="([^"]+)"', view)
    assert rows == ["o1", "d1", "a1", "b1"]
    assert "hxxp://open[.]example/a.exe" in view and "<a " not in view
    assert "CUT + FETCHED" in view and "the deadline" in view and "ALLOWED" in view and "an analyst" in view
    assert "NOT confirmed" in view and "lifted" in view and 'data-fw-open="rizin" data-fw-capture="c-d1"' in view
    assert 'data-sortable data-sort-id="firewall-decisions"' in view
    assert re.search(r'data-fw-decision="o1".*data-fw-decide="block_fetch"', view)
    assert r["posts"] == [{"id": "o1", "action": "block"}]
    assert ["rizin", "C:\\tdc\\samples\\ab\\abab"] in r["opened"]
    assert re.search(r'data-fw-decision="o1".*?CUT<', r["after"]) and "ANSWERING" not in r["after"]


# --- Task 8, fix round 2 -------------------------------------------------------------------

@needs_node
def test_a_slow_connections_answer_does_not_keep_a_decision_from_its_toast():
    r = _decisions(r"""
        // The tab is open on LIVE and /connections hangs: every tick of the tab waits on it
        answer = url => url.startsWith('/api/firewall/connections') ? new Promise(() => {}) : reply(url.startsWith('/api/firewall/pending')
            ? answerOf({ pending: [pitem({ id: 'dl-new' })] }) : {});
        fwReady = true; fwState.live = true; state.activeTab = 'firewall';
        refreshFirewall({ slow: false });
        refreshFirewall({ slow: false });
        const polled = await fwPendingPoll();
        console.log(JSON.stringify({ polled, ids: host.children.map(c => c.getAttribute('data-fw-decision')) }));
        process.exit(0);""")
    assert r == {"polled": True, "ids": ["dl-new"]}


@needs_node
def test_a_failed_click_then_the_deadline_is_a_result_nobody_saw():
    out = _decisions(DEADLINE_DONE + r"""
        answer = (url, init) => (init && init.method === 'POST') ? reply({ error: 'Bad gateway' }, 502) : reply({});
        fwApplyPending(answerOf({ pending: [pitem()] }));
        await fwDecide('dl-000000000001', 'allow');
        fwApplyPending(answerOf({ history: [deadlineDone('dl-000000000001', '2026-11-16T10:00:30.000Z')], server_time: '2026-11-16T10:00:35.000Z' }));
        for (let i = 0; i < 600; i++) { now += 1000; fwDecisionTick(); }
        console.log(JSON.stringify(stack()));""")
    assert "CUT + FETCHED" in out and "Taken by the deadline" in out


@needs_node
def test_decisions_keeps_the_block_of_a_dropped_one_and_says_whose_clock_it_is():
    out = _decisions(r"""
        fwApplyPending(answerOf({ history: [
            pitem({ id: 'x1', action: 'dropped', remaining: 0, resolved_at: '2026-11-16T10:00:00.000Z',
                    result: { reason: 'more than 200 open decisions', block: { rule_id: 'TDC-FW-0123456789ab', verified: true } } }),
            pitem({ id: 'x2', action: 'dropped', remaining: 0, resolved_at: '2026-11-16T10:00:00.000Z', result: { reason: 'more than 200 open decisions' } }),
        ] }));
        fwReady = true; fwSetView('decisions');
        console.log(JSON.stringify(els['firewall-view'].innerHTML));""")
    cells = re.findall(r'<td class="fw-dec-block[^"]*"[^>]*>([^<]*)</td>', out)
    assert cells == ["confirmed", "kept"] and "not set yet" not in out
    assert "Time (VM clock)" in out
    # Date.now of the tests is months after the server_time of the answer
    assert re.search(r"The VM&#39;s clock is [0-9,]+ (minutes|hours|days) behind this computer&#39;s", out), out[:600]


@needs_node
def test_decisions_says_when_it_is_not_up_to_date_or_the_rules_are_unknown():
    r = _decisions(r"""
        fwReady = true;
        fwApplyPending({ pending: 'x' });
        fwSetView('decisions');
        const never = els['firewall-view'].innerHTML;
        fwApplyPending(answerOf({ pending: [Object.assign(pitem(), { can_fetch: null })], server_time: new Date(now).toISOString() }));
        const unknown = els['firewall-view'].innerHTML;
        answer = () => reply({ error: 'boom <b>x</b>' }, 500);
        await fwPendingPoll();
        console.log(JSON.stringify({ never, unknown, stale: els['firewall-view'].innerHTML }));""")
    assert "could not be loaded" in r["never"] and "No decisions" not in r["never"]
    assert "could not read its rules" in r["unknown"] and "behind" not in r["unknown"] and "ahead" not in r["unknown"]
    assert "Not up to date" in r["stale"] and "&lt;b&gt;x" in r["stale"] and 'data-fw-decision="dl-000000000001"' in r["stale"]


@needs_node
def test_a_reload_brings_back_the_results_nobody_closed():
    r = _decisions(DEADLINE_DONE + r"""
        const history = [deadlineDone('kept', '2026-11-16T10:00:07.000Z'), deadlineDone('closed', '2026-11-16T10:00:07.500Z')];
        fwApplyPending(answerOf({ pending: [pitem({ id: 'kept' }), pitem({ id: 'closed' })] }));
        fwApplyPending(answerOf({ history, server_time: '2026-11-16T10:00:08.000Z' }));
        fwDismissDecision('closed');
        const standing = store['tdc.firewall.standing'];
        // The page is loaded again: everything in memory is gone, the storage stays
        fwDecisions = new Map(); fwDecisionOrder = ''; fwPendingFirst = true; fwPendingApplied = 0; fwStandingLoaded = false; fwStandingJson = ''; host.replaceChildren();
        fwApplyPending(answerOf({ history, server_time: '2026-11-16T10:05:00.000Z' }));
        console.log(JSON.stringify({ standing, ids: host.children.map(c => c.getAttribute('data-fw-decision')), out: stack() }));""")
    assert json.loads(r["standing"]) == {"results": ["kept"], "away": []}
    assert r["ids"] == ["kept"] and "Taken by the deadline" in r["out"]


@needs_node
def test_a_refused_fetch_is_offered_again_once_the_server_says_it_can():
    r = _decisions(r"""
        answer = (url, init) => (init && init.method === 'POST') ? reply({ error: 'A block for every program stands' }, 409) : reply({});
        fwApplyPending(answerOf({ pending: [pitem()] }), ++fwPendingReq);
        const before = ++fwPendingReq;
        await fwDecide('dl-000000000001', 'block_fetch');
        fwApplyPending(answerOf({ pending: [Object.assign(pitem(), { can_fetch: true })] }), before);
        const stale = stack();
        fwApplyPending(answerOf({ pending: [Object.assign(pitem(), { can_fetch: true })] }), ++fwPendingReq);
        console.log(JSON.stringify({ stale, fresh: stack() }));""")
    assert "NO FETCH" in r["stale"]
    assert "NO FETCH" not in r["fresh"] and 'data-fw-decide="block_fetch"' in r["fresh"]


# --- Task 9: the perspective switch -------------------------------------------------

def _cmp_terms(node):
    """The (field, op, value) of every comparison in a parsed search part."""
    if not isinstance(node, tuple):
        return []
    if node[0] == "cmp":
        return [(node[1], node[2], node[3])]
    if node[0] in ("and", "or"):
        return [t for n in node[1] for t in _cmp_terms(n)]
    if node[0] == "not":
        return _cmp_terms(node[1])
    return []


def hint_queries(image, ip):
    """Every LOGS query the tab builds for a selection with this image and address: the hints and in LOGS."""
    return _run(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        fwState.loaded = true;
        fwState.rules = [];
        fwState.flows = [flow({ image: %s, dst: %s })];
        fwSelect('f:' + fwFlowKey(fwState.flows[0]));
        FW_HINTS.forEach((h, i) => fwOpenHint(i));
        fwOpenLogs();
        fwSelect('p:' + fwProcKey(fwState.flows[0]));
        fwOpenLogs();
        fwSelect('a:' + fwState.flows[0].dst_ip);
        fwOpenLogs();
        console.log(JSON.stringify(calls2.map(c => c[0])));""" % (json.dumps(image), json.dumps(ip)))


@needs_node
def test_a_hint_click_quotes_the_value_safely():
    import log_search
    for image, ip in [('C:\\x\\a"b\\', 'a"b\\'),
                      ('C:\\x\\" | head 1 OR source=* "', '1.2.3.4" OR "x'),
                      ('C:\\x\\loader.exe', '203.0.113.7')]:
        queries = hint_queries(image, ip)
        assert len(queries) == 5 + 3, queries
        for q in queries:
            parsed = log_search.parse(q)           # the server's own parser: it takes every one of them
            for field, op, value in _cmp_terms(parsed.terms):
                if field == "pid":
                    assert (op, value) == ("=", "4242"), q
                if field not in ("image", "dst_ip"):
                    continue
                want = image if field == "image" else ip
                # the value as given; one ending in a backslash ends in \* (logsQuote), which still matches it
                assert op == "=" and value in (want, want + "*"), (q, field, value)
            # a value never adds a pipe of its own: the pipes are those of the hint
            assert len(parsed.pipes) <= 1, q
            assert sum(1 for f, _, _ in _cmp_terms(parsed.terms) if f in ("image", "dst_ip")) <= 2, q


def open_firewall_tab(filter, flows=None, loaded=True, load=None):
    return _run(r"""
        fwState.loaded = %s;
        fwState.rules = [];
        fwState.flows = %s;
        const ok = openFirewallTab(%s);
        const before = { selected: fwSelected, filter: fwFilter };
        const load = %s;
        if (load) {
            answer = url => url.startsWith('/api/firewall/connections') ? reply({ connections: load.map(o => flow(o)), count: load.length })
                : reply({ pending: [], history: [] });
            await fwLoadFlows();
        }
        const tab = opened.filter(o => o[0] === 'tab').map(o => o[1]).pop();
        console.log(JSON.stringify({ ok, activeTab: tab, before, selected: fwSelected, filter: fwFilter,
            search: els['firewall-search'].value, tree: els['firewall-tree'].innerHTML, hints: els['firewall-hints'].innerHTML }));""" % (
        json.dumps(loaded), _flows_js(flows if flows is not None else [{}, {"dst": "1.2.3.4", "port": 443}]),
        json.dumps(filter), json.dumps(load)))


@needs_node
def test_open_firewall_tab_filters_on_the_endpoint():
    s = open_firewall_tab({"ip": "1.2.3.4", "port": 443})
    # Task 7's selection of an address (every process and port to it); the tree is filtered on it
    assert s["activeTab"] == "firewall" and s["selected"] == "a:1.2.3.4"
    assert s["filter"] == s["search"] == "1.2.3.4" and "203.0.113.7" not in s["tree"]
    assert "1.2.3.4" in s["hints"] and "data-fw-logs" in s["hints"]


@needs_node
def test_open_firewall_tab_selects_a_process_and_one_flow():
    proc = open_firewall_tab({"image": LOADER.upper(), "pid": 4242})
    assert proc["selected"] == "p:%s|4242" % LOADER
    one = open_firewall_tab({"image": LOADER, "ip": "1.2.3.4", "port": 443})
    assert one["selected"] == "f:%s|4242|tcp|10.0.2.15|1.2.3.4|443" % LOADER and one["filter"] == "1.2.3.4"
    # a process that has restarted is found by its image; the newest of its runs is chosen
    gone = open_firewall_tab({"image": LOADER, "pid": 1}, flows=[{"pid": 7}, {"pid": 8, "dst": "1.2.3.4"}])
    assert gone["selected"] in ("p:%s|7" % LOADER, "p:%s|8" % LOADER)
    # the exact selection the way back brings wins over the parts
    exact = open_firewall_tab({"select": "a:203.0.113.7", "ip": "1.2.3.4", "text": ""})
    assert exact["selected"] == "a:203.0.113.7" and exact["filter"] == ""


@needs_node
def test_open_firewall_tab_cold_selects_once_the_connections_are_in():
    s = open_firewall_tab({"ip": "1.2.3.4", "port": 443}, flows=[], loaded=False, load=[{"dst": "1.2.3.4"}, {}])
    assert s["before"] == {"selected": "", "filter": "1.2.3.4"}
    assert s["selected"] == "a:1.2.3.4" and "1.2.3.4" in s["hints"]


@needs_node
def test_a_filter_with_no_connections_in_the_range_says_so():
    s = open_firewall_tab({"image": "C:\\gone\\" + HOSTILE + ".exe"}, load=[{}])
    assert s["selected"] == ""
    assert "No connection in the last 1h matches" in s["tree"] and "wider range" in s["tree"]
    assert "<script>" not in s["tree"] and "&lt;script&gt;" in s["tree"]


@needs_node
def test_in_logs_carries_the_connection_lifetime_not_the_last_range():
    r = _run(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        fwState.loaded = true;
        fwState.rules = [];
        const a = flow(), b = flow({ dst: '1.2.3.4', port: 80 }), c = flow({ pid: 9, image: 'C:\\x\\other.exe' });
        b.first_seen = '2026-11-16T08:00:00Z'; b.last_seen = '2026-11-16T12:30:00Z';
        c.first_seen = '2026-11-16T07:00:00Z'; c.last_seen = '2026-11-16T07:01:00Z';
        fwState.flows = [a, b, c];
        fwRange = '24h';
        fwSelect('f:' + fwFlowKey(a));
        fwOpenLogs();
        FW_HINTS.forEach((h, i) => fwOpenHint(i));
        fwSelect('p:' + fwProcKey(a));
        fwOpenLogs();
        b.first_seen = 'garbage';
        fwSelect('a:1.2.3.4');
        fwOpenLogs();
        fwSelect('');
        fwFilter = 'loader';
        fwOpenHint(2);
        console.log(JSON.stringify(calls2.map(c => [c[0], c[1], c[2], c[3], c[4]])));""")
    flow_, endpoint_hint, rhythm, dropped, dga, cradles, proc, broken, unselected = r
    # one connection: its first and last packet, five minutes either side (DNS before it, a drop after it)
    assert flow_[1:3] == ["2026-11-16T09:55:00Z", "2026-11-16T10:10:00Z"] and flow_[4] == ""
    assert flow_[3]["tab"] == "firewall" and flow_[3]["filter"]["select"].startswith("f:")
    # the process: all of its connections
    assert proc[1:3] == ["2026-11-16T07:55:00Z", "2026-11-16T12:35:00Z"]
    # a hint about the endpoint covers every connection to it, of whichever process; one about the process all of its own
    # (other.exe talked to it at 07:00, loader.exe's connection to 1.2.3.4 is not about this endpoint)
    assert endpoint_hint[1:3] == ["2026-11-16T06:55:00Z", "2026-11-16T10:10:00Z"]
    assert rhythm[1:3] == ["2026-11-16T07:55:00Z", "2026-11-16T12:35:00Z"]
    # the hints about everything take the tab's range
    assert [h[1:3] for h in (dropped, dga, cradles)] == [["-24h", ""]] * 3
    # and their way back keeps the tree as it was (the selection's, with its filter)
    assert dropped[3] == {"tab": "firewall", "filter": {"select": dropped[3]["filter"]["select"], "text": "",
                                                        "image": LOADER, "ip": "203.0.113.7", "pid": 4242, "port": 443}}
    # a time that cannot be read falls back to the tab's range, never to no range at all
    assert broken[1:3] == ["-24h", ""]
    # ... and says so beside the range in LOGS
    assert "could not be read" in broken[4] and "FIREWALL range (the last 24h)" in broken[4]
    # without a selection the way back is the tab with the tree's filter as it was
    assert unselected[1:3] == ["-24h", ""] and unselected[3] == {"tab": "firewall", "filter": {"text": "loader"}}


@needs_node
def test_the_toast_takes_the_time_of_the_download_to_logs():
    r = _decisions(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        const seen = pitem({ id: 'dl-1' }); seen.finding.observed_at = '2026-11-16T09:58:10Z';
        const bare = pitem({ id: 'dl-2' });
        const none = pitem({ id: 'dl-3' }); none.created_at = null;
        for (const item of [seen, bare, none]) { showDecisionToast(item); fwDecisionLogs(item.id); }
        console.log(JSON.stringify(calls2));""")
    assert [c[1:3] for c in r] == [["2026-11-16T09:53:10Z", ""], ["2026-11-16T09:55:00Z", ""], ["-1h", ""]]
    # no time of the download: the FIREWALL range, as every other fallback, and said so
    assert r[0][4] == "" and "not known" in r[2][4] and "FIREWALL range (the last 1h)" in r[2][4]
    assert r[0][3]["filter"]["ip"] == "203.0.113.7" and r[0][3]["filter"]["image"] == LOADER


@needs_node
def test_graph_network_nodes_and_tracing_lead_to_the_firewall_tab():
    r = _run_node(["escapeHtml", "graphFirewallButtonHtml", "rtraceOpenFirewall"], r"""
        const calls2 = [];
        globalThis.openFirewallTab = f => { calls2.push(f); return true; };
        globalThis.state = { processes: { '4242': { image: 'C:\\x\\loader.exe', pid: 4242 }, '9': { pid: 9 } }, rtraceSelectedPid: '4242' };
        const button = graphFirewallButtonHtml({ ip: '1.2.3.4"><script>', port: 443 });
        rtraceOpenFirewall();
        state.rtraceSelectedPid = '9';
        const none = rtraceOpenFirewall();
        console.log(JSON.stringify({ button, calls: calls2, none }));""")
    assert ">FIREWALL<" in r["button"] and "<script>" not in r["button"] and "data-fw-endpoint-ip" in r["button"]
    assert r["calls"] == [{"image": "C:\\x\\loader.exe", "pid": 4242}] and r["none"] is False
    html = _read(INDEX_HTML)
    bar = html[html.index('id="rtrace-info-bar"'):]
    bar = bar[:bar.index("</div>")]
    assert re.search(r'<button[^>]*id="rtrace-firewall"[^>]*onclick="rtraceOpenFirewall\(\)"[^>]*>FIREWALL</button>', bar)
    assert "rtrace-firewall" in _function_source("updateRtraceInfoBar")


@needs_node
def test_graph_draws_the_button_on_a_network_node_and_its_click_opens_the_endpoint():
    r = _run_node(["escapeHtml", "graphFirewallButtonHtml", "showGraphDetail"], r"""
        const calls2 = [];
        globalThis.openFirewallTab = f => { calls2.push(f); return true; };
        globalThis.graphState = { nodes: [], edges: [] };
        const unescape = t => t.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        // A body that finds a button in its markup as a browser would: by its data attributes, with their values decoded
        const body = { innerHTML: '', listeners: [],
            querySelector(sel) {
                const want = /\[(data-[\w-]+)\]$/.exec(sel);
                const tag = want && (this.innerHTML.match(/<button[^>]*>/g) || []).find(t => t.includes(` ${want[1]}="`));
                if (!tag) return null;
                const dataset = {};
                for (const m of tag.matchAll(/ data-([\w-]+)="([^"]*)"/g)) dataset[m[1].replace(/-(\w)/g, (x, c) => c.toUpperCase())] = unescape(m[2]);
                return { dataset, addEventListener: (type, fn) => body.listeners.push([type, fn]) };
            },
            querySelectorAll: () => [] };
        const panel = { classList: { add() {} } }, header = { textContent: '' };
        globalThis.document = { getElementById: id => ({ 'graph-detail-panel': panel, 'graph-detail-header': header, 'graph-detail-body': body })[id] || null };
        showGraphDetail({ id: 'net_x', type: 'network', ip: '1.2.3.4"><script>', port: 443, protocol: 'tcp' });
        const html = body.innerHTML;
        body.listeners.filter(l => l[0] === 'click').forEach(l => l[1]());
        const dns = (body.innerHTML = '', body.listeners = [], showGraphDetail({ id: 'dns_x', type: 'dns', label: 'x.example' }), body.innerHTML);
        console.log(JSON.stringify({ html, calls: calls2, dns }));""")
    assert ">FIREWALL<" in r["html"] and "<script>" not in r["html"]
    assert r["calls"] == [{"ip": '1.2.3.4"><script>', "port": "443"}]
    assert "FIREWALL" not in r["dns"]


@needs_node
def test_a_connection_that_may_still_run_searches_to_now():
    r = _run(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        fwState.loaded = true;
        fwState.rules = [];
        const live = flow();
        // the last packet two minutes before the tests' clock, on the VM's clock (an hour ahead of this computer's)
        fwPendingSkew = 3600000;
        live.first_seen = '2026-11-20T00:30:00Z'; live.last_seen = '2026-11-20T00:58:00Z';
        fwState.flows = [live];
        fwSelect('f:' + fwFlowKey(live));
        fwOpenLogs();
        // the same packet without the skew lies in this computer's future: still to now
        fwPendingSkew = null;
        fwOpenLogs();
        // over for longer than the margin: a closed window
        live.last_seen = '2026-11-19T23:50:00Z'; live.first_seen = '2026-11-19T23:40:00Z';
        fwOpenLogs();
        console.log(JSON.stringify(calls2.map(c => [c[1], c[2], c[4]])));""")
    assert r[0][:2] == ["2026-11-20T00:25:00Z", ""] and "To now" in r[0][2] and "still be running" in r[0][2]
    assert r[1][:2] == ["2026-11-20T00:25:00Z", ""]
    assert r[2] == ["2026-11-19T23:35:00Z", "2026-11-19T23:55:00Z", ""]


@needs_node
def test_the_rhythm_hint_takes_every_run_of_the_image_whatever_its_case():
    r = _run(r"""
        const calls2 = [];
        globalThis.openLogsTab = (...args) => { calls2.push(args); return true; };
        fwState.loaded = true;
        fwState.rules = [];
        const a = flow(), b = flow({ pid: 77, image: %s.toUpperCase() });
        b.first_seen = '2026-11-16T06:00:00Z';
        fwState.flows = [a, b];
        fwSelect('p:' + fwProcKey(a));
        fwOpenHint(1);
        console.log(JSON.stringify(calls2[0].slice(1, 3)));""" % json.dumps(LOADER))
    assert r == ["2026-11-16T05:55:00Z", "2026-11-16T10:10:00Z"]


@needs_node
def test_the_way_back_to_a_selection_that_is_gone_says_so():
    s = open_firewall_tab({"select": "p:%s|4242" % LOADER, "image": LOADER, "pid": 4242, "text": ""},
                          load=[{"image": "C:\\x\\other.exe"}])
    assert s["selected"] == "" and s["filter"] == ""
    assert "loader.exe (PID 4242) has no connections in the last 1h any more" in s["hints"] and "wider range" in s["hints"]
    gone = open_firewall_tab({"select": "a:198.51.100.9", "text": ""}, load=[{}])
    assert "198.51.100.9 has no connections" in gone["hints"]
    hostile = open_firewall_tab({"image": "C:\\" + HOSTILE + ".exe", "ip": HOSTILE, "text": ""}, load=[{}])
    assert "<script>" not in hostile["hints"] and "&lt;script&gt;" in hostile["hints"]
    # a selection of the analyst's own takes the message away
    r = _run(r"""
        fwState.loaded = true; fwState.rules = []; fwState.flows = [flow()];
        openFirewallTab({ ip: '198.51.100.9', text: '' });
        answer = url => url.startsWith('/api/firewall/connections') ? reply({ connections: [flow()], count: 1 })
            : reply({ pending: [], history: [] });
        await fwLoadFlows();
        const before = els['firewall-hints'].innerHTML;
        fwSelect('a:203.0.113.7');
        console.log(JSON.stringify([before.includes('has no connections'), els['firewall-hints'].innerHTML.includes('has no connections')]));""")
    assert r == [True, False]


@needs_node
def test_a_selection_is_gone_only_by_the_fresh_full_list():
    """Task 9 re-review: the message was also set on the first apply, which runs on the list on screen. It showed
    while the load was still out, stayed when the load failed, and claimed "no connections" of a list the server
    had cut to its most severe rows."""
    r = _run(r"""
        fwState.loaded = true; fwState.rules = []; fwState.flows = [flow()];
        openFirewallTab({ ip: '198.51.100.9', text: '' });
        const stale = els['firewall-hints'].innerHTML.includes('has no connections');
        answer = url => url.startsWith('/api/firewall/connections') ? reply({ error: 'down' }, 500)
            : reply({ pending: [], history: [] });
        await fwLoadFlows();
        const failed = fwWantMissed;
        answer = url => url.startsWith('/api/firewall/connections')
            ? reply({ connections: [flow()], count: 900, truncated: true }) : reply({ pending: [], history: [] });
        await fwLoadFlows();
        console.log(JSON.stringify([stale, failed, fwWantMissed]));""")
    stale, failed, cut = r
    assert stale is False and failed == ""
    assert "198.51.100.9 is not among the 1 most severe connections shown" in cut and "has no connections" not in cut


@needs_node
def test_the_fallback_range_does_not_claim_to_hold_more():
    """Task 9 re-review: a range that ends now can also miss what came before it, so "may hold more" was not true."""
    r = _run(r"""
        const notes = [];
        fwRange = '1h';
        notes.push(fwRangeFallback('These connections have no times'));
        fwRange = 'All';
        notes.push(fwRangeFallback('These connections have no times'));
        console.log(JSON.stringify(notes));""")
    hour, every = r
    assert hour["earliest"] == "-1h" and "may hold more" not in hour["note"]
    assert "misses whatever of them came before it" in hour["note"] and "old download" in hour["note"]
    assert every["earliest"] == "" and "everything kept" in every["note"] and "may hold more" not in every["note"]
    assert "LOGS may no longer keep the oldest of theirs" in every["note"]
