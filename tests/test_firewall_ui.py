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
"""

import json
import re
from html.parser import HTMLParser

from test_frontend import SOURCE, _function_source, _run_node, needs_node
from test_theme import INDEX_HTML, INFO_ATTR, STYLE_CSS, _const_source, _Elements, _read

FW_FUNCTION_NAME = re.compile(
    r"^(?:async )?function ((?:fw|renderFirewall|refreshFirewall|initFirewall|firewallTabShown|onFirewall|openLogsTab"
    r"|openFirewallTab)\w*)\(", re.M)
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
    els[id] = { id, innerHTML: '', textContent: '', value: '', hidden: false, disabled: false, title: '', style: {}, attrs: {},
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
""" % (json.dumps(ELEMENT_IDS), json.dumps(LOADER))


def _run(script):
    return _run_node(ALL_FUNCTIONS, "(async () => {\n" + script + "\n})().catch(e => { console.error(e); process.exit(1); });",
                     PRELUDE)


def _flows_js(flows):
    return "[" + ", ".join("flow(%s)" % json.dumps(f) for f in flows) + "]"


def render_tree(flows, isolate=None, extra=""):
    return _run(r"""
        fwState.loaded = true;
        fwState.isolate = %s;
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


HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(1)>"


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
        assert not any(a.startswith("on") or a in ("href", "src") for a in attrs), (name, tag, attrs)


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
    assert "const FW_VIEWS = ['map', 'list', 'asn'];" in SOURCE and "const FW_LIVE_MS = 5000;" in SOURCE
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
    out = render_tree([{"image": TDC_PYTHON, "self": True}], extra="fwOpen.set('tdc', true);")
    assert 'data-fw-block="process"' not in out or "disabled" in out


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
    out = render_map([{"dst": "192.168.64.1", "scope": "local"}, {"dst": "1.2.3.4"}])
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
    assert r["calls"][0][1] == "-4h"
    assert 'image=&quot;C:\\\\x\\\\a\\&quot;b.exe&quot;' in r["html"] or 'a\\&quot;b.exe' in r["html"]


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
        console.log(JSON.stringify({ opened, value: els['firewall-search'].value }));""")
    path = r"C:\tdc\samples\a3\a3f1"
    assert ["rizin", path] in r["opened"] and ["hex", path] in r["opened"] and ["tab", "threatscan"] in r["opened"]


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
    assert all("since=" not in u for u in r["all"]) and len(r["all"]) == 2, "a light tick asks for more than the poll paths"


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
def test_the_perspective_switches_are_stubs_for_task_9():
    r = _run(r"""
        console.log(JSON.stringify([typeof openLogsTab, typeof openFirewallTab]));""")
    assert r == ["function", "function"]
