"""The NETWORK tab: the report of a pcap in the web UI (app.js, index.html, the style sheets).

Regressions covered:
  * a tab nobody can reach: the button between PIPES and SYSMON, the (i) text, the seven
    sub-tabs (no FINGERPRINT yet), the switch that loads it, the help entry and the routes
  * a value of a capture (name, URL, process, rule name, finding, indicator, file name, error)
    reaching the markup unescaped; a header read under its capitalised name (the masked report
    has lower-case keys); a file offered as a link
  * "could not decide" shown as "nothing found": a rule left undecided, a spent regex or hash
    budget, a cut capture and a failed step each need their own say in OVERVIEW; a capture without
    traffic is "not observed" with its note, never "nothing found"
  * a finding another finding absorbed (superseded_by) listed under "suppressed by the baseline",
    here and in the memory evidence block; baseline events and findings not marked
  * the evidence source `network` drawn as live memory (the verdict flow's default kind)
  * the panel for the Submit tab defined but never called by renderDetonationPanels
  * a data table that cannot be sorted, a chart card without CHART / TABLE, a colour written
    into the script, a colour variable that only one theme defines
"""

import json
import os
import re

import pytest

from test_frontend import ROOT, SOURCE, _function_source, _run_node, needs_node

INDEX_HTML = os.path.join(ROOT, "webui", "templates", "index.html")
STYLE_CSS = os.path.join(ROOT, "webui", "static", "css", "style.css")
THEME_CSS = os.path.join(ROOT, "webui", "static", "css", "theme-cyberpunk.css")

REPORT_FNS = [
    "renderNetworkReport", "networkOverviewPane", "networkConnectionsPane", "networkDnsPane",
    "networkHttpPane", "networkTlsPane", "networkFilesPane", "networkIocsPane", "networkText",
    "networkTime", "networkHeader", "networkTypeChip", "networkFlags", "networkRowClass",
    "networkProcess", "networkDetail", "networkEmpty", "networkCut", "networkEventsOf",
    "networkUndecided", "networkStatusHtml", "networkFindingGroups", "networkFindingHtml",
    "networkFindingsHtml", "networkRuleHitsHtml", "networkEventTypesCard",
    "escapeHtml", "cssToken", "sortNumberValue", "severitySortValue", "formatSize",
    "evidenceClassLabel", "viewToggleHtml", "cardViewAttrs", "isTableView", "jsArg",
]
PANEL_FNS = REPORT_FNS + ["renderNetworkPanel", "networkReportOf", "networkEvidenceOf"]
CONSTS = ["NETWORK_SUBS", "NETWORK_ROWS_MAX", "NETWORK_ERRORS_SHOWN", "NETWORK_CONNECTION_TYPES",
          "networkState", "cardViewState", "ALERT_SEVERITIES"]


def _const(name):
    m = re.search(r"^const %s = .*?;\n" % re.escape(name), SOURCE, re.M | re.S)
    assert m, name
    return m.group(0)


PRELUDE = "\n".join(_const(c) for c in CONSTS)


def _index_html():
    with open(INDEX_HTML, encoding="utf-8") as fh:
        return fh.read()


def _tab_block(name):
    html = _index_html()
    start = html.index('id="tab-%s"' % name)
    end = html.index('<div class="tab-content"', start + 1)
    return html[start:end]


def _render(report, fns=REPORT_FNS):
    return _run_node(fns, "console.log(JSON.stringify(renderNetworkReport(%s)))" % json.dumps(report),
                     PRELUDE)


def _panel(results):
    return _run_node(PANEL_FNS, "console.log(JSON.stringify(renderNetworkPanel(%s)))" % json.dumps(results),
                     PRELUDE)


def _pane(html, name):
    m = re.search(r'<section class="net-pane" data-net-pane="%s"[^>]*>(.*?)</section>' % name, html, re.S)
    assert m, name
    return m.group(1)


def _empty_report(**over):
    base = {"events": [], "event_summary": {}, "iocs": [], "files": [], "rule_hits": [],
            "evidence_findings": [], "observed": True, "note": "", "truncated": False, "errors": [],
            "rule_unevaluated": [], "rule_budget_spent": False, "hash_budget_spent": False,
            "suppressed_count": 0}
    base.update(over)
    return base


def _details(html):
    """(summary, body) of every <details> block."""
    return [(m.group(1), m.group(2)) for m in
            re.finditer(r"<details[^>]*><summary>(.*?)</summary>(.*?)</details>", html, re.S)]


# --- the tab ------------------------------------------------------------------------------------

def test_the_tab_button_sits_between_pipes_and_sysmon():
    tabs = re.findall(r'data-tab="([a-z]+)"', _index_html())
    assert tabs[tabs.index("pipes") + 1] == "network"
    assert tabs[tabs.index("network") + 1] == "sysmon"


def test_the_tab_content_has_an_info_text():
    assert re.search(r'id="tab-network".*?<h2 data-info="[^"]{20,300}"', _index_html(), re.S)


def test_every_subtab_exists_and_fingerprint_does_not():
    block = _tab_block("network")
    subs = re.findall(r'data-net-sub="([a-z]+)"[^>]*>([^<]+)<', block)
    assert [label for _, label in subs] == ["OVERVIEW", "CONNECTIONS", "DNS", "HTTP", "TLS", "FILES", "IOCs"]
    assert "FINGERPRINT" not in block.upper()
    for name, _ in subs:
        assert "networkSetSub('%s')" % name in block


def test_switch_tab_loads_the_network_tab():
    assert "networkTabShown()" in _function_source("switchTab")


def test_the_help_has_the_tab_and_the_five_routes():
    html = _index_html()
    guide = html[html.index('id="help-usage"'):html.index('id="help-api"')]
    tabs = re.findall(r'data-tab="[^"]+">([^<]+)</button>', html)
    assert re.findall(r"<h4>([^<]+)</h4>", guide) == tabs
    api = html[html.index('id="help-api"'):]
    for route in ("import", "report", "reports", "baseline", "baseline/capture"):
        assert "<code>/api/network/%s</code>" % route in api, route


def test_the_style_sheets_and_the_script_are_versioned():
    html = _index_html()
    for href in re.findall(r'(?:href|src)="/static/(?:css|js)/[\w.-]+\?v=(\d+)"', html):
        assert int(href) >= 1
    assert len(re.findall(r'\?v=\d+"', html)) == 4


# --- rendering ----------------------------------------------------------------------------------

@needs_node
def test_a_report_renders_a_row_per_event():
    html = _render(_empty_report(
        events=[{"type": "http", "ts": 1, "dest": "evil.top", "method": "POST",
                 "path": "/gate.php", "url": "http://evil.top/gate.php", "process": "a.exe"},
                {"type": "dns", "ts": 2, "dest": "c2.example", "query_type": "A",
                 "answers": ["203.0.113.5"], "process": "a.exe"},
                {"type": "conn", "ts": 3, "dest": "203.0.113.5", "port": 443, "proto": "tcp",
                 "client_bytes": 10, "server_bytes": 2048, "duration": 1.5},
                {"type": "tls", "ts": 4, "dest": "c2.example", "sni": "c2.example", "port": 443,
                 "ja3_hash": "abc", "version": "TLS 1.2"}],
        event_summary={"http": 1, "dns": 1, "conn": 1, "tls": 1}))
    assert "evil.top" in _pane(html, "http") and "/gate.php" in _pane(html, "http")
    assert "203.0.113.5" in _pane(html, "dns") and "c2.example" in _pane(html, "dns")
    assert "203.0.113.5" in _pane(html, "connections") and "tcp" in _pane(html, "connections")
    assert "abc" in _pane(html, "tls")
    assert "evil.top" not in _pane(html, "dns")


@needs_node
def test_only_the_pane_of_the_chosen_sub_tab_is_shown():
    html = _render(_empty_report())
    shown = re.findall(r'data-net-pane="(\w+)"(?! hidden)[^>]*>', html)
    assert [s for s in shown if "hidden" not in re.search(r'data-net-pane="%s"[^>]*>' % s, html).group(0)] == ["overview"]
    assert html.count("<section") == 7


@needs_node
def test_event_fields_are_escaped():
    evil = "<img src=x onerror=alert(1)>"
    report = _empty_report(
        events=[{"type": "http", "ts": 1, "dest": evil, "process": evil, "url": evil, "method": evil,
                 "ua": evil, "headers": {"host": evil}, "resp_headers": {"location": evil}},
                {"type": "dns", "ts": 1, "dest": evil, "answers": [evil]},
                {"type": "tls", "ts": 1, "dest": evil, "sni": evil, "cert_subject": evil},
                {"type": "smtp", "ts": 1, "dest": evil, "mail_from": evil, "rcpt_to": [evil], "subject": evil}],
        event_summary={evil: 1},
        rule_hits=[{"rule_id": evil, "name": evil, "severity": evil, "process": evil, "count": 1,
                    "attack": [evil], "family": evil}],
        evidence_findings=[{"source": evil, "kind": evil, "label": evil, "detail": evil, "dest": evil,
                            "process": evil, "severity": evil, "evidence": evil}],
        iocs=[{"type": evil, "value": evil, "count": 1, "sources": [evil]}],
        files=[{"name": evil, "kind": evil, "dest": evil, "url": evil, "direction": evil}],
        errors=[evil], note=evil, filename=evil, rule_unevaluated=[{"rule_id": evil, "events": 1, "reasons": [evil]}])
    html = _render(report)
    assert "<img" not in html and "&lt;img" in html
    assert "onerror=alert(1)>" not in html.replace("&lt;img src=x onerror=alert(1)&gt;", "")


@needs_node
def test_headers_are_read_under_their_lower_case_keys():
    html = _render(_empty_report(
        events=[{"type": "http", "ts": 1, "dest": "203.0.113.5", "method": "GET", "url": "/",
                 "headers": {"host": "front.example", "Host": "WRONG"},
                 "resp_headers": {"location": "http://next.example/x", "Location": "WRONG"}, "hosts": []}],
        event_summary={"http": 1}))
    pane = _pane(html, "http")
    assert "front.example" in pane and "http://next.example/x" in pane and "WRONG" not in pane


@needs_node
def test_files_are_listed_by_name_and_never_offered():
    sha = "a" * 64
    html = _render(_empty_report(
        files=[{"name": sha + ".pe.bin", "sha256": sha, "kind": "pe", "size": 4096, "direction": "download",
                "dest": "evil.top", "path": "/a.exe", "hashed": "file", "count": 1}]))
    pane = _pane(html, "files")
    assert sha + ".pe.bin" in pane and "never written, opened or run" in pane
    assert "<a " not in pane and "href" not in pane and "download=" not in pane and "onclick" not in pane


@needs_node
def test_indicators_are_listed_with_what_they_are():
    html = _render(_empty_report(
        iocs=[{"type": "ip", "value": "203.0.113.5", "count": 2, "first_ts": 1, "sources": ["dns"], "public": True},
              {"type": "account", "value": "ftp://bob@evil.top", "count": 1, "sources": ["ftp"],
               "password_captured": True}], iocs_capped=True))
    pane = _pane(html, "iocs")
    assert "203.0.113.5" in pane and "public address" in pane and "password captured (masked)" in pane
    assert "capped" in pane


@needs_node
def test_an_event_the_baseline_knows_is_marked():
    html = _render(_empty_report(
        events=[{"type": "dns", "ts": 1, "dest": "ncsi.example", "baseline": "known"},
                {"type": "dns", "ts": 2, "dest": "other.example"}],
        event_summary={"dns": 2}, suppressed_count=1))
    pane = _pane(html, "dns")
    assert pane.count("BASELINE") == 1 and pane.count('class="net-known"') == 1
    assert "1 event(s)" in _pane(html, "overview")


@needs_node
def test_behaviour_events_are_connections():
    html = _render(_empty_report(
        events=[{"type": "beacon", "ts": 1, "dest": "evil.top", "interval": 60, "jitter": 0.02, "connections": 12},
                {"type": "retry", "ts": 2, "dest": "evil.top", "attempts": 9},
                {"type": "conn_failed", "ts": 3, "dest": "198.51.100.9", "attempts": 3, "refused": True}],
        event_summary={"beacon": 1, "retry": 1, "conn_failed": 1}))
    pane = _pane(html, "connections")
    assert "every 60s" in pane and "9 attempts" in pane and "refused" in pane


@needs_node
def test_a_long_table_is_cut_and_says_so():
    events = [{"type": "dns", "ts": i, "dest": "h%d.example" % i} for i in range(1200)]
    html = _render(_empty_report(events=events, event_summary={"dns": 1200}))
    pane = _pane(html, "dns")
    assert pane.count("<tr") == 1001 and "first 1000 of 1200" in pane


# --- what was not decided -----------------------------------------------------------------------

@needs_node
def test_an_empty_report_says_nothing_was_observed():
    html = _render(_empty_report(observed=False, note="no traffic"))
    overview = _pane(html, "overview")
    assert "no traffic" in overview and "NOT OBSERVED" in overview
    assert "NOTHING FOUND" not in overview
    assert "no traffic" in _pane(html, "dns")


@needs_node
def test_nothing_found_is_said_only_when_everything_was_decided():
    html = _render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a.example"}],
                                 event_summary={"dns": 1}))
    overview = _pane(html, "overview")
    assert "NOTHING FOUND" in overview and "COULD NOT DECIDE" not in overview


UNDECIDED = {
    "unevaluated": ({"rule_unevaluated": [{"rule_id": "net.body_regex", "events": 3, "reasons": ["timeout", "cut"]}]},
                    ["net.body_regex", "3 event(s)", "timeout, cut"]),
    "regex budget": ({"rule_budget_spent": True}, ["regex time budget"]),
    "hash budget": ({"hash_budget_spent": True}, ["hash budget"]),
    "truncated": ({"truncated": True}, ["capture was cut"]),
    "errors": ({"errors": ["net_decode on a http event to a.example: ValueError"]}, ["net_decode on a http event"]),
}


@needs_node
@pytest.mark.parametrize("case", sorted(UNDECIDED))
def test_each_undecided_condition_is_shown_and_is_not_nothing_found(case):
    over, texts = UNDECIDED[case]
    html = _render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a.example"}],
                                 event_summary={"dns": 1}, **over))
    overview = _pane(html, "overview")
    assert "COULD NOT DECIDE" in overview
    assert "NOTHING FOUND" not in overview
    for text in texts:
        assert text in overview, text


@needs_node
def test_a_clean_looking_report_with_a_failed_step_still_lists_it_beside_findings():
    html = _render(_empty_report(
        events=[{"type": "dns", "ts": 1, "dest": "a.example"}], event_summary={"dns": 1},
        evidence_findings=[{"source": "network", "kind": "c2_checkin", "label": "Check-in", "dest": "evil.top"}],
        errors=["a step failed"]))
    overview = _pane(html, "overview")
    assert "Check-in" in overview and "COULD NOT DECIDE" in overview and "a step failed" in overview


@needs_node
def test_only_the_first_errors_are_listed():
    html = _render(_empty_report(errors=["error number %d" % i for i in range(25)],
                                 events=[{"type": "dns", "ts": 1, "dest": "a"}]))
    overview = _pane(html, "overview")
    assert "error number 9" in overview and "error number 10" not in overview and "15 more failed step" in overview


# --- superseded is not baseline -----------------------------------------------------------------

FINDINGS = [
    {"source": "network", "kind": "exfil_upload", "label": "ACTIVE-ONE", "dest": "a.example", "evidence": "structural"},
    {"source": "network", "kind": "c2_beaconing", "label": "ABSORBED-ONE", "dest": "b.example",
     "superseded_by": "c2_checkin", "baseline": "new"},
    {"source": "network", "kind": "dns_noise", "label": "BASELINE-ONE", "dest": "c.example", "baseline": "known"},
]


@needs_node
def test_superseded_findings_are_not_listed_as_suppressed_by_the_baseline():
    html = _render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}], evidence_findings=FINDINGS))
    groups = _details(_pane(html, "overview"))
    assert len(groups) == 2
    by_summary = {s: b for s, b in groups}
    baseline = next(b for s, b in by_summary.items() if "suppressed by the baseline" in s)
    absorbed = next(b for s, b in by_summary.items() if "superseded by another finding" in s)
    assert "BASELINE-ONE" in baseline and "ABSORBED-ONE" not in baseline
    assert "ABSORBED-ONE" in absorbed and "BASELINE-ONE" not in absorbed
    assert "superseded by c2_checkin" in absorbed
    overview = _pane(html, "overview")
    assert overview.index("ACTIVE-ONE") < overview.index("<details")
    assert "1 finding(s) suppressed by the baseline" in overview


@needs_node
def test_a_superseded_finding_that_also_says_baseline_is_still_superseded():
    both = [{"source": "network", "kind": "c2_beaconing", "label": "BOTH", "superseded_by": "c2_checkin",
             "baseline": "known"}]
    groups = _details(_pane(_render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}],
                                                  evidence_findings=both)), "overview"))
    assert [s for s, _ in groups if "baseline" in s] == []
    assert len(groups) == 1 and "superseded" in groups[0][0]


@needs_node
def test_the_memory_evidence_block_keeps_superseded_apart_from_the_baseline():
    ev = {"label": "SUSPICIOUS", "score": 3.0, "findings": [], "suppressed_count": 1, "superseded_count": 1,
          "suppressed": [{"label": "KNOWN-ONE", "source": "aether", "baseline": "known"},
                         {"label": "ABSORBED-ONE", "source": "sysmon-network", "superseded_by": "c2_checkin"}]}
    html = _run_node(["renderMemoryEvidence", "escapeHtml", "evidenceClassLabel", "confidenceClass"],
                     "console.log(JSON.stringify(renderMemoryEvidence(%s)))" % json.dumps(ev))
    groups = dict(_details(html))
    baseline = next(b for s, b in groups.items() if "suppressed by the host baseline" in s)
    absorbed = next(b for s, b in groups.items() if "superseded by another finding" in s)
    assert "KNOWN-ONE" in baseline and "ABSORBED-ONE" not in baseline
    assert "ABSORBED-ONE" in absorbed and "KNOWN-ONE" not in absorbed


# --- network is a source of its own -------------------------------------------------------------

@needs_node
def test_network_findings_carry_their_own_source_chip():
    html = _render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}], evidence_findings=FINDINGS[:1]))
    assert '<span class="mem-chip">network</span>' in _pane(html, "overview")


@needs_node
def test_the_verdict_flow_draws_the_network_source_as_a_kind_of_its_own():
    r = _run_node(["_verdictFlowKind"], r"""
        console.log(JSON.stringify([_verdictFlowKind('network'), _verdictFlowKind('sysmon-network'),
                                    _verdictFlowKind('aether'), _verdictFlowKind(undefined)]));""",
                  _const("VERDICT_FLOW_SOURCES"))
    assert r == ["capture", "network", "memory", "memory"]
    kinds = re.search(r"const VERDICT_FLOW_KINDS = \[(.*?)\];", SOURCE, re.S).group(1)
    assert "key: 'capture'" in kinds and "network capture" in kinds


@needs_node
def test_the_panel_takes_the_scored_network_findings_of_the_memory_evidence():
    results = {"network": _empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}],
                                        evidence_findings=[{"source": "network", "label": "RAW-ONE"}]),
               "memory_evidence": {"findings": [{"source": "aether", "label": "MEMORY-ONE", "score": 1.0},
                                                {"source": "network", "label": "SCORED-ONE", "score": 2.5}],
                                   "suppressed": [{"source": "network", "label": "ABSORBED-ONE",
                                                   "superseded_by": "c2_checkin"},
                                                  {"source": "network", "label": "KNOWN-ONE", "baseline": "known"}]}}
    html = _panel(results)
    assert "SCORED-ONE" in html and "2.50" in html
    assert "MEMORY-ONE" not in html and "RAW-ONE" not in html
    groups = dict(_details(html))
    assert "ABSORBED-ONE" in next(b for s, b in groups.items() if "superseded" in s)
    assert "KNOWN-ONE" in next(b for s, b in groups.items() if "suppressed by the baseline" in s)


# --- the panel in the Submit tab ----------------------------------------------------------------

def test_the_submit_results_call_the_panel():
    src = _function_source("renderDetonationPanels")
    assert "renderNetworkPanel(" in src and "tabs.push" in src[src.index("renderNetworkPanel("):]
    assert "det-tab-network" in src
    assert src.index("renderNetworkPanel(") < src.index("det-tab-raw"), "the panel comes before Raw JSON"
    assert re.search(r"data\.network\s*\?\s*networkReportOf\(data\)", src), "results without a report call nothing"


@needs_node
def test_the_panel_is_empty_without_a_report_and_says_what_the_report_holds():
    assert _panel({}) == "" and _panel({"network": None}) == "" and _panel({"network": "x"}) == ""
    html = _panel({"network": _empty_report(
        id="f" * 32, events=[{"type": "dns", "ts": 1, "dest": "a"}], event_summary={"dns": 1},
        iocs=[{"type": "domain", "value": "evil.top", "count": 3}], rule_budget_spent=True)})
    assert "evil.top" in html and "COULD NOT DECIDE" in html
    assert "networkOpenReport(&quot;%s&quot;)" % ("f" * 32) in html


@needs_node
def test_the_panel_for_an_unobserved_capture_says_so():
    assert "NOT OBSERVED" in _panel({"network": _empty_report(observed=False, note="no traffic")})


# --- tables, charts, colours --------------------------------------------------------------------

FULL = _empty_report(
    events=[{"type": "http", "ts": 1, "dest": "a", "method": "GET"}, {"type": "dns", "ts": 2, "dest": "b"},
            {"type": "conn", "ts": 3, "dest": "c"}, {"type": "tls", "ts": 4, "dest": "d"}],
    event_summary={"http": 1, "dns": 1, "conn": 1, "tls": 1},
    rule_hits=[{"rule_id": "net.x", "name": "X", "severity": "high", "count": 1}],
    iocs=[{"type": "domain", "value": "a", "count": 1}],
    files=[{"name": "n.pe.bin", "kind": "pe", "size": 1, "direction": "download"}])


@needs_node
def test_the_tables_are_sortable():
    html = _render(FULL)
    tables = re.findall(r"<table\b[^>]*>", html)
    assert len(tables) >= 8
    ids = []
    for tag in tables:
        assert re.search(r"\sdata-sortable(?=[\s>])", tag), tag
        found = re.search(r'\sdata-sort-id="([a-z0-9-]+)"', tag)
        assert found, tag
        ids.append(found.group(1))
    assert len(set(ids)) == len(ids)


@needs_node
def test_the_event_chart_has_a_chart_and_a_table_view_and_the_switch():
    html = _render(FULL)
    overview = _pane(html, "overview")
    assert 'class="view-toggle"' in overview and 'data-view-toggle="network-events"' in overview
    assert 'data-view-of="network-events" data-view="chart"' in overview
    assert re.search(r'data-view-of="network-events" data-view="table" hidden', overview)
    bars = re.findall(r'class="net-bar-count">(\d+)<', overview)
    table = re.search(r'data-sort-id="net-event-types".*?</table>', overview, re.S).group(0)
    assert sorted(bars) == sorted(re.findall(r'data-sort-value="(\d+)"', table))


@needs_node
def test_an_empty_summary_draws_no_chart():
    assert "net-chart-card" not in _pane(_render(_empty_report()), "overview")


def _network_source():
    names = re.findall(r"^(?:async )?function (network\w+|renderNetwork\w+)\(", SOURCE, re.M)
    assert len(names) > 20
    return "\n".join(_function_source(n) for n in names)


def test_colours_come_from_theme_variables_only():
    src = _network_source() + "\n".join(_const(c) for c in CONSTS[:5])
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsl\(", src)
    assert "style=\"" not in re.sub(r'style="width:\$\{[^}]*\}%"', "", src), "an inline style beyond the bar width"


def test_the_helpers_of_the_render_functions_are_all_listed_for_the_node_tests():
    """Each helper the rendering calls must be in REPORT_FNS / PANEL_FNS: a missing one is a
    ReferenceError only in these tests, so the list is checked against the source."""
    defined = set(re.findall(r"^function (\w+)\(", SOURCE, re.M))
    seen, todo = set(), ["renderNetworkReport", "renderNetworkPanel"]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        # the name of an inline handler is no call of this script (its arguments are)
        body = re.sub(r'\bon[a-z]+="[A-Za-z_]\w*\(', 'onX="(', _function_source(name))
        todo += [c for c in re.findall(r"\b([A-Za-z_]\w*)\(", body) if c in defined and c != name]
    assert seen <= set(PANEL_FNS), sorted(seen - set(PANEL_FNS))


def test_the_event_colours_are_defined_in_both_themes():
    with open(STYLE_CSS, encoding="utf-8") as fh:
        style = fh.read()
    with open(THEME_CSS, encoding="utf-8") as fh:
        theme = fh.read()
    root = style[style.index(":root {"):style.index("\n}", style.index(":root {"))]
    used = set(re.findall(r"var\((--net-[\w-]+)\)", style))
    assert used
    for name in used:
        assert re.search(r"%s:\s*#[0-9a-fA-F]{6};" % re.escape(name), root), "%s in style.css :root" % name
        assert re.search(r"%s:\s*var\(--cp-[\w-]+\);" % re.escape(name), theme), "%s in theme-cyberpunk.css" % name


# --- the controls -------------------------------------------------------------------------------

@needs_node
def test_a_sub_tab_switches_the_panes_and_the_buttons():
    r = _run_node(["networkSetSub"], r"""
        const mk = (attr, value) => ({ attrs: { [attr]: value }, hidden: false,
            getAttribute(n) { return this.attrs[n]; }, setAttribute(n, v) { this.attrs[n] = v; } });
        const buttons = NETWORK_SUBS.map(n => mk('data-net-sub', n));
        const panes = NETWORK_SUBS.map(n => mk('data-net-pane', n));
        globalThis.document = { querySelectorAll: sel => sel.includes('data-net-sub') ? buttons : panes };
        networkSetSub('dns');
        networkSetSub('nonsense');
        console.log(JSON.stringify({ sub: networkState.sub,
            pressed: buttons.filter(b => b.attrs['aria-pressed'] === 'true').map(b => b.attrs['data-net-sub']),
            shown: panes.filter(p => !p.hidden).map(p => p.attrs['data-net-pane']) }));
    """, PRELUDE)
    assert r == {"sub": "dns", "pressed": ["dns"], "shown": ["dns"]}


@needs_node
def test_the_tab_loads_its_reports_each_time_and_the_baseline_once():
    r = _run_node(["networkTabShown"], r"""
        const calls = [];
        function networkRefreshBaseline() { calls.push('baseline'); }
        function networkRefreshReports() { calls.push('reports'); }
        networkTabShown(); networkTabShown();
        console.log(JSON.stringify(calls));
    """, PRELUDE)
    assert r == ["baseline", "reports", "reports"]
