"""The NETWORK tab: the report of a pcap in the web UI (app.js, index.html, the style sheets).

Regressions covered:
  * a tab nobody can reach: the button between PIPES and SYSMON, the (i) text, the seven
    sub-tabs (no FINGERPRINT yet), the switch that loads it, the help entry and the routes
  * a value of a capture (name, URL, process, rule name, finding, indicator, file name, error)
    reaching the markup unescaped; a header read under its capitalised name (the masked report
    has lower-case keys); a file offered as a link
  * "could not decide" shown as "nothing found": a rule left undecided, a spent regex, hash or
    text budget, a capture past its event cap (events_capped), a cut capture and a failed step
    each need their own say in OVERVIEW; a capture without
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
    "networkProcess", "networkDetail", "networkEmpty", "networkCut", "networkEventsOf", "networkEventCount",
    "networkUndecided", "networkStatusHtml", "networkFindingGroups", "networkFindingHtml",
    "networkFindingsHtml", "networkRuleHitsHtml", "networkEventTypesCard",
    "escapeHtml", "cssToken", "sortNumberValue", "severitySortValue", "formatSize",
    "evidenceClassLabel", "viewToggleHtml", "cardViewAttrs", "isTableView", "jsArg",
]
RACE_FNS = ["networkOpenReport", "networkTabShown", "networkRefreshReports", "networkSelectReport",
            "networkRefreshBaseline", "networkFillSelect", "networkText", "networkJson", "networkShowReport",
            "networkFindingGroups"]
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


def test_the_assets_carry_a_version_query():
    """Only that the four assets have a ?v= (a bump itself is not testable here: it is a diff)."""
    html = _index_html()
    assert len(re.findall(r'/static/(?:css|js)/[\w.-]+\?v=\d+"', html)) == 4


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
    "events capped": ({"events_capped": True, "max_events": 20000}, ["more than 20000 events", "report is cut"]),
    "text budget": ({"text_budget_spent": True}, ["text budget"]),
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


# --- stale answers, error bodies, counts --------------------------------------------------------

def _race(delays, action, reports=("NEWEST", "RUN"), fail=(), wait=250, html_error=()):
    """Runs `action` against a fetch whose answers arrive after delays[key] ms; the result is the
    state after everything arrived and the messages shown."""
    script = r"""
        const delays = %s, FAIL = %s, HTML = %s;
        globalThis.fetch = url => new Promise(resolve => {
            let key = url, body = {};
            if (url === '/api/network/reports') body = { reports: %s.map(id => ({ id })) };
            else if (url === '/api/network/baseline') body = { total: 0 };
            else { key = decodeURIComponent(url.split('id=')[1]); body = { id: key, events: [] }; }
            const bad = FAIL.includes(key), html = HTML.includes(key);
            setTimeout(() => resolve({ ok: !bad && !html, status: html ? 502 : (bad ? 404 : 200),
                json: async () => { if (html) throw new SyntaxError("Unexpected token '<'");
                                    return bad ? { error: 'no such report' } : body; } }), delays[key] || 1);
        });
        const messages = [];
        globalThis.document = { getElementById: () => null, querySelectorAll: () => [] };
        function networkMessage(text, isError) { messages.push([text, !!isError]); }
        function renderNetworkReport() { return ''; }
        function networkSetSub() {}
        function switchTab(name) { if (name === 'network') networkTabShown(); }
        %s
        setTimeout(() => console.log(JSON.stringify({ id: networkState.id, want: networkState.want,
            pending: networkState.pending, messages })), %d);
    """ % (json.dumps(delays), json.dumps(list(fail)), json.dumps(list(html_error)), json.dumps(list(reports)), action, wait)
    return _run_node(RACE_FNS, script, PRELUDE)


@needs_node
def test_opening_a_report_from_the_panel_is_not_overwritten_by_the_first_report_of_the_list():
    """The reproduction: the list arrives first (5 ms), the report asked for next (15 ms), the newest
    report the list would pick last (30 ms)."""
    r = _race({"/api/network/reports": 5, "RUN": 15, "NEWEST": 30}, "networkOpenReport('RUN');")
    assert r["id"] == "RUN" and r["want"] == "RUN" and r["pending"] is False


@needs_node
@pytest.mark.parametrize("list_delay", [1, 5, 25, 60])
def test_the_report_asked_for_wins_whatever_arrives_when(list_delay):
    r = _race({"/api/network/reports": list_delay, "RUN": 20, "NEWEST": 10}, "networkOpenReport('RUN');")
    assert r["id"] == "RUN"


@needs_node
def test_the_first_report_is_picked_when_none_was_asked_for():
    r = _race({"/api/network/reports": 5}, "networkTabShown();")
    assert r["id"] == "NEWEST"


@needs_node
@pytest.mark.parametrize("delays", [{"A": 40, "B": 5}, {"A": 5, "B": 40}, {"A": 5, "B": 5}])
def test_quick_changes_of_the_select_show_the_last_one(delays):
    r = _race(delays, "networkSelectReport('A'); networkSelectReport('B');", reports=("A", "B"))
    assert r["id"] == "B" and r["pending"] is False


@needs_node
def test_a_late_failure_of_an_older_request_neither_shows_nor_hides_the_newer_report():
    r = _race({"A": 40, "B": 5}, "networkSelectReport('A'); networkSelectReport('B');", reports=("A", "B"),
              fail=("A",))
    assert r["id"] == "B" and r["messages"] == [["", False]]


@needs_node
def test_a_failed_request_is_said_and_lets_the_list_pick_again():
    r = _race({}, "networkSelectReport('GONE');", fail=("GONE",))
    assert r["id"] == "" and r["pending"] is False
    assert r["messages"][-1] == ["The report could not be loaded: no such report", True]


@needs_node
def test_an_error_body_that_is_no_json_reads_as_its_status():
    r = _race({}, "networkSelectReport('PROXY');", html_error=("PROXY",))
    assert r["messages"][-1] == ["The report could not be loaded: HTTP 502", True]
    assert "Unexpected token" not in json.dumps(r)


@needs_node
def test_every_fetch_of_the_tab_reads_its_answer_through_networkjson():
    block = "\n".join(_function_source(n) for n in re.findall(r"^(?:async )?function (network\w+)\(", SOURCE, re.M)
                      if n != "networkJson")
    assert "resp.json()" not in block and block.count("networkJson(resp)") == 5


@needs_node
def test_events_with_lists_that_are_not_lists_do_not_say_undefined():
    html = _render(_empty_report(
        events=[{"type": "ftp", "ts": 1, "dest": "a", "commands": "USER", "files": None},
                {"type": "websocket", "ts": 2, "dest": "b", "messages": "abc"}],
        event_summary={"ftp": 1, "websocket": 1}))
    pane = _pane(html, "connections")
    assert "0 command(s)" in pane and "0 file(s)" in pane and "0 message(s)" in pane
    assert "undefined" not in pane and "NaN" not in pane


ALL_OUT = [{"source": "network", "kind": "exfil_upload", "label": "KNOWN-ONE", "baseline": "known"},
           {"source": "network", "kind": "c2_beaconing", "label": "ABSORBED-ONE", "superseded_by": "c2_checkin"}]


@needs_node
def test_the_overview_counts_only_active_findings_and_says_when_all_are_out():
    html = _render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}], evidence_findings=ALL_OUT))
    overview = _pane(html, "overview")
    assert "NO ACTIVE FINDING" in overview and "All 2 finding(s) are suppressed by the baseline or superseded" in overview
    assert "NOTHING FOUND" not in overview
    assert '<span class="mem-chip-val">0</span>findings' in overview
    assert "FINDINGS (" not in overview


@needs_node
def test_all_findings_out_and_something_undecided_says_both():
    html = _render(_empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}], evidence_findings=ALL_OUT,
                                 rule_budget_spent=True))
    overview = _pane(html, "overview")
    assert "COULD NOT DECIDE" in overview and "none counts" in overview and "NOTHING FOUND" not in overview


@needs_node
def test_the_panel_banner_and_chips_use_the_same_findings():
    results = {"network": _empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}],
                                        evidence_findings=[{"source": "network", "label": "RAW-ONE"}]),
               "memory_evidence": {"findings": [], "suppressed": [dict(f, source="network") for f in ALL_OUT]}}
    html = _panel(results)
    assert '<span class="mem-chip-val">0</span>findings' in html
    assert '<span class="mem-chip-val">2</span>suppressed or superseded' in html
    assert "NO ACTIVE FINDING" in html and "NOTHING FOUND" not in html and "RAW-ONE" not in html
    clean = _panel({"network": _empty_report(events=[{"type": "dns", "ts": 1, "dest": "a"}])})
    assert "NOTHING FOUND" in clean and "suppressed or superseded" not in clean


# --- the Tracing sub-tabs (Task 16) -------------------------------------------------------------
#
# Regressions covered:
#   * HTTP REQUESTS was a guess from ports 80/443 even when a network report held the real requests;
#     CONNECTIONS and DNS REQUESTS showed no event of a report; there was no TLS sub-tab
#   * the capture's events shown as if the selected process had made them (a pcap knows no process)
#   * a failed connection listed like one that was made
#   * without a report the port guess and the agent's counts must still work
#   * a value of a capture reaching the Tracing markup unescaped; a header read under its capitalised name

RTRACE_FNS = [
    "renderRtraceDetailTabs", "renderRtraceEventTable", "rtraceNetworkEvents", "rtraceNetworkRows",
    "rtraceNetworkDetail", "rtraceNetworkSortValue", "networkText", "networkTime", "networkHeader",
    "networkDetail", "networkFlags", "networkEmpty", "networkCut", "formatSize", "sortNumberValue",
    "compareSortValues", "compareSortKeys", "sortKey", "sortItemsBy", "escapeHtml", "cssToken", "jsArg",
    "formatRelativeTime", "formatTime", "rtraceEventAction", "rtraceEventSortValue", "getActionBadgeClass",
    "getEventDetails", "severitySortValue", "sortTimeValue", "alertSeverity",
]
RTRACE_CONSTS = ["RTRACE_DETAIL_TABS", "RTRACE_NETWORK_TYPES", "NETWORK_ROWS_MAX", "tableSortState",
                 "RTRACE_EVENT_SORT_ID", "SORT_COLLATOR", "ALERT_SEVERITIES"]


def _rtrace_prelude():
    return "\n".join(_const(c) for c in RTRACE_CONSTS)


def _tabs(state):
    return _run_node(RTRACE_FNS, "console.log(JSON.stringify(renderRtraceDetailTabs(%s)))"
                     % json.dumps(state), _rtrace_prelude())


def _rows(kind, state):
    return _run_node(RTRACE_FNS, "console.log(JSON.stringify(renderRtraceEventTable(%s, %s)))"
                     % (json.dumps(kind), json.dumps(state)), _rtrace_prelude())


def _tab_counts(html):
    return dict(re.findall(r'data-rtab="([a-z]+)"[^>]*>[^<]*<span class="rtrace-tab-count">([^<]*)<', html))


@needs_node
def test_the_http_subtab_counts_real_http_events():
    out = _tabs({"network": [{"type": "http", "path": "/a"}, {"type": "http", "path": "/b"}]})
    assert "HTTP REQUESTS" in out and ">2<" in out


@needs_node
def test_the_http_subtab_prefers_real_events_over_the_port_heuristic():
    out = _rows("http", {"network": [{"type": "http", "dest": "evil.top", "path": "/gate.php"}],
                         "events": [{"raw": {"dest_port": 443, "dest_ip": "203.0.113.9"}}]})
    assert "/gate.php" in out and "203.0.113.9" not in out


@needs_node
def test_without_a_report_the_old_heuristic_still_works():
    out = _rows("http", {"events": [{"raw": {"dest_port": 443, "dest_ip": "203.0.113.9"}}]})
    assert "203.0.113.9" in out


@needs_node
def test_a_tls_subtab_exists_and_counts_tls_events():
    assert "TLS" in _tabs({"network": [{"type": "tls", "sni": "a.top"}]})


NET_EVENTS = [
    {"type": "http", "ts": 3, "dest": "evil.top", "port": 80, "method": "POST", "path": "/gate.php", "status": 200},
    {"type": "conn", "ts": 1, "dest": "203.0.113.5", "port": 443, "proto": "tcp", "client_bytes": 10, "server_bytes": 20},
    {"type": "conn_failed", "ts": 2, "dest": "198.51.100.7", "port": 4444, "attempts": 3, "refused": True},
    {"type": "udp", "ts": 4, "dest": "198.51.100.8", "port": 1900, "answered": False},
    {"type": "dns", "ts": 0.5, "dest": "evil.top", "query_type": "A", "answers": ["203.0.113.5"]},
    {"type": "dns", "ts": 0.6, "dest": "gone.top", "query_type": "A", "nxdomain": True},
    {"type": "tls", "ts": 5, "dest": "203.0.113.5", "port": 443, "sni": "cdn.top", "version": "TLS 1.2",
     "ja3_hash": "e7d705a3286e19ea42f587b344ee6865"},
    {"type": "beacon", "ts": 6, "dest": "evil.top", "interval": 60},
]


@needs_node
def test_each_network_subtab_counts_its_own_event_types():
    """CONNECTIONS is conn, conn_failed and udp (a beacon or an http request is no connection row);
    DNS REQUESTS the dns events; the other sub-tabs keep the agent's counts."""
    html = _tabs({"network": NET_EVENTS, "activity": {"http": 9, "network": 9, "dns": 9, "file": 4, "registry": 2}})
    assert _tab_counts(html) == {"http": "1", "connections": "3", "dns": "2", "tls": "1", "files": "4",
                                 "registry": "2", "artifacts": "0", "modules": "0"}
    assert "1 failed" in html and "not attributed to a process" in html


@needs_node
def test_without_a_report_the_tabs_keep_the_agents_counts():
    html = _tabs({"activity": {"http": 5, "network": 7, "dns": 3}, "tab": "dns"})
    counts = _tab_counts(html)
    assert counts["http"] == "5" and counts["connections"] == "7" and counts["dns"] == "3" and counts["tls"] == "0"
    assert re.search(r'class="rtrace-tab active" data-rtab="dns"', html)
    assert "not attributed" not in html


@needs_node
def test_the_tab_bar_is_the_one_of_the_page():
    """The bar drawn with counts has the buttons, labels and order of index.html (TLS among them)."""
    drawn = re.findall(r'data-rtab="([a-z]+)"[^>]*>([A-Z ]+)', _tabs({}))
    html = _index_html()
    bar = html[html.index('id="rtrace-detail-tabs"'):]
    bar = bar[:bar.index("</div>")]
    static = re.findall(r'data-rtab="([a-z]+)"[^>]*>([A-Z ]+)', bar)
    assert [(k, v.strip()) for k, v in drawn] == [(k, v.strip()) for k, v in static]
    assert ("tls", "TLS") in [(k, v.strip()) for k, v in static]
    assert re.search(r'class="rtrace-tab active" data-rtab="live"', bar), "the page marks another tab than the state's"


@needs_node
def test_the_connection_rows_show_a_failed_connection_apart_and_say_they_are_capture_wide():
    out = _rows("connections", {"network": NET_EVENTS, "networkSource": "detonation",
                                "networkReport": {"filename": "run.pcap"}})
    rows = out.split('<div class="rtrace-event-row')[1:]
    assert len(rows) == 3
    assert "198.51.100.7:4444" in rows[1] and "rtrace-net-failed" in rows[1] and "conn failed" in rows[1]
    assert "rtrace-net-failed" not in rows[0] + rows[2]
    assert "refused" in rows[1] and "3 attempt(s)" in rows[1]
    assert "not attributed to a process" in out and "this detonation" in out and "run.pcap" in out
    assert all("not attributed" in r and "\u2014" in r for r in rows), "a pcap row given a process"
    assert "openAlertDetailById" not in out and "focusProcessGraph" not in out


@needs_node
def test_the_rows_name_the_network_tab_when_the_report_is_from_there():
    out = _rows("dns", {"network": NET_EVENTS, "networkSource": "network-tab"})
    assert "NETWORK tab" in out and "NXDOMAIN" in out and "203.0.113.5" in out
    assert out.index("evil.top") < out.index("gone.top"), "not in time order"


@needs_node
def test_the_tls_rows_show_the_server_name_and_fingerprint():
    out = _rows("tls", {"network": NET_EVENTS})
    assert "cdn.top" in out and "TLS 1.2" in out and "e7d705a3286e19ea42f587b344ee6865" in out


@needs_node
def test_a_report_without_events_of_a_kind_says_so_and_does_not_guess():
    alerts = [{"raw": {"dest_port": 443, "dest_ip": "203.0.113.9"}}]
    out = _rows("http", {"network": [{"type": "dns", "dest": "a"}], "networkReport": {}, "events": alerts})
    assert "No HTTP requests in this capture." in out and "203.0.113.9" not in out
    unobserved = _rows("dns", {"network": [], "networkReport": {"observed": False, "note": "no packets"},
                               "events": alerts})
    assert "Not observed: no packets" in unobserved


@needs_node
def test_tls_without_a_report_points_to_the_network_tab():
    out = _rows("tls", {"events": [{"raw": {"dest_port": 443, "dest_ip": "203.0.113.9"}}]})
    assert "NETWORK tab" in out and "203.0.113.9" not in out


@needs_node
def test_the_tracing_rows_escape_every_value_of_the_capture():
    evil = '<img src=x onerror="alert(1)">'
    events = [{"type": "http", "dest": evil, "method": evil, "path": evil, "status": evil,
               "headers": {"host": evil}},
              {"type": "tls", "sni": evil, "version": evil, "alpn": evil, "ja3_hash": evil},
              {"type": "dns", "dest": evil, "query_type": evil, "answers": [evil]},
              {"type": "conn_failed", "dest": evil, "port": evil, "attempts": evil, "pid": evil, "process": evil}]
    report = {"filename": evil}
    for kind in ("http", "tls", "dns", "connections"):
        out = _rows(kind, {"network": events, "networkReport": report})
        assert "<img" not in out and "&lt;img" in out, kind
    assert "<img" not in _tabs({"network": events})


@needs_node
def test_the_host_header_is_read_under_its_lower_case_key():
    out = _rows("http", {"network": [{"type": "http", "dest": "203.0.113.5", "path": "/", "headers": {"host": "fake.top"}},
                                     {"type": "http", "dest": "203.0.113.6", "path": "/",
                                      "headers": {"Host": "capital.top"}}]})
    assert "Host: fake.top" in out and "capital.top" not in out


def test_the_tracing_helpers_are_all_listed_for_the_node_tests():
    """A helper missing from RTRACE_FNS is a ReferenceError only in these tests."""
    defined = set(re.findall(r"^function (\w+)\(", SOURCE, re.M))
    seen, todo = set(), ["renderRtraceDetailTabs", "renderRtraceEventTable"]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        body = re.sub(r'\bon[a-z]+="[A-Za-z_]\w*\(', 'onX="(', _function_source(name))
        # a call after event.stopPropagation(); inside a handler is no call of this script either
        body = re.sub(r'event\.stopPropagation\(\); [A-Za-z_]\w*\(', '(', body)
        todo += [c for c in re.findall(r"\b([A-Za-z_]\w*)\(", body) if c in defined and c != name]
    assert seen <= set(RTRACE_FNS), sorted(seen - set(RTRACE_FNS))


def test_the_tracing_functions_take_colours_from_theme_variables_only():
    src = "\n".join(_function_source(n) for n in ("renderRtraceDetailTabs", "renderRtraceEventTable",
                                                  "rtraceNetworkRows", "rtraceNetworkDetail", "showRtraceEventTable"))
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsl\(", re.sub(r"&#\d+;", "", src))


STATE_FNS = ["rtraceState", "networkReportOf", "rtraceReportEvents", "rtraceFetchReportEvents", "networkJson"]


def _state_of(detonation, network_tab):
    return _run_node(STATE_FNS, r"""
        globalThis.state = { processes: { '7': { pid: 7, alerts: [{ id: 'a' }], children: ['8'], activity: { dns: 2 } },
                                          '8': { pid: 8, alerts: [{ id: 'b' }] } },
                             rtraceSelectedPid: 7, rtraceActiveDetailTab: 'dns', detonationNetwork: DET };
        networkState.report = TAB;
        const v = rtraceState();
        console.log(JSON.stringify({ events: v.events.map(e => e.id), tab: v.tab, activity: v.activity,
                                     network: v.network === undefined ? null : v.network.map(e => e.dest),
                                     source: v.networkSource || null }));
    """.replace("DET", json.dumps(detonation)).replace("TAB", json.dumps(network_tab)),
        _const("networkState"))


@needs_node
def test_the_detonations_report_wins_over_the_one_open_in_the_network_tab():
    det = {"events": [{"type": "dns", "dest": "det.top"}]}
    tab = {"events": [{"type": "dns", "dest": "tab.top"}]}
    both = _state_of(det, tab)
    assert both == {"events": ["a", "b"], "tab": "dns", "activity": {"dns": 2}, "network": ["det.top"],
                    "source": "detonation"}
    assert _state_of(None, tab)["network"] == ["tab.top"] and _state_of(None, tab)["source"] == "network-tab"
    assert _state_of(None, None)["network"] is None and _state_of({"nonsense": 1}, None)["network"] is None


def test_the_detonation_results_hand_their_report_to_tracing():
    for name in ("renderDetonationPanels", "viewDetonationResult"):
        assert re.search(r"state\.detonationNetwork = .*networkReportOf\(data\)", _function_source(name)), name



# --- the eventless report of the poll, the sample field (Rulings 66, 67) ------------------------
#
# Regressions covered:
#   * the detonation results carried every event of the report on every 5 s poll; they now send
#     event_count instead, and the Submit panel must count from it
#   * Tracing needs the events: fetched once per report id, not on every render or poll
#   * the import had no way to tie a capture to the detonated sample

@needs_node
def test_the_panel_works_from_the_eventless_copy_of_the_poll():
    html = _panel({"network": {"id": "a" * 32, "event_count": 7, "observed": True, "event_summary": {"dns": 7},
                               "evidence_findings": [], "rule_hits": [], "iocs": [], "files": []}})
    assert '<span class="mem-chip-val">7</span>events' in html
    assert "NOTHING FOUND" in html and "7 event(s) were evaluated" in html


@needs_node
def test_tracing_fetches_the_events_of_a_report_once_per_id():
    r = _run_node(STATE_FNS + ["renderRtraceDetailTabs", "renderRtraceEventTable", "rtraceNetworkEvents",
                               "rtraceNetworkRows", "escapeHtml", "networkText"], r"""
        (async () => {
            const fetched = [];
            const answers = { ['a'.repeat(32)]: { events: [{ type: 'dns', dest: 'evil.top' }, { type: 'dns', dest: 'b.top' }] } };
            globalThis.fetch = url => {
                fetched.push(url);
                const id = new URL(url, 'http://x').searchParams.get('id');
                return Promise.resolve(answers[id]
                    ? { ok: true, status: 200, json: async () => answers[id] }
                    : { ok: false, status: 404, json: async () => ({ error: 'no such report' }) });
            };
            const redraws = [];
            globalThis.showRtraceDetailTabs = () => redraws.push('tabs');
            globalThis.showRtraceEventTable = () => redraws.push('rows');
            globalThis.networkEmpty = () => 'EMPTY';
            const det = id => ({ id, observed: true, event_summary: { dns: 2, http: 1 } });
            globalThis.state = { processes: { '7': { pid: 7, alerts: [] } }, rtraceSelectedPid: '7', activeTab: 'tracing',
                                 rtraceActiveDetailTab: 'dns', detonationNetwork: det('a'.repeat(32)) };
            const first = rtraceState();
            const r = { pending: first.networkPending, loadingRows: renderRtraceEventTable('dns', first),
                        pendingTabs: renderRtraceDetailTabs(first) };
            rtraceState(); rtraceState();
            await new Promise(res => setImmediate(res));
            const ready = rtraceState();
            r.ready = [ready.networkPending || null, ready.network.map(e => e.dest)];
            r.redraws = redraws.slice();
            state.detonationNetwork = det('b'.repeat(32));
            rtraceState();
            await new Promise(res => setImmediate(res));
            const failed = rtraceState(); rtraceState();
            r.failed = [failed.networkPending, renderRtraceEventTable('dns', failed)];
            state.detonationNetwork = det('a'.repeat(32));
            rtraceState();
            r.fetched = fetched;
            console.log(JSON.stringify(r));
        })();
    """, _const("networkState") + "\n" + "\n".join(_const(c) for c in (
        "rtraceNetworkFetched", "RTRACE_NETWORK_FETCHED_MAX", "RTRACE_NETWORK_RETRY_MS", "RTRACE_DETAIL_TABS",
        "RTRACE_NETWORK_TYPES"))
        + "\nconst NETWORK_ROWS_MAX = 1000;")
    assert r["pending"] == "loading" and "Loading the events" in r["loadingRows"]
    assert _tab_counts(r["pendingTabs"])["dns"] == "2" and _tab_counts(r["pendingTabs"])["http"] == "1", \
        "while the events load, the counts come from the event summary"
    assert r["ready"] == [None, ["evil.top", "b.top"]] and r["redraws"] == ["tabs", "rows"]
    assert r["failed"][0] == "failed" and "could not be loaded" in r["failed"][1]
    assert r["fetched"] == ["/api/network/report?id=" + "a" * 32, "/api/network/report?id=" + "b" * 32], \
        "a report's events were fetched more than once"


def test_the_import_form_has_the_optional_sample_field():
    bar = _tab_block("network")
    tag = re.search(r'<input type="text" id="net-sample"[^>]*>', bar).group(0)
    assert "maxlength" not in tag, "a pasted hash with spaces around it is cut (the script trims)"
    assert "Sample SHA256 (optional)" in bar


@needs_node
def test_the_import_sends_a_valid_sample_and_refuses_a_malformed_one():
    r = _run_node(["networkImport"], r"""
        (async () => {
            const els = { 'net-file': { files: [{ name: 'c.pcap' }], value: 'c.pcap' }, 'net-mode': { value: 'online' },
                          'net-sample': { value: '' }, 'net-import-btn': {} };
            globalThis.document = { getElementById: id => els[id] || null };
            globalThis.FormData = class { constructor() { this.fields = {}; } append(k, v) { this.fields[k] = v; } };
            const sent = [], messages = [];
            globalThis.fetch = (url, opts) => { sent.push(opts.body.fields); return Promise.resolve({}); };
            globalThis.networkJson = async () => ({ filename: 'c.pcap', events: [], sample_sha256: 'ab'.repeat(32) });
            globalThis.networkMessage = (text, error) => messages.push([text, !!error]);
            globalThis.networkShowReport = () => {};
            globalThis.networkRefreshReports = async () => {};
            els['net-sample'].value = 'not-a-hash';
            await networkImport();
            const refused = [sent.length, messages.pop()];
            els['net-sample'].value = '  ' + 'AB'.repeat(32) + ' ';
            await networkImport();
            const tied = [sent[0], messages.pop()[0]];
            els['net-sample'].value = '';
            await networkImport();
            console.log(JSON.stringify({ refused, tied, loose: sent[1] }));
        })();
    """, PRELUDE)
    assert r["refused"] == [0, ["The sample SHA256 must be 64 hex digits, or empty.", True]]
    assert r["tied"][0]["sha256"] == "ab" * 32 and "tied to the sample abababababab" in r["tied"][1]
    assert "sha256" not in r["loose"]


@needs_node
def test_a_failed_events_fetch_is_tried_again_after_a_while():
    """Regressions covered: one transient error left Tracing on "could not be
    loaded" for that report until it fell out of the cache. A failed fetch is
    tried again on a render once RTRACE_NETWORK_RETRY_MS have passed (not on
    every render before that, and never twice at once)."""
    r = _run_node(STATE_FNS, r"""
        (async () => {
            let now = 1000, fail = true;
            Date.now = () => now;
            const fetched = [];
            globalThis.fetch = url => {
                fetched.push(now);
                return Promise.resolve(fail ? { ok: false, status: 503, json: async () => ({ error: 'busy' }) }
                                            : { ok: true, status: 200, json: async () => ({ events: [{ type: 'dns', dest: 'a.top' }] }) });
            };
            globalThis.showRtraceDetailTabs = () => {};
            globalThis.showRtraceEventTable = () => {};
            globalThis.state = { processes: {}, rtraceSelectedPid: null, activeTab: 'tracing',
                                 detonationNetwork: { id: 'c'.repeat(32), observed: true } };
            const tick = () => new Promise(res => setImmediate(res));
            rtraceState(); await tick();
            const r = { failed: rtraceState().networkPending };
            now += RTRACE_NETWORK_RETRY_MS - 1; rtraceState(); rtraceState(); await tick();
            r.early = fetched.length;
            fail = false; now += 1;
            const retrying = rtraceState(); rtraceState();
            r.retrying = [retrying.networkPending, fetched.length];
            await tick();
            const done = rtraceState();
            r.done = [done.networkPending || null, done.network.map(e => e.dest), fetched.length];
            console.log(JSON.stringify(r));
        })();
    """, _const("networkState") + "\n" + "\n".join(_const(c) for c in (
        "rtraceNetworkFetched", "RTRACE_NETWORK_FETCHED_MAX", "RTRACE_NETWORK_RETRY_MS")))
    assert r["failed"] == "failed"
    assert r["early"] == 1, "tried again before the delay"
    assert r["retrying"] == ["loading", 2], "the retry was not made, or made twice"
    assert r["done"] == [None, ["a.top"], 2]
