"""YAML rules over network events: loading, validation, matching, correlation.

Regressions covered:
  * one broken rule (bad regex, unknown operator, unknown field, a ``requires``
    on an id that does not exist) discarded the whole file, or crashed the
    analysis at the first event it was matched against; each is now reported
    with its reason and the other rules run
  * a rule written against a field no event has (a typo, or ``password``)
    loaded cleanly and never fired; the documented fields are checked against
    what the real parsers emit
  * a rule that could read the captured FTP/SMTP password, and a hit that
    carried a ``Secret`` into a report and made ``json.dumps`` raise
  * ``(a+)+$`` and its relatives: nested repetition, overlapping alternation
    and adjacent repeats ran for minutes on a short field, one event stalling
    the analysis; they are refused at load time, and a field is cut before a
    regex sees it
  * ``nxdomain: true`` matching an event whose field was the number 1, and a
    case-sensitive hostname compare that missed ``Evil.TOP``
  * a list-valued field (``via``, ``rcpt_to``) compared as a whole, so that
    ``rcpt_to: a@b.top`` never fired
  * the PE-download rule matching events of an unrelated process and an
    unrelated rule of another process completing a correlation
  * a hit per matching event: a thousand identical requests became a thousand
    findings and a report nobody could read
  * every rule evaluated against every event: the cost grew as rules x events
  * a typo in a rule key (``sevrity``) silently ignored, a list name that does
    not exist silently empty, an empty ``contains`` matching everything
  * ``known_good`` destinations reaching rules, or the opt-out being ignored
"""

import json
import os
import random
import re
import tempfile
import time

import pytest

import net_events
import net_mail_ftp
import net_rules


def _rules(text):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "rules.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return net_rules.load_rules([path])


def _ids(hits):
    return [h["rule_id"] for h in hits]


def _http(ts=1.0, **fields):
    return net_events.NetEvent("http", ts, **fields)


# --- the contract from the brief ------------------------------------------------

def test_a_rule_matches_an_event_field():
    rs = _rules(r"""
rules:
  - id: gate
    name: Panel request
    event: http
    match: {method: POST, path|re: '^/gate\d*\.php$'}
    severity: high
""")
    hits = rs.evaluate([net_events.NetEvent("http", 1.0, dest="e.top",
                                            method="POST", path="/gate7.php")])
    assert rs.errors == [] and _ids(hits) == ["gate"]


def test_a_hit_serializes_to_json():
    rs = _rules("rules:\n  - {id: g, name: g, event: http, match: {method: GET}}")
    hit = rs.evaluate([net_events.NetEvent("http", 1.0, method="GET")])[0]
    assert json.loads(json.dumps(hit))["rule_id"] == "g"
    assert json.loads(json.dumps(rs.rules[0]))["id"] == "g"


def test_a_rule_that_does_not_match_produces_nothing():
    rs = _rules("rules:\n  - {id: x, name: x, event: http, match: {method: PUT}}")
    assert rs.evaluate([net_events.NetEvent("http", 1.0, method="GET")]) == []


def test_a_named_list_is_resolved():
    rs = _rules("""
lists:
  bad: [evil.top, worse.top]
rules:
  - {id: l, name: l, event: dns, match: {dest|in: $bad}}
""")
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="worse.top")])) == 1
    assert rs.lists["bad"] == ["evil.top", "worse.top"]


def test_known_good_destinations_are_invisible_to_rules():
    rs = _rules("""
lists:
  known_good: [www.msftconnecttest.com]
rules:
  - {id: any_dns, name: any, event: dns, match: {}}
""")
    assert rs.evaluate([net_events.NetEvent("dns", 1.0, dest="www.msftconnecttest.com")]) == []
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="evil.top")])) == 1


def test_a_rule_may_opt_into_known_good():
    rs = _rules("""
lists:
  known_good: [www.msftconnecttest.com]
rules:
  - {id: ncsi, name: ncsi, event: dns, match: {}, include_known_good: true}
""")
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="www.msftconnecttest.com")])) == 1


def test_any_all_and_not_blocks_compose():
    rs = _rules("""
rules:
  - id: c
    name: c
    event: http
    match:
      any: [{dest: a.top}, {dest: b.top}]
      not: {path: /ok}
""")
    evs = [net_events.NetEvent("http", 1.0, dest="a.top", path="/x"),
           net_events.NetEvent("http", 2.0, dest="a.top", path="/ok"),
           net_events.NetEvent("http", 3.0, dest="z.top", path="/x")]
    assert len(rs.evaluate(evs)) == 1


def test_count_gte_counts_matching_events():
    rs = _rules("rules:\n  - {id: n, name: n, event: dns, match: {nxdomain: true}, count_gte: 3}")
    few = [net_events.NetEvent("dns", float(i), dest="x", nxdomain=True) for i in range(2)]
    many = [net_events.NetEvent("dns", float(i), dest="x", nxdomain=True) for i in range(4)]
    assert rs.evaluate(few) == [] and len(rs.evaluate(many)) == 1


def test_a_correlation_rule_needs_one_hit_from_each_group():
    rs = _rules("""
rules:
  - {id: dl, name: dl, event: download, match: {kind: pe}}
  - {id: bc, name: bc, event: beacon, match: {}}
  - {id: chain, name: chain, requires: [[dl], [bc]], severity: critical}
""")
    only_dl = [net_events.NetEvent("download", 1.0, process="a.exe", kind="pe")]
    both = only_dl + [net_events.NetEvent("beacon", 2.0, process="a.exe")]
    assert "chain" not in _ids(rs.evaluate(only_dl))
    assert "chain" in _ids(rs.evaluate(both))


def test_a_rule_may_name_an_evidence_kind():
    rs = _rules("rules:\n  - {id: k, name: k, event: upload, match: {}, kind: exfil_upload}")
    assert rs.evaluate([net_events.NetEvent("upload", 1.0)])[0]["kind"] == "exfil_upload"


def test_an_invalid_regex_is_reported_and_the_other_rules_still_run():
    rs = _rules("""
rules:
  - {id: broken, name: b, event: http, match: {path|re: '([unclosed'}}
  - {id: fine, name: f, event: http, match: {method: GET}}
""")
    assert any("broken" in e for e in rs.errors)
    assert _ids(rs.evaluate([net_events.NetEvent("http", 1.0, method="GET")])) == ["fine"]


def test_an_unknown_operator_is_reported():
    rs = _rules("rules:\n  - {id: u, name: u, event: http, match: {path|sideways: x}}")
    assert any("sideways" in e for e in rs.errors) and rs.rules == []


def test_requires_on_an_unknown_rule_id_is_reported():
    rs = _rules("rules:\n  - {id: c, name: c, requires: [[ghost]]}")
    assert any("ghost" in e for e in rs.errors)


def test_broken_yaml_is_reported_without_raising(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("rules: [this: is: not: yaml")
    rs = net_rules.load_rules([str(p)])
    assert rs.errors and rs.rules == []


# --- fields ---------------------------------------------------------------------

def test_an_unknown_field_is_reported_with_the_event_type():
    rs = _rules("rules:\n  - {id: f, name: f, event: http, match: {mehtod: GET}}")
    assert rs.rules == []
    assert any("mehtod" in e and "http" in e for e in rs.errors)


def test_a_field_of_another_event_type_is_not_accepted():
    rs = _rules("rules:\n  - {id: f, name: f, event: dns, match: {method: GET}}")
    assert rs.rules == [] and any("method" in e for e in rs.errors)


def test_a_rule_for_several_event_types_may_use_any_of_their_fields():
    rs = _rules("rules:\n  - {id: f, name: f, event: [http, dns], match: {nxdomain: true}}")
    assert rs.errors == [] and len(rs.rules) == 1


def test_a_nested_field_in_a_block_is_checked_too():
    rs = _rules("rules:\n  - {id: f, name: f, event: http, match: {not: {any: [{pth: /}]}}}")
    assert rs.rules == [] and any("pth" in e for e in rs.errors)


def test_an_unknown_event_type_is_reported():
    rs = _rules("rules:\n  - {id: e, name: e, event: htpp, match: {}}")
    assert rs.rules == [] and any("htpp" in e for e in rs.errors)


def test_a_rule_without_an_event_is_reported():
    rs = _rules("rules:\n  - {id: e, name: e, match: {method: GET}}")
    assert rs.rules == [] and any("event" in e for e in rs.errors)


def test_the_password_field_cannot_be_matched():
    rs = _rules("rules:\n  - {id: p, name: p, event: ftp, match: {password|contains: hunter}}")
    assert rs.rules == [] and any("password" in e for e in rs.errors)


MAX_BOMB = 6


# set by a parser in some cases only; a single sample cannot show them
SOMETIMES = {"download": {"wire_sha256", "wire_size"}}


def _fields_of(events):
    seen = {}
    for e in events:
        seen.setdefault(e["type"], set()).update(e)
    return seen


def test_the_documented_fields_are_what_the_parsers_emit():
    """A rule language whose fields differ from the events is worse than none."""
    import test_net_dns
    import test_net_http
    import test_net_mail_ftp
    import test_net_raw
    import test_net_tls
    import net_behavior
    import net_decode
    import net_dns
    import net_http
    import net_mail_ftp
    import net_raw
    import net_tls

    events = []
    events += net_dns.events_from_flow(test_net_dns._dns_flow("a.top", "A", ["203.0.113.9"]))
    events += net_dns.events_from_flow(test_net_dns._dns_flow("b.top", "A", [], rcode=3))
    pe = b"MZ" + b"\x00" * 600
    request = (b"POST /up HTTP/1.1\r\nHost: x.top\r\nContent-Length: %d\r\n\r\n" % len(pe)) + pe
    events += net_http.events_from_flow(test_net_http._http_flow(request, test_net_http._ok(pe)))
    events += net_http.events_from_flow(test_net_http._http_flow(
        b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n\r\n"
        + test_net_http._ws_frame(b"ping"),
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n" + test_net_http._ws_frame(b"pong")))
    events += net_tls.events_from_flow(test_net_tls._tls_flow(cert=("CN=a.top", "CN=a.top")))
    events += net_raw.events_from_flow(test_net_raw._raw_flow(bytes(range(256)) * 4))
    events += net_mail_ftp.events_from_flow(
        test_net_mail_ftp._line_flow(21, b"USER bot\r\nPASS s3cret\r\nSTOR a.txt\r\n"))
    events += net_mail_ftp.events_from_flow(
        test_net_mail_ftp._line_flow(25, b"EHLO x\r\nMAIL FROM:<a@e.top>\r\nRCPT TO:<b@d.top>\r\n"
                                         b"DATA\r\nSubject: s\r\n\r\nb\r\n.\r\n"))
    events += net_decode.decode_event_fields(
        net_events.NetEvent("http", 1.0, dest="x.top", body_text="data=aGVsbG8gd29ybGQ="))
    events += net_behavior.analyze(
        [net_events.NetEvent("http", t * 60.0, dest="c2.top") for t in range(8)]
        + [net_events.NetEvent("conn_failed", float(t), dest="dead.top") for t in range(6)]
        + [net_events.NetEvent("http", float(t), dest="h%d.top" % t, path="/p") for t in range(6)]
        + [net_events.NetEvent("dns", float(t), dest="n%d.top" % t, nxdomain=True)
           for t in range(12)])
    emitted = _fields_of(events)
    assert {"dns", "http", "upload", "download", "websocket", "tls", "raw", "ftp", "smtp",
            "decoded", "beacon", "retry", "fanout"} <= set(emitted)
    for etype, keys in emitted.items():
        unlisted = keys - net_rules.FIELDS[etype] - net_rules.UNMATCHABLE
        assert not unlisted, "%s events carry fields the rules cannot name: %s" % (etype, sorted(unlisted))
        # a listed field no parser ever sets is a typo that would pass validation
        unused = net_rules.FIELDS[etype] - keys - SOMETIMES.get(etype, set())
        assert not unused, "%s lists fields no parser sets: %s" % (etype, sorted(unused))


# --- operators ------------------------------------------------------------------

def _fires(match, event, event_type="http"):
    rs = _rules("rules:\n  - {id: r, name: r, event: %s, match: %s}" % (event_type, match))
    assert rs.errors == [], rs.errors
    return bool(rs.evaluate([event]))


def test_string_comparison_ignores_case_but_a_regex_does_not():
    ev = _http(dest="Evil.TOP", path="/Gate.php")
    assert _fires("{dest: evil.top}", ev)
    assert _fires("{dest|contains: VIL.t}", ev)
    assert _fires("{dest|startswith: EVIL}", ev)
    assert _fires("{dest|endswith: .top}", ev)
    assert _fires("{dest|in: [evil.top, other.top]}", ev)
    assert not _fires("{path|re: '^/gate'}", ev)
    assert _fires("{path|re: '(?i)^/gate'}", ev)


def test_a_list_value_means_any_of_them():
    ev = _http(path="/b/x.php")
    assert _fires("{path|contains: [/a/, /b/]}", ev)
    assert _fires("{path|endswith: [.exe, .php]}", ev)
    assert _fires("{method: [GET, POST]}", _http(method="POST"))
    assert not _fires("{method: [GET, POST]}", _http(method="PUT"))
    assert _fires("{path|re: ['^/a', '^/b']}", ev)


def test_numbers_compare_numerically():
    ev = _http(status=404, body_bytes=10)
    assert _fires("{status|gte: 404}", ev) and not _fires("{status|gt: 404}", ev)
    assert _fires("{status|lte: 404}", ev) and not _fires("{status|lt: 404}", ev)
    assert _fires("{body_bytes|lt: 11, status|gt: 400}", ev)
    assert _fires("{status: 404}", ev)


def test_integers_and_floats_compare_with_each_other():
    assert _fires("{interval|gte: 59.5}", net_events.NetEvent("beacon", 1.0, interval=60), "beacon")
    assert _fires("{interval|lt: 61}", net_events.NetEvent("beacon", 1.0, interval=60.5), "beacon")
    assert not _fires("{interval|gt: 60}", net_events.NetEvent("beacon", 1.0, interval=60.0), "beacon")
    assert _fires("{interval|lte: 60.0}", net_events.NetEvent("beacon", 1.0, interval=60), "beacon")


def test_a_number_operator_ignores_text_and_missing_values():
    assert not _fires("{status|gte: 0}", _http(status=None))
    assert not _fires("{status|gte: 0}", _http(status="200"))
    assert not _fires("{status|gte: 0}", _http(status=True))


def test_a_boolean_is_not_a_number_and_a_number_is_not_a_boolean():
    assert not _fires("{nxdomain: true}", net_events.NetEvent("dns", 1.0, nxdomain=1), "dns")
    assert not _fires("{port: true}", net_events.NetEvent("dns", 1.0, port=1), "dns")
    assert _fires("{nxdomain: true}", net_events.NetEvent("dns", 1.0, nxdomain=True), "dns")
    assert _fires("{nxdomain: false}", net_events.NetEvent("dns", 1.0, nxdomain=False), "dns")


def test_null_matches_a_missing_value():
    assert _fires("{status: null}", _http(status=None))
    assert not _fires("{status: null}", _http(status=200))


def test_a_list_field_is_tested_element_by_element():
    ev = net_events.NetEvent("smtp", 1.0, rcpt_to=["a@x.top", "B@Drop.top"], attachments=[])
    assert _fires("{rcpt_to: b@drop.top}", ev, "smtp")
    assert _fires("{rcpt_to|endswith: '@drop.top'}", ev, "smtp")
    assert _fires("{rcpt_to|re: '^a@'}", ev, "smtp")
    assert not _fires("{rcpt_to: c@x.top}", ev, "smtp")


def test_has_all_needs_every_value_in_the_list_field():
    ev = net_events.NetEvent("beacon", 1.0, via=["http", "tls"])
    assert _fires("{via|has_all: [http, tls]}", ev, "beacon")
    assert _fires("{via|has_all: [HTTP]}", ev, "beacon")
    assert not _fires("{via|has_all: [http, dns]}", ev, "beacon")
    assert not _fires("{via|has_all: [http]}", net_events.NetEvent("beacon", 1.0, via="http"), "beacon")


def test_count_gte_as_an_operator_measures_the_field():
    ev = net_events.NetEvent("smtp", 1.0, rcpt_to=["a", "b", "c"], subject="abc")
    assert _fires("{rcpt_to|count_gte: 3}", ev, "smtp")
    assert not _fires("{rcpt_to|count_gte: 4}", ev, "smtp")
    assert _fires("{subject|count_gte: 3}", ev, "smtp")
    assert not _fires("{body_bytes|count_gte: 0}", ev, "smtp")


def test_a_not_block_may_hold_a_list_of_alternatives():
    ev = _http(method="GET")
    assert not _fires("{not: [{method: GET}, {method: POST}]}", ev)
    assert _fires("{not: [{method: PUT}, {method: POST}]}", ev)


def test_all_block_needs_every_member():
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {all: [{method: GET}, {path: /x}]}}")
    assert len(rs.evaluate([_http(method="GET", path="/x")])) == 1
    assert rs.evaluate([_http(method="GET", path="/y")]) == []


def test_matching_never_raises_on_odd_field_values():
    rs = _rules("""
rules:
  - id: r
    name: r
    event: http
    match:
      path|re: x
      method|contains: x
      status|gte: 1
      form_names|has_all: [a]
      ua|count_gte: 1
      body_text|in: [a]
""")
    for value in (None, 5, 2.5, True, b"bytes", {"a": 1}, [1, [2]], float("nan"), object()):
        ev = _http(path=value, method=value, status=value, form_names=value, ua=value,
                   body_text=value)
        assert rs.evaluate([ev]) == []


# --- lists ----------------------------------------------------------------------

def test_an_unknown_list_is_reported_not_treated_as_empty():
    rs = _rules("rules:\n  - {id: l, name: l, event: dns, match: {dest|in: $nope}}")
    assert rs.rules == [] and any("nope" in e for e in rs.errors)


def test_a_dollar_dollar_is_a_literal_dollar():
    rs = _rules("rules:\n  - {id: l, name: l, event: http, match: {path: $$HOME}}")
    assert rs.errors == [] and len(rs.evaluate([_http(path="$HOME")])) == 1


@pytest.mark.parametrize("value", ["[$bad, x.top]", "[x.top, $bad]", "[$nope]"])
def test_a_list_name_inside_a_list_literal_is_an_error_not_literal_text(value):
    rs = _rules("lists: {bad: [evil.top]}\nrules:\n"
                "  - {id: l, name: l, event: dns, match: {dest|in: %s}}" % value)
    assert rs.rules == [] and any("$" in e and "list" in e for e in rs.errors)


def test_a_dollar_dollar_inside_a_list_literal_is_a_literal_dollar():
    rs = _rules("rules:\n  - {id: l, name: l, event: http, match: {path|in: [$$HOME, /x]}}")
    assert rs.errors == [] and len(rs.evaluate([_http(path="$HOME")])) == 1


def test_a_list_works_with_every_string_operator():
    rs = _rules("""
lists:
  words: [mimi, katz]
  hosts: [a.top]
  patterns: ['^/x']
rules:
  - {id: a, name: a, event: http, match: {path|contains: $words}}
  - {id: b, name: b, event: http, match: {dest: $hosts}}
  - {id: c, name: c, event: http, match: {path|re: $patterns}}
""")
    assert rs.errors == []
    assert _ids(rs.evaluate([_http(dest="a.top", path="/x/katz")])) == ["a", "b", "c"]


def test_lists_of_several_files_are_joined(tmp_path):
    one, two = tmp_path / "1.yaml", tmp_path / "2.yaml"
    one.write_text("lists: {known_good: [a.top]}\nrules:\n  - {id: r, name: r, event: dns, match: {}}\n")
    two.write_text("lists: {known_good: [b.top]}\n")
    rs = net_rules.load_rules([str(one), str(two)])
    assert rs.errors == [] and rs.lists["known_good"] == ["a.top", "b.top"]
    assert rs.evaluate([net_events.NetEvent("dns", 1.0, dest="b.top")]) == []


def test_known_good_is_predefined_even_when_no_file_names_it():
    rs = _rules("rules:\n  - {id: r, name: r, event: dns, match: {}}")
    assert rs.lists["known_good"] == []
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="a.top")])) == 1


def test_known_good_ignores_case_and_a_trailing_dot_and_may_use_a_wildcard():
    rs = _rules("""
lists:
  known_good: [Update.Example.com, '*.windowsupdate.com']
rules:
  - {id: r, name: r, event: dns, match: {}}
""")
    seen = lambda dest: len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest=dest)]))
    assert seen("update.example.COM.") == 0
    assert seen("a.b.windowsupdate.com") == 0
    assert seen("windowsupdate.com") == 0
    assert seen("evilwindowsupdate.com") == 1
    assert seen("windowsupdate.com.evil.top") == 1
    assert seen("sub.update.example.com") == 1


def test_known_good_does_not_hide_events_without_a_destination():
    rs = _rules("""
lists:
  known_good: ['']
rules:
  - {id: r, name: r, event: fanout, match: {}}
""")
    assert len(rs.evaluate([net_events.NetEvent("fanout", 1.0, hosts=9)])) == 1


# --- hits -----------------------------------------------------------------------

def test_a_hit_carries_the_rule_metadata_and_where_it_matched():
    rs = _rules("""
rules:
  - id: g
    name: Panel
    event: http
    severity: high
    role: c2
    behavior: Posts to a panel
    attack: [T1071.001]
    family: examplebot
    description: why
    match: {method: POST}
""")
    evs = [_http(1.0, dest="a.top", port=80, process="x.exe", method="GET"),
           _http(2.0, dest="e.top", port=8080, process="x.exe", method="POST")]
    hit = rs.evaluate(evs)[0]
    assert hit["rule_id"] == "g" and hit["name"] == "Panel" and hit["severity"] == "high"
    assert hit["role"] == "c2" and hit["family"] == "examplebot"
    assert hit["behavior"] == "Posts to a panel" and hit["attack"] == ["T1071.001"]
    assert hit["process"] == "x.exe" and hit["count"] == 1
    assert hit["events"] == [{"index": 1, "type": "http", "ts": 2.0, "dest": "e.top", "port": 8080}]


def test_one_rule_gives_one_hit_per_process_not_one_per_event():
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {method: GET}}")
    evs = [_http(float(i), process="a.exe", method="GET") for i in range(5)]
    evs += [_http(9.0, process="b.exe", method="GET")]
    hits = rs.evaluate(evs)
    assert [(h["process"], h["count"]) for h in hits] == [("a.exe", 5), ("b.exe", 1)]


def test_the_events_of_a_hit_are_bounded_but_the_count_is_exact():
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {}}")
    hit = rs.evaluate([_http(float(i)) for i in range(5000)])[0]
    assert hit["count"] == 5000 and len(hit["events"]) == net_rules.MAX_HIT_EVENTS
    assert hit["events"][0]["index"] == 0


def test_count_gte_counts_per_process():
    rs = _rules("rules:\n  - {id: n, name: n, event: dns, match: {}, count_gte: 3}")
    evs = [net_events.NetEvent("dns", float(i), process="a.exe") for i in range(2)]
    evs += [net_events.NetEvent("dns", 5.0, process="b.exe") for _ in range(2)]
    assert rs.evaluate(evs) == []
    evs.append(net_events.NetEvent("dns", 6.0, process="a.exe"))
    assert [h["process"] for h in rs.evaluate(evs)] == ["a.exe"]


def test_hits_come_in_rule_order_whatever_the_event_order():
    rs = _rules("""
rules:
  - {id: first, name: f, event: http, match: {method: POST}}
  - {id: second, name: s, event: http, match: {method: GET}}
""")
    evs = [_http(1.0, method="GET"), _http(2.0, method="POST")]
    assert _ids(rs.evaluate(evs)) == ["first", "second"]
    assert _ids(rs.evaluate(evs[::-1])) == ["first", "second"]


def test_evaluate_does_not_change_the_events():
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {method: GET}}")
    ev = _http(method="GET", path="/x")
    before = dict(ev)
    rs.evaluate([ev])
    assert dict(ev) == before


def test_no_events_and_foreign_objects_are_harmless():
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {}}")
    assert rs.evaluate([]) == []
    assert rs.evaluate([None, 5, "x", {"no": "type"}, {"type": "nope"}]) == []


def _type_events():
    return {etype: net_events.NetEvent(etype, 1.0, dest="www.msftconnecttest.com")
            for etype in net_events.EVENT_TYPES}


@pytest.mark.parametrize("etype", net_events.EVENT_TYPES)
def test_known_good_hides_every_type_but_the_ones_that_say_something_crossed_the_wire(etype):
    """``Host: <known-good name>`` on a connection to the sample's own address is
    free to forge, so the evidence of a transfer must not depend on it."""
    rs = _rules("lists: {known_good: [www.msftconnecttest.com]}\n"
                "rules:\n  - {id: r, name: r, event: %s, match: {}}" % etype)
    hits = rs.evaluate([_type_events()[etype]])
    assert bool(hits) == (etype in ("download", "upload", "decoded"))
    assert net_rules.ALWAYS_VISIBLE == {"download", "upload", "decoded"}


def test_a_forged_host_does_not_hide_a_download_from_a_correlation():
    rs = _rules("lists: {known_good: [www.msftconnecttest.com]}\n" + _CHAIN)
    evs = [net_events.NetEvent("download", 1.0, dest="www.msftconnecttest.com", kind="pe"),
           net_events.NetEvent("beacon", 2.0, dest="c2.top")]
    assert "chain" in _ids(rs.evaluate(evs))


# --- credentials ----------------------------------------------------------------

def test_a_hit_on_an_ftp_event_serializes_and_holds_no_password():
    rs = _rules("rules:\n  - {id: f, name: f, event: ftp, match: {user: bot}, severity: high}")
    ev = net_events.NetEvent("ftp", 1.0, dest="203.0.113.9", port=21, user="bot",
                             password=net_mail_ftp.Secret("hunter2"), password_captured=True)
    hits = rs.evaluate([ev])
    text = json.dumps(hits)
    assert _ids(hits) == ["f"] and "hunter2" not in text and "***" not in text


def test_a_rule_can_ask_whether_a_password_was_captured():
    rs = _rules("rules:\n  - {id: f, name: f, event: smtp, match: {password_captured: true}}")
    ev = net_events.NetEvent("smtp", 1.0, password=net_mail_ftp.Secret("x"),
                             password_captured=True)
    assert len(rs.evaluate([ev])) == 1


# --- correlation ----------------------------------------------------------------

_CHAIN = """
rules:
  - {id: dl, name: dl, event: download, match: {kind: pe}}
  - {id: dl2, name: dl2, event: download, match: {kind: zip}}
  - {id: bc, name: bc, event: beacon, match: {}}
  - {id: up, name: up, event: upload, match: {}}
  - {id: chain, name: chain, requires: [[dl, dl2], [bc, up]], severity: critical, kind: payload_staging}
"""


def test_a_correlation_needs_the_same_process():
    rs = _rules(_CHAIN)
    evs = [net_events.NetEvent("download", 1.0, process="a.exe", kind="pe"),
           net_events.NetEvent("beacon", 2.0, process="b.exe")]
    assert "chain" not in _ids(rs.evaluate(evs))


def test_either_rule_of_a_group_satisfies_it_and_the_hit_says_which():
    rs = _rules(_CHAIN)
    evs = [net_events.NetEvent("download", 1.0, process="a.exe", kind="zip"),
           net_events.NetEvent("upload", 2.0, process="a.exe")]
    chain = [h for h in rs.evaluate(evs) if h["rule_id"] == "chain"][0]
    assert chain["process"] == "a.exe" and chain["severity"] == "critical"
    assert chain["kind"] == "payload_staging" and chain["via"] == ["dl2", "up"]
    assert [e["type"] for e in chain["events"]] == ["download", "upload"]
    json.dumps(chain)


def test_a_correlation_fires_for_each_process_that_completes_it():
    rs = _rules(_CHAIN)
    evs = []
    for proc in ("a.exe", "b.exe"):
        evs += [net_events.NetEvent("download", 1.0, process=proc, kind="pe"),
                net_events.NetEvent("beacon", 2.0, process=proc)]
    assert [h["process"] for h in rs.evaluate(evs) if h["rule_id"] == "chain"] == ["a.exe", "b.exe"]


def test_a_correlation_works_in_a_capture_that_knows_no_process():
    rs = _rules(_CHAIN)
    evs = [net_events.NetEvent("download", 1.0, kind="pe"), net_events.NetEvent("beacon", 2.0)]
    assert "chain" in _ids(rs.evaluate(evs))


def test_known_good_events_do_not_complete_a_correlation():
    rs = _rules("lists: {known_good: [ok.top]}\n" + _CHAIN)
    evs = [net_events.NetEvent("download", 1.0, kind="pe"),
           net_events.NetEvent("beacon", 2.0, dest="ok.top")]
    assert "chain" not in _ids(rs.evaluate(evs))


def test_a_correlation_may_not_name_a_correlation_or_itself():
    rs = _rules("""
rules:
  - {id: a, name: a, event: dns, match: {}}
  - {id: c1, name: c1, requires: [[a]]}
  - {id: c2, name: c2, requires: [[c1]]}
  - {id: c3, name: c3, requires: [[c3]]}
""")
    assert [r["id"] for r in rs.rules] == ["a", "c1"]
    assert any("c2" in e and "c1" in e for e in rs.errors)
    assert any("c3" in e for e in rs.errors)


def test_a_correlation_may_name_a_rule_of_another_file(tmp_path):
    one, two = tmp_path / "1.yaml", tmp_path / "2.yaml"
    one.write_text("rules:\n  - {id: chain, name: c, requires: [[late]]}\n")
    two.write_text("rules:\n  - {id: late, name: l, event: dns, match: {}}\n")
    rs = net_rules.load_rules([str(one), str(two)])
    assert rs.errors == [] and len(rs.rules) == 2


def test_a_correlation_on_a_rejected_rule_is_rejected_with_the_reason():
    rs = _rules("""
rules:
  - {id: bad, name: b, event: http, match: {path|re: '(['}}
  - {id: chain, name: c, requires: [[bad]]}
""")
    assert rs.rules == []
    assert any("chain" in e and "bad" in e for e in rs.errors)


def test_a_correlation_rule_takes_no_event_or_match():
    rs = _rules("""
rules:
  - {id: a, name: a, event: dns, match: {}}
  - {id: c, name: c, requires: [[a]], event: dns}
""")
    assert [r["id"] for r in rs.rules] == ["a"] and any("'c'" in e for e in rs.errors)


@pytest.mark.parametrize("requires", ["[]", "[[]]", "[a]", "a", "[[a, 5]]", "[[a], []]"])
def test_a_malformed_requires_is_reported(requires):
    rs = _rules("rules:\n  - {id: a, name: a, event: dns, match: {}}\n"
                "  - {id: c, name: c, requires: %s}" % requires)
    assert [r["id"] for r in rs.rules] == ["a"] and any("requires" in e for e in rs.errors)


# --- rule keys ------------------------------------------------------------------

def test_an_unknown_rule_key_is_reported_and_the_rule_skipped():
    rs = _rules("rules:\n  - {id: r, name: r, event: dns, match: {}, sevrity: high}")
    assert rs.rules == [] and any("sevrity" in e for e in rs.errors)


def test_a_duplicate_id_is_reported_and_the_first_rule_kept():
    rs = _rules("""
rules:
  - {id: r, name: first, event: dns, match: {}}
  - {id: r, name: second, event: dns, match: {}}
""")
    assert [r["name"] for r in rs.rules] == ["first"] and any("duplicate" in e for e in rs.errors)


@pytest.mark.parametrize("rule", [
    "{name: n, event: dns, match: {}}",
    "{id: '', name: n, event: dns, match: {}}",
    "{id: 5, name: n, event: dns, match: {}}",
    "{id: r, event: dns, match: {}}",
    "{id: r, name: n, event: dns, match: {}, severity: urgent}",
    "{id: r, name: n, event: dns, match: {}, include_known_good: 'yes'}",
    "{id: r, name: n, event: dns, match: {}, count_gte: 0}",
    "{id: r, name: n, event: dns, match: {}, count_gte: two}",
    "{id: r, name: n, event: dns, match: {}, attack: 5}",
    "{id: r, name: n, event: dns, match: []}",
    "{id: r, name: n, event: dns, match: {dest: 2020-01-01}}",
    "{id: r, name: n, event: dns, match: {dest|contains: ''}}",
    "{id: r, name: n, event: dns, match: {dest|in: x}}",
    "{id: r, name: n, event: dns, match: {dest: []}}",
    "{id: r, name: n, event: dns, match: {port|gte: high}}",
    "{id: r, name: n, event: dns, match: {port|gte: true}}",
    "{id: r, name: n, event: dns, match: {dest|has_all: []}}",
    "{id: r, name: n, event: dns, match: {dest|count_gte: -1}}",
    "{id: r, name: n, event: dns, match: {dest|re: 5}}",
    "{id: r, name: n, event: dns, match: {any: {dest: x}}}",
    "{id: r, name: n, event: dns, match: {any: []}}",
    "{id: r, name: n, event: dns, match: {not: 5}}",
    "{id: r, name: n, event: dns, match: {'dest|contains|all': x}}",
])
def test_a_malformed_rule_is_reported_and_the_rest_still_load(rule):
    rs = _rules("rules:\n  - %s\n  - {id: ok, name: ok, event: dns, match: {}}" % rule)
    assert [r["id"] for r in rs.rules] == ["ok"], rs.errors
    assert len(rs.errors) == 1


def test_a_key_given_twice_is_reported_not_silently_overwritten():
    rs = _rules("""
rules:
  - id: twice
    name: n
    event: http
    match:
      path|contains: a
      path|contains: b
  - {id: ok, name: ok, event: http, match: {}}
""")
    assert [r["id"] for r in rs.rules] == ["ok"]
    assert len(rs.errors) == 1 and "twice" in rs.errors[0] and "path|contains" in rs.errors[0]


def test_a_rule_key_given_twice_is_reported():
    rs = _rules("rules:\n  - {id: r, name: n, event: dns, match: {}, severity: low, severity: high}")
    assert rs.rules == [] and any("severity" in e and "twice" in e for e in rs.errors)


def test_a_list_or_a_section_given_twice_is_reported():
    rs = _rules("lists: {a: [x], a: [y]}\nrules: []\nrules:\n  - {id: r, name: n, event: dns, match: {}}")
    assert len(rs.errors) == 2 and len(rs.rules) == 1


def test_a_rule_that_is_not_a_mapping_is_reported():
    rs = _rules("rules:\n  - just a string\n  - {id: ok, name: ok, event: dns, match: {}}")
    assert [r["id"] for r in rs.rules] == ["ok"] and len(rs.errors) == 1


def test_severity_defaults_to_info_and_a_rule_carries_what_it_was_given():
    rs = _rules("rules:\n  - {id: r, name: n, event: [dns, http], match: {dest: x}, family: f}")
    rule = rs.rules[0]
    assert rule["severity"] == "info" and rule["event"] == ["dns", "http"]
    assert rule["family"] == "f" and rule["match"] == {"dest": "x"}
    assert rule["include_known_good"] is False and rule["attack"] == []
    json.dumps(rs.rules)


def test_weights_are_not_a_rule_key():
    rs = _rules("rules:\n  - {id: r, name: n, event: dns, match: {}, weight: 9}")
    assert rs.rules == [] and any("weight" in e for e in rs.errors)


def test_the_files_own_keys_are_checked():
    rs = _rules("list: {a: [b]}\nrules:\n  - {id: r, name: n, event: dns, match: {}}")
    assert len(rs.rules) == 1 and any("list" in e for e in rs.errors)


@pytest.mark.parametrize("text", ["", "[1, 2]", "rules: 5", "rules: {a: b}",
                                  "lists: [a]", "lists: {a: 5}", "lists: {a: [[1]]}"])
def test_a_file_of_the_wrong_shape_is_reported_without_raising(text):
    rs = _rules(text)
    assert rs.rules == [] and (rs.errors or text == "")


def test_a_broken_list_does_not_take_the_rest_of_the_file_down():
    rs = _rules("""
lists:
  broken: 5
  fine: [a.top]
rules:
  - {id: r, name: n, event: dns, match: {dest|in: $fine}}
  - {id: s, name: n, event: dns, match: {dest|in: $broken}}
""")
    assert [r["id"] for r in rs.rules] == ["r"] and len(rs.errors) == 2


def test_a_missing_file_and_a_directory_and_a_bad_encoding(tmp_path):
    (tmp_path / "a.yaml").write_text("rules:\n  - {id: a, name: a, event: dns, match: {}}\n")
    (tmp_path / "b.yml").write_text("rules:\n  - {id: b, name: b, event: dns, match: {}}\n")
    (tmp_path / "notes.txt").write_text("not a rule file")
    (tmp_path / "bin.yaml").write_bytes(b"\xff\xfe\x00 rules")
    rs = net_rules.load_rules([str(tmp_path), str(tmp_path / "gone.yaml")])
    assert [r["id"] for r in rs.rules] == ["a", "b"]
    assert any("gone.yaml" in e for e in rs.errors) and any("bin.yaml" in e for e in rs.errors)
    assert not any("notes" in e for e in rs.errors)


def test_a_yaml_that_does_not_stay_small_is_refused(tmp_path):
    big = tmp_path / "big.yaml"
    big.write_text("lists: {x: [" + ",".join(["a"] * 5) + "]}\n" + "#" * (net_rules.MAX_FILE_BYTES + 1))
    rs = net_rules.load_rules([str(big)])
    assert rs.rules == [] and any("big.yaml" in e for e in rs.errors)


@pytest.mark.parametrize("text", [
    "rules: [{id: 2026-13-45, name: x}]",
    "rules: [{id: r, name: x, event: dns, match: {dest: !!float abc}}]",
    "rules: [{id: r, name: x, event: dns, match: {port|gte: !!int zz}}]",
    "rules: [{id: r, name: x, event: dns, match: {dest: !!timestamp 2026-02-30}}]",
    "rules: [{id: r, name: x, event: dns, match: {dest: !!binary '!!'}}]",
])
def test_a_scalar_yaml_cannot_construct_is_reported_not_raised(text, tmp_path):
    (tmp_path / "ok.yaml").write_text("rules:\n  - {id: fine, name: f, event: dns, match: {}}\n")
    (tmp_path / "bad.yaml").write_text(text)
    rs = net_rules.load_rules([str(tmp_path / "bad.yaml"), str(tmp_path / "ok.yaml")])
    assert [r["id"] for r in rs.rules] == ["fine"]
    assert len(rs.errors) == 1 and "bad.yaml" in rs.errors[0]


def test_python_objects_in_yaml_are_not_constructed(tmp_path):
    p = tmp_path / "evil.yaml"
    p.write_text("rules:\n  - !!python/object/apply:os.system ['true']\n")
    rs = net_rules.load_rules([str(p)])
    assert rs.rules == [] and rs.errors


def test_an_alias_bomb_is_refused_not_expanded():
    levels = ["x0: &a0 {dest: x}"]
    for i in range(1, MAX_BOMB):
        levels.append("x%d: &a%d {any: [%s]}" % (i, i, ",".join(["*a%d" % (i - 1)] * 9)))
    start = time.time()
    rs = _rules("\n".join(levels) + "\nrules:\n  - {id: r, name: n, event: dns, match: *a%d}\n"
                % (MAX_BOMB - 1))
    assert time.time() - start < 2.0
    assert [r["id"] for r in rs.rules] == [] and any("'r'" in e for e in rs.errors)


def test_deeply_nested_blocks_are_refused():
    match = "{dest: x}"
    for _ in range(net_rules.MAX_DEPTH + 2):
        match = "{not: %s}" % match
    rs = _rules("rules:\n  - {id: r, name: n, event: dns, match: %s}" % match)
    assert rs.rules == [] and any("deep" in e for e in rs.errors)


# --- hostile regexes ------------------------------------------------------------

@pytest.mark.parametrize("pattern", [
    r"(a+)+$",
    r"(a*)*b",
    r"(.*a){20}x",
    r"(a|aa)+$",
    r"(a|a)*b",
    r"(?:\w\w|\d)+$",
    r"(\w+\s?)+$",
    r"(x+x+)+y",
    r"\w*\w*\w*$",
    r".*.*x",
    r".*a.*a.*b",
    # found by review: a bounded repeat around an open one, an open repeat hidden
    # in an optional group, a conditional group; each took seconds to minutes
    r"^/(\w+/?){1,5}\.php$",
    r"(a+){5}$",
    r"((a+){5}){5}$",
    r"(\w+){1,5}\.exe",
    r"(?:\d+)?(?:\d+)?(?:\d+)?(?:\d+)?x",
    r"()?(?(1)(a+)+$|b)",
    r"(a)?(?(1)(?:b+)+$|c)",
    # found by re-review: alternatives that start alike hid their own cost
    r"^(?:\w*\w*\w*\w*\w*\w*b|\w)",
    r"^(?:\w*\w*\w*\w*\w*b|\w)",
    r"^(?:.*=.*&.*=.*&.*=.*x|/)",
    # found while fuzzing: an optional part that can match what the next round starts with
    r"^(?:(?:(?:a|b)[a-z]?)*/+(?:\.){2})/+x",
    r"(?:[ab][a-z]?)*c",
    r"(?:a?a)+b",
    r"(?:\d{1,3}\.?)+x",
    r"^(?:(?:\s{0,2})?(?:a|bc))+?x",
    r"(?:(?:(?:(?:(?:(?:(?:a*)?)?)?)?)?)?)?x",
    r"(?:\w*)?(?:\d*)?x",
])
def test_a_hostile_regex_is_refused_at_load_time(pattern):
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": '%s'}}" % pattern)
    assert rs.rules == [], pattern
    assert len(rs.errors) == 1 and "h" in rs.errors[0]


@pytest.mark.parametrize("pattern", [
    r"^/gate\d*\.php$",
    r"(\d+\.){3}\d+",
    r"^(?:GET|POST) /",
    r"(?:foo|bar)+x",
    r"[a-z0-9]{8,32}\.top$",
    r"\.(?:exe|dll|scr)$",
    r"^.*\.php.*$",
    r"(?i)update.*\.exe",
    r"^[A-Za-z0-9+/=]{40,}$",
    r"\w+@\w+\.\w+",
    r"(ab)+c",
    r"\d+a\d+b\d+c",
    r"^(?:[a-z0-9-]+\.)+top$",
    r"[^/]+/[^/]+/[^/]+\.php",
    r"\S+\s\S+\s\S+x",
    r"(?:\w+\.)+x",
    r"(?:[a-z0-9-]+\.){2,}[a-z]{2,}$",
    r"(?i)mozilla/5\.0.*windows nt 10.*chrome/\d+",
    r"(?:ab?)+c",
    r"a.*b",
])
def test_ordinary_regexes_are_accepted(pattern):
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": '%s'}}" % pattern)
    assert rs.errors == [] and len(rs.rules) == 1, (pattern, rs.errors)


_SUBJECTS = ["a", "1", "a1", "a.", "ab", "a/", " ", "a b ", "x-", "a.b."]


@pytest.mark.parametrize("pattern", [
    r"a.*b", r"\d+\d+x", r"^.*a.*b", r"\S*?(?:a|bc)+?\.php", r"[ab]*(?:a|bc)*?/{1,5}$",
    r"(?:[a-z0-9-]+\.){2,}[a-z]{2,}$",
])
def test_the_worst_regexes_that_are_accepted_stay_cheap_on_a_huge_field(pattern):
    """Accepted does not mean free; it means bounded: the field is cut first."""
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": '%s'}}"
                % pattern.replace("'", "''"))
    assert rs.errors == [], rs.errors
    for unit in _SUBJECTS:
        subject = (unit * (2000000 // len(unit)))[:2000000]
        start = time.time()
        rs.evaluate([_http(path=subject), _http(path=subject + "!")])
        assert time.time() - start < 0.5, (pattern, unit)


def test_no_regex_that_is_accepted_is_slow_on_a_field_made_to_hurt_it():
    """Random patterns, judged by what they do and not by what the checker thinks.

    Whatever the load-time check lets through is run on subjects built from the
    characters the patterns are made of. The limit is generous (a pattern that
    stalls takes minutes, not a tenth of a second), so a failure here is a hole.
    """
    rng = random.Random(20261125)
    atoms = ["a", "b", "x", r"\.", "/", "-", r"\w", r"\d", r"\s", r"\S", r"\W", ".", "[ab]",
             "[^a]", "[a-z]", "[^/]", "(?:a|b)", "(?:ab|a)", "(?:a|bc)"]
    quants = ["", "", "", "?", "+", "*", "{2}", "{1,3}", "{0,2}", "{2,}", "{1,5}", "+?",
              "*?", "{1,40}"]

    def seq(depth, n):
        out = []
        for _ in range(n):
            if depth < 2 and rng.random() < 0.35:
                out.append("(?:" + seq(depth + 1, rng.randint(1, 3)) + ")")
            else:
                out.append(rng.choice(atoms))
            out[-1] += rng.choice(quants)
        return "".join(out)

    n = net_rules.PRICE_LEN
    subjects = ["a" * n, "a" * n + "!", "1" * n, "a1" * (n // 2), "a." * (n // 2) + "!",
                "ab" * (n // 2) + "!", "a/" * (n // 2), " " * n, "a b " * (n // 4) + "!",
                "x-" * (n // 2) + "."]
    accepted = slowest = 0
    for _ in range(1200):
        pattern = (rng.choice(["", "^"]) + seq(0, rng.randint(1, 5))
                   + rng.choice(["", "$", "x", r"\.php"]))
        try:
            net_rules._compile_regex(pattern)
        except net_rules.RuleError:
            continue
        accepted += 1
        compiled = re.compile(pattern)
        for subject in subjects:
            start = time.perf_counter()
            compiled.search(subject)
            took = time.perf_counter() - start
            assert took < 0.5, (pattern, subject[:6], took)
            slowest = max(slowest, took)
    assert accepted > 300           # the generator is not refused wholesale


def test_a_regex_sees_only_the_start_of_a_field_and_not_a_cut_end():
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": 'x$'}}")
    cut = net_rules.subject_limit()
    assert rs.evaluate([_http(path="a" * (cut - 1) + "x")]) != []
    assert rs.evaluate([_http(path="a" * (cut - 1) + "x" + "b" * 50)]) == []
    assert rs.evaluate([_http(path="a" * (cut + 100) + "x")]) == []
    late = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": 'late'}}")
    assert late.evaluate([_http(path="a" * (cut + 10) + "late")]) == []
    assert late.evaluate([_http(path="late" + "a" * (cut + 10))]) != []


def test_linear_operators_see_the_whole_field():
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"body_text|contains\": 'needle'}}")
    assert rs.evaluate([_http(body_text="a" * 500000 + "needle")]) != []


_BUDGET_SPENT = [{"rule_id": "r", "events": 50, "reasons": ["budget"]}]


def test_a_spent_budget_makes_the_rule_unevaluated_not_false(monkeypatch):
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: 'a'}}")
    evs = [_http(float(i), path="a") for i in range(50)]
    hits = rs.evaluate(evs)
    assert hits[0]["count"] == 50 and hits.unevaluated == [] and hits.budget_spent is False
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    spent = rs.evaluate(evs)
    assert spent == [] and isinstance(spent, list)
    assert spent.unevaluated == _BUDGET_SPENT and spent.budget_spent is True


def test_a_negated_regex_does_not_fire_when_the_budget_is_spent(monkeypatch):
    """The review's attack: spend the budget, and every ``not: {regex}`` rule
    fires on everything after it."""
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {not: {path|re: '^/benign'}}}")
    evs = [_http(float(i), path="/benign") for i in range(10)]
    assert rs.evaluate(evs) == []
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    spent = rs.evaluate(evs)
    assert spent == [] and spent.unevaluated[0]["rule_id"] == "r"
    assert spent.unevaluated[0]["events"] == 10


def test_a_not_around_a_block_with_an_unknown_stays_unknown(monkeypatch):
    rs = _rules("""
rules:
  - {id: a, name: a, event: http, match: {not: {any: [{path|re: x}, {method: POST}]}}}
  - {id: b, name: b, event: http, match: {not: [{path|re: x}, {method: POST}]}}
  - {id: c, name: c, event: http, match: {not: {all: [{path|re: x}, {method: POST}]}}}
""")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    got = rs.evaluate([_http(method="GET", path="/x")])
    # c: the all is false whatever the regex says (GET is not POST), so its not is true
    assert _ids(got) == ["c"]
    assert [u["rule_id"] for u in got.unevaluated] == ["a", "b"]


def test_an_any_is_true_and_an_all_is_false_whatever_an_unknown_member_would_say(monkeypatch):
    rs = _rules("""
rules:
  - {id: any_true, name: a, event: http, match: {any: [{path|re: x}, {method: GET}]}}
  - {id: any_none, name: a, event: http, match: {any: [{path|re: x}, {method: PUT}]}}
  - {id: all_false, name: a, event: http, match: {all: [{path|re: x}, {method: PUT}]}}
  - {id: all_none, name: a, event: http, match: {all: [{path|re: x}, {method: GET}]}}
""")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    got = rs.evaluate([_http(method="GET", path="x")])
    assert _ids(got) == ["any_true"]
    assert [u["rule_id"] for u in got.unevaluated] == ["all_none", "any_none"]


def test_a_rule_unknown_for_some_events_keeps_the_hits_it_could_decide(monkeypatch):
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: x}}")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    assert rs.evaluate([_http(path="x")]) == []
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 20.0)
    assert len(rs.evaluate([_http(path="x")])) == 1


def test_a_spent_budget_is_reported_even_when_nothing_was_skipped(monkeypatch):
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: 'a'}}")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 1e-12)
    hits = rs.evaluate([_http(path="a")])
    assert len(hits) == 1 and hits.unevaluated == [] and hits.budget_spent is True


def test_the_regex_budget_is_spent_by_regex_time_only(monkeypatch):
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {method: GET}}")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    hits = rs.evaluate([_http(method="GET")])
    assert len(hits) == 1 and hits.budget_spent is False and hits.unevaluated == []


def test_the_regex_budget_does_not_leak_into_the_next_call(monkeypatch):
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: 'a'}}")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    assert rs.evaluate([_http(path="a")]).budget_spent is True
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 20.0)
    again = rs.evaluate([_http(path="a")])
    assert len(again) == 1 and again.budget_spent is False
    assert rs.rules[0]._match(_http(path="a")) is True          # outside evaluate: no budget


def test_an_unknown_in_a_list_field_is_unknown_unless_another_element_matches(monkeypatch):
    rs = _rules("rules:\n  - {id: r, name: r, event: smtp, match: {rcpt_to|re: 'd.top'}}")
    event = net_events.NetEvent("smtp", 1.0, rcpt_to=["a@d.top", "b@d.top"])
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    got = rs.evaluate([event])
    assert got == [] and got.unevaluated[0]["reasons"] == ["budget"]


def test_a_correlation_that_could_not_fire_because_a_member_is_unknown_is_listed(monkeypatch):
    rs = _rules("""
rules:
  - {id: a, name: a, event: http, match: {path|re: x}}
  - {id: b, name: b, event: dns, match: {}}
  - {id: chain, name: c, requires: [[a], [b]]}
""")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    got = rs.evaluate([_http(path="x"), net_events.NetEvent("dns", 2.0)])
    assert _ids(got) == ["b"]
    assert [(u["rule_id"], u["reasons"]) for u in got.unevaluated] == [
        ("a", ["budget"]), ("chain", ["requires a"])]


def test_a_regex_looks_only_at_the_first_elements_of_a_list_field():
    rs = _rules("rules:\n  - {id: r, name: r, event: smtp, match: {rcpt_to|re: 'target'}}")
    last = net_rules.MAX_REGEX_ELEMENTS
    near = net_events.NetEvent("smtp", 1.0, rcpt_to=["x"] * (last - 1) + ["target@d.top"])
    far = net_events.NetEvent("smtp", 1.0, rcpt_to=["x"] * last + ["target@d.top"])
    assert len(rs.evaluate([near])) == 1 and rs.evaluate([far]) == []


def test_other_operators_look_at_every_element_of_a_list_field():
    rs = _rules("rules:\n  - {id: r, name: r, event: smtp, match: {rcpt_to|endswith: '@d.top'}}")
    far = net_events.NetEvent("smtp", 1.0, rcpt_to=["x"] * 200 + ["a@d.top"])
    assert len(rs.evaluate([far])) == 1


def _without_the_load_time_check(monkeypatch):
    """Load ``(a|aa)+$`` and its kind, which the load-time check would refuse, to
    see what the timeout does when the check lets one through."""
    monkeypatch.setattr(net_rules._Risk, "work", lambda self, items, inside=False: 0)


needs_regex = pytest.mark.skipif(net_rules._regex_module is None,
                                 reason="no timeout without the regex module")


@needs_regex
def test_a_regex_that_runs_away_times_out_and_the_rule_is_unevaluated(monkeypatch):
    _without_the_load_time_check(monkeypatch)
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: '(a|aa)+$'}}")
    assert rs.errors == []
    evil = _http(1.0, path="a" * 80 + "!")
    start = time.time()
    got = rs.evaluate([evil, _http(2.0, path="aa")])
    assert time.time() - start < 1.0
    assert [h["events"][0]["index"] for h in got] == [1]            # the ordinary event still matches
    assert got.unevaluated == [{"rule_id": "r", "events": 1, "reasons": ["timeout"]}]


@needs_regex
def test_a_timed_out_regex_is_neither_false_nor_true_inside_not(monkeypatch):
    _without_the_load_time_check(monkeypatch)
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {not: {path|re: '(a|aa)+$'}}}")
    got = rs.evaluate([_http(1.0, path="a" * 80 + "!")])
    assert got == [] and got.unevaluated[0]["reasons"] == ["timeout"]


@needs_regex
def test_a_regex_that_cannot_be_stopped_by_the_checker_still_costs_one_timeout_per_call(monkeypatch):
    """What the budget is for: many events made to hurt one pattern."""
    _without_the_load_time_check(monkeypatch)
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: '(a|aa)+$'}}")
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.3)
    evs = [_http(float(i), path="a" * 80 + "!") for i in range(2000)]
    start = time.time()
    got = rs.evaluate(evs)
    took = time.time() - start
    assert took < 0.3 + 5 * net_rules.REGEX_TIMEOUT_S + 0.2
    assert got.budget_spent is True
    reasons = got.unevaluated[0]["reasons"]
    assert got.unevaluated[0]["events"] == 2000 and "budget" in reasons


@needs_regex
@pytest.mark.parametrize("pattern", [
    r"^(?:\w*\w*\w*\w*\w*\w*b|\w)",
    r"^(?:a(?=\w*\w*\w*\w*\w*\w*!))+",
    r"^(?:\w*\w*\w*\w*\w*b|\w)",
    r"^(?:.*=.*&.*=.*&.*=.*x|/)",
    r"(a+)+$",
    r"^/(\w+/?){1,5}\.php$",
])
def test_the_patterns_that_got_past_the_checker_are_harmless_with_the_timeout(pattern, monkeypatch):
    """Judged by what happens, whatever the load-time check says: either refused,
    or one event with a 256-character field is decided or timed out in well under a second."""
    _without_the_load_time_check(monkeypatch)
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": '%s'}}" % pattern)
    assert rs.errors == []
    start = time.time()
    for subject in ("a" * 256, "a=" * 128, "/" + "a/" * 128, "a" * 255 + "!"):
        rs.evaluate([_http(path=subject)])
    assert time.time() - start < 1.0


def test_without_the_regex_module_the_checker_is_the_guard_and_the_cut_is_short(monkeypatch):
    monkeypatch.setattr(net_rules, "_regex_module", None)
    assert net_rules.subject_limit() == net_rules.MAX_SUBJECT_UNGUARDED
    rs = _rules("rules:\n  - {id: r, name: r, event: http, match: {path|re: 'x$'}}\n"
                "  - {id: bad, name: b, event: http, match: {path|re: '(a+)+$'}}")
    assert [r["id"] for r in rs.rules] == ["r"] and len(rs.errors) == 1
    assert not rs.rules[0]["match"] == {} and net_rules._compile_regex("a")._pattern.__class__.__module__ == "re"
    cut = net_rules.MAX_SUBJECT_UNGUARDED
    assert len(rs.evaluate([_http(path="a" * (cut - 1) + "x")])) == 1
    assert rs.evaluate([_http(path="a" * cut + "x")]) == []


def test_with_the_regex_module_the_cut_is_longer_and_calls_are_guarded():
    if net_rules._regex_module is None:
        pytest.skip("no regex module")
    assert net_rules.subject_limit() == net_rules.MAX_SUBJECT > net_rules.MAX_SUBJECT_UNGUARDED
    assert net_rules._compile_regex("a").guarded is True


def test_a_regex_sees_further_into_a_field_with_the_timeout_than_without(monkeypatch):
    rs = _rules("rules:\n  - {id: h, name: h, event: http, match: {\"path|re\": 'late'}}")
    mid = net_rules.MAX_SUBJECT_UNGUARDED + 100
    assert (len(rs.evaluate([_http(path="a" * mid + "late")])) == 1) == (
        net_rules._regex_module is not None)


# --- cost -----------------------------------------------------------------------

def test_rules_are_only_tried_on_events_they_can_match():
    names = ["h%d.top" % i for i in range(200)]
    rs = _rules("rules:\n" + "".join(
        "  - {id: r%d, name: r, event: dns, match: {dest: %s}}\n" % (i, n)
        for i, n in enumerate(names))
        + "  - {id: other, name: o, event: http, match: {path: /x}}\n")
    calls = []
    for rule in rs.rules:
        original = rule._match
        rule._match = lambda e, original=original, rule=rule: (calls.append(rule["id"]), original(e))[1]
    evs = [net_events.NetEvent("dns", float(i), dest="h%d.top" % (i % 250)) for i in range(1000)]
    hits = rs.evaluate(evs)
    assert len(hits) == 200
    assert len(calls) <= len(evs)       # one candidate per event, not 200
    assert "other" not in calls


def test_the_index_agrees_with_trying_every_rule():
    rng = random.Random(7)
    hosts = ["a.top", "B.top", "c.top", "d.top"]
    methods = ["GET", "POST", "PUT"]
    kinds = ["pe", "zip", ""]
    lines = []
    for i in range(60):
        cond = rng.choice([
            "dest: %s" % rng.choice(hosts),
            "method: [%s, %s]" % (rng.choice(methods), rng.choice(methods)),
            "dest|in: [%s, %s]" % (rng.choice(hosts), rng.choice(hosts)),
            "status: %d" % rng.choice([200, 404]),
            "path|startswith: /%s" % rng.choice("abc"),
            "form_names: %s" % rng.choice("xyz"),
        ])
        lines.append("  - {id: r%d, name: r, event: http, match: {%s, path|contains: /}}" % (i, cond))
    rs = _rules("rules:\n" + "\n".join(lines))
    assert rs.errors == []
    events = [_http(float(i), dest=rng.choice(hosts).upper() if i % 3 else rng.choice(hosts),
                    method=rng.choice(methods), status=rng.choice([200, 404, None]),
                    path="/" + rng.choice("abc"), kind=rng.choice(kinds),
                    form_names=[rng.choice("xyz"), rng.choice("xyz")], process=rng.choice(["p", "q"]))
              for i in range(300)]
    got = {(h["rule_id"], h["process"]): h["count"] for h in rs.evaluate(events)}
    want = {}
    for rule in rs.rules:
        for e in events:
            if rule._match(e):
                key = (rule["id"], e["process"])
                want[key] = want.get(key, 0) + 1
    assert got == want and got


def test_a_large_rule_set_over_many_events_stays_fast():
    lines = ["  - {id: r%d, name: r, event: http, match: {dest: h%d.top, method: GET}}" % (i, i)
             for i in range(300)]
    lines += ["  - {id: p%d, name: p, event: http, match: {path|startswith: '/p%d/'}}" % (i, i)
              for i in range(100)]
    rs = _rules("rules:\n" + "\n".join(lines))
    events = [_http(float(i), dest="h%d.top" % (i % 5000), method="GET", path="/q/%d" % i)
              for i in range(50000)]
    start = time.time()
    hits = rs.evaluate(events)
    elapsed = time.time() - start
    assert len(hits) == 300
    assert elapsed < 5.0, elapsed
