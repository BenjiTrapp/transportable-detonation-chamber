"""Behaviour of network traffic over time: beacons, retries, fanout.

Regressions covered:
  * grouping by process lost every beacon in a pcap: a capture knows no
    process, so every event has pid None, and the grouping has to work on
    the destination alone
  * a different notion of "regular" than ``memory_evidence`` gave one sample
    contradictory findings; the thresholds and the robust estimate are the same
  * one slow check-in or retry inside an exact rhythm ruined mean/stdev, so a
    real beacon went unreported
  * the DNS lookup, the connection and the HTTP request of one check-in landed
    milliseconds apart and were read as extra, irregular intervals, which
    skewed the measured interval and the jitter
  * three connections, a burst of requests or irregular traffic were taken for
    a beacon; a wrong interval is worse than none because later runs are
    matched on it
  * unsorted events gave different intervals than the same events sorted
  * one process beaconing to a destination was merged with another process
    that happens to talk to the same destination
  * a path every browser requests ("/") on many hosts was reported as a sample
    working through a fallback list
  * NXDOMAIN answers spread over hours were counted as one burst
  * a NaN or missing timestamp raised, or poisoned the sort
  * the cost grew faster than the number of events
"""

import json
import time

import pytest

import memory_evidence
import net_behavior
import net_events


def ev(type, ts, **kw):
    return net_events.NetEvent(type, ts, **kw)


def of_type(events, type):
    return [e for e in events if e["type"] == type]


# --- Beacons ----------------------------------------------------------------

def test_regular_check_ins_become_a_beacon_event():
    evs = [net_events.NetEvent("http", t * 60.0, dest="c2.top", pid=9) for t in range(6)]
    b = [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"][0]
    assert abs(b["interval"] - 60.0) < 1.0 and b["dest"] == "c2.top"


def test_jitter_is_measured_not_assumed():
    ts = [0, 60, 125, 183, 245, 307]
    evs = [net_events.NetEvent("http", float(t), dest="c2.top", pid=9) for t in ts]
    b = [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"][0]
    assert 0.0 < b["jitter"] < 0.3


def test_three_connections_are_not_enough_for_a_beacon():
    evs = [net_events.NetEvent("http", t * 60.0, dest="c2.top") for t in range(3)]
    assert [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"] == []


def test_irregular_traffic_is_not_a_beacon():
    ts = [0, 3, 400, 405, 1200, 1201]
    evs = [net_events.NetEvent("http", float(t), dest="c2.top") for t in ts]
    assert [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"] == []


def test_a_capture_without_processes_still_yields_a_beacon():
    # Controller ruling: pid is None for every event of a pcap. Grouping by
    # pid would have to treat None as a process of its own; if it ever drops
    # such events, the pcap path loses its most important finding.
    evs = [ev("http", t * 60.0, dest="c2.top") for t in range(6)]
    assert all(e["pid"] is None for e in evs)
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert len(beacons) == 1
    assert beacons[0]["pid"] is None
    assert abs(beacons[0]["interval"] - 60.0) < 0.01


def test_two_processes_to_one_destination_are_two_rhythms():
    # Process 1 checks in every 60 s, process 2 every 100 s, offset. Merged
    # they would be irregular; apart each is exact.
    evs = [ev("http", t * 60.0, dest="c2.top", pid=1) for t in range(6)]
    evs += [ev("http", 13.0 + t * 100.0, dest="c2.top", pid=2) for t in range(6)]
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert sorted((b["pid"], b["interval"]) for b in beacons) == [(1, 60.0), (2, 100.0)]


def test_the_thresholds_are_those_of_memory_evidence():
    assert net_behavior.BEACON_MIN_CONNECTIONS == memory_evidence.BEACON_MIN_CONNECTIONS
    assert net_behavior.BEACON_MAX_COV == memory_evidence.BEACON_MAX_COV
    assert net_behavior.BEACON_MIN_INTERVAL_S == memory_evidence.BEACON_MIN_INTERVAL_S


def test_four_connections_are_enough_like_memory_evidence():
    # memory_evidence needs four connections, i.e. three intervals.
    times = [0.0, 60.0, 120.0, 180.0]
    mine = net_behavior.periodicity(times)
    theirs = memory_evidence.beaconing_from_connections(
        [(t, "10.0.0.1", 443) for t in times])
    assert mine["periodic"] is True and len(theirs) == 1
    assert mine["interval"] == theirs[0]["mean_interval_s"]
    assert mine["cov"] == theirs[0]["cov"]


@pytest.mark.parametrize("times", [
    [0, 60, 120, 180, 240, 300],
    [0, 60, 125, 183, 245, 307],
    [0, 10, 20, 31, 40, 52, 60],
    [0, 3, 400, 405, 1200, 1201],
    [0, 1, 2, 3, 4, 5, 6, 7],
    [0, 60, 120, 180, 900, 960, 1020, 1080],
])
def test_periodicity_agrees_with_memory_evidence_on_what_is_regular(times):
    mine = net_behavior.periodicity([float(t) for t in times])
    theirs = memory_evidence.beaconing_from_connections(
        [(float(t), "10.0.0.1", 443) for t in times])
    assert mine["periodic"] == bool(theirs)


def test_one_slow_check_in_does_not_hide_the_rhythm():
    ts = [0, 60, 120, 180, 240, 540, 600, 660, 720]    # one 300 s gap
    p = net_behavior.periodicity([float(t) for t in ts])
    assert p["periodic"] is True
    assert p["interval"] == 60.0


def test_a_slow_first_connect_does_not_move_the_interval():
    ts = [0, 7, 67, 127, 187, 247]     # the first gap is 7 s, not 60
    p = net_behavior.periodicity([float(t) for t in ts])
    assert p["periodic"] is True and p["interval"] == 60.0


def test_periodicity_reports_the_measurement_even_when_not_periodic():
    p = net_behavior.periodicity([0.0, 3.0, 400.0, 405.0, 1200.0, 1201.0])
    assert p["periodic"] is False
    assert p["interval"] is not None and p["cov"] > net_behavior.BEACON_MAX_COV


def test_periodicity_with_too_few_points_measures_nothing():
    p = net_behavior.periodicity([0.0, 60.0, 120.0])
    assert p["periodic"] is False
    assert p["interval"] is None and p["jitter"] is None and p["cov"] is None


def test_periodicity_of_nothing():
    p = net_behavior.periodicity([])
    assert p["periodic"] is False and p["interval"] is None


def test_exact_rhythm_has_zero_jitter():
    p = net_behavior.periodicity([t * 30.0 for t in range(8)])
    assert p["interval"] == 30.0 and p["jitter"] == 0.0 and p["cov"] == 0.0


def test_jitter_is_a_fraction_equal_to_the_cov():
    p = net_behavior.periodicity([float(t) for t in (0, 60, 125, 183, 245, 307)])
    assert p["jitter"] == p["cov"]
    assert 0.0 < p["jitter"] < 0.3


def test_one_request_burst_is_one_check_in():
    # Each check-in is a DNS lookup, a connection and an HTTP request within a
    # few hundred milliseconds. The interval is 60 s, not 59.8 s.
    evs = []
    for k in range(6):
        t = k * 60.0
        evs += [ev("dns", t, dest="c2.top"), ev("conn", t + 0.05, dest="c2.top"),
                ev("http", t + 0.2, dest="c2.top")]
    b = of_type(net_behavior.analyze(evs), "beacon")
    assert len(b) == 1
    assert b[0]["interval"] == 60.0 and b[0]["jitter"] == 0.0
    assert b[0]["connections"] == 6


def test_a_burst_of_requests_is_not_a_beacon():
    evs = [ev("http", 100.0 + i * 0.1, dest="cdn.example") for i in range(40)]
    assert of_type(net_behavior.analyze(evs), "beacon") == []


def test_unsorted_events_give_the_same_beacon():
    evs = [ev("http", t * 60.0, dest="c2.top") for t in range(6)]
    shuffled = [evs[i] for i in (3, 0, 5, 1, 4, 2)]
    assert net_behavior.analyze(shuffled) == net_behavior.analyze(evs)


def test_beacon_names_what_it_was_made_of():
    evs = [ev("http", t * 60.0, dest="c2.top", process="a.exe", pid=9) for t in range(6)]
    b = of_type(net_behavior.analyze(evs), "beacon")[0]
    assert b["process"] == "a.exe" and b["pid"] == 9
    assert b["ts"] == 0.0 and b["first_ts"] == 0.0 and b["last_ts"] == 300.0
    assert b["connections"] == 6 and b["via"] == ["http"]


def test_only_events_that_reach_out_make_a_beacon():
    # decoded / download / beacon events of an earlier run are not check-ins.
    evs = [ev(t, i * 60.0, dest="c2.top")
           for i in range(6) for t in ("decoded", "download", "beacon", "retry", "fanout")]
    assert of_type(net_behavior.analyze(evs), "beacon") == []


def test_events_without_a_destination_are_ignored():
    evs = [ev("http", t * 60.0, dest="") for t in range(6)]
    assert net_behavior.analyze(evs) == []


# --- Retries -----------------------------------------------------------------

def test_repeated_failures_to_one_endpoint_become_a_retry_event():
    evs = [net_events.NetEvent("conn_failed", t * 10.0, dest="dead.top") for t in range(5)]
    r = [e for e in net_behavior.analyze(evs) if e["type"] == "retry"][0]
    assert r["dest"] == "dead.top" and r["attempts"] == 5


def test_a_few_failures_are_not_a_retry():
    evs = [ev("conn_failed", t * 10.0, dest="dead.top") for t in range(4)]
    assert of_type(net_behavior.analyze(evs), "retry") == []


def test_failures_to_different_endpoints_are_not_retries():
    evs = [ev("conn_failed", t * 10.0, dest="h%d.top" % t) for t in range(8)]
    assert of_type(net_behavior.analyze(evs), "retry") == []


def test_successes_do_not_count_as_retries():
    evs = [ev("conn", t * 10.0, dest="ok.top") for t in range(8)]
    assert of_type(net_behavior.analyze(evs), "retry") == []


def test_a_name_that_never_resolves_is_retried_too():
    evs = [ev("dns", t * 5.0, dest="gone.top", nxdomain=True) for t in range(5)]
    r = of_type(net_behavior.analyze(evs), "retry")
    assert len(r) == 1 and r[0]["dest"] == "gone.top" and r[0]["attempts"] == 5
    assert r[0]["via"] == ["dns"]


def test_resolved_lookups_are_not_retries():
    evs = [ev("dns", t * 5.0, dest="ok.top", nxdomain=False) for t in range(8)]
    assert of_type(net_behavior.analyze(evs), "retry") == []


def test_retry_event_spans_the_attempts():
    evs = [ev("conn_failed", 100.0 + t * 10.0, dest="dead.top", pid=None) for t in range(5)]
    r = of_type(net_behavior.analyze(evs), "retry")[0]
    assert r["ts"] == 100.0 and r["first_ts"] == 100.0 and r["last_ts"] == 140.0
    assert r["pid"] is None and r["via"] == ["conn_failed"]


# --- Fanout ------------------------------------------------------------------

def test_the_same_path_on_many_hosts_becomes_a_fanout_event():
    evs = [net_events.NetEvent("http", float(i), dest="h%d.top" % i, path="/gate.php")
           for i in range(5)]
    f = [e for e in net_behavior.analyze(evs) if e["type"] == "fanout"][0]
    assert f["path"] == "/gate.php" and f["hosts"] == 5


def test_fanout_lists_the_hosts_it_saw():
    evs = [ev("http", float(i), dest="h%d.top" % i, path="/gate.php") for i in range(5)]
    f = of_type(net_behavior.analyze(evs), "fanout")[0]
    assert f["dests"] == ["h%d.top" % i for i in range(5)]


def test_the_same_host_repeated_is_not_fanout():
    evs = [ev("http", float(i), dest="one.top", path="/gate.php") for i in range(9)]
    assert of_type(net_behavior.analyze(evs), "fanout") == []


def test_four_hosts_are_not_fanout():
    evs = [ev("http", float(i), dest="h%d.top" % i, path="/gate.php") for i in range(4)]
    assert of_type(net_behavior.analyze(evs), "fanout") == []


@pytest.mark.parametrize("path", ["/", ""])
def test_the_root_path_on_many_hosts_is_just_browsing(path):
    evs = [ev("http", float(i), dest="h%d.top" % i, path=path) for i in range(12)]
    assert of_type(net_behavior.analyze(evs), "fanout") == []


def test_different_paths_on_many_hosts_are_not_fanout():
    evs = [ev("http", float(i), dest="h%d.top" % i, path="/p%d" % i) for i in range(12)]
    assert of_type(net_behavior.analyze(evs), "fanout") == []


def test_an_nxdomain_burst_is_reported_as_fanout_of_failures():
    evs = [net_events.NetEvent("dns", float(i), dest="x%d.top" % i, nxdomain=True)
           for i in range(12)]
    assert any(e["type"] == "fanout" and e.get("nxdomain") for e in net_behavior.analyze(evs))


def test_nxdomain_fanout_counts_distinct_names():
    evs = [ev("dns", float(i), dest="x%d.top" % (i % 3), nxdomain=True) for i in range(30)]
    assert [e for e in net_behavior.analyze(evs) if e["type"] == "fanout"] == []


def test_nxdomain_spread_over_hours_is_not_a_burst():
    evs = [ev("dns", i * 1800.0, dest="x%d.top" % i, nxdomain=True) for i in range(12)]
    assert [e for e in net_behavior.analyze(evs) if e["type"] == "fanout"] == []


def test_nxdomain_burst_is_found_inside_a_longer_capture():
    evs = [ev("dns", i * 1800.0, dest="old%d.top" % i, nxdomain=True) for i in range(5)]
    evs += [ev("dns", 100000.0 + i, dest="x%d.top" % i, nxdomain=True) for i in range(12)]
    f = [e for e in net_behavior.analyze(evs) if e["type"] == "fanout"]
    assert len(f) == 1
    assert f[0]["hosts"] == 12 and f[0]["ts"] == 100000.0 and f[0]["nxdomain"] is True


def test_answered_lookups_are_not_an_nxdomain_burst():
    evs = [ev("dns", float(i), dest="x%d.top" % i, nxdomain=False) for i in range(12)]
    assert of_type(net_behavior.analyze(evs), "fanout") == []


# --- Shape, robustness, cost -----------------------------------------------

def test_no_events_produce_no_behavior():
    assert net_behavior.analyze([]) == []


def test_output_is_network_events_in_time_order_and_json():
    evs = [ev("http", t * 60.0, dest="c2.top", path="/gate.php") for t in range(6)]
    evs += [ev("conn_failed", 1000.0 + t, dest="dead.top") for t in range(5)]
    out = net_behavior.analyze(evs)
    assert {e["type"] for e in out} == {"beacon", "retry"}
    assert all(isinstance(e, net_events.NetEvent) for e in out)
    assert [e["ts"] for e in out] == sorted(e["ts"] for e in out)
    assert all(e["in_tree"] is False for e in out)
    json.dumps(out)


def test_analyze_does_not_modify_its_input():
    evs = [ev("http", t * 60.0, dest="c2.top") for t in (3, 0, 5, 1, 4, 2)]
    before = [dict(e) for e in evs]
    net_behavior.analyze(evs)
    assert evs == before


def test_unusable_timestamps_do_not_break_the_analysis():
    evs = [ev("http", t * 60.0, dest="c2.top") for t in range(6)]
    bad = ev("http", 0.0, dest="c2.top")
    bad["ts"] = float("nan")
    worse = ev("http", 0.0, dest="c2.top")
    worse["ts"] = None
    out = net_behavior.analyze(evs + [bad, worse])
    assert of_type(out, "beacon")[0]["interval"] == 60.0
    assert net_behavior.periodicity([float("nan"), None, float("inf")])["periodic"] is False


def _workload(n):
    out = []
    for i in range(n):
        k = i % 4
        if k == 0:
            out.append(ev("http", i * 0.7, dest="c2.top", pid=None, path="/gate.php"))
        elif k == 1:
            out.append(ev("http", i * 0.7, dest="h%d.top" % i, path="/gate.php"))
        elif k == 2:
            out.append(ev("dns", i * 0.7, dest="x%d.top" % i, nxdomain=True))
        else:
            out.append(ev("conn_failed", i * 0.7, dest="dead%d.top" % (i % 50)))
    return out


def test_cost_grows_linearly_with_the_number_of_events():
    small, large = _workload(20000), _workload(80000)

    def best(events):
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            net_behavior.analyze(events)
            times.append(time.perf_counter() - t0)
        return min(times)

    ratio = best(large) / best(small)
    # 4x the events: linear is about 4, quadratic about 16.
    assert ratio < 9, ratio


def test_a_huge_single_group_is_analysed_from_a_bounded_window():
    n = net_behavior.MAX_INTERVALS * 5
    p = net_behavior.periodicity([t * 30.0 for t in range(n)])
    assert p["periodic"] is True and p["interval"] == 30.0
    assert p["connections"] == n
