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
  * one C2 became two beacons when its check-ins were a connection to an
    address plus an HTTP request to the name: the same sample fingerprinted
    differently depending on whether its DNS lookup was inside the capture
  * a DNS lookup two seconds before each request was a check-in of its own:
    interval 2.0 with jitter 0.0 for a 60 s beacon, one lookup plus three
    connections made a beacon, TTL re-lookups raised the connection count, and
    a resolver asking for wpad.lan on a timer was reported as a beacon
  * a GET and a POST one second apart per check-in measured an interval of
    1.0 with jitter 0.0, a confident wrong number; the burst is now collapsed
    relative to the gap between check-ins, and a capture whose two time scales
    cannot be told apart reports nothing
  * an IPv6 answer and the same address written in another letter case did not
    meet
  * that merge went too far: an address answered for two names, or looked up
    only after the connection, was claimed by a name, and the address a
    connection really used disappeared from the event
"""

import json
import random
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


def test_periodicity_reports_the_measurement_of_an_irregular_series():
    # Every interval is within a factor of two of the median, so there is one
    # scale and the numbers are meaningful: they say how irregular it is.
    p = net_behavior.periodicity([0.0, 30.0, 90.0, 210.0, 240.0, 360.0])
    assert p["periodic"] is False and p["single_scale"] is True
    assert p["interval"] == 60.0 and p["cov"] > net_behavior.BEACON_MAX_COV


def test_periodicity_withholds_the_numbers_of_a_series_with_two_scales():
    p = net_behavior.periodicity([0.0, 3.0, 400.0, 405.0, 1200.0, 1201.0])
    assert p["periodic"] is False and p["single_scale"] is False
    assert p["interval"] is None and p["jitter"] is None and p["cov"] is None


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


# --- DNS is not a check-in --------------------------------------------------

def test_a_lookup_two_seconds_ahead_of_each_check_in_does_not_change_the_interval():
    evs = []
    for k in range(8):
        evs.append(lookup(k * 60.0 - 2.0, "c2.top", IP))
        evs.append(ev("http", k * 60.0, dest="c2.top"))
    b = of_type(net_behavior.analyze(evs), "beacon")
    assert len(b) == 1
    assert b[0]["interval"] == 60.0 and b[0]["connections"] == 8 and b[0]["jitter"] == 0.0
    assert b[0]["via"] == ["http"]


def test_one_lookup_and_three_connections_are_not_a_beacon():
    evs = [lookup(-2.0, "c2.top", IP)] + check_ins("c2.top", count=3)
    assert of_type(net_behavior.analyze(evs), "beacon") == []


def test_ttl_re_lookups_do_not_raise_the_connection_count():
    evs = check_ins("c2.top", count=20)
    evs += [lookup(k * 300.0 + 20.0, "c2.top", IP) for k in range(4)]
    b = of_type(net_behavior.analyze(evs), "beacon")
    assert len(b) == 1 and b[0]["connections"] == 20 and b[0]["interval"] == 60.0


def test_lookups_on_a_timer_are_not_a_beacon():
    evs = [lookup(k * 300.0, "wpad.lan", "192.0.2.1") for k in range(8)]
    assert of_type(net_behavior.analyze(evs), "beacon") == []


def test_failed_lookups_on_a_timer_are_a_retry_not_a_beacon():
    evs = [ev("dns", k * 300.0, dest="gone.top", nxdomain=True) for k in range(8)]
    out = net_behavior.analyze(evs)
    assert of_type(out, "beacon") == [] and len(of_type(out, "retry")) == 1


# --- More than one time scale ------------------------------------------------
#
# A timestamp list cannot say whether a short interval is the inside of a
# check-in or the rhythm itself, so a series whose intervals fall on more than
# one scale is not measured. Every row here is either refused or measured
# correctly; none may come out as a confident wrong interval.

def requests(offsets, count=8, step=60.0, start=0.0, methods=None):
    """``count`` check-ins ``step`` apart, one HTTP request at each offset."""
    out = []
    for k in range(count):
        for i, off in enumerate(offsets):
            method = methods[i] if methods else "GET"
            out.append(ev("http", start + k * step + off, dest="c2.top", method=method,
                          path="/task" if method == "GET" else "/result"))
    return out


def beacons_of(events):
    return of_type(net_behavior.analyze(events), "beacon")


def stamps(events):
    return sorted(e["ts"] for e in events)


def refused_or(beacons, interval):
    """No beacon, or only beacons that report ``interval``."""
    return all(b["interval"] == interval for b in beacons)


def test_a_get_and_a_post_one_second_apart_are_refused():
    evs = requests((0.0, 1.0), methods=("GET", "POST"))
    assert beacons_of(evs) == []
    p = net_behavior.periodicity(stamps(evs))
    assert p["periodic"] is False
    assert p["interval"] is None and p["jitter"] is None and p["cov"] is None
    assert p["single_scale"] is False


def test_two_pairs_per_check_in_are_refused():
    evs = requests((0.0, 1.0, 6.0, 7.0), methods=("GET", "POST", "GET", "POST"))
    assert beacons_of(evs) == []


def test_four_requests_with_uneven_offsets_are_refused():
    assert beacons_of(requests((0.0, 0.5, 3.1, 3.6))) == []


def test_a_burst_with_uneven_spacing_is_refused():
    assert beacons_of(requests((0.0, 0.8, 2.6, 3.4), step=120.0)) == []


def test_a_duty_cycled_beacon_is_refused_or_measured_correctly():
    ts = []
    for cycle in range(5):
        ts += [cycle * 3600.0 + k * 60.0 for k in range(10)]     # 10 min on, 50 min off
    p = net_behavior.periodicity(ts)
    assert not p["periodic"] or p["interval"] == 60.0
    evs = [ev("http", t, dest="c2.top") for t in ts]
    assert refused_or(beacons_of(evs), 60.0)


def test_a_fast_beacon_with_regular_pauses_is_refused_or_measured_correctly():
    ts = []
    for block in range(4):
        ts += [block * 430.0 + k for k in range(30)]              # 30 s of 1 Hz, 400 s quiet
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is False or p["interval"] == 1.0
    assert p["interval"] != 430.0


def test_a_phase_change_is_refused_rather_than_one_phase_reported():
    first = [k * 10.0 for k in range(15)]
    second = [140.0 + k * 60.0 for k in range(1, 46)]
    p = net_behavior.periodicity(first + second)
    assert p["periodic"] is False and p["interval"] is None
    # even when the first phase is short
    short = [k * 10.0 for k in range(6)] + [50.0 + k * 60.0 for k in range(1, 46)]
    assert net_behavior.periodicity(short)["periodic"] is False


def test_a_just_under_five_to_one_burst_is_refused():
    # 10.2 s and 49.8 s alternate: the ratio that slipped between two scales.
    evs = requests((0.0, 10.2), methods=("GET", "POST"))
    assert beacons_of(evs) == []


@pytest.mark.parametrize("delay", [13.0, 20.0, 30.0])
def test_a_post_that_follows_the_get_by_ten_seconds_or_more_is_refused(delay):
    # The task runs for ``delay`` seconds, then its result is posted. At 30 s
    # the merged series is evenly spaced and only the request kinds give it
    # away: the GETs come every 60 s, the POSTs every 60 s.
    evs = requests((0.0, delay), methods=("GET", "POST"))
    assert beacons_of(evs) == []


def test_requests_of_one_kind_that_alternate_with_another_are_not_a_beacon_of_their_own():
    gets = [ev("http", k * 60.0, dest="c2.top", method="GET", path="/task") for k in range(8)]
    posts = [ev("http", k * 60.0 + 30.0, dest="c2.top", method="POST", path="/result")
             for k in range(8)]
    assert beacons_of(gets + posts) == []
    assert len(beacons_of(gets)) == 1


def test_two_scales_less_than_ten_times_apart_are_refused_by_share():
    # No request kinds to tell them apart, no run, no extreme interval: 13 s
    # and 47 s alternate, and only the share of off-scale intervals shows it.
    ts = []
    for k in range(8):
        ts += [k * 60.0, k * 60.0 + 13.0]
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is False and p["interval"] is None


def test_two_outages_are_a_second_scale_and_one_is_not():
    steady = [k * 60.0 for k in range(40)]
    one = steady[:20] + [t + 3600.0 for t in steady[20:]]
    two = steady[:13] + [t + 3600.0 for t in steady[13:27]] + [t + 7200.0 for t in steady[27:]]
    assert net_behavior.periodicity(one)["interval"] == 60.0
    assert net_behavior.periodicity(two)["periodic"] is False


def test_bursts_at_random_times_are_refused():
    starts = [0, 30, 400, 450, 1000, 1700, 1760, 2500]
    evs = []
    for t in starts:
        evs += [ev("http", float(t), dest="c2.top"), ev("http", t + 1.0, dest="c2.top")]
    assert beacons_of(evs) == []
    assert net_behavior.periodicity(stamps(evs))["periodic"] is False


def test_a_slow_response_in_the_middle_of_a_long_run_does_not_hide_the_interval():
    # Three requests per check-in whose later ones are rare enough to be noise.
    evs = [ev("http", k * 60.0, dest="c2.top") for k in range(30)]
    evs.append(ev("http", 5 * 60.0 + 2.0, dest="c2.top"))
    assert refused_or(beacons_of(evs), 60.0)


# What must keep working.

def jittered(count, interval, fraction, seed):
    rng = random.Random(seed)
    t, out = 0.0, []
    for _ in range(count):
        out.append(t)
        t += interval * (1.0 + rng.uniform(-fraction, fraction))
    return out


def test_a_clean_beacon_is_measured():
    p = net_behavior.periodicity([k * 60.0 for k in range(10)])
    assert p["periodic"] is True and p["interval"] == 60.0 and p["single_scale"] is True


@pytest.mark.parametrize("fraction", [0.1, 0.3])
def test_a_jittered_beacon_is_measured(fraction):
    p = net_behavior.periodicity(jittered(12, 60.0, fraction, seed=3))
    assert p["periodic"] is True
    assert abs(p["interval"] - 60.0) < 60.0 * fraction


def test_a_long_gap_in_the_middle_is_survived():
    ts = [k * 60.0 for k in range(10)] + [540.0 + 3600.0 + k * 60.0 for k in range(1, 10)]
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is True and p["interval"] == 60.0


def test_one_missed_check_in_is_survived():
    ts = [k * 60.0 for k in range(12) if k != 5]
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is True and p["interval"] == 60.0


def test_exactly_four_check_ins_are_a_beacon():
    p = net_behavior.periodicity([0.0, 61.0, 119.0, 180.0])
    assert p["periodic"] is True and p["connections"] == 4


def test_a_poll_with_a_periodic_re_register_is_survived():
    ts, t = [], 0.0
    for k in range(40):
        ts.append(t)
        t += 300.0 if k % 10 == 9 else 60.0       # every tenth gap is a re-register
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is True and p["interval"] == 60.0


def test_sub_half_second_bursts_are_still_one_check_in():
    ts = []
    for k in range(8):
        ts += [k * 60.0, k * 60.0 + 0.1, k * 60.0 + 0.3]
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is True and p["interval"] == 60.0 and p["connections"] == 8


def test_a_fast_beacon_with_one_pause_keeps_its_interval():
    ts = [float(t) for t in range(0, 30)] + [float(t) for t in range(400, 430)]
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is True and p["interval"] == 1.0


def test_a_steady_beacon_with_one_outage_keeps_its_interval():
    ts = [t * 60.0 for t in range(10)] + [540.0 + 3600.0 + t * 60.0 for t in range(1, 10)]
    p = net_behavior.periodicity(ts)
    assert p["periodic"] is True and p["interval"] == 60.0


def test_a_single_request_per_check_in_is_unchanged():
    p = net_behavior.periodicity([t * 60.0 for t in range(8)])
    assert p["interval"] == 60.0 and p["connections"] == 8 and p["periodic"] is True


def test_a_conn_and_an_http_request_per_check_in_stay_one_beacon():
    evs = [lookup(-0.2, "c2.top", IP)] + check_ins("c2.top", IP, count=8)   # conn at t + 0.1
    b = beacons_of(evs)
    assert len(b) == 1 and b[0]["interval"] == 60.0


# --- Noise ----------------------------------------------------------------------
#
# Random traffic must not turn into a beacon. The generators and the seed are
# fixed; the ceilings are what the version before the burst heuristic (fdaeb19)
# scored on these very series (0 and 37 of 2000), which the burst heuristic
# raised to 25 and 54. The number now must not exceed the old one.

NOISE_TRIALS = 2000
NOISE_SEED = 20261125
NOISE_CEILING_POISSON = 0
NOISE_CEILING_UNIFORM = 37


def _poisson_with_follow_ups(rng):
    t, out = 0.0, []
    for _ in range(rng.randint(10, 20)):
        t += rng.expovariate(1 / 60.0)
        out += [t, t + rng.uniform(1.0, 5.0)]
    return out


def _uniform_times(rng):
    n = rng.randint(10, 20)
    return [rng.uniform(0, 60.0 * n) for _ in range(n)]


def _false_periodic(generator):
    rng = random.Random(NOISE_SEED)
    return sum(1 for _ in range(NOISE_TRIALS)
               if net_behavior.periodicity(generator(rng))["periodic"])


def test_poisson_traffic_with_follow_up_requests_is_not_a_beacon():
    assert _false_periodic(_poisson_with_follow_ups) <= NOISE_CEILING_POISSON


def test_uniformly_random_traffic_is_not_a_beacon():
    assert _false_periodic(_uniform_times) <= NOISE_CEILING_UNIFORM


# --- Address spelling ---------------------------------------------------------

def test_an_ipv6_address_in_another_spelling_still_meets_its_name():
    evs = [lookup(-0.2, "c2.top", "2001:db8::1")]
    evs += check_ins("c2.top", "2001:DB8:0:0:0:0:0:1")
    b = of_type(net_behavior.analyze(evs), "beacon")
    assert len(b) == 1 and b[0]["dest"] == "c2.top" and b[0]["addresses"] == ["2001:db8::1"]


# --- Names and addresses ------------------------------------------------------

IP = "203.0.113.9"


def lookup(ts, name, *answers, **kw):
    return ev("dns", ts, dest=name, query_type="A", answers=list(answers), **kw)


def check_ins(dest_name=None, dest_ip=None, count=6, start=0.0, step=60.0, **kw):
    """HTTP requests to a name and/or connections to an address, same instants."""
    out = []
    for k in range(count):
        t = start + k * step
        if dest_name:
            out.append(ev("http", t, dest=dest_name, **kw))
        if dest_ip:
            out.append(ev("conn", t + 0.1, dest=dest_ip, **kw))
    return out


def test_http_to_a_name_and_connections_to_its_address_are_one_beacon():
    evs = [lookup(-0.2, "c2.top", IP)] + check_ins("c2.top", IP)
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert len(beacons) == 1
    b = beacons[0]
    assert b["dest"] == "c2.top" and b["interval"] == 60.0 and b["connections"] == 6
    assert {"conn", "http"} <= set(b["via"])


def test_the_address_actually_contacted_stays_on_the_event():
    evs = [lookup(-0.2, "c2.top", IP)] + check_ins("c2.top", IP)
    b = of_type(net_behavior.analyze(evs), "beacon")[0]
    assert b["addresses"] == [IP]


def test_connections_alone_to_a_resolved_address_are_reported_under_the_name():
    evs = [lookup(-0.2, "c2.top", IP)] + check_ins(dest_ip=IP)
    b = of_type(net_behavior.analyze(evs), "beacon")
    assert len(b) == 1 and b[0]["dest"] == "c2.top" and b[0]["addresses"] == [IP]


def test_the_name_group_works_with_pid_none():
    evs = [lookup(-0.2, "c2.top", IP)] + check_ins("c2.top", IP)
    assert all(e["pid"] is None for e in evs)
    assert len(of_type(net_behavior.analyze(evs), "beacon")) == 1


def test_an_address_nobody_resolved_groups_alone():
    evs = [lookup(-0.2, "c2.top", "198.51.100.1")]
    evs += check_ins("c2.top") + check_ins(dest_ip=IP)
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert sorted(b["dest"] for b in beacons) == [IP, "c2.top"]
    by_dest = {b["dest"]: b for b in beacons}
    assert by_dest[IP]["addresses"] == [] and by_dest["c2.top"]["addresses"] == []


def test_an_address_answered_for_two_names_is_not_merged():
    evs = [lookup(-9.0, "a.top", IP), lookup(-8.0, "b.top", IP)]
    evs += check_ins("a.top", IP)
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert sorted(b["dest"] for b in beacons) == [IP, "a.top"]


def test_two_names_for_one_address_stay_apart_whichever_lookup_came_first():
    evs = [lookup(-9.0, "b.top", IP), lookup(-8.0, "a.top", IP)] + check_ins(dest_ip=IP)
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert [b["dest"] for b in beacons] == [IP]


def test_a_lookup_after_the_connections_does_not_claim_them():
    evs = check_ins(dest_ip=IP) + [lookup(1000.0, "c2.top", IP)]
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert [b["dest"] for b in beacons] == [IP]
    assert beacons[0]["addresses"] == []


def test_a_lookup_in_the_middle_claims_only_the_connections_after_it():
    # The lookup at 119.9 is part of the 120 s check-in. Connections at 0.1 and
    # 60.1 precede it and stay on the address (two, so no beacon of their own);
    # the ones from 120.1 on join the name's HTTP check-ins.
    evs = [lookup(119.9, "c2.top", IP)] + check_ins("c2.top", IP)
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert [b["dest"] for b in beacons] == ["c2.top"]
    assert beacons[0]["interval"] == 60.0 and beacons[0]["connections"] == 6
    assert beacons[0]["addresses"] == [IP]


def test_a_lookup_at_the_same_instant_does_not_claim_the_connection():
    # The answer is not known before the lookup, so a failure stamped with the
    # lookup's own time cannot have used it: five of the six are claimed.
    evs = [lookup(40.0, "dead.top", IP)]
    evs += [ev("conn_failed", 40.0 + t * 10.0, dest=IP) for t in range(6)]
    r = of_type(net_behavior.analyze(evs), "retry")
    assert [(x["dest"], x["attempts"]) for x in r] == [("dead.top", 5)]


def test_the_lookup_may_come_later_in_the_list_than_the_connections():
    evs = check_ins("c2.top", IP) + [lookup(-0.2, "c2.top", IP)]
    beacons = of_type(net_behavior.analyze(evs), "beacon")
    assert len(beacons) == 1 and beacons[0]["dest"] == "c2.top"


def test_answers_that_are_not_addresses_claim_nothing():
    evs = [lookup(-0.2, "c2.top", "alias.example", "not an address")]
    evs += check_ins(dest_ip="alias.example")
    assert [b["dest"] for b in of_type(net_behavior.analyze(evs), "beacon")] == ["alias.example"]


def test_a_txt_record_that_reads_like_an_address_claims_nothing():
    evs = [ev("dns", -5.0, dest="c2.top", query_type="TXT", answers=[IP])]
    evs += check_ins(dest_ip=IP)
    assert [b["dest"] for b in of_type(net_behavior.analyze(evs), "beacon")] == [IP]


def test_a_cname_chain_still_resolves_the_address_to_the_asked_name():
    evs = [lookup(-0.2, "www.c2.top", "edge.cdn.example", IP)] + check_ins(dest_ip=IP)
    b = of_type(net_behavior.analyze(evs), "beacon")
    assert [x["dest"] for x in b] == ["www.c2.top"]


def test_failures_to_a_resolved_address_are_retries_of_the_name():
    evs = [lookup(-0.2, "dead.top", IP)]
    evs += [ev("conn_failed", t * 10.0, dest=IP) for t in range(5)]
    r = of_type(net_behavior.analyze(evs), "retry")
    assert len(r) == 1 and r[0]["dest"] == "dead.top"
    assert r[0]["attempts"] == 5 and r[0]["addresses"] == [IP]


def test_a_host_reached_by_name_and_by_address_counts_once_for_fanout():
    evs = [lookup(-0.2, "h0.top", IP)]
    evs += [ev("http", 0.0, dest="h0.top", path="/gate.php"),
            ev("http", 1.0, dest=IP, path="/gate.php")]
    evs += [ev("http", 2.0 + i, dest="h%d.top" % i, path="/gate.php") for i in range(1, 4)]
    assert of_type(net_behavior.analyze(evs), "fanout") == []


def test_fanout_still_counts_five_hosts_when_some_are_addresses():
    evs = [lookup(-0.2, "h0.top", IP)]
    evs += [ev("http", 1.0, dest=IP, path="/gate.php")]
    evs += [ev("http", 2.0 + i, dest="h%d.top" % i, path="/gate.php") for i in range(1, 5)]
    f = of_type(net_behavior.analyze(evs), "fanout")
    assert len(f) == 1 and f[0]["hosts"] == 5 and "h0.top" in f[0]["dests"]


def test_beacon_to_a_bare_address_without_any_lookup_keeps_its_address():
    b = of_type(net_behavior.analyze(check_ins(dest_ip=IP)), "beacon")[0]
    assert b["dest"] == IP and b["dest_is_ip"] is True


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


def _resolving_workload(n):
    out = []
    for i in range(n):
        name = "h%d.top" % (i % 500)
        ip = "10.%d.%d.%d" % ((i % 500) // 65536, ((i % 500) // 256) % 256, (i % 500) % 256)
        if i % 4 == 0:
            out.append(lookup(i * 0.7, name, ip))
        else:
            out.append(ev("conn", i * 0.7, dest=ip))
    return out


def test_resolving_addresses_costs_linear_time_too():
    small, large = _resolving_workload(20000), _resolving_workload(80000)

    def best(events):
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            net_behavior.analyze(events)
            times.append(time.perf_counter() - t0)
        return min(times)

    ratio = best(large) / best(small)
    assert ratio < 9, ratio


def test_a_huge_single_group_is_analysed_from_a_bounded_window():
    n = net_behavior.MAX_INTERVALS * 5
    p = net_behavior.periodicity([t * 30.0 for t in range(n)])
    assert p["periodic"] is True and p["interval"] == 30.0
    assert p["connections"] == n
