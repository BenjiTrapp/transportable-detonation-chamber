"""Network behaviour over time: beacons, retries and fanout.

The parsers say what each exchange was. One connection to an odd host says
almost nothing; the same connection every sixty seconds is a beacon, five
failures to one dead address is a loader whose C2 is gone, one path tried
against eight hosts is a sample working through a fallback list. This module
reads the whole event list of a capture and reports those repetitions as
``beacon``, ``retry`` and ``fanout`` events.

Several assumptions would make the result wrong:

  * A beacon belongs to a process. A pcap knows no process: every event has
    ``pid`` None, so events are grouped by ``(pid, dest)`` and None is simply
    one more value. Requiring a pid would drop every beacon of the pcap path.
  * "Regular" can be defined per module. ``memory_evidence`` already judges
    periodicity (at least four connections, coefficient of variation up to
    0.5, measured with median and median absolute deviation so that one slow
    check-in does not hide a rhythm). Both results feed one evidence model, so
    this module uses the same thresholds and estimator; a second definition
    would let one sample be periodic by one and irregular by the other.
  * Every event is a separate connection. One check-in is a DNS lookup, a
    connection and an HTTP request within a fraction of a second. Counting
    them separately puts tiny intervals into the statistics and moves the
    measured interval off the true one. Events closer than
    ``BEACON_MIN_INTERVAL_S`` to the check-in they belong to are one check-in.
  * A reported interval is a label. It is a measurement: a fingerprint of the
    sample is built on it later, so a wrong interval is worse than none. A
    group that is not clearly periodic produces no beacon event.
  * Events arrive in time order. They are merged from several parsers, so the
    timestamps of each group are sorted before they are measured.
  * All traffic that has a path is a signal. ``/`` on many hosts is browsing,
    and NXDOMAIN answers hours apart are typing mistakes, so neither counts as
    fanout; a failure burst has to fall within ``NXDOMAIN_WINDOW_S``.
  * The cost may grow with the size of the capture. The events are read once,
    grouped in dictionaries, and each group is measured from at most
    ``MAX_INTERVALS`` intervals, so the work is linear in the number of events
    (sorting a group costs nothing extra when its events are already in time
    order, which is what a merged timeline gives).

Timestamps are Unix seconds as float, as in ``net_events``. An event with a
timestamp that is not a finite number is ignored: it cannot be placed in time.
"""

import math
import statistics

import net_events

# Same thresholds as memory_evidence.beaconing_from_connections.
BEACON_MIN_CONNECTIONS = 4
BEACON_MAX_COV = 0.5
BEACON_MIN_INTERVAL_S = 0.5

# A check-in whose intervals do not cluster around the median is not a rhythm,
# however low the spread of the few that do.
ON_RHYTHM_TOLERANCE = 0.25
ON_RHYTHM_MIN_SHARE = 0.5

# Intervals taken into the measurement of one group. A beacon is established
# long before this; the cap keeps the cost of one huge group bounded.
MAX_INTERVALS = 2000

# Events that are a check-in. Download, upload and websocket events repeat an
# http event, decoded/raw describe a payload, and beacon/retry/fanout are this
# module's own output.
BEACON_TYPES = frozenset(("conn", "conn_failed", "tls", "http", "udp", "dns"))

RETRY_MIN_ATTEMPTS = 5

FANOUT_MIN_HOSTS = 5
FANOUT_IGNORED_PATHS = frozenset(("", "/"))

NXDOMAIN_MIN_NAMES = 10
NXDOMAIN_WINDOW_S = 60.0

# Hosts named in a fanout event; the count in ``hosts`` is complete.
MAX_LISTED_DESTS = 20


def _usable(ts):
    return (isinstance(ts, (int, float)) and not isinstance(ts, bool)
            and math.isfinite(ts))


def _check_ins(times):
    """Start of each check-in of an ascending list.

    An event less than ``BEACON_MIN_INTERVAL_S`` after the one before it
    belongs to the same check-in, so a run of closely spaced requests is one
    check-in however long it goes on.
    """
    starts = []
    previous = None
    for t in times:
        if previous is None or t - previous >= BEACON_MIN_INTERVAL_S:
            starts.append(t)
        previous = t
    return starts


def periodicity(timestamps):
    """Measure the rhythm of ``timestamps``.

    Returns ``interval`` (median seconds between check-ins), ``cov`` (robust
    coefficient of variation: 1.4826 * MAD / median), ``jitter`` (the same
    value, as the fraction of the interval the timing wanders by),
    ``connections`` (check-ins seen), ``on_rhythm`` (share of intervals within
    25% of the median) and ``periodic``. Fewer than ``BEACON_MIN_CONNECTIONS``
    check-ins measure nothing: interval, cov, jitter and on_rhythm are None.
    A group that was measured but is not regular keeps its numbers and has
    ``periodic`` False.
    """
    # sorted() on input that is already in order is a single pass.
    starts = _check_ins(sorted(t for t in timestamps if _usable(t)))
    result = {"interval": None, "jitter": None, "cov": None, "on_rhythm": None,
              "connections": len(starts), "periodic": False}
    if len(starts) < BEACON_MIN_CONNECTIONS:
        return result
    window = starts[:MAX_INTERVALS + 1]
    intervals = [b - a for a, b in zip(window, window[1:])]
    median = statistics.median(intervals)
    mad = statistics.median(abs(x - median) for x in intervals)
    cov = 1.4826 * mad / median
    on_rhythm = sum(1 for x in intervals
                    if abs(x - median) <= ON_RHYTHM_TOLERANCE * median) / len(intervals)
    result.update(
        interval=round(median, 2), cov=round(cov, 3), jitter=round(cov, 3),
        on_rhythm=round(on_rhythm, 2),
        periodic=cov <= BEACON_MAX_COV and on_rhythm >= ON_RHYTHM_MIN_SHARE)
    return result


class _Group:
    """What one destination (or path) did: times, event types, a process name."""

    __slots__ = ("times", "types", "process", "pids")

    def __init__(self):
        self.times = []
        self.types = set()
        self.process = ""
        self.pids = set()

    def add(self, event, ts):
        self.times.append(ts)
        self.types.add(event["type"])
        self.pids.add(event.get("pid"))
        if not self.process:
            self.process = event.get("process") or ""


def _beacon(pid, dest, group):
    p = periodicity(group.times)
    if not p["periodic"]:
        return None
    return net_events.NetEvent(
        "beacon", min(group.times), process=group.process, pid=pid, dest=dest,
        interval=p["interval"], jitter=p["jitter"], cov=p["cov"],
        on_rhythm=p["on_rhythm"], connections=p["connections"],
        first_ts=min(group.times), last_ts=max(group.times),
        via=sorted(group.types))


def _retry(dest, group):
    if len(group.times) < RETRY_MIN_ATTEMPTS:
        return None
    pid = next(iter(group.pids)) if len(group.pids) == 1 else None
    return net_events.NetEvent(
        "retry", min(group.times), process=group.process, pid=pid, dest=dest,
        attempts=len(group.times), first_ts=min(group.times),
        last_ts=max(group.times), via=sorted(group.types))


def _path_fanout(path, hosts, first_ts):
    if len(hosts) < FANOUT_MIN_HOSTS:
        return None
    return net_events.NetEvent(
        "fanout", first_ts, path=path, hosts=len(hosts),
        dests=list(hosts)[:MAX_LISTED_DESTS])


def _nxdomain_fanout(failures):
    """The densest window of NXDOMAIN answers, as one event if it is a burst.

    ``failures`` holds (ts, name). A window slides over them in time order
    with a count per name, so every failure enters and leaves it once.
    """
    failures.sort(key=lambda f: f[0])
    counts = {}
    left = 0
    best = (0, 0, 0)            # distinct names, first index, last index
    for right, (ts, name) in enumerate(failures):
        counts[name] = counts.get(name, 0) + 1
        while ts - failures[left][0] > NXDOMAIN_WINDOW_S:
            gone = failures[left][1]
            counts[gone] -= 1
            if not counts[gone]:
                del counts[gone]
            left += 1
        if len(counts) > best[0]:
            best = (len(counts), left, right)
    names, first, last = best
    if names < NXDOMAIN_MIN_NAMES:
        return None
    seen = {}
    for _, name in failures[first:last + 1]:
        seen.setdefault(name, None)
    return net_events.NetEvent(
        "fanout", failures[first][0], hosts=names, nxdomain=True,
        window_s=NXDOMAIN_WINDOW_S, dests=list(seen)[:MAX_LISTED_DESTS])


def analyze(events):
    """``beacon``, ``retry`` and ``fanout`` events for a capture's events.

    One pass groups the events: check-ins by (pid, dest), failures by dest,
    HTTP requests by path and NXDOMAIN answers in one list. Each group is then
    measured once. The result is in time order and the input is not changed.
    """
    beacons = {}
    retries = {}
    paths = {}
    nx_failures = []

    for e in events:
        ts = e.get("ts")
        if not _usable(ts):
            continue
        etype = e.get("type")
        dest = e.get("dest")
        if not isinstance(dest, str) or not dest:
            continue
        failed = etype == "conn_failed" or (etype == "dns" and e.get("nxdomain"))
        if etype in BEACON_TYPES:
            beacons.setdefault((e.get("pid"), dest), _Group()).add(e, ts)
        if failed:
            retries.setdefault(dest, _Group()).add(e, ts)
        if etype == "dns" and e.get("nxdomain"):
            nx_failures.append((ts, dest))
        path = e.get("path")
        if etype == "http" and isinstance(path, str) and path not in FANOUT_IGNORED_PATHS:
            hosts, first = paths.setdefault(path, ({}, ts))
            hosts.setdefault(dest, None)
            if ts < first:
                paths[path] = (hosts, ts)

    out = []
    for (pid, dest), group in beacons.items():
        out.append(_beacon(pid, dest, group))
    for dest, group in retries.items():
        out.append(_retry(dest, group))
    for path, (hosts, first) in paths.items():
        out.append(_path_fanout(path, hosts, first))
    out.append(_nxdomain_fanout(nx_failures))
    return net_events.sort_events(e for e in out if e is not None)
