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
  * Every event is a separate connection. One check-in is a connection and one
    or several HTTP requests (a GET for tasks, a POST with the result), a
    second or more apart. Counting them separately puts a second, smaller time
    scale into the statistics and the measured interval is the spacing inside
    the burst, with zero jitter: confidently wrong. Events closer than
    ``BEACON_MIN_INTERVAL_S`` to the one before are one check-in; and where the
    gaps between events fall into two scales at least ``BURST_GAP_RATIO``
    apart, the smaller scale is the inside of a check-in and is collapsed too,
    when that leaves at least four check-ins. Four or more bursts that are not
    regular at the larger scale are not a beacon, and the small spacing is not
    reported as one: no beacon beats a wrong interval. (This is the one place
    where the result differs from ``memory_evidence``, which would report the
    1 s spacing; the later merge of the two keeps this behaviour.) The price: a
    fast beacon that also pauses four times for several times its interval is
    reported as nothing.
  * A DNS lookup is a check-in. It is not: it happens seconds before the
    connection it serves, again whenever a TTL expires, and a resolver asks for
    names such as wpad.lan on a timer with no sample involved. Its time would
    put a spurious start into a group (interval 2 s for a 60 s beacon), and
    a lookup plus three connections would reach the four-connection minimum.
    ``dns`` events therefore only build the name-to-address table and feed
    retry and fanout; they never time a beacon, so a DNS-only rhythm is not
    reported either.
  * A reported interval is a label. It is a measurement: a fingerprint of the
    sample is built on it later, so a wrong interval is worse than none. A
    group that is not clearly periodic produces no beacon event.
  * Events arrive in time order. They are merged from several parsers, so the
    timestamps of each group are sorted before they are measured.
  * All traffic that has a path is a signal. ``/`` on many hosts is browsing,
    and NXDOMAIN answers hours apart are typing mistakes, so neither counts as
    fanout; a failure burst has to fall within ``NXDOMAIN_WINDOW_S``.
  * Every destination is a name. A check-in is often a connection to an address
    plus an HTTP request to the name, and the same C2 would be counted as two
    beacons; a fingerprint built on endpoints and intervals would then depend
    on whether the DNS lookup happened to be inside the capture. An address
    that a ``dns`` answer in the same list resolved joins the name's group, and
    the event keeps ``addresses`` so the contact is still visible. A name is
    only credible when it is unambiguous: an address answered for two names, or
    contacted at or before the first lookup that returned it, stays on its own.
    An address with no lookup at all is itself a finding and is never named.
    A lookup in the middle of a capture splits one host into two groups: the
    connections before it stay on the address, the ones after it join the name.
    Those two beacons (``dest`` an address, ``dest`` a name whose ``addresses``
    holds it) can be the same host.
  * The port is part of the identity of a connection. It is deliberately not
    part of the grouping key, unlike ``memory_evidence``'s ``(ip, port)``: one
    host that beacons on two ports is one beacon, not two half-strength ones.
  * The cost may grow with the size of the capture. The events are read once,
    grouped in dictionaries, and each group is measured from at most
    ``MAX_INTERVALS`` intervals, so the work is linear in the number of events
    (sorting a group costs nothing extra when its events are already in time
    order, which is what a merged timeline gives).

Timestamps are Unix seconds as float, as in ``net_events``. An event with a
timestamp that is not a finite number is ignored: it cannot be placed in time.
"""

import ipaddress
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

# Two gap scales are one burst structure when the larger is at least this many
# times the smaller. The gaps are profiled from the first PROFILE_EVENTS events
# of a group, which bounds the sort.
BURST_GAP_RATIO = 5.0
PROFILE_EVENTS = 4000

# Intervals taken into the measurement of one group. A beacon is established
# long before this; the cap keeps the cost of one huge group bounded.
MAX_INTERVALS = 2000

# Events that are a check-in. Download, upload and websocket events repeat an
# http event, decoded/raw describe a payload, dns lookups are not a check-in
# (see the module docstring), and beacon/retry/fanout are this module's own
# output.
BEACON_TYPES = frozenset(("conn", "conn_failed", "tls", "http", "udp"))

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


def _check_ins(times, gap=BEACON_MIN_INTERVAL_S):
    """Start of each check-in of an ascending list.

    An event less than ``gap`` after the one before it belongs to the same
    check-in, so a run of closely spaced requests is one check-in however long
    it goes on.
    """
    starts = []
    previous = None
    for t in times:
        if previous is None or t - previous >= gap:
            starts.append(t)
        previous = t
    return starts


def _burst_gaps(times):
    """Gaps, smallest first, that separate two time scales of an ascending list.

    A gap is returned when the next smaller distinct gap (none below the
    minimum interval) is at least ``BURST_GAP_RATIO`` times smaller: events
    closer than it may be the inside of one check-in.
    """
    head = times[:PROFILE_EVENTS]
    gaps = sorted(max(b - a, BEACON_MIN_INTERVAL_S) for a, b in zip(head, head[1:]))
    return [high for low, high in zip(gaps, gaps[1:]) if high >= BURST_GAP_RATIO * low]


def periodicity(timestamps):
    """Measure the rhythm of ``timestamps``.

    Returns ``interval`` (median seconds between check-ins), ``cov`` (robust
    coefficient of variation: 1.4826 * MAD / median), ``jitter`` (the same
    value, as the fraction of the interval the timing wanders by),
    ``connections`` (check-ins seen), ``on_rhythm`` (share of intervals within
    25% of the median) and ``periodic``. Fewer than ``BEACON_MIN_CONNECTIONS``
    check-ins measure nothing: interval, cov, jitter and on_rhythm are None.
    A group that was measured but is not regular keeps its numbers and has
    ``periodic`` False. ``connections`` counts check-ins: requests closer than
    the gap between two time scales (see the module docstring) are one.
    """
    # sorted() on input that is already in order is a single pass.
    times = sorted(t for t in timestamps if _usable(t))
    starts = _check_ins(times)
    if len(starts) > BEACON_MIN_CONNECTIONS:
        # The smallest scale break that still leaves a rhythm to measure.
        for gap in _burst_gaps(times):
            coarse = _check_ins(times, gap)
            if BEACON_MIN_CONNECTIONS <= len(coarse) < len(starts):
                starts = coarse
                break
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


def _address(text):
    """The canonical form of an IP address, or None."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _resolutions(events):
    """Address -> (name, time of the first lookup that returned it).

    The name is None when the address was answered for more than one name, in
    any order, anywhere in the list: that is a shared host and no name is
    right. The time is that of the query (the time a ``dns`` event carries),
    the earliest instant at which anything could have used the answer.
    """
    table = {}
    for e in events:
        if e.get("type") != "dns" or not _usable(e.get("ts")):
            continue
        name = e.get("dest")
        answers = e.get("answers")
        if (not isinstance(name, str) or not name or not answers
                or e.get("query_type") not in (None, "A", "AAAA")):
            continue
        for answer in answers:
            address = _address(answer) if isinstance(answer, str) else None
            if address is None:
                continue
            known = table.get(address)
            if known is None:
                table[address] = (name, e["ts"])
            else:
                table[address] = (known[0] if known[0] == name else None,
                                  min(known[1], e["ts"]))
    return table


class _Group:
    """What one destination (or path) did: times, event types, a process name."""

    __slots__ = ("times", "types", "process", "pids", "addresses")

    def __init__(self):
        self.times = []
        self.types = set()
        self.process = ""
        self.pids = set()
        self.addresses = set()

    def add(self, event, ts, address=None):
        self.times.append(ts)
        if address:
            self.addresses.add(address)
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
        via=sorted(group.types), addresses=sorted(group.addresses))


def _retry(dest, group):
    if len(group.times) < RETRY_MIN_ATTEMPTS:
        return None
    pid = next(iter(group.pids)) if len(group.pids) == 1 else None
    return net_events.NetEvent(
        "retry", min(group.times), process=group.process, pid=pid, dest=dest,
        attempts=len(group.times), first_ts=min(group.times),
        last_ts=max(group.times), via=sorted(group.types),
        addresses=sorted(group.addresses))


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

    A first pass reads the ``dns`` answers. A second groups the events:
    check-ins by (pid, name), failures by name, HTTP requests by path and
    NXDOMAIN answers in one list, where an address that a lookup before it
    resolved is replaced by its name. Each group is then measured once. The
    result is in time order and the input is not changed.
    """
    resolved = _resolutions(events)
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
        address = None
        known = None
        if etype != "dns":
            # Answers are canonical; only IPv6 has more than one spelling.
            key = (_address(dest) or dest) if ":" in dest else dest
            known = resolved.get(key)
        if known is not None and known[0] is not None and ts > known[1]:
            address, dest = key, known[0]
        failed = etype == "conn_failed" or (etype == "dns" and e.get("nxdomain"))
        if etype in BEACON_TYPES:
            beacons.setdefault((e.get("pid"), dest), _Group()).add(e, ts, address)
        if failed:
            retries.setdefault(dest, _Group()).add(e, ts, address)
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
