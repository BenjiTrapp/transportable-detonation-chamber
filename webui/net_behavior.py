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
  * "Regular" can be defined per module. ``memory_evidence`` judges Sysmon's
    connection log for beacons too (at least four connections, coefficient of
    variation up to 0.5, measured with median and median absolute deviation so
    that one slow check-in does not hide a rhythm). Both results feed one
    evidence model, and a second definition would let one sample be periodic
    by one and irregular by the other, or measured at 59.7 s by one and at
    60.0 s by the other. ``periodicity`` here is the one definition;
    ``memory_evidence.beaconing_from_connections`` calls it.
  * Every event is a separate connection. One check-in is a connection and
    often several requests. Events less than ``BEACON_MIN_INTERVAL_S`` after
    the one before are one check-in (a connection, its TLS handshake and its
    request land within a fraction of a second), so those do not put a second
    time scale into the statistics.
  * A short interval is the rhythm. Often it is the inside of a check-in: a
    GET for tasks and, a second or ten seconds later, a POST with the result.
    The timestamps alone cannot always say which, and the median of 1 s and
    59 s intervals is a confident, jitter-free, wrong "1 s". An attempt to find
    the right scale from the gaps (collapse where two gap scales are five times
    apart) was tried and removed: it picked the wrong scale for several burst
    shapes, turned a duty-cycled beacon into one of 3600 s and, because any
    break leaving four starts was accepted and four to six points pass the
    regularity gate by chance, produced more beacons from random traffic than
    before. Two rules replace it, both properties of the series. A request
    within a tenth of the median interval after the start of a check-in is a
    follow-up of that check-in, when the series shows its extra requests
    after check-ins rather than just before them (see
    ``_follow_ups_joined``): a beacon that posts its result a few seconds
    after the GET on some check-ins keeps its interval. Only intervals far
    *below* the median are joined; one far above it is a pause. Joining may
    explain short intervals inside a rhythm the series already has; whether
    it is regular at all is judged before the join. That works while the
    median is the period, i.e. while fewer than about half the intervals are
    follow-ups; a beacon that posts on (nearly) every check-in has the short
    interval as its median and nothing to join against. What is left, a
    series whose intervals still show more than one scale (see
    ``_single_scale``), is reported without a measurement: the beacon event
    keeps the host, the number of check-ins and the span, ``interval``,
    ``jitter``, ``cov`` and ``on_rhythm`` are None and ``unmeasured`` says
    why. Repeated contact is a fact worth keeping; a number that may be the
    spacing inside a burst is not, because a later run is compared against
    it. Only a series that would otherwise have passed the regularity gate is
    reported this way, and only from ``UNMEASURED_MIN_CONNECTIONS`` check-ins
    on, or every host contacted a few times at random would be.
  * Request kinds (method, path) say something about the rhythm. They do not:
    beacons rotate paths, pick URIs at random, mix GET and POST and add a
    favicon, and all of them are one rhythm. Known limitation: a GET every
    period P with its POST a delay d later on every check-in, where d lies
    strictly between P/3 and 2P/3 (on a 60 s beacon: 20 s < d < 40 s), gives
    intervals d and P - d that are less than a factor of two apart. That is
    one scale; the median is d (P/2 when there are as many d as P - d
    intervals, e.g. one POST missing) and it is reported as a confident beacon
    at that interval with jitter near 0. On a jittered beacon the edges of
    the window follow the actual period. Only the kinds could tell it from a
    beacon at d, and it is not detected. Outside the window such a series is
    reported without a measurement, except when the POST comes within a tenth
    of the period before the next GET: then every check-in is a POST with the
    GET as its follow-up and the period is measured. When only some check-ins
    carry the POST, the median stays at the period: a delay up to a tenth of
    it is joined, a longer one counts as an off interval.
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
    group that is not clearly periodic produces no interval (at most the
    unmeasured form above).
  * Events arrive in time order. They are merged from several parsers, so the
    timestamps of each group are sorted before they are measured.
  * All traffic that has a path is a signal. ``/`` on many hosts is browsing,
    and NXDOMAIN answers hours apart are typing mistakes, so neither counts as
    fanout; a failure burst has to fall within ``NXDOMAIN_WINDOW_S``.
  * Every failing name is a name the sample tried. A resolver and a network
    stack fail on names nobody chose: reverse lookups of a subnet
    (``*.in-addr.arpa``), ``wpad`` and ``isatap`` with every search suffix,
    single-label host names, ``.local`` and the like. Twelve PTR lookups in
    24 seconds is a machine looking up its neighbours, not a generated-name
    search, so those names are not counted into the NXDOMAIN burst (they still
    count as failures of their own name for ``retry``). A rule cannot do this
    afterwards: it compares the elements of a list as "any of", so "most of
    these names are infrastructure" has no spelling.
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

# The one definition of a beacon's minimum and spread; memory_evidence uses these.
BEACON_MIN_CONNECTIONS = 4
BEACON_MAX_COV = 0.5
BEACON_MIN_INTERVAL_S = 0.5

# A check-in whose intervals do not cluster around the median is not a rhythm,
# however low the spread of the few that do.
ON_RHYTHM_TOLERANCE = 0.25
ON_RHYTHM_MIN_SHARE = 0.5

# One time scale (see _single_scale). An interval is "off" when it is
# SCALE_BAND times the median or more, or the median divided by SCALE_BAND or
# less: an exact halving is a second scale. It is "far" when it is off by
# SCALE_FAR times. A rhythm tolerates a fifth of its intervals off (stalls, a
# re-register), 5% far (an outage is an event; two in a thousand check-ins are
# noise, two in eight are a second scale; follow-ups that _follow_ups_joined
# put into their check-in are no longer intervals here) but never fewer than
# SCALE_MIN_FAR so that a short series is not judged by a percentage of three,
# and no run of more than SCALE_MAX_RUN consecutive off intervals (a run is a
# second rhythm, a stall is one interval). SCALE_FAR is also the follow-up
# limit: a request within median / SCALE_FAR of a check-in may belong to it.
SCALE_BAND = 2.0
SCALE_FAR = 10.0
SCALE_MAX_OFF_SHARE = 0.2
SCALE_MAX_FAR_SHARE = 0.05
SCALE_MIN_FAR = 1
SCALE_MAX_RUN = 2
# A long interval within MISSED_TOLERANCE of the median of a whole multiple k
# of the median (2 <= k < SCALE_FAR) is k - 1 missed check-ins of the same
# rhythm, not a second time scale: the rhythm is what put it on the multiple.
# The same insight as the follow-up, one step further: a short interval is
# part of the check-in before it, a long one on the beat is a missed round,
# and only a long one off the beat is a pause. See _missed_rounds. Missed
# rounds fall where they fall; when the intervals on a multiple come on a beat
# of their own (every second interval, every third: at evenly spaced
# positions, MISSED_PATTERN_MIN of them or more), the multiple is a second
# scale after all. A GET with its POST 20 s later every 60 s is 20, 40, 20,
# 40: the 40s sit at every second position. They also never make up half of
# the intervals (MISSED_MAX_SHARE): at half, the median itself is a multiple.
MISSED_TOLERANCE = 0.1
MISSED_MAX_SHARE = 0.5
MISSED_PATTERN_MIN = 4

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
# Names that fail without the sample having chosen them (see the module docstring).
HOUSEKEEPING_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".local", ".localdomain", ".lan",
                         ".home.arpa", ".internal", ".intranet", ".corp", ".home")
HOUSEKEEPING_PREFIXES = ("wpad.", "isatap.")

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


def _follow_ups_joined(starts, median):
    """``starts`` with the follow-ups of each check-in joined to it.

    The starts fall into clusters: a start and every start no more than
    ``median / SCALE_FAR`` after it (measured from the cluster's first start,
    so a long run of requests cannot be chained into one). A cluster is one
    check-in with follow-ups (a task's result POSTed a few seconds after the
    GET, a favicon, a retry) when the series as a whole shows its extra
    requests after the check-in, not before the next one
    (``_follow_ups_come_after``); the check-in is then the cluster's first
    request. Otherwise every start is kept, and the short intervals count
    against the series in ``_single_scale``. Only the short side is joined:
    an interval far above the median is a pause, not part of a check-in.
    """
    limit = median / SCALE_FAR
    clusters = []
    for t in starts:
        if clusters and t - clusters[-1][0] <= limit:
            clusters[-1].append(t)
        else:
            clusters.append([t])
    if not _follow_ups_come_after(clusters, limit):
        return starts
    return [cluster[0] for cluster in clusters]


def _follow_ups_come_after(clusters, limit):
    """Do the extra requests of the clusters follow their check-in?

    Locally a GET with a POST three seconds later and a POST three seconds
    before the next GET are the same two timestamps; joining the second kind
    at its first request would put the check-in at the POST and measure the
    POST's delay, not the period. Which request keeps the rhythm shows in the
    intervals around a cluster: after a check-in with a follow-up the gap
    from the previous check-in to the cluster's first request is longer than
    the gap from its last request to the next check-in, by the cluster's
    span; before a check-in it is shorter by as much. One cluster says little
    under jitter, so the differences are summed over all clusters, each
    clipped to ``limit`` (no cluster spans more, so a larger difference is a
    pause next to it, not evidence). Zero or less joins nothing.
    """
    balance = 0.0
    for i in range(1, len(clusters) - 1):
        cluster = clusters[i]
        if len(cluster) == 1:
            continue
        gap_in = cluster[0] - clusters[i - 1][0]
        gap_out = clusters[i + 1][0] - cluster[-1]
        balance += max(-limit, min(limit, gap_in - gap_out))
    return balance > 0


def _missed_rounds(x, median):
    """Is a long interval ``x`` one or more missed check-ins of the rhythm?"""
    k = round(x / median)
    return 2 <= k < SCALE_FAR and abs(x - k * median) <= MISSED_TOLERANCE * median


def _forgiven(intervals, median):
    """Positions of the intervals that are missed rounds, or an empty set.

    Empty when they are too many (``MISSED_MAX_SHARE``) or come on a beat of
    their own (evenly spaced, ``MISSED_PATTERN_MIN`` or more): that is a
    second rhythm, not check-ins that happened not to happen.
    """
    positions = [i for i, x in enumerate(intervals)
                 if x >= SCALE_BAND * median and _missed_rounds(x, median)]
    if len(positions) >= MISSED_MAX_SHARE * len(intervals):
        return set()
    steps = {b - a for a, b in zip(positions, positions[1:])}
    if len(positions) >= MISSED_PATTERN_MIN and len(steps) == 1:
        return set()
    return set(positions)


def _single_scale(intervals, median):
    """Do the intervals lie on one time scale?

    A property of the intervals themselves, not a search for a break: with a
    median of 60 s a series is one rhythm if almost all intervals are near 60 s,
    and two rhythms if a sizeable share is not. Refused are series in which
    more than ``SCALE_MAX_OFF_SHARE`` of the intervals are off the median by
    ``SCALE_BAND``, more than ``SCALE_MAX_FAR_SHARE`` of them (and more than
    ``SCALE_MIN_FAR``) are off by ``SCALE_FAR``, or more than
    ``SCALE_MAX_RUN`` off intervals follow each other. An interval on a whole
    multiple of the median (``_missed_rounds``) is not off: it is the same
    rhythm with check-ins missing, and a beacon that misses one in five rounds
    (or reuses a connection, which Sysmon logs once) is still that beacon,
    unless the multiples come on a beat of their own (``_forgiven``). Known
    limitation: fewer than ``MISSED_PATTERN_MIN`` evenly spaced multiples
    are not recognised as a beat, so 60, 60, 120, 60, 60, 120, 60 measures
    60 s; a longer series of that shape is refused.
    GET plus POST (1 s, 59 s alternating), several requests per check-in, a
    duty cycle and a change of rhythm all fail one of the three; a jittered
    beacon, missed check-ins, an outage and a periodic re-register pass.
    """
    off = far = run = longest = 0
    forgiven = _forgiven(intervals, median)
    for i, x in enumerate(intervals):
        if x <= median / SCALE_BAND or (x >= SCALE_BAND * median and i not in forgiven):
            off += 1
            run += 1
            longest = max(longest, run)
            if x >= SCALE_FAR * median or x <= median / SCALE_FAR:
                far += 1
        else:
            run = 0
    return (off <= SCALE_MAX_OFF_SHARE * len(intervals)
            and far <= max(SCALE_MIN_FAR, SCALE_MAX_FAR_SHARE * len(intervals))
            and longest <= SCALE_MAX_RUN)


def periodicity(timestamps, rounded=True):
    """Measure the rhythm of ``timestamps``.

    Returns ``interval`` (median seconds between check-ins), ``cov`` (robust
    coefficient of variation: 1.4826 * MAD / median), ``jitter`` (the same
    value, as the fraction of the interval the timing wanders by),
    ``connections`` (check-ins seen), ``on_rhythm`` (share of intervals within
    25% of the median), ``single_scale``, ``regular`` (the intervals pass the
    cov and on_rhythm gate, whatever their scale) and ``periodic``. Fewer than
    ``BEACON_MIN_CONNECTIONS`` check-ins measure nothing: interval, cov,
    jitter, on_rhythm, single_scale and regular are None. A series whose
    intervals lie on more than one time scale (``single_scale`` False, see
    ``_single_scale``) has no rhythm to report either: the median of two
    scales is a number that belongs to neither, so interval, cov, jitter and
    on_rhythm are None there too; ``regular`` still says whether it would have
    been taken for a beacon. A series on one scale that is merely irregular
    keeps its numbers and has ``periodic`` False. ``connections`` counts
    check-ins: requests closer than ``BEACON_MIN_INTERVAL_S`` are one, and so
    is a check-in with its follow-ups (see ``_follow_ups_joined``).

    The follow-ups are found against the median of the series before they are
    joined, once; the scale and the numbers are those of the joined series.
    ``regular`` is judged on the series as it came, before the join: joining
    may explain short intervals inside a rhythm the series already has, it
    must never be what makes a series look regular.

    The numbers are rounded for a report (interval to 0.01 s, cov and jitter
    to 0.001, on_rhythm to 0.01). ``rounded=False`` returns them as measured,
    for a caller that compares them against thresholds of its own
    (``memory_evidence`` decides from them how much a beacon weighs, and a
    share of 16/23 must not become 0.70 on the way).
    """
    # sorted() on input that is already in order is a single pass.
    starts = _check_ins(sorted(t for t in timestamps if _usable(t)))
    result = {"interval": None, "jitter": None, "cov": None, "on_rhythm": None,
              "connections": len(starts), "single_scale": None, "regular": None,
              "periodic": False}
    if len(starts) < BEACON_MIN_CONNECTIONS:
        return result
    raw = _measure(starts)
    starts = _follow_ups_joined(starts, raw["median"])
    result["connections"] = len(starts)
    if len(starts) < BEACON_MIN_CONNECTIONS:
        return result
    joined = _measure(starts)
    result.update(single_scale=joined["single"], regular=raw["regular"])
    if joined["single"]:
        keep = (lambda value, digits: round(value, digits)) if rounded else (lambda value, _d: value)
        result.update(
            interval=keep(joined["median"], 2), cov=keep(joined["cov"], 3),
            jitter=keep(joined["cov"], 3), on_rhythm=keep(joined["on_rhythm"], 2),
            periodic=raw["regular"] and joined["regular"])
    return result


def _measure(starts):
    """Median, robust cov, on_rhythm, the regularity gate and the scale."""
    window = starts[:MAX_INTERVALS + 1]
    intervals = [b - a for a, b in zip(window, window[1:])]
    median = statistics.median(intervals)
    mad = statistics.median(abs(x - median) for x in intervals)
    cov = 1.4826 * mad / median
    on_rhythm = sum(1 for x in intervals
                    if abs(x - median) <= ON_RHYTHM_TOLERANCE * median) / len(intervals)
    return {"median": median, "cov": cov, "on_rhythm": on_rhythm,
            "regular": cov <= BEACON_MAX_COV and on_rhythm >= ON_RHYTHM_MIN_SHARE,
            "single": _single_scale(intervals, median)}


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


UNMEASURED_SCALES = "more than one time scale"

# Repeated contact without a measurement needs enough check-ins for the scale
# rule to tolerate one off interval (SCALE_MAX_OFF_SHARE of five intervals is
# one). Below that a single stall already reads as "two scales", which random
# traffic produces all the time.
UNMEASURED_MIN_CONNECTIONS = 6


def _beacon(pid, dest, group):
    """The beacon of a group, measured; or repeated contact without a number.

    A series that would pass the regularity gate except that its intervals lie
    on more than one scale is still repeated contact with this host, so the
    event is kept, with every measurement None and the reason in ``unmeasured``.
    Anything else that is not periodic is not reported.
    """
    p = periodicity(group.times)
    if p["periodic"]:
        measured, unmeasured = True, None
    elif (p["single_scale"] is False and p["regular"]
          and p["connections"] >= UNMEASURED_MIN_CONNECTIONS):
        measured, unmeasured = False, UNMEASURED_SCALES
    else:
        return None
    return net_events.NetEvent(
        "beacon", min(group.times), process=group.process, pid=pid, dest=dest,
        interval=p["interval"], jitter=p["jitter"], cov=p["cov"],
        on_rhythm=p["on_rhythm"], periodic=measured, unmeasured=unmeasured,
        connections=p["connections"],
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


def is_housekeeping(name):
    """Is this a name a resolver or network stack asks for on its own?"""
    name = name.lower().rstrip(".")
    return ("." not in name or name.startswith(HOUSEKEEPING_PREFIXES)
            or name.endswith(HOUSEKEEPING_SUFFIXES))


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
        if etype == "dns" and e.get("nxdomain") and not is_housekeeping(dest):
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
