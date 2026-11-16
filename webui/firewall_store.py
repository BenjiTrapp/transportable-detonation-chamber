"""Event store, pending decisions and settings for the FIREWALL tab.

``FirewallStore`` keeps what ``firewall.classify`` needs, as the readers delivered it: the single
Sysmon connections (EID 3) in a ring of ``MAX_CONNECTIONS`` entries and ``RETAIN_S`` seconds, the
DNS map (EID 22), the processes (EID 1), the Windows firewall log, and the PowerShell and BITS events
that carry a URL (the download case). It is a store of its own, not ``log_store``: that one bundles at
once, and the tab needs the single connections (beacon detection) and the process start (newborn).

Times: ``since`` and ``until`` are ISO-8601 text (or epoch seconds); what comes out is what
``firewall`` works in, epoch floats. ``events`` returns the raw Sysmon events of a window, the input of
``firewall.classify``; ``connections`` is the same window bundled by ``firewall.bundle``. A ring
forgets what is older than ``RETAIN_S`` before its *newest* entry, not before the wall clock; an entry dated more
than a day ahead of the clock is kept at the clock, so a sample that sets the time forward cannot empty the ring.

``FirewallCollector`` reads the sources incrementally through injected readers. A reader is called with
keyword arguments and returns a list of events, oldest first; a reader that raises, or answers
``{"error": ...}``, marks its source ``unavailable`` with the first line of the message, and the others carry on.

    connections, dns, processes   ``reader(event_ids=[3], since_iso=...)`` (22 and 1 for the others): the
        contract of ``log_store.Collector``, ``app._read_sysmon_for_logs``, which yields Sysmon events as
        ``_read_sysmon_events`` does. The collector keeps the position as a time, asks again from 5 s before
        the newest event it saw, and the store drops what it has already (``add_*`` count only new events).
        The first read is the last 24 h. Time, not ``EventRecordID``: a cleared Sysmon log strands no cursor.
    powershell    ``reader(since=<EventRecordID or None>)``: ``log_store.parse_powershell_events`` events
        (``time``, ``message``, ``fields.record_id``, ``fields.pid``). The position is the highest record id.
        A reader may answer ``(events, newest_record_id)`` with the newest id of the *log*; one below the
        position held means the log was cleared, and the collector reads it again from the start (``since=0``).
    bits          the same, BITS client EID 59/60: ``{"timestamp", "event_id", "data": {"url"}}``, optionally ``pid``
    firewall      ``reader(since=<offset or None>)`` returns ``(events, new_offset)``: ``log_store.parse_firewall_log``

An event-log reader that returns events without a ``record_id`` (and no explicit position) is refused: they would
be read again at every tick. ``tick`` is not thread-safe: one thread calls it, and the fast cadence of a detonation
window is that thread sleeping less (``interval``). In the window the tick reads Sysmon EID 1, 3, 22 and BITS at
every call (1 s); PowerShell and the firewall log keep to every 10 s. Outside it every call (10 s) reads all but BITS.
The store itself may be read from other threads.

``download_findings`` is the download case: a URL to an executable file in a script block, a command
line or a BITS job, and the connection that fetched it; a finding says whether it is in a detonation, and what to
do with it (block, ask, nothing) is the caller's policy, not this module's. ``PendingStore`` holds the decisions
that follow, and ``Settings`` the server-side state of the tab (``webui/firewall_state.json``).
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit

import firewall

logger = logging.getLogger(__name__)

SOURCES = ("connections", "dns", "processes", "powershell", "firewall", "bits")

MAX_CONNECTIONS = 50000
RETAIN_S = 7 * 86400
MAX_FIREWALL_EVENTS = 50000
MAX_PROCESS_EVENTS = 5000
MAX_PROCESSES = 20000
MAX_URL_EVENTS = 500       # PowerShell and BITS events with a URL, each
MAX_SCRIPT_CHARS = 65536   # of a script block that is kept
MAX_COMMANDLINE_CHARS = 8192

MAX_FUTURE_S = 86400       # an entry dated further ahead than this is placed at "now"
BITS_LOOKBACK_S = 600      # a BITS job counts for a submission whose start is lost only this long ago

FAST_INTERVAL = 1.0
SLOW_INTERVAL = 10.0
SLOW_SLACK_S = 0.5                       # a tick a little early still counts as a slow interval
SLOW_SOURCES = ("powershell", "firewall")    # read every SLOW_INTERVAL even in a detonation window
RECORD_SOURCES = ("powershell", "bits")      # event logs read by EventRecordID

# Reading Sysmon by time, as log_store.Collector does
SYSMON_EVENT_IDS = {"connections": (3,), "dns": (22,), "processes": (1,)}
SYSMON_OVERLAP_S = 5       # a read starts this long before the newest event seen
SYSMON_PAGE = 5000         # most events one Sysmon read returns
START_WINDOW_S = 24 * 3600
MAX_DEDUP_KEYS = 50000     # events remembered per Sysmon source, to drop what an overlapping read brings again
_DEDUP_FIELDS = {
    "connections": ("timestamp", "pid", "image", "protocol", "src_ip", "src_port", "dst_ip", "dst_port"),
    "dns": ("timestamp", "pid", "query", "result"),
    "processes": ("timestamp", "pid", "image", "parent_pid"),
}

ASK_MODES = ("detonation", "all", "off")
DECISIONS = ("allow", "block", "block_fetch")
MAX_OPEN = 200
MAX_HISTORY = 1000
HISTORY_S = 24 * 3600

EXECUTABLE_SUFFIXES = frozenset({".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
                                 ".msi", ".jar", ".lnk", ".cpl", ".ocx"})
# Our own pattern, no input of anyone's: a URL ends at white space, a quote, a bracket or a comma.
URL_RE = re.compile(r"https?://[^\s'\"<>`|^\\(){},]+", re.IGNORECASE)
MAX_URL_LEN = 2048
MAX_URLS = 20
_URL_TRAILING = ".;:!?"

_REPLACE_ATTEMPTS = 10
_REPLACE_PAUSE = 0.05


# ---- small helpers ---------------------------------------------------------------------------


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bound(value: Any) -> Optional[float]:
    """A window bound as epoch seconds: ISO text or a number; None stays None."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    epoch = firewall.epoch_of(value)
    if epoch is None:
        raise ValueError(f"not a time: {value!r}")
    return epoch


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _event_id(ev: Any) -> Optional[int]:
    return _to_int(ev.get("event_id")) if isinstance(ev, dict) else None


def _event_epoch(ev: Dict[str, Any]) -> Optional[float]:
    return firewall.epoch_of(ev.get("timestamp") or ev.get("time"))


def _first_line(exc: BaseException) -> str:
    for line in str(exc).splitlines():
        if line.strip():
            return line.strip()[:200]
    return type(exc).__name__


def _write_json(path: str, payload: Any) -> None:
    """Write ``payload`` beside ``path``, flush it to the disk and only then put it in place, so a write
    that fails halfway leaves the old file as it was (the way ``app._save_submissions`` does it)."""
    tmp = path + ".tmp"
    try:
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(1, _REPLACE_ATTEMPTS + 1):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == _REPLACE_ATTEMPTS:
                    raise
                time.sleep(_REPLACE_PAUSE)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


# ---- URLs ------------------------------------------------------------------------------------


def _clean_urls(text: str) -> Iterable[str]:
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING)
        if len(url) <= MAX_URL_LEN and url.partition("://")[2]:
            yield url


def urls_in(text: str) -> List[str]:
    """The http(s) URLs in ``text``, in order and without repeats: at most ``MAX_URLS``, none longer than
    ``MAX_URL_LEN`` (such a one is dropped, not cut). Trailing punctuation is not part of a URL."""
    if not isinstance(text, str) or not text:
        return []
    found: List[str] = []
    for url in _clean_urls(text):
        if url not in found:
            found.append(url)
            if len(found) >= MAX_URLS:
                break
    return found


def executable_urls_in(text: str) -> List[str]:
    """The URLs of ``text`` that name an executable file (``EXECUTABLE_SUFFIXES``), at most ``MAX_URLS``.

    The whole text is scanned and the limit counts executable URLs only, so neither padding nor a crowd of
    harmless URLs in front of a payload URL hides it.
    """
    if not isinstance(text, str) or not text:
        return []
    found: List[str] = []
    for url in _clean_urls(text):
        parts = _url_parts(url)
        if parts is not None and _is_executable_name(parts[2]) and url not in found:
            found.append(url)
            if len(found) >= MAX_URLS:
                break
    return found


def _url_parts(url: str) -> Optional[Tuple[str, int, str]]:
    """``(host, port, file name)`` of a URL, or None when it cannot be taken apart."""
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host:
        return None
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80
    name = unquote(parts.path).rsplit("/", 1)[-1].split(";", 1)[0]
    return host.lower(), port, name


def _is_executable_name(name: str) -> bool:
    dot = name.rfind(".")
    return dot >= 0 and name[dot:].lower() in EXECUTABLE_SUFFIXES


# ---- store -----------------------------------------------------------------------------------


def _window(ring: Iterable[Tuple[float, Any]], since: Optional[float], until: Optional[float]) -> List[Any]:
    return [item for epoch, item in ring
            if (since is None or epoch >= since) and (until is None or epoch <= until)]


class FirewallStore:
    """Thread-safe rings of what the collector read; see the module docstring."""

    def __init__(self, max_connections: int = MAX_CONNECTIONS, retain_s: float = RETAIN_S,
                 now: Callable[[], float] = time.time):
        self.retain_s = retain_s
        self._now = now
        self._lock = threading.Lock()
        self._connections: Deque[Tuple[float, Tuple, Dict[str, Any]]] = deque(maxlen=max(1, int(max_connections)))
        self._firewall: Deque[Tuple[float, Dict[str, Any]]] = deque(maxlen=MAX_FIREWALL_EVENTS)
        self._process_events: Deque[Tuple[float, Dict[str, Any]]] = deque(maxlen=MAX_PROCESS_EVENTS)
        self._powershell: Deque[Tuple[float, Dict[str, Any]]] = deque(maxlen=MAX_URL_EVENTS)
        self._bits: Deque[Tuple[float, Dict[str, Any]]] = deque(maxlen=MAX_URL_EVENTS)
        self._dns: Dict[str, str] = {}
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._status: Dict[str, Tuple[str, str]] = {}
        self._seen: Dict[str, Dict[Tuple[str, ...], None]] = {kind: {} for kind in _DEDUP_FIELDS}

    # -- writing --

    def _placed(self, ev: Dict[str, Any]) -> Optional[float]:
        """The time an event is kept under: its own, but no more than ``MAX_FUTURE_S`` ahead of the clock.

        Setting the clock forward is a sandbox-evasion trick; an entry dated months ahead would otherwise
        make ``_forget_old`` drop the whole ring. Such an entry is kept at "now" (the event keeps its own text).
        """
        epoch = _event_epoch(ev)
        if epoch is not None:
            now = self._now()
            if epoch > now + MAX_FUTURE_S:
                epoch = now
        return epoch

    def _is_new(self, kind: str, ev: Dict[str, Any]) -> bool:
        """Whether this Sysmon event was not added before (and remember it); the caller holds the lock."""
        seen = self._seen[kind]
        key = tuple(str(ev.get(field)) for field in _DEDUP_FIELDS[kind])
        if key in seen:
            return False
        seen[key] = None
        if len(seen) > MAX_DEDUP_KEYS:
            del seen[next(iter(seen))]
        return True

    def _forget_old(self, ring: Deque) -> None:
        """Drop what lies more than ``retain_s`` before the newest entry; the caller holds the lock."""
        if ring:
            newest = ring[-1][0]
            while ring[0][0] < newest - self.retain_s:
                ring.popleft()

    def add_connections(self, events: Iterable[Dict[str, Any]]) -> int:
        """Keep the Sysmon EID 3 events among ``events`` that are new; returns how many."""
        added = 0
        with self._lock:
            for ev in events:
                epoch = self._placed(ev) if _event_id(ev) == 3 and not ev.get("error") else None
                if epoch is not None and self._is_new("connections", ev):
                    self._connections.append((epoch, firewall.flow_key(ev), ev))
                    added += 1
            self._forget_old(self._connections)
        return added

    def add_dns(self, events: Iterable[Dict[str, Any]]) -> int:
        """Fold the new Sysmon EID 22 answers in the IP -> name map (the newest wins); returns how many addresses."""
        with self._lock:
            fresh = [ev for ev in events if _event_id(ev) == 22 and self._is_new("dns", ev)]
            answers = firewall.dns_map(fresh)
            for ip, name in answers.items():
                self._dns.pop(ip, None)
                self._dns[ip] = name
            while len(self._dns) > firewall.DNS_MAX_ENTRIES:
                del self._dns[next(iter(self._dns))]
        return len(answers)

    def add_processes(self, events: Iterable[Dict[str, Any]]) -> int:
        """Keep the new Sysmon EID 1 events among ``events`` and know the process of each; returns how many."""
        added = 0
        with self._lock:
            for ev in events:
                epoch = self._placed(ev) if _event_id(ev) == 1 and not ev.get("error") else None
                pid = _to_int(ev.get("pid")) if epoch is not None else None
                if pid is None or not self._is_new("processes", ev):
                    continue
                commandline = ev.get("commandline")
                if isinstance(commandline, str):
                    # the URLs are taken from the whole text: the part that is cut away may be where the URL is
                    ev = dict(ev, urls=executable_urls_in(commandline), commandline=commandline[:MAX_COMMANDLINE_CHARS])
                self._process_events.append((epoch, ev))
                self._processes.pop(pid, None)       # a reused PID is the newest process
                self._processes[pid] = {
                    "start": _event_epoch(ev) or epoch, "image": str(ev.get("image") or "").strip(),
                    "parent_pid": _to_int(ev.get("parent_pid")),
                    "parent_image": str(ev.get("parent_image") or "").strip(),
                    "commandline": ev.get("commandline") or ""}
                if len(self._processes) > MAX_PROCESSES:
                    del self._processes[next(iter(self._processes))]
                added += 1
            self._forget_old(self._process_events)
        return added

    def add_firewall(self, events: Iterable[Dict[str, Any]]) -> int:
        """Keep Windows firewall log events (``log_store.parse_firewall_log``); returns how many."""
        added = 0
        with self._lock:
            for ev in events:
                epoch = self._placed(ev) if isinstance(ev, dict) else None
                if epoch is not None:
                    self._firewall.append((epoch, ev))
                    added += 1
            self._forget_old(self._firewall)
        return added

    def add_powershell(self, events: Iterable[Dict[str, Any]]) -> int:
        """Keep the PowerShell events whose text names an executable by URL; returns how many.

        The event is kept with ``urls`` (taken from the whole text) and a text cut to ``MAX_SCRIPT_CHARS``.
        """
        added = 0
        with self._lock:
            for ev in events:
                text = ev.get("message") if isinstance(ev, dict) else None
                urls = executable_urls_in(text)
                epoch = self._placed(ev) if urls else None
                if epoch is None:
                    continue
                self._powershell.append((epoch, dict(ev, urls=urls, message=text[:MAX_SCRIPT_CHARS])))
                added += 1
            self._forget_old(self._powershell)
        return added

    def add_bits(self, events: Iterable[Dict[str, Any]]) -> int:
        """Keep the BITS events that name an executable by URL; returns how many."""
        added = 0
        with self._lock:
            for ev in events:
                data = ev.get("data") if isinstance(ev, dict) else None
                urls = executable_urls_in(data.get("url")) if isinstance(data, dict) else []
                epoch = self._placed(ev) if urls else None
                if epoch is not None:
                    self._bits.append((epoch, dict(ev, urls=urls)))
                    added += 1
            self._forget_old(self._bits)
        return added

    def set_status(self, source: str, status: str, hint: str = "") -> None:
        with self._lock:
            self._status[source] = (status, hint)

    # -- reading --

    def events(self, since: Any = None, until: Any = None) -> List[Dict[str, Any]]:
        """The Sysmon EID 3 events of a window (inclusive), oldest read first: the input of ``firewall.classify``."""
        lo, hi = _bound(since), _bound(until)
        with self._lock:
            return _window(((epoch, ev) for epoch, _, ev in self._connections), lo, hi)

    def connections(self, since: Any = None, until: Any = None) -> List[Dict[str, Any]]:
        """The connections of a window bundled to flows (``firewall.bundle``)."""
        return firewall.bundle(self.events(since, until))

    def raw_for(self, image: str, dst_ip: str, dst_port: Optional[int]) -> List[Tuple[float, str, Optional[int]]]:
        """``(epoch, dst_ip, dst_port)`` of every single connection of ``image`` to this endpoint, oldest first.

        The beaconing detector works on these, not on a bundled flow.

        This scans the whole ring: it is for the detail view of **one** flow and must never be called in a loop
        over all flows. A caller that wants every flow gives ``events()`` to ``firewall.classify``, which bundles
        and tags in one pass and needs no scan per flow.
        """
        want = firewall.flow_key({"image": image, "dst_ip": dst_ip, "dst_port": dst_port})
        with self._lock:
            hits = [(epoch, key[4], key[5]) for epoch, key, _ in self._connections
                    if key[0].lower() == want[0].lower() and key[4] == want[4] and key[5] == want[5]]
        return sorted(hits, key=lambda hit: hit[0])

    def dns(self) -> Dict[str, str]:
        """IP -> the name that last resolved to it."""
        with self._lock:
            return dict(self._dns)

    def processes(self) -> Dict[int, Dict[str, Any]]:
        """PID -> ``{"start": epoch, "image", "parent_pid", "parent_image", "commandline"}``, newest process of a PID."""
        with self._lock:
            return {pid: dict(info) for pid, info in self._processes.items()}

    def process_events(self, since: Any = None, until: Any = None) -> List[Dict[str, Any]]:
        lo, hi = _bound(since), _bound(until)
        with self._lock:
            return _window(self._process_events, lo, hi)

    def firewall_events(self, since: Any = None, until: Any = None) -> List[Dict[str, Any]]:
        lo, hi = _bound(since), _bound(until)
        with self._lock:
            return _window(self._firewall, lo, hi)

    def powershell(self, since: Any = None, until: Any = None) -> List[Dict[str, Any]]:
        lo, hi = _bound(since), _bound(until)
        with self._lock:
            return _window(self._powershell, lo, hi)

    def bits(self, since: Any = None, until: Any = None) -> List[Dict[str, Any]]:
        lo, hi = _bound(since), _bound(until)
        with self._lock:
            return _window(self._bits, lo, hi)

    def stats(self) -> Dict[str, Any]:
        """Entry counts, the span of the connection ring (ISO) and the status and hint of every source."""
        with self._lock:
            counts = {"connections": len(self._connections), "dns": len(self._dns),
                      "processes": len(self._processes), "powershell": len(self._powershell),
                      "firewall": len(self._firewall), "bits": len(self._bits)}
            oldest = self._connections[0][0] if self._connections else None
            newest = self._connections[-1][0] if self._connections else None
            status = {s: self._status.get(s, ("idle", ""))[0] for s in SOURCES}
            hints = {s: self._status.get(s, ("idle", ""))[1] for s in SOURCES}
        return {"counts": counts, "oldest": _iso(oldest) if oldest is not None else None,
                "newest": _iso(newest) if newest is not None else None, "status": status, "hints": hints}


# ---- the download case -----------------------------------------------------------------------


def _event_pid(ev: Dict[str, Any]) -> Optional[int]:
    for holder in (ev, ev.get("fields"), ev.get("data")):
        if isinstance(holder, dict):
            for key in ("pid", "processId", "ProcessId"):
                pid = _to_int(holder.get(key))
                if pid is not None:
                    return pid
    return None


def _flow_for(flows: Iterable[Dict[str, Any]], host: str, port: int, pid: Optional[int]) -> Optional[Dict[str, Any]]:
    """The flow that reached ``host`` (a name or an address), of process ``pid`` if given; prefers ``port``, then the newest."""
    address = firewall.flow_key({"dst_ip": host})[4]
    best: Optional[Tuple[Tuple, Dict[str, Any]]] = None
    for flow in flows:
        if pid is not None and flow.get("pid") != pid:
            continue
        name = str(flow.get("dst_hostname") or "").lower().rstrip(".")
        if flow.get("dst_ip") != address and name != host:
            continue
        rank = (flow.get("dst_port") == port, flow.get("last_seen") or 0)
        if best is None or rank > best[0]:
            best = (rank, flow)
    return best[1] if best else None


def _candidates(ps_events, proc_events, bits_events) -> List[Tuple[str, Dict[str, Any], List[str], bool]]:
    """``(source, event, urls, via_bits)`` of every event that names an executable by URL; a BITS job is
    fetched by the BITS service, so its requester is not the process that connects.

    The URLs are those the store took from the whole text before it cut it (``urls``); an event that did not
    pass the store (a caller's own list) is scanned here.
    """
    def urls_of(ev: Dict[str, Any], text: Any) -> List[str]:
        return ev["urls"] if isinstance(ev.get("urls"), list) else executable_urls_in(text)

    out = []
    for ev in ps_events or ():
        if isinstance(ev, dict):
            out.append(("powershell", ev, urls_of(ev, ev.get("message")), False))
    for ev in proc_events or ():
        if isinstance(ev, dict) and _event_id(ev) == 1:
            out.append(("sysmon", ev, urls_of(ev, ev.get("commandline")), False))
    for ev in bits_events or ():
        data = ev.get("data") if isinstance(ev, dict) else None
        if isinstance(data, dict):
            out.append(("bits", ev, urls_of(ev, data.get("url")), True))
    return out


def _bits_job_in_detonation(job: Optional[float], submission_pids: Set[int], starts: Dict[int, List[float]],
                            now: float) -> bool:
    """Whether a submission process was running at the time of the BITS job.

    ``submission_pids`` are the processes of detonation windows that are open now, so the newest process with
    such a PID is the submission (an older one that had the PID before does not count), and it had started by
    the job when its newest start is not after it. A submission whose start is not known (EID 1 left the
    ring) counts only for a job of the last ``BITS_LOOKBACK_S``, not for one from days ago.
    """
    if job is None:
        return False
    for pid in submission_pids:
        if starts.get(pid):
            if max(starts[pid]) <= job:
                return True
        elif now - BITS_LOOKBACK_S <= job:
            return True
    return False


def download_findings(ps_events: List[Dict[str, Any]], proc_events: List[Dict[str, Any]],
                      bits_events: List[Dict[str, Any]], flows: List[Dict[str, Any]],
                      submission_pids: Iterable[int], now: Optional[float] = None) -> List[Dict[str, Any]]:
    """URLs to executable files that were fetched, with the connection that fetched them.

    A URL counts when its file name ends in ``EXECUTABLE_SUFFIXES`` (the path only, not the query) and
    a flow of ``flows`` (``firewall.classify``: it needs ``dst_hostname``) went to its host. That flow
    gives ``pid``, ``image``, ``dst_ip`` and ``dst_port``, the keys of ``Context.downloads`` and of
    ``firewall.rule_key``; a URL whose connection was not seen yet gives nothing, the next call may. A
    PowerShell or Sysmon event without a PID gives nothing.

    Every finding that can be seen is returned; what to do with it is the caller's policy. It says what the
    policy needs: ``in_detonation`` (the process that asked, or an ancestor from ``proc_events``, is in
    ``submission_pids``) and ``self`` (the connecting process is one of TDC's own, ``firewall.is_tdc_image``).

    ``now`` (default: the clock) bounds the BITS test below.

    A BITS job is the exception to the PID test. BITS EID 59/60 do not name the requester and the connection
    is made by the BITS service (``svchost.exe``, so ``image`` says that and ``requested_by`` is ``"bits"``,
    to tell a reader why the name looks innocent). A PID test could never be true for a channel that is a
    stealthy download path (T1197); so a BITS job is ``in_detonation`` when a submission process had started
    by its time, which is deliberately wider than the PID test, and the BITS host is matched in any process.
    The alternative is not to see BITS downloads at all. The window still bounds it (``_bits_job_in_detonation``).

    A finding is ``{id, pid, image, url, dst_ip, dst_port, source, observed_at, origin_pid, requested_by,
    in_detonation, self}``; ``source`` is ``powershell``, ``sysmon`` or ``bits``, ``origin_pid`` the PID of the
    event (None for BITS unless the reader knew it), ``observed_at`` ISO-8601 (UTC). ``id`` is the same for the
    same process and URL, so a call at every tick finds a finding again.
    """
    submissions = {int(p) for p in submission_pids}
    now = time.time() if now is None else now
    parents: Dict[int, Dict[str, Any]] = {}
    starts: Dict[int, List[float]] = {}
    for ev in proc_events or ():
        pid = _to_int(ev.get("pid")) if isinstance(ev, dict) and _event_id(ev) == 1 else None
        if pid is not None:
            parents[pid] = {"parent_pid": _to_int(ev.get("parent_pid"))}
            began = _event_epoch(ev)
            if began is not None:
                starts.setdefault(pid, []).append(began)
    ancestry = firewall.Context(submission_pids=submissions, processes=parents)
    found: Dict[str, Tuple[float, Dict[str, Any]]] = {}
    for source, ev, urls, via_bits in _candidates(ps_events, proc_events, bits_events):
        origin = _event_pid(ev)
        epoch = _event_epoch(ev)
        if origin is None and not via_bits:
            continue
        in_detonation = origin is not None and firewall.is_detonated(origin, ancestry)
        if via_bits and not in_detonation:
            in_detonation = _bits_job_in_detonation(epoch, submissions, starts, now)
        for url in urls:
            parts = _url_parts(url)
            if parts is None or not _is_executable_name(parts[2]):
                continue
            flow = _flow_for(flows or (), parts[0], parts[1], None if via_bits else origin)
            if flow is None or not flow.get("image"):
                continue
            finding_id = "dl-" + hashlib.sha1(
                f"{source}|{origin}|{url}".encode("utf-8", "replace")).hexdigest()[:12]
            if finding_id not in found:
                found[finding_id] = (epoch if epoch is not None else math.inf, {
                    "id": finding_id, "pid": flow["pid"], "image": flow["image"], "url": url,
                    "dst_ip": flow["dst_ip"], "dst_port": flow["dst_port"], "source": source,
                    "observed_at": _iso(epoch) if epoch is not None else None, "origin_pid": origin,
                    "requested_by": "bits" if via_bits else None, "in_detonation": in_detonation,
                    "self": firewall.is_tdc_image(flow["image"])})
    return [finding for _, finding in sorted(found.values(), key=lambda pair: pair[0])]


# ---- pending decisions -----------------------------------------------------------------------


class PendingStore:
    """The decisions that wait for the analyst, and the 24 h of history of those that were taken.

    An item is ``{id, finding, deadline, created_at, action, result, resolved_at}``, times in epoch
    seconds. ``deadline`` is absolute and the server's: ``expired(now)`` lists what ran out, and the
    caller applies the default action to it. ``id`` is the finding's id, so ``add`` of a finding
    that is already there (open or decided) returns that item and changes nothing. At most ``MAX_OPEN``
    items are open: when one more comes, the oldest open item goes to the history as ``dropped``.
    The file ``path`` is written atomically at every change and read back at start; a file that cannot
    be read is moved aside (``.corrupt``) and the store starts empty. A write that fails is logged,
    not raised: the decision still stands in memory.
    """

    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._items: Dict[str, Dict[str, Any]] = {}
        self._load()

    # -- the file --

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            logger.warning("pending decisions unreadable (%s: %s); starting empty", type(e).__name__, e)
            try:
                os.replace(self.path, self.path + ".corrupt")
            except OSError:
                pass
            return
        items = data.get("items") if isinstance(data, dict) else data
        for raw in items if isinstance(items, list) else ():
            item = self._valid(raw)
            if item is not None:
                self._items[item["id"]] = item
        with self._lock:
            self._prune()

    @staticmethod
    def _valid(raw: Any) -> Optional[Dict[str, Any]]:
        if not (isinstance(raw, dict) and isinstance(raw.get("id"), str) and raw["id"]
                and isinstance(raw.get("finding"), dict)):
            return None
        numbers = []
        for key in ("deadline", "created_at"):
            value = raw.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                return None
            numbers.append(float(value))
        action, resolved_at = raw.get("action"), raw.get("resolved_at")
        if action is not None and not isinstance(action, str):
            return None
        if isinstance(resolved_at, bool) or not (resolved_at is None or isinstance(resolved_at, (int, float))):
            return None
        return {"id": raw["id"], "finding": raw["finding"], "deadline": numbers[0], "created_at": numbers[1],
                "action": action, "result": raw.get("result") if isinstance(raw.get("result"), dict) else None,
                "resolved_at": resolved_at if action is not None else None}

    def _save(self) -> None:
        try:
            _write_json(self.path, {"version": 1, "items": list(self._items.values())})
        except Exception as e:
            logger.warning("pending decisions not saved (%s: %s)", type(e).__name__, e)

    def _prune(self) -> None:
        """Forget old history, and the open items beyond ``MAX_OPEN``; the caller holds the lock."""
        now = self._clock()
        decided = sorted((i for i in self._items.values() if i["action"] is not None),
                         key=lambda i: i["resolved_at"] or 0, reverse=True)
        for rank, item in enumerate(decided):       # newest first
            if rank >= MAX_HISTORY or (item["resolved_at"] or 0) < now - HISTORY_S:
                del self._items[item["id"]]
        open_items = [i for i in self._items.values() if i["action"] is None]
        for item in open_items[:max(0, len(open_items) - MAX_OPEN)]:
            item.update(action="dropped", resolved_at=now,
                        result={"reason": f"more than {MAX_OPEN} open decisions"})

    # -- writing --

    def add(self, finding: Dict[str, Any], deadline: float) -> Dict[str, Any]:
        """A new open decision for ``finding``, due at the epoch ``deadline`` (a past one is due at once)."""
        if not isinstance(finding, dict):
            raise TypeError("a finding is a dict")
        due = float(deadline)
        if not math.isfinite(due):
            raise ValueError("deadline must be a finite time")
        with self._lock:
            fid = finding.get("id")
            item_id = fid if isinstance(fid, str) and fid else uuid.uuid4().hex[:12]
            if item_id not in self._items:
                self._items[item_id] = {"id": item_id, "finding": copy.deepcopy(finding), "deadline": due,
                                        "created_at": self._clock(), "action": None, "result": None,
                                        "resolved_at": None}
                self._prune()
                self._save()
            return copy.deepcopy(self._items[item_id])

    def settle(self, pending_id: str, action: str,
               result: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], bool]:
        """``(item, won)``: ``won`` is True for the call that took the decision and False for every later one.

        The caller that wins carries the action out; the others get the decision that was taken. Raises
        ``KeyError`` for an id that is not known and ``ValueError`` for an action outside ``DECISIONS``.
        """
        if action not in DECISIONS:
            raise ValueError(f"action must be one of {DECISIONS}, not {action!r}")
        with self._lock:
            item = self._items.get(pending_id)
            if item is None:
                raise KeyError(pending_id)
            if item["action"] is not None:
                return copy.deepcopy(item), False
            item.update(action=action, result=copy.deepcopy(result), resolved_at=self._clock())
            self._save()
            return copy.deepcopy(item), True

    def resolve(self, pending_id: str, action: str, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Take the decision and return the item. A second answer is no error and changes nothing: it gets the first item."""
        return self.settle(pending_id, action, result)[0]

    def set_result(self, pending_id: str, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Add to the ``result`` of a decided item what became known later (the fetch that followed it).

        Returns the item, or None when it is gone: a fetch can outlive the 24 h of history, and that is no error.
        """
        with self._lock:
            item = self._items.get(pending_id)
            if item is None:
                return None
            item["result"] = dict(item["result"] or {}, **copy.deepcopy(result))
            self._save()
            return copy.deepcopy(item)

    # -- reading --

    def get(self, pending_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._items.get(pending_id)
            return copy.deepcopy(item) if item else None

    def open(self) -> List[Dict[str, Any]]:
        """The decisions still open, oldest first."""
        with self._lock:
            return [copy.deepcopy(i) for i in self._items.values() if i["action"] is None]

    def history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """The decisions taken in the last 24 h, newest first."""
        with self._lock:
            self._prune()
            decided = sorted((i for i in self._items.values() if i["action"] is not None),
                             key=lambda i: i["resolved_at"] or 0, reverse=True)
            return [copy.deepcopy(i) for i in decided[:max(0, int(limit))]]

    def expired(self, now: float) -> List[Dict[str, Any]]:
        """The open decisions whose deadline is ``now`` or earlier, the earliest first."""
        with self._lock:
            due = [i for i in self._items.values() if i["action"] is None and i["deadline"] <= now]
            return [copy.deepcopy(i) for i in sorted(due, key=lambda i: i["deadline"])]


# ---- settings --------------------------------------------------------------------------------


def _check_setting(name: str, value: Any) -> Any:
    if name == "ask_mode":
        if value not in ASK_MODES:
            raise ValueError(f"ask_mode must be one of {ASK_MODES}, not {value!r}")
    elif name == "isolated":
        if not isinstance(value, bool):
            raise ValueError("isolated must be true or false")
    elif name == "outbound_before":
        if value is not None and not isinstance(value, str):
            raise ValueError("outbound_before must be text or null")
    elif name == "isolated_since":
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                  or not math.isfinite(value)):
            raise ValueError("isolated_since must be an epoch time or null")
    else:
        raise ValueError(f"unknown setting: {name!r}")
    return value


class Settings:
    """The server-side state of the tab, kept in ``webui/firewall_state.json``.

    ``ask_mode``         ``detonation`` | ``all`` | ``off`` (``ASK_MODES``)
    ``isolated``         whether ISOLATED is on
    ``outbound_before``  the ``DefaultOutboundAction`` before ISOLATED, to put it back
    ``isolated_since``   epoch seconds ISOLATED went on, or None

    The attributes can be read freely. ``set`` checks, stores and writes the file, and raises (leaving
    everything as it was) when it cannot: whoever isolates the VM must know that the way back was not
    remembered. A file that is missing or cannot be read gives the defaults; ``load_error`` then says why.
    """

    DEFAULTS = {"ask_mode": "detonation", "isolated": False, "outbound_before": None, "isolated_since": None}

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.load_error: Optional[str] = None
        self.ask_mode: str = self.DEFAULTS["ask_mode"]
        self.isolated: bool = self.DEFAULTS["isolated"]
        self.outbound_before: Optional[str] = self.DEFAULTS["outbound_before"]
        self.isolated_since: Optional[float] = self.DEFAULTS["isolated_since"]
        self.load()

    def load(self) -> None:
        """Read the file again; what it does not hold, or holds in a wrong shape, is the default."""
        with self._lock:
            self.load_error = None
            data: Dict[str, Any] = {}
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("not a JSON object")
            except FileNotFoundError:
                data = {}
            except (OSError, ValueError) as e:
                data = {}
                self.load_error = f"{type(e).__name__}: {_first_line(e)}"
                logger.warning("firewall settings unreadable (%s); using the defaults", self.load_error)
            for name, default in self.DEFAULTS.items():
                try:
                    value = _check_setting(name, data[name]) if name in data else default
                except ValueError as e:
                    value = default
                    self.load_error = self.load_error or str(e)
                setattr(self, name, value)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {name: getattr(self, name) for name in self.DEFAULTS}

    def save(self) -> None:
        with self._lock:
            _write_json(self.path, {name: getattr(self, name) for name in self.DEFAULTS})

    def set(self, **changes: Any) -> Dict[str, Any]:
        """Change settings by name and write the file; returns the settings.

        The file is written first and the attributes are changed after, so a reader that does not take the lock
        never sees a value that the file then refuses (it raises and changes nothing).
        """
        checked = {name: _check_setting(name, value) for name, value in changes.items()}
        with self._lock:
            merged = {name: getattr(self, name) for name in self.DEFAULTS}
            merged.update(checked)
            _write_json(self.path, merged)
            for name, value in checked.items():
                setattr(self, name, value)
            return merged


# ---- collector -------------------------------------------------------------------------------


class FirewallCollector:
    """Reads the sources into a ``FirewallStore`` at every ``tick``; see the module docstring for the readers.

    ``fast_window`` says whether a detonation window is open (a submission with a running PID, and
    a minute after it): then ``interval`` is ``FAST_INTERVAL`` and the BITS channel is read as well.
    ``settings`` is the tab's ``Settings`` (the caller's loop reads ``ask_mode`` from it); ``now`` is the clock.

    In the window the tick is lean on purpose: Sysmon EID 1, 3, 22 and BITS every second, PowerShell and the
    firewall log only every ``SLOW_INTERVAL``. The script-block log is not small, and a cradle is a poor reason to
    read it ten times as often. The price is a known latency: a finding needs both the URL (PowerShell) and the
    connection (Sysmon), so a PowerShell cradle's finding can form up to 10 s after its connection. That is
    acceptable in Part A, which blocks after the fact anyway; Part B's proxy has no such latency.
    """

    def __init__(self, store: FirewallStore, settings: Settings, readers: Dict[str, Callable[..., Any]],
                 fast_window: Callable[[], bool], now: Callable[[], float] = time.time):
        self.store = store
        self.settings = settings
        self._readers = readers
        self._fast_window = fast_window
        self._now = now
        self._cursors: Dict[str, Optional[int]] = {}      # powershell, bits, firewall: record id or offset
        self._since: Dict[str, float] = {}                # connections, dns, processes: epoch of the next read
        self._last_read: Dict[str, float] = {}
        self._adders = {"connections": store.add_connections, "dns": store.add_dns,
                        "processes": store.add_processes, "powershell": store.add_powershell,
                        "firewall": store.add_firewall, "bits": store.add_bits}

    def _in_window(self) -> bool:
        try:
            return bool(self._fast_window())
        except Exception:
            return False

    def interval(self) -> float:
        """Seconds to sleep before the next tick."""
        return FAST_INTERVAL if self._in_window() else SLOW_INTERVAL

    def tick(self) -> Dict[str, int]:
        """One incremental read of every source that is due; returns the number of new entries per source read."""
        window = self._in_window()
        now = self._now()
        added: Dict[str, int] = {}
        for name in SOURCES:
            if name == "bits" and not window:
                self.store.set_status(name, "idle", "read only in a detonation window")
                continue
            elapsed = now - self._last_read.get(name, -math.inf)
            due = elapsed >= SLOW_INTERVAL - SLOW_SLACK_S or elapsed < 0      # a clock set back is due, not stalled
            if window and name in SLOW_SOURCES and not due:
                continue
            self._last_read[name] = now
            try:
                added[name] = self._read_sysmon(name, now) if name in SYSMON_EVENT_IDS else self._read(name)
            except Exception as e:  # a failing reader must not stop the others
                self.store.set_status(name, "unavailable", _first_line(e))
        return added

    def _reader(self, name: str) -> Callable[..., Any]:
        reader = self._readers.get(name)
        if reader is None:
            raise RuntimeError(f"no reader for {name}")
        return reader

    @staticmethod
    def _refuse_errors(events: List[Any]) -> None:
        for ev in events:
            if isinstance(ev, dict) and ev.get("error") and not ev.get("event_id"):
                raise RuntimeError(str(ev["error"]))

    def _read_sysmon(self, name: str, now: float) -> int:
        """The Sysmon way of ``log_store.Collector``: by time, from a little before the newest event seen."""
        reader = self._reader(name)
        cutoff = now - START_WINDOW_S
        previous = self._since.get(name)
        if previous is not None:
            previous = self._since[name] = min(previous, now)       # a clock set back must not leave it in the future
        events = list(reader(event_ids=list(SYSMON_EVENT_IDS[name]),
                             since_iso=_iso(previous if previous is not None else cutoff)) or ())
        self._refuse_errors(events)
        count = self._adders[name](events)
        newest = None
        for ev in events:
            epoch = _event_epoch(ev) if isinstance(ev, dict) else None
            if epoch is not None and epoch >= cutoff:
                epoch = min(epoch, now)      # a time in the future (clock skew) must not take the position beyond now
                newest = epoch if newest is None else max(newest, epoch)
        if newest is not None:
            candidate = newest - SYSMON_OVERLAP_S
            if previous is not None and candidate <= previous and len(events) >= SYSMON_PAGE:
                candidate = newest           # a full page inside the overlap would be returned again for ever
            if previous is None or candidate > previous:
                self._since[name] = candidate
        self.store.set_status(name, "ok", "")
        return count

    def _read(self, name: str) -> int:
        """An event log by ``EventRecordID`` (PowerShell, BITS) or a log file by offset (the firewall).

        A reader answers ``(events, position)``. For an event log the position is the newest record id of the
        *log*, also when no event came back: one below the one the collector holds means the log was cleared
        (T1070.001) and its ids start again, so the collector reads it again from the start (``since=0``).
        For the firewall it is the new offset and is taken as it is (the reader handles a rotation itself).
        A reader that answers a plain list gets its position from the events' ``record_id``, and never backwards.
        """
        reader = self._reader(name)
        previous = self._cursors.get(name)
        hint = ""
        for _ in range(2):
            result = reader(since=previous)
            explicit = isinstance(result, tuple) and len(result) == 2
            events, reported = (result[0], result[1]) if explicit else (result, None)
            events = list(events or ())
            self._refuse_errors(events)
            if name in RECORD_SOURCES and explicit and previous and _to_int(reported) is not None \
                    and _to_int(reported) < previous:
                logger.warning("the %s log restarted its record ids (%s < %s); reading it from the start",
                               name, reported, previous)
                previous, hint = 0, "the event log was cleared; read again from its start"
                continue
            break
        if explicit:
            cursor = reported
        else:
            cursor = self._newest_record(events)
            if events and cursor is None:
                raise RuntimeError("the reader returned events without a record_id")
            if cursor is not None and previous is not None:
                cursor = max(cursor, previous)
        count = self._adders[name](events)
        if cursor is not None:
            self._cursors[name] = cursor
        elif previous == 0:
            self._cursors[name] = 0
        self.store.set_status(name, "ok", hint)
        return count

    @staticmethod
    def _newest_record(events: List[Dict[str, Any]]) -> Optional[int]:
        ids = []
        for ev in events:
            if isinstance(ev, dict):
                fields = ev.get("fields")
                record = _to_int(ev.get("record_id"))
                if record is None and isinstance(fields, dict):
                    record = _to_int(fields.get("record_id"))
                if record is not None:
                    ids.append(record)
        return max(ids) if ids else None
