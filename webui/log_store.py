"""Event store and source parsers for the LOGS tab.

The store is a thread-safe ring buffer of event dicts shared by all sources::

    {"id": "<source>-<n>", "time": "<ISO-8601 UTC, Z>", "source": ..., "message": ..., "fields": {...}}

When it is full the event that was added first, whatever its source, is dropped.
``access`` and ``mcp`` events are also appended to ``<persist_dir>/<source>.jsonl``
(rotated to ``.jsonl.1`` at 10 MB, one old file is kept) and read back at start.
The Windows sources are re-read from the system on every start, so they are not
persisted.

The parsers (PowerShell event log XML, Windows Firewall log, Sysmon events) are
pure functions over text or dicts. ``Collector`` runs them incrementally against
readers that are injected, so everything here works without a VM; the real
readers (wevtutil, the firewall file) live in app.py.

Reader contract for ``Collector`` (``None`` as the position means first read: the
reader returns at most the last 24 h and 5000 entries; the collector trims too)::

    read_powershell(since_record_id) -> (xml_text, max_record_id)
    read_sysmon(event_ids, since_iso) -> [event dict as _read_sysmon_events]
    read_firewall(offset)            -> (text, new_offset, status_hint)

A reader that raises, or a Sysmon reader that returns ``{"error": ...}``, marks
its sources ``unavailable`` with the first line of the message; the other sources
carry on.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import xml.etree.ElementTree as ET
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

SOURCES = ("powershell", "access", "mcp", "netflow", "dns", "firewall")
PERSISTED_SOURCES = ("access", "mcp")

MAX_EVENTS = 50000
ROTATE_BYTES = 10 * 1024 * 1024
START_WINDOW_S = 24 * 3600
START_LIMIT = 5000
SYSMON_CACHE_LIMIT = 20000
SYSMON_OVERLAP_S = 5

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


# ---- time ------------------------------------------------------------------------------------


def _iso(epoch: float, millis: bool = False) -> str:
    dt = _EPOCH + timedelta(seconds=epoch)
    if millis:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def _sysmon_epoch(value: Any) -> Optional[float]:
    """Epoch seconds of a Sysmon event timestamp (ISO with offset, or ``Z``); naive means local time."""
    if not isinstance(value, str) or not value:
        return None
    text = _FRACTION.sub(r"\1", value.strip().replace("Z", "+00:00"), count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return (dt - _EPOCH).total_seconds()


def _sort_key(t: str) -> str:
    """Orders ISO times with or without a fraction: fixed-width date, time and microseconds."""
    base, _, frac = t.rstrip("Z").partition(".")
    return base + "." + (frac + "000000")[:6]


# ---- store -----------------------------------------------------------------------------------


class LogStore:
    def __init__(self, max_events: int = MAX_EVENTS, persist_dir: Optional[str] = None):
        self.max_events = max(1, int(max_events))
        self.persist_dir = persist_dir
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._events: Deque[Dict[str, Any]] = deque()
        self._counts: Counter = Counter()
        self._last: Dict[str, str] = {}
        self._status: Dict[str, Tuple[str, str]] = {}
        self._seq = 0
        self._sizes: Dict[str, int] = {}
        self._persist_failed = False

    # -- writing --

    def add(self, source: str, time: str, message: str, fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._append(source, time, message, fields, persist=True)

    def extend(self, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.add(e["source"], e["time"], e.get("message", ""), e.get("fields")) for e in events]

    def replace_netflows(self, flows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Replace every ``netflow`` event by ``flows`` (the re-bundled window) in one step."""
        with self._lock:
            self._events = deque(e for e in self._events if e["source"] != "netflow")
            self._counts["netflow"] = 0
            self._last.pop("netflow", None)
            return [self._insert("netflow", f["time"], f.get("message", ""), f.get("fields")) for f in flows]

    def _insert(self, source: str, time: str, message: str, fields: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Add one event; the caller holds ``self._lock``."""
        if source not in SOURCES:
            raise ValueError(f"unknown log source: {source!r}")
        self._seq += 1
        event = {"id": f"{source}-{self._seq}", "time": time, "source": source,
                 "message": message, "fields": dict(fields or {})}
        self._events.append(event)
        self._counts[source] += 1
        if source not in self._last or _sort_key(time) > _sort_key(self._last[source]):
            self._last[source] = time
        while len(self._events) > self.max_events:
            old = self._events.popleft()
            self._counts[old["source"]] -= 1
            if self._counts[old["source"]] <= 0:
                self._last.pop(old["source"], None)
        return event

    def _append(self, source: str, time: str, message: str, fields: Optional[Dict[str, Any]],
                persist: bool) -> Dict[str, Any]:
        with self._lock:
            event = self._insert(source, time, message, fields)
        if persist and self.persist_dir and source in PERSISTED_SOURCES:
            self._persist(event)
        return event

    # -- reading --

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def counts(self) -> Dict[str, int]:
        with self._lock:
            return {s: self._counts.get(s, 0) for s in SOURCES}

    def last_time(self, source: str) -> Optional[str]:
        with self._lock:
            return self._last.get(source)

    def set_status(self, source: str, status: str, hint: str = "") -> None:
        with self._lock:
            self._status[source] = (status, hint)

    def sources(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{"source": s, "count": self._counts.get(s, 0), "last_time": self._last.get(s),
                     "status": self._status.get(s, ("ok", ""))[0], "hint": self._status.get(s, ("ok", ""))[1]}
                    for s in SOURCES]

    # -- persistence --

    def _path(self, source: str) -> str:
        return os.path.join(self.persist_dir or "", source + ".jsonl")

    def _persist(self, event: Dict[str, Any]) -> None:
        source = event["source"]
        line = json.dumps({k: event[k] for k in ("time", "source", "message", "fields")},
                          ensure_ascii=False, default=str) + "\n"
        data = line.encode("utf-8")
        path = self._path(source)
        with self._io_lock:
            try:
                os.makedirs(self.persist_dir, exist_ok=True)
                if source not in self._sizes:
                    self._sizes[source] = os.path.getsize(path) if os.path.exists(path) else 0
                if self._sizes[source] > 0 and self._sizes[source] + len(data) > ROTATE_BYTES:
                    os.replace(path, path + ".1")
                    self._sizes[source] = 0
                with open(path, "ab") as f:
                    f.write(data)
                self._sizes[source] += len(data)
            except OSError as e:
                if not self._persist_failed:
                    self._persist_failed = True
                    logger.warning("log persistence failed: %s", e)

    def load_persisted(self) -> int:
        """Read the persisted files (old file first) back in time order; bad lines are ignored."""
        if not self.persist_dir:
            return 0
        loaded = 0
        for source in PERSISTED_SOURCES:
            events: List[Dict[str, Any]] = []
            for path in (self._path(source) + ".1", self._path(source)):
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                except OSError:
                    continue
                for line in lines:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if (isinstance(e, dict) and isinstance(e.get("time"), str)
                            and isinstance(e.get("message"), str)):
                        events.append(e)
            events.sort(key=lambda e: _sort_key(e["time"]))
            for e in events:
                fields = e.get("fields")
                self._append(source, e["time"], e["message"], fields if isinstance(fields, dict) else {},
                             persist=False)
                loaded += 1
        return loaded


# ---- PowerShell ------------------------------------------------------------------------------

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_XML_BAD_REF = re.compile(r"&#(?:[xX]([0-9a-fA-F]+)|([0-9]+));")
_PLACEHOLDER_BASE = 0xE000
_UNMASK = {_PLACEHOLDER_BASE + c: chr(c) for c in range(32) if c not in (9, 10, 13)}
_HOST_APP = re.compile(r"^[ \t]*Host Application[ \t]*=[ \t]*(.*?)[ \t]*$", re.M)
_COMMAND_NAME = re.compile(r"^[ \t]*Command Name[ \t]*=[ \t]*(.*?)[ \t]*$", re.M)
_COMMAND_INVOCATION = re.compile(r"CommandInvocation\(([^)]+)\)")


def _mask_control_chars(xml: str) -> str:
    """Control characters (ANSI ESC in script text) are illegal in XML 1.0: carry them as private-use characters."""
    def ref(m: "re.Match[str]") -> str:
        code = int(m.group(1), 16) if m.group(1) else int(m.group(2))
        if code < 32 and code not in (9, 10, 13):
            return chr(_PLACEHOLDER_BASE + code)
        return m.group(0)
    xml = _XML_BAD_REF.sub(ref, xml)
    return _XML_BAD.sub(lambda m: chr(_PLACEHOLDER_BASE + ord(m.group(0))), xml)


def _unmask(text: str) -> str:
    return text.translate(_UNMASK) if text else text


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _xml_event(chunk: str) -> Optional[Dict[str, Any]]:
    try:
        ev = ET.fromstring(_mask_control_chars(chunk))
    except ET.ParseError:
        return None
    eid = ev.find(f"{_NS}System/{_NS}EventID")
    tc = ev.find(f"{_NS}System/{_NS}TimeCreated")
    rec = ev.find(f"{_NS}System/{_NS}EventRecordID")
    ex = ev.find(f"{_NS}System/{_NS}Execution")
    sec = ev.find(f"{_NS}System/{_NS}Security")
    st = tc.get("SystemTime", "") if tc is not None else ""
    epoch = _sysmon_epoch(st if st.endswith("Z") else st + "Z")
    if eid is None or epoch is None:
        return None
    data = {d.get("Name"): _unmask(d.text or "") for d in ev.iter(f"{_NS}Data") if d.get("Name")}
    return {"event_id": _to_int(eid.text) or 0, "epoch": epoch, "record_id": _to_int(rec.text) if rec is not None else None,
            "pid": _to_int(ex.get("ProcessID")) if ex is not None else None,
            "user_sid": sec.get("UserID", "") if sec is not None else "", "data": data}


def parse_powershell_events(xml_text: str) -> List[Dict[str, Any]]:
    """Events of ``wevtutil qe Microsoft-Windows-PowerShell/Operational /f:xml`` (no root element).

    Script blocks split over several 4104 events are joined by ``ScriptBlockId``;
    a block with missing parts is marked ``partial``. Returns events without ``id``,
    oldest first. Script text stays raw (escaping is the UI's job).
    """
    singles: List[Tuple[float, Dict[str, Any]]] = []
    blocks: Dict[str, List[Dict[str, Any]]] = {}
    for chunk in (xml_text or "").split("</Event>"):
        begin = chunk.find("<Event")
        if begin < 0:
            continue
        ev = _xml_event(chunk[begin:] + "</Event>")
        if ev is None:
            continue
        data = ev["data"]
        if ev["event_id"] == 4104 and data.get("ScriptBlockId"):
            blocks.setdefault(data["ScriptBlockId"], []).append(ev)
            continue
        singles.append((ev["epoch"], _powershell_event(ev)))

    for block_id, parts in blocks.items():
        by_number: Dict[int, Dict[str, Any]] = {}
        for p in parts:
            by_number[_to_int(p["data"].get("MessageNumber")) or 1] = p
        numbers = sorted(by_number)
        first = by_number[numbers[0]]
        total = max([_to_int(p["data"].get("MessageTotal")) or 1 for p in parts] + [len(numbers)])
        script = "".join(by_number[n]["data"].get("ScriptBlockText", "") for n in numbers)
        fields = _common_fields(first)
        fields.update({"script_block_id": block_id, "message_number": numbers[0], "message_total": total,
                       "path": first["data"].get("Path", ""), "script": script})
        if numbers != list(range(1, total + 1)):
            fields["partial"] = True
        singles.append((first["epoch"], {"time": _iso(first["epoch"], True), "source": "powershell",
                                         "message": script, "fields": fields}))
    singles.sort(key=lambda t: t[0])
    return [e for _, e in singles]


def _common_fields(ev: Dict[str, Any]) -> Dict[str, Any]:
    return {"event_id": ev["event_id"], "record_id": ev["record_id"], "pid": ev["pid"], "user_sid": ev["user_sid"]}


def _powershell_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    data, eid = ev["data"], ev["event_id"]
    fields = _common_fields(ev)
    if eid == 4104:
        script = data.get("ScriptBlockText", "")
        fields.update({"script_block_id": data.get("ScriptBlockId", ""),
                       "message_number": _to_int(data.get("MessageNumber")),
                       "message_total": _to_int(data.get("MessageTotal")),
                       "path": data.get("Path", ""), "script": script})
        message = script
    elif eid == 4103:
        payload, context = data.get("Payload", ""), data.get("ContextInfo", "")
        fields.update({"payload": payload, "context": context})
        m = _HOST_APP.search(context)
        if m and m.group(1):
            fields["host_application"] = m.group(1)
        m = _COMMAND_NAME.search(context) or _COMMAND_INVOCATION.search(payload)
        if m and m.group(1).strip():
            fields["command"] = m.group(1).strip()
        message = payload.strip() or fields.get("command", "")
    elif eid == 4100:
        error = data.get("Payload", "")
        fields["error"] = error
        message = error.strip()
    else:
        message = next((v for v in data.values() if v and v.strip()), "")
    return {"time": _iso(ev["epoch"], True), "source": "powershell", "message": message, "fields": fields}


# ---- Windows Firewall ------------------------------------------------------------------------

_FW_DEFAULT_FIELDS = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size",
                      "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path", "pid"]


def firewall_fields(text: str) -> Optional[List[str]]:
    """The column names of the last ``#Fields:`` line in ``text``, if any."""
    found = None
    for line in (text or "").splitlines():
        if line.startswith("#Fields:"):
            found = line[len("#Fields:"):].split()
    return found or None


def parse_firewall_log(text: str, utc_offset_s: Optional[int] = None,
                       fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Windows Firewall log lines as events (``id`` is added by the store).

    Date and time in the log are local time; ``utc_offset_s`` is the local offset
    east of UTC in seconds (``None``: the system's own zone). ``fields`` are the
    columns to assume when ``text`` (an incremental read) has no ``#Fields:`` line.
    """
    columns = list(fields) if fields else list(_FW_DEFAULT_FIELDS)
    events: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#Fields:"):
                columns = line[len("#Fields:"):].split() or columns
            continue
        parts = line.split()
        if len(parts) < len(columns) - 1 or len(parts) > len(columns):
            continue
        row = dict(zip(columns, parts))
        epoch = _fw_epoch(row.get("date", ""), row.get("time", ""), utc_offset_s)
        if epoch is None:
            continue
        ev_fields: Dict[str, Any] = {}
        for src, dst in (("action", "action"), ("protocol", "protocol"), ("src-ip", "src_ip"),
                         ("dst-ip", "dst_ip"), ("path", "path")):
            if row.get(src, "-") != "-":
                ev_fields[dst] = row[src]
        for src, dst in (("src-port", "src_port"), ("dst-port", "dst_port"), ("size", "size"), ("pid", "pid")):
            n = _to_int(row.get(src)) if row.get(src, "-") != "-" else None
            if n is not None:
                ev_fields[dst] = n
        if "path" in ev_fields:
            ev_fields["direction"] = ev_fields["path"]
        src_ep = ev_fields.get("src_ip", "-") + (f":{ev_fields['src_port']}" if "src_port" in ev_fields else "")
        dst_ep = ev_fields.get("dst_ip", "-") + (f":{ev_fields['dst_port']}" if "dst_port" in ev_fields else "")
        message = f"{ev_fields.get('action', '-')} {ev_fields.get('protocol', '-')} {src_ep} -> {dst_ep}"
        events.append({"time": _iso(epoch), "source": "firewall", "message": message, "fields": ev_fields})
    return events


def _fw_epoch(date: str, clock: str, utc_offset_s: Optional[int]) -> Optional[float]:
    try:
        naive = datetime.strptime(f"{date} {clock}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if utc_offset_s is None:
        return (naive.astimezone(timezone.utc) - _EPOCH).total_seconds()
    return (naive.replace(tzinfo=timezone.utc) - _EPOCH).total_seconds() - utc_offset_s


# ---- Sysmon ----------------------------------------------------------------------------------


def _is_event(ev: Any, eid: int) -> bool:
    return isinstance(ev, dict) and ev.get("event_id") == eid and not ev.get("error")


def netflows_from_sysmon(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Bundle Sysmon EID 3 events into flows per (image, pid, protocol, src_ip, dst_ip, dst_port).

    The source port is not part of the key, so one process talking to one
    endpoint over many connections is one flow with a ``count``.
    """
    flows: Dict[Tuple, Dict[str, Any]] = {}
    for ev in events:
        if not _is_event(ev, 3):
            continue
        epoch = _sysmon_epoch(ev.get("timestamp"))
        if epoch is None:
            continue
        key = (ev.get("image", ""), str(ev.get("pid") or ""), ev.get("protocol", ""), ev.get("src_ip", ""),
               ev.get("dst_ip", ""), str(ev.get("dst_port", "")))
        flow = flows.get(key)
        if flow is None:
            flows[key] = {"key": key, "count": 1, "first": epoch, "last": epoch,
                          "dst_hostname": ev.get("dst_hostname", "") or ""}
            continue
        flow["count"] += 1
        flow["first"] = min(flow["first"], epoch)
        flow["last"] = max(flow["last"], epoch)
        if not flow["dst_hostname"]:
            flow["dst_hostname"] = ev.get("dst_hostname", "") or ""
    out: List[Dict[str, Any]] = []
    for flow in sorted(flows.values(), key=lambda f: f["last"]):
        image, pid, protocol, src_ip, dst_ip, dst_port = flow["key"]
        port = _to_int(dst_port)
        fields = {"image": image, "pid": _to_int(pid), "protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip,
                  "dst_port": port if port is not None else dst_port, "dst_hostname": flow["dst_hostname"],
                  "count": flow["count"], "first_seen": _iso(flow["first"]), "last_seen": _iso(flow["last"])}
        target = f"{flow['dst_hostname'] or dst_ip}:{dst_port}"
        out.append({"time": fields["last_seen"], "source": "netflow",
                    "message": f"{image} \u2192 {target} ({flow['count']}\u00d7)", "fields": fields})
    return out


def dns_from_sysmon(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sysmon EID 22 (DNSQuery) events as ``dns`` events, oldest first."""
    out: List[Tuple[float, Dict[str, Any]]] = []
    for ev in events:
        if not _is_event(ev, 22):
            continue
        epoch = _sysmon_epoch(ev.get("timestamp"))
        if epoch is None:
            continue
        query, result = ev.get("query", "") or "", ev.get("result", "") or ""
        fields = {"query": query, "result": result, "image": ev.get("image", ""),
                  "pid": _to_int(ev.get("pid")), "status": ev.get("status")}
        message = f"{query} -> {result}" if result else query
        out.append((epoch, {"time": _iso(epoch), "source": "dns", "message": message, "fields": fields}))
    out.sort(key=lambda t: t[0])
    return [e for _, e in out]


# ---- collector -------------------------------------------------------------------------------


def _first_line(exc: BaseException) -> str:
    for line in str(exc).splitlines():
        if line.strip():
            return line.strip()[:200]
    return type(exc).__name__


class Collector:
    """Reads the Windows sources incrementally into a ``LogStore``; call ``tick`` every poll.

    ``now`` is a function returning the current time as an aware datetime.
    ``utc_offset_s`` is the local offset used for the firewall log (``None``: system zone).
    """

    def __init__(self, store: LogStore, read_powershell: Callable[[Optional[int]], Tuple[str, Optional[int]]],
                 read_sysmon: Callable[[List[int], str], List[Dict[str, Any]]],
                 read_firewall: Callable[[Optional[int]], Tuple[str, Optional[int], str]],
                 now: Callable[[], datetime], utc_offset_s: Optional[int] = None):
        self.store = store
        self._read_powershell = read_powershell
        self._read_sysmon = read_sysmon
        self._read_firewall = read_firewall
        self._now = now
        self._utc_offset_s = utc_offset_s
        self._ps_record: Optional[int] = None
        self._fw_offset: Optional[int] = None
        self._fw_fields: Optional[List[str]] = None
        self._sysmon_since: Optional[float] = None
        self._conns: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._dns_seen: Dict[str, float] = {}

    def tick(self) -> Dict[str, int]:
        """One incremental read of every source; returns the number of new events per source."""
        added: Dict[str, int] = {}
        for name, step in (("powershell", self._tick_powershell), ("sysmon", self._tick_sysmon),
                           ("firewall", self._tick_firewall)):
            try:
                added.update(step())
            except Exception as e:  # a failing reader must not stop the others
                hint = _first_line(e)
                targets = ("netflow", "dns") if name == "sysmon" else (name,)
                for s in targets:
                    self.store.set_status(s, "unavailable", hint)
        return added

    def _start_cutoff(self) -> float:
        return self._now().timestamp() - START_WINDOW_S

    def _trim_start(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cutoff = _iso(self._start_cutoff())
        recent = [e for e in events if _sort_key(e["time"]) >= _sort_key(cutoff)]
        return recent[-START_LIMIT:]

    def _tick_powershell(self) -> Dict[str, int]:
        first = self._ps_record is None
        xml_text, max_record = self._read_powershell(self._ps_record)
        events = parse_powershell_events(xml_text)
        if first:
            events = self._trim_start(events)
        if max_record is not None:
            self._ps_record = max(self._ps_record or 0, int(max_record))
        elif first:
            self._ps_record = 0
        self.store.extend(events)
        self.store.set_status("powershell", "ok", "")
        return {"powershell": len(events)}

    def _tick_sysmon(self) -> Dict[str, int]:
        now = self._now().timestamp()
        since = self._sysmon_since if self._sysmon_since is not None else now - START_WINDOW_S
        raw = self._read_sysmon([3, 22], _iso(since))
        for item in raw:
            if isinstance(item, dict) and item.get("error") and not item.get("event_id"):
                raise RuntimeError(str(item["error"]))
        cutoff = now - START_WINDOW_S
        newest = self._sysmon_since
        first = self._sysmon_since is None
        new_dns: List[Dict[str, Any]] = []
        for ev in raw:
            if not isinstance(ev, dict):
                continue
            epoch = _sysmon_epoch(ev.get("timestamp"))
            if epoch is None or epoch < cutoff:
                continue
            key = json.dumps(ev, sort_keys=True, default=str)
            if ev.get("event_id") == 3:
                self._conns.setdefault(key, (epoch, ev))
            elif ev.get("event_id") == 22 and key not in self._dns_seen:
                self._dns_seen[key] = epoch
                new_dns.append(ev)
            else:
                continue
            if newest is None or epoch - SYSMON_OVERLAP_S > newest:
                newest = epoch - SYSMON_OVERLAP_S
        self._sysmon_since = newest
        self._conns = {k: v for k, v in self._conns.items() if v[0] >= cutoff}
        if len(self._conns) > SYSMON_CACHE_LIMIT:
            keep = sorted(self._conns.items(), key=lambda kv: kv[1][0])[-SYSMON_CACHE_LIMIT:]
            self._conns = dict(keep)
        self._dns_seen = {k: t for k, t in self._dns_seen.items() if t >= cutoff}

        dns = dns_from_sysmon(new_dns)
        if first:
            dns = dns[-START_LIMIT:]
        self.store.extend(dns)
        flows = netflows_from_sysmon([ev for _, ev in self._conns.values()])
        self.store.replace_netflows(flows)
        self.store.set_status("netflow", "ok", "")
        self.store.set_status("dns", "ok", "")
        return {"netflow": len(flows), "dns": len(dns)}

    def _tick_firewall(self) -> Dict[str, int]:
        first = self._fw_offset is None
        text, new_offset, hint = self._read_firewall(self._fw_offset)
        found = firewall_fields(text)
        if found:
            self._fw_fields = found
        events = parse_firewall_log(text, self._utc_offset_s, self._fw_fields)
        if first:
            events = self._trim_start(events)
        if new_offset is not None:
            self._fw_offset = new_offset
        elif first:
            self._fw_offset = 0
        self.store.extend(events)
        if hint and not text.strip():
            self.store.set_status("firewall", "unavailable", hint)
        else:
            self.store.set_status("firewall", "ok", hint or "")
        return {"firewall": len(events)}
