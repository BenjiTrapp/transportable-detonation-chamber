"""Event store and source parsers for the LOGS tab.

The store is a thread-safe set of ring buffers of event dicts, one per source::

    {"id": "<source>-<n>", "time": "<ISO-8601 UTC, Z>", "source": ..., "message": ..., "fields": {...}}

Every source has its own cap on events (``SOURCE_CAPS``) and its share of the
character budget (``MAX_CHARS`` split in proportion to the caps). When a source
is full, its own oldest event is dropped: a burst in one source (the UI's own
polling, a busy firewall) never pushes the evidence of another one out.
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
    read_sysmon(event_ids, since_iso) -> [event dict as _read_sysmon_events], oldest first
                                         (a read that hits its cap leaves the newer events for the next tick)
    read_firewall(offset)            -> (text, new_offset, status_hint)

``read_firewall``: ``offset`` is a byte offset into the log file and ``new_offset`` is
the byte offset right after the returned ``text`` (decoded as UTF-8 or ASCII). The
text may end in the middle of a line (the firewall is still writing it); the
collector only consumes whole lines and moves ``new_offset`` back by the bytes of
the unfinished last line, so the next read starts at its beginning. A last line
longer than 64 KB without a newline is consumed as it is.
``read_powershell``: the position moves to ``max_record_id`` even when some of the
returned events cannot be parsed (they are skipped and counted in the source hint).
A 4104 script block is stored once, as ``message``; there is no ``script`` field.
The store holds at most 55 000 events (see ``SOURCE_CAPS``) and 50 million characters of text.

A reader that raises, or a Sysmon reader that returns ``{"error": ...}``, marks
its sources ``unavailable`` with the first line of the message; the other sources
carry on.
"""

from __future__ import annotations

import heapq
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

SOURCE_CAPS = {"powershell": 15000, "firewall": 10000, "dns": 10000, "access": 10000,
               "netflow": 5000, "mcp": 5000}
MAX_CHARS = 50_000_000
ROTATE_BYTES = 10 * 1024 * 1024
START_WINDOW_S = 24 * 3600
START_LIMIT = 5000
SYSMON_CACHE_LIMIT = 20000
DNS_SEEN_LIMIT = 20000
MAX_PENDING_LINE = 65536
SYSMON_OVERLAP_S = 5
SYSMON_PAGE = 5000        # most events one Sysmon read returns

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


# ---- time ------------------------------------------------------------------------------------


def _iso(epoch: float, millis: bool = False) -> str:
    dt = _EPOCH + timedelta(seconds=epoch)
    if millis:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


_FRACTION = re.compile(r"\.(\d+)")


def _sysmon_epoch(value: Any) -> Optional[float]:
    """Epoch seconds of a Sysmon event timestamp (ISO with offset, or ``Z``); naive means local time."""
    if not isinstance(value, str) or not value:
        return None
    # Python 3.9 reads only 3 or 6 fractional digits
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], value.strip().replace("Z", "+00:00"), count=1)
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return (dt - _EPOCH).total_seconds()
    except (ValueError, OverflowError, OSError):
        return None


def _sort_key(t: str) -> str:
    """Orders ISO times with or without a fraction: fixed-width date, time and microseconds."""
    base, _, frac = t.rstrip("Z").partition(".")
    return base + "." + (frac + "000000")[:6]


def _cost(event: Dict[str, Any]) -> int:
    """Characters an event holds (message and string field values); the unit of the store's budget."""
    total = len(event["message"]) if isinstance(event["message"], str) else 0
    for v in event["fields"].values():
        if isinstance(v, str):
            total += len(v)
        elif isinstance(v, (list, tuple)):
            total += sum(len(x) for x in v if isinstance(x, str))
    return total


_FLOW_KEY_FIELDS = ("image", "pid", "protocol", "src_ip", "dst_ip", "dst_port")


def _flow_key(fields: Optional[Dict[str, Any]]) -> Tuple:
    f = fields or {}
    return tuple(f.get(k) for k in _FLOW_KEY_FIELDS)


# ---- store -----------------------------------------------------------------------------------


class LogStore:
    """Per-source ring buffers; ``max_events`` (when given) is the cap of every source, ``caps`` overrides single ones."""

    def __init__(self, max_events: Optional[int] = None, persist_dir: Optional[str] = None,
                 max_chars: int = MAX_CHARS, caps: Optional[Dict[str, int]] = None):
        merged = dict(SOURCE_CAPS)
        if max_events is not None:
            merged = {s: int(max_events) for s in SOURCES}
        merged.update(caps or {})
        self.caps = {s: max(1, int(merged[s])) for s in SOURCES}
        self.max_chars = max(1, int(max_chars))
        total = sum(self.caps.values())
        self.budgets = {s: max(1, self.max_chars * self.caps[s] // total) for s in SOURCES}
        self.persist_dir = persist_dir
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        # per source: (event, characters, insertion number), oldest first
        self._rings: Dict[str, Deque[Tuple[Dict[str, Any], int, int]]] = {s: deque() for s in SOURCES}
        self._chars: Dict[str, int] = {s: 0 for s in SOURCES}
        self._order = 0
        self._flow_ids: Dict[Tuple, str] = {}
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
        """Replace every ``netflow`` event by ``flows`` (the re-bundled window) in one step.

        A flow with the same key (image, pid, protocol, addresses, port) as one
        that is being replaced keeps its id, so the UI can follow it across polls.
        """
        with self._lock:
            self._rings["netflow"].clear()
            self._chars["netflow"] = 0
            self._last.pop("netflow", None)
            ids: Dict[Tuple, str] = {}
            out = []
            for f in sorted(flows, key=lambda f: _sort_key(f["time"])):
                key = _flow_key(f.get("fields"))
                event = self._insert("netflow", f["time"], f.get("message", ""), f.get("fields"),
                                     event_id=None if key in ids else self._flow_ids.get(key))
                ids[key] = event["id"]
                out.append(event)
            self._flow_ids = ids
            return out

    def _insert(self, source: str, time: str, message: str, fields: Optional[Dict[str, Any]],
                event_id: Optional[str] = None) -> Dict[str, Any]:
        """Add one event and evict; the caller holds ``self._lock``.

        Eviction drops the source's own event that was added first, whole, while
        the source has too many events or too many characters (its newest event
        always stays).
        """
        if source not in SOURCES:
            raise ValueError(f"unknown log source: {source!r}")
        if event_id is None:
            self._seq += 1
            event_id = f"{source}-{self._seq}"
        event = {"id": event_id, "time": time, "source": source,
                 "message": message, "fields": dict(fields or {})}
        cost = _cost(event)
        ring = self._rings[source]
        self._order += 1
        ring.append((event, cost, self._order))
        self._chars[source] += cost
        if source not in self._last or _sort_key(time) > _sort_key(self._last[source]):
            self._last[source] = time
        while len(ring) > self.caps[source] or (self._chars[source] > self.budgets[source] and len(ring) > 1):
            _, old_cost, _ = ring.popleft()
            self._chars[source] -= old_cost
        if not ring:
            self._last.pop(source, None)
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
        """Every event, in the order in which they were added (the rings merged)."""
        with self._lock:
            rings = [r for r in self._rings.values() if r]
            return [e for e, _, _ in heapq.merge(*rings, key=lambda item: item[2])]

    def get(self, event_id: str) -> Optional[Dict[str, Any]]:
        """The event with this id, or ``None`` when it is gone (or never was)."""
        source = str(event_id).rpartition("-")[0]
        with self._lock:
            ring = self._rings.get(source)
            if ring is None:
                return None
            for event, _, _ in reversed(ring):
                if event["id"] == event_id:
                    return event
        return None

    def counts(self) -> Dict[str, int]:
        with self._lock:
            return {s: len(self._rings[s]) for s in SOURCES}

    def last_time(self, source: str) -> Optional[str]:
        with self._lock:
            return self._last.get(source)

    def set_status(self, source: str, status: str, hint: str = "") -> None:
        with self._lock:
            self._status[source] = (status, hint)

    def sources(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{"source": s, "count": len(self._rings[s]), "last_time": self._last.get(s),
                     "status": self._status.get(s, ("ok", ""))[0], "hint": self._status.get(s, ("ok", ""))[1]}
                    for s in SOURCES]

    # -- persistence --

    def _path(self, source: str) -> str:
        return os.path.join(self.persist_dir or "", source + ".jsonl")

    def _persist(self, event: Dict[str, Any]) -> None:
        try:
            self._write(event)
        except Exception as e:  # never let a log file problem reach the request that logged
            if not self._persist_failed:
                self._persist_failed = True
                logger.warning("log persistence failed: %s: %s", type(e).__name__, e)

    def _write(self, event: Dict[str, Any]) -> None:
        source = event["source"]
        # ASCII-only JSON: a lone surrogate (cannot be encoded as UTF-8) stays a \udXXX escape
        line = json.dumps({k: event[k] for k in ("time", "source", "message", "fields")},
                          default=str) + "\n"
        data = line.encode("ascii")
        path = self._path(source)
        with self._io_lock:
            os.makedirs(self.persist_dir, exist_ok=True)
            if source not in self._sizes:
                self._sizes[source] = os.path.getsize(path) if os.path.exists(path) else 0
            if self._sizes[source] > 0 and self._sizes[source] + len(data) > ROTATE_BYTES:
                os.replace(path, path + ".1")
                self._sizes[source] = 0
            with open(path, "ab") as f:
                f.write(data)
            self._sizes[source] += len(data)

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


def _event_chunks(text: str) -> Iterable[str]:
    """The ``<Event>...</Event>`` pieces of ``text``, one at a time (no copy of the whole text)."""
    pos = 0
    while True:
        begin = text.find("<Event", pos)
        if begin < 0:
            return
        end = text.find("</Event>", begin)
        if end < 0:
            yield text[begin:]
            return
        pos = end + len("</Event>")
        yield text[begin:pos]


def parse_powershell_events(xml_text: str, stats: Optional[Dict[str, int]] = None) -> List[Dict[str, Any]]:
    """Events of ``wevtutil qe Microsoft-Windows-PowerShell/Operational /f:xml`` (no root element).

    Script blocks split over several 4104 events are joined by ``ScriptBlockId``;
    a block with missing parts is marked ``partial``. Returns events without ``id``,
    oldest first. Script text stays raw (escaping is the UI's job). An event that
    cannot be parsed, for whatever reason, is skipped; ``stats["skipped"]`` gets the count.
    """
    skipped = 0
    singles: List[Tuple[float, Dict[str, Any]]] = []
    blocks: Dict[str, List[Dict[str, Any]]] = {}
    for chunk in _event_chunks(xml_text or ""):
        try:
            ev = _xml_event(chunk)
            if ev is None:
                skipped += 1
                continue
            data = ev["data"]
            if ev["event_id"] == 4104 and data.get("ScriptBlockId"):
                blocks.setdefault(data["ScriptBlockId"], []).append(ev)
            else:
                singles.append((ev["epoch"], _powershell_event(ev)))
        except Exception:
            skipped += 1

    for block_id, parts in blocks.items():
        try:
            singles.append(_script_block_event(block_id, parts))
        except Exception:
            skipped += len(parts)
    if stats is not None:
        stats["skipped"] = skipped
    singles.sort(key=lambda t: t[0])
    return [e for _, e in singles]


def _script_block_event(block_id: str, parts: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    by_number: Dict[int, Dict[str, Any]] = {}
    for p in parts:
        by_number[_to_int(p["data"].get("MessageNumber")) or 1] = p
    numbers = sorted(by_number)
    first = by_number[numbers[0]]
    total = max([_to_int(p["data"].get("MessageTotal")) or 1 for p in parts] + [len(numbers)])
    script = "".join(by_number[n]["data"].get("ScriptBlockText", "") for n in numbers)
    fields = _common_fields(first)
    fields.update({"script_block_id": block_id, "message_number": numbers[0], "message_total": total,
                   "path": first["data"].get("Path", "")})
    if numbers != list(range(1, total + 1)):
        fields["partial"] = True
    return first["epoch"], {"time": _iso(first["epoch"], True), "source": "powershell",
                            "message": script, "fields": fields}


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
                       "path": data.get("Path", "")})
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
        try:
            when = _iso(epoch)
        except (ValueError, OverflowError, OSError):
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
        events.append({"time": when, "source": "firewall", "message": message, "fields": ev_fields})
    return events


def _fw_epoch(date: str, clock: str, utc_offset_s: Optional[int]) -> Optional[float]:
    try:
        naive = datetime.strptime(f"{date} {clock}", "%Y-%m-%d %H:%M:%S")
        if utc_offset_s is None:
            return (naive.astimezone(timezone.utc) - _EPOCH).total_seconds()
        return (naive.replace(tzinfo=timezone.utc) - _EPOCH).total_seconds() - utc_offset_s
    except (ValueError, OverflowError, OSError):
        return None


# ---- Sysmon ----------------------------------------------------------------------------------


def _is_event(ev: Any, eid: int) -> bool:
    return isinstance(ev, dict) and ev.get("event_id") == eid and not ev.get("error")


def _sysmon_str(value: Any) -> str:
    """A Sysmon string value; Sysmon's "-" placeholder and blanks mean unknown (empty string)."""
    text = "" if value is None else str(value).strip()
    return "" if text == "-" else text


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
        key = (_sysmon_str(ev.get("image")), str(ev.get("pid") or ""), ev.get("protocol", ""),
               _sysmon_str(ev.get("src_ip")), _sysmon_str(ev.get("dst_ip")), str(ev.get("dst_port", "")))
        flow = flows.get(key)
        if flow is None:
            flows[key] = {"key": key, "count": 1, "first": epoch, "last": epoch,
                          "dst_hostname": _sysmon_str(ev.get("dst_hostname"))}
            continue
        flow["count"] += 1
        flow["first"] = min(flow["first"], epoch)
        flow["last"] = max(flow["last"], epoch)
        if not flow["dst_hostname"]:
            flow["dst_hostname"] = _sysmon_str(ev.get("dst_hostname"))
    out: List[Dict[str, Any]] = []
    for flow in sorted(flows.values(), key=lambda f: f["last"]):
        image, pid, protocol, src_ip, dst_ip, dst_port = flow["key"]
        port = _to_int(dst_port)
        fields = {"image": image, "pid": _to_int(pid), "protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip,
                  "dst_port": port if port is not None else dst_port, "dst_hostname": flow["dst_hostname"] or None,
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
        query, result = _sysmon_str(ev.get("query")), _sysmon_str(ev.get("result"))
        fields = {"query": query, "result": result, "image": _sysmon_str(ev.get("image")),
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
        # move on first: whatever the parser makes of this text, it is not read again
        if max_record is not None:
            self._ps_record = max(self._ps_record or 0, int(max_record))
        elif first:
            self._ps_record = 0
        stats: Dict[str, int] = {}
        events = parse_powershell_events(xml_text, stats)
        if first:
            events = self._trim_start(events)
        self.store.extend(events)
        skipped = stats.get("skipped", 0)
        self.store.set_status("powershell", "ok",
                              f"{skipped} event{'s' if skipped != 1 else ''} could not be parsed" if skipped else "")
        return {"powershell": len(events)}

    def _tick_sysmon(self) -> Dict[str, int]:
        now = self._now().timestamp()
        since = self._sysmon_since if self._sysmon_since is not None else now - START_WINDOW_S
        raw = self._read_sysmon([3, 22], _iso(since))
        for item in raw:
            if isinstance(item, dict) and item.get("error") and not item.get("event_id"):
                raise RuntimeError(str(item["error"]))
        cutoff = now - START_WINDOW_S
        previous = self._sysmon_since
        newest_seen: Optional[float] = None
        first = previous is None
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
            elif ev.get("event_id") == 22:
                if key not in self._dns_seen:
                    self._dns_seen[key] = epoch
                    new_dns.append(ev)
            else:
                continue
            # a timestamp in the future (clock skew) must not move the position beyond now
            epoch = min(epoch, now)
            if newest_seen is None or epoch > newest_seen:
                newest_seen = epoch
        if newest_seen is not None:
            candidate = newest_seen - SYSMON_OVERLAP_S
            if previous is not None and candidate <= previous and len(raw) >= SYSMON_PAGE:
                # a full page that lies within the overlap: without this the next read returns it again
                candidate = newest_seen
            if previous is None or candidate > previous:
                self._sysmon_since = candidate
        self._conns = {k: v for k, v in self._conns.items() if v[0] >= cutoff}
        if len(self._conns) > SYSMON_CACHE_LIMIT:
            keep = sorted(self._conns.items(), key=lambda kv: kv[1][0])[-SYSMON_CACHE_LIMIT:]
            self._conns = dict(keep)
        self._dns_seen = {k: t for k, t in self._dns_seen.items() if t >= cutoff}
        if len(self._dns_seen) > DNS_SEEN_LIMIT:
            keep = sorted(self._dns_seen.items(), key=lambda kv: kv[1])[-DNS_SEEN_LIMIT:]
            self._dns_seen = dict(keep)

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
        read_text = text
        if text and not text.endswith("\n") and new_offset is not None:
            # an unfinished last line: leave it for the next read (bytes of complete lines only)
            cut = text.rfind("\n") + 1
            tail = text[cut:]
            if len(tail) <= MAX_PENDING_LINE:
                text = text[:cut]
                new_offset = max(0, new_offset - len(tail.encode("utf-8")))
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
        if hint and not read_text.strip():
            self.store.set_status("firewall", "unavailable", hint)
        else:
            self.store.set_status("firewall", "ok", hint or "")
        return {"firewall": len(events)}
