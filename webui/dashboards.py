"""Own dashboards of the LOGS tab: the store behind ``webui/dashboards.json``.

A dashboard is a name and an ordered list of tiles ("panels"); a tile is a saved
log search together with the form it is drawn in and its time range. Nothing is
computed here, and nothing is computed on the server at all: the browser asks
``/api/logs/search`` for the numbers of every tile.

The file holds everything the browser needs to do that::

    {"dashboards": [
      {"id": "d-<12 hex>", "name": "Beacon hunt", "created": "<ISO-8601 Z>",
       "panels": [
         {"id": "p-<12 hex>", "name": "Dropped ports",
          "query": "source=firewall action=DROP | top dst_port", "form": "pie",
          "earliest": "-24h", "latest": "", "created": "<ISO-8601 Z>"}]}]}

Every call reads the file, changes the list and writes it again, all under one
lock, after the pattern of ``submissions.json`` in ``app.py``: the new content is
written beside the file, flushed to the disk and only then put in its place, with
ten attempts against the ``PermissionError`` another program holding the file for
a moment (a virus scanner, an indexer) raises on Windows. A write that fails
leaves the old file as it was and raises what failed; the routes log it and
answer 500. Nothing is cached, so a second web UI process would not overwrite
this one's list with a stale one.

Reading is defensive, because this file is small enough to be edited by hand and
a damaged one must never take the Dashboard tab down: a file that cannot be read
at all - no JSON, no JSON object, no list of dashboards, nested so deeply that the
decoder gives up - reads as no dashboards, and a single record or tile that does
not pass the same checks as a new one falls away instead of breaking the page. A
tile id that repeats anywhere in the file is kept once, on the first dashboard
that carries it, because the UI builds element ids from it. The caps are applied
on reading too, so what ``all()`` hands out always keeps the documented limits.
"""

import datetime
import json
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

# The limits of the data (see the spec, "Eigene Dashboards"): the page stays
# readable, and a sample's output can never grow the file without bounds.
MAX_DASHBOARDS = 10
MAX_PANELS = 12
MAX_NAME = 60
MAX_QUERY = 4000
MAX_TIME = 40
# The forms a tile can be drawn in; checked here, not only in the browser.
FORMS = ("table", "pie", "bars", "line", "sankey")

# Like the write of submissions.json: tried this often, this many seconds apart.
_REPLACE_ATTEMPTS = 10
_REPLACE_PAUSE = 0.05

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DASHBOARD_ID = re.compile(r"^d-[0-9a-f]{12}$")
_PANEL_ID = re.compile(r"^p-[0-9a-f]{12}$")


class NotFound(Exception):
    """A dashboard or tile that is not there (another browser tab deleted it)."""


class Invalid(Exception):
    """A value the store refuses; the text is the reason, shown to the analyst."""


class LimitReached(Invalid):
    """A cap of the data was reached (a limit is a refused value, hence 400)."""


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _name(value: Any) -> str:
    """A dashboard or tile name: 1 to 60 characters, no control characters.

    Surrounding white space is cut (a name pasted from the query), the rest is
    kept as it is; the browser escapes it when it draws it."""
    if not isinstance(value, str):
        raise Invalid("name must be a string")
    if _CONTROL.search(value):
        raise Invalid("name must not contain control characters")
    name = value.strip()
    if not name or len(name) > MAX_NAME:
        raise Invalid("name must be 1 to %d characters" % MAX_NAME)
    return name


def _query(value: Any) -> str:
    """The saved search: not empty, at most as long as the search itself takes."""
    if not isinstance(value, str):
        raise Invalid("query must be a string")
    query = value.strip()
    if not query:
        raise Invalid("query must not be empty")
    if len(query) > MAX_QUERY:
        raise Invalid("query must be at most %d characters" % MAX_QUERY)
    return query


def _form(value: Any) -> str:
    if value not in FORMS:
        raise Invalid("form must be one of %s" % ", ".join(FORMS))
    return value


def _time(value: Any, field: str) -> str:
    """``earliest``/``latest`` as the LOGS tab writes them (``-24h``, ``now``, an
    ISO timestamp, or empty for "no bound"); only their length is checked here,
    the search reads them and says what it cannot read."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise Invalid("%s must be a string" % field)
    if _CONTROL.search(value):
        raise Invalid("%s must not contain control characters" % field)
    text = value.strip()
    if len(text) > MAX_TIME:
        raise Invalid("%s must be at most %d characters" % (field, MAX_TIME))
    return text


def _new_id(prefix: str, taken) -> str:
    while True:
        candidate = prefix + uuid.uuid4().hex[:12]
        if candidate not in taken:
            return candidate


def _stamp(value: Any) -> str:
    """A ``created`` stamp from the file; anything unreadable becomes empty."""
    if isinstance(value, str) and len(value) <= MAX_TIME and not _CONTROL.search(value):
        return value
    return ""


def _panel_from_file(raw: Any, taken) -> Optional[Dict[str, Any]]:
    """One tile of the file, or ``None`` when it cannot be read."""
    if not isinstance(raw, dict):
        return None
    pid = raw.get("id")
    if not isinstance(pid, str) or not _PANEL_ID.match(pid) or pid in taken:
        return None
    try:
        panel = {"id": pid, "name": _name(raw.get("name")), "query": _query(raw.get("query")),
                 "form": _form(raw.get("form")),
                 "earliest": _time(raw.get("earliest"), "earliest"),
                 "latest": _time(raw.get("latest"), "latest"),
                 "created": _stamp(raw.get("created"))}
    except Invalid:
        return None
    return panel


def _dashboard_from_file(raw: Any, taken, panel_ids=()) -> Optional[Dict[str, Any]]:
    """One dashboard of the file, or ``None`` when it cannot be read. A tile list
    that is not a list reads as no tiles: the dashboard itself is still good.
    ``panel_ids`` are the tile ids of the dashboards read before this one, so a
    tile id repeated anywhere in the file falls away (the UI builds element ids
    from them)."""
    if not isinstance(raw, dict):
        return None
    did = raw.get("id")
    if not isinstance(did, str) or not _DASHBOARD_ID.match(did) or did in taken:
        return None
    try:
        name = _name(raw.get("name"))
    except Invalid:
        return None
    panels: List[Dict[str, Any]] = []
    pids = set(panel_ids)
    raw_panels = raw.get("panels")
    for item in raw_panels if isinstance(raw_panels, list) else []:
        panel = _panel_from_file(item, pids)
        if panel is not None:
            panels.append(panel)
            pids.add(panel["id"])
        if len(panels) >= MAX_PANELS:
            break
    return {"id": did, "name": name, "created": _stamp(raw.get("created")), "panels": panels}


class DashboardStore:
    """The own dashboards of the Dashboard tab, kept in one JSON file.

    Every method reads the file and writes it again under one lock, so two
    requests never interleave; the dicts handed out are fresh copies, changing
    them changes nothing."""

    def __init__(self, path: str):
        self.path = path
        # Held over reading the file, changing the list and putting the new file
        # in its place; not re-entrant.
        self._lock = threading.Lock()

    # -- the file ----------------------------------------------------------

    def _read(self) -> List[Dict[str, Any]]:
        # Every failure of reading this file reads as no dashboards: not only the
        # OSError of a file that is gone or locked and the ValueError of text that
        # is no JSON, but anything else the decoder may raise on a hand-written
        # file too - a deeply nested one raises RecursionError, which is no
        # ValueError and would otherwise leave the Dashboard tab with an HTML 500.
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            return []
        if not isinstance(data, dict) or not isinstance(data.get("dashboards"), list):
            return []
        records: List[Dict[str, Any]] = []
        taken = set()
        pids = set()                    # tile ids are unique across the whole file
        for raw in data["dashboards"]:
            record = _dashboard_from_file(raw, taken, pids)
            if record is not None:
                records.append(record)
                taken.add(record["id"])
                pids.update(p["id"] for p in record["panels"])
            if len(records) >= MAX_DASHBOARDS:
                break
        return records

    def _write(self, records: List[Dict[str, Any]]) -> None:
        """Write the list beside the file, flush it to the disk and only then put
        it in its place, so a write that fails halfway (a full disk, a crash)
        leaves the dashboards as they were. What failed is raised: the callers
        log it and answer 500."""
        tmp = self.path + ".tmp"
        try:
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump({"dashboards": records}, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(1, _REPLACE_ATTEMPTS + 1):
                try:
                    os.replace(tmp, self.path)
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

    @staticmethod
    def _find(records: List[Dict[str, Any]], did: Any) -> Dict[str, Any]:
        for record in records:
            if record["id"] == did:
                return record
        raise NotFound("Dashboard not found.")

    @staticmethod
    def _find_panel(record: Dict[str, Any], pid: Any) -> Dict[str, Any]:
        for panel in record["panels"]:
            if panel["id"] == pid:
                return panel
        raise NotFound("Panel not found.")

    # -- dashboards --------------------------------------------------------

    def all(self) -> List[Dict[str, Any]]:
        """Every dashboard with its tiles, in the order they were saved in."""
        with self._lock:
            return self._read()

    def add(self, name: Any) -> Dict[str, Any]:
        """A new, empty dashboard at the end of the list."""
        name = _name(name)
        with self._lock:
            records = self._read()
            if len(records) >= MAX_DASHBOARDS:
                raise LimitReached("at most %d dashboards" % MAX_DASHBOARDS)
            record = {"id": _new_id("d-", {r["id"] for r in records}), "name": name,
                      "created": _now(), "panels": []}
            records.append(record)
            self._write(records)
            return record

    def rename(self, did: Any, name: Any) -> Dict[str, Any]:
        """Give the dashboard another name; names may repeat, the id is the key."""
        name = _name(name)
        with self._lock:
            records = self._read()
            record = self._find(records, did)
            record["name"] = name
            self._write(records)
            return record

    def remove(self, did: Any) -> None:
        """Drop the dashboard and every tile on it."""
        with self._lock:
            records = self._read()
            records.remove(self._find(records, did))
            self._write(records)

    # -- tiles -------------------------------------------------------------

    def add_panel(self, did: Any, name: Any, query: Any, form: Any,
                  earliest: Any = "", latest: Any = "") -> Dict[str, Any]:
        """A new tile at the end of the dashboard: a saved search and its form."""
        name, query, form = _name(name), _query(query), _form(form)
        earliest, latest = _time(earliest, "earliest"), _time(latest, "latest")
        with self._lock:
            records = self._read()
            record = self._find(records, did)
            if len(record["panels"]) >= MAX_PANELS:
                raise LimitReached("at most %d tiles per dashboard" % MAX_PANELS)
            taken = {p["id"] for r in records for p in r["panels"]}
            panel = {"id": _new_id("p-", taken), "name": name, "query": query, "form": form,
                     "earliest": earliest, "latest": latest, "created": _now()}
            record["panels"].append(panel)
            self._write(records)
            return panel

    def update_panel(self, did: Any, pid: Any, name: Any = None, form: Any = None,
                     move: Any = None) -> Dict[str, Any]:
        """Rename a tile, change its form, or move it one place up or down.

        The query and the time range of a tile do not change: that is a new tile
        saved from the LOGS tab. ``move`` at the end of the list does nothing."""
        if name is None and form is None and move is None:
            raise Invalid("name, form or move required")
        if name is not None:
            name = _name(name)
        if form is not None:
            form = _form(form)
        if move is not None and move not in ("up", "down"):
            raise Invalid("move must be 'up' or 'down'")
        with self._lock:
            records = self._read()
            record = self._find(records, did)
            panel = self._find_panel(record, pid)
            if name is not None:
                panel["name"] = name
            if form is not None:
                panel["form"] = form
            if move is not None:
                panels = record["panels"]
                here = panels.index(panel)
                there = max(0, here - 1) if move == "up" else min(len(panels) - 1, here + 1)
                panels.insert(there, panels.pop(here))
            self._write(records)
            return panel

    def remove_panel(self, did: Any, pid: Any) -> None:
        """Drop one tile of the dashboard."""
        with self._lock:
            records = self._read()
            record = self._find(records, did)
            record["panels"].remove(self._find_panel(record, pid))
            self._write(records)
