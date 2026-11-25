"""What a clean machine does on the network, kept so that it stops being evidence.

Every lever of the fake internet acts on the whole machine, so a capture holds
Windows Update, Defender, connectivity checks and the pollers of whatever
software the VM carries, next to the sample. ``known_good`` hides a short list
of names that occur on every Windows machine; everything else that this VM
does on its own is recorded here, from a capture of the clean VM, and a later
analysis suppresses (and counts) the events it recognises. This is the
network-side equivalent of ``memory_evidence.MemoryBaseline`` and is used the
same way (``knows``, ``add``, ``count``, ``stats``, ``clear``; a JSON file
written atomically, with a ``KEY_VERSION``).

The assumption this module refuses to make is that a destination identifies
what happened. A name is what the sample says it talks to (a Host header, a
server name, a lookup): keyed by the name alone, a baseline that has seen the
Defender update ``.exe`` from ``download.windowsupdate.com`` would hide any PE
a sample fetches with that Host header. So a key holds what the clean machine
did, not only where: a download its path, kind, hash and size, a request its
method, path and user agent, a handshake its JA4, a check-in the scale of its
interval, a burst of failed lookups the names that failed. A sample that
borrows a host name with another path, file or rhythm does not match. The
price is that a clean machine whose update changes its file needs a fresh
baseline capture; that is the right direction to fail in.

Two further points:

  * Keys come from events, before or after serialization. A report holds
    masked copies: ``***`` for a password, for the text of a decoded
    credential, and for a credential in a path or a User-Agent, which are part
    of a key. So each copy carries the key of its raw event (``baseline_key``,
    set by ``net_analyze``) and ``event_key`` uses it, and a baseline captured
    from a report matches the raw events of the next analysis. Nothing secret is stored: a key is a hash, and an entry keeps
    the event type, destination and port.
  * A rhythm is not measured twice to the millisecond. A beacon's interval is
    put into a bucket of ``INTERVAL_STEP`` (a factor of 1.25) and a beacon is
    known when a neighbouring bucket is: a 45 s poller matches at 44.6 s and
    at 45.3 s, and a sample beaconing every 13 s to the same name does not.

A file of another ``KEY_VERSION`` is ignored (its keys were built by other
rules and would match the wrong things or nothing) and replaced on the next
``add``; an unreadable one is moved aside to ``<path>.corrupt``.
"""

import hashlib
import ipaddress
import json
import math
import os
import threading
import time

KEY_VERSION = 1
KEY_FIELD = "baseline_key"     # the key, carried by a report's (masked) copy of an event
INTERVAL_STEP = 1.25    # ratio between neighbouring beacon interval buckets


def _name(value):
    if not isinstance(value, str):
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower().rstrip(".")


def _text(value):
    return value if isinstance(value, str) else ""


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) else None


def _bucket(interval):
    interval = _number(interval)
    if interval is None or interval <= 0:
        return None
    return int(math.floor(math.log(interval) / math.log(INTERVAL_STEP)))


def _names(values):
    return sorted({_name(v) for v in values if isinstance(v, str)}) \
        if isinstance(values, (list, tuple)) else []


def _identity(event):
    """What an event did, as a tuple of plain values, without its time.

    The first element is the event type and the second its destination; a
    beacon's interval bucket is the last element (see ``_candidates``).
    """
    etype = event.get("type")
    dest = _name(event.get("dest"))
    port = _number(event.get("port"))
    get = event.get
    if etype == "dns":
        return (etype, dest, _text(get("query_type")), bool(get("nxdomain")))
    if etype in ("conn", "conn_failed", "udp"):
        return (etype, dest, port)
    if etype == "tls":
        return (etype, dest, port, _text(get("ja4")))
    if etype == "http":
        return (etype, dest, _text(get("method")), _text(get("path")), _text(get("ua")))
    if etype == "raw":
        return (etype, dest, port, _text(get("direction")), _text(get("framing")))
    if etype == "ftp":
        return (etype, dest, port, _text(get("user")))
    if etype == "smtp":
        return (etype, dest, port, _text(get("user")), _name(get("mail_from")),
                tuple(_names(get("rcpt_to"))))
    if etype == "websocket":
        return (etype, dest, _text(get("path")))
    if etype == "download":
        return (etype, dest, _text(get("path")), _text(get("kind")),
                _text(get("sha256")) or _text(get("wire_sha256")), _number(get("size")))
    if etype == "upload":
        return (etype, dest, _text(get("method")), _text(get("path")),
                _text(get("content_type")).split(";")[0].strip().lower(), _text(get("kind")))
    if etype == "decoded":
        # A credential is masked in a report, its hash with it; its key is where it went.
        content = "credential" if get("credential") else _text(get("sha256"))
        return (etype, dest, _text(get("source")), _text(get("field")), _text(get("name")),
                _text(get("scheme")), _text(get("kind")), content)
    if etype == "beacon":
        bucket = _bucket(get("interval"))
        return (etype, dest, "unmeasured" if bucket is None else bucket)
    if etype == "retry":
        return (etype, dest)
    if etype == "fanout":
        return (etype, _text(get("path")), bool(get("nxdomain")), tuple(_names(get("dests"))))
    return None


def _hash(identity):
    text = json.dumps([KEY_VERSION] + list(identity), separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _carried(event):
    key = event.get(KEY_FIELD)
    if isinstance(key, str) and len(key) == 32 and all(c in "0123456789abcdef" for c in key):
        return key
    return None


def event_key(event):
    """The baseline key of an event, or None for something that is not one.

    A report's events are masked copies (a path or a User-Agent may have lost a
    credential to ``***``), so ``net_analyze`` puts the key of the raw event in
    ``baseline_key``; it is used when present, and a baseline built from a
    report matches the raw events of the next analysis.
    """
    if not isinstance(event, dict):
        return None
    carried = _carried(event)
    if carried is not None:
        return carried
    identity = _identity(event)
    return _hash(identity) if identity is not None else None


def _candidates(event):
    """Keys under which an event counts as known: its own, and for a measured
    beacon those of the neighbouring interval buckets."""
    identity = _identity(event) if isinstance(event, dict) else None
    if identity is None:
        return []
    keys = [_carried(event) or _hash(identity)]
    if identity[0] == "beacon" and isinstance(identity[-1], int):
        keys += [_hash(identity[:-1] + (identity[-1] + step,)) for step in (-1, 1)]
    return keys


class NetBaseline:
    """Keys of network events observed on this VM while it was clean."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._data = self._empty()
        self.load()

    @staticmethod
    def _empty():
        return {"created": None, "updated": None, "key_version": KEY_VERSION, "keys": {},
                "dests": {}}

    def _stale(self):
        # a file without a version was not written by this module's scheme
        return self._data.get("key_version") != KEY_VERSION

    def load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            if not (isinstance(data, dict) and isinstance(data.get("keys"), dict)):
                raise ValueError("not a network baseline")
            data.setdefault("dests", {})
            self._data = data
            if self._stale():
                print("[net_baseline] %s uses key scheme v%s, current is v%d: ignored until "
                      "the baseline is captured again"
                      % (self.path, data.get("key_version"), KEY_VERSION))
        except (ValueError, OSError) as e:
            print("[net_baseline] unreadable baseline %s: %s" % (self.path, e))
            try:
                os.replace(self.path, self.path + ".corrupt")
            except OSError:
                pass

    def save(self):
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self._data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError as e:
            print("[net_baseline] could not save %s: %s" % (self.path, e))

    def add(self, events):
        """Record events as what this VM does on its own. Returns the number of new keys."""
        added = 0
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            if self._stale():
                self._data = self._empty()
            keys = self._data.setdefault("keys", {})
            dests = self._data.setdefault("dests", {})
            for event in events or ():
                key = event_key(event)
                if key is None:
                    continue
                dest = _name(event.get("dest"))
                entry = keys.get(key)
                if entry is None:
                    port = _number(event.get("port"))
                    keys[key] = {"type": event.get("type"), "dest": dest[:255],
                                 "port": port, "first_seen": now, "count": 1}
                    added += 1
                else:
                    entry["count"] = entry.get("count", 1) + 1
                if dest:
                    dests[dest[:255]] = dests.get(dest[:255], 0) + 1
            self._data["created"] = self._data.get("created") or now
            self._data["updated"] = now
            self.save()
        return added

    def knows(self, key):
        if self._stale():
            return False
        return key in (self._data.get("keys") or {})

    def knows_event(self, event):
        """Is this event what the clean VM did (its key, or a neighbouring rhythm)?"""
        return any(self.knows(key) for key in _candidates(event))

    def knows_dest(self, dest):
        """Did the clean VM talk to this destination at all, whatever it did there?"""
        if self._stale():
            return False
        return _name(dest) in (self._data.get("dests") or {})

    @property
    def count(self):
        return 0 if self._stale() else len(self._data.get("keys") or {})

    def clear(self):
        with self._lock:
            self._data = self._empty()
            self.save()

    def stats(self):
        with self._lock:
            keys = dict(self._data.get("keys") or {})
            created, updated = self._data.get("created"), self._data.get("updated")
            stale = self._stale()
            stored_version = self._data.get("key_version")
        by_type = {}
        for entry in keys.values():
            by_type[entry.get("type", "?")] = by_type.get(entry.get("type", "?"), 0) + 1
        out = {"total": 0 if stale else len(keys), "by_type": {} if stale else by_type,
               "created": created, "updated": updated, "key_version": KEY_VERSION}
        if stale:
            out["stale"] = True
            out["stale_keys"] = len(keys)
            out["note"] = ("Baseline was captured with key scheme v%s and is ignored; capture "
                           "it again on a clean system." % stored_version)
        return out
