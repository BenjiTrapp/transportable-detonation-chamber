"""Network event schema.

Everything TDC learns from a pcap - DNS lookups, connections, TLS handshakes,
HTTP requests, decoded payloads, beacon candidates - has to reach one rule
engine and one UI. Each protocol parser would otherwise invent its own shape,
and every consumer would grow a branch per parser. This module fixes the shape:
one event class, one list of types, built through a constructor that enforces
it.

Several assumptions would quietly corrupt the result:

  * A destination is a hostname. Malware often connects to a bare IP, which is
    itself a signal ("no DNS lookup came first"). The event therefore records
    whether the destination is an IP, rather than leaving every rule to guess
    from the string.
  * A pcap knows which process sent a packet. It does not: it holds packets,
    not processes. "in_tree" (is the process part of the sample's process
    tree) is always False in this phase and must not be derived from
    anything. The field exists because a later phase fills it, so rules and UI
    can already refer to it.
  * Events arrive in time order. They arrive per parser, so merging them
    needs an explicit sort, and events with the same timestamp must keep
    their order or the same pcap yields different timelines between runs.
  * Any string is a valid event type. A misspelt type silently matches no
    rule, so unknown types are rejected where the event is created.

Event timestamps are Unix seconds as float. Parser-specific data goes into
extra keyword fields; the mandatory ones are always present.
"""

import ipaddress

EVENT_TYPES = (
    "dns", "conn", "conn_failed", "tls", "http", "udp", "raw", "ftp", "smtp",
    "websocket", "download", "upload", "decoded", "beacon", "retry", "fanout",
)


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


class NetEvent(dict):
    """One network event.

    A dict subclass built through a constructor that enforces the schema. The
    mandatory fields and the fields of every parser except one are plain JSON
    values, so such an event goes through ``json.dumps`` as it is. The
    exception is deliberate: ``net_mail_ftp`` stores a captured password as a
    ``Secret``, which is not JSON-serializable and makes ``json.dumps`` (and
    pickling) raise ``TypeError``. Events that may hold one (``ftp``, ``smtp``)
    are serialized through ``net_mail_ftp.masked(...)``, which accepts one
    event, a list of them or any nesting and returns plain dicts. Using it on
    every event is always safe.
    """

    def __init__(self, type, ts, process="", pid=None, dest="", **fields):
        if type not in EVENT_TYPES:
            raise ValueError("unknown network event type: %r" % (type,))
        super().__init__()
        self["type"] = type
        self["ts"] = float(ts)
        self["process"] = process
        self["pid"] = pid
        self["dest"] = dest
        self["port"] = None
        self.update(fields)
        # Derived last so that a caller's keyword cannot override them.
        self["dest_is_ip"] = _is_ip(dest) if isinstance(dest, str) else False
        self["in_tree"] = False


def sort_events(events):
    """Return a new list in time order; equal timestamps keep insertion order."""
    # list.sort is stable, which provides the tie rule.
    return sorted(events, key=lambda e: e["ts"])


def event_summary(events):
    """Count of events per type."""
    counts = {}
    for e in events:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    return counts
