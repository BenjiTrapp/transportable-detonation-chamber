"""DNS messages to ``dns`` events.

A pcap's DNS traffic is where most malware's first move shows up: the lookup of
a command server, a burst of names that do not exist, a TXT record carrying
instructions. The assumptions this module refuses to make:

  * A flow is not one lookup. UDP flows are grouped by 4-tuple, so a client
    that keeps its source port puts many DNS messages into one flow. The
    datagrams are read one by one (``Flow.packets``), never as the joined
    stream, because the stream merges them and loses the time of each. An
    event carries the timestamp of the query datagram it came from.
  * An answer belongs to the query before it. It belongs to the query with the
    same transaction ID (and the same question, because IDs are only 16 bits
    and are reused), whatever order the answers arrive in.
  * A query with no answer is not nothing. A lookup that timed out, or whose
    answer was not captured, is still an event, with no answers and no rcode.
  * The direction of a UDP flow is known. It is not: the first sender is only
    taken for the client, so a capture that begins with a response makes the
    resolver look like the client. Query or response is read from the message's
    own header and the resolver from the port 53 side. A response whose query
    is not in the capture is kept as an event of its own; a repeated copy of
    an answer already seen is not a second lookup.
  * The number in the header is enough. NXDOMAIN is what a burst of generated
    names looks like, so it is a flag (``nxdomain``) next to the named rcode,
    and SERVFAIL, REFUSED and the rest are not it.
  * A DNS message from a capture is well-formed. One that is cut, looping or
    not DNS at all is skipped on its own; it does not stop the messages beside
    it. Nothing in a message is executed or opened as a file.

Only UDP is read. DNS over TCP frames its messages inside a stream, and the
flow keeps no per-message time for a stream, so ``is_dns`` leaves those flows
to the generic parser rather than invent timestamps.

The event's ``dest`` is the name that was asked about (what rules and the
behaviour analysis group by); the resolver that answered is ``server``.
"""

import socket

import dpkt

from net_events import NetEvent

DNS_PORT = 53

_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY",
}
_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED",
}
_NXDOMAIN = 3


def is_dns(flow):
    """True for a UDP flow with port 53 on either end."""
    return flow.proto == "udp" and DNS_PORT in (flow.sport, flow.dport)


def _name(raw):
    return raw.lower().rstrip(".") or "."


def _type_name(code):
    return _QTYPES.get(code, "TYPE%d" % code)


def _rcode_name(code):
    return _RCODES.get(code, "RCODE%d" % code)


def _txt(rdata):
    """The character strings of a TXT record joined, tolerating a cut one."""
    out = []
    pos = 0
    while pos < len(rdata):
        size = rdata[pos]
        out.append(rdata[pos + 1:pos + 1 + size])
        pos += 1 + size
    return b"".join(out).decode("utf-8", "backslashreplace")


def _answer(rr):
    kind = rr.type
    if kind == 1 and len(rr.rdata) == 4:
        return socket.inet_ntoa(rr.rdata)
    if kind == 28 and len(rr.rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rr.rdata)
    if kind == 5:
        return _name(rr.cname)
    if kind == 2:
        return _name(rr.nsname)
    if kind == 12:
        return _name(rr.ptrname)
    if kind == 15:
        return _name(rr.mxname)
    if kind == 16:
        return _txt(rr.rdata)
    # RFC 3597 notation for a record this module does not interpret
    return "\\# %d %s" % (len(rr.rdata), rr.rdata.hex())


def _parse(payload):
    """``(txid, is_response, name, qtype, rcode, answers)`` or None to skip."""
    try:
        msg = dpkt.dns.DNS(payload)
        name, qtype = (_name(msg.qd[0].name), msg.qd[0].type) if msg.qd else (None, None)
        answers = [_answer(rr) for rr in msg.an]
        return msg.id, bool(msg.qr), name, qtype, msg.rcode, answers
    except Exception:
        # a datagram from a capture is untrusted; whatever way dpkt fails on
        # it, the datagram is skipped and its neighbours are still read
        return None


def events_from_flow(flow):
    """One ``dns`` event per query (or per unmatched response) of a UDP flow."""
    server = flow.dst if flow.dport == DNS_PORT else flow.src
    events = []
    pending = {}        # txid -> [(name, qtype, event)] of unanswered queries
    seen = set()        # (txid, name, qtype) of every lookup already reported

    def make(ts, name, qtype, rcode=None, answers=()):
        """rcode None: a query whose answer has not been seen."""
        return NetEvent("dns", ts, dest=name, port=DNS_PORT, server=server,
                        query=name, query_type=_type_name(qtype),
                        answers=list(answers),
                        rcode="" if rcode is None else _rcode_name(rcode),
                        nxdomain=rcode == _NXDOMAIN)

    for ts, _direction, payload in flow.packets:
        parsed = _parse(payload)
        if parsed is None:
            continue
        txid, is_response, name, qtype, rcode, answers = parsed
        if not is_response:
            if name is None:
                continue
            event = make(ts, name, qtype)
            events.append(event)
            pending.setdefault(txid, []).append((name, qtype, event))
            seen.add((txid, name, qtype))
            continue
        waiting = pending.get(txid, [])
        match = next((i for i in range(len(waiting) - 1, -1, -1)
                      if name is None or waiting[i][:2] == (name, qtype)), None)
        if match is not None:
            event = waiting.pop(match)[2]
            event["answers"] = answers
            event["rcode"] = _rcode_name(rcode)
            event["nxdomain"] = rcode == _NXDOMAIN
        elif name is not None and (txid, name, qtype) not in seen:
            seen.add((txid, name, qtype))
            events.append(make(ts, name, qtype, rcode, answers))
    return events
