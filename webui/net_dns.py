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
    and are reused), whatever order the answers arrive in. Matching is by
    dictionary lookup, because a capture can hold tens of thousands of queries
    under one ID (scanners and some malware never change it).
  * A query with no answer is not nothing. A lookup that timed out, or whose
    answer was not captured, is still an event, with no answers and no rcode.
    ``rcode == ""`` means that no response was paired with *this* datagram, not
    that the lookup went unanswered: a query that was retransmitted before its
    answer arrived leaves the earlier copy unpaired, and the answer goes to the
    latest copy.
  * The direction of a UDP flow is known. It is not: the first sender is only
    taken for the client, so a capture that begins with a response makes the
    resolver look like the client. Query or response is read from the message's
    own header and the resolver from the port 53 side. A response whose query
    is not in the capture is kept as an event of its own; a repeated copy of
    an answer already seen is not a second lookup.
  * The number in the header is enough. NXDOMAIN is what a burst of generated
    names looks like, so it is a flag (``nxdomain``) next to the named rcode,
    and SERVFAIL, REFUSED and the rest are not it.
  * A name is text. A label may hold any byte, and a lookup with binary labels
    is what DNS tunnelling and some C2 look like, so a library that insists on
    UTF-8 would drop exactly the lookups worth seeing. The names are therefore
    read here, not by dpkt, and written the way a zone file writes them: a
    printable ASCII byte stands for itself, "." and "\\" inside a label are
    preceded by a backslash, and any other byte is "\\DDD" (its decimal
    value). The rendering is unambiguous, so "a.b.top" and a single label
    "a.b" under "top" stay two different destinations, and the original bytes
    can be read back from it. Only A-Z are lower-cased.
  * A DNS message from a capture is well-formed. One that is cut, looping or
    not DNS at all is skipped on its own; it does not stop the messages beside
    it. A response cut inside its answers keeps the records read before the
    cut. Nothing in a message is executed or opened as a file.
  * An answer section is a few records. Compression pointers let 56 KB of
    message hold 4000 answers of 253 characters each, a megabyte of names in
    one event; sixty such replies were 61 MB of report. A message keeps its
    first ``MAX_ANSWERS`` records and ``answers_capped`` says more existed.

Only UDP is read. DNS over TCP frames its messages inside a stream, and the
flow keeps no per-message time for a stream, so ``is_dns`` leaves those flows
to the generic parser rather than invent timestamps.

The event's ``dest`` is the name that was asked about (what rules and the
behaviour analysis group by); the resolver that answered is ``server``.

Which answers to believe is ``trusted_lookups``: a capture holds the
sample's own DNS too, and one reply it served itself (``ocsp.digicert.com A
<its C2>``) made forty uploads to the C2 the clean machine's OCSP requests.
"""

import ipaddress
import socket
import struct

from net_events import NetEvent, render_bytes

DNS_PORT = 53
MAX_ANSWERS = 64                # answer records kept per message

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
_HEADER = struct.Struct("!6H")
_RR_FIXED = struct.Struct("!HHIH")      # type, class, ttl, rdlength
_QUESTION_FIXED = struct.Struct("!HH")  # type, class
_MAX_NAME = 255
_MAX_JUMPS = 127


class _Bad(Exception):
    """The bytes are not a readable piece of a DNS message."""


def is_dns(flow):
    """True for a UDP flow with port 53 on either end."""
    return flow.proto == "udp" and DNS_PORT in (flow.sport, flow.dport)


def _type_name(code):
    return _QTYPES.get(code, "TYPE%d" % code)


def _rcode_name(code):
    return _RCODES.get(code, "RCODE%d" % code)


def _read_name(buf, pos):
    """``(name, position after it)``; follows compression pointers."""
    labels = []
    size = 0
    after = None
    jumps = 0
    while True:
        if pos >= len(buf):
            raise _Bad("name runs past the message")
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise _Bad("cut pointer")
            if after is None:
                after = pos + 2
            jumps += 1
            if jumps > _MAX_JUMPS:
                raise _Bad("compression pointers loop")
            pos = ((length & 0x3F) << 8) | buf[pos + 1]
            continue
        if length & 0xC0:
            raise _Bad("reserved label type")
        raw = buf[pos + 1:pos + 1 + length]
        if len(raw) < length:
            raise _Bad("label runs past the message")
        size += length + 1
        if size > _MAX_NAME:
            raise _Bad("name too long")
        labels.append(render_bytes(raw, escape=b"."))
        pos += 1 + length
    name = ".".join(labels).lower() or "."
    return name, (after if after is not None else pos)


def _txt(rdata):
    """The character strings of a TXT record joined."""
    out = []
    pos = 0
    while pos < len(rdata):
        size = rdata[pos]
        out.append(rdata[pos + 1:pos + 1 + size])
        pos += 1 + size
    return b"".join(out).decode("utf-8", "backslashreplace")


def _generic(rdata):
    """RFC 3597 notation, for a record this module does not interpret."""
    return "\\# %d %s" % (len(rdata), rdata.hex())


def _answer(buf, kind, start, rdata):
    try:
        if kind == 1 and len(rdata) == 4:
            return socket.inet_ntoa(rdata)
        if kind == 28 and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if kind in (2, 5, 12):
            return _read_name(buf, start)[0]
        if kind == 15:
            return _read_name(buf, start + 2)[0]
        if kind == 16:
            return _txt(rdata)
    except _Bad:
        pass
    return _generic(rdata)


def _parse(payload):
    """``(txid, is_response, name, qtype, rcode, answers, capped)`` or None to skip.

    ``name`` and ``qtype`` are None for a message with no question. The header
    and the first question must be readable; the answers are the complete
    records before the first one that is not, at most ``MAX_ANSWERS``
    (``capped`` says the message declared more).
    """
    if len(payload) < _HEADER.size:
        return None
    txid, flags, qdcount, ancount, _ns, _ar = _HEADER.unpack_from(payload)
    pos = _HEADER.size
    name = qtype = None
    try:
        for i in range(qdcount):
            qname, pos = _read_name(payload, pos)
            if pos + _QUESTION_FIXED.size > len(payload):
                raise _Bad("cut question")
            kind, _cls = _QUESTION_FIXED.unpack_from(payload, pos)
            pos += _QUESTION_FIXED.size
            if i == 0:
                name, qtype = qname, kind
    except _Bad:
        return None
    answers = []
    try:
        for _ in range(min(ancount, MAX_ANSWERS)):
            _owner, pos = _read_name(payload, pos)
            if pos + _RR_FIXED.size > len(payload):
                break
            kind, _cls, _ttl, rdlength = _RR_FIXED.unpack_from(payload, pos)
            start = pos + _RR_FIXED.size
            rdata = payload[start:start + rdlength]
            if len(rdata) < rdlength:
                break
            answers.append(_answer(payload, kind, start, rdata))
            pos = start + rdlength
    except _Bad:
        pass
    return (txid, bool(flags & 0x8000), name, qtype, flags & 0x000F, answers,
            ancount > MAX_ANSWERS)


def _take(stack):
    """Pop the most recent unanswered entry of a stack, or None."""
    while stack:
        entry = stack.pop()
        if not entry[1]:
            entry[1] = True
            return entry[0]
    return None


def events_from_flow(flow):
    """One ``dns`` event per query (or per unmatched response) of a UDP flow."""
    server = flow.dst if flow.dport == DNS_PORT else flow.src
    events = []
    # Unanswered queries, most recent last. Each is pushed onto two stacks, one
    # by (txid, name, type) and one by txid alone for a response that carries
    # no question, and is marked answered when either takes it; the other
    # stack drops it when it reaches it. Every entry is pushed and popped once
    # per stack, so matching costs the same however many queries share an ID.
    by_question = {}
    by_txid = {}
    seen = set()        # (txid, name, type) of every lookup already reported

    def make(ts, name, qtype, rcode=None, answers=(), capped=False):
        """rcode None: a query whose answer has not been seen."""
        return NetEvent("dns", ts, dest=name, port=DNS_PORT, server=server,
                        query=name, query_type=_type_name(qtype),
                        answers=list(answers), answers_capped=bool(capped),
                        rcode="" if rcode is None else _rcode_name(rcode),
                        nxdomain=rcode == _NXDOMAIN)

    for ts, _direction, payload in flow.packets:
        parsed = _parse(payload)
        if parsed is None:
            continue
        txid, is_response, name, qtype, rcode, answers, capped = parsed
        if not is_response:
            if name is None:
                continue
            event = make(ts, name, qtype)
            events.append(event)
            entry = [event, False]
            by_question.setdefault((txid, name, qtype), []).append(entry)
            by_txid.setdefault(txid, []).append(entry)
            seen.add((txid, name, qtype))
            continue
        if name is None:
            event = _take(by_txid.get(txid, []))
        else:
            event = _take(by_question.get((txid, name, qtype), []))
        if event is not None:
            event["answers"] = answers
            event["answers_capped"] = capped
            event["rcode"] = _rcode_name(rcode)
            event["nxdomain"] = rcode == _NXDOMAIN
        elif name is not None and (txid, name, qtype) not in seen:
            seen.add((txid, name, qtype))
            events.append(make(ts, name, qtype, rcode, answers, capped))
    return events


# --- which answers a capture's resolution rests on ---------------------------------

RESOLVER_SHARE = 0.25           # of the answered lookups a resolver answered at least
_ENDPOINT_TYPES = frozenset(("conn", "conn_failed"))
_DNS_PORTS = frozenset((53, 853))   # DNS over TCP and DNS over TLS: a resolver's own ports


def _address(text):
    try:
        return str(ipaddress.ip_address(text))
    except (ValueError, TypeError):
        return None


def trusted_lookups(events, resolvers=None):
    """The ``dns`` events of a capture whose answers it may believe, with only
    the answers it may believe.

    ``resolvers``, when given, are the resolvers a network baseline learned on
    the clean machine (``net_baseline.NetBaseline.learned_resolvers``): then
    only lookups those servers answered count, whatever share of the capture
    they answered, and the share rule below is not needed. Without them, a
    sample's own DNS server that answered the only lookup of a capture was
    believed (forty spoofed OCSP uploads to the C2 known to the baseline).

    A DNS answer is the sample's to write when the sample talks to a DNS
    server of its own. An answer counts only when it came from one of the
    capture's resolvers, defined as a server that answered at least
    ``RESOLVER_SHARE`` of the capture's answered lookups (the machine's one
    or two configured resolvers answer nearly all of them; a sample's own
    server answers its few) and to which the capture made no TCP connection
    and sent no HTTP exchange (a resolver is not where an upload goes). A
    connection to port 53 or 853 does not count: Windows asks its resolver
    again over TCP when a reply was truncated, and one such exchange took the
    resolver of an idle hour away (411 of 415 events no longer suppressed,
    thirteen check-ins on known-good servers, SUSPICIOUS 4.0). And
    never an answer that names the server that gave it (a self-answer: the
    C2 vouching for itself). Events without a ``server`` count as one server.

    Not required: that a resolver answered several names. The capture of a
    short detonation may hold one lookup, the C2's, and that answer is what
    ties the name of a check-in to the address of its connections. What this
    leaves open: a sample whose own DNS server, at an address it does not
    otherwise contact, answers a quarter or more of a capture's lookups (in a
    capture with few lookups, one) is believed; the event still names the
    server that answered (``server``).
    """
    lookups = [e for e in events if isinstance(e, dict) and e.get("type") == "dns"]
    counts = {}
    for e in lookups:
        if e.get("answers"):
            server = _address(e.get("server")) or ""
            counts[server] = counts.get(server, 0) + 1
    total = sum(counts.values())
    if not total:
        return []
    endpoints = set()
    for e in events:
        if not isinstance(e, dict) or e.get("type") == "dns":
            continue
        if e.get("type") in _ENDPOINT_TYPES and e.get("port") not in _DNS_PORTS:
            endpoints.add(_address(e.get("dest")))
        for address in e.get("addresses") or ():
            endpoints.add(_address(address))
    learned = None if resolvers is None else {_address(r) or "" for r in resolvers}
    resolvers = {server for server, count in counts.items()
                 if (count >= RESOLVER_SHARE * total if learned is None else server in learned)
                 and server not in endpoints}
    out = []
    for e in lookups:
        server = _address(e.get("server")) or ""
        if server not in resolvers or not e.get("answers"):
            continue
        answers = [a for a in e["answers"] if not server or _address(a) != server]
        out.append(dict(e, answers=answers))
    return out
