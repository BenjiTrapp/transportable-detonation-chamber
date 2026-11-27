"""The DNS server of the fake internet: where a faked name gets its address.

This is the hinge of the approach. The address a name is given here is what the fake servers read back out of a
connection's destination later (``Diverter.name_for``), which is the only way a raw protocol that carries no name, or a
sample that connects by IP, can be attributed at all. So every name gets an address of its own, on first ask, and the
same one every time.

This module opens no socket and starts no thread. The session binds UDP 53 and calls ``answer`` once per datagram,
from whatever thread read it; ``answer`` returns the bytes to send back, or None when nothing should be sent.

What is answered, and why it is this much and no more:

  * A standard query (QR 0, opcode QUERY, one question, class IN) is answered; anything else is not, and is counted. A
    resolver that gets no answer to a status request or an IQUERY just carries on, and answering them would be
    inventing behaviour the sample did not ask for.
  * ``A`` gets one record with the diverter's address for the name. ``AAAA``, ``TXT`` and every other type get NOERROR
    with no records, never NXDOMAIN: NXDOMAIN says the *name* does not exist, and some clients give up on the name for
    every type when they hear it. A DNS tunnel that asks TXT keeps talking too, which is what it is there to show.
  * The question is echoed byte for byte as it was asked. Resolvers randomise the case of the name (DNS 0x20) and
    accept an answer only if the case came back unchanged; the diverter is given the normalised name, so ``C2.eViL``
    and ``c2.evil`` are one name with one address. A question that does not survive being written out again as it
    came in (a label that holds a dot, a byte that is not text) cannot be echoed, and is treated as unreadable.
  * A name on the session's passthrough list is **not** faked and gets no answer from here: the real resolver, when
    there is one, is the answer. The match is exact (after lower case and without the root dot; ``host:port`` counts as
    ``host``), subdomains are not included: allowing ``mine.example`` must not allow ``anything.mine.example``.
  * A name the diverter could neither give an address of its own nor a working shared one (``unaddressed_names`` of
    its state, Ruling 93) is still answered with the shared address, so that the sample tries and the attempt is
    seen. The server notices and lists it in ``summary()``: the report must not say a name was served that nothing
    could be reached through.

What goes where. The query and the reply both go to ``ctx.writer`` as UDP datagrams between the guest and the DNS
address, and ``net_analyze.analyze_pcap`` makes the ``dns`` events out of the capture as it does for any capture. They
are **not** also put into ``ctx.recorder``: the same lookup would then be in the report twice. What the capture cannot
carry, ``summary()`` does: which names were housekeeping, which were let through, which were answered without an
address that leads anywhere, and how many queries were unreadable or not answered.

A capture that fails is never a reason not to answer: a writer that refuses a datagram (or raises) is counted in
``capture_errors`` and the sample gets its answer.
"""

import socket
import threading
import time

import dpkt

DNS_PORT = 53
DEFAULT_ADDRESS = "127.0.0.1"       # where the guest's DNS points when the diverter does not say
DEFAULT_PEER_PORT = 49152           # the guest's side of the exchange when the caller does not know it
REPLY_DELAY = 0.001                 # seconds between a query and its reply in the capture
TTL = 60                            # short: a name asked again is asked again, and goes through the diverter again
MAX_LISTED = 1000                   # names kept per list of the summary; the rest are counted

# What a Windows machine that has been left alone asks for: the connectivity check, Windows Update, Defender and
# SmartScreen, the clock and the telemetry. A sample that has not run yet makes these lookups anyway, so a report that
# shows them as the sample's would be wrong. They are answered like any other name and listed apart. A name matches an
# entry when it is that name or ends in ``.`` and that name, never by a bare substring.
HOUSEKEEPING = (
    "msftconnecttest.com",
    "msftncsi.com",
    "windowsupdate.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "dsp.mp.microsoft.com",
    "time.windows.com",
    "data.microsoft.com",
    "telemetry.microsoft.com",
    "watson.microsoft.com",
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "smartscreen.microsoft.com",
    "smartscreen-prod.microsoft.com",
    "definitionupdates.microsoft.com",
    "crl.microsoft.com",
    "ocsp.msocsp.com",
)

_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
          65: "HTTPS", 255: "ANY"}


def _normal(name):
    """A name as the diverter and the lists know it: lower case, no root dot."""
    return str(name).strip().rstrip(".").lower()


def is_housekeeping(name):
    """True for a name a clean Windows looks up (see ``HOUSEKEEPING``), matched on label boundaries."""
    name = _normal(name)
    return any(name == known or name.endswith("." + known) for known in HOUSEKEEPING)


def _passthrough(entries):
    """The names of the passthrough list as the server compares them. An entry may be ``host:port``."""
    out = set()
    for entry in entries or ():
        entry = _normal(entry)
        if entry.count(":") == 1:
            entry = entry.split(":")[0]
        if entry:
            out.add(entry)
    return out


class _Names:
    """Names in the order they were first seen, each once, at most ``MAX_LISTED``; the others are counted."""

    def __init__(self):
        self.items = []
        self.seen = set()
        self.more = 0

    def add(self, item, key):
        if key in self.seen:
            return
        if len(self.items) >= MAX_LISTED:
            self.more += 1
            return
        self.seen.add(key)
        self.items.append(item)


class DnsServer:
    """Answers DNS queries for a session. ``ctx`` is the ``net_pcap.SessionContext``; it is read on every call."""

    TTL = TTL
    HOUSEKEEPING = HOUSEKEEPING

    def __init__(self, ctx):
        self.ctx = ctx
        self._passthrough = _passthrough(getattr(ctx, "passthrough", None))
        self._lock = threading.Lock()
        self._housekeeping = _Names()
        self._passed = _Names()
        self._unaddressed = _Names()
        self._queries = {}
        self._malformed = 0
        self._unsupported = 0
        self._failed = 0
        self._capture_errors = 0

    # --- the call of the socket ------------------------------------------------------------------------------------

    def answer(self, query_bytes, local_addr=None, peer_addr=None, ts=None):
        """The reply to one datagram, or None when nothing is to be sent. It never raises.

        ``local_addr`` is the ``(ip, port)`` the datagram arrived at: the DNS server as the guest sees it, which is
        what the capture records as the remote end (left out, or ``0.0.0.0`` as a socket bound to every address
        reports it, it is the diverter's ``dns_address`` and port 53). ``peer_addr`` is the guest's ``(ip, port)``;
        the writer knows the guest's address, so only the port is used, and ``DEFAULT_PEER_PORT`` when it is missing.
        ``ts`` is when the datagram arrived, in Unix seconds, and defaults to now.
        """
        ts = time.time() if ts is None else ts
        dest, dport = self._local(local_addr)
        sport = self._peer_port(peer_addr)
        self._capture(ts, dest, dport, sport, query_bytes, False)
        reply = self._reply(query_bytes)
        if reply is not None:
            self._capture(ts + REPLY_DELAY, dest, dport, sport, reply, True)
        return reply

    def summary(self):
        """What the capture cannot carry, as copies, for the report:

        ``housekeeping`` the names a clean Windows asks for that were answered, ``passthrough`` the names that were
        declined, ``unaddressed`` the names answered with the shared address although nothing could be reached
        through it (``[{"name", "reason"}]``, Ruling 93), ``housekeeping_more`` and ``unaddressed_more`` names left out
        of those lists once they held ``MAX_LISTED``; ``queries`` how many standard queries there were per type
        (``{"A": n, ...}``); ``malformed`` datagrams that were not a readable query, ``unsupported`` readable ones
        that are not a standard query in class IN, ``failed`` queries the diverter could not give an address for
        (it raised, or the name is no name); ``capture_errors`` datagrams the writer refused.
        """
        with self._lock:
            return {"housekeeping": list(self._housekeeping.items), "housekeeping_more": self._housekeeping.more,
                    "passthrough": list(self._passed.items),
                    "unaddressed": [dict(item) for item in self._unaddressed.items],
                    "unaddressed_more": self._unaddressed.more,
                    "queries": dict(self._queries), "malformed": self._malformed,
                    "unsupported": self._unsupported, "failed": self._failed,
                    "capture_errors": self._capture_errors}

    # --- the capture -----------------------------------------------------------------------------------------------

    def _local(self, addr):
        ip, port = None, None
        try:
            ip, port = addr[0], addr[1]
        except (TypeError, IndexError, KeyError):
            pass
        if not ip or ip == "0.0.0.0":
            ip = getattr(getattr(self.ctx, "diverter", None), "dns_address", None) or DEFAULT_ADDRESS
        return ip, port or DNS_PORT

    @staticmethod
    def _peer_port(addr):
        try:
            return addr[1] or DEFAULT_PEER_PORT
        except (TypeError, IndexError, KeyError):
            return DEFAULT_PEER_PORT

    def _capture(self, ts, dest, dport, sport, payload, inbound):
        writer = getattr(self.ctx, "writer", None)
        if writer is None:
            return
        try:
            written = writer.datagram(ts, dest, dport, sport, payload, inbound=inbound)
        except Exception:       # a call the writer finds wrong, or a file that failed: the sample is answered anyway
            written = False
        if not written:
            with self._lock:
                self._capture_errors += 1

    # --- the answer ------------------------------------------------------------------------------------------------

    def _count(self, field, qtype=None):
        with self._lock:
            if qtype is None:
                setattr(self, field, getattr(self, field) + 1)
            else:
                self._queries[qtype] = self._queries.get(qtype, 0) + 1

    def _reply(self, query_bytes):
        try:
            raw = bytes(query_bytes)
            msg = dpkt.dns.DNS(raw)
            if msg.qr != dpkt.dns.DNS_Q or msg.opcode != dpkt.dns.DNS_QUERY or len(msg.qd) != 1:
                self._count("_unsupported")
                return None
            question = msg.qd[0]
            asked = bytes(dpkt.dns.DNS(qd=[question]))[12:]
        except Exception:       # whatever a datagram that is not DNS makes the parser raise
            self._count("_malformed")
            return None
        if raw[12:12 + len(asked)] != asked:
            self._count("_malformed")
            return None
        if question.cls != dpkt.dns.DNS_IN:
            self._count("_unsupported")
            return None
        name = _normal(question.name)
        self._count(None, _TYPES.get(question.type, "TYPE%d" % question.type))
        if name in self._passthrough:
            with self._lock:
                self._passed.add(name, name)
            return None
        reply = dpkt.dns.DNS(id=msg.id, qr=dpkt.dns.DNS_R, opcode=dpkt.dns.DNS_QUERY, aa=1, rd=msg.rd, ra=1,
                             rcode=dpkt.dns.DNS_RCODE_NOERR)
        reply.qd = [question]
        if question.type == dpkt.dns.DNS_A:
            address = self._address(name)
            if address is None:
                return None
            packed = socket.inet_aton(address)
            reply.an = [dpkt.dns.DNS.RR(name=question.name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN, ttl=TTL,
                                        rlen=4, rdata=packed, ip=packed)]
        return bytes(reply)

    def _address(self, name):
        """The address the diverter gives ``name``, noting what the report needs of it; None when it gave none."""
        diverter = self.ctx.diverter
        try:
            address = diverter.address_for(name)
            socket.inet_aton(address)
        except Exception:       # stopped, not a name, or not an address: the diverter is not the server's to fix
            self._count("_failed")
            return None
        if is_housekeeping(name):
            with self._lock:
                self._housekeeping.add(name, name)
        if address == getattr(diverter, "shared", None):
            self._note_unaddressed(diverter, name)
        return address

    def _note_unaddressed(self, diverter, name):
        """Ask the diverter whether ``name`` got the shared address for want of any: ``state()`` copies under the
        diverter's lock, so only the names that were given the shared address are looked up, never every query."""
        with self._lock:
            if name in self._unaddressed.seen:
                return
        try:
            state = diverter.state()
        except Exception:
            return
        if name in (state.get("unaddressed_names") or ()):
            with self._lock:
                self._unaddressed.add({"name": name, "reason": state.get("unaddressed_reason")}, name)
