"""The capture of a detonation: what the fake servers served, written as a pcap the analysis already knows how to read.

The seam between the two halves of the fake internet is this file. The servers (DNS, HTTP, TLS, the raw protocols)
answer a sample and record what they said; ``CaptureWriter`` turns each recording into the packets such a
conversation would have been, and ``net_analyze.analyze_pcap`` reads them back as it reads any capture. Nothing behind
that function has to know that the answers came from us, which is the point: a second path in the parsers for "traffic
we faked" would be a second thing to keep right in thirteen modules.

What the reader needs, and so what is written (``net_flows`` is the reader):

  * One TCP exchange is a whole conversation: handshake, request, response, close. ``conversation`` is the general
    form, an ordered list of turns, for traffic that is not one request and one answer: a server that speaks first
    (SMTP, FTP), a TLS handshake followed by what was inside it, a protocol that goes back and forth. ``exchange`` is
    the common case of it. A flow without a SYN is a flow whose
    client the reader has to guess, and one without a close ends in a gap the reader reports.
  * Sequence numbers advance with the payload. Reassembly is driven by them and by nothing else, so a request cut into
    segments carries numbers that add up, the acknowledgement of a side is the other side's next byte, and a FIN
    carries the number just past the last byte. A payload is cut into segments of ``MSS`` bytes: no frame is larger
    than a real network would carry, and the reader's own retention (per segment) is spent the way it is on a real
    capture.
  * A source port used again is a new connection. The two have different initial sequence numbers, which is how the
    reader tells them apart, so each conversation has its own. They are derived from what identifies the
    conversation (address, ports, time, and how many times that four-tuple was used before), not drawn from a shared
    generator, so the bytes of a conversation do not depend on which thread got to the writer first.
  * Timestamps are Unix seconds as floats, the convention of ``net_events``. The time of an exchange is the moment the
    guest began the connection; its packets follow within milliseconds, a segment every 100 microseconds. A time that
    is not a finite number cannot be written (the analysis ignores such an event) and is refused.

What a session needs of the writer, which is more than writing:

  * It never raises into a server because of the *file*. A full disk or a closed writer is a counted drop
    (``dropped``, ``error``), because a capture is never a reason for the sample not to be answered. What is raised is a
    call that is wrong (an address that is not IPv4, a port out of range, text instead of bytes): that is a bug in the
    caller, and writing something plausible instead would hide it.
  * Every conversation is written in one piece under a lock, and flushed. Servers run on threads, and a session can be
    stopped, or the process killed, between two conversations; the file is then what was complete when it happened. A
    conversation is written when the server hands it over, so one that was never handed over is not in the file: a
    server that is stopped while it waits for its answer records what it has with an empty response, and the
    request is then in the capture (a request, the server's acknowledgement and a close). A file cut inside a packet
    (a killed process, a copy that was interrupted) is read by ``net_flows`` as far as it goes.
  * It is bounded by what the reader keeps, and the limits are the reader's own, imported so that they cannot drift
    apart. A direction of one conversation is written up to ``MAX_STREAM_BYTES`` and one byte more: that last segment
    does not fit in what the reader retains, so the reader flags the flow as capped itself, and the file says that
    something was cut even to a reader that never saw this writer's counters (``truncated`` counts it here). The
    number of flows is bounded by ``MAX_FLOWS`` (a TCP conversation is one, and so is each distinct UDP four-tuple),
    because a scanner or a worm is made of connections that carry nothing and the payload budget alone never stops
    them. Once the payload of the whole capture has reached ``MAX_TOTAL_BYTES``, or the flows ``MAX_FLOWS``, the rest
    is dropped and counted.

``SessionContext`` is the one object every server is given. It is only an attribute holder; the runner builds it.
"""

import math
import socket
import threading
import zlib

import dpkt

from net_flows import MAX_FLOWS, MAX_STREAM_BYTES, MAX_TOTAL_BYTES

MSS = 1460
MAX_DATAGRAM = 65507            # what fits in a UDP datagram inside an IPv4 packet

_GUEST_MAC = b"\x52\x54\x00\x12\x34\x56"
_GATEWAY_MAC = b"\x52\x54\x00\x65\x43\x21"
_WINDOW = 64240
_MASK32 = 0xFFFFFFFF
_SEED = "tdc-net-pcap"

# Time between the packets of a conversation, in microseconds.
_RTT = 1000
_THINK = 2000
_SEGMENT = 100


def _address(value, what):
    try:
        return socket.inet_pton(socket.AF_INET, value)
    except (OSError, TypeError, ValueError):
        raise ValueError("%s must be a dotted IPv4 address, not %r" % (what, value))


def _port(value, what):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise ValueError("%s must be a port from 1 to 65535, not %r" % (what, value))
    return value


def _micros(ts):
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise TypeError("ts must be Unix seconds as a number, not %r" % (ts,))
    if not math.isfinite(ts) or not 0 <= ts < 2 ** 32:
        raise ValueError("ts must be a finite number of Unix seconds, not %r" % (ts,))
    return int(round(ts * 1000000))


def _bytes(value, what):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("%s must be bytes, not %s" % (what, type(value).__name__))
    return bytes(value)


def _turns(turns):
    """The turns as a list of ``(direction, bytes)`` with the empty ones gone, or a ValueError/TypeError."""
    out = []
    for turn in list(turns):
        try:
            direction, data = turn
        except (TypeError, ValueError):
            raise ValueError("a turn is a (direction, bytes) pair, not %r" % (turn,))
        if direction not in ("c", "s"):
            raise ValueError("a turn's direction is 'c' (the guest speaks) or 's' (the server does), not %r"
                             % (direction,))
        data = _bytes(data, "a turn's payload")
        if data:
            out.append((direction, data))
    return out


class CaptureWriter:
    """Writes the traffic the fake servers served as a classic pcap (Ethernet, IPv4, TCP and UDP).

    ``guest_ip`` is the address of the detonation machine; every conversation is between it and a remote address.
    ``dest`` is that remote address (an IPv4 string), ``dport`` its port and ``sport`` the guest's.

    Counters, for the session log: ``exchanges`` (conversations and UDP exchanges written), ``datagrams`` (a UDP
    exchange counts its two), ``flows`` (what the reader will see as flows), ``packets`` and ``payload_bytes``
    written, ``truncated`` directions cut at ``MAX_STREAM_BYTES``, ``dropped`` calls that wrote nothing (the writer
    was closed, a budget was spent, the file failed). ``error`` is the reason the file failed, or empty.
    """

    def __init__(self, path, guest_ip):
        self.path = path
        self.guest_ip = guest_ip
        self._guest = _address(guest_ip, "guest_ip")
        self.exchanges = 0
        self.datagrams = 0
        self.flows = 0
        self.packets = 0
        self.payload_bytes = 0
        self.truncated = 0
        self.dropped = 0
        self.error = ""
        self._uses = {}                 # (remote, dport, sport) -> TCP conversations admitted on it
        self._udp = set()               # the UDP four-tuples admitted
        self._lock = threading.Lock()
        self._closed = False
        # Opened, and the header written, now: a path that cannot be written is the session's problem at its start,
        # not a surprise when the first exchange is recorded.
        self._out = open(path, "wb")
        try:
            self._out.write(bytes(dpkt.pcap.LEFileHdr(snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB)))
            self._out.flush()
        except BaseException:
            self._out.close()
            raise

    # --- the calls of the servers --------------------------------------------------------------------------------

    def exchange(self, ts, dest, dport, sport, request, response, proto="tcp"):
        """Record one request and its answer as a whole conversation; True when it was written.

        ``ts`` is when the guest began the connection. For ``proto="tcp"`` this is ``conversation`` with the request
        and then the response as its two turns; for ``"udp"`` it is a datagram each way. Either payload may be
        empty. A request with an empty response is written as what it is: the request, the server's acknowledgement
        and a close.
        """
        if proto not in ("tcp", "udp"):
            raise ValueError("proto must be 'tcp' or 'udp', not %r" % (proto,))
        if proto == "tcp":
            return self.conversation(ts, dest, dport, sport, [("c", request), ("s", response)])
        remote = _address(dest, "dest")
        _port(dport, "dport")
        _port(sport, "sport")
        t0 = _micros(ts)
        request = _bytes(request, "request")
        response = _bytes(response, "response")
        for payload in (request, response):
            if len(payload) > MAX_DATAGRAM:
                raise ValueError("a datagram holds at most %d bytes, not %d" % (MAX_DATAGRAM, len(payload)))
        size = len(request) + len(response)
        if self._admit(("udp", remote, dport, sport), size) is None:
            return False
        frames = [self._udp_frame(t0, remote, dport, sport, request, True),
                  self._udp_frame(t0 + _THINK, remote, dport, sport, response, False)]
        return self._write(frames, size, 0, exchanges=1, datagrams=2)

    def conversation(self, ts, dest, dport, sport, turns):
        """Record a TCP conversation as the turns it took, in order; True when it was written.

        ``turns`` is a sequence of ``(direction, payload)``: ``"c"`` when the guest spoke, ``"s"`` when the server
        did. Consecutive turns of one direction are one run of bytes; an empty payload is skipped. Whatever order
        they are given in is the order they go on the wire, with the numbers a real conversation would have: a server
        that speaks first (a banner) is written server first, and a TLS handshake followed by the plaintext of what
        it carried is one connection, not two. A conversation with no turns is a handshake and a close.
        """
        remote = _address(dest, "dest")
        _port(dport, "dport")
        _port(sport, "sport")
        t0 = _micros(ts)
        turns = _turns(turns)
        turns, cut = self._cut(turns)
        size = sum(len(data) for _d, data in turns)
        use = self._admit(("tcp", remote, dport, sport), size)
        if use is None:
            return False
        frames = self._conversation(t0, remote, dport, sport, turns, use)
        return self._write(frames, size, cut, exchanges=1)

    def datagram(self, ts, dest, dport, sport, payload, inbound=False):
        """Record one UDP datagram; True when it was written.

        By default it is the guest's, sent to ``dest``:``dport``. With ``inbound`` it is ``dest``'s answer, from
        ``dest``:``dport`` to the guest's ``sport``: the arguments name the same conversation either way.
        """
        remote = _address(dest, "dest")
        _port(dport, "dport")
        _port(sport, "sport")
        t0 = _micros(ts)
        payload = _bytes(payload, "payload")
        if len(payload) > MAX_DATAGRAM:
            raise ValueError("a datagram holds at most %d bytes, not %d" % (MAX_DATAGRAM, len(payload)))
        if self._admit(("udp", remote, dport, sport), len(payload)) is None:
            return False
        frame = self._udp_frame(t0, remote, dport, sport, payload, not inbound)
        return self._write([frame], len(payload), 0, datagrams=1)

    def close(self):
        """Flush and close the file. Calling it again, or after a failed write, does nothing."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._out.flush()
            except OSError as exc:
                self._fail(exc)
            try:
                self._out.close()
            except OSError as exc:
                self._fail(exc)

    # --- admission and writing -----------------------------------------------------------------------------------

    @staticmethod
    def _cut(turns):
        """The turns with each direction held to ``MAX_STREAM_BYTES`` plus one byte, and how many were cut.

        The byte past the limit is what makes the reader notice: it will not fit in what it retains, and a reader
        that drops a segment says so (``Flow.capped``). A turn that crosses the limit is cut there; the turns of
        that direction after it are not written.
        """
        room = {"c": MAX_STREAM_BYTES + 1, "s": MAX_STREAM_BYTES + 1}
        cut = set()
        out = []
        for direction, data in turns:
            if len(data) > room[direction]:
                data = data[:room[direction]]
                cut.add(direction)
            if data:
                room[direction] -= len(data)
                out.append((direction, data))
            elif room[direction] == 0:
                cut.add(direction)
        return out, len(cut)

    def _admit(self, key, size):
        """Reserve the room for a conversation, or count a drop. Returns how often its four-tuple was used before
        (the conversation's number, for its initial sequence numbers), or None when it may not be written."""
        proto = key[0]
        with self._lock:
            new = proto == "tcp" or key not in self._udp
            if (self._closed or self.error or (new and self.flows >= MAX_FLOWS)
                    or self.payload_bytes + size > MAX_TOTAL_BYTES):
                self.dropped += 1
                return None
            if new:
                self.flows += 1
            self.payload_bytes += size
            if proto == "udp":
                self._udp.add(key)
                return 0
            use = self._uses.get(key[1:], 0)
            self._uses[key[1:]] = use + 1
            return use

    def _write(self, frames, size, cut, exchanges=0, datagrams=0):
        blob = b"".join(frames)
        with self._lock:
            if self._closed or self.error:
                self.dropped += 1
                self.payload_bytes -= size
                return False
            try:
                self._out.write(blob)
                self._out.flush()
            except OSError as exc:
                self._fail(exc)
                self.dropped += 1
                self.payload_bytes -= size
                return False
            self.packets += len(frames)
            self.truncated += cut
            self.exchanges += exchanges
            self.datagrams += datagrams
            return True

    def _fail(self, exc):
        if not self.error:
            self.error = str(exc) or exc.__class__.__name__

    # --- building packets ----------------------------------------------------------------------------------------

    def _isn(self, use, remote, dport, sport, side):
        """An initial sequence number that belongs to this conversation alone: the same four-tuple used a second
        time (a port that came round again) gets different ones, which is how the reader tells them apart."""
        name = "%s|%s|%d|%d|%d|%s" % (_SEED, socket.inet_ntoa(remote), dport, sport, use, side)
        return zlib.crc32(name.encode("ascii"))

    def _record(self, us, src, dst, proto, l4, outbound, ident):
        ip = dpkt.ip.IP(src=src, dst=dst, p=proto, id=ident & 0xFFFF, df=1, ttl=128 if outbound else 64, data=l4)
        eth = dpkt.ethernet.Ethernet(src=_GUEST_MAC if outbound else _GATEWAY_MAC,
                                     dst=_GATEWAY_MAC if outbound else _GUEST_MAC,
                                     type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        frame = bytes(eth)
        sec, usec = divmod(us, 1000000)
        return bytes(dpkt.pcap.LEPktHdr(tv_sec=sec, tv_usec=usec, caplen=len(frame), len=len(frame))) + frame

    def _end(self, outbound, remote):
        return (self._guest, remote) if outbound else (remote, self._guest)

    def _udp_frame(self, us, remote, dport, sport, payload, outbound):
        src, dst = self._end(outbound, remote)
        l4 = dpkt.udp.UDP(sport=sport if outbound else dport, dport=dport if outbound else sport, data=payload)
        return self._record(us, src, dst, dpkt.ip.IP_PROTO_UDP, l4, outbound, us ^ sport)

    def _conversation(self, t0, remote, dport, sport, turns, use):
        """The packets of one TCP connection: handshake, the turns, close (the server closes first).

        Numbers: the client's first data byte is ``c + 1`` and the server's ``s + 1`` (the SYN takes one each); an
        acknowledgement is always the next byte expected from the other side, so the whole conversation is
        consistent whatever the segmentation and whoever spoke first. The first segment after a change of speaker
        carries the acknowledgement of everything the other side said. When the guest has the last word, the server
        acknowledges it before it closes.
        """
        SYN, ACK, PSH, FIN = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH, dpkt.tcp.TH_FIN
        c = self._isn(use, remote, dport, sport, "c")
        s = self._isn(use, remote, dport, sport, "s")
        frames = []
        clock = [t0]

        def send(step, outbound, flags, seq, ack, payload=b""):
            clock[0] += step
            src, dst = self._end(outbound, remote)
            l4 = dpkt.tcp.TCP(sport=sport if outbound else dport, dport=dport if outbound else sport, flags=flags,
                              seq=seq & _MASK32, ack=ack & _MASK32, win=_WINDOW, data=payload)
            frames.append(self._record(clock[0], src, dst, dpkt.ip.IP_PROTO_TCP, l4, outbound, c + len(frames)))

        send(0, True, SYN, c, 0)
        send(_RTT, False, SYN | ACK, s, c + 1)
        send(_RTT, True, ACK, c + 1, s + 1)
        sent, got = c + 1, s + 1        # the next byte each side will send
        speaker = None
        step = _RTT
        for direction, data in turns:
            if direction != speaker and speaker is not None:
                step = _THINK
            speaker = direction
            for at in range(0, len(data), MSS):
                chunk = data[at:at + MSS]
                if direction == "c":
                    send(step, True, ACK | PSH, sent, got, chunk)
                    sent += len(chunk)
                else:
                    send(step, False, ACK | PSH, got, sent, chunk)
                    got += len(chunk)
                step = _SEGMENT
        if speaker == "c":
            send(_THINK, False, ACK, got, sent)
        send(_RTT, False, FIN | ACK, got, sent)
        send(_RTT, True, FIN | ACK, sent, got + 1)
        send(_RTT, False, ACK, got + 1, sent + 1)
        return frames


class SessionContext:
    """What every server of a session is given: a holder of attributes, with no behaviour of its own.

    ``diverter`` hands out the address of a faked name and takes it back, ``ca`` signs a certificate per name,
    ``writer`` is the ``CaptureWriter``, ``ops`` the machine's ``SystemOps``, ``recorder`` collects the events of
    the session, ``passthrough`` lists the hosts that are not faked (a fresh list for each context),
    ``mode`` is ``"isolated"`` or ``"isolated+passthrough"`` and ``guest_ip`` the detonation machine's address.
    The servers only read it; the runner builds it.
    """

    def __init__(self, diverter=None, ca=None, writer=None, ops=None, recorder=None, passthrough=None,
                 mode="isolated", guest_ip=""):
        self.diverter = diverter
        self.ca = ca
        self.writer = writer
        self.ops = ops
        self.recorder = recorder
        self.passthrough = list(passthrough) if passthrough is not None else []
        self.mode = mode
        self.guest_ip = guest_ip
