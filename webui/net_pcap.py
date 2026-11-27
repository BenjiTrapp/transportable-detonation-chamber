"""The capture of a detonation: what the fake servers served, written as a pcap the analysis already knows how to read.

The seam between the two halves of the fake internet is this file. The servers (DNS, HTTP, TLS, the raw protocols)
answer a sample and record what they said; ``CaptureWriter`` turns each recording into the packets such a
conversation would have been, and ``net_analyze.analyze_pcap`` reads them back as it reads any capture. Nothing behind
that function has to know that the answers came from us, which is the point: a second path in the parsers for "traffic
we faked" would be a second thing to keep right in thirteen modules.

What the reader needs, and so what is written (``net_flows`` is the reader):

  * One TCP exchange is a whole conversation: handshake, request, response, close. A flow without a SYN is a flow whose
    client the reader has to guess, and one without a close ends in a gap the reader reports.
  * Sequence numbers advance with the payload. Reassembly is driven by them and by nothing else, so a request cut into
    segments carries numbers that add up, the acknowledgement of a side is the other side's next byte, and a FIN
    carries the number just past the last byte. A payload is cut into segments of ``MSS`` bytes: no frame is larger
    than a real network would carry, and the reader's own retention (per segment) is spent the way it is on a real
    capture.
  * A source port used again is a new connection. The two have different initial sequence numbers, which is how the
    reader tells them apart, so each conversation draws its own (from a generator with a fixed seed: the same session
    writes the same capture).
  * Timestamps are Unix seconds as floats, the convention of ``net_events``. The time of an exchange is the moment the
    guest began the connection; its packets follow within milliseconds, a segment every 100 microseconds. A time that
    is not a finite number cannot be written (the analysis ignores such an event) and is refused.

What a session needs of the writer, which is more than writing:

  * It never raises into a server because of the *file*. A full disk or a closed writer is a counted drop
    (``dropped``, ``error``), because a capture is never a reason for the sample not to be answered. What is raised is a
    call that is wrong (an address that is not IPv4, a port out of range, text instead of bytes): that is a bug in the
    caller, and writing something plausible instead would hide it.
  * Every exchange is written in one piece under a lock, and flushed. Servers run on threads, and a session can be
    stopped, or the process killed, between two exchanges; the file is then what was complete when it happened. An
    exchange that never finished is not in the file at all (the servers record one when the answer is out), so a
    capture "cut in the middle of an exchange" is a capture that ends before it. A file cut inside a packet (a killed
    process, a copy that was interrupted) is read by ``net_flows`` as far as it goes.
  * It is bounded by what the reader keeps. A direction of one exchange is cut at ``MAX_STREAM_BYTES`` (the reader
    would drop the rest and say so; here it is not written, and ``truncated`` counts it), and once the payload of the
    whole capture has reached ``MAX_TOTAL_BYTES`` the rest is dropped and counted. Both are the reader's own limits,
    imported so that they cannot drift apart.

``SessionContext`` is the one object every server is given. It is only an attribute holder; the runner builds it.
"""

import math
import random
import socket
import struct
import threading

import dpkt

from net_flows import MAX_STREAM_BYTES, MAX_TOTAL_BYTES

MSS = 1460
MAX_DATAGRAM = 65507            # what fits in a UDP datagram inside an IPv4 packet

_GUEST_MAC = b"\x52\x54\x00\x12\x34\x56"
_GATEWAY_MAC = b"\x52\x54\x00\x65\x43\x21"
_WINDOW = 64240
_MASK32 = 0xFFFFFFFF

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


class CaptureWriter:
    """Writes the traffic the fake servers served as a classic pcap (Ethernet, IPv4, TCP and UDP).

    ``guest_ip`` is the address of the detonation machine; every conversation is between it and a remote address.
    ``dest`` is that remote address (an IPv4 string), ``dport`` its port and ``sport`` the guest's.

    Counters, for the session log: ``exchanges`` and ``datagrams`` written (a UDP exchange counts its two datagrams),
    ``packets`` and ``payload_bytes`` written, ``truncated`` payloads cut at ``MAX_STREAM_BYTES``, ``dropped`` calls
    that wrote nothing (the writer was closed, the budget was spent, the file failed). ``error`` is the reason the
    file failed, or empty.
    """

    def __init__(self, path, guest_ip):
        self.path = path
        self.guest_ip = guest_ip
        self._guest = _address(guest_ip, "guest_ip")
        self.exchanges = 0
        self.datagrams = 0
        self.packets = 0
        self.payload_bytes = 0
        self.truncated = 0
        self.dropped = 0
        self.error = ""
        self._ident = 0
        self._rng = random.Random(0x7DC)
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

        ``ts`` is when the guest began the connection. For ``proto="tcp"`` the conversation is a handshake, the
        request, the response and a close; for ``"udp"`` a datagram each way. Either payload may be empty.
        """
        if proto not in ("tcp", "udp"):
            raise ValueError("proto must be 'tcp' or 'udp', not %r" % (proto,))
        remote = _address(dest, "dest")
        _port(dport, "dport")
        _port(sport, "sport")
        t0 = _micros(ts)
        request = _bytes(request, "request")
        response = _bytes(response, "response")
        if proto == "udp":
            for payload in (request, response):
                if len(payload) > MAX_DATAGRAM:
                    raise ValueError("a datagram holds at most %d bytes, not %d" % (MAX_DATAGRAM, len(payload)))
        cut = 0
        if len(request) > MAX_STREAM_BYTES:
            request, cut = request[:MAX_STREAM_BYTES], cut + 1
        if len(response) > MAX_STREAM_BYTES:
            response, cut = response[:MAX_STREAM_BYTES], cut + 1
        if proto == "tcp":
            frames = self._conversation(t0, remote, dport, sport, request, response)
        else:
            frames = [self._udp(t0, remote, dport, sport, request, True)]
            frames.append(self._udp(t0 + _THINK, remote, dport, sport, response, False))
        written = self._write(frames, len(request) + len(response), cut)
        if written:
            with self._lock:
                self.exchanges += 1
                if proto == "udp":
                    self.datagrams += 2
        return written

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
        written = self._write([self._udp(t0, remote, dport, sport, payload, not inbound)], len(payload), 0)
        if written:
            with self._lock:
                self.datagrams += 1
        return written

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

    # --- writing -------------------------------------------------------------------------------------------------

    def _write(self, frames, payload, cut):
        blob = b"".join(frames)
        with self._lock:
            if self._closed or self.error or self.payload_bytes + payload > MAX_TOTAL_BYTES:
                self.dropped += 1
                return False
            try:
                self._out.write(blob)
                self._out.flush()
            except OSError as exc:
                self._fail(exc)
                self.dropped += 1
                return False
            self.packets += len(frames)
            self.payload_bytes += payload
            self.truncated += cut
            return True

    def _fail(self, exc):
        if not self.error:
            self.error = str(exc) or exc.__class__.__name__

    # --- building packets ----------------------------------------------------------------------------------------

    def _isn(self):
        return self._rng.getrandbits(32)

    def _next_ident(self):
        self._ident = (self._ident + 1) & 0xFFFF
        return self._ident

    def _record(self, us, src, dst, proto, l4, outbound):
        ip = dpkt.ip.IP(src=src, dst=dst, p=proto, id=self._next_ident(), df=1, ttl=128 if outbound else 64,
                        data=l4)
        eth = dpkt.ethernet.Ethernet(src=_GUEST_MAC if outbound else _GATEWAY_MAC,
                                     dst=_GATEWAY_MAC if outbound else _GUEST_MAC,
                                     type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        frame = bytes(eth)
        sec, usec = divmod(us, 1000000)
        return bytes(dpkt.pcap.LEPktHdr(tv_sec=sec, tv_usec=usec, caplen=len(frame), len=len(frame))) + frame

    def _end(self, outbound, remote):
        return (self._guest, remote) if outbound else (remote, self._guest)

    def _udp(self, us, remote, dport, sport, payload, outbound):
        src, dst = self._end(outbound, remote)
        l4 = dpkt.udp.UDP(sport=sport if outbound else dport, dport=dport if outbound else sport, data=payload)
        return self._record(us, src, dst, dpkt.ip.IP_PROTO_UDP, l4, outbound)

    def _segment(self, us, remote, dport, sport, outbound, flags, seq, ack, payload=b""):
        src, dst = self._end(outbound, remote)
        l4 = dpkt.tcp.TCP(sport=sport if outbound else dport, dport=dport if outbound else sport, flags=flags,
                          seq=seq & _MASK32, ack=ack & _MASK32, win=_WINDOW, data=payload)
        return self._record(us, src, dst, dpkt.ip.IP_PROTO_TCP, l4, outbound)

    def _conversation(self, t0, remote, dport, sport, request, response):
        """The packets of one TCP connection: handshake, request, response, close (the server closes first).

        Numbers: the client's first data byte is ``c + 1`` and the server's ``s + 1`` (the SYN takes one each); an
        acknowledgement is always the next byte expected from the other side, so the whole conversation is
        consistent whatever the segmentation.
        """
        SYN, ACK, PSH, FIN = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH, dpkt.tcp.TH_FIN
        c, s = self._isn(), self._isn()
        frames = []
        clock = [t0]

        def send(step, outbound, flags, seq, ack, payload=b""):
            clock[0] += step
            frames.append(self._segment(clock[0], remote, dport, sport, outbound, flags, seq, ack, payload))

        send(0, True, SYN, c, 0)
        send(_RTT, False, SYN | ACK, s, c + 1)
        send(_RTT, True, ACK, c + 1, s + 1)
        sent = c + 1
        step = _RTT
        for at in range(0, len(request), MSS):
            chunk = request[at:at + MSS]
            send(step, True, ACK | PSH, sent, s + 1, chunk)
            sent += len(chunk)
            step = _SEGMENT
        got = s + 1
        step = _THINK if request else _RTT
        if response:
            for at in range(0, len(response), MSS):
                chunk = response[at:at + MSS]
                send(step, False, ACK | PSH, got, sent, chunk)
                got += len(chunk)
                step = _SEGMENT
        elif request:
            send(step, False, ACK, got, sent)
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
