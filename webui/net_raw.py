"""Traffic no other parser could name, profiled into ``raw`` events.

A custom C2 protocol is a protocol nobody has a parser for, so what is left of
it is its shape: how its messages are framed, how random its bytes look and
whether something checks in on a rhythm. A later phase builds a fingerprint on
these values to recognise the same implant in another run, which makes a wrong
value worse than a missing one: a mislabelled framing groups unrelated implants
together. The assumptions this module refuses to make:

  * Every stream has a framing. Most do not show one. ``"unknown"`` is the
    answer unless the bytes prove a claim, and a stream that two detectors
    both fit is ``"unknown"`` too, since one of them is wrong.
      - ``length-prefixed``: a 2 or 4 byte length, big or little endian, read
        again and again must walk the stream to its exact end. A zero length, a
        length that runs past the end, a chain that stops inside a message and
        a single message are all not framing, and the readings that fit must
        agree on the messages. The prefix is not counted in ``message_sizes``.
      - ``delimited``: the byte that ends the stream (or CRLF) must also split
        it into at least three messages of a byte or more on average. Text lines
        (``\\n``, ``\\r\\n``) need a mostly printable stream; any other byte
        needs six occurrences, must be the commonest non-printable byte and
        eight times as frequent as a byte of random data is, because random
        data ends in a control byte most of the time and has every byte in it
        somewhere. Short random data still gets there now and then, so this
        reduces false claims rather than excluding them.
      - ``fixed``: at least three equal sends that make up the whole stream.
  * A TCP segment is a message. It is not: Nagle joins sends and the MSS cuts
    them, so equal segments near the MSS say nothing about records (``fixed`` is
    only claimed up to ``MAX_FIXED_SIZE``) and a stream's boundaries are only
    reported when a framing proved them. A UDP datagram is a message, so for
    UDP its size is reported as it is.
  * A length read from a capture can be trusted. It is attacker-controlled: it
    is checked against the bytes that are there before it is used, a chain is
    walked for at most ``MAX_CHAIN`` messages (every turn consumes at least
    three bytes), the size list in the event is cut at ``MAX_REPORTED``
    (``message_count`` is the number seen, a lower bound once ``MAX_CHAIN``
    is reached) and entropy and printability are taken from the first
    ``MAX_PROFILE_BYTES`` of the stream.
  * Entropy tells the protocol apart from another one. It also depends on how
    much there is: 20 random bytes cannot reach 4.4 bits. ``stream_bytes`` is
    reported next to it. It is Shannon entropy over the byte frequencies, bits
    per byte, 8.0 at most.
  * Regular traffic is a heartbeat. The rhythm is measured as the project does
    in ``memory_evidence.beaconing_from_connections``, with its constants (four
    beats at least, robust coefficient of variation up to 0.5 from median and
    median absolute deviation, half the intervals within 25% of the median), so
    both feed one evidence model that decides alike. The unit differs: a
    connection is one event but a send can be several segments, so packets
    less than ``BEACON_MIN_INTERVAL_S`` apart are one beat, timed at its first
    packet. A beat is small (``MAX_HEARTBEAT_SIZE``): regular large sends are a
    transfer, not a keep-alive. Times come from ``Flow.packets``, which holds
    one entry per message with retransmissions folded in, so a retransmit is
    not a beat.
  * A delimiter is a byte string. It is reported as text, written by
    ``net_events.render_bytes``, as DNS names are (a printable byte as itself, any other as ``\\DDD`` with
    its decimal value: newline is ``\\010``), so an event is plain JSON. Every
    other field is a string, number, bool, None or a list of numbers.
  * The two directions look alike. A request and its reply do not, so each
    direction with data is profiled separately (``direction`` "c" or "s", the
    client's first) and ``client_guessed`` is carried over from the flow.

A flow is profiled whatever protocol it carries: which flows are unknown is for
the caller to decide. Nothing from a capture is executed or opened as a file.
"""

import statistics
from collections import Counter
from math import log2

from memory_evidence import (
    BEACON_MAX_COV, BEACON_MIN_CONNECTIONS, BEACON_MIN_INTERVAL_S)
from net_events import NetEvent, render_bytes

MAX_CHAIN = 20000               # messages walked in a length chain
MAX_REPORTED = 256              # sizes listed in an event
MAX_PROFILE_BYTES = 256 * 1024  # bytes entropy and printability are taken from
MAX_FIXED_SIZE = 1024           # larger equal TCP segments are the MSS, not records
MAX_HEARTBEAT_SIZE = 512        # a beat larger than this is a transfer

MIN_PREFIXED = 2                # a chain that fits is hard to get by chance
MIN_MESSAGES = 3                # delimited and fixed have nothing but repetition
MIN_TEXT_RATIO = 0.85           # printable share for a text delimiter
MIN_BINARY_DELIMITERS = 6       # a control byte turns up by chance in short random data
RANDOM_DELIMITER_FACTOR = 8     # times the count a byte of random data would have
ON_RHYTHM_SHARE = 0.5           # same as beaconing_from_connections

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_LENGTH_READINGS = ((2, "big"), (2, "little"), (4, "big"), (4, "little"))


# --- the byte profile ---------------------------------------------------------

def _entropy(counts, total):
    return -sum(n / total * log2(n / total) for n in counts.values())


def _printable_ratio(counts, total):
    return sum(n for byte, n in counts.items() if byte in _PRINTABLE) / total


# --- framing ------------------------------------------------------------------

def _length_chain(stream, width, byteorder):
    """The message sizes of a clean length chain, or None.

    Clean means every length is at least 1 and fits what remains, and the last
    message ends exactly at the end of the stream (or ``MAX_CHAIN`` messages
    have all been consistent).
    """
    pos, total = 0, len(stream)
    sizes = []
    for _ in range(MAX_CHAIN):
        if pos == total:
            break
        end = pos + width
        if end > total:
            return None
        size = int.from_bytes(stream[pos:end], byteorder)
        if size == 0 or size > total - end:
            return None
        sizes.append(size)
        pos = end + size
    return sizes if len(sizes) >= MIN_PREFIXED else None


def _length_prefixed(stream):
    """``(sizes, count)`` when the readings that fit agree on the messages, else None.

    Two readings that cut the stream into different messages cannot both be
    right. Readings that only differ in byte order and give the same sizes (a
    palindromic prefix such as ``01 01``) say the same thing, so they are fine.
    """
    fits = {tuple(sizes) for sizes in (_length_chain(stream, w, o) for w, o in _LENGTH_READINGS)
            if sizes is not None}
    if len(fits) != 1:
        return None
    sizes = fits.pop()
    return list(sizes[:MAX_REPORTED]), len(sizes)


def _delimiter_of(stream, counts, window):
    """The delimiter the stream ends with, or None when it does not prove one."""
    if len(stream) < 2:
        return None
    last = stream[-1]
    if stream.endswith(b"\r\n") and stream.count(b"\n") == stream.count(b"\r\n"):
        delimiter = b"\r\n"
    elif last == 0x0A:
        delimiter = b"\n"
    elif last not in _PRINTABLE:
        delimiter = bytes([last])
    else:
        return None
    found = stream.count(delimiter)
    # messages average at least a byte: a run of delimiters is padding
    if found < MIN_MESSAGES or len(stream) - found * len(delimiter) < found:
        return None
    if delimiter in (b"\r\n", b"\n"):
        return delimiter if _printable_ratio(counts, window) >= MIN_TEXT_RATIO else None
    seen = counts.get(last, 0)
    if found < MIN_BINARY_DELIMITERS or seen < RANDOM_DELIMITER_FACTOR * window / 256:
        return None
    if any(n > seen for byte, n in counts.items() if byte not in _PRINTABLE):
        return None
    return delimiter


def _delimited(stream, counts, window):
    """``(delimiter, sizes, count)``, or None."""
    delimiter = _delimiter_of(stream, counts, window)
    if delimiter is None:
        return None
    sizes = []
    pos = 0
    while len(sizes) < MAX_REPORTED:
        found = stream.find(delimiter, pos)
        if found < 0:
            break
        sizes.append(found - pos)
        pos = found + len(delimiter)
    return delimiter, sizes, stream.count(delimiter)


def _send_sizes(flow, direction):
    return [len(payload) for _ts, d, payload in flow.packets if d == direction and payload]


def _fixed(flow, direction, stream):
    sizes = _send_sizes(flow, direction)
    if len(sizes) < MIN_MESSAGES or len(set(sizes)) != 1 or sum(sizes) != len(stream):
        return None
    if flow.proto == "tcp" and sizes[0] > MAX_FIXED_SIZE:
        return None
    return sizes


def _framing(flow, direction, stream, counts, window):
    """``(framing, delimiter, message_sizes, message_count)``."""
    if flow.proto == "udp":
        sizes = _send_sizes(flow, direction)
        framing = "fixed" if _fixed(flow, direction, stream) else "unknown"
        return framing, None, sizes[:MAX_REPORTED], len(sizes)
    prefixed = _length_prefixed(stream)
    delimited = _delimited(stream, counts, window)
    if prefixed and delimited:
        return "unknown", None, [], 0
    if prefixed:
        return "length-prefixed", None, prefixed[0], prefixed[1]
    if delimited:
        return "delimited", delimited[0], delimited[1], delimited[2]
    sizes = _fixed(flow, direction, stream)
    if sizes:
        return "fixed", None, sizes[:MAX_REPORTED], len(sizes)
    return "unknown", None, [], 0


# --- rhythm -------------------------------------------------------------------

def _beats(flow, direction):
    """``(start_time, bytes)`` per send; packets closer than the burst gap are one."""
    sends = sorted((ts, len(payload)) for ts, d, payload in flow.packets
                   if d == direction and payload)
    beats = []
    previous = None
    for ts, size in sends:
        if previous is not None and ts - previous < BEACON_MIN_INTERVAL_S:
            beats[-1][1] += size
        else:
            beats.append([ts, size])
        previous = ts
    return beats


def _heartbeat(flow, direction):
    """``(is_heartbeat, median_interval)``; the interval is None unless it is one."""
    beats = _beats(flow, direction)
    if len(beats) < BEACON_MIN_CONNECTIONS:
        return False, None
    intervals = [b[0] - a[0] for a, b in zip(beats, beats[1:])]
    median = statistics.median(intervals)
    if median <= 0:
        return False, None
    mad = statistics.median(abs(x - median) for x in intervals)
    # 1.4826 * MAD estimates the standard deviation for normal data.
    robust_cov = 1.4826 * mad / median
    on_rhythm = sum(1 for x in intervals if abs(x - median) <= 0.25 * median) / len(intervals)
    if robust_cov > BEACON_MAX_COV or on_rhythm < ON_RHYTHM_SHARE:
        return False, None
    if statistics.median(size for _ts, size in beats) > MAX_HEARTBEAT_SIZE:
        return False, None
    return True, round(median, 2)


# --- events -------------------------------------------------------------------

def _written(delimiter):
    """The delimiter as text, by ``net_events.render_bytes``.

    A printable byte stands for itself and any other is ``\\DDD`` (decimal), so a
    newline is ``\\010`` and CRLF ``\\013\\010``. The event has to go through
    ``json.dumps`` (report, API), which refuses ``bytes``; one escaping style
    for the whole project keeps the output readable and reversible.
    """
    return None if delimiter is None else render_bytes(delimiter)


def _event(flow, direction, stream):
    window = stream[:MAX_PROFILE_BYTES]
    counts = Counter(window)
    framing, delimiter, sizes, count = _framing(flow, direction, stream, counts, len(window))
    heartbeat, interval = _heartbeat(flow, direction)
    first = min((ts for ts, d, payload in flow.packets if d == direction and payload),
                default=flow.first_ts)
    return NetEvent(
        "raw", first, dest=flow.dst, port=flow.dport, proto=flow.proto, direction=direction,
        framing=framing, delimiter=_written(delimiter), message_sizes=sizes, message_count=count,
        entropy=round(_entropy(counts, len(window)), 4),
        printable_ratio=round(_printable_ratio(counts, len(window)), 4),
        heartbeat=heartbeat, interval=interval, stream_bytes=len(stream),
        stream_gaps=list(flow.gaps), stream_capped=bool(flow.capped),
        client_guessed=bool(flow.client_guessed))


def events_from_flow(flow):
    """A ``raw`` event for each direction of the flow that has stream data.

    The client's direction comes first. A direction whose stream is empty gives
    no event, so a flow without payload gives an empty list.
    """
    events = []
    for direction, stream in (("c", flow.client_stream()), ("s", flow.server_stream())):
        if stream:
            events.append(_event(flow, direction, stream))
    return events
