"""TLS handshakes to ``tls`` events, with JA3 and JA4 fingerprints.

Regressions covered:
  * a ClientHello from a capture is routinely incomplete (a lost segment, a
    capture that ended, a hello spread over several TLS records) and a parser
    written for whole input raised on it; a cut or inconsistent hello gives no
    event, and never a fingerprint of half a hello that would put one client
    into two database entries
  * every length in the hello comes from an untrusted file; a record or
    handshake that claims megabytes, a cipher list or extension longer than
    the bytes there, an odd cipher list, a chain of empty records and random
    damage to a valid hello are each contained (no exception, no read past the
    data, no unbounded loop)
  * GREASE values sit at random places in a modern client's lists, so a
    fingerprint that kept them changed at every run; JA3, JA4 and the reported
    ``ciphers`` / ``extensions`` do not contain them
  * the hello split over several records or TCP segments was read as only its
    first piece, giving another fingerprint for the same client
  * a JA4 that does not match the published one is useless for comparing with
    anything outside this project; the Chrome example of the specification is
    reproduced exactly (cipher hash, extension and signature hash, ALPN code)
  * a missing, cut or unreadable server certificate (common: chains in
    captures are incomplete; TLS 1.3 encrypts it) dropped the event or raised;
    the event stays and the certificate fields are empty
  * only the leaf of a chain is the server's certificate, so a chain's CA is
    not reported as the subject
  * a connection to a bare IP, or without SNI, had an empty ``dest``
  * a capture that begins with the server's flight made the server the
    client, so ``dest`` was the client's address and the hello was not found
  * the event took the flow's first time (the SYN) instead of the hello's
  * a second ClientHello after a HelloRetryRequest produced a second event
  * a flow that is not TLS (HTTP, UDP) produced an event
  * a hello cut after its server name (a lost segment, the end of the capture)
    dropped the event and with it the name, which is the one indicator left
    when the client refuses our certificate; the event is kept with ``sni``
    and ``dest`` and ``hello_incomplete``, and its fingerprint fields are
    empty because a fingerprint of half a hello would split one client over
    several database entries
  * a hello cut before its server name is readable, or inconsistent rather
    than cut, still gives no event
"""

import datetime
import hashlib
import os
import random
import socket
import tempfile

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import net_flows
import net_tls

CLIENT = "192.0.2.10"
SERVER = "198.51.100.7"
CPORT = 49152
SPORT = 443

_SYN, _ACK, _PSH = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH

CHROME_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                  0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
CHROME_SIGNATURES = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


# --- building bytes -----------------------------------------------------------

def _u(value, size):
    return value.to_bytes(size, "big")


def _ext(kind, data=b""):
    return _u(kind, 2) + _u(len(data), 2) + data


def _list16(values):
    body = b"".join(_u(v, 2) for v in values)
    return _u(len(body), 2) + body


def _sni_ext(name):
    raw = name.encode()
    entry = b"\x00" + _u(len(raw), 2) + raw
    return _ext(0, _u(len(entry), 2) + entry)


def _alpn_ext(protocols):
    body = b"".join(_u(len(p), 1) + p for p in protocols)
    return _ext(16, _u(len(body), 2) + body)


def _hello(sni="a.top", ciphers=(0x1301, 0x1302), exts=None, version=0x0303, session=b""):
    """A ClientHello handshake message; ``exts`` replaces the default extensions."""
    if exts is None:
        exts = []
        if sni is not None:
            exts.append(_sni_ext(sni))
        exts += [_ext(10, _list16([29, 23])), _ext(11, b"\x01\x00"), _ext(43, b"\x02\x03\x04")]
    block = b"".join(exts)
    body = (_u(version, 2) + bytes(range(32)) + _u(len(session), 1) + session
            + _list16(ciphers) + b"\x01\x00" + _u(len(block), 2) + block)
    return b"\x01" + _u(len(body), 3) + body


def _records(handshake, split=None, version=0x0301):
    """TLS handshake records around ``handshake``; ``split`` bytes per record."""
    step = split or max(len(handshake), 1)
    out = b""
    for i in range(0, max(len(handshake), 1), step):
        part = handshake[i:i + step]
        out += b"\x16" + _u(version, 2) + _u(len(part), 2) + part
    return out


def _message(kind, body=b""):
    return _u(kind, 1) + _u(len(body), 3) + body


def _name(text):
    return x509.Name.from_rfc4514_string(text)


_KEYS = {}


def _key(label):
    if label not in _KEYS:
        _KEYS[label] = ec.generate_private_key(ec.SECP256R1())
    return _KEYS[label]


def _cert_der(subject, issuer):
    """A certificate for ``subject`` signed by ``issuer`` (itself when they are equal)."""
    own = _key(subject)
    signer = own if subject == issuer else _key(issuer)
    built = (x509.CertificateBuilder()
             .subject_name(_name(subject)).issuer_name(_name(issuer))
             .public_key(own.public_key()).serial_number(7)
             .not_valid_before(datetime.datetime(2020, 1, 1))
             .not_valid_after(datetime.datetime(2030, 1, 2, 3, 4, 5))
             .sign(signer, hashes.SHA256()))
    return built.public_bytes(serialization.Encoding.DER)


def _server_flight(chain, split=None):
    """ServerHello, Certificate and ServerHelloDone (the TLS 1.2 flight)."""
    hello = _message(2, _u(0x0303, 2) + bytes(32) + b"\x00" + _u(0xc02f, 2) + b"\x00")
    parts = hello
    if chain is not None:
        entries = b"".join(_u(len(d), 3) + d for d in chain)
        parts += _message(11, _u(len(entries), 3) + entries)
    parts += _message(14)
    return _records(parts, split=split, version=0x0303)


def _tls13_flight():
    hello = _message(2, _u(0x0303, 2) + bytes(32) + b"\x00" + _u(0x1301, 2) + b"\x00")
    return (_records(hello, version=0x0303) + b"\x14\x03\x03\x00\x01\x01"
            + b"\x17\x03\x03\x00\x20" + bytes(32))


# --- building flows -----------------------------------------------------------

def _frame(src, sport, dst, dport, seq, ack, flags, payload=b""):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF,
                       ack=ack & 0xFFFFFFFF, flags=flags, win=8192, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=seg)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _flow_from(segments, syn=True, drop=(), segment=60000):
    """Write the segments to a pcap, read it back, return the single flow.

    ``segments`` is a list of ``(ts, "c" | "s", payload)``; a payload longer
    than ``segment`` is sent as several TCP segments. ``drop`` lists indices of
    the written TCP data segments that are never captured (their sequence
    space is still used, which leaves a hole); ``syn=False`` is a capture that
    begins mid-connection. The parser is fed what the real reader produces.
    """
    ends = {"c": (CLIENT, CPORT, SERVER, SPORT), "s": (SERVER, SPORT, CLIENT, CPORT)}
    isn = {"c": 1000, "s": 5000}
    nxt = {"c": isn["c"] + 1, "s": isn["s"] + 1}
    data = []
    for ts, direction, payload in segments:
        other = "s" if direction == "c" else "c"
        for i in range(0, len(payload), segment):
            part = payload[i:i + segment]
            data.append((ts, _frame(*ends[direction], nxt[direction], nxt[other],
                                    _ACK | _PSH, part)))
            nxt[direction] += len(part)
    packets = []
    if syn:
        t0 = min(ts for ts, _d, _p in segments) - 1.0
        packets += [
            (t0, _frame(*ends["c"], isn["c"], 0, _SYN)),
            (t0 + 0.1, _frame(*ends["s"], isn["s"], isn["c"] + 1, _SYN | _ACK)),
            (t0 + 0.2, _frame(*ends["c"], isn["c"] + 1, isn["s"] + 1, _ACK)),
        ]
    packets += [p for i, p in enumerate(data) if i not in drop]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "tls.pcap")
        with open(path, "wb") as fh:
            w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
            for ts, buf in packets:
                w.writepkt(buf, ts)
        result = net_flows.read_pcap(path)
    assert len(result.flows) == 1, result.note
    return result.flows[0]


def _tls_flow(sni="a.top", ciphers=(0x1301, 0x1302), cert=None, truncate=None,
              split=None, segment=60000, drop=(), hello=None, flight=None, **kw):
    """A flow holding a ClientHello and, with ``cert=(subject, issuer)``, the server's flight."""
    client = _records(hello if hello is not None else _hello(sni=sni, ciphers=ciphers),
                      split=split)
    if truncate is not None:
        client = client[:truncate]
    if flight is None:
        flight = _server_flight([_cert_der(*cert)]) if cert else b""
    segments = [(10.0, "c", client)]
    if flight:
        segments.append((10.5, "s", flight))
    return _flow_from(segments, segment=segment, drop=drop, **kw)


def _chrome_hello():
    """The ClientHello of the JA4 specification's Chrome example, GREASE included."""
    exts = [
        _ext(0x0a0a), _sni_ext("example.com"), _ext(0xff01, b"\x00"), _ext(10, _list16([0x2a2a, 29, 23, 24])),
        _ext(11, b"\x01\x00"), _ext(35), _alpn_ext([b"h2", b"http/1.1"]), _ext(5, b"\x01\x00\x00\x00\x00"),
        _ext(13, _list16(CHROME_SIGNATURES)), _ext(18), _ext(51, b"\x00\x00"), _ext(45, b"\x01\x01"),
        _ext(43, b"\x06\x1a\x1a\x03\x04\x03\x03"), _ext(27, b"\x02\x00\x02"), _ext(0x4469, b"\x00"),
        _ext(23), _ext(21, b"\x00" * 4), _ext(0x1a1a, b"\x00"),
    ]
    return _hello(ciphers=[0x5a5a] + CHROME_CIPHERS, exts=exts)


def _one(flow):
    events = net_tls.events_from_flow(flow)
    assert len(events) == 1
    return events[0]


# --- the contract from the brief ----------------------------------------------

def test_the_server_name_is_read_from_the_client_hello():
    e = net_tls.events_from_flow(_tls_flow(sni="steamcommunity.com"))[0]
    assert e["type"] == "tls" and e["sni"] == "steamcommunity.com"
    assert e["dest"] == "steamcommunity.com" and e["port"] == 443
    assert e["dest_is_ip"] is False and e["in_tree"] is False


def test_a_server_name_keeps_its_bytes_for_the_caller_to_render():
    raw = b"Caf\xe9\x00\n.top"
    entry = b"\x00" + _u(len(raw), 2) + raw
    hello = net_tls.parse_client_hello(_records(_hello(exts=[_ext(0, _u(len(entry), 2) + entry)])))
    assert hello.sni.encode("ascii", "surrogateescape") == raw.lower()


def test_ja3_is_stable_for_the_same_hello():
    f = _tls_flow(sni="a.top")
    assert net_tls.events_from_flow(f)[0]["ja3_hash"] == net_tls.events_from_flow(f)[0]["ja3_hash"]
    again = net_tls.events_from_flow(_tls_flow(sni="a.top"))[0]
    assert again["ja3_hash"] == net_tls.events_from_flow(f)[0]["ja3_hash"]


def test_ja3_differs_when_the_cipher_list_differs():
    a = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1301, 0x1302]))[0]
    b = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1302, 0x1301]))[0]
    assert a["ja3_hash"] != b["ja3_hash"]


def test_grease_values_do_not_change_ja3():
    plain = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1301]))[0]
    greased = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x0a0a, 0x1301]))[0]
    assert plain["ja3_hash"] == greased["ja3_hash"]
    assert greased["ciphers"] == [0x1301]


def test_ja4_reports_sni_presence_and_counts():
    e = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1301, 0x1302]))[0]
    assert e["ja4"].startswith("t") and "d" in e["ja4"][:5]
    assert e["ja4"].startswith("t13d0204")      # TLS 1.3, SNI, 2 ciphers, 4 extensions


def test_a_self_signed_certificate_is_flagged():
    e = net_tls.events_from_flow(_tls_flow(sni="a.top", cert=("CN=a.top", "CN=a.top")))[0]
    assert e["self_signed"] is True


def test_a_hello_that_is_cut_short_does_not_raise():
    assert net_tls.events_from_flow(_tls_flow(sni="a.top", truncate=20)) == []


# --- the fingerprints ---------------------------------------------------------

def test_ja3_string_has_the_five_fields_in_order():
    e = _one(_tls_flow(sni="a.top", ciphers=[0x1301, 0x1302]))
    assert e["ja3"] == "771,4865-4866,0-10-11-43,29-23,0"
    assert e["ja3_hash"] == hashlib.md5(e["ja3"].encode()).hexdigest()


def test_grease_is_removed_from_every_ja3_list():
    hello = _hello(ciphers=[0xfafa, 0x1301], exts=[
        _ext(0x2a2a), _sni_ext("a.top"), _ext(10, _list16([0x0a0a, 29])), _ext(11, b"\x01\x00"),
        _ext(0xdada)])
    e = _one(_tls_flow(hello=hello))
    assert e["ja3"] == "771,4865,0-10-11,29,0"
    assert e["extensions"] == [0, 10, 11]


def test_grease_lookalikes_are_kept():
    # 0x0a1a and 0x1a0a are not GREASE: only equal bytes of the form 0x?a are
    assert net_tls.is_grease(0x0a0a) and net_tls.is_grease(0xfafa)
    assert not net_tls.is_grease(0x0a1a) and not net_tls.is_grease(0x1a0a)
    assert not net_tls.is_grease(0x0b0b) and not net_tls.is_grease(0x1301)


def test_ja4_of_the_specifications_chrome_example():
    e = _one(_tls_flow(hello=_chrome_hello()))
    assert e["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert e["version"] == "TLS 1.3" and e["alpn"] == ["h2", "http/1.1"]
    assert len(e["ciphers"]) == 15 and len(e["extensions"]) == 16


def test_ja4_does_not_depend_on_the_order_of_ciphers_and_extensions():
    a = _one(_tls_flow(sni="a.top", ciphers=[0x1301, 0x1302]))
    b = _one(_tls_flow(sni="a.top", ciphers=[0x1302, 0x1301]))
    assert a["ja4"] == b["ja4"] and a["ja3_hash"] != b["ja3_hash"]


def test_ja4_marks_a_hello_without_sni():
    e = _one(_tls_flow(sni=None))
    assert e["ja4"][3] == "i" and e["sni"] == ""


def test_ja4_alpn_code_uses_hex_for_non_alphanumeric_edges():
    assert net_tls._alpn_code([]) == "00"
    assert net_tls._alpn_code(["h2"]) == "h2"
    assert net_tls._alpn_code(["http/1.1"]) == "h1"
    assert net_tls._alpn_code(["\xab\xcd"]) == "ad"
    assert net_tls._alpn_code(["x"]) == "xx"


def test_ja4_of_a_hello_without_extensions_or_ciphers():
    hello = _hello(ciphers=[], exts=[])
    e = _one(_tls_flow(hello=hello))
    assert e["ja4"] == "t12i0000" + "00_000000000000_000000000000"
    assert e["ja3"] == "771,,,,"


def test_a_tls12_client_has_its_own_version():
    exts = [_sni_ext("a.top")]
    assert _one(_tls_flow(hello=_hello(exts=exts)))["version"] == "TLS 1.2"
    assert _one(_tls_flow(hello=_hello(exts=exts, version=0x0301)))["ja4"].startswith("t10d")


# --- parts of the hello -------------------------------------------------------

def test_a_hello_spread_over_records_and_segments_gives_the_same_fingerprint():
    whole = _one(_tls_flow(hello=_chrome_hello()))
    by_record = _one(_tls_flow(hello=_chrome_hello(), split=40))
    by_segment = _one(_tls_flow(hello=_chrome_hello(), split=40, segment=70))
    assert by_record["ja4"] == whole["ja4"] == by_segment["ja4"]
    assert by_record["ja3_hash"] == whole["ja3_hash"] == by_segment["ja3_hash"]


def test_a_hello_with_a_lost_segment_gives_no_event():
    # the stream ends at the hole, inside the hello
    assert net_tls.events_from_flow(_tls_flow(hello=_chrome_hello(), segment=100, drop=(1,))) == []


def test_the_name_is_lower_case_and_dest_follows_it():
    e = _one(_tls_flow(sni="Steam.Example.COM"))
    assert e["sni"] == "steam.example.com" and e["dest"] == "steam.example.com"


def test_without_sni_dest_is_the_server_address():
    e = _one(_tls_flow(sni=None))
    assert e["sni"] == "" and e["dest"] == SERVER and e["dest_is_ip"] is True


def test_an_empty_server_name_extension_falls_back_to_the_address():
    e = _one(_tls_flow(hello=_hello(exts=[_ext(0, b"\x00\x00")])))
    assert e["sni"] == "" and e["dest"] == SERVER
    assert e["ja4"][3] == "d"           # the extension is present, as JA4 defines it


def test_a_name_with_odd_bytes_is_kept_readable_and_bounded():
    odd = _one(_tls_flow(hello=_hello(exts=[_ext(0, _u(6 + 3, 2) + b"\x00" + _u(6, 2) + b"a\xffb\x00c\n")])))
    # raw here; net_analyze renders it (a\\255b\\000c\\010) as it renders DNS names
    assert odd["sni"] == "a\udcffb\x00c\n" and isinstance(odd["dest"], str)
    long_name = _one(_tls_flow(sni="a" * 5000))
    assert len(long_name["sni"]) == net_tls.MAX_NAME


def test_alpn_is_listed_in_order():
    exts = [_sni_ext("a.top"), _alpn_ext([b"h2", b"http/1.1"])]
    assert _one(_tls_flow(hello=_hello(exts=exts)))["alpn"] == ["h2", "http/1.1"]
    assert _one(_tls_flow(sni="a.top"))["alpn"] == []


def test_the_event_takes_the_time_of_the_hello():
    assert _one(_tls_flow(sni="a.top"))["ts"] == 10.0     # the SYN was at 9.0


def test_a_second_hello_after_a_retry_request_is_not_a_second_event():
    stream = _records(_hello(sni="a.top")) + _records(_hello(sni="b.top"))
    flow = _flow_from([(1.0, "c", stream)])
    events = net_tls.events_from_flow(flow)
    assert [e["sni"] for e in events] == ["a.top"]


def test_the_hello_is_found_when_the_capture_begins_with_the_server():
    flow = _flow_from([(1.0, "s", _server_flight([_cert_der("CN=a.top", "CN=a.top")])),
                       (2.0, "c", _records(_hello(sni="a.top")))], syn=False)
    assert flow.client_guessed and flow.src == SERVER
    e = _one(flow)
    assert e["sni"] == "a.top" and e["port"] == 443
    assert e["self_signed"] is True and e["cert_subject"] == "CN=a.top"
    flow = _flow_from([(1.0, "s", _server_flight(None)),
                       (2.0, "c", _records(_hello(sni=None)))], syn=False)
    assert _one(flow)["dest"] == SERVER


# --- certificates -------------------------------------------------------------

def test_the_certificate_fields_are_read():
    e = _one(_tls_flow(cert=("CN=a.top", "CN=Fake CA")))
    assert e["cert_subject"] == "CN=a.top" and e["cert_issuer"] == "CN=Fake CA"
    assert e["cert_not_after"] == "2030-01-02T03:04:05Z"
    assert e["self_signed"] is False


def test_only_the_leaf_of_a_chain_is_the_servers_certificate():
    chain = [_cert_der("CN=a.top", "CN=Mid CA"), _cert_der("CN=Mid CA", "CN=Mid CA")]
    e = _one(_tls_flow(flight=_server_flight(chain)))
    assert e["cert_subject"] == "CN=a.top" and e["self_signed"] is False


def test_a_certificate_spread_over_records_and_segments_is_read():
    flight = _server_flight([_cert_der("CN=a.top", "CN=a.top")], split=100)
    e = _one(_tls_flow(flight=flight, segment=150))
    assert e["self_signed"] is True and e["cert_subject"] == "CN=a.top"


def test_a_server_without_a_certificate_leaves_the_event_intact():
    for flight in (b"", _server_flight(None), _tls13_flight()):
        e = _one(_tls_flow(sni="a.top", flight=flight or None))
        assert e["sni"] == "a.top" and e["ja3_hash"]
        assert (e["cert_subject"], e["cert_issuer"], e["cert_not_after"]) == ("", "", "")
        assert e["self_signed"] is False


def test_a_damaged_certificate_leaves_the_event_intact():
    der = _cert_der("CN=a.top", "CN=a.top")
    for chain in ([b"not a certificate"], [der[:60]], [b"\x31" + der[1:]],
                  [b""], [bytes(range(256)) * 4]):
        e = _one(_tls_flow(flight=_server_flight(chain)))
        assert e["sni"] == "a.top" and e["cert_subject"] == ""
        assert e["self_signed"] is False


def test_a_certificate_cut_by_a_lost_segment_is_reported_as_missing_not_wrong():
    flight = _server_flight([_cert_der("CN=a.top", "CN=a.top")])
    flow = _tls_flow(flight=flight, segment=150, drop=(2,))
    e = _one(flow)
    assert e["cert_subject"] == "" and e["self_signed"] is False
    assert e["stream_gaps"] and e["stream_capped"] is False


def test_a_certificate_message_that_lies_about_its_length_is_contained():
    der = _cert_der("CN=a.top", "CN=a.top")
    lying = _message(11, _u(0xFFFFFF, 3) + _u(0xFFFFFF, 3) + der)
    flight = _records(_message(2, bytes(40)) + lying, version=0x0303)
    e = _one(_tls_flow(flight=flight))
    assert e["cert_subject"] == "" and e["sni"] == "a.top"


# --- things that are not TLS --------------------------------------------------

def test_a_flow_that_is_not_tls_gives_no_event():
    http = _flow_from([(1.0, "c", b"GET / HTTP/1.1\r\nHost: a.top\r\n\r\n"),
                       (2.0, "s", b"HTTP/1.1 200 OK\r\n\r\n")])
    assert net_tls.events_from_flow(http) == []
    assert net_tls.events_from_flow(_flow_from([(1.0, "s", b"x")])) == []


def test_a_udp_flow_gives_no_event():
    class Udp:
        proto = "udp"

    assert net_tls.events_from_flow(Udp()) == []


def test_other_handshake_messages_are_not_a_hello():
    server_hello = _records(_message(2, bytes(40)))
    assert net_tls.parse_client_hello(server_hello) is None
    assert net_tls.parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None
    assert net_tls.parse_client_hello(b"\x16\x03\x07\x00\x05hello") is None     # no such version
    assert net_tls.parse_client_hello(b"") is None


# --- hostile input ------------------------------------------------------------

def test_every_cut_of_a_valid_hello_is_contained():
    stream = _records(_chrome_hello(), split=60)
    assert net_tls.parse_client_hello(stream) is not None
    for n in range(len(stream)):
        assert net_tls.parse_client_hello(stream[:n]) is None, n


def test_a_record_that_claims_more_than_tls_allows_is_not_read():
    huge = b"\x16\x03\x01\xff\xff" + _hello()
    assert net_tls.parse_client_hello(huge) is None
    just_over = b"\x16\x03\x01" + _u(net_tls.MAX_RECORD + 1, 2) + _hello()
    assert net_tls.parse_client_hello(just_over) is None


def test_a_handshake_that_claims_megabytes_is_not_waited_for():
    claim = b"\x01\xff\xff\xff" + bytes(200)
    assert net_tls.parse_client_hello(_records(claim)) is None
    over = b"\x01" + _u(net_tls.MAX_HELLO + 1, 3) + bytes(net_tls.MAX_HELLO + 1)
    assert net_tls.parse_client_hello(_records(over, split=16000)) is None


def test_lengths_inside_the_hello_that_exceed_the_data_give_no_hello():
    head = b"\x03\x03" + bytes(32)
    start = head + b"\x00" + _list16([0x1301]) + b"\x01\x00"
    for bad in (
        head + b"\xff" + bytes(10),                                  # session id longer than the hello
        head + b"\x00" + b"\xff\xff" + bytes(10),                    # cipher list longer than the hello
        head + b"\x00" + b"\x00\x03" + bytes(3) + b"\x01\x00",       # an odd number of cipher bytes
        head + b"\x00" + _list16([0x1301]) + b"\x40",                # compression list longer than the hello
        start + b"\x00\x20" + _ext(0),                              # extension block longer than the hello
        start + _u(8, 2) + _u(0, 2) + _u(0xFFFF, 2) + bytes(4),      # an extension longer than its block
        start + b"\x00",                                            # one byte where a length should be
        start + _u(3, 2) + bytes(3),                                 # a block that ends inside an extension header
        head[:20],                                                   # cut inside the random
    ):
        wrapped = b"\x01" + _u(len(bad), 3) + bad
        assert net_tls.parse_client_hello(_records(wrapped)) is None, bad.hex()


def test_lists_that_lie_inside_an_extension_read_only_what_is_there():
    exts = [_ext(0, b"\xff\xff\x00\xff\xff" + b"ab"), _ext(10, b"\xff\xff\x00\x1d\x00"),
            _ext(11, b"\xff\x01"), _ext(13, b"\xff"), _ext(16, b"\xff\xff\xff\x68\x32"),
            _ext(43, b"\xff\x03")]
    hello = net_tls.parse_client_hello(_records(_hello(exts=exts)))
    assert hello is not None
    assert hello.groups == [29] and hello.point_formats == [1]
    assert hello.sni == "ab" and hello.alpn == ["h2"]
    assert hello.signatures == [] and hello.versions == []


def test_a_chain_of_empty_records_ends():
    empties = b"\x16\x03\x01\x00\x00" * 100000
    assert net_tls.parse_client_hello(empties) is None
    assert net_tls.parse_client_hello(empties + _records(_hello())) is None
    flow = _flow_from([(1.0, "c", empties[:200000])])
    assert net_tls.events_from_flow(flow) == []


def test_a_hello_made_of_many_empty_extensions_is_read_in_bounded_time():
    exts = [_ext(0x1000 + i % 4096) for i in range(15000)]
    hello = net_tls.parse_client_hello(_records(_hello(exts=exts), split=16000))
    assert hello is not None and len(hello.extensions) == 15000


def test_random_damage_to_a_hello_never_raises():
    rng = random.Random(5)
    stream = bytearray(_records(_chrome_hello(), split=300))
    survivors = 0
    for _ in range(3000):
        damaged = bytearray(stream)
        for _flip in range(rng.randint(1, 6)):
            damaged[rng.randrange(len(damaged))] = rng.randrange(256)
        if rng.random() < 0.3:
            del damaged[rng.randrange(len(damaged)):]
        hello = net_tls.parse_client_hello(bytes(damaged))
        if hello is not None:
            survivors += 1
            net_tls.ja3(hello)
            net_tls.ja4(hello)
    assert survivors > 0


def test_a_hostile_flow_gives_no_event_and_no_exception():
    hostile = b"\x16\x03\x01\xff\xff" + b"\x01\xff\xff\xff" * 50
    assert net_tls.events_from_flow(_flow_from([(1.0, "c", hostile)])) == []
    assert net_tls.events_from_flow(_flow_from([(1.0, "c", hostile), (2.0, "s", hostile)])) == []


def test_a_server_stream_of_hostile_records_leaves_the_event_intact():
    hostile = b"\x16\x03\x03\x40\x00" + b"\x0b\xff\xff\xff" + bytes(100)
    e = _one(_tls_flow(sni="a.top", flight=hostile))
    assert e["sni"] == "a.top" and e["cert_subject"] == ""
    empties = b"\x16\x03\x03\x00\x00" * 50000
    assert _one(_tls_flow(sni="a.top", flight=empties))["cert_subject"] == ""


# --- a hello that is cut after its server name -------------------------------

_FINGERPRINT_FIELDS = ("ja3", "ja3_hash", "ja4", "version")


def _name_end(stream, name=b"a.top"):
    return stream.index(name) + len(name)


def test_a_hello_cut_after_the_name_keeps_the_name_and_no_fingerprint():
    stream = _records(_hello(sni="a.top"))
    e = _one(_tls_flow(sni="a.top", truncate=_name_end(stream)))
    assert e["type"] == "tls" and e["sni"] == "a.top" and e["dest"] == "a.top"
    assert e["port"] == 443 and e["ts"] == 10.0
    assert e["hello_incomplete"] is True
    for field in _FINGERPRINT_FIELDS:
        assert e[field] == "", field
    assert e["ciphers"] == [] and e["extensions"] == [] and e["alpn"] == []


def test_a_hello_cut_before_the_name_is_complete_still_gives_no_event():
    stream = _records(_hello(sni="a.top"))
    end = _name_end(stream)
    for n in (20, end - 5, end - 1):
        assert net_tls.events_from_flow(_tls_flow(sni="a.top", truncate=n)) == [], n


def test_the_name_is_kept_at_exactly_the_cuts_that_leave_it_readable():
    stream = _records(_chrome_hello())
    end = _name_end(stream, b"example.com")
    for n in range(len(stream)):
        assert (net_tls.cut_server_name(stream[:n]) == "example.com") == (n >= end), n
    assert net_tls.cut_server_name(stream) is None          # not cut: there is a hello


def test_the_same_holds_when_the_hello_is_spread_over_records():
    stream = _records(_chrome_hello(), split=70)
    found = [n for n in range(len(stream)) if net_tls.cut_server_name(stream[:n])]
    assert found == list(range(found[0], len(stream))) and found[0] > 106


def test_the_hello_is_complete_once_nothing_is_missing():
    e = _one(_tls_flow(sni="a.top"))
    assert e["hello_incomplete"] is False
    assert e["ja3"] and e["ja3_hash"] and e["ja4"] and e["version"]


def test_a_lost_segment_after_the_name_keeps_the_name_and_reports_the_hole():
    flow = _tls_flow(hello=_chrome_hello(), segment=110, drop=(1,))
    e = _one(flow)
    assert e["sni"] == "example.com" and e["dest"] == "example.com"
    assert e["hello_incomplete"] is True and e["ja3"] == "" and e["ja4"] == ""
    assert e["stream_gaps"]


def test_a_cut_hello_still_reports_the_servers_certificate():
    stream = _records(_hello(sni="a.top"))
    e = _one(_tls_flow(sni="a.top", truncate=_name_end(stream), cert=("CN=a.top", "CN=a.top")))
    assert e["hello_incomplete"] is True and e["self_signed"] is True


def test_a_cut_hello_is_found_when_the_capture_begins_with_the_server():
    stream = _records(_hello(sni="a.top"))[:_name_end(_records(_hello(sni="a.top")))]
    flow = _flow_from([(1.0, "s", _server_flight(None)), (2.0, "c", stream)], syn=False)
    e = _one(flow)
    assert e["sni"] == "a.top" and e["hello_incomplete"] is True and e["ts"] == 2.0


def test_a_hello_cut_before_the_name_does_not_borrow_the_one_beside_it():
    cut = _records(_hello(sni="a.top"))[:30]
    flow = _flow_from([(1.0, "s", _server_flight(None)), (2.0, "c", cut)], syn=False)
    assert net_tls.events_from_flow(flow) == []


def test_a_complete_but_inconsistent_hello_gives_no_event_even_with_a_name():
    # not cut: every byte is there and a length contradicts the rest
    body = (b"\x03\x03" + bytes(32) + b"\x00" + _list16([0x1301]) + b"\x01\x00"
            + _u(20, 2) + _sni_ext("a.top") + _u(8, 2) + _u(0xFFFF, 2))
    wrapped = b"\x01" + _u(len(body), 3) + body
    assert net_tls.cut_server_name(_records(wrapped)) is None
    assert net_tls.events_from_flow(_flow_from([(1.0, "c", _records(wrapped))])) == []


def test_a_cut_hello_whose_name_extension_is_cut_or_lies_gives_no_name():
    sni = _sni_ext("a.top")
    prefix = b"\x03\x03" + bytes(32) + b"\x00" + _list16([0x1301]) + b"\x01\x00"
    for tail in (_u(300, 2) + sni[:-1],                 # the name extension itself is cut
                 _u(300, 2) + _ext(0, b"\xff\xff\x00\xff\xff"[:3]),   # no host name inside
                 _u(300, 2) + _ext(0, b"\x00\x00"),   # an empty list
                 _u(300, 2) + _ext(0xFFFF - 1)[:3]):    # a header cut inside
        stream = _records(b"\x01" + _u(500, 3) + prefix + tail)
        assert net_tls.cut_server_name(stream) is None, tail.hex()


def test_a_cut_hello_that_claims_megabytes_gives_no_name():
    body = b"\x03\x03" + bytes(32) + b"\x00" + _list16([0x1301]) + b"\x01\x00" + _u(60000, 2) + _sni_ext("a.top")
    over = _records(b"\x01" + _u(net_tls.MAX_HELLO + 1, 3) + body)
    assert net_tls.cut_server_name(over) is None
    huge = _records(b"\x01\xff\xff\xff" + body)
    assert net_tls.cut_server_name(huge) is None


def test_cutting_a_hello_anywhere_never_raises_and_never_invents_a_name():
    rng = random.Random(11)
    stream = bytearray(_records(_chrome_hello(), split=300))
    for _ in range(3000):
        damaged = bytearray(stream)
        for _flip in range(rng.randint(0, 4)):
            damaged[rng.randrange(len(damaged))] = rng.randrange(256)
        del damaged[rng.randrange(len(damaged)):]
        name = net_tls.cut_server_name(bytes(damaged))
        assert name is None or isinstance(name, str)
