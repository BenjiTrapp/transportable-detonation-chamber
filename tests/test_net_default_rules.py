"""The starter rule set for network events (``rules/network/default.yaml``).

Regressions covered:
  * a rule file that does not load, or loads with some rules refused, leaves
    the analyst with fewer rules than the file shows and no sign of it
  * a rule that names fields which never occur on one event loads cleanly and
    never fires: every rule here is fired by events that went through the real
    pcap reader and the real parsers, not by hand-made events whose fields were
    chosen to fit
  * a rule file nobody ran against ordinary traffic: a clean Windows machine
    (connectivity checks, Windows Update, certificate revocation, time sync,
    telemetry, a browser) must produce no hit and nothing undecided, or the
    operator learns to ignore the report
  * ``known_good`` that silences a capture only because the capture contains
    nothing periodic: the same capture against the rules without the list
    must fire, and a PE downloaded from a "known good" name must still fire
  * a gate page rule that matched every PHP form, or missed ``/panel/Gate.PHP``
    and a GET of the same page
  * the correlation firing for events of different processes, or for the
    download alone
  * a credential reaching a report through the hit of an FTP or SMTP rule
  * an evidence ``kind`` misspelt in the YAML: nothing validates it yet, so
    the set in use is pinned here
"""

import base64
import copy
import json
import os
import random
import socket
import struct
import tempfile

import dpkt
import pytest
import yaml

import net_behavior
import net_decode
import net_dns
import net_events
import net_flows
import net_http
import net_mail_ftp
import net_raw
import net_rules
import net_tls

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES = os.path.join(ROOT, "rules", "network", "default.yaml")

CLIENT = "192.0.2.10"
RESOLVER = "198.51.100.53"

# The evidence arts Task 12 defines (plan, Task 12). A rule may name one of these.
EVIDENCE_ARTS = {"c2_checkin", "exfil_upload", "credential_in_transit", "fallback_rotation",
                 "dead_c2_retry", "recon_service", "tls_ja3_known", "dga_pattern",
                 "payload_staging"}

_SYN, _ACK, _PSH = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH
_UA = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"


# --- a capture, built the way a real one is -------------------------------------------

def _ip_frame(src, dst, proto, transport):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto,
                    ttl=64, data=transport)
    return bytes(dpkt.ethernet.Ethernet(
        dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _tcp_frame(src, sport, dst, dport, seq, ack, flags, payload=b""):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, win=8192,
                       data=payload)
    return _ip_frame(src, dst, dpkt.ip.IP_PROTO_TCP, seg)


def _udp_frame(src, sport, dst, dport, payload):
    dgram = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    dgram.ulen = 8 + len(payload)
    return _ip_frame(src, dst, dpkt.ip.IP_PROTO_UDP, dgram)


class Capture:
    """Packets of a client that talks to a few servers, written to a real pcap."""

    def __init__(self):
        self.packets = []
        self._cport = 49152
        self._txid = 0
        self._servers = {}

    def server(self, name):
        """A stable address for a name, so that a lookup and the connection agree."""
        return self._servers.setdefault(name, "198.51.100.%d" % (len(self._servers) + 100))

    def _port(self):
        self._cport += 1
        return self._cport

    def dns(self, ts, name, rcode=0, qtype="A", answer=None):
        """A lookup and its answer (an address for NOERROR, none otherwise)."""
        self._txid += 1
        kind = {"A": 1, "AAAA": 28, "PTR": 12, "TXT": 16}[qtype]
        ask = dpkt.dns.DNS(id=self._txid, qr=dpkt.dns.DNS_Q, opcode=dpkt.dns.DNS_QUERY,
                           qd=[dpkt.dns.DNS.Q(name=name, type=kind, cls=1)])
        reply = dpkt.dns.DNS(id=self._txid, qr=dpkt.dns.DNS_R, opcode=dpkt.dns.DNS_QUERY,
                             rcode=rcode, qd=[dpkt.dns.DNS.Q(name=name, type=kind, cls=1)])
        if rcode == 0 and kind == 1:
            address = answer or self.server(name)
            reply.an = [dpkt.dns.DNS.RR(name=name, type=1, ttl=60,
                                        ip=socket.inet_aton(address))]
        port = self._port()
        self.packets.append((ts, _udp_frame(CLIENT, port, RESOLVER, 53, bytes(ask))))
        self.packets.append((ts + 0.05, _udp_frame(RESOLVER, 53, CLIENT, port, bytes(reply))))

    def udp(self, ts, server, dport, request, reply):
        port = self._port()
        self.packets.append((ts, _udp_frame(CLIENT, port, server, dport, request)))
        self.packets.append((ts + 0.05, _udp_frame(server, dport, CLIENT, port, reply)))

    def tcp(self, ts, server, dport, exchange):
        """One connection. ``exchange`` is a list of ``("c" | "s", payload)``, 50 ms apart."""
        cport = self._port()
        ends = {"c": (CLIENT, cport, server, dport), "s": (server, dport, CLIENT, cport)}
        isn = {"c": 1000, "s": 5000}
        nxt = {"c": 1001, "s": 5001}
        self.packets += [
            (ts - 0.3, _tcp_frame(*ends["c"], isn["c"], 0, _SYN)),
            (ts - 0.2, _tcp_frame(*ends["s"], isn["s"], 1001, _SYN | _ACK)),
            (ts - 0.1, _tcp_frame(*ends["c"], 1001, 5001, _ACK)),
        ]
        for step, (side, payload) in enumerate(exchange):
            other = "s" if side == "c" else "c"
            for i in range(0, len(payload), 60000):
                part = payload[i:i + 60000]
                self.packets.append((ts + 0.05 * step, _tcp_frame(
                    *ends[side], nxt[side], nxt[other], _ACK | _PSH, part)))
                nxt[side] += len(part)

    def web(self, ts, host, request, response, port=80, lookup=True):
        """A name lookup 0.4 s before the connection, then one request and its response."""
        if lookup:
            self.dns(ts - 0.4, host)
        self.tcp(ts, self.server(host), port, [("c", request), ("s", response)])

    def get(self, ts, host, path, body=b"", ctype="text/plain", headers=b""):
        request = (b"GET " + path.encode() + b" HTTP/1.1\r\nHost: " + host.encode()
                   + b"\r\nUser-Agent: " + _UA + b"\r\n" + headers + b"\r\n")
        self.web(ts, host, request, _ok(body, ctype))

    def post(self, ts, host, path, body, ctype="application/x-www-form-urlencoded",
             reply=b"ok", reply_type="text/plain"):
        request = (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: " + host.encode()
                   + b"\r\nUser-Agent: " + _UA + b"\r\nContent-Type: " + ctype.encode()
                   + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.web(ts, host, request, _ok(reply, reply_type))

    def tls(self, ts, name, lookup=True):
        if lookup:
            self.dns(ts - 0.4, name)
        self.tcp(ts, self.server(name), 443, [("c", _client_hello(name)),
                                              ("s", b"\x16\x03\x03\x00\x04\x02\x00\x00\x00")])

    def read(self):
        """The capture through the real reader, parsers, decoder and behaviour analysis."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture.pcap")
            with open(path, "wb") as fh:
                writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
                for ts, frame in sorted(self.packets, key=lambda p: p[0]):
                    writer.writepkt(frame, ts)
            result = net_flows.read_pcap(path)
        assert result.flows, result.note
        return _events_of(result.flows)


def _ok(body, ctype="text/plain"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype.encode() + b"\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)


def _client_hello(name):
    raw = name.encode()
    sni = (b"\x00\x00" + struct.pack("!HH", len(raw) + 5, len(raw) + 3) + b"\x00"
           + struct.pack("!H", len(raw)) + raw)
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
            + b"\x01\x00" + struct.pack("!H", len(sni)) + sni)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _events_of(flows):
    """What an orchestrator does with the flows: the parser that claims one, else raw."""
    events = []
    for flow in flows:
        if net_dns.is_dns(flow):
            events += net_dns.events_from_flow(flow)
            continue
        events += (net_http.events_from_flow(flow) or net_tls.events_from_flow(flow)
                   or net_mail_ftp.events_from_flow(flow) or net_raw.events_from_flow(flow))
    for event in [e for e in events if e["type"] == "http"]:
        events += net_decode.decode_event_fields(event)
    events = net_events.sort_events(events)
    return net_events.sort_events(events + net_behavior.analyze(events))


def _rules():
    return net_rules.load_rules([DEFAULT_RULES])


def _fired(events, rules=None):
    return [h["rule_id"] for h in (rules or _rules()).evaluate(events)]


def _pe(size=400):
    return b"MZ" + b"\x90\x00\x03\x00" * 8 + bytes(size)


# --- the contract from the brief --------------------------------------------------------

def test_the_default_rules_load_without_errors():
    rs = net_rules.load_rules([DEFAULT_RULES])
    assert rs.errors == [] and len(rs.rules) >= 7


def test_every_rule_has_a_name_a_severity_and_a_behaviour_line():
    for r in net_rules.load_rules([DEFAULT_RULES]).rules:
        assert r["name"] and r["severity"] in ("info", "low", "medium", "high", "critical")
        assert r["behavior"]


def test_a_pe_download_followed_by_beaconing_fires_the_chain_rule():
    rs = net_rules.load_rules([DEFAULT_RULES])
    evs = [net_events.NetEvent("download", 1.0, process="l.exe", dest="e.top", kind="pe"),
           net_events.NetEvent("beacon", 60.0, process="l.exe", dest="c2.top", interval=60.0)]
    assert any(h["severity"] == "critical" for h in rs.evaluate(evs))


def test_ordinary_windows_traffic_fires_nothing():
    rs = net_rules.load_rules([DEFAULT_RULES])
    evs = [net_events.NetEvent("dns", 1.0, dest="www.msftconnecttest.com"),
           net_events.NetEvent("http", 2.0, dest="www.msftconnecttest.com",
                               method="GET", path="/connecttest.txt", status=200)]
    assert rs.evaluate(evs) == []


# --- the file itself ---------------------------------------------------------------------

def test_every_rule_carries_the_documented_fields_and_an_attack_technique():
    for r in _rules().rules:
        assert r["id"].startswith("net.") and r["role"] and r["description"], r["id"]
        assert r["attack"], r["id"]


def test_the_evidence_kinds_in_use_are_arts_the_evidence_model_defines():
    kinds = {r["kind"] for r in _rules().rules if r["kind"]}
    assert kinds == {"payload_staging", "c2_checkin", "dga_pattern", "recon_service",
                     "credential_in_transit"}
    assert kinds <= EVIDENCE_ARTS


def test_known_good_names_the_windows_housekeeping_traffic():
    names = {n.lower() for n in _rules().lists["known_good"]}
    for needed in ("www.msftconnecttest.com", "www.msftncsi.com", "dns.msftncsi.com",
                   "*.windowsupdate.com", "time.windows.com", "ocsp.digicert.com",
                   "crl.microsoft.com", "*.events.data.microsoft.com"):
        assert needed in names


# --- ordinary Windows traffic, through the real parsers ------------------------------------

def _benign_capture():
    """A quiet Windows machine for an hour: what it does without anyone asking."""
    cap = Capture()
    rng = random.Random(5)

    def noise(n):
        return rng.randbytes(n)

    # connectivity checks, every 30 s
    for i in range(10):
        cap.get(30.0 * i + 1, "www.msftconnecttest.com", "/connecttest.txt",
                b"Microsoft Connect Test")
        cap.get(30.0 * i + 4, "www.msftncsi.com", "/ncsi.txt", b"Microsoft NCSI")
    cap.dns(5.0, "dns.msftncsi.com", answer="131.107.255.255")
    # the certificate trust list, polled every two minutes; update payloads (cab, esd)
    for i in range(6):
        cap.get(100.0 + 120.0 * i, "ctldl.windowsupdate.com",
                "/msdownload/update/v3/static/trustedr/en/authrootstl.cab",
                b"MSCF\x00\x00\x00\x00" + noise(900), "application/vnd.ms-cab-compressed")
    for i, name in enumerate(("windows11.0-kb5040442-x64_ab12.cab", "kb5040442.psf",
                              "windows11.0-kb5041585-x64_cd34.esd")):
        cap.get(400.0 + 37.0 * i, "download.windowsupdate.com",
                "/c/msdownload/update/software/updt/2026/11/" + name,
                b"MSCF\x00\x00\x00\x00" + noise(50000), "application/octet-stream")
    # revocation checks: a CRL, an OCSP request, in no rhythm
    cap.get(210.0, "crl3.digicert.com", "/DigiCertGlobalRootG2.crl",
            b"\x30\x82\x03\x10" + noise(780), "application/pkix-crl")
    cap.get(655.0, "crl.microsoft.com", "/pki/crl/products/MicRooCerAut_2010-06-23.crl",
            b"\x30\x82\x01\x20" + noise(300), "application/pkix-crl")
    for at in (230.0, 1210.0, 2333.0):
        cap.post(at, "ocsp.digicert.com", "/", b"\x30\x51" + noise(600),
                 "application/ocsp-request", noise(300), "application/ocsp-response")
    # time sync, every 1024 s, and the name it asks for
    for i in range(4):
        cap.dns(60.0 + 1024.0 * i, "time.windows.com", answer=cap.server("time.windows.com"))
        cap.udp(61.0 + 1024.0 * i, cap.server("time.windows.com"), 123,
                b"\x23" + bytes(47), b"\x24" + noise(47))
    # telemetry and Edge, over TLS, on timers
    for i in range(8):
        cap.tls(20.0 + 300.0 * i, "v10.events.data.microsoft.com")
        cap.tls(45.0 + 60.0 * i, "settings-win.data.microsoft.com")
        cap.tls(90.0 + 450.0 * i, "msedge.api.cdp.microsoft.com")
    # names the resolver tries by itself
    for i in range(6):
        cap.dns(15.0 + 9.0 * i, "wpad", rcode=3)
    cap.dns(16.0, "isatap", rcode=3)
    cap.dns(17.0, "10.2.0.192.in-addr.arpa", rcode=3, qtype="PTR")
    # a person browsing: pages, forms, files, secure sites, each in its own time
    visits = (3.0, 3.9, 17.0, 52.0, 53.0, 190.0)
    for at, path in zip(visits, ("/", "/style.css", "/logo.png", "/news", "/favicon.ico", "/")):
        cap.get(at + 1200.0, "www.example.com", path,
                b"<html><body>hello</body></html>", "text/html")
    cap.post(1330.0, "www.example.com", "/login", b"user=alice&pass=correct+horse")
    cap.get(1340.0, "intranet.example.com", "/reports", b"<html>reports</html>", "text/html",
            headers=b"Authorization: Basic " + base64.b64encode(b"alice:correct horse") + b"\r\n")
    cap.get(1500.0, "files.example.org", "/guide.pdf", b"%PDF-1.7\n" + noise(2000),
            "application/pdf")
    cap.get(1560.0, "files.example.org", "/archive.zip", b"PK\x03\x04" + noise(2000),
            "application/zip")
    for at, name in ((1210.0, "www.bing.com"), (1215.0, "www.bing.com"), (1260.0, "github.com"),
                     (1262.0, "avatars.githubusercontent.com"), (1400.0, "www.wikipedia.org"),
                     (1405.0, "upload.wikimedia.org"), (1650.0, "fonts.gstatic.com"),
                     (1900.0, "www.microsoft.com"), (2100.0, "www.bing.com")):
        cap.tls(at, name)
    return cap.read()


def test_the_benign_capture_holds_what_it_claims_to():
    events = _benign_capture()
    kinds = {e["type"] for e in events}
    assert {"dns", "http", "tls", "raw", "beacon", "retry", "decoded", "download"} <= kinds
    beacons = {e["dest"] for e in events if e["type"] == "beacon"}
    assert {"www.msftconnecttest.com", "www.msftncsi.com", "ctldl.windowsupdate.com",
            "v10.events.data.microsoft.com", "settings-win.data.microsoft.com"} <= beacons
    assert {e["kind"] for e in events if e["type"] == "download"} == {"pdf", "zip"}


def test_ordinary_windows_traffic_in_a_real_capture_fires_nothing_and_leaves_nothing_undecided():
    rs = _rules()
    hits = rs.evaluate(_benign_capture())
    assert rs.errors == []
    assert [h["rule_id"] for h in hits] == []
    assert hits.unevaluated == [] and hits.budget_spent is False


def test_the_silence_comes_from_known_good_and_not_from_an_empty_capture():
    events = _benign_capture()
    with open(DEFAULT_RULES, encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    without = copy.deepcopy(spec)
    del without["lists"]["known_good"]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "no_known_good.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(without, fh)
        bare = net_rules.load_rules([path])
    assert bare.errors == []
    hits = bare.evaluate(events)
    assert "net.periodic_checkin" in [h["rule_id"] for h in hits]
    assert sum(h["count"] for h in hits if h["rule_id"] == "net.periodic_checkin") >= 5


def test_an_executable_from_a_known_good_name_still_fires_because_a_name_is_no_evidence():
    cap = Capture()
    cap.get(5.0, "download.windowsupdate.com", "/msdownload/update/software/defu/am_delta.exe",
            _pe(), "application/octet-stream")
    cap.get(9.0, "www.msftconnecttest.com", "/connecttest.txt", _pe(), "text/plain")
    hits = _rules().evaluate(cap.read())
    fired = {h["rule_id"] for h in hits}
    assert "net.exe_download" in fired
    assert next(h for h in hits if h["rule_id"] == "net.exe_download")["count"] == 2


# --- staging ---------------------------------------------------------------------------------

def test_an_executable_over_http_fires_and_names_the_evidence_art():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/update.exe", _pe(), "application/octet-stream")
    hits = _rules().evaluate(cap.read())
    assert [h["rule_id"] for h in hits] == ["net.exe_download"]
    assert hits[0]["severity"] == "high" and hits[0]["kind"] == "payload_staging"
    assert hits[0]["count"] == 1 and hits[0]["events"][0]["dest"] == "cdn.evil.top"


def test_an_elf_over_http_fires_too():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/a.out", b"\x7fELF" + bytes(300), "application/octet-stream")
    assert _fired(cap.read()) == ["net.exe_download"]


@pytest.mark.parametrize("body,ctype", [
    (b"%PDF-1.7\n" + bytes(300), "application/pdf"),
    (b"PK\x03\x04" + bytes(300), "application/zip"),
    (b"MSCF\x00\x00\x00\x00" + bytes(300), "application/vnd.ms-cab-compressed"),
    (b"\x89PNG\r\n\x1a\n" + bytes(300), "image/png"),
])
def test_other_downloads_are_not_executables(body, ctype):
    cap = Capture()
    cap.get(5.0, "files.example.org", "/thing", body, ctype)
    assert _fired(cap.read()) == []


def test_an_executable_served_as_a_picture_fires_both_staging_rules():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/img/logo.png", _pe(), "image/png")
    assert sorted(_fired(cap.read())) == ["net.disguised_exe_download", "net.exe_download"]


def test_an_executable_labelled_text_fires_the_disguised_rule_whatever_the_name():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/download?id=4", _pe(), "text/plain")
    assert "net.disguised_exe_download" in _fired(cap.read())


def test_an_honest_executable_is_not_disguised():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/setup.exe", _pe(), "application/x-msdownload")
    assert _fired(cap.read()) == ["net.exe_download"]


def test_an_executable_inside_base64_in_a_response_fires():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/data.php", base64.b64encode(_pe(300)), "text/html")
    events = cap.read()
    assert [e["kind"] for e in events if e["type"] == "decoded"] == ["pe"]
    hits = _rules().evaluate(events)
    assert [h["rule_id"] for h in hits] == ["net.exe_in_encoded_field"]
    assert hits[0]["kind"] == ""


def test_base64_text_is_not_an_encoded_executable():
    cap = Capture()
    cap.get(5.0, "cdn.evil.top", "/data.php",
            base64.b64encode(b"hostname=PC01 user=alice domain=CORP"), "text/html")
    events = cap.read()
    assert any(e["type"] == "decoded" for e in events)
    assert _fired(events) == []


# --- command and control --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/gate.php", "/panel/Gate.PHP", "/a/b/bot.php", "/tasks.php",
                                  "/cmd.php", "/command.php"])
def test_a_post_to_a_gate_page_fires(path):
    cap = Capture()
    cap.post(5.0, "c2.evil.top", path, b"id=1234&os=10&data=QWxhZGRpbjpvcGVu")
    hits = _rules().evaluate(cap.read())
    assert "net.gate_post" in [h["rule_id"] for h in hits]
    hit = next(h for h in hits if h["rule_id"] == "net.gate_post")
    assert hit["severity"] == "high" and hit["kind"] == "" and hit["family"]


@pytest.mark.parametrize("method,path", [
    ("GET", "/gate.php"),              # fetching the page is not reporting to it
    ("POST", "/gateway.php"), ("POST", "/gate.php.txt"), ("POST", "/navigate.php"),
    ("POST", "/submit.php"), ("POST", "/login.php"), ("POST", "/api/gate"),
])
def test_other_requests_are_not_a_gate_post(method, path):
    cap = Capture()
    if method == "GET":
        cap.get(5.0, "site.example.org", path, b"<html></html>", "text/html")
    else:
        cap.post(5.0, "site.example.org", path, b"a=1&b=2")
    assert "net.gate_post" not in _fired(cap.read())


def _checkins(cap, host="c2.evil.top", start=100.0, every=60.0, n=6, jitter=(0, 1, -1, 2, -2, 0)):
    for i in range(n):
        cap.get(start + every * i + jitter[i % len(jitter)], host, "/tasks/%d" % i, b"none")


def test_regular_requests_to_one_host_fire_the_check_in_rule_with_the_interval():
    cap = Capture()
    _checkins(cap)
    events = cap.read()
    beacon = next(e for e in events if e["type"] == "beacon")
    assert 57 <= beacon["interval"] <= 63
    hits = _rules().evaluate(events)
    assert [h["rule_id"] for h in hits] == ["net.periodic_checkin"]
    assert hits[0]["kind"] == "c2_checkin" and hits[0]["severity"] == "medium"
    assert hits[0]["events"][0]["dest"] == "c2.evil.top"


def test_a_tls_check_in_is_regular_contact_too():
    cap = Capture()
    for i in range(6):
        cap.tls(100.0 + 30.0 * i, "c2.evil.top")
    assert _fired(cap.read()) == ["net.periodic_checkin"]


def test_irregular_visits_are_not_a_rhythm():
    cap = Capture()
    for at in (100.0, 104.0, 190.0, 191.5, 600.0, 1400.0):
        cap.get(at, "www.example.com", "/", b"<html></html>", "text/html")
    assert _fired(cap.read()) == []


def test_too_few_visits_are_not_a_rhythm():
    cap = Capture()
    _checkins(cap, n=3)
    assert _fired(cap.read()) == []


def test_a_download_and_a_rhythm_of_one_process_fire_the_chain():
    cap = Capture()
    cap.get(20.0, "cdn.evil.top", "/stage2.exe", _pe(), "application/octet-stream")
    _checkins(cap, start=100.0)
    hits = _rules().evaluate(cap.read())
    chain = [h for h in hits if h["rule_id"] == "net.chain_exe_then_beacon"]
    assert len(chain) == 1 and chain[0]["severity"] == "critical"
    assert sorted(chain[0]["via"]) == ["net.exe_download", "net.periodic_checkin"]


def test_an_encoded_executable_and_a_rhythm_fire_the_chain():
    cap = Capture()
    cap.get(20.0, "cdn.evil.top", "/data.php", base64.b64encode(_pe(300)), "text/html")
    _checkins(cap, start=100.0)
    assert "net.chain_exe_then_beacon" in _fired(cap.read())


def test_neither_half_alone_fires_the_chain():
    download = Capture()
    download.get(20.0, "cdn.evil.top", "/stage2.exe", _pe(), "application/octet-stream")
    rhythm = Capture()
    _checkins(rhythm)
    assert "net.chain_exe_then_beacon" not in _fired(download.read())
    assert "net.chain_exe_then_beacon" not in _fired(rhythm.read())


def test_a_download_of_one_process_and_a_rhythm_of_another_are_no_chain():
    evs = [net_events.NetEvent("download", 1.0, process="a.exe", dest="e.top", kind="pe"),
           net_events.NetEvent("beacon", 60.0, process="b.exe", dest="c2.top", interval=60.0)]
    assert "net.chain_exe_then_beacon" not in _fired(evs)


def test_a_beacon_without_a_measured_interval_is_not_a_check_in():
    evs = [net_events.NetEvent("beacon", 60.0, dest="c2.top", interval=None, periodic=False,
                               unmeasured="more than one time scale", connections=8)]
    assert _fired(evs) == []


def test_a_burst_of_names_that_do_not_exist_fires():
    cap = Capture()
    for i in range(14):
        cap.dns(100.0 + 1.5 * i, "q%dxk%dwz.top" % (i * 7919 % 1000, i), rcode=3)
    events = cap.read()
    fan = [e for e in events if e["type"] == "fanout"]
    assert len(fan) == 1 and fan[0]["nxdomain"] is True
    hits = _rules().evaluate(events)
    assert [h["rule_id"] for h in hits] == ["net.nxdomain_burst"]
    assert hits[0]["kind"] == "dga_pattern"


def test_a_few_failed_lookups_are_not_a_burst():
    cap = Capture()
    for i in range(6):
        cap.dns(100.0 + i, "typo%d.example.com" % i, rcode=3)
    assert _fired(cap.read()) == []


def test_failed_lookups_spread_over_hours_are_not_a_burst():
    cap = Capture()
    for i in range(14):
        cap.dns(100.0 + 1800.0 * i, "typo%d.example.com" % i, rcode=3)
    assert _fired(cap.read()) == []


def test_fewer_than_ten_names_or_answers_other_than_nxdomain_are_not_a_burst():
    evs = [net_events.NetEvent("fanout", 1.0, hosts=9, nxdomain=True, window_s=60.0, dests=[]),
           net_events.NetEvent("fanout", 1.0, hosts=12, nxdomain=False, window_s=60.0, dests=[])]
    assert _fired(evs) == []


# --- reconnaissance ------------------------------------------------------------------------------

def test_a_lookup_of_the_public_address_fires_once_per_process_with_every_event_counted():
    cap = Capture()
    cap.get(5.0, "api.ipify.org", "/", b"203.0.113.77")
    cap.tls(9.0, "ipinfo.io")
    cap.dns(12.0, "myip.opendns.com")
    events = cap.read()
    hits = _rules().evaluate(events)
    assert [h["rule_id"] for h in hits] == ["net.ip_lookup"]
    assert hits[0]["count"] >= 5          # DNS, HTTP and TLS events of the three services
    assert hits[0]["kind"] == "recon_service" and hits[0]["severity"] == "low"


def test_an_ordinary_site_is_not_an_address_lookup():
    cap = Capture()
    cap.get(5.0, "www.example.com", "/", b"<html></html>", "text/html")
    cap.tls(9.0, "ipinformation.example.org")
    assert _fired(cap.read()) == []


# --- credentials in clear text ---------------------------------------------------------------------

def _session(cap, ts, server, port, client, reply):
    cap.tcp(ts, server, port, [("c", client), ("s", reply)])


def test_an_ftp_login_in_clear_text_fires_and_the_hit_carries_no_password():
    cap = Capture()
    _session(cap, 5.0, "203.0.113.20", 21,
             b"USER stealer\r\nPASS Tr0ub4dor&3\r\nSTOR harvest.zip\r\n",
             b"220 ok\r\n331 ok\r\n230 ok\r\n150 ok\r\n")
    events = cap.read()
    hits = _rules().evaluate(events)
    assert [h["rule_id"] for h in hits] == ["net.ftp_cleartext_credentials"]
    assert hits[0]["kind"] == "credential_in_transit" and hits[0]["severity"] == "high"
    assert "Tr0ub4dor" not in json.dumps(hits)


def test_an_ftp_session_without_a_password_does_not_fire():
    cap = Capture()
    _session(cap, 5.0, "203.0.113.20", 21, b"USER anonymous\r\nRETR readme.txt\r\n",
             b"220 ok\r\n331 ok\r\n")
    assert _fired(cap.read()) == []


def test_an_smtp_login_in_clear_text_fires_and_the_hit_carries_no_password():
    cap = Capture()
    _session(cap, 5.0, "203.0.113.25", 587,
             b"EHLO pc\r\nAUTH LOGIN\r\n" + base64.b64encode(b"drop@evil.top") + b"\r\n"
             + base64.b64encode(b"hunter2-hunter2") + b"\r\n",
             b"220 ok\r\n250 ok\r\n334 x\r\n334 y\r\n235 ok\r\n")
    hits = _rules().evaluate(cap.read())
    assert [h["rule_id"] for h in hits] == ["net.smtp_cleartext_credentials"]
    assert hits[0]["kind"] == "credential_in_transit"
    assert "hunter2" not in json.dumps(hits)


def test_an_smtp_session_without_a_login_does_not_fire():
    cap = Capture()
    _session(cap, 5.0, "203.0.113.25", 25,
             b"EHLO pc\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nQUIT\r\n",
             b"220 ok\r\n250 ok\r\n250 ok\r\n250 ok\r\n221 bye\r\n")
    assert _fired(cap.read()) == []


# --- all of it ------------------------------------------------------------------------------------

def test_every_rule_fires_on_events_that_came_through_the_real_parsers():
    cap = Capture()
    cap.get(20.0, "cdn.evil.top", "/img/logo.png", _pe(), "image/png")
    cap.get(30.0, "cdn.evil.top", "/data.php", base64.b64encode(_pe(300)), "text/html")
    cap.post(40.0, "c2.evil.top", "/gate.php", b"id=1")
    cap.get(50.0, "api.ipify.org", "/", b"203.0.113.77")
    _session(cap, 60.0, "203.0.113.20", 21, b"USER s\r\nPASS pw\r\n", b"220 ok\r\n331 ok\r\n230 ok\r\n")
    _session(cap, 70.0, "203.0.113.25", 587,
             b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n", b"334 x\r\n334 y\r\n235 ok\r\n")
    for i in range(14):
        cap.dns(200.0 + i, "zz%dqq.top" % i, rcode=3)
    _checkins(cap, start=300.0)
    rs = _rules()
    hits = rs.evaluate(cap.read())
    assert sorted(h["rule_id"] for h in hits) == sorted(r["id"] for r in rs.rules)
    assert hits.unevaluated == []
