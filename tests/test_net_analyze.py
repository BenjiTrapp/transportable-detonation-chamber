"""A pcap through the whole network analysis (``webui/net_analyze.py``) and the
network baseline (``webui/net_baseline.py``).

Regressions covered:
  * nothing produced ``conn``, ``conn_failed`` or ``udp`` events, so a dead C2
    was never a retry, rules written on those types could not fire and a
    connection no parser claimed vanished from the report
  * the findings were built without the rule set's ``known_good``, and an
    idle Windows hour scored like an infection
  * "no finding" and "the rules could not decide" looked the same: a spent
    regex budget left no trace in the report
  * a server name with NUL or newline went raw into ``dest`` and from there into
    rules, logs and the report, while a DNS name with the same bytes was
    rendered ``\\DDD``; every name field is now rendered once, like DNS
  * many small decompression bombs made the HTTP parser hash about a thousand
    times the bytes the capture retained; one budget bounds the capture
  * the text was not bounded per capture: 200 pipelined 290-byte gzip POSTs
    (77 KB) became 52.6 MB of JSON in 65 s, and 4 MB of one-line GETs 150,001
    events and 1.7 GB of memory; a text budget (``text_budget_spent``) and an
    event cap (``events_capped``, the parser stops reading) bound both, and
    the report's event copies are masked once, not twice
  * the baseline could not absorb what the clean machine does (a Defender
    update ``.exe`` fires ``net.exe_download``; a poller not in ``known_good``
    is a ``c2_checkin``), or absorbed a sample that only borrowed the name of
    such a host with another path, size or hash
  * a report built from the raw events raised on the ``Secret`` of an FTP or
    SMTP login, or showed the password, or the text and base64 of a decoded
    credential, or a password sent in plain text (a login form, a query
    string, URL userinfo, a ``name: value`` upload)
  * a password in a URL reached the report through a finding built from the
    raw event; a WebSocket message, a cookie, an API-key header and a
    response echoing the password were not masked either. One masking pass now
    covers the whole report, whatever key a value sits under
  * one name had two spellings: DNS and TLS rendered it byte by byte, HTTP and
    SMTP after a UTF-8-or-Latin-1 guess, so a name with a byte above 0x7F gave
    two IOCs; URLs and user names kept raw control bytes
  * every server address of the idle machine came back as an IOC through the
    connection events, although the name it served was ``known_good``
  * an error line copied a raw NUL out of an exception text
  * the mask cut ``keys.top:8080/stage.exe`` down to ``keys.top:***`` in a
    finding's URL, the Host header and the URL IOC, and rewrote a rule's text
    and a User-Agent
  * a baseline built from a report's (masked) events no longer matched the
    raw event whose path or User-Agent the mask had changed
  * a second or folded Host header was dropped, so ``Host: <known good>``
    followed by ``Host: evil.top`` hid the request and lost the IOC
  * ``headers.host`` kept raw ESC and NUL
  * keys after ``#``, ``|``, ``(``, ``[`` or ``=`` (an OAuth token in a URL
    fragment, a Location header, a pipe-joined body) and a ``password:x`` in a
    header value leaked through the anchored mask
  * a report's ``baseline_key`` was the hash of the raw path, so a short
    secret in it came back to ten thousand guesses
  * an absolute-form target's host was ignored when a Host header was there,
    so ``GET http://evil.top/x`` with a known-good Host was hidden
  * FTP ``commands`` carried raw ESC
  * ``/dl/token=abc/file.bin`` was not masked once keys had to start at a
    boundary; after a ``/`` a key counts with ``=`` only, so ``/key/stage.exe``
    and ``keys.top:8080/stage.exe`` stay whole
  * one parser that raised took the whole analysis down
  * a session header (X-Session, Session-Id, X-SID), an XML login and a
    percent-encoded form reached the report unmasked (final review M6, M7)
  * the baseline hid an upload to a spoofed known host: its key had no size
    and no address, so 200 KB with the OCSP Host header sent to the sample's
    own address was the clean machine's 600-byte OCSP POST; and
    ``/dl;token=abc/stage.exe`` was keyed (and shown) as ``/dl;token=***``
    like ``.../update.bin`` (final review I2)
  * an empty capture looked the same as a capture in which nothing was found
  * decoded values and DNS answers were outside every budget: 2.8 MB of GETs
    with base64-gzip query values were 800 decoded events, 60.6 MB of JSON and
    14 s, sixty DNS replies of 4000 pointer answers 61.5 MB; the decoded
    events of a capture and of each flow have a budget (``decoded_capped``),
    so do its DNS answers (``dns_answers_capped``), and a body is no longer
    inflated past what the text budget can still keep (follow-up F1)
  * the caps were first come: one flow of 20,001 GETs before a C2 left no
    finding and no hit, 40 gzip bombs before a base64 PE lost its decoding;
    a flow keeps ``MAX_EVENTS_PER_FLOW`` events and a share of the analysis
    text, every flow keeps its connection event, the report's text budget
    cuts only what the report keeps, and a cut capture says so in
    ``incomplete`` (follow-up F2)
  * a decoded value flagged as a credential was replaced whole, so a base64
    XML config with a ``<key>`` lost its C2 URL, and ``<keywords>``,
    ``<author>`` or a ``<keys>`` around a ``<server>`` hid a config that holds
    no secret; a value that is a credential by its text keeps the text with
    the secrets masked, one found under a secret name is still masked whole
    (follow-up F3)
  * one DNS answer the C2 served about itself (``ocsp.digicert.com A <C2>``)
    made forty uploads to it known to the baseline, its address quiet and its
    beacon the OCSP host's; only the answers of the capture's resolvers count,
    never a self-answer or one from where traffic went (follow-up F4)
  * one DNS-over-TCP exchange with the real resolver took it away as a
    resolver: an idle hour with its baseline lost 4 suppressions and scored
    SUSPICIOUS 4.0 with thirteen check-ins on known-good servers (follow-up
    review, Important 1)
  * a sample's own DNS server answering the only lookup of a capture was
    believed: forty spoofed OCSP uploads to the C2 stayed known to the
    baseline; the baseline learns the clean machine's resolvers and, with a
    baseline, only their answers count (Ruling 77)
  * a decoded text flagged only by a line shape was masked in part:
    ``login: bob`` kept the password on the bare next line, a dump of 300
    ``name: value`` lines its bare secret line; such a text is masked whole
    (Ruling 78)
  * a flow without payload after the cap was reached set ``events_capped``,
    so a capture that lost nothing read INCOMPLETE (follow-up review, Minor 3)
  * ``<key><url>``, ``<auth><server>`` and ``<token><host>`` masked the C2 in
    the report again, in a plain response and in decoded text (round-2
    review, Minor)
"""

import base64
import json
import os
import struct

import dpkt
import pytest

import memory_evidence
import net_analyze
import net_baseline
import net_events
import net_rules
import net_tls
import test_net_http

from test_net_default_rules import (CLIENT, RESOLVER, Capture, _benign_capture, _ok, _pe,
                                    _tcp_frame, _udp_frame)

C2 = "203.0.113.66"
_SYN, _ACK, _RST = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_RST


def _write(tmp_path, cap, name="capture.pcap"):
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, frame in sorted(cap.packets, key=lambda p: p[0]):
            writer.writepkt(frame, ts)
    return path


def _http_c2(cap, start=100.0, count=8, every=60.0):
    for i in range(count):
        cap.post(start + every * i, "evil.top", "/gate.php", b"id=42&st=ok")


def _pcap_with_http_c2(tmp_path, name="c2.pcap"):
    cap = Capture()
    _http_c2(cap)
    return _write(tmp_path, cap, name)


def _empty_pcap(tmp_path):
    return _write(tmp_path, Capture(), "empty.pcap")


def _truncated_pcap(tmp_path):
    path = _pcap_with_http_c2(tmp_path, "cut.pcap")
    with open(path, "r+b") as fh:
        fh.truncate(os.path.getsize(path) - 7)
    return path


def _ncsi(cap):
    for i in range(6):
        cap.get(30.0 * i + 1, "www.msftconnecttest.com", "/connecttest.txt",
                b"Microsoft Connect Test")


def _pcap_with_ncsi(tmp_path):
    cap = Capture()
    _ncsi(cap)
    return _write(tmp_path, cap, "ncsi.pcap")


def _pcap_with_pe_download(tmp_path):
    cap = Capture()
    cap.get(5.0, "stage.top", "/a.bin", _pe(), "application/octet-stream")
    return _write(tmp_path, cap, "pe.pcap")


def _pcap_with_exfil(tmp_path):
    cap = Capture()
    cap.post(5.0, "drop.top", "/upload", os.urandom(4000), "application/octet-stream")
    return _write(tmp_path, cap, "exfil.pcap")


def _kinds(report):
    return sorted(f["kind"] for f in report["evidence_findings"])


# --- the contract from the brief ----------------------------------------------------------

def test_a_pcap_becomes_a_report_with_events_and_iocs(tmp_path):
    p = _pcap_with_http_c2(tmp_path)
    r = net_analyze.analyze_pcap(p)
    assert r["observed"] is True
    assert r["event_summary"]["http"] >= 1
    assert "evil.top" in [i["value"] for i in r["iocs"]]


def test_an_empty_pcap_is_observed_but_empty(tmp_path):
    r = net_analyze.analyze_pcap(_empty_pcap(tmp_path))
    assert r["observed"] is False and r["note"]
    assert r["evidence_findings"] == []


def test_a_truncated_pcap_is_reported_as_such(tmp_path):
    r = net_analyze.analyze_pcap(_truncated_pcap(tmp_path))
    assert r["truncated"] is True and r["observed"] is True


def test_baseline_entries_are_suppressed_and_counted(tmp_path):
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    first = net_analyze.analyze_pcap(_pcap_with_ncsi(tmp_path))
    bl.add(first["events"])
    again = net_analyze.analyze_pcap(_pcap_with_ncsi(tmp_path), baseline=bl)
    assert again["suppressed_count"] >= 1


def test_a_baseline_survives_a_restart(tmp_path):
    path = str(tmp_path / "bl.json")
    net_baseline.NetBaseline(path).add(
        [net_events.NetEvent("dns", 1.0, dest="www.msftconnecttest.com")])
    assert net_baseline.NetBaseline(path).knows_dest("www.msftconnecttest.com")


def test_transferred_files_are_listed_with_their_hashes(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_pe_download(tmp_path))
    assert r["files"] and len(r["files"][0]["sha256"]) == 64
    assert r["files"][0]["name"].endswith(".bin")


def test_isolated_mode_marks_findings_as_partly_observed(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_exfil(tmp_path), mode="isolated")
    assert all(f.get("observation", 1.0) < 1.0
               for f in r["evidence_findings"] if f["kind"] == "exfil_upload")
    assert any(f["kind"] == "exfil_upload" for f in r["evidence_findings"])


def test_a_rule_file_with_errors_does_not_stop_the_analysis(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - {id: x, name: x, event: http, match: {p|nope: 1}}")
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path), rules=[str(bad)])
    assert r["errors"] and r["event_summary"]["http"] >= 1


# --- the whole report serializes ------------------------------------------------------------

def test_the_report_is_plain_json(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path))
    again = json.loads(json.dumps(r))
    assert again["event_summary"] == r["event_summary"]
    assert set(r) >= {"events", "event_summary", "behavior", "rule_hits", "evidence_findings",
                      "iocs", "files", "observed", "note", "truncated", "errors",
                      "suppressed_count", "rule_unevaluated", "rule_budget_spent", "mode"}


def test_an_unknown_mode_is_refused(tmp_path):
    with pytest.raises(ValueError):
        net_analyze.analyze_pcap(_empty_pcap(tmp_path), mode="offline")


def test_a_file_that_is_not_a_pcap_says_so_and_is_not_observed(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"nope")
    r = net_analyze.analyze_pcap(str(p))
    assert r["observed"] is False and "pcap" in r["note"].lower() and r["events"] == []


def test_the_http_c2_is_found_and_scored(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path), process="a.exe")
    assert "net.gate_post" in [h["rule_id"] for h in r["rule_hits"]]
    assert "c2_checkin" in _kinds(r)
    assert any(b["type"] == "beacon" and b["dest"] == "evil.top" for b in r["behavior"])


def test_rule_hits_name_events_of_the_report(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path))
    for hit in r["rule_hits"]:
        for ref in hit["events"]:
            event = r["events"][ref["index"]]
            assert (event["type"], event["dest"], event["ts"]) == (ref["type"], ref["dest"],
                                                                    ref["ts"])


# --- connections ---------------------------------------------------------------------------

def _syn(cap, ts, server, port, cport, answer=None):
    cap.packets.append((ts, _tcp_frame(CLIENT, cport, server, port, 1000, 0, _SYN)))
    if answer == "reset":
        cap.packets.append((ts + 0.01, _tcp_frame(server, port, CLIENT, cport, 0, 1001,
                                                  _RST | _ACK)))


def test_an_established_connection_is_a_conn_event(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 8443, [("c", b"\x01\x02\x03hello"), ("s", b"\x04\x05")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    conn = [e for e in r["events"] if e["type"] == "conn"]
    assert len(conn) == 1
    c = conn[0]
    assert (c["dest"], c["port"], c["src"], c["proto"], c["app"]) == (C2, 8443, CLIENT, "tcp",
                                                                     "raw")
    assert (c["client_bytes"], c["server_bytes"]) == (8, 2) and c["duration"] > 0
    assert r["event_summary"]["raw"] == 2


def test_a_syn_nobody_answers_and_a_refused_one_are_failed_connections(tmp_path):
    cap = Capture()
    for i in range(3):
        _syn(cap, 1.0 + i, C2, 443, 50000)
    _syn(cap, 10.0, C2, 8080, 50001, answer="reset")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    failed = sorted((e["port"], e["attempts"], e["refused"]) for e in r["events"]
                    if e["type"] == "conn_failed")
    assert failed == [(443, 3, False), (8080, 1, True)]
    assert "conn" not in r["event_summary"]


def test_repeated_failures_to_one_address_are_a_dead_c2(tmp_path):
    cap = Capture()
    for i in range(6):
        _syn(cap, 10.0 * i, C2, 443, 50000 + i)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), process="a.exe")
    assert "retry" in [b["type"] for b in r["behavior"]]
    assert "dead_c2_retry" in _kinds(r)
    assert C2 in [i["value"] for i in r["iocs"] if i["type"] == "ip"]


def test_udp_that_no_parser_claims_is_a_udp_event(tmp_path):
    cap = Capture()
    cap.udp(5.0, C2, 4444, b"\x13\x37" * 20, b"\x00\x01")
    cap.dns(1.0, "evil.top")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    udp = [e for e in r["events"] if e["type"] == "udp"]
    assert len(udp) == 1 and udp[0]["port"] == 4444 and udp[0]["answered"] is True
    assert (udp[0]["client_bytes"], udp[0]["server_bytes"]) == (40, 2)
    assert r["event_summary"]["dns"] == 1 and "conn" not in r["event_summary"]


def test_udp_on_port_53_that_is_not_dns_is_not_lost(tmp_path):
    cap = Capture()
    cap.udp(5.0, C2, 53, b"\xff" * 3, b"")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert [e["type"] for e in r["events"] if e["port"] == 53] == ["udp", "raw"]


def test_the_rule_fields_of_connection_events_are_what_the_analysis_emits(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 8443, [("c", b"abc"), ("s", b"d")])
    _syn(cap, 9.0, C2, 443, 50000)
    cap.udp(11.0, C2, 4444, b"x", b"y")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    seen = {}
    for e in r["events"]:
        seen.setdefault(e["type"], set()).update(e)
    for etype in ("conn", "conn_failed", "udp"):
        keys = seen[etype] - {"baseline", "known_good", "baseline_key"}
        assert keys - net_rules.UNMATCHABLE == net_rules.FIELDS[etype], etype


# --- known_good, and the rules' undecided -----------------------------------------------------

def test_an_hour_of_ordinary_windows_traffic_is_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(Capture, "read", lambda self: self)
    cap = _benign_capture()
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), process="a.exe")
    assert r["rule_hits"] == [] and r["rule_unevaluated"] == []
    assert memory_evidence.score(r["evidence_findings"])["label"] == "CLEAN"
    assert "c2_checkin" not in _kinds(r)


def test_known_good_names_are_marked_and_not_iocs(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_ncsi(tmp_path))
    http = [e for e in r["events"] if e["type"] == "http"]
    assert http and all(e["known_good"] is True for e in http)
    assert "www.msftconnecttest.com" not in [i["value"] for i in r["iocs"]]


def test_a_spent_regex_budget_is_in_the_report(tmp_path, monkeypatch):
    monkeypatch.setattr(net_rules, "REGEX_BUDGET_S", 0.0)
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path))
    assert r["rule_budget_spent"] is True
    assert "net.gate_post" in [u["rule_id"] for u in r["rule_unevaluated"]]


def test_a_decided_run_says_so(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path))
    assert r["rule_budget_spent"] is False and r["rule_unevaluated"] == []


# --- names are rendered once, like DNS names ----------------------------------------------------

def _client_hello_bytes(raw):
    sni = (b"\x00\x00" + struct.pack("!HH", len(raw) + 5, len(raw) + 3) + b"\x00"
           + struct.pack("!H", len(raw)) + raw)
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(sni)) + sni)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _dns_query(ts, cport, labels):
    question = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00" + b"\x00\x01\x00\x01"
    msg = struct.pack("!6H", 7, 0x0100, 1, 0, 0, 0) + question
    return (ts, _udp_frame(CLIENT, cport, RESOLVER, 53, msg))


def test_control_bytes_in_a_server_name_are_rendered_like_a_dns_name(tmp_path):
    raw = b"ev\x00il\n.t\xe9p"
    cap = Capture()
    cap.tcp(5.0, C2, 443, [("c", _client_hello_bytes(raw)), ("s", b"\x15\x03\x03\x00\x02\x02\x28")])
    cap.packets.append(_dns_query(4.0, 50000, raw.split(b".")))
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    tls = [e for e in r["events"] if e["type"] == "tls"][0]
    dns = [e for e in r["events"] if e["type"] == "dns"][0]
    assert tls["sni"] == tls["dest"] == dns["dest"] == "ev\\000il\\010.t\\233p"
    text = json.dumps(r)
    assert "\\u0000" not in text and "\\n" not in json.dumps([e["dest"] for e in r["events"]])
    assert tls["dest"] in [i["value"] for i in r["iocs"]]


def test_a_backslash_in_a_name_cannot_pass_for_an_escape(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 443, [("c", _client_hello_bytes(b"a\\000b.top")), ("s", b"")])
    cap.tcp(6.0, C2, 443, [("c", _client_hello_bytes(b"a\x00b.top")), ("s", b"")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    names = [e["sni"] for e in r["events"] if e["type"] == "tls"]
    assert names == ["a\\\\000b.top", "a\\000b.top"]


def test_host_headers_and_mail_addresses_are_rendered_too(tmp_path):
    cap = Capture()
    cap.web(5.0, "x", b"GET / HTTP/1.1\r\nHost: ev\x01il.top\r\n\r\n", _ok(b"hi"), lookup=False)
    cap.tcp(9.0, C2, 25, [("c", b"EHLO x\r\nMAIL FROM:<a\x7f@e.top>\r\nRCPT TO:<b\x02@d.top>\r\n"
                                b"QUIT\r\n"), ("s", b"220 smtp\r\n250 ok\r\n250 ok\r\n250 ok\r\n")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http"][0]
    smtp = [e for e in r["events"] if e["type"] == "smtp"][0]
    assert http["dest"] == "ev\\001il.top"
    assert smtp["mail_from"] == "a\\127@e.top" and smtp["rcpt_to"] == ["b\\002@d.top"]


# --- a hashing budget for the whole capture -------------------------------------------------------

def test_one_hashing_budget_bounds_the_whole_capture(tmp_path, monkeypatch):
    import gzip
    monkeypatch.setattr(net_analyze, "CAPTURE_HASH_BUDGET", 3 * 1024 * 1024)
    payload = b"MZ" + b"\x00" * (1024 * 1024)
    bomb = gzip.compress(payload, 9)
    reply = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n"
             % len(bomb)) + bomb
    cap = Capture()
    for i in range(6):
        cap.web(5.0 + i, "bomb.top", b"GET /b HTTP/1.1\r\nHost: bomb.top\r\n\r\n", reply)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    downloads = [e for e in r["events"] if e["type"] == "download"]
    assert len(downloads) == 6
    assert sum(1 for d in downloads if d["sha256"]) == 2
    assert sum(1 for d in downloads if d.get("hash_budget_spent")) == 4
    assert r["hash_budget_spent"] is True


# --- an output budget for the whole capture (final review C1) ---------------------------------------

def _gzip_posts(count, body):
    import gzip
    bomb = gzip.compress(body, 9)
    req = (b"POST /x HTTP/1.1\r\nHost: a.top\r\nContent-Encoding: gzip\r\nContent-Type: text/plain"
           b"\r\nContent-Length: %d\r\n\r\n" % len(bomb)) + bomb
    cap = Capture()
    cap.tcp(10.0, C2, 80, [("c", req * count)])
    return cap


def test_one_text_budget_bounds_the_body_text_of_the_whole_report(tmp_path, monkeypatch):
    # 290 bytes of gzip are 256 KiB of text each; two hundred of them were 52.6 MB of JSON.
    # The report's budget cuts what is kept; the analysis read every body whole (F2).
    monkeypatch.setattr(net_analyze, "CAPTURE_TEXT_BUDGET", 1024 * 1024)
    r = net_analyze.analyze_pcap(_write(tmp_path, _gzip_posts(12, b"A" * (256 * 1024))))
    http = [e for e in r["events"] if e["type"] == "http"]
    assert len(http) == 12
    kept = sum(len(e["body_text"] or "") for e in http)
    assert kept == 1024 * 1024
    assert sum(1 for e in http if e.get("report_text_cut")) == 8
    assert all(e["body_capped"] for e in http[4:]) and http[-1]["body_text"] == ""
    assert all(e["body_bytes"] < 1000 for e in http)          # the size on the wire stays exact
    assert r["report_text_cut"] is True and r["max_report_text"] == 1024 * 1024
    assert r["text_budget_spent"] is False and r["incomplete"] == []
    assert len(json.dumps(r)) < 2 * 1024 * 1024


def test_the_default_text_budget_keeps_a_bomb_capture_small(tmp_path):
    # the reviewer's probe: 77 KB of capture, 51 MiB of text, 52.6 MB of JSON before
    r = net_analyze.analyze_pcap(_write(tmp_path, _gzip_posts(200, b"A" * (256 * 1024))))
    assert r["text_budget_spent"] is True       # the flow's share of the analysis text
    assert net_analyze.CAPTURE_TEXT_BUDGET <= 32 * 1024 * 1024
    assert len(json.dumps(r)) < 2 * net_analyze.CAPTURE_TEXT_BUDGET


def test_a_capture_past_the_event_cap_is_cut_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(net_analyze, "MAX_EVENTS", 50)
    req = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
    cap = Capture()
    for i in range(5):
        cap.tcp(1.0 + i, "198.51.100.%d" % (10 + i), 80, [("c", req * 5000)])
    for i in range(5):
        cap.tcp(20.0 + i, "203.0.113.%d" % (20 + i), 80, [("c", req)])
    calls = []
    real = net_analyze.net_http._read_messages

    def counted(stream, request, cut, methods=(), limit=None):
        out = real(stream, request, cut, methods, limit)
        calls.append(len(out))
        return out
    monkeypatch.setattr(net_analyze.net_http, "_read_messages", counted)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http"]
    assert len(http) == 50
    assert r["events_capped"] is True and r["max_events"] == 50
    assert max(calls) <= 51                 # the parser stopped reading, not only the report
    # every flow keeps its connection event, also those past the cap (F2)
    conns = [e for e in r["events"] if e["type"] == "conn"]
    assert len(conns) == 10 and r["flows_unparsed"] == 9
    assert not any(e["dest"].startswith("203.0.113.2") for e in http)
    assert any("parser events" in line for line in r["incomplete"])


def _query_amplifier(cap, count, server=C2, values=4):
    import gzip
    val = base64.urlsafe_b64encode(gzip.compress(b"hello world, this is text\n" * 40330, 9)).decode()
    q = "&".join("v%d=%s" % (i, val) for i in range(values))
    cap.tcp(10.0, server, 80, [("c", ("GET /g?%s HTTP/1.1\r\nHost: a.top\r\n\r\n" % q).encode() * count)])


def test_decoded_values_have_a_budget_per_capture_and_say_when_it_was_spent(tmp_path):
    # the reviewer's probe: 2.8 MB of capture, 800 decoded events, 60.6 MB of JSON, 14 s
    cap = Capture()
    _query_amplifier(cap, 200)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    decoded = [e for e in r["events"] if e["type"] == "decoded"]
    assert r["decoded_capped"] is True and r["max_decoded"] == net_analyze.MAX_DECODED
    assert sum(len(d["text"] or "") for d in decoded) <= net_analyze.DECODED_TEXT_PER_FLOW
    assert len(json.dumps(r)) < 4 * os.path.getsize(_write(tmp_path, cap, "again.pcap"))


def test_one_flow_cannot_spend_the_decoding_budget_of_the_others(tmp_path, monkeypatch):
    monkeypatch.setattr(net_analyze, "MAX_DECODED_PER_FLOW", 20)
    cap = Capture()
    _query_amplifier(cap, 50, values=1)
    secret = base64.b64encode(b"<config><c2>http://evil-c2.top/gate.php</c2></config>").decode()
    cap.get(50.0, "evil.top", "/s?cfg=" + secret, b"ok")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    decoded = [e for e in r["events"] if e["type"] == "decoded"]
    assert sum(1 for d in decoded if d["dest"] == "a.top") == 20
    assert any(d["dest"] == "evil.top" and "evil-c2.top" in (d["text"] or "") for d in decoded)
    assert r["decoded_capped"] is True


def test_dns_answers_have_a_budget_per_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(net_analyze, "MAX_DNS_ANSWERS", 100)
    import test_net_dns
    cap = Capture()
    ask, reply = test_net_dns._pointer_reply(4000)
    for i in range(5):
        cap.udp(10.0 + i, RESOLVER, 53, ask, reply)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    dns = [e for e in r["events"] if e["type"] == "dns"]
    assert len(dns) == 5 and all(e["answers_capped"] for e in dns)
    assert sum(len(e["answers"]) for e in dns) == 100
    assert r["dns_answers_capped"] is True and r["max_dns_answers"] == 100
    assert len(json.dumps(r)) < 200 * 1024


def test_a_capture_under_the_event_cap_is_not_marked_cut(tmp_path):
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path))
    assert r["events_capped"] is False and r["text_budget_spent"] is False
    assert r["decoded_capped"] is False and r["dns_answers_capped"] is False


# --- the baseline ----------------------------------------------------------------------------------

_MPAM = "/c/msdownload/update/software/defu/2026/11/am_delta_patch_1.421.33.0_x64.exe"


def _defender_update(cap, ts, path=_MPAM, body=None):
    cap.get(ts, "download.windowsupdate.com", path, body or _pe(3000),
            "application/octet-stream")


def _poller(cap, start=10.0, every=45.0, path="/v1/status"):
    for i in range(8):
        cap.get(start + every * i, "api.vendor-sync.example", path, b'{"ok":true}',
                "application/json")


def test_a_defender_update_is_absorbed_by_the_baseline(tmp_path):
    clean = Capture()
    _defender_update(clean, 5.0)
    first = net_analyze.analyze_pcap(_write(tmp_path, clean, "clean.pcap"), process="a.exe")
    assert "net.exe_download" in [h["rule_id"] for h in first["rule_hits"]]
    assert "payload_staging" in _kinds(first)
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(first["events"])
    again = net_analyze.analyze_pcap(_write(tmp_path, clean, "clean2.pcap"), process="a.exe",
                                     baseline=bl)
    assert "payload_staging" not in _kinds(again) and again["rule_hits"] == []
    assert again["suppressed_count"] >= 1
    known = [e for e in again["events"] if e["type"] == "download"]
    assert known and all(e["baseline"] == "known" for e in known)
    assert again["files"] and again["files"][0]["baseline"] == "known"


@pytest.mark.parametrize("change", ["path", "body"])
def test_a_sample_that_borrows_the_update_host_is_not_absorbed(tmp_path, change):
    clean = Capture()
    _defender_update(clean, 5.0)
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(net_analyze.analyze_pcap(_write(tmp_path, clean, "clean.pcap"))["events"])
    spoof = Capture()
    if change == "path":
        _defender_update(spoof, 5.0, path=_MPAM.replace("am_delta", "am_deIta"))
    else:
        _defender_update(spoof, 5.0, body=_pe(3000) + b"\xcc" * 64)
    r = net_analyze.analyze_pcap(_write(tmp_path, spoof, "spoof.pcap"), process="a.exe",
                                 baseline=bl)
    assert "net.exe_download" in [h["rule_id"] for h in r["rule_hits"]]
    assert "payload_staging" in _kinds(r)
    assert [e.get("baseline") for e in r["events"] if e["type"] == "download"] == [None]


def test_a_benign_poller_is_absorbed_but_a_beacon_borrowing_its_name_is_not(tmp_path):
    clean = Capture()
    _poller(clean)
    first = net_analyze.analyze_pcap(_write(tmp_path, clean, "clean.pcap"), process="a.exe")
    assert "c2_checkin" in _kinds(first)
    assert "net.periodic_checkin" in [h["rule_id"] for h in first["rule_hits"]]
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(first["events"])
    shifted = Capture()
    _poller(shifted, start=500.0, every=45.3)
    again = net_analyze.analyze_pcap(_write(tmp_path, shifted, "again.pcap"), process="a.exe",
                                     baseline=bl)
    assert "c2_checkin" not in _kinds(again) and again["rule_hits"] == []
    spoof = Capture()
    _poller(spoof, start=500.0, every=13.0, path="/v1/tasks")
    r = net_analyze.analyze_pcap(_write(tmp_path, spoof, "spoof.pcap"), process="a.exe",
                                 baseline=bl)
    assert "c2_checkin" in _kinds(r)


def test_a_baseline_of_another_key_version_is_ignored_and_replaced(tmp_path):
    path = tmp_path / "bl.json"
    old = net_baseline.NetBaseline(str(path))
    old.add([net_events.NetEvent("dns", 1.0, dest="a.top")])
    data = json.loads(path.read_text())
    data["key_version"] = net_baseline.KEY_VERSION - 1
    path.write_text(json.dumps(data))
    bl = net_baseline.NetBaseline(str(path))
    event = net_events.NetEvent("dns", 1.0, dest="a.top")
    assert bl.count == 0 and not bl.knows(net_baseline.event_key(event))
    assert not bl.knows_dest("a.top")
    bl.add([net_events.NetEvent("dns", 1.0, dest="b.top")])
    assert bl.count == 1 and json.loads(path.read_text())["key_version"] == net_baseline.KEY_VERSION


def test_an_unreadable_baseline_is_kept_aside_not_overwritten(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text("{not json")
    bl = net_baseline.NetBaseline(str(path))
    assert bl.count == 0 and (tmp_path / "bl.json.corrupt").read_text() == "{not json"


def test_the_baseline_counts_what_it_learned_and_names_no_secret(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 21, [("c", b"USER bot\r\nPASS Hunter2Secret\r\nQUIT\r\n"),
                          ("s", b"220 ftp\r\n331 ok\r\n230 ok\r\n221 bye\r\n")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    added = bl.add(r["events"])
    assert added == bl.count >= 2 and bl.add(r["events"]) == 0
    assert "Hunter2Secret" not in (tmp_path / "bl.json").read_text()
    assert bl.knows_dest(C2) and bl.stats()["total"] == bl.count


def test_the_raw_events_and_the_report_events_have_the_same_baseline_key(tmp_path):
    cap = Capture()
    _http_c2(cap)
    cap.tcp(5.0, C2, 21, [("c", b"USER bot\r\nPASS x\r\n"), ("s", b"220 ftp\r\n")])
    events, _errors, _result = net_analyze.collect_events(_write(tmp_path, cap))
    report = net_analyze.analyze_pcap(_write(tmp_path, cap, "b.pcap"))
    assert [net_baseline.event_key(e) for e in events if e["type"] != "decoded"] == \
        [net_baseline.event_key(e) for e in report["events"]
         if e["type"] not in ("decoded", "beacon", "retry", "fanout")]


# --- nothing secret reaches the report ----------------------------------------------------------

def test_the_report_carries_no_password_in_any_form(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 21, [("c", b"USER stealer\r\nPASS Tr0ub4dor&3\r\nSTOR h.zip\r\n"),
                          ("s", b"220 ftp\r\n331 ok\r\n230 ok\r\n150 ok\r\n")])
    login = base64.b64encode(b"Hunter2Login").decode()
    cap.tcp(7.0, C2, 25, [("c", b"EHLO x\r\nAUTH LOGIN\r\n" + base64.b64encode(b"bot@e.top")
                                + b"\r\n" + login.encode() + b"\r\nQUIT\r\n"),
                          ("s", b"220 smtp\r\n250 ok\r\n334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n"
                                b"235 ok\r\n221 bye\r\n")])
    basic = base64.b64encode(b"alice:Correct-Horse-9").decode()
    cap.get(9.0, "panel.top", "/admin", b"hi", headers=b"Authorization: Basic "
            + basic.encode() + b"\r\n")
    cap.post(11.0, "shop.top", "/login", b"user=alice&pass=Plain-Form-77&go=1")
    cap.get(13.0, "shop.top", "/api?user=alice&password=Query-Pw-55", b"ok")
    cap.web(15.0, "proxy.top", b"GET ftp://bob:Userinfo-Pw-3@files.top/x HTTP/1.1\r\n"
            b"Host: files.top\r\n\r\n", _ok(b"ok"))
    cap.post(17.0, "drop.top", "/up", b"Host: PC01\nUser: bob\nPassword: Line Pw 99\n",
             "text/plain")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    text = json.dumps(r)
    for secret in ("Tr0ub4dor", "Hunter2Login", login, "Correct-Horse-9", basic,
                   "Plain-Form-77", "Query-Pw-55", "Userinfo-Pw-3", "Line Pw", "Pw 99"):
        assert secret not in text, secret
    ftp = [e for e in r["events"] if e["type"] == "ftp"][0]
    assert ftp["password"] == "***" and ftp["password_captured"] is True
    creds = [e for e in r["events"] if e["type"] == "decoded" and e["credential"]]
    assert creds and all(e["text"] == "***" and e["encoded"] == "***" for e in creds)
    assert "ftp://stealer@" + C2 in [i["value"] for i in r["iocs"]]
    form = [e for e in r["events"] if e["type"] == "http" and e["path"] == "/login"][0]
    assert form["body_text"] == "user=alice&pass=***&go=1"


def test_rules_see_the_plain_value_and_only_the_report_is_masked(tmp_path):
    rule = tmp_path / "r.yaml"
    rule.write_text("rules:\n  - {id: pw, name: pw, event: http, "
                    "match: {body_text|contains: Plain-Form-77}}\n")
    cap = Capture()
    cap.post(11.0, "shop.top", "/login", b"user=alice&pass=Plain-Form-77")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), rules=[str(rule)])
    assert [h["rule_id"] for h in r["rule_hits"]] == ["pw"]
    assert "Plain-Form-77" not in json.dumps(r)


# --- one failure stops nothing --------------------------------------------------------------------

def test_a_parser_that_raises_is_an_error_and_the_rest_goes_on(tmp_path, monkeypatch):
    def broken(flow):
        raise RuntimeError("boom")

    monkeypatch.setattr(net_tls, "events_from_flow", broken)
    cap = Capture()
    cap.tls(5.0, "x.top")
    _http_c2(cap)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert any("net_tls" in e and "boom" in e for e in r["errors"])
    assert r["event_summary"]["http"] >= 1 and r["event_summary"]["conn"] >= 2
    assert r["observed"] is True


def test_a_broken_step_after_the_parsers_is_an_error_too(tmp_path, monkeypatch):
    import net_behavior

    monkeypatch.setattr(net_behavior, "analyze", lambda events: 1 / 0)
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path))
    assert any("net_behavior" in e for e in r["errors"]) and r["behavior"] == []
    assert r["event_summary"]["http"] >= 1


# --- review round 1 ----------------------------------------------------------------------

_ODD = b"ev\x1bil\x00x.t\xe9p"
_ODD_TEXT = "ev\\027il\\000x.t\\233p"


def test_a_password_on_an_event_that_makes_a_finding_is_masked_there_too(tmp_path):
    cap = Capture()
    cap.get(5.0, "stage.top", "/a.exe?user=x&password=Find-Pw-1", _pe(),
            "application/octet-stream")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), process="a.exe")
    staging = [f for f in r["evidence_findings"] if f["kind"] == "payload_staging"]
    assert staging and staging[0]["url"] == "http://stage.top/a.exe?user=x&password=***"
    assert "Find-Pw-1" not in json.dumps(r)


def test_messages_cookies_key_headers_and_replies_are_masked(tmp_path):
    cap = Capture()
    request = (b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n"
               b"Cookie: session=Cookie-Tok-88; pass=Cookie-Pw-88\r\nX-Api-Key: Hdr-Key-99\r\n\r\n"
               + test_net_http._ws_frame(b"login user=eve&pass=Ws-Pw-15", masked=True))
    cap.web(5.0, "c2.top", request, b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
    cap.post(9.0, "shop.top", "/login", b"user=bob&pass=Echo-Pw-44",
             reply=b'{"ok": true, "password": "Echo-Pw-44"}', reply_type="application/json")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    text = json.dumps(r)
    for secret in ("Ws-Pw-15", "Cookie-Tok-88", "Cookie-Pw-88", "Hdr-Key-99", "Echo-Pw-44"):
        assert secret not in text, secret
    assert r["event_summary"]["websocket"] == 1


def test_one_masking_pass_covers_any_key_of_the_report():
    report = {"future": [{"url": "http://h.top/?pass=Fut-Pw-1", "deep": {"note": "token=Fut-2"}}],
              "events": [{"headers": {"cookie": "a=b", "x-auth-token": "t", "accept": "*/*"}}]}
    out = net_analyze.mask_report(report)
    assert "Fut-Pw-1" not in json.dumps(out) and "Fut-2" not in json.dumps(out)
    assert out["events"][0]["headers"] == {"cookie": "***", "x-auth-token": "***",
                                           "accept": "*/*"}


def test_one_name_has_one_spelling_whichever_protocol_carried_it(tmp_path):
    cap = Capture()
    cap.packets.append(_dns_query(4.0, 50000, _ODD.split(b".")))
    cap.tcp(5.0, C2, 443, [("c", _client_hello_bytes(_ODD)), ("s", b"")])
    cap.web(6.0, "x", b"GET / HTTP/1.1\r\nHost: " + _ODD + b"\r\n\r\n", _ok(b"hi"), lookup=False)
    cap.tcp(7.0, C2, 25, [("c", b"EHLO x\r\nMAIL FROM:<a@" + _ODD + b">\r\nQUIT\r\n"),
                          ("s", b"220 smtp\r\n250 ok\r\n250 ok\r\n")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    dests = {e["type"]: e["dest"] for e in r["events"] if e["type"] in ("dns", "tls", "http")}
    assert dests == {"dns": _ODD_TEXT, "tls": _ODD_TEXT, "http": _ODD_TEXT}
    smtp = [e for e in r["events"] if e["type"] == "smtp"][0]
    assert smtp["mail_from"] == "a@" + _ODD_TEXT
    domains = [i for i in r["iocs"] if i["type"] == "domain"]
    assert [d["value"] for d in domains] == [_ODD_TEXT]
    assert sorted(domains[0]["sources"]) == ["dns", "http", "tls"]
    assert "a@" + _ODD_TEXT in [i["value"] for i in r["iocs"] if i["type"] == "email"]


def test_urls_and_user_names_carry_no_raw_control_byte(tmp_path):
    cap = Capture()
    cap.web(6.0, "x", b"GET /p HTTP/1.1\r\nHost: " + _ODD + b"\r\n\r\n", _ok(b"hi"), lookup=False)
    cap.tcp(9.0, C2, 21, [("c", b"USER b\x1bot\r\nPASS x\r\n"), ("s", b"220 ftp\r\n230 ok\r\n")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http"][0]
    ftp = [e for e in r["events"] if e["type"] == "ftp"][0]
    assert http["url"] == "http://" + _ODD_TEXT + "/p" and ftp["user"] == "b\\027ot"
    assert "http://" + _ODD_TEXT + "/p" in [i["value"] for i in r["iocs"] if i["type"] == "url"]
    assert "ftp://b\\027ot@" + C2 in [i["value"] for i in r["iocs"]]
    for ioc in r["iocs"]:
        assert all(c.isprintable() for c in ioc["value"]), ioc


def test_the_servers_of_known_good_names_are_not_iocs(tmp_path, monkeypatch):
    monkeypatch.setattr(Capture, "read", lambda self: self)
    cap = _benign_capture()
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    rules = net_rules.load_rules([net_analyze.DEFAULT_RULES])
    kg = net_rules.KnownGood(rules.lists["known_good"])
    ips = {i["value"] for i in r["iocs"] if i["type"] == "ip"}
    known = {address for name, address in cap._servers.items() if kg.hides({"dest": name})}
    assert known and not ips & known
    assert cap.server("www.example.com") in ips


def test_a_known_good_name_on_a_foreign_address_keeps_the_address(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 80, [("c", b"POST / HTTP/1.1\r\nHost: ocsp.digicert.com\r\n"
                                b"Content-Length: 900\r\n\r\n" + b"\x30" * 900),
                          ("s", _ok(b"ok"))])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert C2 in [i["value"] for i in r["iocs"] if i["type"] == "ip"]


def test_an_error_line_carries_no_raw_control_byte(tmp_path, monkeypatch):
    def broken(flow):
        raise RuntimeError("bo\x00om\nnext")

    monkeypatch.setattr(net_tls, "events_from_flow", broken)
    cap = Capture()
    cap.tls(5.0, "x.top")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    line = [e for e in r["errors"] if "net_tls" in e][0]
    assert "bo\\000om\\010next" in line and line.isprintable()


def test_a_baseline_without_a_key_version_is_ignored(tmp_path):
    path = tmp_path / "bl.json"
    path.write_text(json.dumps({"keys": {net_baseline.event_key(
        net_events.NetEvent("dns", 1.0, dest="a.top")): {"type": "dns"}}, "dests": {"a.top": 1}}))
    bl = net_baseline.NetBaseline(str(path))
    assert bl.count == 0 and not bl.knows_dest("a.top")


def test_a_known_good_host_header_on_an_unresolved_address_keeps_the_address(tmp_path):
    cap = Capture()
    cap.tcp(5.0, "203.0.113.50", 80, [("c", b"GET /connecttest.txt HTTP/1.1\r\n"
                                           b"Host: www.msftconnecttest.com\r\n\r\n"),
                                      ("s", _ok(b"Microsoft Connect Test"))])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert "203.0.113.50" in [i["value"] for i in r["iocs"] if i["type"] == "ip"]


def test_an_address_that_also_served_another_name_stays_an_ioc(tmp_path):
    cap = Capture()
    address = cap.server("www.msftconnecttest.com")
    cap.get(5.0, "www.msftconnecttest.com", "/connecttest.txt", b"Microsoft Connect Test")
    cap.tcp(9.0, address, 80, [("c", b"GET /gate HTTP/1.1\r\nHost: evil.top\r\n\r\n"),
                               ("s", _ok(b"ok"))])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert address in [i["value"] for i in r["iocs"] if i["type"] == "ip"]
    only = Capture()
    only.get(5.0, "www.msftconnecttest.com", "/connecttest.txt", b"Microsoft Connect Test")
    r = net_analyze.analyze_pcap(_write(tmp_path, only, "only.pcap"))
    assert address not in [i["value"] for i in r["iocs"] if i["type"] == "ip"]


# --- review round 2 ----------------------------------------------------------------------

@pytest.mark.parametrize("host,port", [("keys.top", 8080), ("monkey.top", 8443)])
def test_a_host_with_a_secret_word_and_a_port_keeps_host_port_and_path(tmp_path, host, port):
    cap = Capture()
    authority = "%s:%d" % (host, port)
    cap.web(5.0, host, b"GET /stage.exe HTTP/1.1\r\nHost: " + authority.encode() + b"\r\n\r\n",
            _ok(_pe(), "application/octet-stream"), port=port)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), process="a.exe")
    url = "http://%s/stage.exe" % authority
    staging = [f for f in r["evidence_findings"] if f["kind"] == "payload_staging"]
    assert staging and staging[0]["url"] == url
    http = [e for e in r["events"] if e["type"] == "http"][0]
    assert http["headers"]["host"] == authority and http["url"] == url
    assert url in [i["value"] for i in r["iocs"] if i["type"] == "url"]


def test_rule_text_and_a_user_agent_are_not_rewritten(tmp_path):
    rule = tmp_path / "r.yaml"
    rule.write_text("rules:\n  - {id: t, name: 'token_exfil: auth: bearer', event: http,"
                    " description: 'auth: bearer token: x', match: {method: GET}}\n")
    cap = Capture()
    cap.web(5.0, "x.top", b"GET / HTTP/1.1\r\nHost: x.top\r\nUser-Agent: Agent/2 key:val\r\n\r\n",
            _ok(b"hi"))
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), rules=[str(rule)])
    assert r["rule_hits"][0]["name"] == "token_exfil: auth: bearer"
    assert r["rule_hits"][0]["description"] == "auth: bearer token: x"
    http = [e for e in r["events"] if e["type"] == "http"][0]
    assert http["ua"] == "Agent/2 key:val" and http["headers"]["user-agent"] == "Agent/2 key:val"


def test_a_baseline_from_a_report_matches_a_path_the_mask_changed(tmp_path):
    cap = Capture()
    cap.web(5.0, "dl.top", b"GET /dl;token=Tk-1/file.bin HTTP/1.1\r\nHost: dl.top\r\n"
            b"User-Agent: Agent/1.0 token=Tk-2\r\n\r\n", _ok(b"data"))
    first = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in first["events"] if e["type"] == "http"][0]
    assert http["path"] == "/dl;token=***/file.bin" and http["ua"] == "Agent/1.0 token=***"
    assert "Tk-1" not in json.dumps(first) and "Tk-2" not in json.dumps(first)
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(first["events"])
    again = net_analyze.analyze_pcap(_write(tmp_path, cap, "again.pcap"), baseline=bl)
    assert again["suppressed_count"] == len(again["events"])


def _ocsp(cap, ts, size, address=None):
    """An OCSP request: looked up and sent (``address`` None), or sent straight
    to ``address`` with the same Host header and no lookup."""
    body = os.urandom(size)
    if address is None:
        cap.post(ts, "ocsp.digicert.com", "/", body, "application/ocsp-request")
        return
    cap.tcp(ts, address, 80, [("c", b"POST / HTTP/1.1\r\nHost: ocsp.digicert.com\r\nUser-Agent: x\r\n"
                                    b"Content-Type: application/ocsp-request\r\nContent-Length: %d"
                                    b"\r\n\r\n" % size + body), ("s", _ok(b"ok"))])


def _ocsp_baseline(tmp_path):
    clean = Capture()
    _ocsp(clean, 5.0, 600)
    bl = net_baseline.NetBaseline(str(tmp_path / "ocsp-bl.json"))
    bl.add(net_analyze.analyze_pcap(_write(tmp_path, clean, "clean.pcap"))["events"])
    return bl


def _uploads(report):
    return [(e["size"], e.get("baseline")) for e in report["events"] if e["type"] == "upload"]


def test_the_baseline_does_not_hide_an_upload_to_a_spoofed_known_host(tmp_path):
    """Regressions covered (final review I2): the upload key was the claimed
    name, method, path, content type and file kind, so a 200 KB POST with the
    clean machine's OCSP Host header and type, sent to the sample's own address
    without a lookup, was suppressed and its exfil_upload with it."""
    bl = _ocsp_baseline(tmp_path)
    for name, size, address in (("spoofed", 200000, "203.0.113.66"), ("spoofed-small", 600, "203.0.113.66"),
                                ("big", 200000, None)):
        cap = Capture()
        _ocsp(cap, 10.0, size, address)
        r = net_analyze.analyze_pcap(_write(tmp_path, cap, name + ".pcap"), baseline=bl)
        assert _uploads(r) == [(size, None)], name
        assert "exfil_upload" in _kinds(r), name
    # the clean machine's own request, looked up again, is still what it was
    cap = Capture()
    _ocsp(cap, 10.0, 640)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap, "again.pcap"), baseline=bl)
    assert _uploads(r) == [(640, "known")] and "exfil_upload" not in _kinds(r)


def test_a_file_after_a_masked_value_in_a_path_keeps_its_own_key(tmp_path):
    """Regressions covered (final review I2): the masked value ran past "/", so
    ``/dl;token=abc/update.bin`` and ``/dl;token=abc/stage.exe`` were one
    ``/dl;token=***`` with one key, and the report lost the file name."""
    clean = Capture()
    clean.get(5.0, "dl.top", "/dl;token=abc/update.bin", b"data")
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(net_analyze.analyze_pcap(_write(tmp_path, clean, "clean.pcap"))["events"])
    sample = Capture()
    sample.get(5.0, "dl.top", "/dl;token=abc/stage.exe", b"data")
    r = net_analyze.analyze_pcap(_write(tmp_path, sample, "sample.pcap"), baseline=bl)
    http = [e for e in r["events"] if e["type"] == "http"][0]
    assert http["path"] == "/dl;token=***/stage.exe" and http.get("baseline") is None
    assert http["url"] == "http://dl.top/dl;token=***/stage.exe"
    assert "abc" not in json.dumps(r)


def _two_hosts(cap, second):
    cap.tcp(5.0, C2, 80, [("c", b"GET /t HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n" + second
                                + b"\r\n"), ("s", _ok(b"ok"))])


@pytest.mark.parametrize("second", [b"Host: evil.top\r\n", b" evil.top\r\n"])
def test_every_host_name_of_a_request_counts_and_two_are_never_known_good(tmp_path, second):
    cap = Capture()
    _two_hosts(cap, second)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http"][0]
    assert http["hosts"] == ["www.msftconnecttest.com", "evil.top"]
    assert http["known_good"] is False
    domains = [i["value"] for i in r["iocs"] if i["type"] == "domain"]
    assert "evil.top" in domains and "www.msftconnecttest.com" in domains
    assert C2 in [i["value"] for i in r["iocs"] if i["type"] == "ip"]
    assert net_rules.KnownGood(["www.msftconnecttest.com"]).hides(http) is False


def test_the_host_header_value_is_rendered_like_the_name(tmp_path):
    cap = Capture()
    cap.web(6.0, "x", b"GET / HTTP/1.1\r\nHost: " + _ODD + b"\r\n\r\n", _ok(b"hi"), lookup=False)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http"][0]
    assert http["headers"]["host"] == _ODD_TEXT
    assert "\\u001b" not in json.dumps(r) and "\\u0000" not in json.dumps(r)


def test_a_credential_in_a_path_segment_is_masked_and_a_secret_looking_path_is_not(tmp_path):
    cap = Capture()
    cap.get(5.0, "dl.top", "/dl/token=Seg-Tk-1/file.bin", b"data")
    cap.get(7.0, "keys.top:8080", "/key/stage.exe", b"data")
    cap.get(9.0, "x.top", "/password/x", b"data")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert "Seg-Tk-1" not in json.dumps(r)
    paths = sorted(e["path"] for e in r["events"] if e["type"] == "http")
    assert paths == ["/dl/token=***/file.bin", "/key/stage.exe", "/password/x"]


# --- review round 3 ----------------------------------------------------------------------

def test_no_credential_leaks_through_fragments_brackets_pipes_or_header_pairs(tmp_path):
    """The reviewer's probe p8.py, end to end."""
    cap = Capture()
    cap.web(5.0, "a.top", b"GET /cb HTTP/1.1\r\nHost: a.top\r\nReferer: https://idp.top/x"
            b"#access_token=FragTok-1&token_type=bearer\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: https://app.top/cb#id_token=FragTok-2\r\n"
            b"Content-Length: 0\r\n\r\n")
    cap.web(6.0, "b.top", b"GET /q?cfg=(token=Paren-3)&x=key=Eq-4 HTTP/1.1\r\nHost: b.top\r\n"
            b"X-Debug: password:Col-5\r\n\r\n", _ok(b"x"))
    cap.post(7.0, "c.top", "/f", b"a=1|password=Pipe-6\n[password=Brk-7]\nkey=Ok-8")
    request = (b"GET /ws HTTP/1.1\r\nHost: d.top\r\nUpgrade: websocket\r\n\r\n"
               + test_net_http._ws_frame(b"{key:Ws-9} |token=Ws-10", masked=True))
    cap.web(8.0, "d.top", request, b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
    cap.get(9.0, "e.top", "/a?Q=1&PASSWORD=Up-11&\tpwd=Tab-12", b"x")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    text = json.dumps(r)
    leaked = [v for v in ("FragTok-1", "FragTok-2", "Paren-3", "Eq-4", "Col-5", "Pipe-6",
                          "Brk-7", "Ok-8", "Ws-9", "Ws-10", "Up-11", "Tab-12") if v in text]
    assert leaked == []
    http = [e for e in r["events"] if e["type"] == "http" and e["dest"] == "a.top"][0]
    assert http["resp_headers"]["location"] == "https://app.top/cb#id_token=***"


def test_session_headers_xml_and_percent_encoded_credentials_do_not_leak(tmp_path):
    """Regressions covered (final review M6, M7): an X-Session or Session-Id
    value, an XML login and a percent-encoded form in a query reached the
    report as they were; and a base64 value in a session header decoded to an
    event that was not a credential."""
    import base64 as b64mod
    cap = Capture()
    cap.web(5.0, "a.top", b"GET /s HTTP/1.1\r\nHost: a.top\r\nX-Session: Sess-1\r\n"
            b"Session-Id: Sess-2\r\nX-SID: Sess-3\r\nX-Side: left\r\nSession-Data: "
            + b64mod.b64encode(b"session secret Sess-4") + b"\r\n\r\n", _ok(b"x"))
    cap.post(6.0, "b.top", "/x", b"<login><user>bob</user><pwd>Xml-5</pwd><password>Xml-6</password></login>",
             "text/xml")
    cap.get(7.0, "c.top", "/a?data=user%3Dbob%26password%3DPct-7%26go%3D1", b"x")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    text = json.dumps(r)
    leaked = [v for v in ("Sess-1", "Sess-2", "Sess-3", "Sess-4", "Xml-5", "Xml-6", "Pct-7")
              if v in text]
    assert leaked == []
    http = [e for e in r["events"] if e["type"] == "http" and e["dest"] == "a.top"][0]
    assert http["headers"]["x-session"] == "***" and http["headers"]["x-side"] == "left"
    assert "bob" in text                     # only the secrets go


def test_a_baseline_key_cannot_be_guessed_back_to_the_secret_it_held(tmp_path):
    cap = Capture()
    cap.get(5.0, "dl.top", "/dl;token=4821/f.bin", b"ok")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert "baseline_key" not in json.dumps(r) and "4821" not in json.dumps(r)
    http = [e for e in r["events"] if e["type"] == "http"][0]
    raw = dict(http, path="/dl;token=4821/f.bin")
    guess = dict(http, path="/dl;token=0000/f.bin")
    assert net_baseline.event_key(raw) == net_baseline.event_key(guess) == \
        net_baseline.event_key(http)


def test_an_absolute_target_names_its_host_beside_the_host_header(tmp_path):
    cap = Capture()
    cap.tcp(5.0, C2, 80, [("c", b"GET http://evil.top/x HTTP/1.1\r\n"
                                b"Host: www.msftconnecttest.com\r\n\r\n"), ("s", _ok(b"ok"))])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http"][0]
    assert http["hosts"] == ["www.msftconnecttest.com", "evil.top"] and http["known_good"] is False
    assert "evil.top" in [i["value"] for i in r["iocs"] if i["type"] == "domain"]
    assert "http://evil.top/x" in [i["value"] for i in r["iocs"] if i["type"] == "url"]


def test_ftp_commands_and_file_names_are_rendered(tmp_path):
    cap = Capture()
    cap.tcp(9.0, C2, 21, [("c", b"USER b\x1bot\xe9\r\nPASS x\r\nSTOR h\x00a rv.zip\r\n"),
                          ("s", b"220 ftp\r\n331 ok\r\n230 ok\r\n150 ok\r\n")])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    ftp = [e for e in r["events"] if e["type"] == "ftp"][0]
    assert ftp["commands"] == ["USER b\\027ot\\233", "PASS ***", "STOR h\\000a rv.zip"]
    assert ftp["files"] == ["h\\000a rv.zip"] and ftp["user"] == "b\\027ot\\233"
    assert "\\u001b" not in json.dumps(r) and "\\u0000" not in json.dumps(r)


# --- a padded flow cannot push the C2 out of the verdict (follow-up F2) -------------------------

def _padded_c2(cap, pad_gets=20001):
    if pad_gets:
        req = b"GET / HTTP/1.1\r\nHost: www.msftconnecttest.com\r\n\r\n"
        cap.tcp(1.0, "198.51.100.200", 80, [("c", req * pad_gets)])
    for i in range(12):
        cap.dns(100.0 + i * 60 - 0.4, "evil.top")
        cap.web(100.0 + i * 60, "evil.top",
                b"POST /gate.php HTTP/1.1\r\nHost: evil.top\r\nContent-Length: 4\r\n\r\nping",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def test_one_padded_flow_keeps_only_its_share_of_the_events(tmp_path):
    # the reviewer's probe: 20,001 GETs in one flow before the C2 left 0 findings, 0 hits
    cap = Capture()
    _padded_c2(cap)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert [(f["kind"], f["dest"]) for f in r["evidence_findings"]] == [("c2_checkin", "evil.top")]
    assert {"net.gate_post", "net.periodic_checkin"} <= {h["rule_id"] for h in r["rule_hits"]}
    pad = [e for e in r["events"] if e["type"] == "http" and e["dest"] == "www.msftconnecttest.com"]
    assert len(pad) == net_analyze.MAX_EVENTS_PER_FLOW
    assert r["flows_capped"] == 1 and r["events_capped"] is False
    assert r["incomplete"] and "2000 events" in r["incomplete"][0]


def test_an_unpadded_capture_is_complete(tmp_path):
    cap = Capture()
    _padded_c2(cap, pad_gets=0)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert r["flows_capped"] == 0 and r["incomplete"] == []
    assert [(f["kind"], f["dest"]) for f in r["evidence_findings"]] == [("c2_checkin", "evil.top")]


def _bomb_flow(cap, count=40):
    import gzip
    bomb = gzip.compress(b"A" * (256 * 1024), 9)
    req = (b"POST /x HTTP/1.1\r\nHost: cdn.example\r\nContent-Encoding: gzip\r\n"
           b"Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(bomb)) + bomb
    cap.tcp(1.0, "198.51.100.200", 80, [("c", req * count)])


def test_a_bomb_flow_cannot_spend_the_text_the_analysis_of_another_flow_needs(tmp_path):
    # the reviewer's probe: 40 gzip bombs first, and a later base64 PE was no longer decoded
    pe = b"MZ" + b"\x90" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + os.urandom(2000)
    b64 = base64.b64encode(pe)
    for pad in (False, True):
        cap = Capture()
        if pad:
            _bomb_flow(cap)
        cap.web(50.0, "evil.top", b"GET /s HTTP/1.1\r\nHost: evil.top\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n"
                % len(b64) + b64)
        r = net_analyze.analyze_pcap(_write(tmp_path, cap, "pe%d.pcap" % pad))
        assert [e["kind"] for e in r["events"] if e["type"] == "decoded"] == ["pe"], pad
        assert "net.exe_in_encoded_field" in {h["rule_id"] for h in r["rule_hits"]}, pad
        assert r["text_budget_spent"] is pad


def test_the_report_budget_cuts_the_report_not_the_analysis(tmp_path, monkeypatch):
    # bodies past the report's budget are still read by the decoder and the rules
    monkeypatch.setattr(net_analyze, "CAPTURE_TEXT_BUDGET", 1024)
    pe = b"MZ" + b"\x90" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + os.urandom(2000)
    cap = Capture()
    cap.post(10.0, "cdn.example", "/a", b"x" * 4000, "text/plain")
    cap.post(20.0, "evil.top", "/b", b"data=" + base64.b64encode(pe), "application/x-www-form-urlencoded")
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    http = [e for e in r["events"] if e["type"] == "http" and e["dest"] == "evil.top"][0]
    assert http["body_text"] == "" and http["report_text_cut"] is True
    assert [e["kind"] for e in r["events"] if e["type"] == "decoded"] == ["pe"]
    assert "net.exe_in_encoded_field" in {h["rule_id"] for h in r["rule_hits"]}
    assert r["report_text_cut"] is True and r["incomplete"] == []


# --- a decoded config keeps its C2 URL (follow-up F3) --------------------------------------------

def _served(cap, ts, host, body):
    cap.web(ts, host, b"GET /c HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode(),
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n"
            % len(body) + body)


def test_a_decoded_config_with_a_key_keeps_its_c2_url_and_loses_only_the_key(tmp_path):
    configs = {
        "xml": b"<config><c2>http://evil-c2.top/gate.php</c2><key>A1B2C3D4E5</key><sleep>60</sleep></config>",
        "json": b'{"c2": "http://evil-c2.top/gate.php", "author": "Kit-Author-7", "api_key": "A1B2C3D4E5"}',
    }
    for kind, config in configs.items():
        cap = Capture()
        encoded = base64.b64encode(config)
        _served(cap, 10.0, "cdn.example", encoded)
        r = net_analyze.analyze_pcap(_write(tmp_path, cap, kind + ".pcap"))
        text = json.dumps(r)
        assert "A1B2C3D4E5" not in text and encoded.decode() not in text, kind
        d = [e for e in r["events"] if e["type"] == "decoded"][0]
        assert d["credential"] is True and "http://evil-c2.top/gate.php" in d["text"], kind
        assert d["encoded"] == "***" and d["sha256"] is None and d["preview"] == "", kind
        assert "***" in d["text"], kind


def test_a_decoded_config_without_a_secret_is_not_a_credential(tmp_path):
    for i, config in enumerate((b"<doc><keywords>invoice</keywords><server>http://evil-c2.top/a</server></doc>",
                                b"<keys><server>evil-c2.top</server><port>443</port></keys>",
                                b"<cfg><authority>https://evil-c2.top/login</authority></cfg>")):
        cap = Capture()
        _served(cap, 10.0, "cdn.example", base64.b64encode(config))
        _served(cap, 20.0, "cdn2.example", config)
        r = net_analyze.analyze_pcap(_write(tmp_path, cap, "c%d.pcap" % i))
        d = [e for e in r["events"] if e["type"] == "decoded"][0]
        assert d["credential"] is False and d["text"] == config.decode()
        plain = [e for e in r["events"] if e["type"] == "http" and e["dest"] == "cdn2.example"][0]
        assert plain["resp_text"] == config.decode()


def test_a_value_under_a_secret_name_is_still_masked_whole(tmp_path):
    cap = Capture()
    value = base64.b64encode(b"http://evil-c2.top/a and more text").decode()
    cap.post(10.0, "evil.top", "/x", ("password=%s&x=1" % value).encode())
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    d = [e for e in r["events"] if e["type"] == "decoded"][0]
    assert d["credential"] is True and d["text"] == "***" and d["encoded"] == "***"
    assert value not in json.dumps(r) and "evil-c2.top/a and more" not in json.dumps(r)


# --- a self-served DNS answer is no resolution (follow-up F4) ----------------------------------

def _fake_lookup(cap, ts, name, server, address=C2):
    import socket
    q = dpkt.dns.DNS(id=7, qr=dpkt.dns.DNS_Q, qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)])
    a = dpkt.dns.DNS(id=7, qr=dpkt.dns.DNS_R, qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)],
                     an=[dpkt.dns.DNS.RR(name=name, type=1, ttl=60, ip=socket.inet_aton(address))])
    cap.udp(ts, server, 53, bytes(q), bytes(a))


def _spoofed_uploads(cap, count=40):
    for i in range(count):
        _ocsp(cap, 10.0 + i * 30, 1000, C2)


def test_a_self_served_answer_does_not_make_spoofed_uploads_known(tmp_path):
    # the reviewer's probe: 40/40 known, no findings, 41 suppressed
    bl = _ocsp_baseline(tmp_path)
    for name, others in (("alone", 0), ("beside the resolver", 6)):
        cap = Capture()
        _fake_lookup(cap, 9.0, "ocsp.digicert.com", C2)
        for i in range(others):
            cap.dns(1.0 + i, "name%d.example.org" % i)
        _spoofed_uploads(cap)
        for baseline in (bl, None):
            r = net_analyze.analyze_pcap(_write(tmp_path, cap, "fake.pcap"), baseline=baseline)
            assert _uploads(r) == [(1000, None)] * 40, name
            found = {(f["kind"], f["dest"]) for f in r["evidence_findings"]}
            assert found == {("c2_checkin", C2), ("exfil_upload", "ocsp.digicert.com")}, (name, found)
            assert C2 in [i["value"] for i in r["iocs"]], name


def test_an_answer_from_a_server_the_capture_also_talked_to_is_not_believed(tmp_path):
    bl = _ocsp_baseline(tmp_path)
    cap = Capture()
    _fake_lookup(cap, 9.0, "ocsp.digicert.com", "203.0.113.67")
    _spoofed_uploads(cap, 3)
    cap.tcp(5.0, "203.0.113.67", 443, [("c", b"\x00" * 20), ("s", b"\x00" * 20)])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), baseline=bl)
    assert _uploads(r) == [(1000, None)] * 3


def test_the_resolvers_answers_still_absorb_the_clean_machine(tmp_path):
    # the clean machine's own OCSP request beside a sample's own server for another name
    bl = _ocsp_baseline(tmp_path)
    cap = Capture()
    _ocsp(cap, 10.0, 640)
    _fake_lookup(cap, 3.0, "evil.top", C2)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), baseline=bl)
    assert _uploads(r) == [(640, "known")] and "exfil_upload" not in _kinds(r)


def test_dns_over_tcp_to_the_resolver_keeps_an_idle_hour_absorbed(tmp_path, monkeypatch):
    monkeypatch.setattr(Capture, "read", lambda self: self)
    p = _write(tmp_path, _benign_capture(), "hour.pcap")
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(net_analyze.analyze_pcap(p)["events"])
    hour = _benign_capture()
    hour.tcp(1800.0, RESOLVER, 53, [("c", b"\x00\x20" + os.urandom(32)), ("s", b"\x00\x40" + os.urandom(64))])
    r = net_analyze.analyze_pcap(_write(tmp_path, hour, "hour2.pcap"), baseline=bl)
    assert r["evidence_findings"] == [] and r["suppressed_count"] >= 415
    s = memory_evidence.score(memory_evidence.collect({"network": r}, process="sample.exe"))
    assert s["label"] == "CLEAN" and s["score"] == 0


# --- with a baseline, only the resolvers it learned (Ruling 77) -------------------------------------

def test_the_baseline_learns_the_resolvers_of_the_clean_capture(tmp_path):
    bl = _ocsp_baseline(tmp_path)
    assert bl.learned_resolvers() == frozenset((RESOLVER,))
    with open(bl.path) as fh:
        data = json.load(fh)
    assert data["key_version"] == net_baseline.KEY_VERSION == 3 and data["resolvers"] == {RESOLVER: 1}
    assert net_baseline.NetBaseline(str(tmp_path / "none.json")).learned_resolvers() is None


def test_a_fake_server_answering_the_only_lookup_is_not_believed_with_a_baseline(tmp_path):
    bl = _ocsp_baseline(tmp_path)
    cap = Capture()
    _fake_lookup(cap, 9.0, "ocsp.digicert.com", "203.0.113.67")
    _spoofed_uploads(cap)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), baseline=bl)
    assert _uploads(r) == [(1000, None)] * 40
    assert {(f["kind"], f["dest"]) for f in r["evidence_findings"]} == {
        ("c2_checkin", C2), ("exfil_upload", "ocsp.digicert.com")}
    assert C2 in [i["value"] for i in r["iocs"]]
    # without a baseline the capture's own share rule still believes it (as before)
    plain = net_analyze.analyze_pcap(_write(tmp_path, cap, "plain.pcap"))
    assert C2 not in [i["value"] for i in plain["iocs"]]


def test_a_one_lookup_capture_through_the_learned_resolver_is_judged_as_before(tmp_path):
    bl = _ocsp_baseline(tmp_path)
    cap = Capture()
    cap.dns(1.0, "evil.top")
    for i in range(12):
        cap.web(100.0 + i * 60, "evil.top", b"POST /gate.php HTTP/1.1\r\nHost: evil.top\r\nContent-Length: 4"
                b"\r\n\r\nping", _ok(b"ok"), lookup=False)
    _ocsp(cap, 50.0, 640)
    r = net_analyze.analyze_pcap(_write(tmp_path, cap), baseline=bl)
    assert _uploads(r) == [(640, "known")]
    assert [(f["kind"], f["dest"]) for f in r["evidence_findings"]] == [("c2_checkin", "evil.top")]
    assert r["evidence_findings"][0]["addresses"]          # the lookup still ties name and address


def test_a_baseline_that_learned_no_resolver_believes_no_answer(tmp_path):
    bl = net_baseline.NetBaseline(str(tmp_path / "nodns.json"))
    cap = Capture()
    _ocsp(cap, 5.0, 600, "198.51.100.9")     # learned without any lookup
    bl.add(net_analyze.analyze_pcap(_write(tmp_path, cap, "clean.pcap"))["events"])
    assert bl.learned_resolvers() == frozenset()
    sample = Capture()
    _ocsp(sample, 10.0, 640)
    r = net_analyze.analyze_pcap(_write(tmp_path, sample), baseline=bl)
    assert _uploads(r) == [(640, None)]


# --- a credential by line shape alone is masked whole (Ruling 78) -------------------------------------

def test_a_decoded_text_flagged_only_by_a_line_shape_is_masked_whole(tmp_path):
    cases = [b"login: bob\nSec-Pw-10\n",
             b"".join(b"line %d: x\n" % i for i in range(300)) + b"Sec-Pw-19 admin\n",
             b"https://bank.example/login\tbob\tSec-Pw-02\n"]
    cap = Capture()
    for i, text in enumerate(cases):
        _served(cap, 10.0 + i, "h%d.example" % i, base64.b64encode(text))
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    blob = json.dumps(r)
    for secret in ("Sec-Pw-10", "Sec-Pw-19", "Sec-Pw-02"):
        assert secret not in blob, secret
    decoded = [e for e in r["events"] if e["type"] == "decoded"]
    assert len(decoded) == 3 and all(d["credential"] and d["text"] == "***" for d in decoded)


def test_a_shape_that_says_where_the_secret_is_still_masks_in_part(tmp_path):
    cap = Capture()
    _served(cap, 10.0, "h.example", base64.b64encode(b"host: evil-c2.top\n<cfg><pwd>Sec-Pw-5</pwd></cfg>"))
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    d = [e for e in r["events"] if e["type"] == "decoded"][0]
    assert "Sec-Pw-5" not in json.dumps(r) and "<pwd>***</pwd>" in d["text"]


def test_a_flow_without_payload_past_the_cap_is_no_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(net_analyze, "MAX_EVENTS", 5)
    req = b"GET / HTTP/1.1\r\nHost: a.top\r\n\r\n"
    cap = Capture()
    cap.tcp(1.0, "10.7.0.1", 80, [("c", req * 5)])
    cap.tcp(2.0, "10.7.0.2", 80, [])
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    assert sum(e["type"] == "conn" for e in r["events"]) == 2
    assert r["events_capped"] is False and r["flows_unparsed"] == 0 and r["incomplete"] == []
    cap.tcp(3.0, "10.7.0.3", 80, [("c", req)])          # one with payload is cut, and says so
    r = net_analyze.analyze_pcap(_write(tmp_path, cap, "more.pcap"))
    assert r["events_capped"] is True and r["flows_unparsed"] == 1


def test_a_c2_host_inside_a_secret_element_stays_in_the_report(tmp_path):
    shapes = (b"<key><url>http://evil-c2.top/g</url></key>", b"<auth><server>evil-c2.top</server></auth>",
              b"<token><host>evil-c2.top</host></token>")
    cap = Capture()
    for i, xml in enumerate(shapes):
        _served(cap, 10.0 + i, "p%d.example" % i, xml)
        _served(cap, 20.0 + i, "d%d.example" % i, base64.b64encode(xml))
    r = net_analyze.analyze_pcap(_write(tmp_path, cap))
    for i, xml in enumerate(shapes):
        plain = [e for e in r["events"] if e["type"] == "http" and e["dest"] == "p%d.example" % i][0]
        assert plain["resp_text"] == xml.decode()
        d = [e for e in r["events"] if e["type"] == "decoded" and e["dest"] == "d%d.example" % i][0]
        assert d["text"] == xml.decode() and d["credential"] is False
    still = Capture()
    _served(still, 10.0, "s.example", b"<password><item>Sec-Pw-22</item></password>")
    _served(still, 11.0, "t.example", base64.b64encode(b"<cfg><password><![CDATA[Sec-Pw-15]]></password></cfg>"))
    blob = json.dumps(net_analyze.analyze_pcap(_write(tmp_path, still, "still.pcap")))
    assert "Sec-Pw-22" not in blob and "Sec-Pw-15" not in blob
