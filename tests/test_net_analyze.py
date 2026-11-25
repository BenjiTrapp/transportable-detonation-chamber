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
  * an empty capture looked the same as a capture in which nothing was found
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
    assert http["path"] == "/dl;token=***" and http["ua"] == "Agent/1.0 token=***"
    assert "Tk-1" not in json.dumps(first) and "Tk-2" not in json.dumps(first)
    bl = net_baseline.NetBaseline(str(tmp_path / "bl.json"))
    bl.add(first["events"])
    again = net_analyze.analyze_pcap(_write(tmp_path, cap, "again.pcap"), baseline=bl)
    assert again["suppressed_count"] == len(again["events"])


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
    assert paths == ["/dl/token=***", "/key/stage.exe", "/password/x"]


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
