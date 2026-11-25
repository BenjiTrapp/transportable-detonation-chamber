# Netzwerk-Analyse (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** TDC liest Netzwerkverkehr aus einem pcap, zerlegt ihn in Events, bewertet Verhalten über Zeit, prüft YAML-Regeln dagegen und zeigt das Ergebnis in einem NETWORK-Tab — ohne Fake-Internet, ohne VM.

**Architecture:** Eine Kette flacher Module in `webui/` nach dem Muster der bestehenden (`net_events` → `net_flows` → Protokoll-Parser → `net_behavior` → `net_rules` → `net_analyze`). Befunde gehen als `evidence_findings` in das bestehende `memory_evidence`-Modell, das dafür um Verdrängung zwischen Arten und einen Beobachtungsfaktor erweitert wird. Die UI folgt dem Muster des LOGS-Tabs: Flask-Endpoint, JSON, clientseitiges Rendern in `app.js`.

**Tech Stack:** Python 3.9-kompatibel, Flask, `dpkt` (pcap, neu), `pyyaml` (Regeln, neu), `pefile` (vorhanden); Vanilla JS ohne Build-Step; pytest.

**Spec:** `docs/superpowers/specs/2026-11-25-fake-internet-design.md`

## Global Constraints

- **Python 3.9-kompatibel.** Das lokale venv ist 3.9.6, die CI nutzt 3.12. Kein `match`, kein `X | Y` in Annotationen, kein `dict[str, int]` ohne `from __future__ import annotations`.
- **Aus NetLens wird nichts übernommen** — kein Code, keine Regel, kein Fixture, keine Übersetzung. Siehe Spec, Abschnitt *Herkunft*.
- Neue Module liegen flach in `webui/` mit Prefix `net_`, nach dem Muster von `memory_evidence.py`, `log_store.py`, `pipe_analysis.py`.
- Modul-Docstring nennt, was das Modul löst und welche Fehlannahme es vermeidet — Stil von `webui/memory_evidence.py:1-27`.
- Tests nutzen das `tdc`-Fixture aus `tests/conftest.py`; Test-Docstrings führen „Regressions covered" wie `tests/test_memory.py:1-12`.
- Frontend: HTML-Strings nur über `escapeHtml()`, `cssToken()`, `jsArg()`; Farben nur über `themeColor()`; Werte in `style.css :root` **und** `theme-cyberpunk.css :root[data-theme="cyberpunk"]`, Formen in `theme-layout.css` mit `[data-theme]`-Prefix.
- Asset-Versionen `?v=` in `index.html:22-24` und `:1622` hochzählen, sobald CSS oder JS sich ändert (`tests/test_frontend.py:147`).
- Jede neue Route genau einmal in die README-API-Tabelle (`tests/test_docs.py:25`); neue Dateien in alle drei Deploy-Pfade: `scripts/deploy-utm.py:39-55`, `Makefile` Target `deploy`, `make.ps1` Block `'deploy'` (`tests/test_docs.py:72`).
- Keine Bytes aus einem pcap werden ausgeführt oder geöffnet; extrahierte Dateien heißen `.bin`.

## Review Focus

Fünf Eingaben, die die Spec voraussetzt, ohne sie zu nennen. Jede bekommt ihren Test im zuständigen Task.

1. **Abgeschnittener oder beschädigter pcap** — halbe Pakete, falsche Längenfelder, Datei endet mitten im Record. Erwartung: Analyse liefert, was lesbar war, und meldet den Abbruch; kein Traceback. → Task 2.
2. **TCP-Strom mit Lücken, Retransmits und vertauschter Reihenfolge** — Erwartung: der Parser arbeitet mit dem, was da ist, markiert die Lücke und erfindet nichts. → Task 2.
3. **Binärdaten, wo Text erwartet wird** — Nicht-UTF-8 in Headern, Hostnamen, Formularfeldern. Erwartung: nichts wirft, das Feld wird als Bytes gekennzeichnet. → Task 8.
4. **Fehlerhafte Regeldatei** — ungültiger Regex, unbekanntes Feld, `requires` auf eine Regel-ID, die es nicht gibt. Erwartung: die Datei wird mit Grund abgelehnt, die übrigen Regeln laufen weiter. → Task 10.
5. **Ein Lauf ohne Netzwerkverkehr** — Erwartung: „nichts beobachtet" ist von „beobachtet und nichts gefunden" unterscheidbar, wie `aether.observed is False` es in `_compute_verdict` (`webui/app.py:4745`) schon trennt. → Task 13.

---

## File Structure

| Datei | Verantwortung |
|---|---|
| `webui/net_events.py` | Event-Schema: Typen, Pflichtfelder, Normalisierung, Zeitordnung |
| `webui/net_flows.py` | pcap lesen, Pakete zu Flows bündeln, TCP-Streams zusammensetzen |
| `webui/net_dns.py` | DNS-Nachrichten zu `dns`-Events |
| `webui/net_http.py` | HTTP/1.x-Streams zu `http`-, `download`-, `upload`-Events |
| `webui/net_tls.py` | ClientHello/ServerHello, SNI, JA3, JA4, Zertifikate |
| `webui/net_mail_ftp.py` | FTP- und SMTP-Sitzungen, Zugangsdaten, Übertragungen |
| `webui/net_raw.py` | Unbekannte Protokolle profilieren |
| `webui/net_decode.py` | Base64, Hex, URL-Kodierung — nur wenn das Ergebnis sinnvoll ist |
| `webui/net_behavior.py` | Verhalten über Zeit: Beaconing, Retries, Rotation, Fanout, DGA |
| `webui/net_rules.py` | YAML-Regeln laden, prüfen, auswerten, korrelieren |
| `webui/net_baseline.py` | Netzwerk-Baseline einer sauberen Maschine |
| `webui/net_analyze.py` | Orchestrierung: pcap → Events → Verhalten → Regeln → Report |
| `webui/net_evidence.py` | Netzwerk-Befunde zu `MemoryFinding`-Objekten |
| `webui/memory_evidence.py` | **ändern**: neue Arten, Verdrängung, Beobachtungsfaktor |
| `webui/app.py` | **ändern**: Endpoints für Import, Report, Baseline |
| `rules/network/default.yaml` | Startregelsatz |
| `webui/templates/index.html`, `static/js/app.js`, CSS | **ändern**: NETWORK-Tab |

---

### Task 1: Event-Schema

**Files:**
- Create: `webui/net_events.py`
- Test: `tests/test_net_events.py`

**Interfaces:**
- Consumes: nichts
- Produces: `EVENT_TYPES` (tuple of str), `NetEvent(dict)` mit `__init__(self, type, ts, process="", pid=None, dest="", **fields)`, `sort_events(events) -> list`, `event_summary(events) -> dict` (Zähler je Typ)

Die Pflichtfelder jedes Events: `type`, `ts` (float, Unix-Sekunden), `process`, `pid`, `dest`, `dest_is_ip` (bool), `port`, `in_tree` (bool). Typen: `dns conn conn_failed tls http udp raw ftp smtp websocket download upload decoded beacon retry fanout`.

`in_tree` bleibt in dieser Phase immer `False`: ein pcap allein weiß nichts über Prozesse. Das Feld existiert trotzdem, weil Phase 2 es füllt und die Regeln und die UI schon darauf verweisen können.

- [ ] **Step 1: Write the failing tests**

```python
def test_event_carries_the_mandatory_fields():
    e = net_events.NetEvent("dns", 1700000000.5, process="a.exe", pid=42,
                            dest="evil.top", query_type="A")
    assert e["type"] == "dns" and e["pid"] == 42
    assert e["dest_is_ip"] is False
    assert e["in_tree"] is False
    assert e["query_type"] == "A"

def test_an_ip_destination_is_marked_as_one():
    assert net_events.NetEvent("conn", 1.0, dest="203.0.113.9")["dest_is_ip"] is True
    assert net_events.NetEvent("conn", 1.0, dest="evil.top")["dest_is_ip"] is False

def test_an_unknown_type_is_rejected():
    with pytest.raises(ValueError):
        net_events.NetEvent("teleport", 1.0)

def test_events_sort_by_time_and_keep_insertion_order_on_ties():
    a = net_events.NetEvent("dns", 2.0, dest="b")
    b = net_events.NetEvent("dns", 1.0, dest="a")
    c = net_events.NetEvent("conn", 1.0, dest="c")
    assert [e["dest"] for e in net_events.sort_events([a, b, c])] == ["a", "c", "b"]

def test_summary_counts_each_type():
    evs = [net_events.NetEvent("dns", 1.0), net_events.NetEvent("dns", 2.0),
           net_events.NetEvent("http", 3.0)]
    assert net_events.event_summary(evs) == {"dns": 2, "http": 1}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_events.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'net_events'`

- [ ] **Step 3: Implement `webui/net_events.py`**

`NetEvent` erbt von `dict` wie `MemoryFinding` (`webui/memory_evidence.py:238`), damit es direkt nach JSON serialisiert. `dest_is_ip` über `ipaddress.ip_address` in einem `try`. Stabile Sortierung über `enumerate`-Index als zweiten Schlüssel.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_events.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_events.py tests/test_net_events.py
git commit -m "feat(net): event schema for network analysis"
```

---

### Task 2: pcap lesen, Flows und TCP-Streams

**Files:**
- Create: `webui/net_flows.py`
- Test: `tests/test_net_flows.py`, `tests/samples/` (erzeugte pcaps)

**Interfaces:**
- Consumes: Task 1
- Produces: `read_pcap(path) -> PcapResult`, `PcapResult` mit `.flows` (list of `Flow`), `.truncated` (bool), `.note` (str), `.packet_count` (int); `Flow` mit `.proto`, `.src`, `.sport`, `.dst`, `.dport`, `.first_ts`, `.last_ts`, `.client_bytes`, `.server_bytes`, `.gaps` (list of int), `.packets` (list of `(ts, direction, payload)`, `direction` ist `"c"` oder `"s"`), `.client_stream()`, `.server_stream()`

`.packets` trägt die Zeitstempel je Nachricht — Task 7 misst daraus Heartbeat-Abstände, was mit `first_ts`/`last_ts` allein nicht geht.

Deckt Review Focus 1 und 2.

- [ ] **Step 1: Write the failing tests**

Die Tests bauen ihre pcaps selbst mit `dpkt`, damit keine Binärdateien im Repo liegen; ein Helfer `_pcap(tmp_path, packets)` schreibt sie.

```python
def test_a_tcp_conversation_becomes_one_flow_per_direction(tmp_path):
    p = _pcap(tmp_path, _tcp_exchange(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"))
    r = net_flows.read_pcap(p)
    assert len(r.flows) == 1
    f = r.flows[0]
    assert f.dport == 80 and f.proto == "tcp"
    assert f.client_stream().startswith(b"GET /")
    assert f.server_stream().startswith(b"HTTP/1.1 200")

def test_out_of_order_segments_are_reassembled_in_sequence(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(2, b"world"), (1, b"hello ")]))
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"hello world"

def test_a_retransmitted_segment_is_not_duplicated(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"abc"), (1, b"abc"), (2, b"def")]))
    assert net_flows.read_pcap(p).flows[0].client_stream() == b"abcdef"

def test_a_missing_segment_leaves_a_recorded_gap(tmp_path):
    p = _pcap(tmp_path, _tcp_segments([(1, b"aaa"), (3, b"ccc")]))
    f = net_flows.read_pcap(p).flows[0]
    assert f.gaps and f.client_stream() == b"aaa"

def test_a_truncated_pcap_yields_what_was_readable(tmp_path):
    full = _pcap(tmp_path, _tcp_exchange(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"))
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(full.read_bytes()[:-12])
    r = net_flows.read_pcap(str(cut))
    assert r.truncated is True and r.note
    assert r.packet_count >= 1

def test_a_file_that_is_not_a_pcap_is_refused_with_a_reason(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"this is not a capture")
    r = net_flows.read_pcap(str(bad))
    assert r.flows == [] and "pcap" in r.note.lower()

def test_udp_packets_become_flows_too(tmp_path):
    p = _pcap(tmp_path, _udp_packet(53, b"\x00\x01"))
    assert net_flows.read_pcap(p).flows[0].proto == "udp"

def test_each_message_keeps_its_timestamp_and_direction(tmp_path):
    p = _pcap(tmp_path, _tcp_exchange(b"ping", b"pong", client_ts=10.0, server_ts=11.5))
    pk = net_flows.read_pcap(p).flows[0].packets
    assert [(d, bytes(pl)) for _, d, pl in pk] == [("c", b"ping"), ("s", b"pong")]
    assert [ts for ts, _, _ in pk] == [10.0, 11.5]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_flows.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'net_flows'`

- [ ] **Step 3: Add `dpkt>=1.9.8` to `webui/requirements.txt`**

- [ ] **Step 4: Implement `webui/net_flows.py`**

Reassembly: je Richtung ein Dict `seq -> payload`, am Ende nach Sequenznummer zusammensetzen; ein Segment, dessen Sequenznummer schon belegt ist und dessen Nutzlast gleich ist, wird verworfen. Fehlt ein Stück, endet der Strom dort und die Lücke wird in `gaps` vermerkt — nicht mit Nullbytes gefüllt. Flow-Schlüssel ist das sortierte Tupel `(src, sport, dst, dport, proto)`, damit beide Richtungen zusammenfinden. Lesefehler von `dpkt` fangen und in `truncated`/`note` übersetzen, nie weiterwerfen.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_flows.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add webui/net_flows.py webui/requirements.txt tests/test_net_flows.py
git commit -m "feat(net): read pcaps into reassembled flows"
```

---

### Task 3: DNS

**Files:**
- Create: `webui/net_dns.py`
- Test: `tests/test_net_dns.py`

**Interfaces:**
- Consumes: Tasks 1, 2
- Produces: `events_from_flow(flow) -> list` (von `NetEvent`), `is_dns(flow) -> bool`

`dns`-Events tragen zusätzlich: `query`, `query_type`, `answers` (list of str), `rcode` (str), `nxdomain` (bool).

- [ ] **Step 1: Write the failing tests**

```python
def test_a_query_and_its_answer_become_one_event():
    e = net_dns.events_from_flow(_dns_flow("evil.top", "A", ["203.0.113.9"]))[0]
    assert e["type"] == "dns" and e["query"] == "evil.top"
    assert e["answers"] == ["203.0.113.9"] and e["nxdomain"] is False

def test_nxdomain_is_marked():
    e = net_dns.events_from_flow(_dns_flow("gone.top", "A", [], rcode=3))[0]
    assert e["nxdomain"] is True and e["rcode"] == "NXDOMAIN"

def test_a_txt_answer_keeps_its_text():
    e = net_dns.events_from_flow(_dns_flow("c2.top", "TXT", ["cm0="]))[0]
    assert e["answers"] == ["cm0="] and e["query_type"] == "TXT"

def test_a_query_without_an_answer_is_still_an_event():
    assert net_dns.events_from_flow(_dns_flow("slow.top", "A", None))[0]["answers"] == []

def test_a_malformed_dns_payload_is_skipped_without_raising():
    assert net_dns.events_from_flow(_raw_udp_flow(53, b"\xff\xff\xff")) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_dns.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_dns.py`**

`dpkt.dns.DNS` zum Parsen; Antworten dem Query über die Transaktions-ID zuordnen. Ein Query ohne Antwort bleibt ein Event mit leerem `answers`. Jeder Parse-Fehler überspringt das Paket.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_dns.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_dns.py tests/test_net_dns.py
git commit -m "feat(net): DNS events from flows"
```

---

### Task 4: HTTP

**Files:**
- Create: `webui/net_http.py`
- Test: `tests/test_net_http.py`

**Interfaces:**
- Consumes: Tasks 1, 2
- Produces: `events_from_flow(flow) -> list`, `looks_like_http(stream) -> bool`, `ws_frames(stream) -> list`

`http`-Events tragen: `method`, `url`, `path`, `query`, `ua`, `headers` (dict), `header_order` (list of str), `body_text` (str or None), `body_bytes` (int), `form_names` (list of str), `status` (int or None), `resp_text`, `resp_bytes`, `content_type`. Ein Antwortkörper, der nach einer Datei aussieht, erzeugt zusätzlich ein `download`-Event mit `sha256`, `size`, `kind`; ein Anfragekörper über 512 Bytes ein `upload`-Event. Ein Upgrade auf WebSocket erzeugt ein `websocket`-Event mit `messages` (je `{direction, text, size}`).

`header_order` ist nicht Zierde: die Reihenfolge der Header geht in den Fingerprint (Phase 4).

- [ ] **Step 1: Write the failing tests**

```python
def test_a_get_becomes_an_event_with_path_and_user_agent():
    e = net_http.events_from_flow(_http_flow(
        b"GET /gate.php?id=7 HTTP/1.1\r\nHost: evil.top\r\nUser-Agent: curl/8\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))[0]
    assert e["method"] == "GET" and e["path"] == "/gate.php"
    assert e["query"] == "id=7" and e["ua"] == "curl/8"
    assert e["dest"] == "evil.top" and e["status"] == 200

def test_header_order_is_preserved():
    e = net_http.events_from_flow(_http_flow(
        b"GET / HTTP/1.1\r\nHost: a.top\r\nAccept: */*\r\nUser-Agent: x\r\n\r\n", b""))[0]
    assert e["header_order"] == ["Host", "Accept", "User-Agent"]

def test_a_post_form_exposes_its_field_names():
    e = net_http.events_from_flow(_http_flow(
        b"POST /api HTTP/1.1\r\nHost: evil.top\r\nContent-Length: 15\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\nhwid=A1&os=win",
        b"HTTP/1.1 200 OK\r\n\r\n"))[0]
    assert sorted(e["form_names"]) == ["hwid", "os"]

def test_two_requests_on_one_keep_alive_connection_become_two_events():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /a HTTP/1.1\r\nHost: x.top\r\n\r\nGET /b HTTP/1.1\r\nHost: x.top\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
    assert [e["path"] for e in evs if e["type"] == "http"] == ["/a", "/b"]
    assert [e["status"] for e in evs if e["type"] == "http"] == [200, 404]

def test_a_chunked_response_body_is_joined():
    e = net_http.events_from_flow(_http_flow(
        b"GET / HTTP/1.1\r\nHost: x.top\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n"))[0]
    assert e["resp_text"] == "abcdefg"

def test_an_executable_response_becomes_a_download_event():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /s.dll HTTP/1.1\r\nHost: evil.top\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMZ\x90\x00"))
    d = [e for e in evs if e["type"] == "download"][0]
    assert d["kind"] == "pe" and d["size"] == 4 and len(d["sha256"]) == 64

def test_a_large_request_body_becomes_an_upload_event():
    evs = net_http.events_from_flow(_http_flow(
        b"POST /up HTTP/1.1\r\nHost: evil.top\r\nContent-Length: 600\r\n\r\n" + b"x" * 600,
        b"HTTP/1.1 200 OK\r\n\r\n"))
    assert [e["type"] for e in evs if e["type"] == "upload"] == ["upload"]

def test_a_response_without_a_request_is_still_reported():
    evs = net_http.events_from_flow(_http_flow(b"", b"HTTP/1.1 200 OK\r\n\r\nhi"))
    assert evs and evs[0]["method"] == ""

def test_a_websocket_upgrade_and_its_frames_become_websocket_events():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n\r\n"
        + _ws_frame(b"ping"),
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        + _ws_frame(b"pong")))
    ws = [e for e in evs if e["type"] == "websocket"]
    assert ws and ws[0]["dest"] == "c2.top"
    assert [m["text"] for m in ws[0]["messages"]] == ["ping", "pong"]

def test_a_websocket_frame_with_binary_payload_is_kept_as_bytes():
    evs = net_http.events_from_flow(_http_flow(
        b"GET /ws HTTP/1.1\r\nHost: c2.top\r\nUpgrade: websocket\r\n\r\n"
        + _ws_frame(b"\xff\x00\xfe", opcode=2),
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n"))
    m = [e for e in evs if e["type"] == "websocket"][0]["messages"][0]
    assert m["text"] is None and m["size"] == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_http.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_http.py`**

Die Streams selbst zerlegen, nicht über `http.client`: ein Strom aus einem pcap ist unvollständig und soll das überleben. Anfragen und Antworten der Reihe nach paaren. `body_text` nur setzen, wenn der Körper als UTF-8 oder Latin-1 dekodierbar ist, sonst `None` bei gesetztem `body_bytes`. Dateityp über die ersten Bytes (`MZ`, `\x7fELF`, `PK`, `%PDF`); eine Obergrenze für behaltene Körper, damit ein 2-GB-Download nicht im Speicher landet.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_http.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_http.py tests/test_net_http.py
git commit -m "feat(net): HTTP events, downloads and uploads"
```

---

### Task 5: TLS mit JA3 und JA4

**Files:**
- Create: `webui/net_tls.py`
- Test: `tests/test_net_tls.py`

**Interfaces:**
- Consumes: Tasks 1, 2
- Produces: `events_from_flow(flow) -> list`, `ja3(client_hello) -> str`, `ja4(client_hello) -> str`

`tls`-Events tragen: `sni`, `version`, `ciphers` (list of int), `extensions` (list of int), `alpn` (list of str), `ja3`, `ja3_hash`, `ja4`, `cert_subject`, `cert_issuer`, `cert_not_after`, `self_signed` (bool).

JA3 ist festgelegt: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`, Werte mit `-` verbunden, GREASE-Werte entfernt, MD5 über den String. JA4 in der Form `t<ver><sni><nciphers><nextensions><alpn>_<hash12>_<hash12>`.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_server_name_is_read_from_the_client_hello():
    e = net_tls.events_from_flow(_tls_flow(sni="steamcommunity.com"))[0]
    assert e["type"] == "tls" and e["sni"] == "steamcommunity.com"
    assert e["dest"] == "steamcommunity.com"

def test_ja3_is_stable_for_the_same_hello():
    f = _tls_flow(sni="a.top")
    assert net_tls.events_from_flow(f)[0]["ja3_hash"] == net_tls.events_from_flow(f)[0]["ja3_hash"]

def test_ja3_differs_when_the_cipher_list_differs():
    a = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1301, 0x1302]))[0]
    b = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1302, 0x1301]))[0]
    assert a["ja3_hash"] != b["ja3_hash"]

def test_grease_values_do_not_change_ja3():
    plain = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1301]))[0]
    greased = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x0a0a, 0x1301]))[0]
    assert plain["ja3_hash"] == greased["ja3_hash"]

def test_ja4_reports_sni_presence_and_counts():
    e = net_tls.events_from_flow(_tls_flow(sni="a.top", ciphers=[0x1301, 0x1302]))[0]
    assert e["ja4"].startswith("t") and "d" in e["ja4"][:5]

def test_a_self_signed_certificate_is_flagged():
    e = net_tls.events_from_flow(_tls_flow(sni="a.top", cert=("CN=a.top", "CN=a.top")))[0]
    assert e["self_signed"] is True

def test_a_hello_that_is_cut_short_does_not_raise():
    assert net_tls.events_from_flow(_tls_flow(sni="a.top", truncate=20)) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_tls.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_tls.py`**

Das ClientHello von Hand aus dem Strom lesen (Record-Header, Handshake-Header, dann die Felder); `dpkt.ssl` hilft beim Record-Rahmen. GREASE sind die Werte `0x?a?a` mit gleichen Nibbles. Zertifikate über `cryptography.x509` lesen, wenn das Server-Zertifikat im Strom steht; `self_signed` ist Subject gleich Issuer.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_tls.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_tls.py tests/test_net_tls.py
git commit -m "feat(net): TLS events with JA3 and JA4"
```

---

### Task 6: FTP und SMTP

**Files:**
- Create: `webui/net_mail_ftp.py`
- Test: `tests/test_net_mail_ftp.py`

**Interfaces:**
- Consumes: Tasks 1, 2
- Produces: `events_from_flow(flow) -> list`

`ftp`-Events tragen `user`, `password`, `commands` (list of str), `files` (list of str); `smtp`-Events `mail_from`, `rcpt_to` (list), `subject`, `user`, `password`, `body_bytes`, `attachments` (list of str).

Zugangsdaten im Klartext sind ein eigener Befund (Task 12, `credential_in_transit`) — deshalb werden sie erfasst, aber im Report maskiert ausgegeben.

- [ ] **Step 1: Write the failing tests**

```python
def test_ftp_credentials_and_commands_are_captured():
    e = net_mail_ftp.events_from_flow(_line_flow(21,
        b"USER bot\r\nPASS s3cret\r\nSTOR log.txt\r\n", b"220 ok\r\n331 ok\r\n230 ok\r\n150 ok\r\n"))[0]
    assert e["type"] == "ftp" and e["user"] == "bot" and e["password"] == "s3cret"
    assert "log.txt" in e["files"]

def test_smtp_envelope_and_subject_are_captured():
    e = net_mail_ftp.events_from_flow(_line_flow(25,
        b"EHLO x\r\nMAIL FROM:<a@evil.top>\r\nRCPT TO:<b@drop.top>\r\nDATA\r\n"
        b"Subject: logs\r\n\r\nbody\r\n.\r\n", b"220 ok\r\n250 ok\r\n250 ok\r\n250 ok\r\n354 go\r\n"))[0]
    assert e["type"] == "smtp" and e["mail_from"] == "a@evil.top"
    assert e["rcpt_to"] == ["b@drop.top"] and e["subject"] == "logs"

def test_smtp_auth_login_credentials_are_decoded():
    e = net_mail_ftp.events_from_flow(_line_flow(587,
        b"AUTH LOGIN\r\nYm90\r\nczNjcmV0\r\n", b"334 x\r\n334 y\r\n235 ok\r\n"))[0]
    assert e["user"] == "bot" and e["password"] == "s3cret"

def test_an_incomplete_session_yields_what_was_seen():
    e = net_mail_ftp.events_from_flow(_line_flow(21, b"USER bot\r\n", b"220 ok\r\n"))[0]
    assert e["user"] == "bot" and e["password"] == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_mail_ftp.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_mail_ftp.py`**

Beide Protokolle sind zeilenbasiert; ein Zustandsautomat je Richtung reicht. `AUTH LOGIN` überträgt Benutzer und Passwort als zwei Base64-Zeilen nach den `334`-Antworten.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_mail_ftp.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_mail_ftp.py tests/test_net_mail_ftp.py
git commit -m "feat(net): FTP and SMTP sessions"
```

---

### Task 7: Unbekannte Protokolle profilieren

**Files:**
- Create: `webui/net_raw.py`
- Test: `tests/test_net_raw.py`

**Interfaces:**
- Consumes: Tasks 1, 2
- Produces: `events_from_flow(flow) -> list`

`raw`-Events tragen: `framing` (`"length-prefixed"`, `"delimited"`, `"fixed"`, `"unknown"`), `delimiter` (bytes or None), `message_sizes` (list of int), `entropy` (float), `printable_ratio` (float), `heartbeat` (bool), `interval` (float or None).

Das ist, was von einem C2 bleibt, dessen Protokoll niemand kennt — und oft genug reicht es zur Wiedererkennung.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_length_prefixed_stream_is_recognized():
    e = net_raw.events_from_flow(_raw_flow(b"\x00\x03abc\x00\x04defg"))[0]
    assert e["framing"] == "length-prefixed" and e["message_sizes"] == [3, 4]

def test_a_newline_delimited_stream_is_recognized():
    e = net_raw.events_from_flow(_raw_flow(b"one\ntwo\nthree\n"))[0]
    assert e["framing"] == "delimited" and e["delimiter"] == b"\n"

def test_high_entropy_is_reported():
    e = net_raw.events_from_flow(_raw_flow(os.urandom(4096)))[0]
    assert e["entropy"] > 7.5 and e["printable_ratio"] < 0.5

def test_text_traffic_reports_low_entropy_and_high_printability():
    e = net_raw.events_from_flow(_raw_flow(b"hello world " * 200))[0]
    assert e["entropy"] < 5.0 and e["printable_ratio"] > 0.9

def test_regular_small_messages_count_as_a_heartbeat():
    e = net_raw.events_from_flow(_raw_flow_timed([(t * 30.0, b"\x01") for t in range(6)]))[0]
    assert e["heartbeat"] is True and abs(e["interval"] - 30.0) < 1.0

def test_an_empty_stream_produces_no_event():
    assert net_raw.events_from_flow(_raw_flow(b"")) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_raw.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_raw.py`**

Shannon-Entropie über die Bytehäufigkeit. Längenpräfix erkennen, indem die ersten zwei oder vier Bytes als Länge gelesen werden und geprüft wird, ob die Kette dadurch sauber aufgeht. Trennzeichen: der häufigste Nicht-Druckbare oder `\n`, wenn er die Nachrichten gleichmäßig teilt. Heartbeat wie in `memory_evidence.beaconing_from_connections` (`:490`) über den Variationskoeffizienten der Abstände.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_raw.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_raw.py tests/test_net_raw.py
git commit -m "feat(net): profile unknown protocols"
```

---

### Task 8: Dekodierung

**Files:**
- Create: `webui/net_decode.py`
- Test: `tests/test_net_decode.py`

**Interfaces:**
- Consumes: Task 1
- Produces: `decode(value) -> Decoded or None`, `Decoded` mit `.scheme`, `.text`, `.bytes`, `.kind`; `decode_event_fields(event) -> list` (von `decoded`-Events)

Entscheidend ist, **wann nicht** dekodiert wird: nur wenn das Ergebnis Text oder ein bekannter Dateityp ist. Sonst ist jede Hex-Zeichenkette plötzlich „dekodiert". Deckt Review Focus 3.

- [ ] **Step 1: Write the failing tests**

```python
def test_base64_that_yields_text_is_decoded():
    d = net_decode.decode("aGVsbG8gd29ybGQ=")
    assert d.scheme == "base64" and d.text == "hello world"

def test_base64_that_yields_noise_is_not_decoded():
    assert net_decode.decode("3q2+7w3q2+7w3q2+7w==") is None

def test_base64_that_yields_a_pe_is_decoded_as_a_file():
    d = net_decode.decode(base64.b64encode(b"MZ\x90\x00" + b"\x00" * 60).decode())
    assert d.scheme == "base64" and d.kind == "pe"

def test_hex_that_yields_text_is_decoded():
    assert net_decode.decode("68656c6c6f").text == "hello"

def test_url_encoding_is_decoded():
    assert net_decode.decode("a%20b%26c").text == "a b&c"

def test_a_short_value_is_left_alone():
    assert net_decode.decode("abcd") is None

def test_binary_input_does_not_raise():
    assert net_decode.decode(b"\xff\xfe\x00\x01" * 8) is None

def test_decoding_walks_the_fields_of_an_http_event():
    e = net_events.NetEvent("http", 1.0, dest="evil.top", method="POST",
                            body_text="data=aGVsbG8gd29ybGQ=")
    out = net_decode.decode_event_fields(e)
    assert [d["type"] for d in out] == ["decoded"]
    assert out[0]["text"] == "hello world" and out[0]["field"] == "body_text"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_decode.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_decode.py`**

„Sinnvoll" heißt: der Anteil druckbarer Zeichen liegt über einer Schwelle, oder die ersten Bytes treffen eine bekannte Dateisignatur. Mindestlänge für einen Versuch, damit kurze Wörter nicht zufällig als Base64 durchgehen. Bytes-Eingaben vor dem Dekodieren verlustfrei nach Latin-1 bringen, statt eine Ausnahme zu riskieren.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_decode.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_decode.py tests/test_net_decode.py
git commit -m "feat(net): decode encoded fields when the result is meaningful"
```

---

### Task 9: Verhalten über Zeit

**Files:**
- Create: `webui/net_behavior.py`
- Test: `tests/test_net_behavior.py`

**Interfaces:**
- Consumes: Tasks 1, 3, 4
- Produces: `analyze(events) -> list` (von `beacon`-, `retry`-, `fanout`-Events), `periodicity(timestamps) -> dict` mit `interval`, `jitter`, `cov`, `periodic` (bool)

Ein einzelner Verbindungsversuch sagt nichts; die Wiederholung sagt alles. Schwellen wie in `memory_evidence.beaconing_from_connections` (`:490`): mindestens vier Verbindungen, Variationskoeffizient bis 0.5.

- [ ] **Step 1: Write the failing tests**

```python
def test_regular_check_ins_become_a_beacon_event():
    evs = [net_events.NetEvent("http", t * 60.0, dest="c2.top", pid=9) for t in range(6)]
    b = [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"][0]
    assert abs(b["interval"] - 60.0) < 1.0 and b["dest"] == "c2.top"

def test_jitter_is_measured_not_assumed():
    ts = [0, 60, 125, 183, 245, 307]
    evs = [net_events.NetEvent("http", float(t), dest="c2.top", pid=9) for t in ts]
    b = [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"][0]
    assert 0.0 < b["jitter"] < 0.3

def test_three_connections_are_not_enough_for_a_beacon():
    evs = [net_events.NetEvent("http", t * 60.0, dest="c2.top") for t in range(3)]
    assert [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"] == []

def test_irregular_traffic_is_not_a_beacon():
    ts = [0, 3, 400, 405, 1200, 1201]
    evs = [net_events.NetEvent("http", float(t), dest="c2.top") for t in ts]
    assert [e for e in net_behavior.analyze(evs) if e["type"] == "beacon"] == []

def test_repeated_failures_to_one_endpoint_become_a_retry_event():
    evs = [net_events.NetEvent("conn_failed", t * 10.0, dest="dead.top") for t in range(5)]
    r = [e for e in net_behavior.analyze(evs) if e["type"] == "retry"][0]
    assert r["dest"] == "dead.top" and r["attempts"] == 5

def test_the_same_path_on_many_hosts_becomes_a_fanout_event():
    evs = [net_events.NetEvent("http", float(i), dest="h%d.top" % i, path="/gate.php")
           for i in range(5)]
    f = [e for e in net_behavior.analyze(evs) if e["type"] == "fanout"][0]
    assert f["path"] == "/gate.php" and f["hosts"] == 5

def test_an_nxdomain_burst_is_reported_as_fanout_of_failures():
    evs = [net_events.NetEvent("dns", float(i), dest="x%d.top" % i, nxdomain=True)
           for i in range(12)]
    assert any(e["type"] == "fanout" and e.get("nxdomain") for e in net_behavior.analyze(evs))

def test_no_events_produce_no_behavior():
    assert net_behavior.analyze([]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_behavior.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_behavior.py`**

Gruppieren nach `(pid, dest)` für Beaconing, nach `dest` für Retries, nach `path` für Fanout. `jitter` ist der Variationskoeffizient, als Anteil ausgegeben; `periodic` ist wahr, wenn mindestens vier Abstände vorliegen und der Koeffizient unter der Schwelle bleibt.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_behavior.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/net_behavior.py tests/test_net_behavior.py
git commit -m "feat(net): beaconing, retries and fanout over time"
```

---

### Task 10: Regel-Engine

**Files:**
- Create: `webui/net_rules.py`
- Test: `tests/test_net_rules.py`

**Interfaces:**
- Consumes: Task 1
- Produces: `load_rules(paths) -> RuleSet`, `RuleSet` mit `.rules` (list of `Rule`), `.errors` (list of str), `.lists`; `RuleSet.evaluate(events) -> list` (von `RuleHit`). `Rule` und `RuleHit` erben beide von `dict`, wie `MemoryFinding` (`webui/memory_evidence.py:238`), damit Report und Regelübersicht direkt nach JSON serialisieren. `Rule` trägt die Schlüssel der YAML-Regel (`id`, `name`, `severity`, `role`, `behavior`, `attack`, `family`, `kind`); `RuleHit` zusätzlich `rule_id`, `events` (list), `process`

Operatoren: Gleichheit (Wert oder Liste), `|re`, `|contains`, `|startswith`, `|endswith`, `|in`, `|gte`, `|lte`, `|gt`, `|lt`, `|count_gte`, `|has_all`; Blöcke `any`, `all`, `not`; Listen über `$name`; Korrelation über `requires: [[a, b], [c]]` — aus jeder Gruppe muss eine Regel für denselben Prozess getroffen haben.

Die Liste `known_good` ist vordefiniert: Events, deren Ziel darin steht, sind für jede Regel unsichtbar, solange die Regel nicht `include_known_good: true` setzt. Ohne das kann Task 11 nicht verlangen, dass gewöhnlicher Windows-Verkehr nichts auslöst, und die Spec nennt die Unterdrückung bekannter Infrastruktur ausdrücklich.

Ein optionales `kind:` ordnet den Treffer einer Evidence-Art zu; die Art bestimmt das Gewicht, nicht die Regel (Spec, *Analyse, Events und Regeln*). Deckt Review Focus 4.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_rule_matches_an_event_field():
    rs = _rules("""
rules:
  - id: gate
    name: Panel request
    event: http
    match: {method: POST, path|re: '^/gate\\\\d*\\\\.php$'}
    severity: high
""")
    hits = rs.evaluate([net_events.NetEvent("http", 1.0, dest="e.top",
                                            method="POST", path="/gate7.php")])
    assert [h["rule_id"] for h in hits] == ["gate"]

def test_a_hit_serializes_to_json():
    rs = _rules("rules:\n  - {id: g, name: g, event: http, match: {method: GET}}")
    hit = rs.evaluate([net_events.NetEvent("http", 1.0, method="GET")])[0]
    assert json.loads(json.dumps(hit))["rule_id"] == "g"

def test_a_rule_that_does_not_match_produces_nothing():
    rs = _rules("rules:\n  - {id: x, name: x, event: http, match: {method: PUT}}")
    assert rs.evaluate([net_events.NetEvent("http", 1.0, method="GET")]) == []

def test_a_named_list_is_resolved():
    rs = _rules("""
lists:
  bad: [evil.top, worse.top]
rules:
  - {id: l, name: l, event: dns, match: {dest|in: $bad}}
""")
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="worse.top")])) == 1

def test_known_good_destinations_are_invisible_to_rules():
    rs = _rules("""
lists:
  known_good: [www.msftconnecttest.com]
rules:
  - {id: any_dns, name: any, event: dns, match: {}}
""")
    assert rs.evaluate([net_events.NetEvent("dns", 1.0, dest="www.msftconnecttest.com")]) == []
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="evil.top")])) == 1

def test_a_rule_may_opt_into_known_good():
    rs = _rules("""
lists:
  known_good: [www.msftconnecttest.com]
rules:
  - {id: ncsi, name: ncsi, event: dns, match: {}, include_known_good: true}
""")
    assert len(rs.evaluate([net_events.NetEvent("dns", 1.0, dest="www.msftconnecttest.com")])) == 1

def test_any_all_and_not_blocks_compose():
    rs = _rules("""
rules:
  - id: c
    name: c
    event: http
    match:
      any: [{dest: a.top}, {dest: b.top}]
      not: {path: /ok}
""")
    evs = [net_events.NetEvent("http", 1.0, dest="a.top", path="/x"),
           net_events.NetEvent("http", 2.0, dest="a.top", path="/ok"),
           net_events.NetEvent("http", 3.0, dest="z.top", path="/x")]
    assert len(rs.evaluate(evs)) == 1

def test_count_gte_counts_matching_events():
    rs = _rules("rules:\n  - {id: n, name: n, event: dns, match: {nxdomain: true}, count_gte: 3}")
    few = [net_events.NetEvent("dns", float(i), dest="x", nxdomain=True) for i in range(2)]
    many = [net_events.NetEvent("dns", float(i), dest="x", nxdomain=True) for i in range(4)]
    assert rs.evaluate(few) == [] and len(rs.evaluate(many)) == 1

def test_a_correlation_rule_needs_one_hit_from_each_group():
    rs = _rules("""
rules:
  - {id: dl, name: dl, event: download, match: {kind: pe}}
  - {id: bc, name: bc, event: beacon, match: {}}
  - {id: chain, name: chain, requires: [[dl], [bc]], severity: critical}
""")
    only_dl = [net_events.NetEvent("download", 1.0, process="a.exe", kind="pe")]
    both = only_dl + [net_events.NetEvent("beacon", 2.0, process="a.exe")]
    assert "chain" not in [h["rule_id"] for h in rs.evaluate(only_dl)]
    assert "chain" in [h["rule_id"] for h in rs.evaluate(both)]

def test_a_rule_may_name_an_evidence_kind():
    rs = _rules("rules:\n  - {id: k, name: k, event: upload, match: {}, kind: exfil_upload}")
    assert rs.evaluate([net_events.NetEvent("upload", 1.0)])[0]["kind"] == "exfil_upload"

def test_an_invalid_regex_is_reported_and_the_other_rules_still_run():
    rs = _rules("""
rules:
  - {id: broken, name: b, event: http, match: {path|re: '([unclosed'}}
  - {id: fine, name: f, event: http, match: {method: GET}}
""")
    assert any("broken" in e for e in rs.errors)
    assert [h["rule_id"] for h in rs.evaluate([net_events.NetEvent("http", 1.0, method="GET")])] == ["fine"]

def test_an_unknown_operator_is_reported():
    rs = _rules("rules:\n  - {id: u, name: u, event: http, match: {path|sideways: x}}")
    assert any("sideways" in e for e in rs.errors) and rs.rules == []

def test_requires_on_an_unknown_rule_id_is_reported():
    rs = _rules("rules:\n  - {id: c, name: c, requires: [[ghost]]}")
    assert any("ghost" in e for e in rs.errors)

def test_broken_yaml_is_reported_without_raising(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("rules: [this: is: not: yaml")
    rs = net_rules.load_rules([str(p)])
    assert rs.errors and rs.rules == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_rules.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Add `pyyaml>=6.0` to `webui/requirements.txt`**

- [ ] **Step 4: Implement `webui/net_rules.py`**

Regeln beim Laden einmal prüfen und übersetzen: Regex kompilieren, Operatoren auflösen, Listen einsetzen, `requires` gegen die bekannten IDs halten. Was nicht trägt, wandert mit Grund nach `errors` und wird übersprungen — eine kaputte Regel darf die Datei nicht unbrauchbar machen. Korrelationsregeln laufen in einem zweiten Durchgang über die Treffer des ersten, gruppiert nach Prozess.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_rules.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add webui/net_rules.py webui/requirements.txt tests/test_net_rules.py
git commit -m "feat(net): YAML rule engine for network events"
```

---

### Task 11: Startregelsatz

**Files:**
- Create: `rules/network/default.yaml`
- Test: `tests/test_net_default_rules.py`

**Interfaces:**
- Consumes: Task 10
- Produces: eine Regeldatei, die `load_rules` ohne Fehler lädt

Geschrieben aus eigenen Beobachtungen, nicht aus NetLens (Global Constraints). Enthalten sind mindestens: Abruf einer ausführbaren Datei über HTTP, POST an eine Pfadform wie `/gate.php`, Abfrage eines IP-Lookup-Dienstes, Zugangsdaten im Klartext über FTP oder SMTP, NXDOMAIN-Salve, periodische Check-ins, und eine Korrelationsregel „ausführbarer Download und danach Beaconing". Dazu die Liste `known_good` mit den Namen, die auf einer Windows-Maschine ohnehin auftreten.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_default_rules.py -v`
Expected: FAIL, Datei fehlt

- [ ] **Step 3: Write `rules/network/default.yaml`**

Jede Regel trägt `id`, `name`, `severity`, `role`, `behavior`; `attack` und `family`, wo es zutrifft; `kind`, wo sie auf eine Evidence-Art zeigt. Regeln ignorieren `known_good`, solange sie nicht `include_known_good: true` setzen.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_default_rules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rules/network/default.yaml tests/test_net_default_rules.py
git commit -m "feat(net): starter rule set for network events"
```

---

### Task 12: Evidence-Modell erweitern

**Files:**
- Modify: `webui/memory_evidence.py` (`KINDS` ab `:100`, `score()` ab `:732`)
- Create: `webui/net_evidence.py`
- Test: `tests/test_net_evidence.py`, `tests/test_memory.py` (ergänzen)

**Interfaces:**
- Consumes: Tasks 1, 9, 10
- Produces: `net_evidence.findings_from(events, hits, process="", observed_fully=True) -> list` (von `memory_evidence.MemoryFinding`); in `memory_evidence`: neue Arten `c2_checkin`, `exfil_upload`, `credential_in_transit`, `fallback_rotation`, `dead_c2_retry`, `recon_service`, `tls_ja3_known`, `dga_pattern`, `payload_staging`, dazu `supersedes` in `KINDS` und ein Faktor `observation` in `score()`

Die Gewichte stehen in der Spec, Abschnitt *Einhängen in das Evidence-Modell*; `payload_staging` 4.0 steht unter *Stage-Sicherung*.

Zwei Erweiterungen an `score()`:

- **Verdrängung.** Ein Finding, dessen Art in `KINDS[andere]["supersedes"]` steht und für dieselben `(process, dest)` ein Finding jener anderen Art vorliegt, wandert nach `suppressed` mit `superseded_by`. `c2_checkin` verdrängt `c2_beaconing`: im abgeschotteten Modus belegen beide dieselbe Schleife, zusammen 7.0 bei 6.0 Schwelle.
- **Beobachtungsfaktor.** `score()` liest `f.get("observation", 1.0)` als dritten Faktor neben Persistenz und Bestätigung und schreibt ihn nach `factors["observation"]`. Bestehende Findings haben das Feld nicht und bleiben bei 1.0 — die Memory- und Pipe-Verdicts dürfen sich nicht verschieben.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_memory.py — die bestehenden Verdicts dürfen sich nicht ändern
def test_existing_findings_keep_their_score_without_an_observation_factor(tdc):
    f = tdc.memory_evidence.MemoryFinding("aether", "reflective_pe", "a.exe")
    assert tdc.memory_evidence.score([f])["findings"][0]["factors"]["observation"] == 1.0

def test_an_observation_factor_below_one_lowers_the_contribution(tdc):
    me = tdc.memory_evidence
    full = me.score([me.MemoryFinding("net", "exfil_upload", "a.exe")])["score"]
    half = me.score([me.MemoryFinding("net", "exfil_upload", "a.exe",
                                      extra={"observation": 0.5})])["score"]
    assert half < full

def test_a_checkin_supersedes_beaconing_for_the_same_process_and_host(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe", extra={"dest": "c2.top"})
    ck = me.MemoryFinding("net", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    out = me.score([bc, ck])
    assert [f["kind"] for f in out["findings"]] == ["c2_checkin"]
    assert out["suppressed"][0]["superseded_by"] == "c2_checkin"

def test_beaconing_to_another_host_is_not_superseded(tdc):
    me = tdc.memory_evidence
    bc = me.MemoryFinding("sysmon", "c2_beaconing", "a.exe", extra={"dest": "other.top"})
    ck = me.MemoryFinding("net", "c2_checkin", "a.exe", extra={"dest": "c2.top"})
    assert len(me.score([bc, ck])["findings"]) == 2

# tests/test_net_evidence.py
def test_a_rule_hit_with_a_kind_becomes_a_finding():
    hits = [_hit("x", kind="exfil_upload", process="a.exe")]
    f = net_evidence.findings_from([], hits, process="a.exe")[0]
    assert f["kind"] == "exfil_upload" and f["source"] == "network"

def test_a_rule_hit_without_a_kind_produces_no_finding():
    assert net_evidence.findings_from([], [_hit("x", kind=None)]) == []

def test_a_beacon_event_becomes_a_checkin_finding():
    evs = [net_events.NetEvent("beacon", 1.0, process="a.exe", dest="c2.top", interval=60.0)]
    kinds = [f["kind"] for f in net_evidence.findings_from(evs, [], process="a.exe")]
    assert "c2_checkin" in kinds

def test_an_isolated_run_marks_its_findings_as_partly_observed():
    evs = [net_events.NetEvent("upload", 1.0, process="a.exe", dest="c2.top", body_bytes=4096)]
    f = net_evidence.findings_from(evs, [], process="a.exe", observed_fully=False)[0]
    assert f["observation"] < 1.0

def test_the_same_phenomenon_is_not_reported_twice():
    evs = [net_events.NetEvent("beacon", 1.0, process="a.exe", dest="c2.top", interval=60.0)]
    hits = [_hit("beaconing", kind="c2_checkin", process="a.exe")]
    out = net_evidence.findings_from(evs, hits, process="a.exe")
    assert len([f for f in out if f["kind"] == "c2_checkin"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_evidence.py tests/test_memory.py -v`
Expected: FAIL — neue Arten fehlen, `factors["observation"]` fehlt

- [ ] **Step 3: Extend `KINDS` and `score()` in `webui/memory_evidence.py`**

Die neun Arten mit den Gewichten aus der Spec; `supersedes: ("c2_beaconing",)` auf `c2_checkin`. In `score()` den Verdrängungsdurchgang vor der Bewertung (er entscheidet, was überhaupt bewertet wird) und `observation` als dritten Faktor in `confidence`.

- [ ] **Step 4: Implement `webui/net_evidence.py`**

Findings aus zwei Quellen: Events mit eindeutiger Bedeutung (`beacon`, `upload`, `retry`, `fanout`, `download`) und Regeltreffer mit `kind`. Gleiche `(kind, process, dest)` nur einmal; `observation` unter 1.0, wenn `observed_fully` falsch ist, weil im abgeschotteten Modus unser eigener Server die Daten annahm.

- [ ] **Step 5: Run the full suite — the existing verdicts must not move**

Run: `python -m pytest tests/test_memory.py tests/test_net_evidence.py tests/test_attribution.py -v`
Expected: PASS, keine bestehende Zusicherung geändert

- [ ] **Step 6: Commit**

```bash
git add webui/memory_evidence.py webui/net_evidence.py tests/test_net_evidence.py tests/test_memory.py
git commit -m "feat(net): network findings in the shared evidence model"
```

---

### Task 13: Baseline und Orchestrierung

**Files:**
- Create: `webui/net_baseline.py`, `webui/net_analyze.py`
- Test: `tests/test_net_analyze.py`

**Interfaces:**
- Consumes: Tasks 1-12
- Produces: `net_baseline.NetBaseline(path)` mit `.knows(key)`, `.knows_dest(dest)`, `.add(events)`, `.count` — Namen wie `memory_evidence.MemoryBaseline` (`:668`, `:695`), damit beide gleich zu bedienen sind; `net_analyze.analyze_pcap(path, rules=None, baseline=None, process="", mode="online") -> dict`

Der Report: `{events, event_summary, behavior, rule_hits, evidence_findings, iocs, files, observed (bool), note, truncated, errors, suppressed_count}`.

`mode` bildet auf `observed_fully` von Task 12 ab: `"online"` → `True`, `"isolated"` → `False`. Im abgeschotteten Modus hat unser eigener Server die Daten angenommen, das belegt den Versuch und nicht den Erfolg.

`observed` trennt „nichts beobachtet" von „beobachtet und nichts gefunden", wie `_compute_verdict` es für Aether tut (`webui/app.py:4745`). Deckt Review Focus 5.

- [ ] **Step 1: Write the failing tests**

```python
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

def test_a_rule_file_with_errors_does_not_stop_the_analysis(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - {id: x, name: x, event: http, match: {p|nope: 1}}")
    r = net_analyze.analyze_pcap(_pcap_with_http_c2(tmp_path), rules=[str(bad)])
    assert r["errors"] and r["event_summary"]["http"] >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_analyze.py -v`
Expected: FAIL, `ModuleNotFoundError`

- [ ] **Step 3: Implement `webui/net_baseline.py`**

Nach dem Muster von `memory_evidence.MemoryBaseline` (`:613-731`): JSON-Datei, `KEY_VERSION`, atomar geschrieben, eine Version alter Schlüssel wird verworfen statt falsch gelesen. `add()` nimmt Events statt Findings, `knows()` prüft den normalisierten Schlüssel, `knows_dest()` nur das Ziel.

- [ ] **Step 4: Implement `webui/net_analyze.py`**

Die Kette in einer Funktion: Flows lesen, je Flow den passenden Parser wählen (Port und Inhalt, nicht nur Port), Events sammeln, dekodieren, Verhalten rechnen, Regeln prüfen, Findings bauen, IOCs einsammeln. Dateien unter einem `.bin`-Namen aus Hash und Typ führen, nie öffnen. Jeder Parser-Fehler landet in `errors` und beendet nichts.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_analyze.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add webui/net_baseline.py webui/net_analyze.py tests/test_net_analyze.py
git commit -m "feat(net): network baseline and analysis pipeline"
```

---

### Task 14: API

**Files:**
- Modify: `webui/app.py`, `README.md`
- Test: `tests/test_net_api.py`

**Interfaces:**
- Consumes: Task 13
- Produces: `POST /api/network/import` (multipart `file`, optional `mode`) → Report; `GET /api/network/report?id=` → gespeicherter Report; `GET /api/network/reports` → Liste; `GET /api/network/baseline`, `POST /api/network/baseline/capture`

Reports werden über `_ResultStore` (`webui/app.py:6029`) gehalten, damit sie einen Neustart überleben — dasselbe Muster wie die Memory-Ergebnisse. Uploads nach dem Muster von `_save_scan_upload` (`:6375`) mit Pruning.

- [ ] **Step 1: Write the failing tests**

```python
def test_importing_a_pcap_returns_a_report(client, tmp_path):
    data = {"file": (open(_pcap_with_http_c2(tmp_path), "rb"), "c.pcap")}
    r = client.post("/api/network/import", data=data,
                    content_type="multipart/form-data")
    assert r.status_code == 200
    assert r.get_json()["event_summary"]["http"] >= 1

def test_a_report_can_be_fetched_again_by_id(client, tmp_path):
    data = {"file": (open(_pcap_with_http_c2(tmp_path), "rb"), "c.pcap")}
    rid = client.post("/api/network/import", data=data,
                      content_type="multipart/form-data").get_json()["id"]
    assert client.get("/api/network/report?id=%s" % rid).get_json()["id"] == rid

def test_importing_without_a_file_is_a_bad_request(client):
    assert client.post("/api/network/import").status_code == 400

def test_a_file_that_is_not_a_pcap_is_refused_with_a_reason(client, tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"nope")
    data = {"file": (open(str(p), "rb"), "x.pcap")}
    r = client.post("/api/network/import", data=data, content_type="multipart/form-data")
    assert r.status_code == 400 and "pcap" in r.get_json()["error"].lower()

def test_capturing_a_baseline_reports_what_it_learned(client, tmp_path):
    data = {"file": (open(_pcap_with_ncsi(tmp_path), "rb"), "b.pcap")}
    r = client.post("/api/network/baseline/capture", data=data,
                    content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_json()["count"] >= 1

def test_the_reports_list_is_newest_first(client, tmp_path):
    for name in ("a.pcap", "b.pcap"):
        client.post("/api/network/import",
                    data={"file": (open(_pcap_with_http_c2(tmp_path), "rb"), name)},
                    content_type="multipart/form-data")
    names = [r["filename"] for r in client.get("/api/network/reports").get_json()["reports"]]
    assert names[0] == "b.pcap"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_api.py -v`
Expected: FAIL, 404 auf den Routen

- [ ] **Step 3: Implement the endpoints in `webui/app.py`**

Der Import schreibt die Datei in ein Upload-Verzeichnis mit Pruning, ruft `net_analyze.analyze_pcap` und legt den Report über `_ResultStore` ab. Die Baseline hängt an einem Modul-Objekt wie `_memory_baseline` (`:290`), damit die Tests es ersetzen können.

- [ ] **Step 4: Register the baseline in `tests/conftest.py`**

Nach dem Muster von `_memory_baseline` (`tests/conftest.py:46`) auf eine Datei in `tmp_path` zeigen.

- [ ] **Step 5: Document the five routes in the README API table**

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_net_api.py tests/test_docs.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/app.py tests/test_net_api.py tests/conftest.py README.md
git commit -m "feat(net): endpoints for pcap import, reports and baseline"
```

---

### Task 15: NETWORK-Tab

**Files:**
- Modify: `webui/templates/index.html`, `webui/static/js/app.js`, `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`, `webui/static/css/theme-layout.css`, `README.md`
- Modify: `scripts/deploy-utm.py`, `Makefile`, `make.ps1` (nur falls neue Dateien entstehen)
- Test: `tests/test_net_ui.py`, `tests/test_theme.py` (Zählungen), `tests/test_docs.py`

**Interfaces:**
- Consumes: Task 14
- Produces: Tab `network` zwischen `pipes` und `sysmon`; Unterkarten `OVERVIEW CONNECTIONS DNS HTTP TLS FILES IOCs`; `networkTabShown()`, `renderNetworkReport(report)`, `renderNetworkPanel(results)` in `app.js`

`FINGERPRINT` gehört zu Phase 4 und bleibt hier weg. Das Submit-Panel (`renderNetworkPanel`) zeigt in dieser Phase, was ein importierter oder zugeordneter Report hergibt.

- [ ] **Step 1: Write the failing tests**

Die JS-Funktionen werden isoliert in Node geprüft. `_run_node(functions, script, prelude="")` aus `tests/test_frontend.py:44` nimmt eine **Liste** von Funktionsnamen — jede aufgerufene Hilfsfunktion muss mit hinein — und ein Script, das sein Ergebnis als JSON auf stdout schreibt.

```python
REPORT_FNS = ["renderNetworkReport", "escapeHtml", "cssToken"]

def _render(report):
    return _run_node(REPORT_FNS,
                     "console.log(JSON.stringify(renderNetworkReport(%s)))"
                     % json.dumps(report))

def _empty_report(**over):
    base = {"events": [], "event_summary": {}, "iocs": [], "files": [],
            "evidence_findings": [], "observed": True, "note": ""}
    base.update(over)
    return base

def test_the_tab_button_sits_between_pipes_and_sysmon():
    tabs = re.findall(r'data-tab="([a-z]+)"', _index_html())
    assert tabs[tabs.index("pipes") + 1] == "network"

def test_the_tab_content_has_an_info_text():
    assert re.search(r'id="tab-network".*?<h2 data-info="[^"]{20,300}"', _index_html(), re.S)

def test_every_subtab_exists():
    block = _tab_block("network")
    for label in ("OVERVIEW", "CONNECTIONS", "DNS", "HTTP", "TLS", "FILES", "IOC"):
        assert label in block

def test_switch_tab_loads_the_network_tab():
    assert "networkTabShown()" in _function_source("switchTab")

def test_a_report_renders_a_row_per_event():
    html = _render(_empty_report(
        events=[{"type": "http", "ts": 1, "dest": "evil.top", "method": "POST",
                 "path": "/gate.php", "process": "a.exe"}],
        event_summary={"http": 1}))
    assert "evil.top" in html and "/gate.php" in html

def test_event_fields_are_escaped():
    html = _render(_empty_report(
        events=[{"type": "http", "ts": 1, "dest": "<img src=x onerror=alert(1)>",
                 "process": "a.exe"}],
        event_summary={"http": 1}))
    assert "<img" not in html and "&lt;img" in html

def test_an_empty_report_says_nothing_was_observed():
    assert "no traffic" in _render(_empty_report(observed=False, note="no traffic"))

def test_the_tables_are_sortable():
    assert _tab_block("network").count("data-sortable") >= 4

def test_colours_come_from_theme_variables_only():
    src = _function_source("renderNetworkReport") + _function_source("renderNetworkPanel")
    assert not re.search(r"#[0-9a-fA-F]{6}|rgb\(", src)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_ui.py -v`
Expected: FAIL, Tab fehlt

- [ ] **Step 3: Add the tab button, content and sub-tabs to `index.html`**

Dazu den `<h4>Network</h4>`-Eintrag in `#help-usage` an derselben Position wie der Tab-Button und die fünf Routen in `#help-api`.

- [ ] **Step 4: Implement the block `// ===== NETWORK =====` in `app.js`**

Nach dem Muster des LOGS-Blocks (`app.js:12036`): `networkTabShown()` lädt beim ersten Öffnen, `renderNetworkReport()` baut die Tabellen, Unterkarten schalten clientseitig. Zweig in `switchTab()` (`:412-461`). Jede Datentabelle bekommt `data-sortable data-sort-id` (`tests/test_theme.py:2804`), jede Chart-Karte den CHART/TABLE-Umschalter (`:3320`).

- [ ] **Step 5: Add the colour values and the layout rules**

Werte in `style.css :root` und `theme-cyberpunk.css`, Formen in `theme-layout.css`. Asset-Versionen hochzählen.

- [ ] **Step 6: Update the tab counts and the README tab table**

`tests/test_theme.py:3037` zählt Tabs und Header hart; die README-Tabelle `### Web UI Tabs` muss dieselbe Reihenfolge haben (`tests/test_docs.py:54`).

- [ ] **Step 7: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add webui/templates/index.html webui/static/js/app.js webui/static/css README.md tests/test_net_ui.py tests/test_theme.py
git commit -m "feat(net): NETWORK tab with events, IOCs and files"
```

---

### Task 16: Tracing-Unterkarten anschließen

**Files:**
- Modify: `webui/static/js/app.js` (`renderRtraceDetailTabs` `:4123`, `renderRtraceEventTable` `:4162-4225`), `webui/templates/index.html:384-394`
- Test: `tests/test_net_ui.py` (ergänzen)

**Interfaces:**
- Consumes: Tasks 14, 15
- Produces: die Unterkarten `HTTP REQUESTS`, `CONNECTIONS`, `DNS REQUESTS` zählen und zeigen Netzwerk-Events; neue Unterkarte `TLS`

Heute filtert `app.js:4178` Netzwerk-Events nach Port 80/443 und nennt das HTTP. Das wird durch echte `http`-Events ersetzt, wo es welche gibt; ohne Report bleibt die Heuristik als Rückfall.

- [ ] **Step 1: Write the failing tests**

```python
def _tabs(state):
    return _run_node(["renderRtraceDetailTabs", "escapeHtml"],
                     "console.log(JSON.stringify(renderRtraceDetailTabs(%s)))"
                     % json.dumps(state))

def _rows(kind, state):
    return _run_node(["renderRtraceEventTable", "escapeHtml", "cssToken"],
                     "console.log(JSON.stringify(renderRtraceEventTable(%s, %s)))"
                     % (json.dumps(kind), json.dumps(state)))

def test_the_http_subtab_counts_real_http_events():
    out = _tabs({"network": [{"type": "http", "path": "/a"}, {"type": "http", "path": "/b"}]})
    assert "HTTP REQUESTS" in out and ">2<" in out

def test_the_http_subtab_prefers_real_events_over_the_port_heuristic():
    out = _rows("http", {"network": [{"type": "http", "dest": "evil.top", "path": "/gate.php"}],
                         "events": [{"raw": {"dest_port": 443, "dest_ip": "203.0.113.9"}}]})
    assert "/gate.php" in out and "203.0.113.9" not in out

def test_without_a_report_the_old_heuristic_still_works():
    out = _rows("http", {"events": [{"raw": {"dest_port": 443, "dest_ip": "203.0.113.9"}}]})
    assert "203.0.113.9" in out

def test_a_tls_subtab_exists_and_counts_tls_events():
    assert "TLS" in _tabs({"network": [{"type": "tls", "sni": "a.top"}]})
```

Die heutigen `renderRtrace*`-Funktionen lesen ihren Zustand aus globalen Variablen. Damit diese Tests möglich sind, nehmen beide den Zustand als Parameter — die Aufrufstellen übergeben das, was sie heute global lesen.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_net_ui.py -v`
Expected: FAIL

- [ ] **Step 3: Wire the sub-tabs to the network report in `app.js`**

Zählung in `renderRtraceDetailTabs` aus den Netzwerk-Events, Filterzweige in `renderRtraceEventTable`; `TLS` als Knopf mit `data-rtab="tls"` in `index.html`.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/static/js/app.js webui/templates/index.html tests/test_net_ui.py
git commit -m "feat(net): tracing sub-tabs show real network events"
```

---

## Nach Phase 1

Diese Phase liefert für sich: fremde pcaps auswerten, die drei leeren Tracing-Unterkarten füllen, Netzwerk-Befunde im gemeinsamen Verdict. Die Phasen 2 bis 4 der Spec (Fake-Internet, C2-Listener mit Stage-Sicherung, Fingerprint) bekommen eigene Pläne, sobald diese steht — Phase 2 beginnt mit dem Spike zur Adressvergabe, dessen Ergebnis ihren Zuschnitt bestimmt.
