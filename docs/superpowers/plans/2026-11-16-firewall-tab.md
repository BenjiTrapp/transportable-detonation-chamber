# Tab „FIREWALL“ – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein Reiter `FIREWALL`, der jede Verbindung der Chamber nach Prozess, Bewertung und Ziel zeigt, sie aus der Oberfläche kappen kann, bei einem Download eines detonierten Prozesses das Sample sichert statt es ausführen zu lassen, und per Klick in LOGS weiterjagt.

**Architecture:** Vier neue Python-Module mit klaren Grenzen — `geoip.py` (Offline-Lookup über eine mmap-Indexdatei), `firewall.py` (reine Bewertung, kein I/O, läuft unter pytest auf macOS), `firewall_store.py` (Ring, Cursor, Collector, offene Entscheidungen, Einstellungen), `firewall_rules.py` (alles mit Nebenwirkung, der Kommandoaufruf wird injiziert). `app.py` bekommt nur Routen und den Fetcher. Im Frontend ein neuer `// --- FIREWALL ---`-Block in `app.js` nach dem Muster des LOGS-Blocks, plus eine selbstgezeichnete SVG-Weltkarte.

**Tech Stack:** Python 3.12 (nur Standardbibliothek plus das vorhandene Flask/requests), Vanilla JS, SVG, PowerShell für die Durchsetzung, pytest + Node für die Tests.

**Spec:** `docs/superpowers/specs/2026-11-16-firewall-tab-design.md`

## Global Constraints

- **Teil A nur.** Der Proxy aus Teil B wird in diesem Plan nicht gebaut. Keine Byte-Zähler: Sysmon liefert keine, `pfirewall.log` hat das `size`-Feld meist leer. Der Tab zeigt `count` und `fw_records`.
- **Keine neue Abhängigkeit.** `webui/requirements.txt` bleibt bei `flask>=3.0`, `requests>=2.31`, `watchdog>=4.0`, `pefile>=2023.2.7`. Keine Fremdbibliothek, kein CDN im Frontend.
- **Farben nur als `var(--…)`.** Farbliterale ausschließlich in `:root` von `style.css`; `theme-cyberpunk.css` nur unter `:root[data-theme="cyberpunk"]`; `theme-layout.css` unter `[data-theme]` und ohne Farbwerte.
- **Alles aus der VM ist Malware-Text.** Jede Ausgabe durch `escapeHtml` / `jsArg` / `cssToken`. URLs und Hostnamen werden **defanged angezeigt** (`hxxp://`, `example[.]com`) und **nie** als `<a href>`. Gespeichert wird das Original.
- **Regelnamen** tragen den Präfix `TDC-FW-`.
- **Die automatische Sperre gilt dem Loader:** immer mit `-Program <image>`. Ohne `-Program` nur auf ausdrücklichen Knopf.
- **Vorgabeaktion nach Ablauf der Frist:** `block_fetch` — sperren *und* selbst holen, serverseitig, auch ohne offenen Browser. Frist 30 s, `TDC_FIREWALL_DECIDE_SECONDS`, `0` = sofort holen.
- **`ASK`-Stellungen:** `detonation` (Vorgabe) sperrt und fragt nur im Detonations-Kontext, `all` bei jedem Download-Fund außer von TDC selbst, `off` sperrt und fragt nie und markiert nur. Der Schalter liegt serverseitig in `webui/firewall_state.json`.
- **Selbstausschluss:** das `python.exe` der Web-UI-venv, Detonator, DetonatorAgent, LitterBox, Fibratus, Rustinel, der Pipe-Proxy, `git.exe` werden nie automatisch gesperrt und lösen nie einen Toast aus, bleiben aber sichtbar und getaggt.
- **MCP nur lesend:** `tdc_firewall_connections`, `tdc_firewall_captures`. Kein `isolate`, `block`, `decide`.
- **`/api/firewall/decide` nimmt keine URL**, nur die einmalig verwendbare `id` einer offenen Entscheidung.
- **Fetch-Grenzen:** 64 MB, 30 s, höchstens 3 Weiterleitungen, Ziel-IP muss die beobachtete sein (kein erneutes DNS).
- **Sprache:** Oberfläche, README, Kommentare und Commit-Nachrichten englisch; dieser Plan und die Spec deutsch.
- **Tabs-Pflichten:** Nav-Reihenfolge `… SYSMON, FIREWALL, LOGS, …`; README-Tabellenzeile und Help-Eintrag in genau dieser Reihenfolge; `data-info` ≤ 300 Zeichen, 1–2 Sätze, ohne `<`, `&`, `${`; `?v=` auf `style.css`, `theme-layout.css`, `theme-cyberpunk.css`, `app.js`; `tests/test_theme.py` 12 → 13 Content-Header und 14 → 15 Tab-Contents; neue `webui/*.py` und `webui/data/` in allen drei Deploy-Wegen.
- **Tests** laufen mit `make -s unit-test`, unter `TZ=UTC` und `TZ=Europe/Berlin`, auf macOS ohne Windows.

## Review Focus

1. **Eine Regel, die nicht beißt.** Ist ein Firewall-Profil aus, gehen `New-NetFirewallRule` und `DefaultOutboundAction` wirkungslos durch, und die Oberfläche zeigt `blocked`, obwohl nichts gesperrt ist. Erwartung: Deny-Schalter und `ISOLATED` sind deaktiviert, der Kopf trägt ein Band, und `blocked` wird erst nach einer Gegenprobe gesetzt. → Test in Task 4.
2. **Malware-Text als Markup.** URL, Hostname, Imagepfad, AS-Name und Kommandozeile kommen aus der VM. Erwartung: nichts davon wird als Markup wirksam, keine URL wird ein Link, `javascript:`- und `data:`-URLs erscheinen defanged als Text. → Test in Task 7.
3. **TDC als Proxy für Malware.** Im Isolated-Modus darf nur TDCs python raus. Erwartung: `decide` nimmt keine URL, eine `id` wirkt genau einmal, eine unbekannte oder abgelaufene `id` gibt 404/409 ohne Netzzugriff, und eine zweite Antwort auf dieselbe `id` liefert das bereits gefallene Ergebnis statt einer zweiten Verbindung. → Test in Task 5.
4. **Isolated als Falle.** Erwartung: der Vorzustand wird vor dem Umschalten gemerkt, ein Absturz hebt die Sperre **nicht** von selbst auf, der Zustand wird beim Start gemeldet, Tool-Updates verweigern mit Hinweis, und eingehender Zugang zu Port 9000 bleibt. → Test in Task 4.
5. **Adressen, die in keinen Bereich fallen.** Erwartung: RFC1918/Loopback/Link-Local/CGNAT/Multicast werden `scope: local` und erscheinen nicht auf der Karte; IPv6 wird aufgelöst oder sauber `None`; eine IP in keinem Bereich, eine kaputte Zeichenkette und fehlende Datendateien ergeben `None` statt einer Ausnahme, und der Tab bleibt benutzbar. → Test in Task 1.

---

### Task 1: Geo offline

**Files:**
- Neu: `webui/geoip.py`
- Neu: `webui/data/ip2asn-v4.tsv.gz`, `webui/data/ip2asn-v6.tsv.gz`, `webui/data/countries.tsv`
- Neu: `scripts/fetch-geoip.py`
- Neu: `tests/test_geoip.py`, `tests/samples/geoip/ip2asn-v4.tsv.gz` (eine Handvoll Bereiche), `tests/samples/geoip/countries.tsv`
- Ändern: `Makefile` (Ziel `geoip`), `.gitignore` (nicht die Daten — die gehören ins Git; nur `*.bin` des Index)

**Interfaces:**
- Consumes: nichts.
- Produces:
  - `GeoInfo = namedtuple("GeoInfo", "cc country lat lon asn as_org scope")`
  - `scope_of(ip: str) -> str` → `"public" | "local" | "invalid"`
  - `lookup(ip: str) -> GeoInfo | None`
  - `jitter(ip: str, lat: float, lon: float) -> tuple[float, float]`
  - `load(data_dir: str = DATA_DIR) -> None`
  - `available() -> bool`
  - `build_index(tables_dir: str, out_dir: str) -> str` — vom Fetch-Skript gerufen, nicht beim Start

- [ ] **Step 1: Write the failing tests**

```python
def test_scope_separates_local_from_public():
    for ip in ("10.0.0.5", "192.168.64.4", "172.17.251.7", "127.0.0.1", "::1",
               "169.254.1.1", "100.64.0.1", "224.0.0.1", "fe80::1"):
        assert geoip.scope_of(ip) == "local"
    assert geoip.scope_of("185.244.25.17") == "public"
    for bad in ("", "x", "1.2.3", "999.1.1.1", "185.244.25.17:443"):
        assert geoip.scope_of(bad) == "invalid"

def test_lookup_resolves_country_and_asn(geo):
    g = geo.lookup("185.244.25.17")
    assert (g.cc, g.asn) == ("RU", 200557)
    assert g.as_org and g.scope == "public"
    assert -90 <= g.lat <= 90 and -180 <= g.lon <= 180

def test_lookup_returns_none_outside_every_range(geo):
    assert geo.lookup("203.0.113.9") is None        # in no range of the fixture
    assert geo.lookup("10.0.0.5") is None           # local, never looked up
    assert geo.lookup("nonsense") is None

def test_lookup_handles_ipv6(geo):
    assert geo.lookup("2001:db8::1").cc == "DE"

def test_missing_data_is_not_an_error(tmp_path):
    geoip.load(str(tmp_path), str(tmp_path))
    assert geoip.available() is False
    assert geoip.lookup("185.244.25.17") is None

def test_jitter_is_stable_and_small(geo):
    a = geo.jitter("185.244.25.17", 55.0, 37.0)
    assert a == geo.jitter("185.244.25.17", 55.0, 37.0)
    assert a != geo.jitter("185.244.25.18", 55.0, 37.0)
    assert abs(a[0] - 55.0) <= 2 and abs(a[1] - 37.0) <= 2

def test_index_is_built_once(geo, tmp_path):
    first = geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    mtime = os.path.getmtime(first)
    geoip.build_index(str(FIXTURE_DIR), str(tmp_path))
    assert os.path.getmtime(first) == mtime
```

Die Fixture `geo` lädt `tests/samples/geoip/` in ein `tmp_path`-Indexverzeichnis.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_geoip.py -v`
Expected: FAIL, `ModuleNotFoundError: geoip`

- [ ] **Step 3: Implement `webui/geoip.py`**

`scope_of` über `ipaddress.ip_address` und dessen `is_private`/`is_loopback`/`is_link_local`/`is_multicast`/`is_reserved`, plus CGNAT `100.64.0.0/10` ausdrücklich. `build_index` liest die `.tsv.gz` (Spalten `range_start`, `range_end`, `AS_number`, `country_code`, `AS_description`), schreibt zwei Dateien pro Familie: einen Satzstrom fester Länge (`>IIIH` für v4, `>16s16sIH` für v6) sortiert nach Startadresse, und eine `asn-names.tsv` mit `asn\tdescription`. Neu gebaut wird nur, wenn Größe oder mtime der Quelle von der gemerkten abweichen (eine kleine `.stamp`-Datei daneben). `lookup` mappt die Indexdatei per `mmap` und sucht mit `bisect` über eine `__getitem__`-Hülle; AS-Namen werden beim ersten Treffer lazy in ein dict geladen. `jitter` streut über `hashlib.blake2s(ip)` auf Winkel und Radius bis 2°.

`DATA_DIR` ist `webui/data`, `index_dir` standardmäßig `os.path.join(tempfile.gettempdir(), "tdc-geoip")`.

- [ ] **Step 4: Write `scripts/fetch-geoip.py` and the `geoip` make target**

Das Skript holt `https://iptoasn.com/data/ip2asn-v4.tsv.gz` und `-v6.tsv.gz` nach `webui/data/` und schreibt daneben eine `SOURCES.md` mit Datum und Lizenz (CC0). `countries.tsv` (Ländercode, Name, lat, lon, Region, ~250 Zeilen) wird **von Hand** angelegt, nicht geholt — es ändert sich nicht.

Makefile:
```make
geoip:  ## Refresh the offline IP-to-country/ASN tables (needs internet)
	python3 scripts/fetch-geoip.py
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_geoip.py -v`
Expected: PASS (7 Tests)

- [ ] **Step 6: Commit**

```bash
git add webui/geoip.py webui/data scripts/fetch-geoip.py tests/test_geoip.py tests/samples/geoip Makefile .gitignore
git commit -m "feat(firewall): offline IP to country and ASN lookup"
```

---

### Task 2: Bewertung der Verbindungen

**Files:**
- Neu: `webui/firewall.py`
- Neu: `tests/test_firewall.py`, `tests/samples/firewall/sysmon_events.json` (EID 1/3/22 einer gespielten Detonation)
- Ändern: nichts.

**Interfaces:**
- Consumes: `geoip.lookup`, `geoip.scope_of`, `geoip.jitter` (Task 1); `memory_evidence.beaconing_from_connections` (vorhanden, `webui/memory_evidence.py:479`).
- Produces:
  - `SEVERITIES = ("info", "low", "medium", "high", "critical")`
  - `TAGS: dict[str, str]` — Tag → Schweregrad, genau die 13 der Spec
  - `Context` (dataclass): `dns: dict[str, str]`, `alerts: list[dict]`, `submission_pids: set[int]`, `ioc_ips: set[str]`, `ioc_domains: set[str]`, `processes: dict[int, dict]`, `rules: dict[str, str]`, `now: float`
  - `flow_key(ev: dict) -> tuple`
  - `bundle(events: list[dict]) -> list[dict]`
  - `dns_map(events: list[dict]) -> dict[str, str]`
  - `attach_firewall(flows: list[dict], fw_events: list[dict]) -> None`
  - `entropy(text: str) -> float`
  - `is_dga(name: str) -> bool`
  - `tag_flow(flow: dict, ctx: Context) -> list[str]`
  - `classify(events: list[dict], fw_events: list[dict], ctx: Context) -> list[dict]`
  - `summarize(flows: list[dict]) -> dict`
  - `severity_of(tags: list[str]) -> str`

- [ ] **Step 1: Write the failing tests**

```python
def test_bundle_merges_by_key_without_source_port():
    flows = firewall.bundle([conn(pid=4812, dst="1.2.3.4", dport=443, sport=51000, t=1),
                             conn(pid=4812, dst="1.2.3.4", dport=443, sport=51001, t=61)])
    assert len(flows) == 1
    assert flows[0]["count"] == 2
    assert flows[0]["first_seen"] < flows[0]["last_seen"]

def test_hostname_falls_back_to_the_dns_map():
    ctx = ctx_with(dns={"1.2.3.4": "evil.example"})
    flows = firewall.classify([conn(dst="1.2.3.4", hostname="-")], [], ctx)
    assert flows[0]["dst_hostname"] == "evil.example"

def test_direct_ip_when_no_dns_resolved_there():
    flows = firewall.classify([conn(dst="1.2.3.4")], [], ctx_with(dns={}))
    assert "direct-ip" in flows[0]["tags"]

def test_ioc_hit_is_critical():
    flows = firewall.classify([conn(dst="1.2.3.4")], [],
                              ctx_with(ioc_ips={"1.2.3.4"}))
    assert "ioc" in flows[0]["tags"]
    assert firewall.severity_of(flows[0]["tags"]) == "critical"

def test_beaconing_is_found_in_a_regular_rhythm():
    events = [conn(dst="1.2.3.4", dport=443, t=t) for t in range(0, 900, 60)]
    flows = firewall.classify(events, [], ctx_with())
    assert "beacon" in flows[0]["tags"]

def test_newborn_only_within_sixty_seconds():
    ctx = ctx_with(processes={4812: {"start": 100.0, "image": r"C:\x\a.exe"}})
    near = firewall.classify([conn(pid=4812, t=140)], [], ctx)
    far = firewall.classify([conn(pid=4812, t=400)], [], ctx)
    assert "newborn" in near[0]["tags"] and "newborn" not in far[0]["tags"]

def test_dga_detection():
    assert firewall.is_dga("kqj3x9zmfvbt7w2p.top") is True
    assert firewall.is_dga("cdn.statically.io") is False
    assert firewall.is_dga("") is False

def test_tdc_processes_are_tagged_but_never_blockable():
    f = firewall.classify([conn(image=TDC_PYTHON, dst="140.82.121.3")], [], ctx_with())[0]
    assert f["self"] is True
    f2 = firewall.classify([conn(image=TDC_PYTHON, dst="1.2.3.4")], [], ctx_with())[0]
    assert "tdc-anomaly" in f2["tags"]

def test_firewall_records_land_on_the_endpoint_not_the_process():
    flows = firewall.classify([conn(pid=1, dst="1.2.3.4", dport=443),
                               conn(pid=2, dst="1.2.3.4", dport=443)],
                              [fw(action="DROP", dst="1.2.3.4", dport=443)], ctx_with())
    assert all(f["fw_dropped"] == 1 for f in flows)
    assert all("dropped" in f["endpoint_tags"] for f in flows)
    assert all("dropped" not in f["tags"] for f in flows)

def test_local_addresses_get_scope_local_and_no_geo():
    f = firewall.classify([conn(dst="192.168.64.1")], [], ctx_with())[0]
    assert f["geo"]["scope"] == "local" and f["geo"]["lat"] is None

def test_summarize_counts_states_and_tops():
    s = firewall.summarize(firewall.classify(SAMPLE_EVENTS, [], ctx_with()))
    assert set(s) >= {"connections", "blocked", "pending", "captures",
                      "top_processes", "top_endpoints", "top_countries"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall.py -v`
Expected: FAIL, `ModuleNotFoundError: firewall`

- [ ] **Step 3: Implement `webui/firewall.py`**

Reine Funktionen, kein `subprocess`, kein `open` außer der IOC-Listen, die als Mengen hereingegeben werden. Die Listen (`LOLBINS`, `DEAD_DROPS`, `RISKY_TLDS`, `COMMON_PORTS`, `SUSPICIOUS_PORTS`, `TDC_IMAGES`, `TDC_ENDPOINTS`) und die Schwellen (`DGA_ENTROPY = 3.5`, `DGA_MIN_LEN = 12`, `NEWBORN_S = 60`) stehen als Konstanten oben im Modul.

`bundle` nutzt `(image, pid, protocol, src_ip, dst_ip, dst_port)` und normalisiert Sysmons `"-"` wie `log_store._sysmon_str` es tut. `attach_firewall` joint nur über `(protocol, src_ip, dst_ip, dst_port)`, Protokoll normalisiert (`tcp`/`TCP`/`6` → `tcp`), und schreibt `fw_records`/`fw_allowed`/`fw_dropped` sowie `endpoint_tags`. `beacon` ruft `memory_evidence.beaconing_from_connections` mit den Einzelverbindungen des Flows. Jeder Flow trägt `state` (`allowed`/`blocked`/`pending`, aus `ctx.rules`), `self` (Selbstausschluss) und `geo` als dict mit `scope` und `lat`/`lon` nach `jitter`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall.py -v`
Expected: PASS (11 Tests)

- [ ] **Step 5: Commit**

```bash
git add webui/firewall.py tests/test_firewall.py tests/samples/firewall
git commit -m "feat(firewall): connection bundling, tagging and summary"
```

---

### Task 3: Store, Collector und der Download-Fund

**Files:**
- Neu: `webui/firewall_store.py`
- Neu: `tests/test_firewall_store.py`
- Ändern: `scripts/configure-logging.ps1` (BITS-Kanal einschalten, falls aus)

**Interfaces:**
- Consumes: `firewall.bundle`, `firewall.dns_map` (Task 2).
- Produces:
  - `class FirewallStore` — `add_connections(events)`, `add_dns(events)`, `add_processes(events)`, `connections(since=None, until=None) -> list[dict]`, `dns() -> dict[str, str]`, `processes() -> dict[int, dict]`, `raw_for(image, dst_ip, dst_port) -> list[tuple]`, `stats() -> dict`
  - `class PendingStore` — `add(finding: dict, deadline: float) -> dict`, `open() -> list[dict]`, `history(limit=100) -> list[dict]`, `resolve(pending_id: str, action: str, result: dict | None = None) -> dict`, `expired(now: float) -> list[dict]`
  - `class Settings` — Felder `ask_mode`, `isolated`, `outbound_before`, `isolated_since`; `load()`, `save()`, `set(**kw)`
  - `urls_in(text: str) -> list[str]`
  - `download_findings(ps_events, proc_events, bits_events, flows, submission_pids) -> list[dict]`
  - `class FirewallCollector` — `__init__(store, settings, readers: dict, fast_window: Callable[[], bool])`, `tick()`, `interval() -> float`
  - `EXECUTABLE_SUFFIXES`, `URL_RE`, `MAX_CONNECTIONS = 50000`, `RETAIN_S = 7 * 86400`

- [ ] **Step 1: Write the failing tests**

```python
def test_ring_drops_the_oldest_and_honours_the_window():
    s = FirewallStore(max_connections=3)
    for t in range(5):
        s.add_connections([conn(t=t, dst=f"1.2.3.{t}")])
    assert len(s.connections()) == 3
    assert s.connections(since=iso(3))[0]["dst_ip"] == "1.2.3.3"

def test_raw_for_keeps_single_connections_for_beaconing():
    s = FirewallStore()
    s.add_connections([conn(t=t, dst="1.2.3.4", dport=443) for t in (0, 60, 120)])
    assert len(s.raw_for(IMAGE, "1.2.3.4", 443)) == 3

def test_urls_in_finds_cradles_and_ignores_the_rest():
    assert urls_in("IEX(New-Object Net.WebClient).DownloadString('http://a.b/c.dll')") == ["http://a.b/c.dll"]
    assert urls_in("certutil -urlcache -f https://x.y/z.exe out.exe") == ["https://x.y/z.exe"]
    assert urls_in("no url here") == []
    assert urls_in("http://" + "a" * 5000) == []          # length guard

def test_download_finding_only_for_executables_in_a_detonation():
    f = download_findings([ps("… 'http://a.b/c.dll'", pid=4812)], [], [], FLOWS, {4812})
    assert f[0]["url"] == "http://a.b/c.dll" and f[0]["pid"] == 4812
    assert download_findings([ps("… 'http://a.b/page.html'", pid=4812)], [], [], FLOWS, {4812}) == []
    assert download_findings([ps("… 'http://a.b/c.dll'", pid=99)], [], [], FLOWS, set()) == []

def test_bits_url_becomes_a_finding():
    f = download_findings([], [], [bits(url="http://a.b/s.exe", pid=4812)], FLOWS, {4812})
    assert f[0]["source"] == "bits"

def test_pending_resolve_is_idempotent(tmp_path):
    p = PendingStore(str(tmp_path / "pending.json"))
    item = p.add(FINDING, deadline=time.time() + 30)
    first = p.resolve(item["id"], "allow")
    second = p.resolve(item["id"], "block_fetch")
    assert second["action"] == "allow" and second == first
    assert p.open() == []

def test_pending_survives_a_restart(tmp_path):
    path = str(tmp_path / "pending.json")
    item = PendingStore(path).add(FINDING, deadline=time.time() + 30)
    assert PendingStore(path).open()[0]["id"] == item["id"]

def test_expired_lists_only_what_ran_out():
    p = PendingStore(PATH)
    old = p.add(FINDING, deadline=100.0)
    p.add(FINDING2, deadline=10_000.0)
    assert [e["id"] for e in p.expired(now=200.0)] == [old["id"]]

def test_settings_round_trip_and_defaults(tmp_path):
    s = Settings(str(tmp_path / "state.json"))
    assert (s.ask_mode, s.isolated) == ("detonation", False)
    s.set(ask_mode="off", isolated=True, outbound_before="Allow")
    assert Settings(str(tmp_path / "state.json")).ask_mode == "off"

def test_collector_ticks_fast_only_in_the_detonation_window():
    c = FirewallCollector(STORE, SETTINGS, READERS, fast_window=lambda: True)
    assert c.interval() == 1.0
    c2 = FirewallCollector(STORE, SETTINGS, READERS, fast_window=lambda: False)
    assert c2.interval() == 10.0

def test_a_failing_reader_does_not_stop_the_tick():
    calls = []
    readers = {"connections": boom, "dns": lambda **k: calls.append("dns") or [],
               "processes": lambda **k: [], "powershell": lambda **k: [],
               "firewall": lambda **k: [], "bits": lambda **k: []}
    FirewallCollector(STORE, SETTINGS, readers, lambda: False).tick()
    assert calls == ["dns"]
    assert STORE.stats()["status"]["connections"] == "unavailable"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall_store.py -v`
Expected: FAIL, `ModuleNotFoundError: firewall_store`

- [ ] **Step 3: Implement `webui/firewall_store.py`**

`FirewallStore` hält einen `deque` der Einzelverbindungen (für `raw_for` und die Beaconing-Erkennung) und baut `connections()` daraus über `firewall.bundle`. Cursor je Ereignis-ID als `EventRecordID`, wie `log_store.Collector` es macht. `urls_in` begrenzt die Länge einer URL auf 2048 und die Anzahl pro Text auf 20, kein benutzergesteuerter Regex. `download_findings` verlangt: Endung in `EXECUTABLE_SUFFIXES` (`.exe .dll .scr .ps1 .bat .cmd .vbs .js .hta .msi .jar .lnk .cpl .ocx`) **oder** ein `Content-Disposition`-freies BITS-Ziel mit solcher Endung, und die PID (oder ein Vorfahr) in `submission_pids` — außer der Aufrufer gibt `ask_mode="all"` durch. Die Findung trägt `{id, pid, image, url, dst_ip, dst_port, source, observed_at}`.

`PendingStore` schreibt atomar wie `_save_submissions` (`app.py:757`), hält höchstens 200 offene und 24 h Verlauf, und `resolve` ist durch ein Lock plus die Prüfung auf ein bereits gesetztes `action` idempotent.

`FirewallCollector.tick()` ruft jeden Reader in `try/except`, setzt pro Quelle einen Status wie `log_store.Collector.set_status`, und liest `bits` nur, wenn `fast_window()` wahr ist.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall_store.py -v`
Expected: PASS (11 Tests)

- [ ] **Step 5: Add the BITS channel to `scripts/configure-logging.ps1`**

Nach dem Firewall-Block: `wevtutil sl Microsoft-Windows-Bits-Client/Operational /e:true /ms:33554432`, idempotent, mit derselben Ausgabe-Machart wie die übrigen Blöcke.

- [ ] **Step 6: Commit**

```bash
git add webui/firewall_store.py tests/test_firewall_store.py scripts/configure-logging.ps1
git commit -m "feat(firewall): connection store, collector and download findings"
```

---

### Task 4: Durchsetzung

**Files:**
- Neu: `webui/firewall_rules.py`
- Neu: `scripts/tdc-unisolate.ps1`
- Neu: `tests/test_firewall_rules.py`

**Interfaces:**
- Consumes: `firewall_store.Settings` (Task 3).
- Produces:
  - `RULE_PREFIX = "TDC-FW-"`
  - `class RuleError(Exception)`
  - `profiles_off(run) -> list[str]`
  - `enable_firewall(run) -> None`
  - `block(run, *, image=None, ip=None, port=None, protocol=None) -> dict` → `{"rule_id", "name", "image", "ip", "port", "protocol", "verified"}`
  - `unblock(run, rule_id: str) -> None`
  - `rules(run) -> list[dict]`
  - `startup_state(run, settings) -> dict` → `{"isolated", "profiles_off", "announce"}`
  - `verify(run, rule_id: str) -> bool`
  - `kill(run, pid: int) -> None`
  - `isolate(run, on: bool, *, fetcher: str, settings) -> dict`
  - `run_powershell(args: list[str]) -> tuple[int, str, str]` — die echte Umsetzung, in Tests ersetzt

- [ ] **Step 1: Write the failing tests**

```python
def test_block_scopes_to_the_program_by_default():
    run = FakeRun()
    r = rules_mod.block(run, image=r"C:\x\loader.exe", ip="1.2.3.4", port=443, protocol="tcp")
    cmd = " ".join(run.calls[0])
    assert "-Program" in cmd and r"C:\x\loader.exe" in cmd
    assert "-RemoteAddress 1.2.3.4" in cmd and "-Action Block" in cmd
    assert r["rule_id"].startswith("TDC-FW-")

def test_block_for_everyone_omits_the_program():
    run = FakeRun()
    rules_mod.block(run, ip="1.2.3.4")
    assert "-Program" not in " ".join(run.calls[0])

def test_block_is_verified_before_it_counts():
    run = FakeRun(get_rule_returns="")           # the rule is not there
    r = rules_mod.block(run, image=IMAGE, ip="1.2.3.4")
    assert r["verified"] is False

def test_a_disabled_profile_is_reported():
    run = FakeRun(profiles={"Domain": True, "Private": False, "Public": False})
    assert rules_mod.profiles_off(run) == ["Private", "Public"]

def test_enforcement_refuses_while_a_profile_is_off():
    run = FakeRun(profiles={"Domain": False, "Private": False, "Public": False})
    with pytest.raises(rules_mod.RuleError) as e:
        rules_mod.isolate(run, True, fetcher=PY, settings=SETTINGS)
    assert "firewall" in str(e.value).lower()

def test_isolate_remembers_the_previous_outbound_action():
    run, settings = FakeRun(outbound="Allow"), FakeSettings()
    rules_mod.isolate(run, True, fetcher=PY, settings=settings)
    assert settings.outbound_before == "Allow"
    assert any("DefaultOutboundAction Block" in " ".join(c) for c in run.calls)
    assert any("-Program " + PY in " ".join(c) and "-Action Allow" in " ".join(c) for c in run.calls)
    assert any("127.0.0.0/8" in " ".join(c) for c in run.calls)

def test_leaving_isolated_restores_exactly_what_was_there():
    run, settings = FakeRun(), FakeSettings(outbound_before="Allow", isolated=True)
    rules_mod.isolate(run, False, fetcher=PY, settings=settings)
    assert any("DefaultOutboundAction Allow" in " ".join(c) for c in run.calls)
    assert settings.isolated is False and settings.outbound_before is None

def test_isolated_is_never_lifted_on_its_own():
    settings = FakeSettings(isolated=True, outbound_before="Allow")
    state = rules_mod.startup_state(FakeRun(outbound="Block"), settings)
    assert state["isolated"] is True and state["announce"] is True

def test_rule_names_are_only_ours():
    run = FakeRun(rule_list=["TDC-FW-abc123", "Core Networking"])
    assert [r["rule_id"] for r in rules_mod.rules(run)] == ["TDC-FW-abc123"]

def test_no_shell_and_no_interpolation_of_malware_text():
    run = FakeRun()
    rules_mod.block(run, image=r'C:\x\a"; Remove-Item C:\ -Recurse #.exe', ip="1.2.3.4")
    assert all(isinstance(c, list) for c in run.calls)
    assert not any(";" in part for part in run.calls[0][1:] if part.startswith("-"))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall_rules.py -v`
Expected: FAIL, `ModuleNotFoundError: firewall_rules`

- [ ] **Step 3: Implement `webui/firewall_rules.py`**

Jeder Aufruf geht als Argumentliste an `run`, nie durch eine Shell und nie mit interpoliertem Text; Pfade und Adressen gehen als eigene Argumente (`powershell -NoProfile -NonInteractive -Command` mit einem Skript, dessen Werte aus `-ArgumentList`-Parametern kommen). `rule_id` ist `TDC-FW-` plus 12 Hex-Zeichen aus `blake2s` über Scope, Image, IP und Port — damit ist dieselbe Sperre wiedererkennbar.

`isolate(on=True)` in dieser Reihenfolge: Profile prüfen (sonst `RuleError`), `DefaultOutboundAction` lesen und in `settings.outbound_before` merken, Allow-Regeln für Loopback (`127.0.0.0/8`, `::1`) und `-Program <fetcher>` setzen, dann `DefaultOutboundAction Block`. `isolate(on=False)` genau rückwärts. `startup_state` meldet einen Isolated-Zustand, den der Nutzer nicht in dieser Sitzung gesetzt hat, mit `announce: True` und hebt ihn **nicht** auf.

`scripts/tdc-unisolate.ps1`: setzt `DefaultOutboundAction` auf `Allow`, entfernt alle `TDC-FW-*`-Regeln, sagt was es getan hat. Für den Fall, dass die Oberfläche selbst nicht mehr erreichbar ist.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall_rules.py -v`
Expected: PASS (10 Tests)

- [ ] **Step 5: Commit**

```bash
git add webui/firewall_rules.py scripts/tdc-unisolate.ps1 tests/test_firewall_rules.py
git commit -m "feat(firewall): rule enforcement, isolated mode and the escape hatch"
```

---

### Task 5: API, Fetcher und Sample-Store

**Files:**
- Modify: `webui/app.py` (Importe und Wiring beim Modulkopf; die neuen Routen nach dem LOGS-Block bei `app.py:10884`; `_readable_roots` bei `app.py:4829`; der Startthread bei `app.py:10901`; Tool-Updates-Sperre bei `app.py:10574`)
- Modify: `webui/requirements.txt` — **nicht**, bleibt unverändert
- Neu: `tests/test_firewall_api.py`
- Modify: `tests/conftest.py` (Fixture: leerer Store, eigene `pending.json`, `captures.json`, `samples`-Verzeichnis, gefälschtes `run`)

**Interfaces:**
- Consumes: alles aus Task 1–4.
- Produces:
  - Routen: `GET /api/firewall/connections`, `/summary`, `/geo`, `/rules`, `/pending`, `/captures`, `/capture/<id>`; `POST /api/firewall/block`, `/unblock`, `/isolate`, `/decide`, `/ask`
  - `_fetch_capture(pending: dict) -> dict` — holt, prüft, speichert
  - `_capture_store() -> list[dict]`, `_record_capture(meta) -> dict`
  - `CAPTURE_DIR = r"C:\tdc\samples"`, `CAPTURES_FILE`, `FETCH_MAX_BYTES = 64 * 1024 * 1024`, `FETCH_TIMEOUT = 30`, `FETCH_MAX_REDIRECTS = 3`
  - `_firewall_decide_seconds() -> float`

- [ ] **Step 1: Write the failing tests**

```python
def test_connections_returns_tagged_flows(client, fw):
    r = client.get("/api/firewall/connections?max=50")
    assert r.status_code == 200
    assert isinstance(r.json["connections"], list)
    assert set(r.json["connections"][0]) >= {"image", "dst_ip", "dst_port", "tags", "geo", "state"}

def test_decide_takes_no_url(client, fw):
    r = client.post("/api/firewall/decide", json={"url": "http://evil/x.exe", "action": "block_fetch"})
    assert r.status_code == 400
    assert fw.fetches == []

def test_decide_with_an_unknown_id_touches_no_network(client, fw):
    r = client.post("/api/firewall/decide", json={"id": "nope", "action": "block_fetch"})
    assert r.status_code == 404 and fw.fetches == []

def test_decide_works_exactly_once(client, fw):
    pid = fw.pending.add(FINDING, deadline=time.time() + 30)["id"]
    first = client.post("/api/firewall/decide", json={"id": pid, "action": "block_fetch"})
    second = client.post("/api/firewall/decide", json={"id": pid, "action": "allow"})
    assert first.status_code == 200 and second.status_code == 200
    assert second.json["action"] == "block_fetch"
    assert len(fw.fetches) == 1

def test_fetch_refuses_a_different_destination(client, fw):
    fw.resolve_to = "9.9.9.9"                    # DNS would point elsewhere now
    out = app_module._fetch_capture({**FINDING, "dst_ip": "1.2.3.4"})
    assert out["error"] and fw.fetches == []

def test_fetch_stops_at_the_size_limit(client, fw):
    fw.body = b"A" * (app_module.FETCH_MAX_BYTES + 1)
    out = app_module._fetch_capture(FINDING)
    assert out["error"] == "too large" and out.get("sha256") is None

def test_a_capture_is_recorded_and_never_marked_executed(client, fw):
    fw.body = b"MZ" + b"\x00" * 100
    out = app_module._fetch_capture(FINDING)
    rec = client.get("/api/firewall/captures").json["captures"][0]
    assert rec["sha256"] == out["sha256"] and rec["magic"] == "MZ"
    assert rec["executed"] is False

def test_expired_decisions_are_fetched_without_a_browser(client, fw):
    fw.pending.add(FINDING, deadline=time.time() - 1)
    app_module._firewall_sweep(now=time.time())
    assert len(fw.fetches) == 1
    assert fw.pending.open() == []

def test_ask_off_neither_blocks_nor_fetches(client, fw):
    client.post("/api/firewall/ask", json={"mode": "off"})
    fw.pending.add(FINDING, deadline=time.time() - 1)
    app_module._firewall_sweep(now=time.time())
    assert fw.fetches == [] and fw.run.calls == []

def test_isolate_refuses_when_the_firewall_is_off(client, fw):
    fw.profiles = {"Domain": False, "Private": False, "Public": False}
    r = client.post("/api/firewall/isolate", json={"on": True})
    assert r.status_code == 409 and "firewall" in r.json["error"].lower()

def test_tool_updates_refuse_in_isolated(client, fw):
    client.post("/api/firewall/isolate", json={"on": True})
    r = client.post("/api/tools/update", json={"tool": "capa"})
    assert r.status_code == 409 and "isolated" in r.json["error"].lower()

def test_block_and_unblock_round_trip(client, fw):
    r = client.post("/api/firewall/block", json={"scope": "endpoint", "ip": "1.2.3.4",
                                                 "port": 443, "image": IMAGE})
    rule_id = r.json["rule_id"]
    assert client.get("/api/firewall/rules").json["rules"][0]["rule_id"] == rule_id
    assert client.post("/api/firewall/unblock", json={"rule_id": rule_id}).status_code == 200

def test_every_action_is_written_to_the_access_log(client, fw):
    client.post("/api/firewall/block", json={"scope": "process", "image": IMAGE})
    hits = client.get('/api/logs/search?q=path="/api/firewall/block"').json
    assert hits["count"] >= 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall_api.py -v`
Expected: FAIL, 404 auf alle Routen

- [ ] **Step 3: Implement the routes in `webui/app.py`**

Alle Antworten über `_json_response` mit `allow_nan=False`, lange Zeichenketten über den vorhandenen `_cap_log_value`-Weg gekappt. `/decide` nimmt genau `{"id", "action"}` und lehnt jeden weiteren Schlüssel ab. Der Sweep `_firewall_sweep(now)` läuft im Collector-Thread, nimmt `pending.expired(now)` und führt die Vorgabeaktion aus, sofern `ask_mode != "off"`.

`_fetch_capture` benutzt `requests` mit `allow_redirects=False` und eigener Weiterleitungsschleife (höchstens 3), bindet die Verbindung an die beobachtete IP (`Host`-Header gesetzt, Ziel per IP), streamt in eine `NamedTemporaryFile` und bricht über `FETCH_MAX_BYTES` ab, bestimmt `magic` aus den ersten acht Bytes und verschiebt dann nach `CAPTURE_DIR`. Niemals `shell=True`, niemals ausführen.

- [ ] **Step 4: Create the directory and the Defender exclusion at startup**

Beim Start (neben `_start_update_check_thread`, `app.py:10901`): `geoip.load()` einmal rufen (Einarmig, `data_dir` vorbelegt; schlägt es fehl, bleibt `available()` falsch und der Tab läuft ohne Geo weiter), `CAPTURE_DIR` anlegen und `Add-MpPreference -ExclusionPath` idempotent setzen, Fehler nur loggen. Dieselbe Zeile zusätzlich in `scripts/install-webui.ps1` neben der bestehenden `scan_uploads`-Ausnahme. `CAPTURE_DIR` kommt in `_readable_roots` und **nicht** in die Schreib-Allowlist.

Dazu ein Test: mit der Geo-Fixture geladen trägt `/api/firewall/connections` für eine öffentliche IP `geo.cc` und `geo.asn`, ohne geladene Daten `geo.scope` und sonst `null` — und keine der beiden Lagen wirft.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall_api.py -v`
Expected: PASS (13 Tests)

- [ ] **Step 6: Commit**

```bash
git add webui/app.py scripts/install-webui.ps1 tests/test_firewall_api.py tests/conftest.py
git commit -m "feat(firewall): API, guarded sample fetch and the capture store"
```

---

### Task 6: Die Weltkarte

**Files:**
- Neu: `webui/static/data/world.json`
- Neu: `scripts/build-worldmap.py`
- Modify: `webui/static/js/app.js` (neue Funktionen im Chart-Kit-Bereich, nach `sankeySvg` bei `app.js:3693`)
- Neu: `tests/test_worldmap.py` (Datenform), Ergänzung in `tests/test_firewall_ui.py` folgt in Task 7

**Interfaces:**
- Consumes: nichts.
- Produces:
  - `world.json`: `{"scale": 10, "shapes": [[lon0, lat0, lon1, lat1, …], …]}` — Zehntelgrad als Ganzzahlen
  - `project(lon, lat, box) -> [x, y]`
  - `worldMapSvg(points, arcs, opts) -> string` — `points: [{id, lon, lat, label, tone, r}]`, `arcs: [{from, to, tone, weight, pending}]`
  - `WORLD_BOX = {lon0: -180, lon1: 180, lat0: 82, lat1: -58, w: 720, h: 280}`

- [ ] **Step 1: Write the failing test**

```python
def test_world_data_is_small_and_well_formed():
    data = json.load(open("webui/static/data/world.json"))
    assert data["scale"] == 10
    assert 20 <= len(data["shapes"]) <= 400
    for ring in data["shapes"]:
        assert len(ring) >= 6 and len(ring) % 2 == 0
        assert all(isinstance(v, int) for v in ring)
        assert all(-1800 <= ring[i] <= 1800 for i in range(0, len(ring), 2))
        assert all(-900 <= ring[i] <= 900 for i in range(1, len(ring), 2))
    assert os.path.getsize("webui/static/data/world.json") < 300_000
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/test_worldmap.py -v`
Expected: FAIL, `FileNotFoundError`

- [ ] **Step 3: Write `scripts/build-worldmap.py` and generate the data**

Das Skript liest eine Natural-Earth-110m-Landmaske (public domain) als GeoJSON von einem Pfad, den man ihm gibt, vereinfacht mit Douglas-Peucker auf eine Toleranz von 0,4°, wirft Ringe unter 1,5° Umfang weg, rundet auf Zehntelgrad und schreibt `world.json`. Die Herkunft und die Lizenz kommen in `webui/static/data/SOURCES.md`. Das Ergebnis wird **eingecheckt**; das Skript ist nur für die Auffrischung da.

- [ ] **Step 4: Implement `project` and `worldMapSvg` in `app.js`**

Äquidistant zylindrisch, auf `WORLD_BOX` beschnitten. Gezeichnet wird als Template-String-SVG wie die übrigen Diagramme: Gradnetz (`.fw-grat`), Landmaske (`.fw-land`), dann die Bögen als quadratische Béziers mit einem Kontrollpunkt senkrecht zur Mitte (Faktor 0,17), dann die Punkte mit Pille und Text. Farben kommen als Klassen (`.fw-tone-critical` … `.fw-tone-info`), nicht als Literale, damit der Theme-Wechsel ohne Neuzeichnen wirkt. Jeder Punkt und jeder Bogen trägt `data-fw-id`, damit ein Klick den Perspektivwechsel auslösen kann. Bögen mit `pending: true` bekommen die Klasse `.fw-arc-pending`; deren Animation steht in der CSS unter `prefers-reduced-motion` still.

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest tests/test_worldmap.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add webui/static/data scripts/build-worldmap.py webui/static/js/app.js tests/test_worldmap.py
git commit -m "feat(firewall): offline world map as self-drawn SVG"
```

---

### Task 7: Der Tab

**Files:**
- Modify: `webui/templates/index.html` (Nav-Knopf nach `data-tab="sysmon"` bei Zeile 88; Panel `#tab-firewall` vor `#tab-logs` bei Zeile 638; Help-Eintrag in `#help-usage` in derselben Reihenfolge; `?v=` bei Zeile 22–24 und 1620)
- Modify: `webui/static/js/app.js` (neuer Block `// --- FIREWALL ---`; Weiche in `switchTab` bei `app.js:432`)
- Modify: `webui/static/css/style.css` (Tokens in `:root`, Block `/* FIREWALL */`), `theme-layout.css` (`[data-theme] .fw-*`), `theme-cyberpunk.css` (scoped)
- Neu: `tests/test_firewall_ui.py`
- Modify: `tests/test_theme.py` (12 → 13, 14 → 15)

**Interfaces:**
- Consumes: `worldMapSvg`, `project` (Task 6); die Routen aus Task 5.
- Produces:
  - `FW_RANGES`, `FW_DEFAULT_RANGE`, `FW_ASK_MODES`, `FW_TONES`, `FW_VIEWS = ['map','list','asn']`, `FW_LIVE_MS = 5000`, `FW_HINTS`
  - `initFirewall()`, `firewallTabShown()`, `refreshFirewall(opts)`
  - `renderFirewallTree(flows)`, `renderFirewallMap(flows)`, `renderFirewallList(flows)`, `renderFirewallAsn(flows)`, `renderFirewallSummary(summary)`, `renderFirewallHints(sel)`
  - `fwDefang(text) -> string`
  - `fwBlock(scope, flow)`, `fwUnblock(ruleId)`, `fwToggleIsolated()`, `fwSetAsk(mode)`
  - `renderFirewallCaptures(captures)` — die gesicherten Samples mit `RIZIN`, `HEX`, `THREATSCAN`
  - `fwSelect(id)` — wählt Prozess, Endpunkt oder Kartenpunkt

- [ ] **Step 1: Write the failing tests**

Nach dem Muster von `tests/test_logs_ui.py` (Node über `_function_source` / `_run_node`, DOM-Stubs):

```python
def test_malware_text_never_becomes_markup():
    out = render_tree([flow(image=r'C:\x\<img src=x onerror=alert(1)>.exe',
                            hostname='<script>a</script>evil.example',
                            as_org='"><b>ACME')])
    assert "<script>" not in out and "onerror=" not in out
    assert "&lt;script&gt;" in out

def test_urls_and_hosts_are_defanged_and_never_links():
    out = render_tree([flow(hostname="evil.example", url="http://evil.example/a.dll")])
    assert "hxxp://" in out and "evil[.]example" in out
    assert "<a " not in out and "href=" not in out

def test_a_javascript_url_stays_text():
    assert "javascript:" not in fw_defang("javascript:alert(1)")

def test_the_highest_tag_sets_the_tone():
    assert tone_of(["dropped", "ioc", "lolbin"]) == "critical"
    assert tone_of(["newborn"]) == "low"

def test_local_endpoints_are_not_on_the_map():
    out = render_map([flow(dst="192.168.64.1", scope="local"), flow(dst="1.2.3.4")])
    assert out.count("data-fw-id") == 1

def test_tdc_processes_sit_in_their_own_collapsed_group():
    out = render_tree([flow(image=TDC_PYTHON, self=True), flow(image=LOADER)])
    assert "fw-group-tdc" in out and 'data-fw-open="false"' in out

def test_deny_is_disabled_while_a_profile_is_off():
    out = render_tree([flow()], {"profiles_off": ["Public"]})
    assert "disabled" in out and "Windows Firewall is off" in out

def test_firewall_records_are_labelled_as_the_endpoint_s():
    out = render_list([flow(fw_dropped=3)])
    assert "FW (endpoint)" in out

def test_no_byte_columns_in_part_a():
    out = render_summary(SUMMARY)
    assert "MB" not in out and "sent" not in out.lower()

def test_a_stale_response_does_not_overwrite_a_newer_one():
    assert fw_sequence_drops_stale() is True

def test_live_pauses_in_a_hidden_tab():
    assert fw_live_tick_when(hidden=True, activeTab="firewall") == "skipped"
    assert fw_live_tick_when(hidden=False, activeTab="logs") == "skipped"

def test_tab_button_sits_between_sysmon_and_logs():
    tabs = [b["data-tab"] for b in _Elements(INDEX_HTML).nav_tabs()]
    assert tabs[tabs.index("sysmon") + 1] == "firewall"
    assert tabs[tabs.index("firewall") + 1] == "logs"

def test_the_tab_has_its_info_text_and_a_help_entry():
    assert len(_Elements(INDEX_HTML).data_info("firewall")) <= 300
    assert "FIREWALL" in _read(INDEX_HTML).split('id="help-usage"')[1]

def test_isolated_asks_before_it_cuts():
    calls = fw_toggle_isolated_clicks()
    assert calls["confirm"] == 1 and calls["post"] == 0      # declined: nothing sent
    assert fw_toggle_isolated_clicks(confirm=True)["post"] == 1

def test_a_capture_opens_in_rizin_hex_and_threatscan():
    out = render_captures([capture(sha256="a3f1", path=r"C:\tdc\samples\a3\a3f1")])
    for label in ("RIZIN", "HEX", "THREATSCAN"):
        assert label in out
    assert "data-fw-open" in out and "executed" not in out.lower()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall_ui.py -v`
Expected: FAIL, die Funktionen und die Elemente fehlen

- [ ] **Step 3: Add the markup in `index.html`**

Nav-Knopf `<button class="tab" data-tab="firewall">Firewall</button>` direkt nach Sysmon. Panel `#tab-firewall` mit `.content-header > h2[data-info]`, dem Kopf (`LIVE`, `ASK ▾`, `ISOLATED`, Zeitbereich), dem Band für die abgeschaltete Firewall, dem Raster `#firewall-tree` / `#firewall-view` / `#firewall-summary`, dem Umschalter `#firewall-views` und dem Hinweisblock `#firewall-hints`. Help-Eintrag `<h4>FIREWALL</h4>` zwischen Sysmon und LOGS. Alle vier `?v=` erhöhen.

- [ ] **Step 4: Implement the FIREWALL block in `app.js`**

Aufbau genau wie der LOGS-Block: Konstanten, `let`-Zustand, Renderfunktionen, **ein** delegierter Klick-Handler (`onFirewallClick` über `data-fw-*`), ein monoton steigender `fwSeq` gegen veraltete Antworten, `fwLiveTick` mit den Abbrüchen bei `document.hidden` und fremdem Tab, `initFirewall()` einmalig und `firewallTabShown()` aus `switchTab`. `fwDefang` ersetzt `http`→`hxxp`, `.`→`[.]` im Hostteil und schreibt jedes andere Schema als `scheme[:]`. Jede Ausgabe durch `escapeHtml`; Klassennamen durch `cssToken`.

`fwToggleIsolated` geht durch den vorhandenen `tdcConfirm(options)` (`danger: true`, Totenkopf, Fokus auf Abbrechen) und schickt erst nach der Bestätigung. Der Text nennt, was abgeschnitten wird, was erreichbar bleibt und den Weg zurück über `scripts/tdc-unisolate.ps1`.

`renderFirewallCaptures` zeigt pro Capture Zeitpunkt, defanged URL, Größe, `magic` und die gekürzte SHA-256, dazu `RIZIN`, `HEX` und `THREATSCAN` über die vorhandenen Einsprünge mit einem Pfad (`rizinOpenPath`, `hexOpenFile`, der Scan-Upload-Weg). Kein Knopf, der etwas ausführt.

- [ ] **Step 5: Add the styles**

`style.css`: Tokens `--fw-tone-critical` … `--fw-tone-info`, `--fw-land`, `--fw-grat`, `--fw-chamber` in `:root`, danach der Block `/* FIREWALL */`. `theme-layout.css`: die Form unter `[data-theme] .fw-*`, inklusive des Umbruchs auf eine Spalte unter 900 px und der Summary als dritte Spalte ab 1400 px. `theme-cyberpunk.css`: die Tokens neu gesetzt, scoped. Die Animation `.fw-arc-pending` im `prefers-reduced-motion`-Block stillstellen.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall_ui.py tests/test_theme.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add webui/templates/index.html webui/static/js/app.js webui/static/css tests/test_firewall_ui.py tests/test_theme.py
git commit -m "feat(firewall): FIREWALL tab with process tree, world map and summary"
```

---

### Task 8: Der Entscheidungs-Toast

**Files:**
- Modify: `webui/static/js/app.js` (`showDecisionToast` neben `showToast` bei `app.js:8`; der Abruf von `/api/firewall/pending` im Polling)
- Modify: `webui/static/css/style.css`, `theme-layout.css` (`.toast-decision`)
- Modify: `tests/test_firewall_ui.py`

**Interfaces:**
- Consumes: `GET /api/firewall/pending`, `POST /api/firewall/decide` (Task 5).
- Produces:
  - `showDecisionToast(item) -> HTMLElement`
  - `fwPendingPoll()`, `FW_PENDING_MS = 3000`, `FW_TOASTS_VISIBLE = 3`
  - `fwDecide(id, action)`

- [ ] **Step 1: Write the failing tests**

```python
def test_a_decision_toast_never_dismisses_itself():
    assert decision_toast_timers() == []

def test_the_countdown_names_the_default_action():
    out = decision_toast({"deadline_in": 24})
    assert "0:24" in out and "FETCH" in out.upper()

def test_three_are_shown_and_the_rest_counted():
    out = render_pending([p(1), p(2), p(3), p(4), p(5)])
    assert out.count("toast-decision") == 3 and "+ 2 more" in out

def test_the_throttle_of_showToast_does_not_apply():
    assert decision_toasts_for_same_title(2) == 2

def test_the_url_in_a_toast_is_defanged_text():
    out = decision_toast({"url": "http://evil.example/a.dll"})
    assert "hxxp://evil[.]example/a.dll" in out and "<a " not in out

def test_answering_twice_sends_one_request():
    assert decide_clicks_sent_after_double_click() == 1

def test_an_absence_summary_is_announced_once():
    out = absence_toast({"captures": 3})
    assert "3" in out and "away" in out.lower()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall_ui.py -k decision -v`
Expected: FAIL

- [ ] **Step 3: Implement `showDecisionToast` and the polling**

Eigene Form neben `showToast`, ohne `_toastThrottle` und ohne `autoDismiss`. Knöpfe `KAPPEN + SELBST HOLEN` (primär), `NUR KAPPEN`, `ZULASSEN`, `in LOGS ▸`. Nach dem ersten Klick werden alle Knöpfe deaktiviert, damit ein Doppelklick nicht zwei Anfragen schickt. Der Countdown zählt `deadline_in` herunter, das der Server mitgibt; läuft er ab, bleibt der Toast als Quittung stehen, bis der nächste `/pending`-Abruf ihn ablöst. Gepollt wird alle 3 s, ausgesetzt bei `document.hidden`. Beim ersten Abruf nach dem Laden fasst ein Info-Toast zusammen, was in Abwesenheit entschieden und gesichert wurde.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall_ui.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/static/js/app.js webui/static/css tests/test_firewall_ui.py
git commit -m "feat(firewall): decision toast with accept, cut and fetch"
```

---

### Task 9: Perspektivwechsel

**Files:**
- Modify: `webui/static/js/app.js` (`openLogsTab` neben `openAlertsTab` bei `app.js:1826`; der Rückweg-Chip im LOGS-Block; Knopf `FIREWALL` am Netzwerk-Detailpanel des Graphen bei `app.js:10995` und in der Tracing-Konsole)
- Modify: `tests/test_firewall_ui.py`, `tests/test_logs_ui.py`

**Interfaces:**
- Consumes: `logsSetQuery`, `logsSetRange`, `logsZoom`, `logsReady`, `switchTab` (vorhanden); `fwSelect` (Task 7).
- Produces:
  - `openLogsTab(query: string, earliest?: string, latest?: string, back?: string) -> void`
  - `openFirewallTab(filter: {ip?, port?, image?}) -> void`
  - `logsBackChipHtml() -> string`, `logsBack` (Zustand)

- [ ] **Step 1: Write the failing tests**

```python
def test_open_logs_tab_sets_query_and_window():
    s = open_logs_tab('dst_ip="1.2.3.4"', "2026-11-16T14:02:00Z", "2026-11-16T14:19:00Z")
    assert s["activeTab"] == "logs"
    assert s["query"] == 'dst_ip="1.2.3.4"'
    assert (s["earliest"], s["latest"]) == ("2026-11-16T14:02:00Z", "2026-11-16T14:19:00Z")

def test_the_first_open_is_not_overwritten_by_the_last_search():
    s = open_logs_tab_cold('dst_ip="1.2.3.4"')      # logsReady false, stored query present
    assert s["query"] == 'dst_ip="1.2.3.4"'

def test_the_way_back_is_shown_and_removable():
    out = logs_back_chip("firewall")
    assert "FIREWALL" in out and 'data-logs-back' in out

def test_a_hint_click_quotes_the_value_safely():
    q = hint_query('dst_ip="%s" | top image', 'a"b\\')
    assert q.count('"') % 2 == 0 and not q.endswith('\\"')

def test_open_firewall_tab_filters_on_the_endpoint():
    s = open_firewall_tab({"ip": "1.2.3.4", "port": 443})
    assert s["activeTab"] == "firewall" and s["selected"] == "1.2.3.4:443"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_firewall_ui.py -k "logs or firewall_tab" -v`
Expected: FAIL

- [ ] **Step 3: Implement `openLogsTab` and `openFirewallTab`**

`openLogsTab` setzt `logsLimit` zurück, wechselt den Tab (womit `logsTabShown` und beim ersten Mal `initLogs` läuft), setzt **danach** Zeitfenster und Query und sucht. Der `logsLastQuery()`-Pfad in `initLogs` darf eine mitgegebene Query nicht überschreiben — dafür eine Zustandsvariable `logsPending`, die `initLogs` beachtet. Werte in Queries gehen immer durch `logsQuote`. Der Rückweg steht als Chip `← FIREWALL` über der Suchzeile, Klick ruft `openFirewallTab` mit dem gemerkten Filter.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_firewall_ui.py tests/test_logs_ui.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add webui/static/js/app.js tests/test_firewall_ui.py tests/test_logs_ui.py
git commit -m "feat(firewall): perspective switch between FIREWALL and LOGS"
```

---

### Task 10: Doku, MCP und Deploy

**Files:**
- Modify: `README.md` (Tabellenzeile, Abschnitt `## Firewall`, API-Zeilen, MCP-Werkzeugzahl)
- Modify: `webui/templates/index.html` (`#help-api`-Zeilen)
- Modify: `mcp/server.py` (zwei lesende Werkzeuge)
- Modify: `Makefile`, `make.ps1`, `scripts/deploy-utm.py`
- Neu: `docs/superpowers/plans/2026-11-16-firewall-tab-handover.md`

**Interfaces:**
- Consumes: alle Routen aus Task 5.
- Produces: `tdc_firewall_connections(since="-24h", tag="", process="", limit=100)`, `tdc_firewall_captures(limit=50)`.

- [ ] **Step 1: Run the documentation tests to see them fail**

Run: `python -m pytest tests/test_docs.py -v`
Expected: FAIL — `test_readme_tabs_match_the_ui`, `test_help_tab_guide_covers_every_tab`, die API-Tabellenprüfung und `test_every_deploy_path_uploads_the_web_ui_modules`

- [ ] **Step 2: Add the README row, section and API rows**

Tabellenzeile `FIREWALL` zwischen Sysmon und LOGS, in der Machart der übrigen Zeilen. Abschnitt `## Firewall` mit: was der Tab zeigt, die Tag-Tabelle, die drei `ASK`-Stellungen, Isolated samt `scripts/tdc-unisolate.ps1`, der Hunting-Teil mit den fünf Beispielsuchen, dem Sample-Store und dem Satz, warum in Teil A keine Byte-Zahlen stehen. Die zwölf API-Zeilen in die API-Tabelle und nach `#help-api`.

- [ ] **Step 3: Add the two read-only MCP tools**

`tdc_firewall_connections` und `tdc_firewall_captures` nach dem Muster von `tdc_logs_search` (`mcp/server.py:1615`). Kein Werkzeug, das sperrt, isoliert oder entscheidet. Die Werkzeugzahl im README (`(N tools`) anheben.

- [ ] **Step 4: Add the new files to all three deploy paths**

`firewall.py`, `firewall_store.py`, `firewall_rules.py`, `geoip.py` und die Verzeichnisse `webui/data/` und `webui/static/data/` in `scripts/deploy-utm.py` (`FILES`), `Makefile` (`deploy`) und `make.ps1`.

- [ ] **Step 5: Run the whole suite**

Run: `make -s unit-test`
Expected: PASS, auch unter `TZ=Europe/Berlin`

- [ ] **Step 6: Write the handover note**

`docs/superpowers/plans/2026-11-16-firewall-tab-handover.md`: die drei Screenshots, die auf einer laufenden VM entstehen müssen (Tab mit Karte und Prozessbaum, Toast mit offener Entscheidung, Isolated aktiv mit rotem Band), wohin sie im README gehören, und die Erinnerung, dass `make geoip` und `scripts/configure-logging.ps1` auf einer bestehenden VM einmal laufen müssen.

- [ ] **Step 7: Commit**

```bash
git add README.md webui/templates/index.html mcp/server.py Makefile make.ps1 scripts/deploy-utm.py docs/superpowers/plans
git commit -m "docs(firewall): README, help, MCP tools and deploy paths"
```
