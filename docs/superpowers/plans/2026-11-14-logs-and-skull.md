# Skull-Button, Dialog und Tab „Logs“ – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- Ein roter Totenkopf-Knopf für „Update all“ und ein eigener Bestätigungsdialog.
- Ein neuer Top-Menü-Tab LOGS. Er zeigt PowerShell, Access, MCP, Netflow, DNS und Firewall und hat eine Suche nach Art von SPL.

**Architecture:**
- Teil A ist rein Frontend: `app.js` mit `skullButtonSvg()` und `tdcConfirm()`, dazu CSS in beiden Themes.
- Teil B:
  - `webui/log_search.py` (neu) ist der reine Parser und Auswerter.
  - `webui/log_store.py` (neu) enthält Ringpuffer, JSONL-Persistenz und Parser für die Quellen, mit injizierten Lesern.
  - `webui/app.py` liefert die Access- und MCP-Erfassung in `after_request`, den Collector-Thread und die Routen.
  - `mcp/server.py` sendet zwei Header und bekommt ein neues Tool.
  - `scripts/configure-logging.ps1` schaltet PowerShell- und Firewall-Logging ein.

**Tech Stack:** Python 3.9 / Flask, Vanilla JS, SVG, CSS, PowerShell 5.1, pytest + Node.

**Spec:** `docs/superpowers/specs/2026-11-14-logs-and-skull-design.md`

## Global Constraints

- **Python:**
  - 3.9-kompatibel, `from __future__ import annotations`;
  - keine neue Abhängigkeit;
  - Code-Kommentare, Oberfläche und README englisch.
- **Frontend:**
  - Vanilla JS mit Funktionen auf oberster Ebene.
  - Alles, was aus Logs kommt, ist escaped (`escapeHtml`) oder `textContent`. Inline-`on*` interpoliert nur `jsArg`/`jsInt`.
  - Farben nur als `var(--…)`. Farbwerte nur in `:root` von `style.css`. Cyberpunk nur unter `[data-theme="cyberpunk"]`. Keine gemeinsamen `@keyframes`-Namen.
  - `?v=`-Versionen in `index.html` erhöhen.
- **Neuer Tab (Tests beachten):**
  - README-Tabelle `### Web UI Tabs` und Hilfe `#help-usage` mit `<h4>LOGS`/Tabname, wie die anderen.
  - `test_info_texts_cover_every_tab` zählt dann 12 `.content-header` und 14 `.tab-content`. Zählung im Test anpassen.
  - `data-info` für den Tab: höchstens 300 Zeichen, 1–2 Sätze, ohne `<`, `&`, `${`.
- **Grenzwerte:**
  - Store höchstens 50 000 Ereignisse;
  - Startlesen 24 h und höchstens 5000 pro Windows-Quelle;
  - Poll 10 s;
  - JSONL-Rotation 10 MB, eine alte Datei;
  - Suche höchstens 10 000 Treffer in den Pipes, Antwort höchstens 1000 Zeilen;
  - Feld-Seitenleiste Top 10.
- **Quellen-IDs genau so:** `powershell`, `access`, `mcp`, `netflow`, `dns`, `firewall`.
- **MCP-Header genau so:** `X-TDC-Client: mcp`, `X-TDC-MCP-Tool: <toolname>`.
- **Polling-Pfade** mit `fields.poll = true`: `/api/logs/`, `/api/status`, `/api/updates`, `/api/alerts`, `/api/health`.
- **Deploy:** Neue Module `webui/log_search.py` und `webui/log_store.py` gehen in die drei Deploy-Wege (`deploy-utm.py` FILES, Makefile `deploy:`/`deploy-app`, `make.ps1`). `webui/logs/` kommt in `.gitignore`.
- **Doku:** Neue Routen in der README-API-Tabelle und in `#help-api`. Neue MCP-Tools in der README-Liste mit `(N tools`.
- **Tests:** `make -s unit-test`. Einzeln: `webui/.venv/bin/python -m pytest tests/<datei> -q`. Die CI läuft unter `TZ=UTC` und `TZ=Europe/Berlin`.

## Review Focus

1. **Malware-Text in Script Blocks** (`<script>`, ANSI, 100 000 Zeichen, NUL): Er bleibt Text, und die Liste kürzt ihn optisch (aufklappbar). Tests in Task 3 und 5.
2. **Kaputte oder feindliche Suchanfragen** (offene Klammer, `| stats` ohne Funktion, Regex-Sonderzeichen im Wert, 10 000 Zeichen): Sie ergeben 400 mit `pos` und nie 500. Test in Task 2.
3. **Suche bei vollem Store:** Sie gibt das Lock sofort frei; `/api/health` antwortet währenddessen. Test in Task 4.
4. **Collector ohne Windows oder ohne Kanal:** Er wirft nicht. Die Quelle zeigt `unavailable` mit Hinweis. Test in Task 3/4.
5. **MCP-Aufruf ohne Header** (alter MCP-Server): Er wird als `access` mit `client=other` geführt, aber nicht als `mcp`. Test in Task 4.

---

### Task 1: Skull-Button und `tdcConfirm`

**Files:**
- Ändern: `webui/static/js/app.js` (Update-Panel aus dem vorigen Feature: `renderUpdates`/`updatesHtml`, `applyUpdates`), `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`, `webui/templates/index.html` (`?v=`).
- Tests: `tests/test_tool_updates_ui.py` (erweitern).

**Interfaces – Produces:**
- `function skullButtonSvg() -> string`: ein Inline-SVG. Verläufe bekommen eindeutige IDs mit Präfix `tdc-skull-`. Farben kommen über `var(--…)`-Variablen: neu in `:root` z. B. `--skull-red`, `--skull-red-dark`, `--skull-shine`, `--skull-bone`.
- **Update-all-Knopf:** `<button class="btn-skull" …>` mit SVG, Text `UPDATE ALL` und Badge `N`.
  - Bei N = 0 oder Modus ≠ `idle` hat er `disabled` und einen `title` mit dem Grund: `No updates to install` bzw. `An update check or install is running`.
  - Der Knopftext enthält weiterhin `Update all (N)` für Screenreader (`aria-label="Update all (N)"`), damit der bisherige Test passt. Den Test darauf anpassen.
- `function tdcConfirm({title, message, items = [], confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false}) -> Promise<boolean>`:
  - Erzeugt `#tdc-confirm` (Backdrop plus Dialog, `role="dialog"`, `aria-modal="true"`, `aria-labelledby`) und entfernt ihn beim Schließen wieder.
  - `items` sind `{name, from, to}` und werden als Liste gezeigt; höchstens 12, darunter `+ K more`.
  - Esc und Klick auf den Backdrop ergeben `false`, Enter auf den Bestätigungs-Knopf `true`. Der Fokus liegt am Anfang auf Abbrechen, Tab bleibt im Dialog, danach kehrt der Fokus zurück.
  - Bei `danger` erscheint das Totenkopf-SVG im Kopf.
  - Alle Texte kommen über `textContent`.
  - Ein zweiter Aufruf, solange einer offen ist, löst den ersten mit `false` auf.
- **Einsatz im Update-Panel:**
  - **Update all:** `tdcConfirm({title: "Install N updates?", message: "Detonations, scans and uploads are paused while they run.", items, confirmLabel: "Install", danger: true})`.
  - **Gepinntes Tool:** `title: "<name> is pinned"`, `message: "<name> is pinned to <pin> for compatibility. Install <available> anyway?"`, `confirmLabel: "Install anyway"`, `danger: true`. Für choco-Python steht der Detailtext des Eintrags in `message`, wie bisher.
  - Bei N = 1 heißt der Titel `Install 1 update?`.
- **Aussehen:**
  - Der Knopf wirkt glänzend: Verlauf, Lichtreflex, Schatten. Beim Hover pulsiert ein roter Glow; mit `prefers-reduced-motion` gibt es keine Animation.
  - Der Dialog ist zentriert und hat einen Backdrop mit Blur.
  - Cyberpunk: Neonrand, Scanlines (`repeating-linear-gradient` mit Variablen) und ein Glitch beim Öffnen (eigener `@keyframes`-Name).
  - Classic: ruhig, mit dem bisherigen Card-Stil.

- [ ] **Step 1: Failing tests** (Node, DOM-Stub wie in den vorhandenen UI-Tests):
  - `test_skull_svg_has_no_colour_literals`.
  - `test_update_all_uses_skull_button`: Der Knopf hat die Klasse `btn-skull` und `aria-label` `Update all (2)`; bei 0 ist er `disabled` mit `title`.
  - `test_confirm_resolves_false_on_escape_and_backdrop`.
  - `test_confirm_resolves_true_on_confirm`.
  - `test_confirm_escapes_items`: Ein Item-Name `<img onerror>` erscheint nur als Text.
  - `test_confirm_lists_at_most_12_items`: 15 Items ergeben 12 Einträge und `+ 3 more`.
  - `test_update_all_calls_tdcConfirm_not_native_confirm`: `confirm` ist im Stub nicht definiert bzw. wirft; der Fluss läuft über `tdcConfirm`.
  - `test_singular_title`.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Umsetzen.
- [ ] **Step 4:** `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(updates): skull update-all button and themed confirm dialog`.

### Task 2: Suchsprache (`webui/log_search.py`)

**Files:** Neu `webui/log_search.py`, `tests/test_log_search.py`. Das Modul in die drei Deploy-Wege aufnehmen.

**Interfaces – Produces:**
- `class SearchError(Exception)` mit `.pos: int`.
- `parse(query: str) -> Query` mit `Query.terms` (AST), `Query.pipes: list[Pipe]`, `Query.earliest: str | None`, `Query.latest: str | None`.
- `resolve_time(value: str, now: datetime) -> datetime` für `-15m`, `-2h`, `-1d`, `-1w`, `now` und ISO-8601. Ein ungültiger Wert ergibt einen `SearchError`.
- `run(query: str, events: Iterable[dict], now: datetime, earliest: str | None = None, latest: str | None = None, max_matches: int = 10000, max_rows: int = 1000) -> dict`:
  - Inline-Zeiten im Query haben Vorrang vor den Parametern.
  - Ereignisformat laut Spec. Felder werden über `fields`, `source`, `time`, `message` und `id` adressiert; `sourcetype` und `index` sind Aliase für `source`.
  - **Ergebnis bei Ereignissen:** `{"type": "events", "events": [...], "count", "matched", "truncated", "histogram": {"bins": [{"start", "end", "counts": {source: n}}], "span_s"}, "fields": [{"name", "count", "top": [{"value", "count"}]}], "columns": None}`.
  - **Bei transformierenden Pipes:** `"type": "table"` mit `columns` und `rows`; `histogram` und `fields` beziehen sich auf die Treffer vor den Pipes.
  - **Bei `timechart`:** `"type": "timechart"` mit `columns` (`_time`, Serie…) und `rows`.
- **Semantik:**
  - **Wörter:** Groß-/Kleinschreibung egal, Teilstring über `message` und alle Feldwerte. `*` ist ein Platzhalter. Wörter und Werte werden escaped, bevor sie zu Regex werden; kein Nutzer-Regex.
  - **Vergleiche:** `=` und `!=` vergleichen Text (Platzhalter erlaubt, Groß-/Kleinschreibung egal). `>`, `<`, `>=`, `<=` vergleichen numerisch, wenn beide Seiten Zahlen sind, sonst als Text. Ein fehlendes Feld passt bei `=` nie und bei `!=` immer.
  - **Vorrang:** `NOT` vor `AND` vor `OR`. `AND` ist implizit, Klammern sind erlaubt.
  - **Pipes:** wie in der Spec. `stats` ohne `by` ergibt eine Zeile; `values()` ist sortiert und auf 100 Werte begrenzt. `top` und `rare` haben den Standard N = 10 und die Spalten `feld`, `count`, `percent`. `timechart span=` hat die Einheiten `s`, `m`, `h`, `d`, ohne `span` gilt die automatische Breite (etwa 60 Bins).
  - **Histogramm:** etwa 60 Bins über den Zeitraum der Treffer bzw. `earliest`–`latest`.
  - **Fehlertexte:** `Unknown command: x`, `Unbalanced parenthesis`, `Expected a function after stats`, `Invalid time: x`. Die Anfrage darf höchstens 4000 Zeichen lang sein, sonst `Query too long`.

- [ ] **Step 1: Failing tests:**
  - Freitext, Phrase, Platzhalter.
  - `source=powershell`, `index=dns`.
  - `status>=400` numerisch; `status>=400` auf ein Text-Feld.
  - `NOT`, `OR` mit Klammern, implizites `AND`.
  - `earliest=-15m` gegen ein festes `now`.
  - `| stats count by source`; `| stats dc(dst_ip) as hosts by image`.
  - `| top 3 query`.
  - `| sort -count | head 2`.
  - `| table time, source, message`.
  - `| dedup dst_ip`.
  - `| timechart span=1m count by source`.
  - Histogramm-Bins summieren sich zu `matched`.
  - Feld-Seitenleiste: Top 10.
  - `max_rows` setzt `truncated`.
  - Ein Wert mit `.*+?[](){}|\^$` passt wörtlich.
  - Parametrisierte Fehler mit `pos`: `(a`, `| stats`, `| foo`, `earliest=-xz`, 4001 Zeichen.
  - Kein Absturz bei `None`, Listen und Zahlen in `fields`.
- [ ] **Step 2:** FAIL. **Step 3:** Umsetzen, mit Tokenizer und rekursivem Abstieg. **Step 4:** grün, `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(logs): SPL-like search language`.

### Task 3: Log-Store und Quellen-Parser (`webui/log_store.py`)

**Files:** Neu `webui/log_store.py`, `tests/test_log_store.py`. Das Modul geht in die drei Deploy-Wege, `webui/logs/` in `.gitignore`.

**Interfaces – Consumes:** keine aus Task 2. Der Store liefert Ereignisse, die Task 4 an `log_search.run` gibt.

**Interfaces – Produces:**
- `SOURCES = ("powershell", "access", "mcp", "netflow", "dns", "firewall")`.
- **`class LogStore(max_events=50000, persist_dir: str | None = None)`:**
  - `.add(source, time, message, fields) -> dict` vergibt `id` (monoton, `"<source>-<n>"`).
  - `.extend(events)`, `.snapshot() -> list[dict]` (Kopie der Liste, Lock nur für die Kopie).
  - `.counts() -> dict[source, int]`, `.last_time(source) -> str | None`.
  - `.set_status(source, status, hint="")` und `.sources() -> list[{"source","count","last_time","status","hint"}]`.
  - Verdrängt wird das älteste Ereignis insgesamt.
  - Persistenz nur für `access` und `mcp`:
    - Datei: `persist_dir/<source>.jsonl`;
    - Rotation: Ab 10 MB wird die Datei zu `<source>.jsonl.1`, eine alte Datei bleibt;
    - Laden: `.load_persisted()` liest beide Dateien in Zeitreihenfolge und ignoriert kaputte Zeilen.
- **`parse_powershell_events(xml_text: str) -> list[dict]`:**
  - Eingabe ist `wevtutil qe … /f:xml` mit mehreren `<Event>`-Elementen ohne Wurzel.
  - 4104: Felder `script_block_id`, `message_number`, `message_total`, `path`, `script` (ScriptBlockText).
  - Teile mit gleicher `ScriptBlockId` werden nach `MessageNumber` zu einem Ereignis zusammengesetzt; die Zeit ist die des ersten Teils. Fehlen noch Teile, bekommt das Ereignis `partial=true`.
  - 4103: `payload` (aus `Payload`), `context` (aus `ContextInfo`), daraus `host_application` und `command` per Regex, wenn vorhanden.
  - 4100: `error`.
  - Alle Ereignisse bekommen `event_id`, `record_id`, `pid`, `user_sid`.
  - `message` ist bei 4104 der Script-Text (ungekürzt), sonst der sinnvollste Text.
  - Kaputtes XML eines Events wird übersprungen.
- **`parse_firewall_log(text: str) -> list[dict]`:**
  - W3C-Format mit `#Fields:`-Kopf. Datum und Zeit sind lokale Zeit; sie werden mit dem lokalen Offset nach UTC umgerechnet.
  - Felder: `action`, `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `size`, `path`, `direction`.
  - `message` lautet `ALLOW TCP 10.0.0.5:52311 -> 1.2.3.4:443`.
- **`netflows_from_sysmon(events: list[dict]) -> list[dict]`:**
  - Eingabe sind Sysmon-EID-3-Ereignisse im Format von `_read_sysmon_events` in `webui/app.py`; die Feldnamen dort nachlesen.
  - Gebündelt nach `(image, pid, protocol, src_ip, src_port→ignoriert, dst_ip, dst_port)`, d. h. der Quellport ist nicht Teil des Schlüssels.
  - Felder: `image`, `pid`, `protocol`, `src_ip`, `dst_ip`, `dst_port`, `dst_hostname`, `count`, `first_seen`, `last_seen`.
  - `time` ist `last_seen`, `message` lautet `image → dst_hostname|dst_ip:port (count×)`.
- **`dns_from_sysmon(events) -> list[dict]`** für EID 22: `query`, `result`, `image`, `pid`, `status`.
- **`class Collector(store, read_powershell, read_sysmon, read_firewall, now)`:**
  - Die Leser sind injizierte Funktionen:
    - `read_powershell(since_record_id) -> (xml_text, max_record_id)`;
    - `read_sysmon(event_ids, since_iso) -> list`;
    - `read_firewall(offset) -> (text, new_offset, status_hint)`.
  - `.tick()` liest inkrementell.
  - **netflow:** Die Flows des letzten Fensters werden neu gebündelt. Ein Flow mit gleichem Schlüssel wird aktualisiert, nicht doppelt gezählt: Der Store kennt `replace_netflows(flows)` für die Quelle `netflow`. Diese Methode gehört zu `LogStore` und ersetzt alle `netflow`-Einträge.
  - **Fehler:** Wirft ein Leser, bekommt die Quelle `unavailable` mit Hinweis aus der ersten Zeile; die anderen Quellen laufen weiter.
  - **Startlesen:** Zuerst 24 h bzw. höchstens 5000 pro Quelle.

- [ ] **Step 1: Failing tests** mit festen XML- und Text-Beispielen in `tests/samples/logs/` (neu):
  - 4104 in 3 Teilen, in falscher Reihenfolge, ergibt 1 Ereignis.
  - Ein fehlender Teil ergibt `partial`.
  - 4103 mit Payload.
  - Kaputtes Event wird übersprungen.
  - Script-Text mit `<script>` und ANSI bleibt roh im Feld; das Escapen ist Sache der UI.
  - Firewall-Log mit Kopf, Kommentaren und kaputter Zeile; UTC-Umrechnung mit festem Offset (Offset injizierbar).
  - Netflow-Bündelung mit Zählung.
  - Ringpuffer-Verdrängung über Quellen hinweg.
  - JSONL-Rotation und erneutes Laden (`tmp_path`).
  - Ein Collector, dessen Leser wirft, setzt `unavailable`, und die anderen Quellen laufen weiter.
  - `snapshot()` gibt eine Kopie zurück.
- [ ] **Step 2:** FAIL. **Step 3:** Umsetzen. **Step 4:** grün, `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(logs): log store and source parsers`.

### Task 4: Anbindung: Flask, MCP, Logging-Skript

**Files:**
- Ändern: `webui/app.py`, `mcp/server.py`, `tests/test_mcp.py`, `README.md` (API: `### Logs` mit zwei Zeilen; MCP-Liste und Anzahl; Konfigurations-Umgebungsvariable `TDC_LOG_DIR`, Standard `webui/logs` neben `app.py`), `webui/templates/index.html` (`#help-api`, MCP-Anzahl).
- Neu: `scripts/configure-logging.ps1`, eingebunden in `Vagrantfile`, `Vagrantfile.utm` und `scripts/setup-macos-utm.sh` (SCRIPTS-Liste), jeweils vor `configure-services.ps1`.
- Tests: `tests/test_logs_api.py` (neu), Erweiterung in `tests/test_tool_update_scripts.py` oder ein neuer statischer Test für das Skript.

**Interfaces – Consumes:** `LogStore`, `Collector` und die Parser aus Task 3; `log_search.run` und `SearchError` aus Task 2.

**Interfaces – Produces:**
- `after_request`:
  - Für jede Antwort außer auf `/static/` und `/favicon` kommt ein `access`-Ereignis in den Store. Felder: `method`, `path`, `query`, `status`, `duration_ms` (Start in `before_request` über `g`), `remote_addr`, `user_agent`, `client`, `poll`.
  - `client` ist `mcp`, wenn der Header `X-TDC-Client: mcp` gesetzt ist; `browser`, wenn der User-Agent `Mozilla` enthält; sonst `other`.
  - Bei `client=mcp` kommt zusätzlich ein `mcp`-Ereignis mit `tool` (Header), `method`, `path`, `status`, `duration_ms` und `message` (`tool → METHOD path (status)`).
  - Ein Fehler beim Loggen darf die Antwort nie stören (try/except).
- **Collector-Thread:** Er startet im `_background_disabled`-Block neben den anderen Threads und ruft alle 10 s `tick()` auf. Die echten Leser:
  - PowerShell über `_wevtutil_query` bzw. dasselbe Muster mit `Microsoft-Windows-PowerShell/Operational`, XPath `*[System[(EventID=4103 or EventID=4104 or EventID=4100) and EventRecordID>N]]`.
  - Sysmon über die vorhandenen Lesefunktionen (EID 3 und 22, `since`).
  - Die Firewall-Datei per Offset. Fehlt sie und ist die Firewall aus (`Get-NetFirewallProfile` einmal pro Minute gecacht oder Registry), lautet der Hinweis `Firewall is off; no packets are logged.`
  - Außerhalb von Windows sind die Windows-Quellen `unavailable` mit Hinweis `Windows event logs are only available on the VM.`
- **`GET /api/logs/search`:**
  - Parameter: `q` (Standard `*`), `earliest` (Standard `-24h`), `latest`, `limit` (1–1000, Standard 200).
  - Ablauf: `store.snapshot()`, dann `log_search.run(...)`.
  - Ergebnis: 200 mit dem Ergebnis plus `took_ms`. Bei einem `SearchError` 400 mit `{"error","pos"}`; andere Ausnahmen ergeben 500 mit allgemeinem Text, mit Log-Eintrag.
- **`GET /api/logs/sources`:** `store.sources()`.
- **`mcp/server.py`:**
  - `_get`, `_post` und `_call` senden `X-TDC-Client: mcp` und `X-TDC-MCP-Tool`. Den Tool-Namen liefert ein `contextvars.ContextVar`, gesetzt über einen Decorator oder einen Wrapper um jedes `@mcp.tool()`.
  - Die Lösung muss auch für die bestehenden 46 Tools gelten, ohne jedes Tool von Hand zu ändern.
  - Neues Tool `tdc_logs_search(query: str = "*", earliest: str = "-24h", limit: int = 100)`. Ergebnis: kompakter Text mit Anzahl und den ersten Zeilen bzw. der Tabelle. Docstring mit allen Argumenten.
- **`scripts/configure-logging.ps1`:**
  - Script Block Logging und Module Logging (`ModuleNames` `*`) über `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\…`.
  - `wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456`.
  - `Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767 -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`.
  - Darf mehrfach laufen, mit farbigen Meldungen, Exit 0.
  - Mit `pwsh` auf Syntax prüfen.

- [ ] **Step 1: Failing tests:**
  - Eine Anfrage ergibt ein `access`-Ereignis mit Status und Dauer.
  - Eine Anfrage mit MCP-Headern ergibt zusätzlich `mcp` mit `tool`.
  - Ohne Header wird sie nicht als `mcp` geführt.
  - `/static/…` wird nicht geloggt.
  - `/api/status` hat `poll=true`.
  - Search 200 mit Ergebnis-Schema; 400 mit `pos`.
  - `limit` wird geklemmt.
  - `/api/logs/sources` listet alle 6 Quellen.
  - Eine Suche über einen Store mit 50 000 Ereignissen blockiert `/api/health` nicht. Ein zweiter Thread hält parallel die Suche; die Health-Antwort kommt in unter 1 s.
  - MCP-Test: Das gemockte httpx bekommt beide Header mit dem richtigen Tool-Namen, für ein bestehendes Tool und für `tdc_logs_search`.
  - Ein statischer Skript-Test prüft `EnableScriptBlockLogging`, `EnableModuleLogging`, `LogAllowed True`, `LogBlocked True` und die Einbindung in die drei Provisionierungsdateien.
  - Die Doku-Tests sind grün.
- [ ] **Step 2:** FAIL. **Step 3:** Umsetzen. **Step 4:** `make -s unit-test` grün, inklusive MCP.
- [ ] **Step 5: Commit** `feat(logs): capture access and MCP logs, collectors and search API`.

### Task 5: Tab „LOGS“ im Frontend

**Files:** Ändern `webui/templates/index.html` (Tab-Knopf `LOGS` nach `SYSMON`, `#tab-logs` mit `.content-header` und `data-info`, Hilfe-Eintrag, `?v=`), `webui/static/js/app.js` (Block „LOGS“, `switchTab` lädt beim ersten Öffnen), CSS in beiden Themes, `README.md` (Tab-Tabelle und Abschnitt `## Logs` nach `## Tool Updates` mit Inhaltsverzeichnis-Eintrag, Quellen, Suchsyntax mit Beispielen und Hinweis auf `configure-logging.ps1`), `tests/test_theme.py` (Zählungen 12/14). Test: `tests/test_logs_ui.py` (neu).

**Interfaces – Consumes:** `/api/logs/search` und `/api/logs/sources` (Task 4).

**Interfaces – Produces (app.js, oberste Ebene):**
- **Zustand:** `let logsState = {query, earliest, latest, live, result, openIds}`.
- **Konstanten:** `LOGS_EXAMPLES` (mindestens: `source=powershell`, `source=mcp | stats count by tool`, `source=access NOT poll=true`, `source=netflow | sort -count | head 20`, `source=dns | top query`, `source=firewall action=DROP`, `* | timechart span=5m count by source`), `LOGS_RANGES` (`15m`, `1h`, `4h`, `24h`, `7d`, `All`).
- **`initLogs()`:** baut den Tab auf, stellt den Zustand aus `localStorage` (`tdc.logs.recent`, höchstens 10) wieder her und sucht einmal.
- **`async function runLogsSearch()`:** Ein Sequenzzähler verwirft veraltete Antworten. Ein 400 zeigt eine Fehlerzeile mit Markierung an `pos` unter dem Suchfeld.
- **`renderLogsResult(result)`:** zeichnet Histogramm, Feldleiste, Ereignisliste und Tabelle.
  - **Histogramm:** `stackedBarsSvg`, nach Quelle gestapelt, Brush über `initBarsBrush` setzt `earliest` und `latest`.
  - **Ereignisse:** Die Zeit ist lokal formatiert, wie in den anderen Tabs.
  - **Bei Ereignissen:** eine Liste. Eine Zeile zeigt Zeit, ein Quellen-Badge und den Text, auf etwa 2 Zeilen gekürzt. Ein Klick klappt die Felder und den Rohtext auf (`<pre>` über `textContent`), mit Treffer-Hervorhebung über sichere Teilung in Text-Knoten.
  - **Bei Tabelle oder `timechart`:** eine sortierbare Tabelle (`data-sortable`); bei `timechart` zusätzlich ein Liniendiagramm oder gestapelte Balken.
- **`logsHighlight(text, terms) -> string`:** HTML, das nur escapten Text und `<mark>` enthält.
- **`logsAddFilter(field, value)`:** ergänzt `field="value"` (Anführungszeichen im Wert escaped) und sucht.
- **`renderLogsSources(list)`:** zeichnet die Chips mit Anzahl, Status-Punkt und Hinweis als `title`.
- **Live-Schalter:** sucht alle 10 s erneut, nur wenn der Tab sichtbar ist und `document.hidden` falsch ist.
- **Syntax-Hinweis:** `title` mit einem kurzen Spickzettel, dazu Beispiele im Dropdown.

- [ ] **Step 1: Failing tests** (Node):
  - Ein Script Block mit `<script>alert(1)</script>` erscheint nur als Text.
  - `logsHighlight` erzeugt nur `<mark>` und keine anderen Tags.
  - `logsAddFilter` escaped `"`.
  - Ein 400 mit `pos` zeigt die Markierung.
  - Die letzten Suchen sind auf 10 begrenzt.
  - Eine veraltete Antwort wird verworfen.
  - Tabelle bei `type=table`, Liste bei `events`.
  - Die Quellen-Chips zeigen den Hinweis.
  - Ein Markup-Test: `#tab-logs`, Tab-Knopf nach Sysmon, Hilfe-`<h4>`.
  - Die vorhandenen Doku-, Theme- und Frontend-Tests sind grün; Zählungen 12/14.
- [ ] **Step 2:** FAIL. **Step 3:** Umsetzen, Aussehen in beiden Themes. Lokal mit `make run` ansehen, wenn möglich. **Step 4:** `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(logs): LOGS tab with search, timeline and field sidebar`.

### Task 6: Prüfung auf der VM (Controller)

1. Deploy mit `python3 scripts/deploy-utm.py --vm-ip 192.168.64.4 --vm-user tdc --vm-pass tdc --restart`. Danach `--install configure-logging.ps1`, Detonator und LitterBox wieder starten.
2. Auf der VM einen PowerShell-Befehl erzeugen. Dann mehrere Suchen ausführen: `source=powershell`, `source=netflow`, `source=dns`, `source=firewall` und eine Suche mit `stats`.
3. Ein MCP-Tool aufrufen und es als `source=mcp` finden. Ist der Host-MCP nicht nutzbar, `curl` mit den Headern nehmen.
4. Den Tab und den Skull-Dialog per Screenshot prüfen.
