# Named Pipes – Beobachten und Abfangen – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pipe-Aktivität jeder Detonation passiv auswerten (Sysmon EID 17/18, Musterkatalog, Graph, Urteil) und einzelne Pipes im neuen Tab „Pipes" per Proxy mitschneiden oder anhalten/ändern.

**Architecture:** Reine Analyse-Logik in `webui/pipe_analysis.py` (keine Win32-Abhängigkeit, voll testbar), Proxy-Engine in `webui/pipe_proxy.py` hinter einer austauschbaren Backend-Schnittstelle (`Win32PipeBackend` via `ctypes` auf der VM, `FakePipeBackend` in Tests). `app.py` verdrahtet beides in Sysmon-Parsing, Detonations-Ergebnisse, Prozessgraph, Baseline-Sweep und neue Routen; Frontend und MCP konsumieren die Routen.

**Tech Stack:** Python 3.12 / Flask, `ctypes` (kernel32), Vanilla JS (`app.js`), pytest, Sysmon 15 auf Windows 11 ARM64.

**Spec:** `docs/superpowers/specs/2026-11-04-named-pipes-design.md`

## Global Constraints

- Keine neuen Python-Abhängigkeiten; Win32 nur über `ctypes`.
- A darf das Sample nicht verändern: Detonationen starten nie einen Proxy.
- Sysmon `PipeEvent` im **exclude**-Modus; der Rest der SwiftOnSecurity-Konfiguration bleibt unverändert.
- Musterkatalog als Datei `webui/pipe_signatures.json`, erweiterbar ohne Codeänderung.
- Baseline-Normalisierung: Hex-/GUID-/Zahlenläufe → `*` (`status_4a3f` → `status_*`); Funde aus dem C2-Katalog werden **nie** durch die Baseline unterdrückt.
- Baseline-Aufnahme über „Sweep as baseline", Pipe-Fenster Standard **30 min**.
- `/api/pipes` filtert standardmäßig auf die **letzte Stunde**.
- Graph-Toggle „Pipes": an bei Detonationen, aus sonst; Pipe-Knoten nur für Prozesse des gezeigten Teilbaums.
- Proxy-Sitzung: maximale Dauer Standard **10 min**; angehaltene Nachrichten werden nach Timeout automatisch weitergereicht; keine Wiederaufnahme nach Neustart; Sperrliste `\lsass`, `\ntsvcs`, `\protected_storage`; Größenlimits pro Nachricht und Sitzung.
- Zwei Startarten: **attach** (exakter Name, nur wenn die Pipe existiert) und **arm** (exakt/Präfix/Regex, Beobachter übernimmt die erste passende neue Pipe); **squat** nur als ausdrückliche Option bei exaktem Namen.
- MCP: Sitzungen und Mitschnitte lesen ja; starten/ändern nein.
- Prozesse sind Instanzen (`<pid>` / `<pid>@<start>`); Pipe-Events über `_PidInstances.resolve` zuordnen.
- Neue Routen und MCP-Tools müssen in README und Hilfe erscheinen (`tests/test_docs.py` erzwingt es); Asset-Version in `index.html` erhöhen.

## Review Focus

1. **Pipe-Namen mit Präfix `\\.\pipe\` oder ohne führenden Backslash** – Sysmon liefert `\name`, Nutzer tippen `name` oder `\\.\pipe\name`; alle drei müssen gleich behandelt werden (Test in Task 1).
2. **Client hängt, weil Proxy oder Server verschwindet** – beendet sich der echte Server oder läuft die Sitzung ab, müssen beide Seiten geschlossen werden statt zu blockieren (Test in Task 6).
3. **Angehaltene Nachricht wird nie beantwortet** (Tab geschlossen) – Auto-Weiterreichen nach Timeout (Test in Task 6).
4. **Sysmon-Ausschluss zu breit** – eigene Pipes eines Samples, die zufällig wie Browser-Mojo heißen, dürfen nicht unsichtbar werden; Ausschluss nur für Prozess+Name-Paare, nicht für Namen allein (Prüfung in Task 2).
5. **Proxy fängt seine eigenen Events** – EID 17/18 des Web-UI-Prozesses (Proxy-Instanzen) dürfen nicht als Sample-Aktivität oder als Baseline erscheinen (Test in Task 3).

---

## Dateistruktur

| Datei | Verantwortung |
|---|---|
| `webui/pipe_signatures.json` (neu) | Musterkatalog: Familie, Muster, Typ, Gewicht |
| `webui/pipe_analysis.py` (neu) | Namen normalisieren, Katalog-Abgleich, Ereignisse einer Detonation bewerten, Baseline-Funde |
| `webui/pipe_proxy.py` (neu) | Sitzungen, Weiterleitung, Anhalten/Bearbeiten, Watcher; Backend-Schnittstelle + Win32-Backend |
| `webui/memory_evidence.py` | neue `KINDS`, `baseline_exempt`, `collect()` liest `named_pipes` |
| `webui/app.py` | EID 17/18 parsen, `/api/pipes*`, Detonation, Graph, Sweep, Verdict-Quellen |
| `scripts/install-sysmon.ps1` | PipeEvent → exclude, Logmaximum |
| `webui/static/js/app.js`, `templates/index.html`, `static/css/style.css` | Pipes-Tab, Abschnitt in Ergebnissen, Graph-Knoten/Toggle, Isometrie |
| `mcp/server.py` | `tdc_pipes`, `tdc_pipe_sessions` |
| `tests/test_pipes.py`, `tests/test_pipe_proxy.py` (neu) | Tests für A und B |
| `README.md` | Abschnitt Named Pipes, API, MCP, Tab |

---

### Task 1: Musterkatalog und Namensnormalisierung

**Files:**
- Create: `webui/pipe_signatures.json`, `webui/pipe_analysis.py`
- Test: `tests/test_pipes.py`

**Interfaces:**
- Produces:
  - `canonical_name(name: str) -> str` – `\\.\pipe\x`, `x`, `\x` → `\x`; Groß/Klein bleibt erhalten.
  - `normalize_for_key(name: str) -> str` – kleingeschrieben, Läufe von ≥4 Hex-Zeichen, GUIDs und Ziffernfolgen → `*`.
  - `load_signatures(path: str | None = None) -> list[dict]` – Einträge `{"family","pattern","match":"prefix"|"exact"|"contains"|"regex","weight","note"}`; ungültige Regex werden beim Laden verworfen und geloggt.
  - `match_signature(name: str, signatures: list[dict]) -> dict | None` – erster Treffer, case-insensitiv, auf `canonical_name`.
  - `looks_random(name: str) -> bool` – Shannon-Entropie des letzten Namensteils ≥ 3.5 bei Länge ≥ 12, oder GUID-förmig.

- [ ] **Step 1: Failing tests** in `tests/test_pipes.py`:
  - `test_canonical_name` – `canonical_name(r"\\.\pipe\msagent_12")`, `"msagent_12"`, `r"\msagent_12"` sind alle `r"\msagent_12"`.
  - `test_normalize_for_key` – `status_4a3f9c` → `\status_*`; `MSSE-1234-server` → `\msse-*-server`; `{3F2504E0-4F89-11D3-9A0C-0305E82C3301}` → `\*`.
  - `test_signature_catalog_matches_defaults` – Treffer mit Familie `Cobalt Strike` für `\msagent_5b`, `\postex_ab12`, `\status_33`, `\MSSE-4242-server`, `\postex_ssh_1a`; `PsExec` für `\PSEXESVC`; `PAExec/RemCom/CSExec` für `\paexec_x`, `\RemCom_communicaton`, `\csexecsvc`; kein Treffer für `\lsass`, `\mojo.123.456`.
  - `test_invalid_regex_entry_is_skipped` – Katalog mit `{"pattern":"(", "match":"regex"}` lädt die übrigen Einträge.
  - `test_looks_random` – `\a8f3c2e9b7d1f4e6` wahr; `\docker_engine` falsch.
- [ ] **Step 2:** `webui/.venv/bin/python -m pytest tests/test_pipes.py -q` → FAIL (Modul fehlt).
- [ ] **Step 3:** Katalog anlegen: Cobalt Strike (`msagent_`, `postex_`, `postex_ssh_`, `status_`, `MSSE-*-server` als regex `^\\MSSE-\d+-server$`), Sliver/Metasploit/Covenant-Defaults soweit öffentlich dokumentiert (`gruntsvc` Covenant), PsExec `PSEXESVC`, PAExec/RemCom/CSExec, Credential-Dumper (`lsadump`, `cachedump`, `wceservicepipe`), sowie die übrigen Namen aus dem SwiftOnSecurity-PipeEvent-Block. Gewichte: C2-Default 4.0, Remote-Exec 3.0, Credential-Dumper 4.0. Modul implementieren.
- [ ] **Step 4:** Tests laufen → PASS.
- [ ] **Step 5:** Commit `feat(pipes): signature catalog and name normalization`.

---

### Task 2: Sysmon protokolliert Pipe-Events

**Files:**
- Modify: `scripts/install-sysmon.ps1` (nach dem Download der Konfiguration, vor `-i`/`-c`)
- Test: `tests/test_pipes.py`

**Interfaces:**
- Produces: Sysmon schreibt EID 17/18 für alle Pipes außer Ausschlüssen; Log-Maximum ≥ 512 MB.

- [ ] **Step 1: Failing test** `test_sysmon_installer_switches_pipeevent_to_exclude` – liest `install-sysmon.ps1` und prüft: es ersetzt den `<PipeEvent onmatch="include">`-Block durch `<PipeEvent onmatch="exclude">` mit Regeln, die jeweils **Image und PipeName gemeinsam** (`<Rule groupRelation="and">`) ausschließen, und setzt `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:` mit ≥ 536870912.
- [ ] **Step 2:** Test → FAIL.
- [ ] **Step 3:** PowerShell-Nachbearbeitung per `[xml]`: alle `PipeEvent`-Elemente entfernen, ein `RuleGroup` mit `PipeEvent onmatch="exclude"` einfügen. Ausschlüsse (Image endswith + PipeName begin with): `chrome.exe`/`msedge.exe` + `\mojo.`, `\crashpad_`; `svchost.exe` + `\lsass`, `\ntsvcs`, `\srvsvc`, `\wkssvc`; `MsMpEng.exe` + beliebig; `powershell.exe` mit `ParentImage` der Web-UI ist in Sysmon nicht ausdrückbar – diese Pipes (`\PSHost.`) filtert stattdessen Task 3. Danach `Sysmon -c`. Log-Größe setzen.
- [ ] **Step 4:** Test → PASS. Auf der VM: `python3 scripts/deploy-utm.py --vm-ip 192.168.64.4 --vm-user tdc --vm-pass tdc --install install-sysmon.ps1`, dann `wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=17 or EventID=18)]]" /c:5 /rd:true /f:text` → Ereignisse vorhanden.
- [ ] **Step 5:** Commit `feat(sysmon): log pipe events in exclude mode`.

---

### Task 3: EID 17/18 parsen und einer Detonation zuordnen

**Files:**
- Modify: `webui/app.py` (`_read_sysmon_events` Typzweige; neue Funktion neben `_network_beaconing_for_pid`)
- Modify: `webui/pipe_analysis.py`
- Test: `tests/test_pipes.py`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - Sysmon-Eventdict für EID 17/18: `{"type": "PipeCreated"|"PipeConnected", "pipe": canonical_name, "event_type": item["EventType"], "image", "pid", "user", "timestamp"}`.
  - `pipe_analysis.analyze(events: list[dict], sample_keys: set[str], resolve: Callable[[str, str], str | None], self_pid: int) -> dict` mit
    `{"pipes": [{"pipe","family","note","created_by":[key],"connected_by":[key],"first_seen","last_seen","flags":[str]}], "evidence_findings": [MemoryFinding]}`.
    `flags` ⊂ `{"c2_default","cross_process","sensitive_system","random_name"}`. Events des Prozesses `self_pid` und Pipes mit Präfix `\PSHost.` werden ignoriert.
  - `app._pipe_activity_for(pid, sha256=None, at=None) -> dict` – Sample-Instanz via `_PidInstances`, Teilbaum aus `_build_full_process_map`, Zeitfenster Submission-Start − 60 s … +6 h (wie `_AGENT_PID_WINDOW`), Abfrage `_read_sysmon_events(event_ids=[17,18], since=…, until=…, max_events=2000)`; Ergebnis von `analyze` plus `"available": bool`. Cache wie `_net_beacon_cache`.

- [ ] **Step 1: Failing tests:**
  - `test_parse_pipe_events` – XML-Fragment mit EventID 17 `PipeName=\msagent_5b` → Dict mit `type == "PipeCreated"`, `pipe == r"\msagent_5b"` (über `_read_sysmon_events` mit gemocktem `_wevtutil_query`).
  - `test_analyze_flags` – Sample `4072` legt `\msagent_5b` an, `rundll32` (`5000`) verbindet → Pipe-Eintrag mit `family == "Cobalt Strike"`, `flags ⊇ {"c2_default","cross_process"}`, `connected_by == ["5000"]`.
  - `test_analyze_sensitive_system_pipe` – Sample verbindet `\svcctl` → Flag `sensitive_system`, kein `c2_default`.
  - `test_analyze_ignores_own_proxy_and_pshost` – Events mit `pid == self_pid` und `\PSHost.1.2.powershell` erscheinen nicht.
  - `test_unrelated_processes_are_not_attributed` – Pipe-Events eines fremden Prozesses ohne Bezug zu Sample-Pipes fehlen im Ergebnis.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Implementieren. `cross_process`: Pipe von einer Sample-Instanz angelegt **und** von einer Nicht-Sample-Instanz verbunden (oder umgekehrt). `sensitive_system`: Sample verbindet `\svcctl`, `\lsarpc`, `\samr`, `\netlogon`, `\atsvc`. `random_name`: `looks_random`.
- [ ] **Step 4:** Tests → PASS.
- [ ] **Step 5:** Commit `feat(pipes): attribute pipe events to detonations`.

---

### Task 4: Evidenz, Baseline und Urteil

**Files:**
- Modify: `webui/memory_evidence.py`, `webui/pipe_analysis.py`, `webui/app.py` (`api_detonation_results`, `_compute_verdict` `mem_sources`, `_run_sweep`)
- Test: `tests/test_pipes.py`

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `KINDS`: `pipe_c2_default` (weight aus Katalog, `EVIDENCE_STRUCTURAL`, `corroborate: False`, `baseline_exempt: True`), `pipe_cross_process` (1.5, behavioral, corroborate), `pipe_sensitive_system` (1.0, behavioral, corroborate), `pipe_random_name` (0.8, string, corroborate). Quelle `sysmon-pipes`; Identität `(normalize_for_key(pipe),)`, Prozess = Image-Pfad.
  - `score()` unterdrückt Funde mit `KINDS[kind].get("baseline_exempt")` nie.
  - `collect()` liest `results["named_pipes"]["evidence_findings"]`.
  - `pipe_analysis.baseline_findings(events, self_pid) -> list[MemoryFinding]` – für jedes Event die nicht-C2-Arten mit derselben Identität.
  - `/api/detonation/results` enthält `"named_pipes": _pipe_activity_for(pid, sha256)`; `"named_pipes"` zählt in `mem_sources`, wenn `evidence_findings` nicht leer.
  - `_run_sweep(..., capture_baseline=True)` liest EID 17/18 der letzten 30 min und fügt `baseline_findings` zur Baseline hinzu; Ergebnis meldet `"pipe_keys_added"`.

- [ ] **Step 1: Failing tests:**
  - `test_c2_pipe_alone_is_suspicious` – nur `pipe_c2_default` (4.0) → Label `SUSPICIOUS`.
  - `test_c2_pipe_not_suppressed_by_baseline` – Baseline enthält den Schlüssel → `suppressed_count == 0`.
  - `test_baseline_suppresses_known_cross_process_pipe` – `status_4a3f` im Baseline, Detonation sieht `status_9c21` → unterdrückt (gleicher normalisierter Schlüssel, Art `pipe_cross_process`).
  - `test_pipe_corroborates_memory` – `pipe_cross_process` + `memory_signature` gleicher Prozess → `corroborated_by` enthält `sysmon-pipes`.
  - `test_detonation_results_include_named_pipes` – Route mit gemocktem `_pipe_activity_for` → `d["named_pipes"]["pipes"][0]["pipe"]` und `"sysmon-pipes"` in Urteilsgründen.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Implementieren.
- [ ] **Step 4:** `webui/.venv/bin/python -m pytest -q` → alle PASS (bestehende Evidenz-Tests unverändert grün).
- [ ] **Step 5:** Commit `feat(pipes): pipe evidence, baseline and verdict`.

---

### Task 5: `/api/pipes` und Pipes im Prozessgraphen (Backend)

**Files:**
- Modify: `webui/app.py` (`api_process_graph`, neue Route)
- Test: `tests/test_pipes.py`

**Interfaces:**
- Consumes: Tasks 1, 3.
- Produces:
  - `GET /api/pipes?pid=&key=&since=&until=&name=&max=` → `{"events":[…], "since": iso}`; ohne `since` = jetzt − 1 h; `name` per `match` auf `canonical_name` (Teilstring, case-insensitiv); `key` nutzt `_PidInstances.resolve_key`.
  - `/api/process-graph` antwortet zusätzlich mit `"pipes": [{"key","pid","pipe","action":"created"|"connected","family","timestamp"}]` für die Instanzen des Teilbaums (XPath auf deren PIDs + Zeitfenster der Instanzen; dieselbe Zuordnung über `instances.resolve`).
- [ ] **Step 1: Failing tests:** `test_api_pipes_default_window` (ohne `since` ist `since` ≈ jetzt − 3600 s), `test_api_pipes_name_filter`, `test_graph_includes_pipes_of_subtree_only` (Pipe eines Prozesses außerhalb des Teilbaums fehlt; Event eines früheren PID-Inhabers fehlt).
- [ ] **Step 2:** FAIL. **Step 3:** Implementieren. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(pipes): pipes API and graph data`.

---

### Task 6: Proxy-Engine

**Files:**
- Create: `webui/pipe_proxy.py`
- Test: `tests/test_pipe_proxy.py`

**Interfaces:**
- Consumes: `pipe_analysis.canonical_name`.
- Produces:
  - `class PipeBackend` (Protokoll): `list_pipes() -> list[str]`, `exists(name) -> bool`, `pipe_mode(name) -> "byte"|"message"`, `create_server(name, mode, first_instance: bool) -> Handle`, `accept(h, timeout: float) -> bool`, `connect(name, timeout: float) -> Handle`, `read(h, timeout: float) -> bytes | None` (None = geschlossen, b"" = Timeout), `write(h, data: bytes) -> None`, `close(h) -> None`.
  - `class FakePipeBackend(PipeBackend)` im selben Modul (für Tests und Entwicklung auf macOS): In-Memory-Paare, Methoden `fake_server(name)`, `fake_client(name)` liefern Endpunkte mit `send/recv`.
  - `class Win32PipeBackend(PipeBackend)` – `ctypes`: `CreateNamedPipeW` (`PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED`, `FILE_FLAG_FIRST_PIPE_INSTANCE` nur wenn `first_instance`), `ConnectNamedPipe`/`CreateFileW`/`ReadFile`/`WriteFile` mit Overlapped + `WaitForSingleObject`, `GetNamedPipeInfo`, `FindFirstFileW(r"\\.\pipe\*")` für `list_pipes`.
  - `class InterceptManager(backend, store_dir, clock=time.time)`:
    - `start(pattern: str, mode: "observe"|"hold", how: "attach"|"arm", match: "exact"|"prefix"|"regex", squat: bool=False, max_duration: int=600, hold_timeout: int=30) -> dict` (Sitzung) – wirft `ValueError` für Sperrliste, `attach` auf nicht existierende Pipe, `squat` ohne `exact`.
    - `stop(sid) -> dict`, `get(sid) -> dict`, `list() -> list[dict]`.
    - `messages(sid, after: int = 0, limit: int = 200) -> list[dict]` – `{"seq","conn","dir":"c2s"|"s2c","ts","size","data_b64","state":"passed"|"held"|"edited"|"dropped"|"auto_passed"}`.
    - `act(sid, seq, action: "forward"|"drop"|"edit", data_b64: str | None = None) -> dict`, `release_all(sid)`.
    - Limits: Nachricht ≤ 1 MiB (größere werden durchgereicht und gekürzt protokolliert), Mitschnitt ≤ 50 MiB pro Sitzung.
    - Mitschnitt wird beim Beenden als `store_dir/<sid>.json` geschrieben; beim Start des Managers werden alte Sitzungen nur als „beendet" gelistet.
- [ ] **Step 1: Failing tests** (mit `FakePipeBackend` und einer steuerbaren Uhr):
  - `test_observe_relays_both_directions` – Client sendet `b"ping"`, Server antwortet `b"pong"`; beide kommen an; zwei Nachrichten `c2s`/`s2c` mit Zustand `passed`.
  - `test_hold_edit_forward_and_drop` – im Modus `hold` kommt nichts an, bis `act(edit, "cGluZw==")` → Server erhält `b"ping"`; `act(drop)` → nichts kommt an.
  - `test_held_message_auto_forwarded_after_timeout` – Uhr +31 s → Server erhält die Nachricht, Zustand `auto_passed`.
  - `test_session_expires_and_closes_both_ends` – Uhr +601 s → Sitzung `ended`, Client- und Server-Endpunkt geschlossen.
  - `test_server_disappears_closes_client` – echter Server schließt → Client liest `None`.
  - `test_arm_prefix_takes_first_new_matching_pipe` – Watcher (Intervall injizierbar) sieht `\postex_ab12` neu → Sitzung verbunden; schon vorher existierende `\postex_old` wird nicht genommen.
  - `test_blocklist_and_validation` – `\lsass` → `ValueError`; `attach` auf fehlende Pipe → `ValueError`; `squat` mit `prefix` → `ValueError`.
  - `test_message_mode_is_preserved` – Ziel im Message-Modus → Proxy-Instanz im Message-Modus.
  - `test_large_message_truncated_in_log_but_relayed_in_full`.
- [ ] **Step 2:** `pytest tests/test_pipe_proxy.py` → FAIL.
- [ ] **Step 3:** Implementieren: je Client-Verbindung zwei Pump-Threads; im `hold`-Modus Warteschlange pro Richtung, Reihenfolge bleibt erhalten (Nachricht n+1 wartet hinter n); Watcher-Thread für `arm`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(pipes): interception engine`.

---

### Task 7: Proxy-Routen und Test auf der VM

**Files:**
- Modify: `webui/app.py`
- Create: `scripts/pipe-roundtrip-test.py` (manueller VM-Test: eigener Pipe-Server + Client über `Win32PipeBackend`)
- Test: `tests/test_pipe_proxy.py`

**Interfaces:**
- Consumes: Task 6.
- Produces: `_intercept = InterceptManager(Win32PipeBackend() if os.name == "nt" else FakePipeBackend(), store_dir=webui/pipe_sessions)`; Routen:
  - `POST /api/pipes/intercept` (JSON wie `start`) → 201 Sitzung / 400 Fehlertext
  - `GET /api/pipes/intercept` → Liste; `GET /api/pipes/intercept/<sid>` → Sitzung
  - `DELETE /api/pipes/intercept/<sid>` → beendet
  - `GET /api/pipes/intercept/<sid>/messages?after=&limit=`
  - `POST /api/pipes/intercept/<sid>/messages/<seq>` (`{"action","data_b64"}`), `POST /api/pipes/intercept/<sid>/release`
  - `GET /api/pipes/intercept/<sid>/export` → JSON-Anhang (Download mit Sandbox-CSP wie `/api/file/download`)
  - `webui/pipe_sessions/` in `.gitignore`.
- [ ] **Step 1: Failing tests:** `test_intercept_routes_roundtrip` (Fake-Backend: start → Nachricht → messages → act → stop), `test_intercept_rejects_cross_site_post` (Origin fremd → 403, bestehender Schutz greift), `test_intercept_rejects_blocked_pipe` (400).
- [ ] **Step 2:** FAIL. **Step 3:** Implementieren. **Step 4:** PASS.
- [ ] **Step 5:** Auf der VM deployen (`deploy-utm.py --restart`), `scripts/pipe-roundtrip-test.py` per WinRM ausführen: Server `\tdc_test`, Sitzung `attach` + `observe`, Client sendet 3 Nachrichten → Skript gibt `OK 3/3` aus; danach `hold` + `edit` → Server sieht geänderte Bytes.
- [ ] **Step 6:** Commit `feat(pipes): interception API`.

---

### Task 8: Frontend – Pipes-Tab, Ergebnisse, Graph

**Files:**
- Modify: `webui/templates/index.html` (Tab-Button nach „Graph", Tab-Inhalt, Graph-Toggle, Hilfe-Tab-Guide, Asset-Versionen), `webui/static/js/app.js`, `webui/static/css/style.css`
- Test: `tests/test_frontend.py`, `tests/test_docs.py` (bestehend)

**Interfaces:**
- Consumes: Routen aus Tasks 4, 5, 7.
- Produces:
  - Tab `data-tab="pipes"` Label **Pipes**: oben Ereignisliste (`/api/pipes`, Filter Name/PID, Treffer-Badges), unten Sitzungen: Formular (Name/Muster, `match`, `how`, `mode`, `squat`-Checkbox nur bei `exact`+`arm`, Dauer), Sitzungsliste, Nachrichtenansicht (Hex+ASCII, Richtung, Zustand), für `held` Buttons Weiterreichen/Ändern/Verwerfen und „alles durchlassen", Export-Link. Polling 1 s solange Tab sichtbar und Sitzung aktiv.
  - Detonations-Ergebnisse (Submit-Panel und `viewDetonationResult`): Abschnitt „NAMED PIPES" aus `data.named_pipes` – Tabelle Zeit/Prozess/Aktion/Pipe/Familie/Flags; Button „Abfangen" (öffnet Pipes-Tab mit vorausgefülltem `attach`), deaktiviert mit Hinweis, wenn die Pipe nicht mehr existiert (Prüfung über `/api/pipes/intercept`-Fehlertext).
  - Graph: Toggle `graph-show-pipes` (an, wenn der Fokus ein detonierter Prozess ist); Knotentyp `pipe` (Farbe `#38bdf8`, Raute), Kanten `pipe-create`/`pipe-connect`; Isometrie: Aktivitätssymbol „pipe" mit Anzahl und teal-Brücke zwischen zwei Prozessen derselben Pipe (wie `inject`).
  - Alle Werte über `escapeHtml`/`jsArg`/`jsInt`/`cssToken`.
- [ ] **Step 1:** Tab-Button einfügen, `make unit-test` → FAIL in `test_docs.py` (`test_readme_tabs_match_the_ui`, `test_help_tab_guide_covers_every_tab`). Zeile **Pipes** in README-Tab-Tabelle und Hilfe-Tab-Guide ergänzen → wieder PASS.
- [ ] **Step 2:** Implementieren; `node --check webui/static/js/app.js`.
- [ ] **Step 3:** `make unit-test` → PASS (inkl. Escaping-Tests über die neuen Templates).
- [ ] **Step 4:** Deploy, Headless-Chrome-Rundgang (Skript wie `shot/smoke.js`): Pipes-Tab lädt ohne Pagefehler, Sitzung gegen `\tdc_test` startet, Nachrichten erscheinen; Graph mit Toggle zeigt Pipe-Knoten für eine Detonation.
- [ ] **Step 5:** Commit `feat(pipes): pipes tab, results section and graph`.

---

### Task 9: MCP

**Files:**
- Modify: `mcp/server.py`
- Test: `tests/test_mcp.py`

**Interfaces:**
- Produces: `tdc_pipes(pid: Optional[str] = None, name: Optional[str] = None, since: Optional[str] = None, max_events: int = 100) -> str`; `tdc_pipe_sessions(session_id: Optional[str] = None, max_messages: int = 20) -> str` (ohne ID: Liste; mit ID: Nachrichten als Hex-Vorschau). `tdc_detonation_results` gibt eine Zeile „Named pipes: n (Familien …)" aus.
- [ ] **Step 1: Failing tests** in `tests/test_mcp.py`: `test_pipes_tool_formats_families`, `test_pipe_sessions_tool_reads_messages`, `test_detonation_results_mentions_pipes`.
- [ ] **Step 2:** FAIL. **Step 3:** Implementieren. **Step 4:** `mcp/.venv/bin/python -m pytest tests/test_mcp.py` PASS.
- [ ] **Step 5:** Commit `feat(mcp): pipe tools`.

---

### Task 10: Dokumentation und End-to-End auf der VM

**Files:**
- Modify: `README.md` (Feature-Abschnitt „Named Pipes" inkl. Grenzen aus der Spec, API-Tabelle, MCP-Tabelle, Tab-Tabelle, Dateistruktur, Konfiguration), `webui/templates/index.html` (Hilfe: API, Services), Screenshots `static/pipes_tab.png`, `static/detonation_pipes.png`
- Create: Test-Sample `pipesim` (C, x64, lokal mit Zig gebaut wie die bisherigen Testsamples): legt `\msagent_<hex>` an, startet ein Kind, das sich verbindet und alle 2 s eine Nachricht austauscht, 60 s Laufzeit.
- Test: `tests/test_docs.py` (bestehend)

- [ ] **Step 1:** `make unit-test` → PASS (Doku-Abgleich grün).
- [ ] **Step 2:** VM: `pipesim.exe` detonieren → Ergebnis zeigt Familie **Cobalt Strike**, Flag `cross_process`, Urteil mindestens SUSPICIOUS mit Grund aus `sysmon-pipes`; Graph zeigt Pipe-Kante zwischen Parent und Kind.
- [ ] **Step 3:** VM: Sitzung `arm` + `prefix` `msagent_` + `observe`, dann `pipesim.exe` detonieren → Mitschnitt enthält die Nachrichten beider Richtungen; Sample läuft bis zum Ende.
- [ ] **Step 4:** Regression: `shortlived`/`injectsim`/`beaconsim` → Memory-Werte unverändert (0.32 / 6.54 / 3.8).
- [ ] **Step 5:** Screenshots aufnehmen und prüfen, README-Demo ergänzen; Commit `docs(pipes): README, help, screenshots`.
