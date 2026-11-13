# Tool-Updates aus dem Dashboard – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Das Service Dashboard prüft alle Tools der VM auf Updates und installiert sie. Während eines Updates gilt ein Wartungsmodus mit Banner, und der Server weist Detonationen, Scans und Uploads ab.

**Architecture:**
- Neues Modul `webui/tool_updates.py`. Es enthält den Katalog und die Prüfungen (choco, winget, git, GitHub-Releases, Sysinternals-ETag). Der `UpdateManager` hält Zustand und Ablauf.
- Installiert wird über die vorhandenen `scripts/install-*.ps1`. Wo nötig bekommen sie die Parameter `-Force`, `-Version` und `-PackageSha256`.
- `webui/app.py` stellt die Routen `/api/updates…` bereit, sperrt im Wartungsmodus und startet die tägliche Prüfung.
- Das Frontend (`app.js`, Vanilla) zeichnet den Dashboard-Bereich und das Banner.

**Tech Stack:** Python 3.9 / Flask, Vanilla JS, CSS, PowerShell 5.1, pytest + Node.

**Spec:** `docs/superpowers/specs/2026-11-13-tool-updates-design.md` (enthält den Werkzeugkatalog mit Pfaden, Repos, Pins und Verbrauchern; daraus übernehmen).

## Global Constraints

- **Python:** 3.9-kompatibel (lokales venv ist 3.9.6). `from __future__ import annotations`, kein `match`. Keine neue Abhängigkeit; HTTP über `requests`, das schon da ist.
- **Testbarkeit:**
  - Alles, was Prozesse startet, Dateien liest oder HTTP spricht, geht in `tool_updates.py` über ein injiziertes `Env`-Objekt. Die Tests nutzen eine Fake-`Env`.
  - Die CI hat kein Windows und kein PowerShell. `conftest.py` setzt `TDC_NO_BACKGROUND=1`, dann startet kein Hintergrund-Thread.
- **Git als SYSTEM:** Jeder Git-Aufruf beginnt mit `git -c core.fsmonitor=false -c core.hooksPath=NUL -c core.sshCommand= -c credential.helper= -c safe.directory=<dir> -C <dir>`. Ein Update nutzt `pull --ff-only --autostash`.
- **Status-Werte, genau so:** `up_to_date`, `update_available`, `pinned_update`, `unknown`, `not_installed`, `offline`, `error`, `queued`, `updating`, `updated`, `failed`, `reboot_required`.
- **Modus-Werte:** `idle`, `checking`, `updating`.
- **503-Text, genau so:** `Maintenance: tool updates are running. Detonations, scans and uploads are paused.` mit `"maintenance": true`. Gesperrt sind POST, PUT, PATCH und DELETE, außer Pfaden, die mit `/api/updates/` beginnen.
- **Grenzwerte:**
  - Skript höchstens 45 min (`SCRIPT_TIMEOUT = 2700`);
  - Check pro Tool 60 s;
  - `choco outdated` 180 s;
  - höchstens 4 parallele Prüfungen;
  - Protokoll höchstens 200 Zeilen pro Tool;
  - tägliche Prüfung alle `TDC_UPDATE_CHECK_HOURS` Stunden (Standard 24; 0 schaltet sie ab), erste Prüfung 5 min nach dem Start.
- **Exit-Codes:** 0 ist Erfolg. 3010 und 1641 ergeben `reboot_required`, alles andere `failed`.
- **Umgebungsvariablen:**
  - `TDC_SCRIPTS_DIR`, Standard `C:\tdc\scripts`;
  - `TDC_UPDATE_LOG`, Standard `C:\tools\logs\tool-updates.log`, außerhalb von Windows neben `app.py`;
  - `TDC_GITHUB_TOKEN`, optional.
- **Zustandsdatei:** `webui/tool_updates_state.json`. Sie wird atomar geschrieben (tmp, fsync, `os.replace`, wie `_save_submissions`) und kommt in `.gitignore`.
- **Frontend:**
  - Vanilla JS mit Funktionen auf oberster Ebene.
  - Alles aus dem Server (Tool-Namen, Versionen, Protokoll, Details) wird escaped (`escapeHtml`) oder als `textContent` gesetzt. Inline-`on*` interpoliert nur `jsArg`/`jsInt`.
  - Farben nur als `var(--…)`. Farbwerte in `style.css` nur in `:root`. `theme-cyberpunk.css` nur unter `[data-theme="cyberpunk"]`.
  - Keine neuen `.content-header` oder `.tab-content`. Die Zählungen in `test_info_texts_cover_every_tab` bleiben 11 und 13.
  - `data-info`-Texte: höchstens 300 Zeichen, ein bis zwei Sätze, ohne `<`, `&` und `${`.
  - Bei jeder Änderung an CSS oder JS die `?v=`-Versionen in `index.html` erhöhen.
- **Doku-Tests:**
  - Jede neue Route steht in der API-Tabelle der README.
  - Neue MCP-Tools stehen in der README-Liste, mit angepasster Anzahl `(N tools`.
  - Ein neues Modul `webui/tool_updates.py` geht über alle drei Deploy-Wege (`scripts/deploy-utm.py` FILES, `Makefile` `deploy:`, `make.ps1` `deploy`).
- **Sonstiges:**
  - Oberfläche, README und Code-Kommentare englisch.
  - Den gesperrten Fremdnamen aus den Projektregeln nirgends verwenden.
- **Tests laufen mit** `make -s unit-test` (venv `webui/.venv`). Einzeln: `webui/.venv/bin/python -m pytest tests/<datei> -q`.

## Review Focus

1. **Lauf während einer Detonation:** Wenn der Agent `in_use` meldet, ein Sweep oder Process-Dump läuft, antwortet `/api/updates/apply` mit 409 und Grund, und nichts wird gestoppt. Test in Task 4.
2. **VM ohne Internet:** Die Prüfung endet in Sekunden. Netzabhängige Tools stehen auf `offline` und zeigen „No internet access from the VM“, statt bei `checking` hängen zu bleiben. Test in Task 2.
3. **Dienst lief vorher und bleibt aus:** Ein Verbraucher, der vorher lief, wird nach Erfolg und auch nach Fehler wieder gestartet. Einer, der vorher aus war, bleibt aus. Test in Task 3.
4. **Gepinnte Tools:** „Update all“ lässt `pinned_update` aus. Nur `include_pinned` oder eine explizite ID mit `include_pinned: true` installiert sie. Für Rizin ohne Digest kommt `failed` mit Grund. Test in Task 3.
5. **Neustart des Web-UI während `updating`:** Danach ist der Modus `idle`, und das Tool hat den Status `failed` mit „Interrupted: the web UI restarted during the update.“. Das Banner verschwindet. Test in Task 3.

---

## Dateistruktur

| Datei | Verantwortung |
|---|---|
| `scripts/install-*.ps1` | Schalter `-Force`, `-Version` und `-PackageSha256`, Marker `tdc-release.txt` |
| `Vagrantfile`, `Vagrantfile.utm` | Skripte nach `C:\tdc\scripts` |
| `webui/tool_updates.py` (neu) | Katalog, Prüfungen, Verbraucher, `UpdateManager` |
| `webui/app.py` | Routen, Sperre, Vorbedingungen, Hintergrund-Prüfung |
| `webui/templates/index.html`, `webui/static/js/app.js`, CSS | Dashboard-Bereich, Banner |
| `mcp/server.py` | drei MCP-Tools |
| `tests/test_tool_update_scripts.py`, `tests/test_tool_updates.py`, `tests/test_tool_updates_ui.py` (neu) | Tests |
| `README.md`, `scripts/deploy-utm.py`, `Makefile`, `make.ps1`, `.gitignore` | Doku und Deploy |

---

### Task 1: Install-Skripte für Updates öffnen und auf die VM bringen

**Files:**
- Ändern:
  - `scripts/install-capa.ps1`
  - `scripts/install-beaconeye.ps1`
  - `scripts/install-process-dump.ps1`
  - `scripts/install-scanner-tools.ps1`
  - `scripts/install-rustinel.ps1`
  - `scripts/install-fibratus.ps1`
  - `scripts/install-aether.ps1`
  - `scripts/install-sysmon.ps1`
  - `scripts/install-rizin.ps1`
  - `Vagrantfile`, `Vagrantfile.utm`
  - `scripts/deploy-utm.py`, `Makefile` (`deploy:`), `make.ps1` (`deploy`)
- Test: `tests/test_tool_update_scripts.py` (neu).

**Interfaces – Produces** (Task 2 und 3 rufen die Skripte so auf):
- **Gemeinsamer Schalter:** `-Force` (`[switch]`) übergeht in jedem der ersten acht Skripte die Prüfung „schon installiert, Ende“ und installiert neu. Ohne `-Force` bleibt das heutige Verhalten exakt gleich.
- **Marker:** `tdc-release.txt` (ASCII, eine Zeile mit dem Release-Tag, z. B. `v9.4.0`). Die Skripte schreiben ihn nach jeder erfolgreichen Installation in:
  - `C:\tools\capa`
  - `C:\tools\BeaconEye`
  - `C:\tools\ProcessDump`
  - `C:\tools\ThreatCheck`
  - `C:\tools\DefenderCheck`
  - `C:\tools\rustinel`
  - `C:\Program Files\Fibratus`

  Bei `releases/latest`-Downloads wird der Tag vorher über `https://api.github.com/repos/<repo>/releases/latest` (`tag_name`) ermittelt.
- `install-scanner-tools.ps1 -Only ThreatCheck|DefenderCheck`: Mit dem Parameter wird nur das genannte Tool installiert. Leer heißt beide.
- `install-rustinel.ps1 -Version <x.y.z>` (Standard der bisherige Pin `1.1.1`):
  - Vor dem Ersetzen der exe: Task `Rustinel` stoppen, nssm-Dienst `Rustinel` stoppen, falls vorhanden, Prozess `rustinel` beenden.
  - Ersetzt wird nur `rustinel.exe`. `rules\`, `logs\`, `alerts\` und `config.toml` bleiben.
- `install-fibratus.ps1 -Version <x.y.z>` (Standard `3.0.0`). Mit `-Force`:
  1. Dienst `fibratus` stoppen.
  2. Vorhandenes Fibratus-MSI deinstallieren (`Get-Package`/Uninstall-Registry, `msiexec /x … /qn /norestart`).
  3. Neu installieren.
  4. `fibratus.yml` aus `C:\vagrant_config` zurückkopieren.
  5. `install-service`, Dienst starten.

  Der Exit-Code von msiexec wird durchgereicht, wenn er 3010 oder 1641 ist.
- **`install-aether.ps1 -Force`:** Zusammen mit `-NoPrebuilt` baut es aus den Quellen neu, auch wenn `Aether.exe` existiert.
- **`install-sysmon.ps1 -Force`:**
  - Installiert das Binary neu: `Sysmon64[a].exe -u force`, dann `-accepteula -i <config>`.
  - Schreibt nach jedem Download die ETags in `C:\tools\sysmon\tdc-source.json`: `{"binary_etag": "...", "config_etag": "..."}`.
  - Ohne `-Force` und bei laufendem Sysmon: wie heute nur die Config, aber der `config_etag` wird aktualisiert.
- **`install-rizin.ps1`:**
  - Neue Parameter `-Version <cutter x.y.z>` (Standard `2.5.0`), `-PackageSha256 <hex>` (Standard der heutige Pin) und `-RizinVersion <x.y.z>`.
  - Sind die Werte nicht angegeben: Standard `0.9.1`, wenn `-Version` 2.5.0 ist. Sonst wird die Versionsprüfung im Selbsttest übersprungen, aber `rizin -v` wird ausgegeben.
  - Paketname und URL werden aus `-Version` gebildet.
- **Skripte auf der VM:**
  - Beide Vagrantfiles bekommen `config.vm.provision "file", source: "scripts", destination: "C:\\tdc\\scripts"`, direkt neben den bestehenden File-Provisionern.
  - Die drei Deploy-Wege laden zusätzlich alle `scripts/install-*.ps1` nach `C:\tdc\scripts\`:
    - `deploy-utm.py` über eine eigene Liste `SCRIPT_FILES`, die aus `glob` gebildet wird;
    - Makefile und make.ps1 über eine Schleife.

- [ ] **Step 1: Failing tests** in `tests/test_tool_update_scripts.py`:
  - `test_force_switch_in_every_update_script`: Jedes der acht Skripte enthält `[switch]$Force` im `param(`-Block. Die „already installed → exit/return“-Stelle hängt an `-not $Force`; das per Regex prüfen.
  - `test_release_marker_written`: capa, beaconeye, process-dump, scanner-tools, rustinel und fibratus enthalten `tdc-release.txt` und `Set-Content`.
  - `test_pinned_scripts_take_a_version`:
    - rustinel: `[string]$Version = "1.1.1"`;
    - fibratus: `[string]$Version = "3.0.0"`;
    - rizin: `$Version = "2.5.0"` und `$PackageSha256 = "a04154a03a392dbf5886a629938582f7d23a93636fa0611c3e1c34905b197e69"` als Parameter-Standard.
  - `test_scanner_tools_only_parameter`: `install-scanner-tools.ps1` enthält `$Only`.
  - `test_sysmon_records_etags`: `install-sysmon.ps1` enthält `tdc-source.json`, `binary_etag`, `config_etag` und `-u force`.
  - `test_scripts_reach_the_vm`:
    - Beide Vagrantfiles enthalten `destination: "C:\\tdc\\scripts"`.
    - `deploy-utm.py`, `Makefile` und `make.ps1` erwähnen `C:\tdc\scripts` (in der jeweiligen Schreibweise mit escapeten Backslashes).
    - Die bestehenden Tests (`test_install_rizin_is_pinned_and_wired` u. a.) bleiben grün.
- [ ] **Step 2:** `webui/.venv/bin/python -m pytest tests/test_tool_update_scripts.py -q` → FAIL.
- [ ] **Step 3:** Skripte ändern, im Stil der Datei:
  - farbige Meldungen;
  - `-Force` verändert sonst nichts;
  - Rizin-Logik mit Marker und Ordnertausch bleibt.
  - Wenn `pwsh` lokal vorhanden ist, jedes geänderte Skript mit `pwsh -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile('<pfad>', [ref]$null, [ref]$e) | Out-Null; $e"` auf Syntaxfehler prüfen (Ausgabe leer). Ohne `pwsh` im Bericht vermerken.
- [ ] **Step 4:** Neue Tests grün, `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(updates): install scripts can force a reinstall and pick a version`.

### Task 2: Katalog und Prüfungen (`webui/tool_updates.py`)

**Files:**
- Neu: `webui/tool_updates.py`, `tests/test_tool_updates.py`.
- `webui/tool_updates.py` in die drei Deploy-Wege aufnehmen (`test_every_deploy_path_uploads_the_web_ui_modules`).

**Interfaces – Produces:**
- **`class Env`**, die Standard-Implementierung:
  - `run(args: list[str], timeout: float) -> RunResult` mit `returncode`, `stdout`, `stderr`. Unter Windows über `subprocess.run` mit `CREATE_NO_WINDOW`. `FileNotFoundError` wird zu `returncode=127` und `stderr="not found: <exe>"`. `TimeoutExpired` wird zu `returncode=124`.
  - `http_get(url: str, timeout: float, method: str = "GET") -> HttpResult` mit `status`, `headers` (dict, Schlüssel klein geschrieben), `json` (oder `None`), `text`. Netzfehler ergeben `status=0`.
  - `exists(path: str) -> bool`, `read_text(path: str) -> str | None`.
  - GitHub-Aufrufe senden `Accept: application/vnd.github+json` und, wenn gesetzt, `Authorization: Bearer $TDC_GITHUB_TOKEN`.
- `RunResult` und `HttpResult` sind `NamedTuple`s.
- **`@dataclass ToolSpec`:**
  - Felder: `id`, `name`, `kind` (`"choco"|"winget"|"git"|"release"|"sysinternals"`), `path`;
  - `repo: str | None`, `version_cmd: list[str] | None`, `version_regex: str | None`, `marker: str | None`;
  - `script: str | None`, `script_args: list[str]`, `pinned: str | None`;
  - `consumers: list[str]`, `network: bool = True`.
- `CATALOG: list[ToolSpec]`: alle Nicht-choco-Zeilen aus dem Katalog der Spec, in dieser Reihenfolge.
- `CHOCO_CONSUMERS = {"python312": ["task:LitterBox", "task:DetonatorAPI", "task:DetonatorUI"], "dotnet-8.0-sdk": ["task:DetonatorAgent"], "php": ["task:theZoo-WebUI"]}`.
- **Verbraucher-IDs, genau so:**
  - `task:Rustinel`, `service:Rustinel`, `task:DetonatorAgent`, `task:DetonatorAPI`, `task:DetonatorUI`, `task:LitterBox`, `task:theZoo-WebUI`, `service:fibratus`, `rizin_sessions`.
- **Hilfsfunktionen:**
  - `normalize_version(s: str) -> str`: entfernt ein führendes `v`/`V` und Leerraum.
  - `compare_versions(a: str, b: str) -> int`: vergleicht numerisch je Teil. Nicht-numerische Teile werden als Text verglichen. Ergebnis −1, 0 oder 1.
- `parse_choco_outdated(text: str) -> list[dict]`: Zeilen `name|current|available|pinned`. Andere Zeilen werden ignoriert. Ergebnis: `{"package","current","available","pinned": bool}`.
- **`check_choco(env) -> list[dict]`:**
  - Ruft `choco outdated -r --ignore-unfound --limit-output` auf.
  - Pro Paket ein Eintrag mit `id="choco:<paket>"`, `kind="choco"` und Status `update_available`, oder `pinned_update`, wenn `pinned` gesetzt ist.
  - Fehlt choco (127), kommt eine leere Liste mit einem Eintrag `id="choco"`, Status `not_installed`.
- `check_tool(spec, env) -> dict`: Eintrag mit den Feldern aus der Spec (`id`, `name`, `kind`, `installed`, `available`, `status`, `pinned`, `detail`, `log: []`, `updated_at: None`).
- `check_all(env, max_workers=4) -> list[dict]`:
  1. Netzprobe `env.http_get("https://api.github.com", timeout=5)`.
  2. Bei `status == 0` bekommt jedes Tool mit `network=True`, das installiert ist, `offline` mit Detail `No internet access from the VM`. Es wird dann nichts weiter abgefragt und kein `git fetch` gemacht.
  3. Sonst `check_choco` plus `check_tool` für den Katalog, parallel.
  4. Ein Fehler in einem Tool wird zu `status="error"` mit einzeiligem `detail` und reißt den Rest nicht mit.

**Regeln je Art:**
- **Nicht installiert:** Fehlt `path`, ist der Status `not_installed`. Das gilt bei git für `<path>\.git`.
- **git:**
  - `installed` ist der Kurz-Hash (`rev-parse --short HEAD`), `available` der Kurz-Hash von `@{u}`.
  - Behind-Zahl > 0 ergibt `update_available` mit Detail `N new commits`.
  - Schlägt `fetch` fehl, ergibt das `error` mit erster stderr-Zeile.
- **release:**
  - `installed`: aus `version_cmd` und `version_regex`, sonst aus `marker`, sonst `unknown`.
  - `available` ist `tag_name` von `releases/latest`.
  - Eine neuere oder unbekannte installierte Version ergibt `update_available`, bei gesetztem `pinned` `pinned_update`.
  - Gleiche Version ergibt `up_to_date`.
  - Rizin liest die Cutter-Version aus `tdc-package.txt` (`Cutter-v(\S+)-Windows`).
- **sysinternals:**
  - `HEAD` auf die URL; der `etag` wird mit dem Wert aus `tdc-source.json` verglichen.
  - Ungleich ergibt `update_available`, gleich `up_to_date`. Fehlt der Marker: `unknown` mit Detail `Not checked yet; an update records the current version`.
- **winget:** Fehlt winget, ist der Status `unknown` mit Detail `winget is not available for SYSTEM`. Kommt die ID in der Ausgabe von `--upgrade-available` vor, ist der Status `update_available`.

- [ ] **Step 1: Failing tests** in `tests/test_tool_updates.py` mit einer `FakeEnv`. Sie bildet Kommandos (Tupel von Argumenten oder Präfixe) und URLs auf Antworten ab:
  - `test_compare_versions`:
    - `("v1.1.1","1.2.0")` → −1;
    - `("3.0.0","3.0.0")` → 0;
    - `("9.10.0","9.4.0")` → 1;
    - `("2.5.0","v2.5.0")` → 0.
  - `test_parse_choco_outdated`: `"Chocolatey v2.2.2\ngit|2.40.0|2.41.0|false\nphp|8.2.1|8.3.0|true\n"` → zwei Einträge; `php` hat `pinned` True.
  - `test_git_behind_reports_commits`:
    - `fetch` ok, `rev-list --count HEAD..@{u}` ergibt `3`, was `update_available` mit Detail `3 new commits` ergibt.
    - Jeder Git-Aufruf beginnt mit `webui/tool_updates.py:git_command(path, ...)` (fsmonitor, hooksPath, sshCommand and credential.helper off, `safe.directory=<path>`, `-C path`).
  - `test_release_pinned_newer`: rustinel `--version` gibt `rustinel 1.1.1`, latest ist `v1.2.0`. Erwartet: `pinned_update`, `installed == "1.1.1"`, `available == "1.2.0"`.
  - `test_release_without_marker_is_unknown_and_updatable`: beaconeye ohne Marker ergibt `installed == "unknown"` und `update_available`.
  - `test_offline_marks_network_tools`: Die Netzprobe gibt `status=0`. Alle installierten Tools mit Netz bekommen `offline` und dieses Detail. Die FakeEnv bestätigt, dass kein `fetch` aufgerufen wurde.
  - `test_missing_tool_is_not_installed`.
  - `test_one_failing_tool_does_not_break_the_check`: `version_cmd` wirft eine Ausnahme. Das ergibt bei diesem Tool `error`, die anderen sind ok.
  - `test_catalog_ids_are_unique_and_match_spec`: Die IDs sind genau die Nicht-choco-IDs aus der Spec-Tabelle, in Spec-Reihenfolge. Rizin hat `consumers == ["rizin_sessions"]`, fibratus `["service:fibratus"]`, rustinel `["task:Rustinel","service:Rustinel"]`.
- [ ] **Step 2:** `webui/.venv/bin/python -m pytest tests/test_tool_updates.py -q` → FAIL.
- [ ] **Step 3:** Modul schreiben. Katalogwerte stammen aus der Spec. Versionsbefehle:
  - capa: `[exe,"--version"]`, Regex `(\d+\.\d+\.\d+)`;
  - rustinel: `["C:\\tools\\rustinel\\rustinel.exe","--version"]`;
  - fibratus: `[exe,"version"]`.
- [ ] **Step 4:** Tests grün, `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(updates): tool catalog and update checks`.

### Task 3: `UpdateManager`: Zustand, Ablauf, Wartungsmodus

**Files:**
- Ändern: `webui/tool_updates.py`, `tests/test_tool_updates.py`, `.gitignore` (`webui/tool_updates_state.json`, `webui/tool_updates_state.json.tmp`).

**Interfaces – Consumes:** `Env`, `CATALOG`, `CHOCO_CONSUMERS`, `check_all` aus Task 2.

**Interfaces – Produces:**
- **Verbraucher-Funktionen:**
  - `consumer_running(cid: str, env) -> bool`, `stop_consumer(cid, env) -> None`, `start_consumer(cid, env) -> None` steuern Tasks und Dienste über PowerShell:
    - **Task:** `(Get-ScheduledTask -TaskName X).State -eq 'Running'`; `Stop-ScheduledTask` plus Beenden der Prozesse, deren Pfad im Installordner liegt; `Start-ScheduledTask`.
    - **Dienst:** `Get-Service`, `Stop-Service -Force`, `Start-Service`.
  - `rizin_sessions` wird nicht von diesen Funktionen behandelt, sondern über den Callback `close_rizin`.
- **`class UpdateManager`:**
  - Konstruktor: `UpdateManager(env, state_path: str, log_path: str, scripts_dir: str, preconditions: Callable[[], str | None] = lambda: None, close_rizin: Callable[[], None] = lambda: None, spawn: Callable[[Callable[[], None]], None] = <daemon thread>)`.
  - Beim Erzeugen wird die Zustandsdatei geladen. Ein gespeicherter Modus `updating` oder `checking` wird zu `idle`. Ein Tool mit `updating` wird zu `failed` mit Detail `Interrupted: the web UI restarted during the update.`, `queued` zurück zum vorherigen Status oder zu `unknown`.
  - `.maintenance -> bool`: wahr genau bei Modus `updating`.
  - `.snapshot() -> dict`: `{"mode","checked_at","tools":[…],"progress":{"done":int,"total":int,"current":str|None},"last_run":{"started_at","finished_at","results":{id: status}}|None}`. Gibt eine tiefe Kopie zurück.
  - `.start_check() -> tuple[int, dict]`:
    - `(202, {"started": True})`.
    - Ist der Modus nicht `idle`, `(409, {"error": "An update check or install is already running."})`.
    - Ergebnis setzt `tools` und `checked_at` (ISO-8601 UTC). Laufzeitfelder `log` und `updated_at` vorhandener Einträge bleiben erhalten.
  - `.start_apply(tools: list[str] | str, include_pinned: bool = False) -> tuple[int, dict]`:
    1. Ist der Modus nicht `idle`: 409 wie oben.
    2. `preconditions()` liefert einen Grund: 409 `{"error": <Grund>}`.
    3. Unbekannte IDs: 400 `{"error": "Unknown tools: a, b"}`.
    4. `"all"` wählt jedes Tool mit `update_available`. `pinned_update` kommt nur mit `include_pinned` dazu. Eine explizite ID mit `pinned_update` ohne `include_pinned` ergibt 409 `{"error": "<name> is pinned to <pin>. Pass include_pinned to install <available>."}`.
    5. Leere Auswahl: 409 `{"error": "No updates to install."}`.
    6. Sonst `(202, {"started": True, "tools": [ids]})`. Die Tools stehen auf `queued`, der Modus auf `updating`.
  - **Lauf je Tool, in Reihenfolge:** Katalogreihenfolge, choco zuletzt, `choco:python312` ganz zuletzt.
    1. Status `updating`, `progress.current = name`.
    2. Bei `rizin_sessions` wird `close_rizin()` aufgerufen.
    3. Für jeden anderen Verbraucher: `consumer_running`; die laufenden merken und stoppen.
    4. Die Aktion je Art:
       - **git:** `pull --ff-only --autostash`, dann Skript.
       - **release, sysinternals:** Skript mit `script_args`. Bei gepinnten Tools kommt `-Version <available>` dazu. Rizin bekommt zusätzlich `-PackageSha256 <hex>` aus dem `digest` (`sha256:<hex>`) des Assets `Cutter-v<available>-Windows-x86_64.zip` in `releases/latest`. Fehlt der Digest: `failed`, Detail `GitHub publishes no SHA-256 for this package; not installed.`
       - **choco:** `choco upgrade <paket> -y --no-progress`.
       - **winget:** der Befehl aus der Spec.
       - **Skriptaufruf:** `["powershell","-NoProfile","-ExecutionPolicy","Bypass","-File", os.path.join(scripts_dir, script), *args]` mit `SCRIPT_TIMEOUT`. Fehlt das Skript: `failed`, Detail `Install script missing: <pfad> (run make deploy)`.
    5. Die gemerkten Verbraucher starten, in einem `finally`, also auch nach Fehlern.
    6. Ergebnis aus dem Exit-Code (siehe Global Constraints). Bei Erfolg dieses eine Tool neu mit `check_tool`, bei choco mit `check_choco`. Bei `reboot_required` bleibt der Status so.
    7. Die Protokollzeilen (stdout und stderr, die letzten 200) gehen in `log` und an die Logdatei. Format: `<ISO-Zeit> [<id>] <zeile>`. `updated_at` wird gesetzt.
  - **Nach dem Lauf:** Modus `idle`, `last_run` gefüllt, Zustand gespeichert. Der Zustand wird nach jedem Tool gespeichert.
  - `.run_check_sync()` und `.run_apply_sync()` sind die Arbeitsfunktionen. `start_*` übergibt sie an `spawn`; die Tests geben ein `spawn` mit, das sofort ausführt.

- [ ] **Step 1: Failing tests** (FakeEnv aus Task 2 weiterverwenden, `spawn=lambda f: f()`, `tmp_path` für Zustand und Log):
  - `test_apply_all_skips_pinned`.
  - `test_apply_pinned_needs_include_pinned`: 409 mit genauer Meldung. Mit `include_pinned` läuft der Skriptaufruf mit `-Force -Version 1.2.0`.
  - `test_running_consumer_restarted_after_failure`:
    - Task `LitterBox` läuft, das Skript endet mit 1. Erwartet: stop vor dem Skript, start danach, Status `failed`.
    - Ein Verbraucher, der vorher nicht lief, wird nicht gestartet.
  - `test_reboot_required_exit_code`: choco gibt 3010 zurück, Status `reboot_required`.
  - `test_preconditions_block`: `preconditions` gibt `"A detonation is running."` zurück. Erwartet: 409, kein Stop- oder Skriptaufruf, Modus `idle`.
  - `test_busy_returns_409`.
  - `test_unknown_tool_400`.
  - `test_maintenance_flag_during_run`: Ein Fake-Skript liest `manager.maintenance` während des Laufs aus und sieht `True`; danach ist es `False`.
  - `test_interrupted_state_recovered`: Zustandsdatei mit Modus `updating` und Tool `updating`. Ein neuer Manager hat Modus `idle`, das Tool hat `failed` mit genauem Detail.
  - `test_git_update_pulls_with_autostash_then_runs_script`.
  - `test_rizin_without_digest_fails_and_closes_sessions`: `close_rizin` wurde aufgerufen, Status `failed`, genaues Detail.
  - `test_missing_script_fails_cleanly`.
  - `test_python312_runs_last`.
  - `test_log_is_capped`: 500 Zeilen stdout ergeben 200 im `log`.
  - `test_state_written_atomically`: Nach einem Lauf gibt es keine `.tmp`-Datei. Die JSON lässt sich laden.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Umsetzen, mit `threading.Lock` um den Zustand.
- [ ] **Step 4:** Tests grün, `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(updates): update runner with maintenance state`.

### Task 4: Flask: Routen, Sperre, Vorbedingungen, tägliche Prüfung

**Files:**
- Ändern: `webui/app.py`, `README.md` (API-Tabelle: neue Unterüberschrift `### Tool Updates` mit drei Zeilen), `webui/templates/index.html` (nur die API-Hilfetabelle `#help-api`, drei Zeilen; `?v=` hier nicht nötig).
- Test: `tests/test_tool_updates.py` ergänzen (Flask-Teil mit `client`/`tdc`-Fixtures).

**Interfaces – Consumes:** `UpdateManager`, `Env` aus Task 2 und 3.

**Interfaces – Produces:**
- **`_update_manager`:** In `app.py` modulweit, lazy über `_get_update_manager()` erzeugt:
  - Zustand in `os.path.join(APP_DIR, "tool_updates_state.json")`. Den vorhandenen Namen für den App-Ordner verwenden, wie bei `SCAN_HISTORY_FILE`.
  - Log, Skripte und Token aus den Umgebungsvariablen.
  - `preconditions=_update_preconditions`, `close_rizin=<schließt alle Rizin-Sitzungen über den vorhandenen Sitzungsmanager>`.
- **`_update_preconditions() -> str | None`**, die Gründe genau so:
  - Agent `/api/lock/status` meldet `in_use` (oder `locked`): `A detonation is running. Wait until it finishes.`
  - `_sweep_state["running"]`: `A memory sweep is running.`
  - Ein laufender Process-Dump-Job (vorhandenen Zustand verwenden): `A process dump is running.`
  - Ist der Agent nicht erreichbar, zählt das nicht als laufende Detonation.
- **Routen:**
  - `GET /api/updates` liefert `snapshot()`.
  - `POST /api/updates/check`.
  - `POST /api/updates/apply`: Body `{"tools": [...] | "all", "include_pinned": bool}`. Fehlt `tools` oder ist der Typ falsch: 400 `{"error": "tools must be \"all\" or a list of tool ids"}`.
- **Sperre:**
  - Ein zweites `@app.before_request` nach `_block_cross_site_requests`.
  - Ist `_update_manager` erzeugt, `maintenance` wahr, die Methode in `_UNSAFE_METHODS` und der Pfad beginnt nicht mit `/api/updates/`, antwortet es mit 503 und dem genauen Text aus den Global Constraints.
  - Ein noch nicht erzeugter Manager wird dafür nicht angelegt.
- **Tägliche Prüfung:**
  - Ohne `TDC_NO_BACKGROUND` startet beim Laden ein Daemon-Thread, wo die anderen Hintergrund-Threads starten.
  - Er wartet 300 s, dann prüft er alle `TDC_UPDATE_CHECK_HOURS` Stunden mit `start_check()`, aber nur, wenn der Modus `idle` ist. Bei 0 startet kein Thread.

- [ ] **Step 1: Failing tests:**
  - `test_updates_get_shape`: Die Schlüssel `mode`, `checked_at`, `tools`, `progress` und `last_run` sind vorhanden.
  - `test_maintenance_blocks_unsafe_requests`:
    - Manager per monkeypatch auf `maintenance=True`.
    - `POST /api/submit` und `POST /api/service/launch` ergeben 503 mit genauem Text und `maintenance: true`.
    - `GET /api/status` ist nicht 503. `POST /api/updates/check` ist nicht 503 (409 erlaubt).
  - `test_apply_refused_during_detonation`: `_probe_http` bzw. der Lock-Abruf wird gepatcht, sodass er `{"in_use": true}` liefert. Erwartet: 409 mit genauem Text.
  - `test_apply_bad_body_400`.
  - `test_cross_site_post_still_403`: Das Origin `http://evil.example` bei `/api/updates/apply` ergibt 403.
  - Die Doku-Tests (`tests/test_docs.py`) sind grün, inklusive README-API-Tabelle und Hilfe-API-Zeilen.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Umsetzen. Die Manager-Erzeugung in Tests über eine Fixture mit `tmp_path`, ohne echte Prozesse (FakeEnv).
- [ ] **Step 4:** `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(updates): update API and maintenance gate`.

### Task 5: Frontend: Dashboard-Bereich „Tool Updates“ und Wartungs-Banner

**Files:**
- Ändern: `webui/templates/index.html` (Bereich im `#tab-dashboard` unter `#dashboard-grid`; `#maintenance-banner` direkt nach der Topbar; `?v=` erhöhen), `webui/static/js/app.js`, `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`, die Hilfe zum Dashboard in `#help-usage` (ein Satz zu Tool Updates).
- Test: `tests/test_tool_updates_ui.py` (neu). Die neuen Funktionen werden in die passenden Listen in `tests/test_theme.py` bzw. `tests/test_frontend.py` eingetragen, wenn deren Tests es verlangen.

**Interfaces – Consumes:** `GET /api/updates`, `POST /api/updates/check`, `POST /api/updates/apply`, die 503-Antwort (Task 4).

**Interfaces – Produces (app.js, oberste Ebene):**
- `let updatesState = null;`, `let updatesPollTimer = null;`
- `async function refreshUpdates()` holt `/api/updates`, ruft `renderUpdates` und `renderMaintenanceBanner` auf und stellt die Abfrage auf 3 s, solange der Modus nicht `idle` ist. Wechselt der Modus von `updating` zu `idle`, kommt ein Toast mit Zusammenfassung (`N updated, M failed`, Typ `success` oder `warning`). Die Abfrage läuft zusätzlich alle 10 s über das vorhandene `setInterval` mit `refreshDashboard`, unter derselben `document.hidden`-Bedingung.
- `function renderUpdates(state)` zeichnet in `#tool-updates`:
  - Kopfzeile: „Last checked …“ bzw. „Never checked“, Knopf **Check for updates** und Knopf **Update all (N)** (N = Zahl der Tools mit `update_available`, deaktiviert bei 0 oder Modus ≠ `idle`).
  - Tabelle mit den Spalten Tool, Source, Installed, Available, Status und Aktion.
  - Je Zeile ein Knopf **Update** für `update_available`, `pinned_update`, `failed` und `reboot_required`.
  - Ein Klick auf die Zeile klappt `log` auf (`<pre>` über `textContent` oder escaped).
- `function updateStatusLabel(status) -> string`: lesbarer englischer Text je Status-Wert, z. B. `pinned_update` → `Pinned – newer available`, `reboot_required` → `Reboot required`.
- `async function checkUpdates()`, `async function applyUpdates(ids, includePinned)`:
  - Ein gepinntes Tool fragt zuerst `confirm("<name> is pinned to <pin> for compatibility. Install <available> anyway?")`.
  - **Update all** fragt `confirm("Install N updates? Detonations, scans and uploads are paused while they run.")`.
  - Fehler zeigen `showToast('error', …, data.error)`.
- `function renderMaintenanceBanner(state)`: `#maintenance-banner` ist nur bei Modus `updating` sichtbar.
  - Text: `MAINTENANCE — Updating tools (done+1/total: current). Detonations, scans and uploads are paused.`
  - Ein Fortschrittsbalken.
  - `document.body.classList` bekommt `maintenance-active` oder verliert es.
- **Start:** Fehlen `#tool-updates` oder `#maintenance-banner`, bricht nichts (`test_a_missing_part_does_not_stop_the_start_up`). `updateServiceStatus` bleibt unverändert.
- **(i)-Text** am Bereich: `data-info="Checks every installed tool for a newer version and installs it. While an update runs, detonations, scans and uploads are paused."`

- [ ] **Step 1: Failing tests** in `tests/test_tool_updates_ui.py`, Node über `_function_source`/`_run_node` mit kleinem DOM-Stub wie in den vorhandenen UI-Tests:
  - `test_update_all_count_excludes_pinned`: Der Zustand mit 2× `update_available` und 1× `pinned_update` ergibt den Knopftext `Update all (2)`.
  - `test_tool_names_are_escaped`: Ein Tool mit dem Namen `<img src=x onerror=alert(1)>` und Log `</pre><script>` erscheint nicht als Element.
  - `test_banner_only_while_updating`: Modus `checking` versteckt das Banner. `updating` mit `progress {done:2,total:5,current:"LitterBox"}` ergibt `3/5: LitterBox`.
  - `test_status_labels_cover_all_statuses`: Jeder der 12 Status-Werte ergibt einen nicht leeren Text, der nicht gleich dem rohen Wert ist.
  - `test_markup_present`: In `index.html` stehen `id="tool-updates"` innerhalb von `#tab-dashboard` und `id="maintenance-banner"` außerhalb aller `.tab-content`.
  - Die bestehenden Theme-, Frontend- und Info-Tests sind grün.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Umsetzen:
  - Badges in den vorhandenen Statusfarben (`--…`-Variablen; neue Variablen nur in `:root`).
  - Das Banner auffällig, aber im Stil der vorhandenen `*-banner`-Klassen.
  - Cyberpunk-Varianten nur unter `[data-theme="cyberpunk"]`.
- [ ] **Step 4:** `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(updates): tool updates panel and maintenance banner`.

### Task 6: MCP-Tools und Doku

**Files:**
- Ändern: `mcp/server.py`, `tests/test_mcp.py` (falls die Mindestzahl angepasst werden muss), `README.md`, `webui/templates/index.html` (Zahl der MCP-Tools in `#help-api`).
- Neu: `static/tool_updates.png`. Optional; nur wenn ein Screenshot in Task 7 entsteht, dort einfügen.

**Interfaces – Produces:**
- `tdc_updates_status()` ruft `GET /api/updates` auf.
- `tdc_updates_check()` ruft `POST /api/updates/check` auf.
- `tdc_updates_apply(tools: str = "all", include_pinned: bool = False)`. `tools` ist `"all"` oder eine kommaseparierte Liste von IDs; sie wird in eine Liste umgewandelt und an `POST /api/updates/apply` geschickt.
- Docstrings nennen jedes Argument, wie `test_mcp.py` es verlangt.
- **README:**
  - Abschnitt `## Tool Updates` nach `## Rizin`, mit Eintrag im Inhaltsverzeichnis. Er beschreibt:
    - was geprüft wird (Tabelle der Quellen, kurz);
    - gepinnte Tools;
    - den Wartungsmodus;
    - die tägliche Prüfung;
    - die Umgebungsvariablen `TDC_SCRIPTS_DIR`, `TDC_UPDATE_LOG`, `TDC_UPDATE_CHECK_HOURS`, `TDC_GITHUB_TOKEN`;
    - dass die VM dafür Internet braucht.
  - Die Liste der Features um einen Eintrag ergänzt.
  - Die MCP-Liste ergänzt, mit angepasster Anzahl.

- [ ] **Step 1:** Doku- und MCP-Tests laufen lassen (`make -s unit-test`). Nach dem Hinzufügen der Tools schlagen sie fehl, bis die README stimmt.
- [ ] **Step 2:** Umsetzen.
- [ ] **Step 3:** `make -s unit-test` grün (inklusive MCP-Teil).
- [ ] **Step 4: Commit** `docs(updates): tool updates section and MCP tools`.

### Task 7: Prüfung auf der VM (Controller)

- Ist die UTM-VM erreichbar (`http://192.168.64.4:9000/api/health`), mit `python3 scripts/deploy-utm.py --vm-ip 192.168.64.4 --vm-user tdc --vm-pass tdc --restart` deployen und dann:
  - `GET /api/updates`;
  - `POST /api/updates/check`;
  - warten, bis der Modus `idle` ist;
  - prüfen, dass jedes Katalog-Tool einen Status hat und keines ohne Grund `error` zeigt;
  - ein kleines, ungepinntes Tool aktualisieren (z. B. ein Git-Repo mit Update oder capa) und dabei Banner und 503 bei `POST /api/submit` beobachten.
- Ist die VM nicht erreichbar, wird das im Abschlussbericht gesagt. Dann gelten nur die Unit-Tests als Beleg.
