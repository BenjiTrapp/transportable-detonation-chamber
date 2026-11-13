# Tool-Updates aus dem Dashboard – Design

## Absicht

Die Tools in der VM sollen aktuell bleiben, ohne die VM neu zu provisionieren. Auf dem Service Dashboard gibt es dazu einen Bereich **Tool Updates**:

- Er prüft für jedes installierte Tool, ob es eine neuere Version gibt.
- Er installiert die Updates, einzeln oder alle.
- Während ein Update läuft, ist TDC im **Wartungsmodus**. Ein Banner auf jeder Seite sagt, dass Detonationen, Scans und Uploads pausiert sind und was gerade aktualisiert wird. Der Server weist solche Aufrufe ab.

Der Nutzer hat ausdrücklich „alle Tools“ verlangt und auf Rückfragen verzichtet. Entscheidungen, die er nicht selbst getroffen hat, sind unten als **Entscheidung** markiert.

## Ziele

- Jedes Tool aus `scripts/install-*.ps1` hat einen Eintrag mit installierter Version, verfügbarer Version und Status.
- „Check for updates“ läuft im Hintergrund. Zusätzlich prüft der Server einmal pro Tag selbst, installiert aber nie von allein.
- „Update all“ aktualisiert alle Tools mit Update, die nicht fest gepinnt sind. Jedes Tool hat einen eigenen „Update“-Knopf.
- Dienste, die ein Tool benutzen, werden vor dem Update gestoppt und danach wieder gestartet, aber nur die, die vorher liefen.
- Jedes Update schreibt ein Protokoll. Die Oberfläche zeigt pro Tool die letzten Zeilen und den Grund eines Fehlers.

## Nicht-Ziele

- Das Web-UI aktualisiert sich nicht selbst. Es und seine pip-Pakete kommen weiter über `make deploy` oder `deploy-utm.py`.
- Keine automatische Installation ohne Klick.
- Kein Zurückrollen auf eine ältere Version.
- System-pip und uv werden nicht geprüft, OpenSSH auch nicht.

## Anti-Ziele

Diese Fälle gelten als Fehlschlag, auch wenn das Update technisch durchläuft:

- Ein Update startet während einer laufenden Detonation, eines Memory-Sweeps oder eines Process-Dump-Jobs.
- Ein Dienst, der vorher lief, bleibt nach dem Update aus, ohne dass die Oberfläche das meldet.
- Ein gepinntes Tool (feste Version, Prüfsumme) wird durch „Update all“ still auf eine ungeprüfte Version gehoben.
- Eine VM ohne Internet zeigt hängende Knöpfe oder rote Fehlerwände statt „offline“.

## Ansätze

1. **Eigene Update-Logik in Python pro Tool:** Herunterladen, Entpacken und Bauen würden in Python nachgebaut. Das verdoppelt die Logik der Install-Skripte mit ihren Fallbacks und läuft auseinander.
2. **Python prüft, die vorhandenen Install-Skripte installieren (gewählt):**
   - Die Prüfung (Versionen, `choco outdated`, `git fetch`, GitHub-API) liegt in einem neuen Modul `webui/tool_updates.py`.
   - Installiert wird mit den bestehenden, wiederholbaren Skripten. Wo ein Skript heute abbricht, weil das Tool schon da ist, bekommt es einen Schalter `-Force`. Gepinnte Skripte bekommen Parameter für Version und Prüfsumme.
   - Python orchestriert: Vorbedingungen, Dienste stoppen, `git pull`, Skript ausführen, Dienste starten, neu prüfen.
3. **Ein großes PowerShell-Update-Skript, das das Web-UI nur startet:** Unabhängig vom Web-UI-Prozess, aber in CI nicht testbar (kein PowerShell), und Status und Protokoll müssten über Dateien zurück.

**Entscheidung:** Ansatz 2, weil er die erprobten Install-Wege wiederverwendet und die Logik mit pytest testbar bleibt.

## Werkzeugkatalog

| id | Anzeige | Art | Prüfung | Update | Pin | Stoppt |
|---|---|---|---|---|---|---|
| `choco:<paket>` | jedes Paket, das `choco outdated` meldet (git, dotnet-8.0-sdk, python312, 7zip, brave, die, ghidra, php, temurin21jdk, visualstudio2022buildtools, chocolatey …) | choco | `choco outdated -r --ignore-unfound` | `choco upgrade <paket> -y --no-progress` | gepinnt, wenn choco es als pinned meldet (`choco_pinned`: `choco upgrade` kann es nicht, auch nicht mit `include_pinned`); `python312` ist immer von TDC gepinnt (`pinned_update`, `pinned` = installierte Version): das Web-UI läuft auf diesem Python | `python312`: LitterBox, Detonator; `dotnet-8.0-sdk`: DetonatorAgent; `php`: theZoo-WebUI |
| `windbg` | WinDbg | winget | `winget list --id Microsoft.WinDbg --upgrade-available` | `winget upgrade --id Microsoft.WinDbg --silent --accept-source-agreements --accept-package-agreements` | – | – |
| `rustinel_rules` | Rustinel rules | git | `C:\tools\detection-rules\rustinel-rules` | pull + `install-detection-rules.ps1` | – | – |
| `elastic_rules` | Elastic YARA rules | git | `C:\tools\detection-rules\elastic-protections` | pull + `install-detection-rules.ps1` | – | – |
| `detonator_agent` | DetonatorAgent | git | `C:\DetonatorAgent` | pull + `install-detonator.ps1` | – | Task DetonatorAgent |
| `detonator` | Detonator | git | `C:\detonator` | pull + `install-detonator.ps1` | – | Tasks DetonatorAPI, DetonatorUI |
| `litterbox` | LitterBox | git | `C:\LitterBox` | pull + `install-litterbox.ps1` | – | Task LitterBox |
| `thezoo_webui` | theZoo WebUI | git | `C:\tools\theZoo-WebUI` | pull + `install-thezoo.ps1` | – | Task theZoo-WebUI |
| `thezoo` | theZoo | git | `C:\tools\theZoo-WebUI\theZoo` | pull + `install-thezoo.ps1` | – | Task theZoo-WebUI |
| `hunt_sleeping_beacons` | Hunt-Sleeping-Beacons | git | `C:\tools\Hunt-Sleeping-Beacons-src` | pull + `install-hunt-sleeping-beacons.ps1` | – | – |
| `ember` | EMBER2024 | git | `C:\tools\EMBER2024\EMBER2024` | pull + `install-ember.ps1` | – | – |
| `aether` | Aether | git | `C:\tools\Aether-src`; fehlt der Ordner, Status `unknown` | `install-aether.ps1 -NoPrebuilt -Force` | – | – |
| `capa` | capa | release `mandiant/capa` | `capa.exe --version` | `install-capa.ps1 -Force` | – | – |
| `beaconeye` | BeaconEye | release `CCob/BeaconEye` | Marker | `install-beaconeye.ps1 -Force` | – | – |
| `process_dump` | Process Dump | release `glmcdona/Process-Dump` | Marker | `install-process-dump.ps1 -Force` | – | – |
| `threatcheck` | ThreatCheck | release `rasta-mouse/ThreatCheck` | Marker | `install-scanner-tools.ps1 -Force -Only ThreatCheck` | – | – |
| `defendercheck` | DefenderCheck | release `matterpreter/DefenderCheck` | Marker | `install-scanner-tools.ps1 -Force -Only DefenderCheck` | – | – |
| `rustinel` | Rustinel | release `Karib0u/rustinel` | `rustinel.exe --version` | `install-rustinel.ps1 -Force -Version <neu>` | 1.1.1 | Task Rustinel, nssm-Dienst Rustinel |
| `fibratus` | Fibratus | release `rabbitstack/fibratus` | `fibratus.exe version` | `install-fibratus.ps1 -Force -Version <neu>` | 3.0.0 | Dienst fibratus |
| `rizin` | Rizin (Cutter) | release `rizinorg/cutter` | `C:\tools\cutter\tdc-package.txt` (`Cutter-v<x>-…`) | `install-rizin.ps1 -Version <neu> -PackageSha256 <digest>` | Cutter 2.5.0 | Rizin-Sitzungen schließen |
| `sysmon` | Sysmon | sysinternals | `ETag` von `https://download.sysinternals.com/files/Sysmon.zip` gegen Marker | `install-sysmon.ps1 -Force` | – | (Skript selbst) |
| `sysmon_config` | Sysmon config | sysinternals | `ETag` der SwiftOnSecurity-Config gegen Marker | `install-sysmon.ps1` (lädt die Config neu, wenn Sysmon läuft) | – | – |

- **Git-Prüfung:** `git -c core.fsmonitor=false -c core.hooksPath=NUL -c core.sshCommand= -c credential.helper= -c safe.directory=<dir> -C <dir> fetch --quiet`, dann `rev-list --count HEAD..@{u}`. Das Web-UI läuft als SYSTEM, die Repos gehören einem anderen Nutzer; ohne `safe.directory` meldet Git „dubious ownership“.
- **Git-Update:** `git -c core.fsmonitor=false -c core.hooksPath=NUL -c core.sshCommand= -c credential.helper= -c safe.directory=<dir> -C <dir> pull --ff-only --autostash`. Das hebt lokale Änderungen wie LitterBox' `config.yaml` auf. Danach läuft das Skript, das neu baut. Sein eigener Pull ändert dann nichts mehr.
- **Release-Prüfung:** `GET https://api.github.com/repos/<repo>/releases/latest`. Ein optionales Token kommt aus `TDC_GITHUB_TOKEN`. Versionen werden ohne führendes `v` verglichen.
- **Marker:** `tdc-release.txt` im Installordner enthält den installierten Tag. Die Install-Skripte schreiben ihn nach jeder Installation. Fehlt er, ist die installierte Version `unknown` und der Status `update_available`. Er wird erst nach dem ersten Update gefüllt.
- **Gepinnte Tools:**
  - **Entscheidung:** Ist eine neuere Version da, ist der Status `pinned_update`. „Update all“ lässt sie aus. Der eigene Knopf fragt nach („Pinned to X for compatibility. Install Y anyway?“).
  - Für Rizin wird die Prüfsumme aus dem `digest` des GitHub-Assets übernommen. Fehlt der Digest, wird das Update mit Grund abgewiesen.
  - Nach einem erneuten Provisionieren gilt wieder der Pin aus dem Skript.
- **Nicht installiert:** Fehlt ein Tool auf der VM, ist der Status `not_installed`, ohne Knopf.
- **Choco-Fallbacks:** DIE und Ghidra, die nicht über choco, sondern über Fallback-Zip installiert wurden, tauchen in `choco outdated` nicht auf. Sie gelten als nicht im Katalog. **Entscheidung:** Das ist bewusst so (YAGNI).

## Status je Tool

Werte für `status`: `up_to_date`, `update_available`, `pinned_update`, `unknown`, `not_installed`, `offline`, `error`, `queued`, `updating`, `updated`, `failed`, `reboot_required`.

Jeder Eintrag hat: `id`, `name`, `kind`, `installed`, `available`, `status`, `pinned` (Version oder `null`), `detail` (ein Satz), `log` (bis zu 200 letzte Zeilen des letzten Updates), `updated_at`.

## Wartungsmodus

- **Zustand:** `mode` ist `idle`, `checking` oder `updating`. Er liegt im Speicher und in `webui/tool_updates_state.json`; die Datei wird atomar geschrieben und ist git-ignoriert.
- **Abweisen:** Während `updating` lehnt ein `before_request` jede POST-, PUT-, PATCH- oder DELETE-Anfrage ab, außer unter `/api/updates/`. Antwort: 503 mit `{"error": "Maintenance: tool updates are running. Detonations, scans and uploads are paused.", "maintenance": true}`. GET bleibt erlaubt, damit Dashboard und Banner weiterlaufen.
- **Vorbedingungen:** Ein Update startet nicht (409, mit Grund), wenn
  - der DetonatorAgent `in_use` meldet,
  - ein Memory-Sweep oder Process-Dump-Job läuft,
  - schon ein Check oder Update läuft.
- **Neustart des Web-UI mitten im Update:** Der gespeicherte Zustand `updating` wird beim Start zu `idle`. Das laufende Tool bekommt `failed` mit „Interrupted: the web UI restarted during the update.“
- **Reihenfolge eines Laufs:**
  1. Für jedes Tool: Rizin-Sitzungen schließen, wenn nötig.
  2. Laufende Verbraucher merken und stoppen.
  3. Pull (bei git), Skript oder Paketmanager ausführen.
  4. Verbraucher wieder starten.
  5. Das Tool neu prüfen.
  6. choco-`python312` kommt immer zuletzt.
- **Ergebnis:** Exit-Code 3010 oder 1641 (choco, msiexec) ergibt `reboot_required`. Ein Fehler bei einem Tool bricht den Lauf nicht ab.
- **Zeitlimit:** Ein Skript läuft höchstens 45 Minuten. Ein Check pro Tool höchstens 60 Sekunden, `choco outdated` höchstens 180 Sekunden.
- **Protokoll:** Pro Tool im Zustand, gesammelt in `C:\tools\logs\tool-updates.log` (über `TDC_UPDATE_LOG` änderbar; außerhalb von Windows neben `app.py`).

## Oberfläche

- **Bereich auf dem Dashboard:** Ein Abschnitt „Tool Updates“ unter den Service-Karten, in beiden Themes:
  - Kopfzeile mit „Last checked …“, Knopf „Check for updates“ und Knopf „Update all (N)“.
  - Eine Tabelle: Tool, Source, Installed, Available, Status-Badge und ein Knopf je Zeile.
  - Ein Klick auf eine Zeile klappt ihr Protokoll auf.
  - Es gibt einen (i)-Text.
- **Banner:** Ein Banner `#maintenance-banner` erscheint auf jeder Seite unter der Topbar. Text: „MAINTENANCE — Updating tools (3/12: LitterBox). Detonations, scans and uploads are paused.“ Es zeigt einen Fortschrittsbalken. Ist der Lauf fertig, erscheint ein Toast mit dem Ergebnis, und das Banner verschwindet.
- **Abfrage:** `/api/updates` wird alle 10 Sekunden zusammen mit dem Dashboard abgefragt, während `checking` oder `updating` alle 3 Sekunden.
- **Ohne Internet:** Die Zeilen zeigen `offline` mit „No internet access from the VM“.

## API

| Methode | Route | Zweck |
|---|---|---|
| GET | `/api/updates` | Zustand, `checked_at`, Tools, Fortschritt |
| POST | `/api/updates/check` | Prüfung im Hintergrund starten (202; 409 wenn beschäftigt) |
| POST | `/api/updates/apply` | `{"tools": ["id", …]}` oder `{"tools": "all"}`, optional `"include_pinned": true` (202; 400 bei unbekannten IDs; 409 mit Grund) |

MCP bekommt dazu die Tools `tdc_updates_status`, `tdc_updates_check` und `tdc_updates_apply`.

## Skripte auf der VM

- Das Web-UI führt Skripte aus `TDC_SCRIPTS_DIR` aus, Standard `C:\tdc\scripts`.
- UTM legt sie dort schon ab.
- Die Vagrantfiles bekommen einen File-Provisioner `scripts` → `C:\tdc\scripts`.
- `make deploy`, `make.ps1 deploy` und `deploy-utm.py` laden die Install-Skripte auch hoch.
- Fehlt ein Skript, schlägt das Update dieses Tools mit „Install script missing: … (run make deploy)“ fehl.

## Dem Bauenden überlassen

- Das genaue Layout von Tabelle und Banner im Stil der vorhandenen Karten.
- Wie die Install-Skripte `-Force` intern umsetzen. Für Fibratus heißt das: vorherige Installation per MSI deinstallieren, dann installieren und die Config zurückkopieren.
- Die Parallelität der Prüfungen (höchstens 4 gleichzeitig).
