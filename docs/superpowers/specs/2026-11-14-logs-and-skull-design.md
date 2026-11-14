# Skull-Button, eigener Dialog und Tab „Logs“ – Design

Der Nutzer hat auf Rückfragen verzichtet („headless, ohne nachzufragen“). Alles, was er nicht selbst gesagt hat, ist als **Entscheidung** markiert.

## Teil A: Skull-Button und Dialog

**Wunsch:**
- „Update all“ im Tool-Updates-Panel wird ein runder, glänzend roter Knopf mit schwarzem Totenkopf und gekreuzten Knochen, wie in der Vorlage.
- Der native Browser-Dialog `confirm()` wird durch einen eigenen, „cooleren“ Dialog ersetzt.

**Entscheidungen:**
- **Grafik:** Der Knopf wird als eigenes Inline-SVG gezeichnet. Es kommt keine fremde Bilddatei ins Repo.
  - Aufbau: glänzender roter Kreis mit Verlauf, Lichtreflex und dunklem Rand; schwarzer Schädel mit roten Augen; gekreuzte Knochen.
  - Größe etwa 56 px.
  - Neben dem Knopf steht `UPDATE ALL` und die Zahl N als Badge.
- **Zustände:**
  - Hover: leichtes Pulsieren und roter Glow.
  - Deaktiviert (N = 0 oder beschäftigt): entsättigt und ohne Glow. Der Tooltip erklärt den Grund.
- **Dialog:** `tdcConfirm(options) -> Promise<boolean>`, wiederverwendbar.
  - **Optionen:** Titel, Text, optionale Liste (Tool, installierte Version → verfügbare Version), Beschriftung des Bestätigungs-Knopfs, `danger` (zeigt den Totenkopf), Fokus auf Abbrechen.
  - **Verhalten:** Esc und Klick auf den Hintergrund brechen ab, Enter bestätigt. Der Fokus bleibt im Dialog, danach kehrt er an die vorherige Stelle zurück.
  - **Aussehen:** In beiden Themes passend. Cyberpunk mit Neon-Rand, Scanlines und kurzem Glitch beim Öffnen, Classic schlicht.
- **Einsatz:** Der Dialog ersetzt beide `confirm()` des Update-Panels:
  - Update all: Liste der Tools, Text „Detonations, scans and uploads are paused while they run.“
  - Gepinntes Tool: Pin-Warnung.

  **Entscheidung:** Die übrigen `confirm()`-Aufrufe der App bleiben (YAGNI).

## Teil B: Tab „LOGS“

**Wunsch:**
- Ein eigener Reiter im Top-Menü.
- Er zeigt PowerShell-Logs, Access Logs, Netflows, Netzwerklogs und alle MCP-Aktionen.
- Er hat eine Suche wie in Splunk.

### Quellen

Jedes Ereignis wird einheitlich gespeichert: `{"id", "time" (ISO-8601 UTC), "source", "message", "fields": {...}}`.

| source | Inhalt | Herkunft |
|---|---|---|
| `powershell` | Script Blocks (4104), Module/Pipeline (4103), Engine-Start (4100 Fehler) | `Microsoft-Windows-PowerShell/Operational` über `wevtutil`. Mehrteilige 4104 (MessageNumber/MessageTotal) werden zu einem Ereignis zusammengesetzt. |
| `access` | Jede HTTP-Anfrage an das Web-UI (ohne `/static/`) | `after_request`: method, path, query, status, duration_ms, remote_addr, user_agent, client (`browser`/`mcp`/`other`) |
| `mcp` | Jede Aktion des MCP-Servers | Der MCP-Server sendet `X-TDC-Client: mcp` und `X-TDC-MCP-Tool: <name>`. Das Web-UI legt dafür zusätzlich ein `mcp`-Ereignis an (tool, method, path, status, duration_ms). |
| `netflow` | Verbindungen (Sysmon 3), zu Flows gebündelt | Schlüssel: image, pid, protocol, src/dst ip:port. Felder: count, first_seen, last_seen. |
| `dns` | DNS-Abfragen (Sysmon 22) | query, result, image, pid |
| `firewall` | Windows-Firewall-Log | `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log` (W3C): action, protocol, src/dst ip, ports, path |

**Entscheidungen:**
- **„Netzwerklogs“** sind `dns` und `firewall`. „Netflows“ sind die gebündelten Sysmon-3-Verbindungen.
- **PowerShell- und Firewall-Logging** sind heute aus. Ein neues Skript `scripts/configure-logging.ps1` schaltet ein:
  - Script Block Logging und Module Logging (`*`);
  - die Größe des PowerShell/Operational-Logs auf 256 MB;
  - Firewall-Logging für erlaubte und verworfene Pakete aller Profile, 32 MB.

  Ist die Firewall aus (`build-box-macos.sh`), bleibt das Log leer. Die Quelle zeigt dann `Firewall is off; no packets are logged.`
- **Speicher:**
  - Ein Ringpuffer pro Quelle, höchstens 50 000 Ereignisse insgesamt; die ältesten fallen zuerst heraus.
  - `access` und `mcp` werden zusätzlich als JSONL in `webui/logs/` geschrieben und beim Start geladen. Ab 10 MB wird rotiert, eine alte Datei bleibt.
  - Windows-Quellen werden beim Start der letzten 24 h neu gelesen (höchstens 5000 pro Quelle), danach alle 10 s inkrementell nach `EventRecordID`.
  - Das Firewall-Log wird ab dem letzten Offset gelesen.
- **Datenschutz:** Request-Bodies werden nie geloggt. Query-Strings schon; das Web-UI hat keine Zugangsdaten.

### Suche (Teilmenge von SPL)

**Suchteil:**
- **Wörter:** freie Wörter (Teilstring in `message` und allen Feldern, ohne Groß-/Kleinschreibung) und `"Phrasen"`. `*` ist ein Platzhalter.
- **Feldvergleiche:** `feld=wert`, `feld!=wert`, `feld>n`, `<`, `>=`, `<=`. Zahlen werden numerisch verglichen.
- **Verknüpfungen:** `AND` (implizit), `OR`, `NOT`, Klammern.
- **Aliase:** `source`, `sourcetype` und `index` meinen alle die Quelle.
- **Zeit:** `earliest=-15m` und `latest=now` mit den Einheiten `s`, `m`, `h`, `d`, `w`, oder ISO-8601.

**Pipes:**
- `| head N`, `| tail N`
- `| sort [-]feld[, …]`
- `| dedup feld[, …]`
- `| table f1, f2`, `| fields f1, f2`
- `| stats count|dc(f)|sum(f)|avg(f)|min(f)|max(f)|values(f) [as name], … [by f1, f2]`
- `| top [N] feld`, `| rare [N] feld`
- `| timechart span=1m count [by feld]`

**Grenzen und Fehler:**
- Ein Syntaxfehler gibt 400 mit `{"error": "<Text>", "pos": <Index>}`.
- Unbekannte Befehle: `Unknown command: <name>`.
- Höchstens 10 000 Treffer gehen in die Pipes. Die Antwort enthält höchstens 1000 Zeilen.

**Antwort:**
- `events` oder `table` (`columns`, `rows`);
- `count`, `took_ms`;
- `histogram` (Zeitbins der Treffer vor den Pipes);
- `fields`: pro Feld die 10 häufigsten Werte, für eine Seitenleiste wie in Splunk;
- `truncated`.

### Oberfläche

- **Reiter:** Der neue Reiter `LOGS` steht im Top-Menü direkt nach `SYSMON`. **Entscheidung:** Diese Position, weil die Inhalte verwandt sind.
- **Kopf:**
  - Suchfeld (monospace) mit Syntax-Highlighting light (Pipes und Felder farbig), Knopf `SEARCH`, Enter sucht.
  - Zeitwahl `15m`, `1h`, `4h`, `24h`, `7d`, `All`.
  - Beispiel-Suchen als Dropdown. Die letzten 10 Suchen stehen in `localStorage`.
- **Quellen:** Je Quelle ein Chip mit Anzahl und Status; ein Klick ergänzt `source=x`. Eine Quelle ohne Daten zeigt ihren Hinweis als Tooltip.
- **Zeitleiste:** Ein Histogramm der Treffer, nach Quelle gestapelt. Ziehen zoomt; dabei werden `earliest` und `latest` gesetzt.
- **Felder:** Eine Leiste links mit den Feldern und ihren Top-Werten. Ein Klick ergänzt `feld="wert"`.
- **Ergebnis:**
  - Ohne transformierende Pipe: eine Ereignisliste mit Zeit, Quelle und Text. Ein Klick klappt die Felder und den Rohtext auf, mit hervorgehobenen Suchwörtern.
  - Mit `stats`, `table`, `top` oder `timechart`: eine sortierbare Tabelle, bei `timechart` zusätzlich ein Diagramm.
- **Aktualisierung:** Ein Live-Schalter sucht alle 10 s erneut.
- **Sicherheit:** Alle Texte stammen potentiell von Malware, besonders PowerShell-Script-Blocks. Sie werden immer escaped.

### API und MCP

| Methode | Route | Zweck |
|---|---|---|
| GET | `/api/logs/search` | `q`, `earliest`, `latest`, `limit` |
| GET | `/api/logs/sources` | Pro Quelle: `count`, `last_time`, `status` (`ok`/`empty`/`unavailable`), `hint` |

MCP-Tool `tdc_logs_search(query, earliest="-24h", limit=100)`.

## Nicht-Ziele

- Keine Alarmregeln.
- Keine gespeicherten Suchen auf dem Server.
- Kein Export außer dem, was die Tabelle hergibt.
- Keine echten NetFlow/IPFIX-Collector.
- Keine Logs anderer Hosts.

## Anti-Ziele

- Eine Suche darf das Web-UI nicht blockieren. Sie läuft auf einer Kopie und gibt das Lock sofort frei.
- Ein Script Block mit HTML oder ANSI darf das Layout nicht brechen.
- Das Access-Log darf nicht durch das eigene Polling der Logs-Seite unbenutzbar werden. **Entscheidung:** `/api/logs/*` und die regelmäßigen Polls (`/api/status`, `/api/updates`, `/api/alerts`, `/api/health`) bekommen `fields.poll = true`. Die Standardsuche blendet sie mit `NOT poll=true` nicht aus, die Beispiel-Suche „Access without polling“ schon.
