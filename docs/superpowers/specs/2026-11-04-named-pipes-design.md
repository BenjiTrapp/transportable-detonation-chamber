# Named Pipes: Beobachten und gezielt Abfangen

## Absicht

Bei einer Detonation soll sichtbar werden, was das Sample über Named Pipes
tut, und ob das nach Beacon- oder Malware-Verhalten aussieht: Cobalt-Strike-
SMB-Beacons, Post-Exploitation-Jobs (`postex_*`), PsExec-artige Remote-
Ausführung, Credential-Dumper, eigene IPC zwischen Sample-Prozessen.
Zusätzlich soll man eine interessante Pipe gezielt abfangen können, um ihre
Inhalte zu sehen und bei Bedarf zu verändern (Vorbild: pipe-intercept).

## Ziele

1. **Beobachten (A), bei jeder Detonation automatisch und passiv:**
   - Welche Pipes das Sample und seine Kindprozesse anlegen (EID 17) und
     öffnen (EID 18), und welche anderen Prozesse sich mit vom Sample
     angelegten Pipes verbinden.
   - Abgleich der Pipe-Namen mit bekannten Mustern von C2-Frameworks und
     Tools; Treffer werden benannt ("Cobalt Strike default post-ex pipe").
   - Pipe-Beziehungen als Kanten im Prozessgraphen (alle drei Layouts).
   - Die Funde fließen ins bestehende Evidenz-Modell und damit ins
     Gesamturteil; sie können Memory-Funde bestätigen und umgekehrt.
2. **Abfangen (B), manuell auf Knopfdruck:**
   - Für eine Pipe (Name aus A übernommen oder frei eingegeben) einen Proxy
     starten: Client → Proxy → echter Server.
   - Nachrichten beider Richtungen live im Browser, als Hex + ASCII.
   - Modus "beobachten" (durchreichen und mitschneiden) und Modus "anhalten"
     (jede Nachricht wartet, kann bearbeitet, weitergereicht oder verworfen
     werden).
   - Mitschnitte bleiben gespeichert und sind exportierbar.

## Nicht-Ziele

- Kein automatisches Abfangen während normaler Detonationen (verfälscht das
  Verhalten des Samples).
- Kein Abfangen von Pipes auf anderen Rechnern; nur lokal auf der VM.
- Keine Protokoll-Dekodierung (SMB-Beacon-Frames, RPC/NDR) in der ersten
  Version; Rohdaten genügen.
- Kein Burp/WebSocket-Umweg; alles im eigenen Tab.

## Anti-Ziele (wäre ein Misserfolg, auch wenn es technisch läuft)

- A verändert das Verhalten des Samples oder macht sich für Anti-Analyse
  bemerkbar.
- Sysmon flutet das Log mit Pipe-Events von Browsern und Systemdiensten, so
  dass die Ereignisse des Samples nicht mehr in die Abfragefenster passen
  (die UI liest gezielt per XPath, aber das Log hat eine Maximalgröße).
- Bekannte, harmlose Windows-Pipes (z. B. `\lsass`, `\ntsvcs`, Chrome-Mojo)
  erzeugen Falsch-Alarme im Urteil.
- Ein vergessener Proxy blockiert eine Systempipe dauerhaft.

## Rahmenbedingungen (Stand des Projekts)

- Die VM-Sysmon-Konfiguration ist SwiftOnSecurity `sysmonconfig-export.xml`
  (`scripts/install-sysmon.ps1`). Deren `PipeEvent` ist im **include**-Modus
  mit einer Namensliste → aktuell 0 Pipe-Events im Log. Für A muss die
  Konfiguration angepasst werden.
- Sysmon-Events liest die Web-UI über `_read_sysmon_events` (wevtutil +
  XPath); EID 17/18 werden dort noch nicht strukturiert ausgewertet.
- Prozesse sind Instanzen (`<pid>` / `<pid>@<start>`); Events werden über
  `_PidInstances.resolve` der zur Zeit laufenden Instanz zugeordnet. Pipe-
  Events müssen denselben Weg gehen.
- Detonations-Zuordnung über Submission-Zeitfenster + Kindprozesse
  (`build_process_tree`, `_agent_detonation_index`).
- Evidenz-Modell: `webui/memory_evidence.py` (`KINDS`, `MemoryFinding`,
  `score`, `collect`). Bestätigung zwischen Quellen ist dort schon gelöst.
- Kein Login, CSRF- und Host-Schutz aktiv; die Web-UI läuft als SYSTEM.
- Keine neuen schweren Abhängigkeiten; Win32-Aufrufe bisher über `ctypes`.
- Tests unter `tests/`, Doku-Abgleich-Tests erzwingen README/Hilfe für jede
  neue Route und jedes neue MCP-Tool.
- ARM64-VM: Samples laufen meist emuliert als x64. Pipes sind ein
  Kernel-Objekt, die Architektur spielt für A und B keine Rolle.

## Ansätze

| | Ansatz | Abwägung |
|---|---|---|
| **A** | Passiv über Sysmon EID 17/18 | kein Eingriff, sieht Namen und Beteiligte, keine Inhalte |
| **B** | A + Proxy-Abfangen auf Knopfdruck (pipe-intercept-Prinzip) | sieht und ändert Inhalte; Pipe-Name nötig, Wettlauf um die erste Verbindung, kann Sample stören |
| C | A + Mitschnitt im Sample-Prozess (Frida/API-Hooks) | alle Inhalte ohne Wettlauf, aber Eingriff ins Sample, auffällig, aufwendig unter x64-Emulation |

**Gewählt (vom Nutzer): A und B.** C entfällt.

## Entscheidungen zum Wie

### A – Beobachten

- **Sysmon-Konfiguration** *(meine Entscheidung)*: `PipeEvent` auf
  **exclude**-Modus umstellen, d. h. alle Pipe-Events protokollieren außer
  einer Liste bekannter, sehr häufiger, harmloser Pipes (Browser-Mojo-Pipes,
  `\PSHost.*` der Web-UI-eigenen PowerShell-Aufrufe, typische Systemdienste).
  Umsetzung als Nachbearbeitung der heruntergeladenen SwiftOnSecurity-Datei
  in `install-sysmon.ps1`, damit der Rest der Konfiguration unverändert
  bleibt; Anwenden über `Sysmon -c`. Sysmon-Logmaximum prüfen und ggf.
  erhöhen.
- **Muster-Katalog** *(meine Entscheidung)*: eine Datei
  `webui/pipe_signatures.json` mit Name, Familie, Muster (Präfix/Regex) und
  Gewicht; Startbestand aus öffentlich dokumentierten Defaults (Cobalt
  Strike, Sliver, Metasploit, Covenant, PsExec/PAExec/RemCom/CSExec,
  Credential-Dumper; die Liste aus der SwiftOnSecurity-Konfiguration dient
  als Quelle). Erweiterbar ohne Codeänderung.
- **Merkmale, die ohne Musterliste auffallen** *(meine Entscheidung)*:
  - Sample legt eine Pipe an, mit der sich ein *anderer* Prozess verbindet
    (Kommunikation zwischen Prozessen, z. B. Beacon ↔ injizierter Job).
  - Sample verbindet sich mit einer Pipe eines Systemprozesses, die für
    Lateral Movement/Credential-Zugriff bekannt ist (`\svcctl`, `\lsarpc`,
    `\samr`) – als Hinweis, nicht als Beweis.
  - Zufällig aussehende Pipe-Namen (hohe Entropie / GUID-artig) vom Sample.
- **Evidenz**: neue `KINDS` in `memory_evidence.py`, Quelle
  `sysmon-pipes`; bekannter C2-Default stark und eigenständig, die übrigen
  Merkmale schwach und auf Bestätigung angewiesen. Baseline-fähig, damit
  harmlose Pipes des Hosts unterdrückt werden.
- **Baseline für Pipes** *(meine Entscheidung)*: kein eigener Capture-Knopf.
  Die bestehende Funktion "Sweep as baseline" nimmt zusätzlich alle Pipe-
  Namen auf, die Sysmon im letzten Zeitfenster (Standard 30 min) gesehen hat,
  in dieselbe Baseline-Datei. Zufällige Namensteile (Hex/GUID/Zahlen) werden
  vor dem Schlüssel normalisiert (`status_4a3f` → `status_*`), damit Läufe
  übereinstimmen; ein Muster aus dem C2-Katalog wird nie durch die Baseline
  unterdrückt.
- **Umfang der Pipe-Daten** *(meine Entscheidung)*: Pipe-Knoten im Graphen
  nur für die Prozesse des ausgewählten Teilbaums, per gezielter XPath-
  Abfrage auf deren PIDs und Zeitfenster; der Toggle "Pipes" ist
  standardmäßig an bei Detonationen und aus bei anderen Prozessen.
  `/api/pipes` filtert standardmäßig auf die letzte Stunde.
- **Anzeige**:
  - Abschnitt "Named Pipes" in den Detonations-Ergebnissen (Submit-Tab und
    Detailansicht): Tabelle Zeit, Prozess, Aktion (angelegt/verbunden),
    Pipe-Name, Treffer; Knopf "Abfangen" je Pipe (→ B).
  - Prozessgraph: Pipe als eigener Knotentyp (wie DNS/Netzwerk) mit Kanten
    "erstellt"/"verbunden"; ein Toggle "Pipes" in der Toolbar; in der
    Isometrie als Aktivitätssymbol + Brücke zwischen zwei Prozessen, die
    über dieselbe Pipe sprechen.
  - Neuer Tab **Pipes** mit zwei Bereichen: Liste der jüngsten Pipe-Events
    (filterbar) und die Abfang-Sitzungen aus B.
- **API/MCP**: `/api/pipes` (Events, Filter PID/Instanz/Zeit/Name),
  Pipe-Daten in `/api/detonation/results` und `/api/process-graph`;
  MCP-Tool `tdc_pipes`.

### B – Abfangen

- **Prinzip wie pipe-intercept**: Der Proxy legt zusätzliche Server-
  Instanzen der Ziel-Pipe an; verbindet sich ein Client, öffnet der Proxy
  selbst eine Verbindung zum echten Server und reicht Nachrichten in beide
  Richtungen durch. Implementierung in Python über `ctypes`
  (`CreateNamedPipeW`, `ConnectNamedPipe`, `CreateFileW`, Overlapped-I/O),
  im Web-UI-Prozess als Hintergrund-Threads *(meine Entscheidung; keine neue
  Abhängigkeit, läuft als SYSTEM mit den nötigen Rechten)*.
- **Zwei Arten, eine Sitzung zu starten (vom Nutzer gewählt):**
  1. **Anhängen** an eine bestehende Pipe (exakter Name): Der Proxy legt
     zusätzliche Instanzen neben denen des echten Servers an. Für den
     schnellen Blick in laufende Kommunikation; der Knopf "Abfangen" in A
     startet diese Art und ist nur aktiv, solange die Pipe existiert.
  2. **Scharf schalten mit Muster** (exakter Name, Präfix oder Regex, z. B.
     `postex_*`, `msagent_*`), typischerweise vor einer (erneuten)
     Detonation. Ein Beobachter erkennt neue passende Pipes sofort (Sysmon
     EID 17 reicht als Auslöser nicht, da es nachträglich protokolliert;
     der Beobachter fragt die Pipe-Liste `\\.\pipe\` in kurzen Abständen
     ab oder nutzt eine schnellere Quelle – dem Umsetzenden überlassen).
     Sobald eine passende Pipe auftaucht, hängt sich der Proxy an. Optional
     "Namen besetzen": Der Proxy legt bei einem exakten Namen die erste
     Instanz selbst an, bevor der echte Server startet, und verbindet sich
     zum echten Server, sobald dieser seine Instanz anlegt. Das greift
     stärker ein (Server mit `FILE_FLAG_FIRST_PIPE_INSTANCE` scheitern) und
     ist deshalb ausdrücklich abzuwählen, nicht Standard.
  Variante "exakter Name vor der Detonation" ist Art 2 mit exaktem Muster.
- Byte- und Message-Modus der Ziel-Pipe übernehmen
  (`GetNamedPipeInfo`/`GetNamedPipeHandleState` am echten Server).
- **Bedienung im Tab Pipes**: Sitzung starten (Pipe-Name, Modus, maximale
  Dauer), Nachrichtenliste live (Polling wie im Rest der UI), Hex/ASCII-
  Ansicht, im Modus "anhalten" Bearbeiten im Hex-Editor-Stil, Weiterreichen,
  Verwerfen, "alles durchlassen". Sitzung beenden.
- **Schutz vor Schäden**:
  - Jede Sitzung hat eine maximale Dauer (Standard 10 min) und endet von
    selbst; angehaltene Nachrichten werden nach einem Timeout automatisch
    weitergereicht, damit Prozesse nicht hängen.
  - Beim Neustart der Web-UI werden keine Sitzungen wiederaufgenommen.
  - Eine kurze Sperrliste kritischer Systempipes, die nicht abgefangen
    werden dürfen (z. B. `\lsass`, `\ntsvcs`, `\protected_storage`).
  - Grenzen für Nachrichtengröße und Mitschnittumfang pro Sitzung.
- **Speicherung**: Mitschnitte als Datei je Sitzung (wie
  `memory_results/`), Export als JSON/rohe Bytes.
- **API/MCP**: `/api/pipes/intercept` (starten/stoppen/Status),
  `/api/pipes/intercept/<id>/messages` (lesen, Aktionen für angehaltene
  Nachrichten). MCP: Sitzungen lesen ja; starten und Nachrichten verändern
  vorerst nicht per MCP *(meine Entscheidung, analog zum Hex-Schreiben)*.
- Bekannte Grenzen werden im Tab und im README genannt: Pipe-Name muss
  bekannt sein; die erste Verbindung kann am Proxy vorbeigehen; Programme,
  die die Gegenseite prüfen (PID, Benutzer) oder `FILE_FLAG_FIRST_PIPE_
  INSTANCE` nutzen, funktionieren evtl. nicht.

## Dem Umsetzenden überlassen

- Genaue Ausschlussliste für Sysmon und Startbestand des Musterkatalogs.
- Gewichte der neuen Evidenz-Arten (an bestehenden Arten orientieren).
- Darstellung der Pipe-Knoten im Graphen im Detail.
- Polling-Intervall und Seitengröße für Live-Nachrichten.
- Tests: Parser für EID 17/18, Zuordnung zu Instanzen, Muster, Evidenz,
  Proxy-Logik mit simuliertem Pipe-Paar (unter Windows) bzw. gemockten
  Win32-Aufrufen (in CI), Doku-Abgleich.
