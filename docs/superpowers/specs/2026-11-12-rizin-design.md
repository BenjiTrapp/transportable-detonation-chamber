# Rizin im Web-UI: Reverse Engineering direkt aus TDC

## Absicht

TDC zeigt eine Datei heute als Hex, als FileMap, mit PE/ELF-Analyse, capa und
DiE. Ghidra liegt zwar auf der VM, aber nur als Desktop-Programm. Der Nutzer
möchte Dateien direkt aus TDC heraus reversen, ohne auf der VM ein eigenes
Programm zu öffnen. Dafür soll TDC Rizin kapseln und im Web-UI bedienbar
machen.

**Wer es nutzt:** der Nutzer selbst, im Browser. Werkzeuge für Agenten über MCP
kommen später.

**Gewählt hat der Nutzer im Mockup** die Variante C in ihrer entzerrten Form A:
- Ansichten wie in Cutter, dazu eine Rizin-Konsole, und beide folgen einander;
- der Kontrollfluss-Graph steht neben dem Disassembly;
- Imports, Strings und Querverweise liegen als Reiter unten bei der Konsole.

## Ziele

1. **Neuer Tab „RIZIN“** (Oberfläche englisch). Aufbau von oben nach unten:
   - **Werkzeugleiste in einer Zeile:**
     - **OPEN ▾** mit den Quellen Submissions, Dumps, Upload und einem Pfad;
     - der Pfad der offenen Datei, Format, Architektur und Größe;
     - der SHA256, gekürzt, voll im Tooltip;
     - der Analyse-Status;
     - **SEEK** (Adresse, Funktions- oder Flag-Name), dahinter **GO** und **◀ ▶** für den Verlauf der Sprünge.
   - **Links FUNCTIONS:**
     - Name und Größe, die Adresse im Tooltip; filterbar;
     - die aktuelle Funktion ist markiert;
     - mit « klappt die Liste ein.
   - **Mitte, links:** die Reiter DISASSEMBLY, DECOMPILER und HEX für die aktuelle Funktion bzw. Adresse.
   - **Mitte, rechts:** GRAPH, der Kontrollfluss-Graph der aktuellen Funktion.
     - Der Block der aktuellen Adresse ist markiert.
     - Grün heißt Sprung, rot kein Sprung, ein unbedingter Übergang ist neutral.
     - Mit − + FIT wird gezoomt, Ziehen verschiebt den Ausschnitt.
     - **⇱** gibt einer Hälfte die ganze Breite.
     - Die Trennlinie zwischen den Hälften lässt sich ziehen.
     - Unter etwa 1400 px Fensterbreite werden Disassembly und Graph zu Reitern.
   - **Unten ein Bereich mit den Reitern CONSOLE, XREFS, STRINGS und IMPORTS:**
     - In der Höhe ziehbar und einklappbar.
     - XREFS zeigt die Querverweise zur aktuellen Adresse bzw. Funktion und von ihr weg.
     - STRINGS ist filterbar.
     - IMPORTS: Ein Klick auf einen Import zeigt seine Querverweise.
   - **Höhe:** Die Arbeitsfläche füllt die Fensterhöhe, jede Liste scrollt in sich.
2. **Ein Ort überall.**
   - Die aktuelle Adresse ist in allen Ansichten dieselbe: markiert im Disassembly, ihr Block im Graph, die passende Zeile im Decompiler, wo das geht, und die Konsole steht dort.
   - Ein Klick auf eine Funktion, einen Block, eine Adresse im Disassembly, einen Querverweis, einen String oder einen Import springt.
   - Ein Sprung in der Konsole (`s`, `pdf @ …`, `afn` …) bewegt die Ansichten mit. Die Eingabezeile zeigt die aktuelle Adresse (`[0x1400014b7]>`).
3. **Rizin-Konsole.**
   - Sie nimmt Rizin-Befehle an, die Ausgabe erscheint so, wie Rizin sie druckt: Farben im Theme, Sprungpfeile.
   - ↑ ↓ blättern im Verlauf, Tab ergänzt Befehle sowie Funktions- und Flag-Namen.
   - Darüber liegt eine Schnellwahl für häufige Befehle: `afl`, `pdf`, `pdg`, `iz`, `ii`, `axt`, `?`.
   - **Keine Shell:** Abgewiesen wird alles, was Programme startet, Dateien schreibt oder liest, die Sitzung verlässt oder die Rizin-Einstellungen gefährlich ändert.
     - Dazu gehören `!`, `|`, `>`, `>>`, Befehlsersetzung, `.`-Skripte, `#!`, Makros, Umgebungsvariablen, das Öffnen anderer Dateien und Debugging.
     - Rizin selbst kennt keine solche Sperre. In Rizin 0.9.1 gibt es weder `cfg.sandbox` noch einen Webserver.
     - Die Ablehnung nennt den Grund in einer Zeile.
4. **Sitzungen.**
   - Öffnen startet auf der VM eine Rizin-Sitzung für diese Datei, eine Datei pro Browser-Tab. Eine neu geöffnete Datei ersetzt die alte.
   - **Dieselbe Datei in einem zweiten Browser-Tab:** Die Sitzung wandert in den neuen Tab. Der alte zeigt „Open in another tab“ und einen Knopf, um sie zurückzuholen. So schreiben nie zwei Sitzungen in dasselbe Projekt.
   - **Analyse:** Sie startet sofort, mit sichtbarem Status. Bis etwa 20 MB ist es `aaa`, darüber `aa` mit einem Knopf für die volle Analyse.
     - Rizin läuft in Schritten, nämlich den Teilschritten von `aaa` (`aa`, `aac`, …). Zwischen zwei Schritten beantwortet die Sitzung wartende Anfragen. So zeigt der Tab schon, was bis dahin analysiert ist; der Status nennt den Schritt.
     - Während ein Schritt läuft, sagen Ansichten und Konsole „busy“ statt zu hängen.
     - Nach 10 Minuten hält die Analyse am nächsten Schrittende an, der Rest bleibt nutzbar, mit Hinweis.
     - Ein einzelner Schritt, der hängt, beendet die Sitzung. TDC startet sie neu mit den fertigen Schritten und sagt das. Einen Abbruch mitten im Schritt gibt es nicht, weil Rizin unter Windows dafür ein Konsolensignal bräuchte.
   - **Ende:** 30 Minuten ohne Nutzung beendet die Sitzung, ebenso das Schließen des Browser-Tabs. Höchstens drei Sitzungen laufen gleichzeitig; eine vierte schließt die am längsten unbenutzte.
   - **Zeitlimit:** Jeder Befehl hat eines. Eine Sitzung, deren Rizin nicht mehr antwortet, wird beendet, und die Oberfläche sagt das. Kein Befehl darf das übrige Web-UI blockieren.
5. **Dateien.**
   - Geöffnet werden kann, was TDC auf der VM ohnehin liest:
     - die Samples der Einreichungen (`C:\Users\Public\Downloads`);
     - die Speicher-Dumps (`C:\dumps`);
     - Uploads im Tab;
     - Pfade unter denselben Ordnern, die der Download erlaubt (`/api/file/download`).
   - Die Datei wird nur gelesen, nie verändert.
   - **„Open in Rizin“** erscheint dort, wo TDC den Pfad einer Datei auf der VM kennt: im Hex-Tab, in den Submit-Ergebnissen und im Submit-Verlauf, bei den Dump-Dateien und im ThreatScan-Verlauf, sofern die Datei noch da ist.
6. **Umbenennen und Kommentare.**
   - Funktionen umbenennen (`afn`) und Kommentare setzen (`CC`) geht per Rechtsklick auf eine Funktion, eine Adresse im Disassembly oder einen Block, und in der Konsole.
   - TDC speichert das als Rizin-Projekt in `webui/rizin_projects/<sha256>.rzdb` (git-ignoriert, wie `webui/memory_results/`), automatisch nach jeder Änderung. Ein Projekt entsteht nur, wenn man etwas umbenennt oder kommentiert, nicht für die Analyse allein. In die Ordner mit den Samples wird nichts geschrieben.
   - Öffnet man dieselbe Datei wieder, auch unter anderem Pfad, ist alles wieder da.
7. **Decompiler** über rz-ghidra (`pdg`).
   - Fehlt das Plugin, zeigt der Reiter „Decompiler not available (rz-ghidra missing)“ statt eines Fehlers.
8. **Große Dateien.**
   - Lange Funktionen lädt das Disassembly beim Scrollen nach.
   - Graphen mit mehr als etwa 200 Blöcken erscheinen als verkleinerte Übersicht ohne Befehlstext, mit Zoom in einen Ausschnitt.
   - Strings und Imports kommen seitenweise vom Server und werden auf dem Server gefiltert.
   - Die Konsole kürzt eine sehr lange Ausgabe (etwa 1 MB) und sagt das.
9. **Bereitstellung.**
   - Neues Skript `scripts/install-rizin.ps1`. Es lädt das Windows-Paket von Cutter (v2.5.0, `Cutter-v2.5.0-Windows-x86_64.zip`), prüft dessen SHA-256 gegen den Wert, den GitHub für die Release veröffentlicht, installiert das mitgelieferte `vc_redist.x64.exe` still, falls nötig, und entpackt nach `C:\tools\cutter`.
   - Das Paket enthält `rizin.exe` (Rizin 0.9.1), die rz-Werkzeuge und `lib/rizin/plugins/core_ghidra.dll` samt `rz_ghidra_sleigh`. Version passt also zu Plugin.
   - Am Ende prüft das Skript `rizin -v` und, mit `Lc`, dass das Ghidra-Plugin lädt.
   - Eingebunden wird es wie die anderen Install-Skripte (`Vagrantfile`, `Vagrantfile.utm`, `scripts/setup-macos-utm.sh`) und auf der laufenden VM einmal ausgeführt.
   - Rizin läuft auf der ARM64-VM als x64 unter Emulation, wie Aether und BeaconEye.
10. **Doku.**
    - README: Tab-Tabelle, ein Abschnitt zu Rizin, die API und das Install-Skript.
    - Dazu die Hilfe, die (i)-Texte und ein Screenshot `static/rizin.png` (Cyberpunk, 1920×960, echte Daten).

## Nicht-Ziele

- MCP-Werkzeuge für Agenten, also Reversing per Claude (später möglich).
- Debugging oder dynamische Analyse mit Rizin. Samples laufen weiter über die Detonation von TDC.
- Dateien patchen oder überhaupt verändern.
- Mehrere Dateien in einem Browser-Tab, gemeinsames Arbeiten mehrerer Nutzer an einer Sitzung.
- Ghidra selbst einbinden, Binärvergleich, ein eigener ARM64-Build von Rizin.
- Cutter als Programm. Das Paket liefert nur Rizin und das Plugin.

## Anti-Ziele (Misserfolg, auch wenn es technisch läuft)

- Über die Konsole lässt sich ein Programm auf der VM starten oder eine Datei schreiben. Das Web-UI läuft dort als SYSTEM und hat keinen Login.
- Ein Name, String oder Kommentar aus einer Datei wird im Browser als HTML oder JavaScript ausgeführt. Malware bestimmt diese Texte.
- Eine lange Analyse oder ein hängender Befehl friert das Web-UI ein.
- Sitzungen bleiben liegen und füllen den Speicher der VM.
- Ein Sample wird auf der Platte verändert.
- Die Oberfläche wird wieder gedrungen. Funktionsnamen und Befehle müssen bei 1920 px lesbar bleiben.
- Konsole und Ansichten zeigen verschiedene Orte, ohne dass man es merkt.

## Rahmenbedingungen

- **Server:** Flask-App `webui/app.py` auf der VM. Die Logik der Sitzungen kommt in ein eigenes Modul (z. B. `webui/rizin_sessions.py`), die Routen unter `/api/rizin/...`.
  - Rizin wird mit `-q0` (Pipe-Modus) und `-N` (keine Nutzer-Einstellungen) gestartet, ohne `-w`, mit `scr.interactive=false` und leerem `scr.pager`.
  - Für die Konsole kommen Farben in ANSI, für die Ansichten JSON ohne Farbe.
- **Frontend:** Vanilla JS in `webui/static/js/app.js`, keine Bibliothek, Funktionen auf oberster Ebene, SVG für den Graphen, gezeichnet wie die Diagramme.
- **Farben:**
  - nur als `var(--…)`;
  - `style.css` mit Farbwerten nur in `:root`;
  - `theme-cyberpunk.css` nur unter `[data-theme="cyberpunk"]`.
- **Classic** ändert sich nur durch den neuen Tab und die „Open in Rizin“-Knöpfe.
- **Escaping:** Alles, was aus Rizin kommt (Namen, Strings, Kommentare, Disassembly, Konsole), wird escaped oder als `textContent` gesetzt. ANSI wird in Spans mit Theme-Klassen übersetzt, nie roh eingefügt. Klicks laufen über delegierte Handler, die Adressen aus `data-`-Attributen lesen.
- **Sicherheit:** Die CSRF- und Host-Header-Schutzmechanismen gelten auch für die neuen Routen, es gibt keinen Login. Der Konsolen-Filter steht auf dem Server, nicht nur im Browser.
- **Tests:**
  - Die CI kennt kein Rizin. Die Server-Tests laufen gegen eine nachgebaute Rizin (ein kleines Skript, das den `-q0`-Pipe-Modus mit festen Antworten spielt).
  - Die Tests des Filters prüfen eine Liste von Angriffs-Eingaben.
  - Das Frontend wird mit Node-Tests in `tests/` geprüft, wie die Diagramme (`_function_source`, `_run_node`).
  - Die CI läuft mit Node 20 unter `TZ=UTC` und `TZ=Europe/Berlin`.
- **Sonstiges:**
  - Englische Oberfläche und README.
  - Asset-Versionen in `index.html` bei jeder Änderung an CSS oder JS erhöhen.
  - Den gesperrten Fremdnamen aus den Projektregeln nirgends verwenden.
  - Name und Adresse der internen Referenzseite kommen nie ins Repo.
- **Prüfung auf der VM** (UTM, 192.168.64.4):
  - beide Themes, bei 1920 und 1280 px;
  - echte Eingaben über CDP;
  - ein eigenes Chrome mit frischem Profil, nie an einen laufenden Debugging-Port hängen;
  - Deploy mit `scripts/deploy-utm.py`.

## Ansätze

1. **Rizin-Sitzungen im Web-UI, eigene Ansichten (gewählt).**
   - Der Flask-Server startet je geöffnete Datei einen Rizin-Prozess, wie heute schon capa und andere Werkzeuge.
   - JSON-Schnittstellen liefern die Ansichten, ein Konsolen-Endpunkt trägt den Filter.
   - Der Browser zeichnet alles selbst, passend zu Themes und Tabs.
   - *Kosten:* Funktionsliste, Disassembly und die Anordnung der Graph-Blöcke sind eigener Code.
2. **Cutter auf der VM, im Browser per Fernbild (verworfen).**
   - Man hätte sofort die ganze Oberfläche.
   - Dafür braucht es einen VNC-Server mit Browser-Anbindung, Cutter hat nicht das Aussehen von TDC, und es gibt keine Verbindung zu den Tabs.
   - Cutters Konsole lässt eine Shell zu, und die ist dort nicht zu sperren.
3. **Rizin im Browser als WebAssembly (verworfen).** Die Samples müssten die VM verlassen.

*Rizins eingebauter Webserver kam nicht in Frage:* Rizin 0.9.1 hat keinen.

## Gestaltung

- **Vorlage:** Variante A in
  `.superpowers/brainstorm/14564-1794468004/content/rizin-roomy-v4.html`
  (lokal, git-ignoriert).
  - Die Farben des Disassembly folgen `rizin-ui-v2.html`: Adressen cyan, `call` pink, Sprünge grün, Symbole und Strings gelb, Kommentare gedämpft.
  - Die Daten dort sind echte Rizin-0.9.1-Ausgaben für `pipesim.exe`.
- **Cyberpunk** wie im Mockup.
- **Classic:** gleicher Aufbau in den Classic-Variablen, monospaced wie der Hex-Tab.

## Dem Builder überlassen

- Ob die Pipe über das Paket `rzpipe` (0.6.2) oder eine eigene Umsetzung des `-q0`-Protokolls läuft. Pflicht sind dabei ein Zeitlimit für jeden Befehl und das Beenden einer hängenden Sitzung.
- Der genaue Algorithmus für die Anordnung des Graphen: geschichtet, ohne überlappende Blöcke, Kanten mit wenigen Kreuzungen.
- Die genaue Liste erlaubter und abgewiesener Befehle innerhalb der Regel oben, mit Tests.
- Seitengrößen, die Kürzung der Konsole und die genauen Grenzwerte innerhalb der genannten Größenordnung.
- Wie die Sitzungs-ID im Browser gehalten wird und wie das Schließen des Tabs gemeldet wird.
- Ob HEX die Bytes selbst zeigt oder in den Hex-Tab an die Stelle springt.

## Entscheidungen des Assistenten (zur Prüfung)

- Die Installation über das Cutter-Paket statt über das Rizin-Paket, damit Rizin und rz-ghidra sicher zusammenpassen.
- Die Konsole ohne Shell, mit einem Filter auf dem Server.
- Nur statische Analyse, kein Debugging.
- Eine Datei pro Browser-Tab, höchstens drei Sitzungen gleichzeitig, Ende nach 30 Minuten ohne Nutzung.
- Dieselbe Datei in einem zweiten Tab übernimmt die Sitzung, der alte Tab kann sie zurückholen. Damit gehen keine Umbenennungen verloren.
- Die Analyse läuft in Schritten, und dazwischen ist der Tab benutzbar. Bei 10 Minuten hält sie am nächsten Schrittende an; ein hängender Schritt startet die Sitzung neu. Kein Abbruch mitten im Schritt.
- `aaa` bis etwa 20 MB, darüber `aa` mit einem Knopf.
- Projekte unter `webui/rizin_projects/<sha256>.rzdb`, nur bei Umbenennungen oder Kommentaren, automatisch gespeichert.
- „Open in Rizin“ im Hex-Tab, bei Submit, bei Dumps und im ThreatScan-Verlauf.
- Unter etwa 1400 px werden Disassembly und Graph zu Reitern; ab etwa 200 Blöcken zeigt der Graph eine Übersicht.
