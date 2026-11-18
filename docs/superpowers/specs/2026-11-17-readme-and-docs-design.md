# Entwurf: README als Schaufenster, Doku als Führung, Wiki als eine Datei

Datum: 2026-11-17 · Status: Entwurf zur Freigabe

## Warum

Die README ist auf 2.203 Zeilen gewachsen und ist heute drei Dinge auf einmal: Schaufenster,
Handbuch und Referenz. Wer das Werkzeug zum ersten Mal sieht, muss an der API-Referenz, der
Dateistruktur und dem Troubleshooting vorbeiscrollen, bevor klar wird, was es kann. Wer damit
arbeitet, sucht die Anleitung zwischen Werbung und Tabellen.

Dazu drei Dinge, die ins Auge fallen:

1. **Drei ASCII-Zeichnungen** tragen die Architektur, den Dateibaum und die VM-Pfade. Die Architektur
   als Kasten-Grafik ist in jedem Editor anders breit und sagt weniger, als ein Diagramm sagen könnte.
   Abläufe — Detonation, Verdict-Bildung, Rizin-Sitzungen — stecken als Nummernlisten im Text.
2. **Die Hilfe im Web-UI** ist eine dritte Stelle mit Overview, Usage Guide, API, Architektur und
   Services. Sie ist knapp und bleibt, aber sie führt nicht.
3. **Auf der VM gibt es kein Netz.** Wer dort arbeitet, hat weder GitHub noch eine Doku-Seite.

## Ziele

1. **README als Schaufenster**, etwa 400 Zeilen: Logo, Kurzbeschreibung, die zwei Theme-Bilder und
   das Demo-Video, acht bis zehn Features mit je einem Satz und einem Bild, das Architektur-Diagramm
   als Mermaid, die Dienste-Tabelle, die Tab-Tabelle, Quick Start in beiden Varianten,
   Plattform-Hinweise, Security Notes, Credits — und Wege in die Doku.
2. **`docs/` als Führung**: eine Seite je Thema, zwei Leserwege („Ich will es aufsetzen",
   „Ich will damit arbeiten"), Beispiele und Bilder an der Stelle, an der man sie braucht.
   Mermaid-Diagramme für die vier Abläufe, die heute Prosa sind.
3. **`make docs` baut ein Wiki**: eine einzige, in sich geschlossene HTML-Datei mit Navigation,
   Suche, eingebetteten Bildern und gerenderten Diagrammen, die ohne Netz funktioniert — auf dem
   Mac und auf der VM. Das Web-UI verlinkt sie, wenn sie da ist.
4. **Die Doku-Tests ziehen mit**: Die API-Zeilen und die Rizin-Sätze werden künftig in der Doku
   geprüft, die Tab-Tabelle bleibt in der README, und kein Bild verwaist.

## Nicht-Ziele

- **Kein neuer Inhalt.** Beschrieben wird, was es gibt; nichts wird dazuerfunden und nichts
  stillschweigend weggelassen. Was heute in der README steht, steht danach entweder dort oder in der
  Doku.
- **Keine Doku-Website**, kein Publizieren in der CI, kein GitHub Pages, keine Versionierung der
  Doku.
- **Keine Übersetzung.** README, Doku und Wiki sind englisch, wie die Oberfläche.
- **Die Hilfe im Web-UI wird nicht ersetzt.** Sie bleibt, wie sie ist, und bekommt nur einen Weg zum
  Wiki.
- **Kein Umbau der Entwurfs- und Plan-Dateien** unter `docs/superpowers/`.
- **Der Dateibaum bleibt eingerückter Text.** Als Diagramm liest er sich schlechter.
- **Kein Mermaid für Mermaids willen.** Vier bis sechs Diagramme, jedes für einen Ablauf, den Prosa
  schlecht trägt.

## Anti-Ziele

Daran wäre die Arbeit gescheitert, auch wenn sie technisch läuft:

- **Zwei Quellen, die auseinanderlaufen.** Das Wiki ist erzeugt, nie von Hand gepflegt.
- **Ein Wiki, das veraltet, ohne dass es auffällt.** Es trägt den Stand, aus dem es gebaut wurde.
- **Die README verliert, was sie verkauft.** Bilder, Features und Quick Start bleiben vorn.
- **Ein Build, den niemand ausführen kann.** `make docs` läuft ohne Netz, ohne npm und ohne Node.
- **Tests, die nichts mehr festhalten.** Nach dem Umzug prüfen sie dieselben Zusagen an der neuen
  Stelle, nicht weniger.
- **Ein Wiki, das auf der VM nicht aufgeht,** weil es von einem CDN lädt.

## Randbedingungen

- **Bestand.** 30 PNGs in `static/` (9,1 MB) und `static/demo.gif` (10 MB). Die README nennt heute
  alle PNGs; ein Test verlangt, dass jedes benutzt wird und keines fehlt.
- **Doku-Tests heute** (`tests/test_docs.py`): jede `/api/`-Route genau eine README-Zeile der Form
  `| GET | `/api/x` | … |`; die Tab-Tabelle unter `### Web UI Tabs` gleich der Reihenfolge der
  Oberfläche; jeder `<h4>` im Usage Guide der Hilfe gleich derselben Liste; jedes Bild benutzt und
  vorhanden; die MCP-Werkzeuge vollständig samt `(N tools`; die Rizin-Zeilen sagen, was der Server
  antwortet; jedes `webui/*.py` in allen drei Deploy-Wegen.
- **Mermaid** rendert GitHub in ```mermaid-Blöcken von selbst. Im Wiki gibt es kein Netz, also muss
  der Renderer mitkommen (siehe „Das Wiki").
- **Die VM** hat kein Netz und Python 3.9; alles, was dort läuft, bleibt 3.9-verträglich.
- **Repo-Regeln:** englische Doku; keine lokalen Pfade; kein Name der früheren Vergleichs-Software
  des Hex-Editors und keine interne Referenz-Seite; `.gitignore` für erzeugte Dateien; neue
  `webui/*.py` über alle drei Deploy-Wege.
- **Das Wiki ist ein Erzeugnis**, kein Quelltext: nicht eingecheckt, sondern gebaut.

## Wege

**Weg A — nur Markdown unter `docs/`.** README verkauft, `docs/*.md` führt, GitHub rendert Mermaid.
*Preis:* Wer offline auf der VM sitzt, liest rohes Markdown; keine Suche, keine Führung.

**Weg B — Markdown plus erzeugtes Wiki (gewählt).** Dasselbe wie A, dazu ein Generator, der aus den
Markdown-Dateien eine einzelne HTML-Datei baut: Navigation, Suche, Beispiele, eingebettete Bilder.
*Preis:* ein Generator mehr im Repo, und das Wiki muss neu gebaut werden, wenn sich die Doku ändert.

**Weg C — Wiki von Hand als HTML.** Volle Kontrolle über Führung und Layout.
*Preis:* zwei Quellen für denselben Inhalt; eine läuft der anderen hinterher, und die Doku-Tests
können HTML schlecht festhalten.

**Gewählt: Weg B.** Eine Quelle, auf GitHub lesbar, und trotzdem eine geführte Oberfläche mit
Bildern, die auch ohne Netz aufgeht.

## 1. Die README danach

Reihenfolge und Inhalt:

| Abschnitt | Was drin steht |
|---|---|
| Kopf | Logo, ein Satz, die Badges wie heute |
| Bilder | die zwei Theme-Bilder, das Demo-Video (verlinkt, nicht eingebettet) |
| **What it does** | acht bis zehn Features, je eine Zeile und ein Bild: Detonation mit Verdict, Alerts mit Drilldown, Tracing, Prozess-Graph, Named Pipes, Sysmon und ETW, ThreatScan, Hex und File Map, Rizin, LOGS mit eigenen Dashboards |
| **Architecture** | das Mermaid-Diagramm (Diagramm 1) und die Dienste-Tabelle |
| **Web UI Tabs** | die Tabelle wie heute (ein Test hängt daran) |
| **Quick Start** | beide Varianten, je drei bis fünf Zeilen, dann ein Weg in die Doku |
| **Platform support** | die Kurzfassung: was auf ARM64 anders ist |
| **Documentation** | die Karte der Doku: je eine Zeile pro Seite, dazu „Wiki bauen: `make docs`" |
| Security Notes, Credits, License | wie heute |

Alles andere zieht um. Die Doku-Karte ist der einzige neue Abschnitt.

## 2. Die Doku

`docs/` bekommt eine Index-Seite und dreizehn Seiten. Die Index-Seite führt die zwei Leserwege:

- **Set it up:** `setup.md` → `installation.md` → `configuration.md`
- **Work with it:** `workflow.md` → die Werkzeugseiten → `api.md`

**Entscheidung:** Die README ist **keine** Seite des Wikis. Das Wiki ist die Führung, die README das
Schaufenster; wer auf der VM liest, braucht kein Schaufenster, sondern die Anleitung. Damit nichts
doppelt gepflegt wird, beginnt `docs/README.md` mit einem Absatz, was die Chamber ist, und verweist
für Bilder und Features auf die README im Repository. Quick Start steht ohnehin ausführlich in
`installation.md`.

| Seite | Woher | Inhalt |
|---|---|---|
| `docs/README.md` | neu, dazu Detection Engines | die zwei Leserwege, die Seitenliste mit je einem Satz, Diagramm 1, die Engines und die Dienste-Tabelle |
| `setup.md` | Prerequisites, Platform Support | Voraussetzungen je Host, ARM64, die VM anlegen |
| `installation.md` | Installation, Quick Start (Langfassung) | `make`/`make.ps1`, Provisionierung, manuell |
| `configuration.md` | Configuration, Detection Rules | Umgebungsvariablen, eigene Sigma- und YARA-Regeln, Sysmon, Defender |
| `workflow.md` | Usage | Detonation (Diagramm 2), CLI, Scanner, PE- und ELF-Analyse, HSB |
| `memory.md` | Live Memory Analysis | was nach einer Detonation läuft, Diagramm 3 (Verdict), Grenzen |
| `pipes.md` | Named Pipes | Beobachtung, Interception, Grenzen |
| `rizin.md` | Rizin | Öffnen, Ansichten, Konsole, Sitzungen (Diagramm 4), Projekte, Installation, Grenzen |
| `logs.md` | Logs | die sechs Quellen, die Suchsprache, eigene Dashboards |
| `updates.md` | Tool Updates | was geprüft wird, Pins, Wartungsmodus, Skripte |
| `web-ui.md` | Features (Charts, ETW, Binary Analysis), Themes, Demo | die Tabs im Detail, die Themes, die Bildergalerie |
| `api.md` | API Reference, MCP Server | alle Routen und alle MCP-Werkzeuge (die Tests ziehen hierher) |
| `development.md` | Tests, Developer Experience | die Test-Abteilungen, `make`-Ziele, Dev-Server, CI |
| `troubleshooting.md` | Troubleshooting, File Structure, VM File Layout | Diagnose, Dateibaum, VM-Pfade |

Jede Seite beginnt mit einem Satz, was sie beantwortet, und endet mit „Weiter:" und einem Link.

## 3. Die Mermaid-Diagramme

Vier, jedes ersetzt etwas, das heute Prosa oder ASCII ist:

1. **Architektur** (`flowchart`): Host (Browser, MCP, make) → Web UI :9000 → DetonatorAgent,
   LitterBox, die Detection-Engines, die Memory-Scanner. Ersetzt die Kasten-Grafik. In README und
   `docs/README.md`.
2. **Detonationskette** (`flowchart` von links nach rechts): Einreichen → Exit-Capture armieren →
   ausführen → PID → Engines und Scanner parallel → Ergebnisse. Ersetzt die siebenteilige
   Nummernliste in „Data Flow". In `workflow.md`.
3. **Verdict-Bildung** (`flowchart`): ein Memory-Fund → Persistenz, Bestätigung, Host-Baseline → mit
   EDR-Alarmen und LitterBox → der gemeinsame Verdict. In `memory.md`.
4. **Rizin-Sitzung** (`stateDiagram-v2`): offen → Analyse (aaa oder aa) → benutzbar → übernommen von
   einem anderen Tab, beendet nach 30 Minuten, beendet bei `pagehide`. In `rizin.md`.

Jedes Diagramm hat darunter zwei bis drei Sätze, die es in Worten sagen — für jeden, der kein
Mermaid gerendert bekommt.

## 4. Das Wiki

**`make docs` → `webui/static/wiki.html`** (git-ignoriert), eine Datei, die ohne Netz aufgeht — auch
als lose Datei im Browser (`open webui/static/wiki.html`), nicht nur über den Server. Deshalb kein
ES-Modul und kein `fetch` im Wiki.

**Wo es gebaut wird (Entscheidung):** auf dem Host, nicht auf der VM. `make docs` auf macOS und
Linux, `.\make.ps1 docs` auf Windows — der Generator ist reines Python, also können beide Hosts es.
Die VM bekommt die fertige Datei über die drei Deploy-Wege, wenn sie existiert; sie baut nichts.
Trotzdem bleibt der Generator mit Python 3.9 verträglich, wie alles im Repo, das auf der VM landen
könnte.

**Generator:** `scripts/build-wiki.py`, Python 3.9, nur Standardbibliothek. Er liest `docs/*.md` in
der Reihenfolge, die `docs/README.md` vorgibt, und schreibt eine HTML-Datei mit:

- **Navigation** links aus den Überschriften (Seiten und `##`-Ebene), die aktuelle Stelle markiert;
- **Suche** über alle Seiten, im Browser, ohne Server: ein Index aus Überschrift, Pfad und Textzeile,
  Treffer als Liste mit Sprungziel;
- **Bildern** als `data:`-URI eingebettet (die 30 PNGs, etwa 12 MB nach Base64); `demo.gif` wird
  **nicht** eingebettet und auch nicht relativ verlinkt — kein Deploy-Weg lädt `static/` auf die VM,
  und ein toter Link ist schlimmer als keiner. Stattdessen nennt das Wiki das Video und verlinkt es
  im Repository; dass dafür Netz nötig ist, steht dabei (Entscheidung).
- **Diagrammen**, die beim Öffnen gerendert werden: eine gepinnte Kopie von `mermaid.min.js` liegt
  unter `scripts/wiki/` und wird mit eingebettet. **Entscheidung des Nutzers:** Mermaid mitliefern.
  Es ist Mermaid 10 als UMD-Bündel — Version 11 gibt es nur als ES-Modul und lädt aus einer losen
  Datei gar nicht. Version und SHA-256 stehen im Generator, die MIT-Lizenz kommt als Datei daneben
  und als Zeile in die Credits; `make docs` bricht ab, wenn Datei oder Prüfsumme fehlen, statt
  stillschweigend Quelltext zu zeigen. Kein CDN, kein npm, kein Node zur Bauzeit. Das Wiki wächst
  damit auf etwa 15 MB.
- **Dem Aussehen des Produkts:** dieselbe Palette wie das Cyberpunk-Theme, Schrift wie dort,
  Codeblöcke wie im Web-UI. Kein Theme-Umschalter.

**Markdown-Umfang, den der Generator trägt:** Überschriften, Absätze, Listen (auch verschachtelt),
Code-Blöcke mit Sprache, Inline-Code, Fett, Kursiv, Links, Bilder, Tabellen, Blockquotes,
horizontale Linien und ```mermaid-Blöcke. Mehr braucht die Doku nicht; was er nicht kennt, bleibt
als Text stehen, statt verschluckt zu werden.

**Im Web-UI:** Die Hilfe bekommt oben einen Weg zum Wiki. Das Web-UI prüft beim Start, ob
`static/wiki.html` da ist; fehlt sie, steht dort statt des Links eine Zeile, wie man sie baut
(`make docs`). `scripts/deploy-utm.py`, `Makefile` und `make.ps1` laden die Datei mit hoch, wenn sie
existiert.

## 5. Die Tests

- **`tests/test_docs.py` zieht mit:** Die API-Zeilen werden in `docs/api.md` geprüft, die
  Rizin-Zeilen in `docs/rizin.md`, die MCP-Werkzeuge in `docs/api.md`; die Tab-Tabelle und die
  Bilder bleiben in der README (jedes PNG muss von README **oder** Doku benutzt werden, keines
  verwaisen).
- **Tests außerhalb von `test_docs.py` dürfen mitziehen (Entscheidung):** `tests/test_logs_ui.py`
  hält heute einen README-Satz über die Befehlskarte fest; diese Zusage wandert nach `docs/logs.md`.
  Wo ein Test an einem Satz hängt, der umzieht, zieht der Test mit — das ist Teil dieser Arbeit, kein
  Grund, den Satz in der README zu lassen.
- **Neu `tests/test_wiki.py`:** der Generator als Einheit — Navigation aus den Überschriften, Suche
  findet ein Wort aus einer tiefen Seite, jedes Bild als `data:`-URI, kein `http://` oder `https://`
  als **Ressource** (`src`, `href` eines Stylesheets, `import`) — Links im Text dürfen bleiben —,
  Mermaid-Blöcke als `<pre class="mermaid">`, die gepinnte Kopie eingebettet, eine unbekannte
  Markdown-Zeile bleibt Text, eine Seite ohne Überschrift bricht nichts, und ein `<script>` im
  Markdown bleibt Text.
- **Doku-Struktur:** jede Datei unter `docs/` (außer `superpowers/`) ist von `docs/README.md`
  verlinkt und umgekehrt; jede Seite hat ihren Einleitungssatz und ihr „Weiter:".
- **Die Mermaid-Blöcke** werden geparst, soweit das ohne Renderer geht: jeder Block beginnt mit einem
  bekannten Diagrammtyp und seine Klammern und Pfeile sind paarweise.
- **Der Stand des Wikis (Entscheidung):** Der Generator schreibt das Baudatum (UTC) in die Fußzeile,
  dazu die kurze Commit-Kennung, wenn `git` erreichbar ist — sonst nur das Datum. Keine lokalen
  Pfade, kein Rechnername. Die Hilfe im Web-UI nennt neben dem Link das Datum der Datei, damit ein
  altes Wiki zu sehen ist und nicht stillschweigend falsch bleibt.

## Was der Baumeister entscheidet

- Die Worte: jede Zeile der README, jeder Satz der Doku, die Bildunterschriften.
- Welche acht bis zehn Features ins Schaufenster kommen und mit welchem Bild.
- Aufbau und Aussehen der Navigation und der Suche im Wiki, solange beide ohne Netz funktionieren.
- Die Namen der Doku-Dateien, solange die Index-Seite und die Tests zusammenpassen.
- Wie der Generator Markdown parst (eine Zeile für Zeile arbeitende Funktion reicht; keine
  Abhängigkeit).
- Ob die Dienste-Tabelle in der README oder in `docs/README.md` die ausführlichere ist.
