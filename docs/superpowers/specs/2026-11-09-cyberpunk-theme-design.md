# Zweites Theme „Cyberpunk“

## Absicht

Die Web UI bekommt neben dem heutigen Aussehen („Classic“) ein zweites Theme,
„Cyberpunk“: Neon auf tiefem Violett, Kopfleiste statt Seitenleiste, Karten
mit Bedienelementen. Man schaltet über einen Knopf in der Oberfläche sofort
um, ohne Neuladen (Vorbild für den Knopf: das ✶ in der Kopfleiste von
Hecate). Vorbild für Farben, Aufbau und Bedienelemente der Karten ist eine
interne Management-Ansicht, die der Nutzer gezeigt hat. Ihr Name und ihre
Adresse gehören nicht ins Repo (öffentlich auf GitHub); dieses Dokument hält
nur die übernommenen Gestaltungswerte fest.

## Ziele

1. **Umschalten:** Ein Theme-Knopf (✶) ist in beiden Themes sichtbar und
   wechselt sofort zwischen Classic und Cyberpunk. Layout, Farben, Graph und
   Diagramme bauen sich ohne Neuladen um. Die Wahl wird im Browser gespeichert
   (`localStorage`); ohne gespeicherte Wahl startet Cyberpunk (Änderung vom
   2026-11-10 auf Wunsch des Nutzers; ursprünglich Classic). Der Knopf ist die
   Einstellung; ein eigenes Einstellungsfenster gibt es nicht.
2. **Cyberpunk-Aufbau** (siehe unten): Kopfleiste oben, Prozessliste und
   Zeitleiste in einer ausklappbaren Schublade links, Inhalt in voller Breite
   mit Kopfbereich je Tab und Karten.
3. **Bedienelemente auf Karten, in beiden Themes:**
   - **(i)** an Karten- und Abschnittsüberschriften: kurzer Erklärtext.
   - **CHART / TABLE:** wo heute eine Grafik ist, schaltet man auf eine
     Tabelle derselben Daten um.
   - **Sortieren:** Datentabellen per Klick auf den Spaltenkopf.
   - **Kacheln öffnen ihre Liste:** Kennzahl-Kacheln sind anklickbar und
     führen zur passenden, gefilterten Ansicht.
4. **Logo:** In beiden Themes das Original (`webui/static/icon.png`),
   unverändert. Kein neues Logo, kein Banner.
5. **Neue Alert-Liste** (Ziel der Alert-Kachel, in beiden Themes): alle
   Alerts in einer Tabelle, filterbar nach Schweregrad und Engine, mit
   Textsuche. Ein Klick auf die Kachel öffnet sie ungefiltert, ein Klick auf
   die high/medium/low-Angabe der Kachel gleich mit diesem Schweregrad
   vorgefiltert.

## Nicht-Ziele

- Kein drittes Theme in dieser Runde (der Aufbau soll eins aber nicht
  verhindern).
- Keine neuen Diagramme oder Kennzahlen; CHART/TABLE nur für vorhandene
  Grafiken. Einzige neue Ansicht ist die Alert-Liste.
- Kein Umbau der Detailansicht rechts (Alert-Details, Detonationsergebnisse):
  sie bekommt nur das Cyberpunk-Aussehen.
- Keine Prozess-Suche per Tastenkürzel (Variante C der Layout-Vorschläge).
- Keine Mobil-Ansicht.
- Kein serverseitiges Speichern der Wahl.

## Anti-Ziele (Misserfolg, auch wenn es technisch läuft)

- Classic sieht nach der Umstellung anders aus als heute (außer dem neuen
  ✶-Knopf und den neuen Bedienelementen).
- Umschalten verliert Zustand: aktiver Tab, offene Detailansicht, Filter,
  Graph-Ansicht, laufende Abfang-Sitzungen, Scrollposition des Inhalts.
- Beim Laden flackert kurz das falsche Theme auf.
- Ein Teil der Oberfläche bleibt im Cyberpunk-Theme in Classic-Farben stehen
  (vergessene fest eingetragene Farben, Canvas-Grafiken).
- Neue XSS-Lücken durch die Bedienelemente (Erklärtexte, sortierte Zellen,
  Tabellenansichten).
- Name oder Adresse der internen Vorbild-Seite landen im Repo.

## Rahmenbedingungen

- Frontend ist Vanilla-JS ohne Build-Schritt: `webui/static/js/app.js`
  (~10 100 Zeilen), `webui/static/css/style.css` (~7 300 Zeilen),
  `webui/templates/index.html`. Keine neuen Abhängigkeiten.
- `style.css` nutzt überwiegend Variablen aus `:root` (~1 100 `var(--…)`),
  enthält aber ~330 fest eingetragene Farben; `app.js` hat ~100 fest
  eingetragene Farben (Graph, Zeitleiste, PE-Abschnitte, Datenkarte,
  Severity-Farben) und 7 Canvas-Zeichenstellen.
- Heute liegen Logo, Tabs (`nav.sidebar-tabs`), Prozessliste
  (`#process-list-section`), Zeitleiste (`#timeline-section`) und Dienststatus
  (`#service-status`) zusammen in `aside#sidebar`; der Inhalt ist
  `main#main-content`, jede Tab-Seite hat einen `.content-header` mit Titel
  und Untertitel. Es gibt keine `@media`-Regeln.
- Sicherheitshelfer `escapeHtml`, `jsArg`, `jsInt`, `cssToken` sind Pflicht;
  `tests/test_frontend.py` prüft das statisch.
- `tests/test_docs.py` verlangt, dass jedes Bild in `static/` in der README
  steht und umgekehrt, und dass README-Tab-Tabelle und Hilfe zu den Tabs
  passen.
- Asset-Versionen in `index.html` (`app.js?v=`, `style.css?v=`) werden bei
  Änderungen erhöht; nach Template-Änderungen ist auf der VM ein Neustart der
  Web UI nötig (Flask cached Templates).
- Oberflächensprache ist Englisch; README Englisch.

## Ansätze

1. **Ein gemeinsames Gerüst, das Theme steuert CSS (gewählt).** Am `<html>`
   hängt `data-theme="classic|cyberpunk"`. Cyberpunk-Regeln stehen in einer
   eigenen Datei und greifen nur unter `[data-theme="cyberpunk"]`. Ein kleines
   Stück JS hängt beim Umschalten Tab-Leiste und Status zwischen Seitenleiste
   und Kopfleiste um (dieselben DOM-Knoten, Klick-Handler bleiben). Canvas-
   und Inline-Farben kommen aus CSS-Variablen; nach dem Umschalten zeichnen
   sich Grafiken neu. *Kosten:* einmalige Umstellung der fest eingetragenen
   Farben. *Gewinn:* jeder Tab existiert einmal; neue Funktionen sind
   automatisch in beiden Themes da.
2. **Eigene Seitenvorlage je Theme.** Verworfen: Umschalten hieße Neuladen,
   und alle Tabs müssten doppelt gepflegt werden.
3. **JS baut das Gerüst je Theme aus einer Layout-Beschreibung.** Verworfen:
   viel mehr Code und Fehlerquellen ohne Vorteil bei zwei Themes.

## Das Cyberpunk-Theme im Detail

### Aufbau (Layout-Variante A)

- **Kopfleiste**, oben fixiert, ca. 56 px hoch, von links nach rechts:
  - Knopf **☰ PROCESSES** mit Anzahl; öffnet die Schublade.
  - Original-Logo `icon.png` (unverändert) und der Schriftzug
    „DETONATION CHAMBER“ im Cyberpunk-Stil (Text, kein Bild).
  - Die Tabs als zusammenhängende Schalterleiste; der aktive Tab
    magentafarben gefüllt mit Glow. Passen nicht alle Tabs in die Breite,
    wandern die übrigen in ein Menü „…“.
  - Rechts: Dienste-Zusammenfassung (Punkt + „n/m ONLINE“), Uhrzeit,
    „? Help“, ✶-Knopf. Ein Klick auf die Zusammenfassung öffnet ein kleines
    Aufklappfeld unter ihr; darin steht der umgehängte `#service-status` mit
    den Einzelstatus.
- **Schublade** links über dem Inhalt (Inhalt dahinter abgedunkelt): enthält
  Prozessliste und Zeitleiste. Schließt bei Esc, Klick daneben und nach
  Auswahl eines Prozesses (die Auswahl wirkt wie heute). Der
  Öffnungszustand wird nicht gespeichert.
- **Inhalt** in voller Breite. Der `.content-header` jedes Tabs wird zum
  Kopfbereich: kleine grüne Monospace-Zeile darüber (z. B.
  „TDC // DETONATION CHAMBER · <TAB>“), Titel in Monospace mit Verlauf
  Amber → Rot, Untertitel gedämpft.
- **Karten und Kacheln:** Abschnittstitel in Cyan, Monospace, Großbuchstaben;
  Kennzahl-Kacheln mit 3 px farbiger linker Kante nach Schweregrad; Karten
  mit zartem Magenta-Rand.

### Gestaltungswerte

| Rolle | Wert |
|---|---|
| Hintergrund | `#0b0716`, darüber Gitter 28 px aus `rgba(255,79,216,.045)` und oben zwei radiale Scheine (Magenta `.22`, Amber `.10`) |
| Kopfleiste | Verlauf `#170e2c` → `#120a22`, unten 1 px `rgba(255,79,216,.5)`, Schatten `0 1px 0 rgba(255,79,216,.25), 0 8px 28px rgba(255,79,216,.12)` |
| Karte / Kachel | `#140d24`, Rand 1 px `rgba(255,79,216,.22)`, Radius 6 px, Schatten `0 0 0 1px rgba(0,0,0,.35), 0 8px 24px -16px rgba(255,79,216,.35)`, Innenabstand 12–16 px |
| Erhöhte Flächen (Knöpfe, Tabellenkopf) | `#1b1232` |
| Trennlinien | `#251a3d` |
| Text / gedämpft | `#f3eefc` / `#c9bfe3`, schwächer `#8a7fb0` |
| Akzent (aktiv, Glow) | Magenta `#ff4fd8`, Glow `0 0 14px rgba(255,79,216,.35)`, Text darauf `#12081f` |
| Überschrift-Verlauf | `#ffd060` → `#ffb000` (45 %) → `#ff3b3b` |
| Tabellenköpfe, Abschnittstitel | Cyan `#37e0ff` |
| Kopfbereich-Zeile, „online“ | Grün `#39d98a` |
| Schweregrade | critical `#ff3b3b` (Kachelkante `#d03b3b`), high `#ff7a1a`, medium `#ffb000`, low `#39d98a`, info `#37e0ff` |
| Schrift | Labels, Titel, Navigation: `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`, 10.5–12 px, Sperrung 0.05–0.12 em, Großbuchstaben; Fließtext `system-ui, -apple-system, "Segoe UI", sans-serif` 14 px; Kennzahlen 28 px / 600 |

Classic behält seine heutigen Werte aus `:root` (`--bg-primary` `#080c14`
usw.).

## Gemeinsame Teile (beide Themes)

### Theme-Umschaltung

- Knopf ✶: in Classic im `.sidebar-header` neben „? Help“, in Cyberpunk rechts
  in der Kopfleiste. Tooltip und `aria-label` nennen das Ziel-Theme.
- Speicherung unter einem `localStorage`-Schlüssel; ein kleines Inline-Skript
  im `<head>` setzt `data-theme` vor dem ersten Zeichnen (kein Flackern).
- Beim Umschalten: DOM-Knoten umhängen, ein Ereignis (z. B.
  `tdc:themechange`) auslösen; Graph, Zeitleiste und Canvas-Grafiken zeichnen
  sich darauf neu. Zustand bleibt erhalten (siehe Anti-Ziele).

### Farben aus Variablen

- Fest eingetragene Farben in `style.css` werden zu Variablen; Classic-Werte
  bleiben exakt gleich, Cyberpunk setzt eigene.
- `app.js` liest Farben über einen Helfer aus den CSS-Variablen. Auch
  bedeutungstragende Datenfarben (PE-Abschnittsarten, Entropie-Stufen,
  Graph-Knotenarten, Engine-Farben der Zeitleiste) werden Variablen, damit
  Cyberpunk sie an seine Palette anpassen kann; die Zuordnung Bedeutung →
  Farbe bleibt in beiden Themes unterscheidbar.

### Bedienelemente auf Karten

Sie gelten überall, wo die betreffende Karte oder Tabelle gerendert wird,
auch in der Detailansicht und in den Detonationsergebnissen (Submit-Tab und
Detailansicht teilen sich die Render-Funktionen, z. B.
`renderNamedPipesBlock`). „Kein Umbau der Detailansicht“ betrifft nur deren
Aufbau.

- **(i):** öffnet einen kleinen Erklärtext (Klick, Esc schließt). Texte auf
  Englisch, ein bis zwei Sätze, aus vorhandenem Wissen (Hilfe-Modal, README).
- **CHART / TABLE:** für die vorhandenen Grafiken: Zeitleiste, Severity-Leiste
  im Tracing, PE-Abschnitts-/Entropie-Darstellung und jede weitere Stelle, an
  der eine Grafik Zahlen zeigt, die sich als Tabelle lesen lassen. Die Wahl
  gilt pro Karte bis zum Neuladen.
- **Sortieren:** alle Datentabellen. Klick auf den Kopf: aufsteigend,
  absteigend; Zahlen numerisch, Zeiten chronologisch; Anzeige ↕/▲/▼. Die
  Sortierung bleibt erhalten, wenn eine Tabelle durch Polling neu gerendert
  wird.
- **Kacheln:** die Kennzahl-Kacheln des Dashboards führen zur passenden
  Ansicht: TOTAL ALERTS → Alert-Liste (high/medium/low vorgefiltert, siehe
  unten), PROCESSES TRACKED → Prozessliste (Classic: Seitenleiste in den
  Blick scrollen, Cyberpunk: Schublade öffnen), SERVICES ONLINE →
  Dienstkarten des Dashboards, DETECTION RULES → Hilfe, Abschnitt Detection
  Rules, SCANNER TOOLS → ThreatScan.

### Alert-Liste

- Eigener Tab **Alerts** direkt nach Dashboard (README-Tab-Tabelle und
  Hilfe-Tab-Übersicht werden ergänzt; `tests/test_docs.py` prüft das).
- Daten aus dem schon geladenen Alert-Bestand des Frontends
  (`state.alerts`); keine neue API nötig (`/api/alerts` kennt die Filter
  bereits, falls der Builder serverseitig filtern will).
- Spalten: Zeit, Schweregrad, Engine, Regel/Titel, Prozess (Name und
  Instanz), Kurzbeschreibung. Sortierbar wie alle Tabellen; neueste zuerst.
- Filter: Schweregrad (Mehrfachauswahl), Engine, Textsuche über Regel,
  Prozess und Beschreibung; Anzeige „n von m“. Ein Klick auf eine Zeile
  öffnet die vorhandene Alert-Detailansicht (`openAlertDetailById`), ein
  Klick auf den Prozess springt wie in der Prozessliste.
- Große Mengen: höchstens die neuesten 2000 Zeilen anzeigen, mit Hinweis.
- Alle Werte sind Angreiferdaten: Escaping wie überall.

## Prüfen und Doku

- Unit-Tests: Umschalten setzt `data-theme`, speichert, hängt Tabs/Status um
  und zurück; Sortierung; Tabellenansicht; `test_frontend.py` bleibt grün
  (Escaping auch in den neuen Teilen).
- Klickprüfung im Headless-Chrome auf der VM: jeder Tab in beiden Themes ohne
  Fehler, Umschalten mit offener Detailansicht, laufendem Graph und Pipes-Tab.
  Screenshots ansehen.
- README: Abschnitt zu Themes und Bedienelementen, ein Cyberpunk-Screenshot
  in `static/`; Hilfe-Modal erwähnt den ✶-Knopf.

## Dem Builder überlassen

- Genaue Liste der Karten mit (i) und die Erklärtexte.
- Welche Grafiken CHART/TABLE bekommen (nach obiger Regel) und wie die
  Tabellen aussehen.
- Schwelle für das „…“-Menü, Breite der Schublade, Kopfbereich-Texte je Tab.
- Variablennamen und wie die fest eingetragenen Farben gruppiert werden.
- Ob die Cyberpunk-Regeln in einer eigenen CSS-Datei oder einem Block in
  `style.css` stehen (eigene Datei bevorzugt).

## Entscheidungen des Assistenten (zur Prüfung)

- Die Alert-Liste ist ein eigener Tab „Alerts“ nach Dashboard; DETECTION
  RULES führt zur Hilfe (Abschnitt Detection Rules).

- Namen der Themes in der Oberfläche: „Classic“ und „Cyberpunk“.
- Bedienelemente (i, CHART/TABLE, Sortieren, Kacheln) kommen in beide Themes.
- Der ✶-Knopf ist die Einstellung; kein eigenes Einstellungsfenster.
- Detailansicht rechts bleibt im Aufbau unverändert; die Bedienelemente
  wirken aber auch dort, weil die Tabellen dieselben Render-Funktionen nutzen.
- Dienst-Einzelstatus in Cyberpunk: Aufklappfeld unter „n/m ONLINE“ in der
  Kopfleiste (dorthin wird `#service-status` umgehängt), nicht in der
  Schublade.
- Tabs ohne `.content-header` (Tracing, Graph) bekommen keinen künstlichen
  Kopfbereich; ihre vorhandene Kopfzeile wird nur umgestaltet.
- Keine Prozess-Suche per Tastenkürzel.
- Name/Adresse der Vorbild-Seite stehen nicht im Repo.
