# Befehlskarte, Formwahl und eigene Dashboards — Umsetzungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Der LOGS-Tab bekommt eine stehende Befehlskarte und eine Formwahl für sein Ergebnis (Tabelle, Kreis, Balken, Linie, Senkey), und eine Auswertung lässt sich als Kachel auf einer eigenen Dashboard-Seite speichern.

**Architecture:** Alles baut auf dem, was da ist: `/api/logs/search` bleibt die einzige Rechenquelle, die Zeichner (`pieSvg`, `verdictBarsSvg`, `stackedBarsSvg`, `layoutSankey`/`sankeySvg`) kommen aus der CHARTS-Abteilung von `app.js`, dazu kommt ein Zeichner für mehrere Linien. Die Kacheln liegen in `webui/dashboards.json` hinter einem neuen Modul `webui/dashboards.py` mit sieben Routen; gerechnet wird im Browser, eine Kachel nach der anderen.

**Tech Stack:** Flask (Python 3.9 auf der VM), Vanilla JS ohne Build, SVG ohne Bibliothek, pytest, Node 20 für die Frontend-Tests.

**Spec:** `docs/superpowers/specs/2026-11-16-logs-dashboards-design.md`

## Global Constraints

- **Formen:** `table`, `pie`, `bars`, `line`, `sankey`. Mehr nicht; `form` wird serverseitig gegen diese Menge geprüft.
- **Spalten lesen:** Spalte 0 ist der Name, die erste Spalte danach, deren Werte alle Zahlen sind, ist der Wert. Weitere Spalten bleiben unbenutzt. Ohne Zahlenspalte sind die Bild-Formen gesperrt. `rows: []` sperrt nichts.
- **Formen je Antwort-Typ:** `events` → nur EVENTS; `table` → TABLE, PIE, BARS, SANKEY (je nach Spalten); `timechart` → TABLE, LINE, BARS. Voreinstellung: `events` → EVENTS, `table` → STATISTICS, `timechart` → VISUALIZATION mit LINE.
- **BARS** zeichnet `stackedBarsSvg` bei `timechart` und `verdictBarsSvg` bei einer Namensspalte; gespeichert wird nur `bars`.
- **Grenzen der Darstellung:** PIE und BARS zeigen die zwölf größten Werte plus `other`; SANKEY je Seite die zwölf größten plus `other`; LINE die Reihen des Servers (höchstens zehn plus `OTHER`).
- **`limit`:** 200 für EVENTS und STATISTICS, **1000** für jede Bild-Form und für eine Bild-Kachel; eine Tabellenkachel zeigt höchstens **20** Zeilen.
- **Warnzeile:** Bei `count > rows.length` oder `truncated` steht unter dem Bild und auf der Kachel „only N of M groups shown — add `| sort -count | head 20`"; ein Klick darauf hängt genau diese Pipe an die Abfrage.
- **Grenzen der Daten:** höchstens **10** Dashboards, **12** Kacheln je Dashboard, Name **1–60** Zeichen ohne Steuerzeichen, Abfrage höchstens **4000** Zeichen, `earliest`/`latest` höchstens **40** Zeichen.
- **Speichern nur mit Pipe:** Eine Abfrage ohne Pipe lässt sich nicht als Kachel speichern (SAVE gesperrt).
- **Rechnen:** Kacheln laufen eine nach der anderen, nie gleichzeitig; von selbst rechnet nichts nach. Nachladen oben für alle, am Kachelkopf für eine.
- **Kein neuer Tab:** `.content-header` bleibt bei 12, `.tab-content` bei 14. Die eigenen Dashboards sind Unterseiten des Dashboard-Tabs; `.dashboard-body` und seine Kinderliste bleiben unverändert.
- **Sicherheit:** jeder Text vom Server durch `escapeHtml`; Inline-Handler nur mit `jsArg`/`jsInt`; Klassen aus Daten durch `cssToken`; kein `eval`.
- **Farben:** keine Farbliterale in `app.js`, `index.html` und `style.css` außerhalb des ersten `:root`-Blocks; Markup nutzt `var(--x)`, Canvas `themeColor('--x')`. Wie sich das Aussehen auf `style.css`, `theme-cyberpunk.css` und eine etwaige gemeinsame Layout-Datei verteilt, richtet sich nach dem Stand von `main` zu Beginn der Umsetzung (siehe Spec, Randbedingungen).
- **(i)-Texte:** höchstens 300 Zeichen, 1–2 Sätze, Ende mit `.`, `!` oder `?`, kein `<`, `${` oder `&`.
- **Asset-Versionen** in `webui/templates/index.html` bei jeder Änderung an `app.js`, `style.css` oder einer Theme-Datei erhöhen; ein Test prüft, dass der alte Wert weg ist.
- **Doku-Tests:** genau eine README-API-Zeile je neuer Route; `webui/dashboards.py` in allen drei Deploy-Wegen (`scripts/deploy-utm.py`, `Makefile`, `make.ps1`); `<code>/api/…</code>` in der Hilfe nur für echte Routen.
- **Tests:** `make -s unit-test` grün; Node-Tests mit Node 20, der Fassung der CI, als erste Stelle im PATH; die volle Suite je einmal unter `TZ=UTC` und `TZ=Europe/Berlin`. Neue Funktionen und Konstanten, die ein Node-Test braucht, gehören in die Listen in `tests/test_theme.py`.
- **Python 3.9** auf der VM: keine Syntax oder Bibliothek, die jünger ist.
- **Sprache:** Oberfläche, README und Hilfe englisch; Code-Kommentare englisch.

## Review Focus

1. **Text aus einem Sample in einem Namen oder einer Abfrage** — ein Kachelname mit `<script>`, ein Gruppenwert mit `</text>` in einem Senkey, 30.000 Zeichen in einer Zelle: bleibt Text, bricht kein SVG, friert die Seite nicht ein (Tasks 2, 3, 6).
2. **`dashboards.json` von Hand verändert oder halb geschrieben** — unbekannte Felder, falsche Typen, `panels` als Objekt statt Liste, abgeschnittene Datei: der Dashboard-Tab lädt trotzdem, der kaputte Satz fällt weg (Task 4).
3. **Zwei Browser-Tabs am selben Dashboard** — Tab A löscht eine Kachel, Tab B speichert danach: der letzte Schreiber gewinnt, und der Browser holt nach jedem Schreiben die Liste neu, statt mit einer veralteten weiterzuarbeiten (Tasks 4, 6).
4. **Eine Kachel, deren Suche nicht mehr geht** — ein Feld, das es nicht mehr gibt, eine Abfrage mit Syntaxfehler, eine Form, die zu den neuen Spalten nicht passt: die Kachel nennt den Grund, die anderen rechnen weiter (Task 6).
5. **Wechsel während des Rechnens** — Unterseite oder Tab wechseln, während Kacheln laufen; eine Suche, die zehn Sekunden braucht: laufende Anfragen werden abgebrochen, keine Antwort landet auf der falschen Seite, das übrige Web-UI bleibt bedienbar (Task 6).

---

### Task 1: Befehlskarte (COMMANDS)

**Files:**
- Modify: `webui/static/js/app.js` (LOGS-Abteilung, bei den Konstanten ab `LOGS_EXAMPLES`)
- Modify: `webui/templates/index.html` (`#tab-logs` linke Spalte, der `?`-Knopf, Asset-Versionen)
- Modify: `webui/static/css/style.css` und die Theme-Datei(en) des Hauses
- Test: `tests/test_logs_ui.py`

**Interfaces:**
- Consumes: `logsCurrentQuery()`, `logsSetQuery(q)`, `logsAddSource(s)`, `logsInsertTerm(t)`, `logsPipeIndex(q)` (alle vorhanden).
- Produces:
  - `const LOGS_COMMANDS` — `[{group: 'SEARCH'|'PIPES'|'TIME'|'SOURCES', items: [{text, hint, kind: 'term'|'pipe'|'source'}]}]`
  - `logsCommandsHtml() -> string` (rein)
  - `logsInsertCommand(text: string, kind: string) -> boolean` — fügt ein, ersetzt nie, sucht nie
  - `toggleLogsCommands(force?: boolean) -> boolean`
  - `logsCommandsOpen()` / `logsRememberCommands(open)` über `localStorage['tdc.logs.commands']`

- [ ] **Step 1: Failing tests** in `tests/test_logs_ui.py`

```python
def test_commands_card_lists_every_group_and_stays_text():
    # LOGS_COMMANDS hat die vier Gruppen; logsCommandsHtml() enthält jede Gruppe,
    # jeden Befehlstext und jeden Halbsatz; ein Hinweis mit "<img src=x>" bleibt Text.
    # Jede Zeile hat data-logs-cmd und data-logs-kind; kein Inline-Handler traegt Daten.

def test_a_command_is_inserted_not_substituted():
    # Query 'source=dns foo' + logsInsertCommand('| stats count by ', 'pipe')
    #   -> 'source=dns foo | stats count by ' und KEIN fetch
    # Query 'a | head 5' + logsInsertCommand('field=', 'term') -> 'a field= | head 5'
    # logsInsertCommand('source=firewall', 'source') geht ueber logsAddSource (sucht)
    # ein unbekanntes kind -> false, Query unveraendert

def test_the_question_button_toggles_the_card():
    # toggleLogsCommands() kippt hidden und aria-expanded des Knopfes,
    # schreibt tdc.logs.commands, und initLogs stellt den Zustand wieder her;
    # blockierter localStorage bricht nichts (setItem wirft)

def test_both_themes_style_the_commands_card():
    # style.css hat die .logs-commands-Regeln inkl. position: sticky,
    # die Theme-Datei(en) ihre Entsprechung, keine Farbe ausserhalb :root,
    # und unter 1100 px liegt die Karte ueber den Ergebnissen
```

- [ ] **Step 2:** Tests laufen lassen → FAIL (`LOGS_COMMANDS is not defined`).
- [ ] **Step 3: Implementieren.** `LOGS_COMMANDS` mit den Gruppen und Zeilen aus der Spec (Abschnitt 1, Tabelle); `logsCommandsHtml()` zeichnet je Gruppe eine aufklappbare Liste; `logsInsertCommand` setzt `kind: 'pipe'` hinter die Abfrage, `'term'` an der Cursorstelle (über `logsInsertTerm`), `'source'` über `logsAddSource`; Markup in `index.html` als `<section class="logs-commands" id="logs-commands" hidden>` über `.logs-fields`, der `?`-Knopf bekommt `onclick="toggleLogsCommands()"` und `aria-expanded`; `LOGS_SYNTAX_HINT` entfällt samt der Zeile in `initLogs`, die ihn als `title` setzte. (i)-Text an der Karte.
- [ ] **Step 4:** Tests grün; `node --check webui/static/js/app.js`; `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(logs): a commands card that stays while you scroll`.

---

### Task 2: Zeichner für mehrere Linien (`lineSvg`)

**Files:**
- Modify: `webui/static/js/app.js` (CHARTS-Abteilung, neben `sparklineSvg`)
- Modify: `tests/test_theme.py` (`CHART_FUNCTIONS` um `lineSvg` erweitern)
- Test: `tests/test_charts.py`

**Interfaces:**
- Consumes: `_chartColor`, `_chartNumber`, `_chartCoord`, `_chartTicks`, `_chartPeriodLabel`, `escapeHtml`.
- Produces: `lineSvg(series, opts) -> string` mit
  `series: [{key, label, color, points: [[tMs, value], …]}]`,
  `opts: {width = 560, height = 140, unit, step}`; `''` wenn nichts zu zeichnen ist.

- [ ] **Step 1: Failing tests** in `tests/test_charts.py`

```python
def test_line_svg_draws_every_series_and_nothing_else():
    # drei Reihen a 5 Punkte -> drei <path class="chart-line" data-key=...>,
    # Achse, Gitter, <text class="chart-ymax">, je Reihe ein <title>;
    # Farben nur aus _chartColor (keine Farbe im Markup, die nicht var(--x) ist)

def test_line_svg_is_empty_without_data():
    # [] -> '', [{points: []}] -> '', alle Werte null -> ''

def test_line_svg_handles_one_point_and_flat_series():
    # ein Punkt -> ein Kreis (chart-point), kein Pfad mit NaN;
    # alle Werte gleich -> waagerechte Linie, ymax > 0

def test_line_svg_escapes_labels():
    # label '</text><script>' erscheint nur escaped, nie als Tag
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** `lineSvg` nach dem Muster der Nachbarn: Punkte nach Zeit sortiert, `null` unterbricht die Linie nicht sondern wird übersprungen, Punkte nur bei höchstens 30 Werten je Reihe, `data-key` je Pfad, `<title>` mit Reihenname und Spanne, Rückgabe `''` ohne zeichenbare Reihe.
- [ ] **Step 4:** Tests grün; `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(charts): a line chart for several series`.

---

### Task 3: Reiter und Formwahl im LOGS-Tab

**Files:**
- Modify: `webui/static/js/app.js` (LOGS-Abteilung)
- Modify: `webui/templates/index.html` (Reiterzeile und Formschalter über `#logs-results`, Asset-Versionen)
- Modify: `webui/static/css/style.css` und die Theme-Datei(en)
- Test: `tests/test_logs_ui.py`

**Interfaces:**
- Consumes: `renderLogsResultBody`, `logsTableHtml`, `logsEventsHtml`, `logsTimechartHtml`, `runLogsSearch`, `logsState`, `pieSvg`, `chartLegendHtml`, `verdictBarsSvg`, `stackedBarsSvg`, `layoutSankey`, `sankeySvg`, `topWithOther`, `chartEmptyHtml`, `lineSvg` (Task 2).
- Produces:
  - `logsResultShape(result) -> {type, label: number|null, value: number|null, labels: number[], rows: number, count: number, truncated: boolean}`
  - `logsFormsFor(shape) -> {table: true, pie: bool, bars: bool, line: bool, sankey: bool, why: {form: reason}}`
  - `logsViewFor(shape) -> 'events'|'statistics'|'visualization'` (Voreinstellung je Typ)
  - `logsChartHtml(result, form) -> string` (rein; `''` wenn die Form nicht passt)
  - `logsTruncNoteHtml(shape) -> string` und `logsAddSortPipe()` (hängt `| sort -count | head 20` an und sucht)
  - `setLogsView(view)`, `setLogsForm(form)`; `let logsView = { view: '', form: '' }`
  - `logsChartLimit(form) -> 200|1000`

- [ ] **Step 1: Failing tests** in `tests/test_logs_ui.py`

```python
def test_result_shape_finds_the_name_and_the_number_column():
    # ['f','count']            -> label 0, value 1
    # ['f','count','percent']  -> label 0, value 1          (top f)
    # ['status','count']       -> label 0, value 1          (Zahlen in beiden)
    # ['a','b','c'] nur Text   -> value None
    # ['_time','powershell','access'] -> type timechart, labels [0]
    # ['a','b','count']        -> labels [0,1], value 2     (Senkey)
    # rows [] mit Spalten      -> Formen bleiben erlaubt

def test_the_tabs_lock_with_a_reason_and_pick_a_default():
    # events      -> EVENTS aktiv, STATISTICS und VISUALIZATION aria-disabled mit Grund im title
    # table       -> STATISTICS aktiv
    # timechart   -> VISUALIZATION aktiv mit form 'line'
    # ein Reiter, der unbenutzbar wird, faellt auf den ersten benutzbaren zurueck

def test_the_form_switches_match_the_columns():
    # ['f','count']            -> pie, bars, sankey? (sankey nein), table ja
    # ['a','b','count']        -> sankey ja
    # ['_time',...]            -> line ja, bars ja, pie nein (Grund im title)
    # ['a','b','c'] nur Text   -> nur table

def test_each_form_draws_its_chart():
    # pie -> <svg class="chart-svg chart-pie"> + .chart-legend
    # bars auf ['f','count'] -> chart-bars ueber verdictBarsSvg
    # bars auf timechart     -> chart-bars ueber stackedBarsSvg
    # line -> chart-line Pfade; sankey -> chart-sankey mit zwei Spalten
    # 13 Gruppen -> zwoelf plus 'other'; leere rows -> chartEmptyHtml

def test_a_chart_form_asks_for_a_thousand_rows_and_warns_when_it_is_short():
    # setLogsForm('pie') -> fetch mit limit=1000
    # count 5312 bei 1000 Zeilen -> Warnzeile mit beiden Zahlen,
    # Klick darauf haengt '| sort -count | head 20' an und sucht
    # setLogsView('statistics') -> limit zurueck auf 200

def test_hostile_values_stay_text_in_every_form():
    # Gruppenwert '</text><script>alert(1)</script>' und 30 000 Zeichen:
    # kein Tag aus den Daten, Laufzeit unter einer Sekunde in Node
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** `logsResultShape` liest die Spalten nach der Regel der Global Constraints (eine Spalte gilt als Zahlenspalte, wenn jeder nicht-leere Wert eine endliche Zahl ist; ohne Zeilen entscheidet der Spaltenname `count`/`percent`/`avg(…)`/`sum(…)`/`dc(…)`/`min(…)`/`max(…)`); `logsFormsFor` setzt die Tabelle aus Global Constraints um und gibt je gesperrte Form einen englischen Grund; `renderLogsResultBody` zeichnet nach `logsView`; die Reiterzeile und die Formschalter kommen aus `index.html` und werden über `aria-selected`/`aria-disabled` gesetzt; `logsChartHtml` bündelt die Zeichner inklusive `topWithOther`-Kürzung und Senkey-Aufbau (`columns` = die zwölf größten je Seite, `links` = die Zeilen).
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(logs): result tabs and a form for every result`.

---

### Task 4: Dashboard-Speicher auf dem Server

**Files:**
- Create: `webui/dashboards.py`
- Modify: `webui/app.py` (sieben Routen, Instanz wie `_logs`)
- Modify: `README.md` (sieben Zeilen in der API-Tabelle)
- Modify: `scripts/deploy-utm.py`, `Makefile`, `make.ps1`
- Modify: `.gitignore` (`webui/dashboards.json`)
- Test: `tests/test_dashboards.py` (neu)

**Interfaces:**
- Produces:
  - `class DashboardStore(path: str)` mit
    `all() -> list[dict]`, `add(name) -> dict`, `rename(did, name) -> dict`, `remove(did) -> None`,
    `add_panel(did, name, query, form, earliest, latest) -> dict`,
    `update_panel(did, pid, name=None, form=None, move=None) -> dict`, `remove_panel(did, pid) -> None`
  - Fehler: `class NotFound(Exception)`, `class Invalid(Exception)` (Text ist die Begründung), `class LimitReached(Invalid)`
  - Konstanten: `MAX_DASHBOARDS = 10`, `MAX_PANELS = 12`, `MAX_NAME = 60`, `MAX_QUERY = 4000`, `MAX_TIME = 40`, `FORMS = ("table", "pie", "bars", "line", "sankey")`
  - Routen nach der Tabelle der Spec, Abschnitt 3.

- [ ] **Step 1: Failing tests** in `tests/test_dashboards.py`

```python
def test_a_dashboard_and_its_panels_round_trip(tmp_path):
    # add / add_panel / rename / update_panel(move='up') / remove_panel / remove,
    # danach ein neuer Store auf derselben Datei liest dasselbe;
    # ids sind 'd-'/'p-' plus 12 Hexzeichen und bleiben stabil

def test_every_limit_and_every_bad_value_is_refused(tmp_path):
    # 11. Dashboard, 13. Kachel, Name '' / 61 Zeichen / 'a\nb' / 'a\x00',
    # form 'donut', query 4001 Zeichen, earliest 41 Zeichen,
    # move 'sideways' -> Invalid bzw. LimitReached, Datei unveraendert

def test_a_broken_file_does_not_break_the_store(tmp_path):
    # kein JSON, {} statt {'dashboards': [...]}, panels als dict,
    # ein Satz ohne id, ein Panel mit form 42, abgeschnittene Datei
    # -> all() liefert, was lesbar ist, der Rest faellt weg; kein Fehler nach aussen

def test_a_failed_write_leaves_the_old_file(tmp_path, monkeypatch):
    # os.replace wirft -> der alte Inhalt steht noch, .tmp ist weg,
    # der Fehler erreicht den Aufrufer

def test_the_routes_answer_the_documented_shapes(client, tdc, tmp_path):
    # GET /api/dashboards -> {'dashboards': []}
    # POST -> 201 {'dashboard': {...}}; PATCH -> {'dashboard': ...}; DELETE -> {'deleted': True}
    # POST .../panels -> 201 {'panel': ...}; PATCH -> {'panel': ...}; DELETE -> {'deleted': True}
    # unbekanntes Feld im Koerper -> 400 mit Namen; unbekannte id -> 404 mit Text;
    # kein JSON-Objekt -> 400

def test_a_write_against_something_that_is_gone_says_so(client, tdc):
    # Dashboard angelegt, geloescht, dann eine Kachel dorthin -> 404
    # Kachel angelegt, geloescht, dann PATCH darauf -> 404
    # (der zweite Browser-Tab arbeitet mit einer veralteten Liste)

def test_the_write_routes_are_protected(client, tdc, monkeypatch):
    # Origin einer anderen Seite -> 403 'Cross-site request rejected'
    # waehrend einer Wartung -> 503 mit maintenance True
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** `DashboardStore` nach dem Muster von `submissions.json`: ein `threading.Lock` über Lesen und Schreiben, Schreiben nach `.tmp` mit `flush`, `os.fsync` und `os.replace` (zehn Versuche gegen `PermissionError`, 50 ms Pause), defensives Lesen (jeder Satz einzeln geprüft, unlesbares fällt weg), `all()` gibt Kopien. In `app.py` eine Instanz wie `_logs` samt `set_dashboard_store()` für die Tests, die Routen mit Prüfung des Körpers im Hausstil (`request.get_json(silent=True)`, unbekannte Felder nennen, `Invalid` → 400, `NotFound` → 404, Schreibfehler → 500 mit Logeintrag). README-Zeilen und die drei Deploy-Wege mit den Schreibweisen, die `tests/test_docs.py` verlangt.
- [ ] **Step 4:** Tests grün; `webui/.venv/bin/python -m pytest tests/test_dashboards.py tests/test_docs.py -q`; `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(dashboards): a store and routes for own dashboards`.

---

### Task 5: SAVE-Dialog im LOGS-Tab

**Files:**
- Modify: `webui/static/js/app.js` (LOGS-Abteilung)
- Modify: `webui/templates/index.html` (`#logs-save` nach dem Muster des Hilfefensters, SAVE in der Reiterzeile, Asset-Versionen)
- Modify: `webui/static/css/style.css` und die Theme-Datei(en)
- Test: `tests/test_logs_ui.py`

**Interfaces:**
- Consumes: Task 3 (`logsView`, `logsResultShape`, `logsFormsFor`), Task 4 (die Routen), `logsState`, `showToast`, `escapeHtml`, `jsArg`.
- Produces:
  - `logsSaveName(query, shape) -> string` (rein; Vorbelegung des Namens)
  - `openLogsSave()` / `closeLogsSave()` / `logsSaveHtml(dashboards, pick) -> string`
  - `async submitLogsSave() -> boolean`
  - `let logsSave = { open: false, dashboards: [], dashboard: '', fixed: false }`

- [ ] **Step 1: Failing tests** in `tests/test_logs_ui.py`

```python
def test_save_is_locked_without_a_pipe_and_open_with_one():
    # query 'source=dns' -> SAVE disabled mit Grund im title
    # query 'source=dns | top query' -> SAVE klickbar

def test_the_dialog_shows_the_dashboards_and_prefills_the_name():
    # GET /api/dashboards wird einmal geholt; die Namen stehen als Schalter,
    # dazu '+ New' mit Namensfeld; logsSaveName('… | stats count by dst_port')
    # -> 'dst_port'; ein Dashboardname mit '<script>' bleibt Text

def test_saving_posts_exactly_the_chosen_form_and_range():
    # Form 'pie', Zeitraum relativ -> POST .../panels mit
    # {name, query, form: 'pie', earliest: '-24h', latest: ''}
    # Zeitraum fest -> earliest/latest aus logsState (ISO, UTC)
    # '+ New' -> erst POST /api/dashboards, dann die Kachel dorthin

def test_the_dialog_reports_a_refused_save():
    # 503 maintenance -> Hinweis 'a tool update is running', Dialog bleibt offen
    # 400 -> die Meldung des Servers steht im Dialog, nicht als Toast
    # Escape und der Backdrop schliessen; der Fokus startet im Namensfeld
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** Dialogmarkup wie `#help-modal` (Backdrop plus Inhalt, `role="dialog"`, `aria-modal`), Felder nach der Tabelle der Spec, `logsSaveName` nimmt die `by`-Felder der Abfrage, sonst das Feld von `top`/`rare`, sonst das erste Wort, gekürzt auf 60 Zeichen.
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(logs): save a result as a dashboard tile`.

---

### Task 6: Eigene Dashboards auf der Dashboard-Seite

**Files:**
- Modify: `webui/static/js/app.js` (Dashboard-Abteilung)
- Modify: `webui/templates/index.html` (`.dashboard-pages` und `.dashboard-own` in `#tab-dashboard`, Asset-Versionen)
- Modify: `webui/static/css/style.css` und die Theme-Datei(en)
- Modify: `tests/test_theme.py` (`DASHBOARD_CHART_FUNCTIONS`, `DASHBOARD_CHART_CONSTS` erweitern)
- Test: `tests/test_dashboards_ui.py` (neu)

**Interfaces:**
- Consumes: Task 2 und 3 (`lineSvg`, `logsResultShape`, `logsFormsFor`, `logsChartHtml`, `logsTruncNoteHtml`), Task 4 (die Routen), `switchTab`, `logsSetQuery`, `logsSetRange`, `showToast`.
- Produces:
  - `let dashboardPages = { list: [], page: 'services', loading: false, at: 0 }`
  - `async loadDashboardPages()`, `renderDashboardPages()`, `setDashboardPage(id)`
  - `renderOwnDashboard()`, `panelCardHtml(panel, state) -> string` (rein)
  - `async loadPanels(ids?)` — der Reihe nach, mit `AbortController` je Lauf
  - `async refreshPanel(pid)`, `openPanelInLogs(pid)`, `panelMenu(pid, action)`
  - `renameDashboard(id)`, `deleteDashboard(id)`
  - `localStorage['tdc.dashboard.page']`

- [ ] **Step 1: Failing tests** in `tests/test_dashboards_ui.py`

```python
def test_the_page_bar_switches_and_remembers():
    # SERVICES und je ein Dashboard als Knopf, dahinter '+ NEW';
    # setDashboardPage schreibt tdc.dashboard.page, versteckt .dashboard-body
    # und zeigt .dashboard-own; ein gespeichertes, nicht mehr vorhandenes
    # Dashboard faellt auf SERVICES zurueck; ein Name mit '<script>' bleibt Text

def test_the_panels_load_one_after_the_other():
    # drei Kacheln, verzoegerte Antworten: nie mehr als eine Anfrage offen,
    # die zweite beginnt erst nach der ersten Antwort,
    # vor dem Lauf stehen 'Queued', waehrenddessen 'Loading…';
    # eine Tabellenkachel fragt mit limit=200, eine Bildkachel mit limit=1000

def test_one_panel_refreshes_alone_and_an_error_stays_local():
    # refreshPanel schickt genau eine Anfrage;
    # eine Kachel mit 400 zeigt die Meldung des Servers als Text,
    # die anderen behalten ihre Zahlen; die Uhrzeit im Kopf steht an jeder Kachel;
    # Refresh der Kopfzeile laedt auf einer eigenen Seite alle Kacheln neu,
    # auf SERVICES keine

def test_a_form_that_no_longer_fits_falls_back_to_the_table():
    # gespeichert 'pie', Antwort ['a','b','c'] nur Text ->
    # Tabelle plus Zeile 'saved as pie, which needs one name and one number column'

def test_switching_away_aborts_what_is_running():
    # Wechsel der Unterseite und switchTab brechen laufende Anfragen ab;
    # eine Antwort, die danach kommt, zeichnet nichts

def test_the_panel_menu_does_what_it_says():
    # Open in LOGS -> switchTab('logs') mit Abfrage und Zeitraum
    # Rename / Change form / Move up / Move down -> genau ein PATCH mit dem Feld
    # Delete -> Rueckfrage, dann DELETE, danach wird die Liste neu geholt
    # (jedes Schreiben holt die Liste neu, damit ein zweiter Tab nicht mit
    #  einer veralteten weiterarbeitet)
    # Rename und Delete des Dashboards liegen am '⋯' des offenen Dashboards,
    # die Rueckfrage nennt die Zahl der Kacheln

def test_both_themes_style_the_pages_and_the_tiles():
    # Regeln fuer .dashboard-pages, .dashboard-own und .dashboard-panel in beiden
    # Themes; zweispaltig ab 1100 px, Tabelle/Linie/Senkey ueber die ganze Breite
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** `.dashboard-pages` als Geschwister direkt unter der Kopfzeile, `.dashboard-own` neben `.dashboard-body`; `loadPanels` arbeitet eine Warteschlange ab (`for`-Schleife mit `await`), jede Anfrage mit `signal`, `limit` nach Form, Antwort nur zeichnen, wenn Seite und Lauf noch stimmen; `panelCardHtml` baut Kopf (Name, Zeitraum, Uhrzeit, `↻`, `⋯`), Körper (`logsChartHtml` oder Tabelle mit höchstens 20 Zeilen) und Fuß (Abfrage, gekürzt, ganzer Text im `title`); `refreshDashboard` ruft zusätzlich `loadPanels()`, wenn eine eigene Seite offen ist.
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`.
- [ ] **Step 5: Sichtprüfung lokal.** `dev_server.py --mock` mit einem gefüllten Store: beide Themes, 1920 und 1280 px, eine Kachel je Form, eine kaputte Kachel, Seitenwechsel während des Ladens. PNGs lesen.
- [ ] **Step 6: Commit** `feat(dashboards): own dashboard pages with tiles`.

---

### Task 7: Doku, Hilfe, Screenshot, Prüfung auf der VM

**Files:**
- Modify: `README.md` (Abschnitt „## Logs" um Befehlskarte und Formen, neuer Abschnitt „### Own dashboards" im Dashboard-Teil, Demo-Bild)
- Modify: `webui/templates/index.html` (Hilfe: Overview, Usage Guide bei Dashboard und LOGS, Asset-Versionen)
- Create: `static/dashboards.png`
- Test: `tests/test_docs.py` bleibt grün

- [ ] **Step 1: Gesamtprüfung auf der VM.** Deploy, dann mit echten Daten: Befehlskarte (Einfügen, Klappen, schmales Fenster), alle fünf Formen, Warnzeile bei einer großen Gruppenliste, Speichern in ein neues und ein vorhandenes Dashboard, Seitenwechsel, Nachladen oben und an der Kachel, Kachel-Menü samt Umbenennen und Löschen, Dashboard umbenennen und löschen, zwei Browser-Tabs am selben Dashboard. Beide Themes, 1920 und 1280 px. Zeit bis zur fertigen Seite mit acht Kacheln messen. Jedes PNG lesen.
- [ ] **Step 2: Screenshot** `static/dashboards.png`: Cyberpunk, 1920×960, ein eigenes Dashboard mit vier Kacheln (Kreis, Balken, Linie, Senkey), ohne offene Menüs.
- [ ] **Step 3: Doku** schreiben; `webui/.venv/bin/python -m pytest tests/test_docs.py tests/test_dashboards.py tests/test_logs_ui.py tests/test_dashboards_ui.py -q`; die volle Suite je einmal unter `TZ=UTC` und `TZ=Europe/Berlin`; `make -s unit-test`.
- [ ] **Step 4: Commit** `docs: the commands card, result forms and own dashboards`.
