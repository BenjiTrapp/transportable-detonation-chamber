# Zweites Theme „Cyberpunk“ – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein zweites, sofort umschaltbares Theme „Cyberpunk“ (Kopfleiste, Schublade, Neon-Karten) neben „Classic“, dazu Karten-Bedienelemente ((i), CHART/TABLE, Sortieren, anklickbare Kacheln) und ein neuer Tab „Alerts“ in beiden Themes.

**Architecture:** Ein gemeinsames DOM; `data-theme` am `<html>` wählt das Theme. Alle Farben kommen aus CSS-Variablen (Classic-Werte in `:root` von `style.css`, Cyberpunk-Werte und -Layout in `theme-cyberpunk.css`, vollständig unter `[data-theme="cyberpunk"]`). Beim Umschalten hängt `app.js` nur Tab-Leiste und Dienststatus zwischen Seitenleiste und Kopfleiste um und löst `tdc:themechange` aus; Canvas-Grafiken zeichnen sich darauf neu.

**Tech Stack:** Vanilla JS (`webui/static/js/app.js`, kein Build-Schritt), CSS, Flask-Template `webui/templates/index.html`, pytest + Node für Frontend-Tests, Headless Chrome für Sichtprüfung.

**Spec:** `docs/superpowers/specs/2026-11-09-cyberpunk-theme-design.md`

## Global Constraints

- Keine neuen Abhängigkeiten; JavaScript bleibt in `app.js` (Tests ziehen Funktionen per `_function_source` aus dieser Datei).
- Theme-Werte `classic` | `cyberpunk`; Anzeigenamen „Classic“, „Cyberpunk“; `localStorage`-Schlüssel `tdc-theme`; ohne gültigen Wert gilt `classic`.
- Ereignis `tdc:themechange` auf `document`, `detail: {theme}`.
- Classic sieht exakt aus wie heute; einzige sichtbare Neuerungen: ✶-Knopf, (i), CHART/TABLE, Sortier-Anzeige, Tab „Alerts“, anklickbare Kacheln.
- Original-Logo `webui/static/icon.png` unverändert in beiden Themes.
- Cyberpunk-Werte (aus der Spec): Hintergrund `#0b0716` + Gitter 28 px `rgba(255,79,216,.045)` + radiale Scheine Magenta `.22` / Amber `.10`; Kopfleiste `#170e2c` → `#120a22`, unten `1px rgba(255,79,216,.5)`, Schatten `0 1px 0 rgba(255,79,216,.25), 0 8px 28px rgba(255,79,216,.12)`; Karte `#140d24`, Rand `1px rgba(255,79,216,.22)`, Radius 6 px, Schatten `0 0 0 1px rgba(0,0,0,.35), 0 8px 24px -16px rgba(255,79,216,.35)`; erhöht `#1b1232`; Trennlinien `#251a3d`; Text `#f3eefc` / `#c9bfe3` / `#8a7fb0`; Akzent `#ff4fd8`, Glow `0 0 14px rgba(255,79,216,.35)`, Text darauf `#12081f`; Überschrift-Verlauf `#ffd060` → `#ffb000` 45 % → `#ff3b3b`; Cyan `#37e0ff`; Grün `#39d98a`; Schweregrade critical `#ff3b3b` (Kachelkante `#d03b3b`), high `#ff7a1a`, medium `#ffb000`, low `#39d98a`, info `#37e0ff`; Schrift Labels/Titel/Navigation `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` 10.5–12 px, Sperrung 0.05–0.12 em, Großbuchstaben; Fließtext `system-ui, -apple-system, "Segoe UI", sans-serif` 14 px; Kennzahlen 28 px / 600.
- Name und Adresse der internen Vorbild-Seite stehen nirgends im Repo.
- Oberfläche und README auf Englisch; Werte aus Daten immer über `escapeHtml` / `jsArg` / `jsInt` / `cssToken` bzw. `textContent`.
- Jede Frontend-Änderung erhöht `app.js?v=` bzw. `style.css?v=` (und `theme-cyberpunk.css?v=`) in `index.html`.

## Review Focus

1. **Umschalten mitten in der Arbeit** – offene Detailansicht, angezeigter Graph, laufende Pipes-Sitzung, gesetzte Filter: nach ✶ ist alles noch da, keine doppelten Intervalle oder Listener, kein Neuladen (statischer Test in Task 3, Sichtprüfung in Task 9).
2. **Lange oder bösartige Texte in neuen Teilen** – Regel- und Prozessnamen mit `<img onerror>` oder 300 Zeichen in Alerts-Tab, Info-Popover, Kopfleiste: escaped, mit Ellipse statt Layoutbruch (Node-Test in Task 6).
3. **Schmale Fenster (1280 px) in Cyberpunk** – Tabs passen nicht in die Kopfleiste: überzählige wandern ins „…“-Menü, Kopfleiste bricht nicht um (Node-Test in Task 4, Sichtprüfung in Task 9).
4. **Sortieren in Tabellen, die per Polling neu gerendert werden** (Pipes-Events, Sysmon, Alerts) – Sortierung bleibt nach dem Neurendern, Zahlen numerisch, Zeiten chronologisch, leere Zellen zuletzt (Node-Test in Task 7).
5. **Erster Aufruf mit leerem, ungültigem oder gesperrtem `localStorage`** – Classic, keine Ausnahme, kein Flackern (Node-Test und statischer Test in Task 3).

---

## Dateistruktur

| Datei | Verantwortung |
|---|---|
| `webui/static/css/style.css` | Classic-Werte aller Farben als Variablen in `:root`; keine Farb-Literale außerhalb von `:root` |
| `webui/static/css/theme-cyberpunk.css` (neu) | Cyberpunk-Variablen, Layout (Kopfleiste, Schublade) und Komponenten-Stil, alles unter `[data-theme="cyberpunk"]` |
| `webui/static/js/app.js` | `themeColor`, Theme-Umschaltung, Schublade, Tab-Überlauf, Dienste-Aufklappfeld, Alerts-Tab, Info-Popover, Sortierung, CHART/TABLE, Kachel-Sprünge |
| `webui/templates/index.html` | Kopf-Skript gegen Flackern, `#topbar`, ✶-Knöpfe, Tab „Alerts“, `data-info`-Texte, Stylesheet-Link |
| `scripts/deploy-utm.py`, `Makefile`, `make.ps1` | `theme-cyberpunk.css` mit ausliefern |
| `tests/test_theme.py` (neu) | Farb-Literale, Scoping, Umschaltung, Überlauf, Sortierung, CHART/TABLE, Info-Texte |
| `tests/test_frontend.py`, `tests/test_docs.py` | bestehende Prüfungen; Deploy-Test um statische Assets erweitert |
| `README.md`, Hilfe-Modal | Themes, Bedienelemente, Alerts-Tab, Screenshot |

---

### Task 1: Classic-Farben als Variablen in `style.css`

**Files:**
- Modify: `webui/static/css/style.css` (`:root` ab Zeile 4 und alle Farb-Literale danach: ~312 Hex, ~461 `rgba()`, 15 Verläufe)
- Test: `tests/test_theme.py` (neu)

**Interfaces:**
- Produces: Für jede bisher literal verwendete Farbe eine Variable in `:root`, Präfix `--c-` (Name nach Farbton und Stufe, z. B. `--c-amber-400: #fbbf24`), vorhandene Variablen werden wiederverwendet, wo der Wert gleich ist (`#ef4444` → `--accent-red`). Für Farben mit Alpha-Varianten zusätzlich ein Tripel `--c-<name>-rgb: 251, 191, 36`, verwendet als `rgba(var(--c-<name>-rgb), 0.15)`. Weiß/Schwarz: `--c-white-rgb: 255, 255, 255`, `--c-black-rgb: 0, 0, 0`. Task 5 überschreibt genau diese Namen.

- [ ] **Step 1: Failing test** `test_style_css_has_no_literal_colors_outside_root`: liest `style.css`, entfernt Kommentare und den ersten `:root { … }`-Block, und prüft, dass weder `#[0-9a-fA-F]{3,8}\b` noch `rgba?\(\s*[\d.]` vorkommt (erlaubt bleibt `rgba(var(--…-rgb), a)`). Meldet die ersten 20 Fundstellen mit Zeilennummer.
- [ ] **Step 2:** `webui/.venv/bin/python -m pytest tests/test_theme.py -q` → FAIL mit Fundliste.
- [ ] **Step 3:** Literale durch Variablen ersetzen (ein einmaliges Hilfsskript ist erlaubt, wird nicht committet).
- [ ] **Step 4: Gleichheit belegen:** Wegwerf-Skript löst in der neuen `style.css` jedes `var(--x)` und `rgba(var(--x-rgb), a)` mit den `:root`-Werten auf und vergleicht normalisiert (Kleinschreibung, Leerzeichen in `rgba()`, `0.15` = `.15`) Deklaration für Deklaration mit `git show HEAD:webui/static/css/style.css`. Erwartet: `0 differences`. Ausgabe in den Bericht.
- [ ] **Step 5:** Test grün; `make -s unit-test` grün; `style.css?v=` erhöhen.
- [ ] **Step 6: Commit** `refactor(css): classic colours as variables`

### Task 2: Farben in `app.js` aus dem Theme

**Files:**
- Modify: `webui/static/js/app.js` (191 Farb-Literale, v. a. `renderGraph`, `renderDetectionOverview`, `renderIsometricGraph`, `_isoNodeStyle`, `openAlertDetail`, `renderRtraceTimeline`, `renderLitterboxFiles`, `openProcessDetail`, `_isoActivityIcons`, `showGraphDetail`, `renderPeAnalysis`, Konstante bei Zeile ~840 mit Engine-Farben), `webui/static/css/style.css` (`:root`: neue Variablen `--graph-*`, `--engine-*`, `--pe-*`, `--assess-*` mit den heutigen Werten)
- Test: `tests/test_theme.py`

**Interfaces:**
- Consumes: `--c-*`-Variablen aus Task 1.
- Produces: `themeColor(name: string, alpha?: number) -> string` – liest `getComputedStyle(document.documentElement).getPropertyValue(name).trim()`; mit `alpha` aus `name + '-rgb'` → `rgba(r, g, b, alpha)`; Cache pro Theme, geleert bei `tdc:themechange`. Listener auf `tdc:themechange`, der `renderGraph()` (wenn Graph-Tab aktiv), `renderTimeline()`, `renderDashboard()` und die Tracing-Grafiken neu zeichnet. Inline-Styles in HTML-Strings nutzen `var(--…)` direkt statt `themeColor`.

- [ ] **Step 1: Failing tests:**
  - `test_app_js_has_no_literal_colors`: Kommentare entfernen; kein `#[0-9a-fA-F]{3,8}\b` (außer in `&#\d+;`-Entities und HTML-Ankern) und kein `rgba?\(\s*\d` in `app.js`.
  - `test_theme_color_reads_css_variables` (Node): `globalThis.getComputedStyle = () => ({getPropertyValue: n => ({'--accent-red': ' #ef4444', '--accent-red-rgb': '239, 68, 68'})[n] || ''})`, `document = {documentElement: {}}`; erwartet `themeColor('--accent-red') === '#ef4444'` und `themeColor('--accent-red', 0.2) === 'rgba(239, 68, 68, 0.2)'`.
- [ ] **Step 2:** Tests laufen lassen → FAIL.
- [ ] **Step 3:** `themeColor` implementieren, Literale ersetzen, Variablen in `:root` ergänzen, Listener registrieren.
- [ ] **Step 4:** Tests grün; `node --check webui/static/js/app.js`; `make -s unit-test`; Asset-Versionen erhöhen.
- [ ] **Step 5: Sichtprüfung Classic:** Deploy (`python3 scripts/deploy-utm.py --vm-ip 192.168.64.4 --vm-user tdc --vm-pass tdc --restart`), Headless-Chrome-Screenshots von Graph (Baum + isometrisch), Tracing, PE-Analyse im Hex-Tab: Farben wie vorher.
- [ ] **Step 6: Commit** `refactor(ui): canvas and inline colours from theme variables`

### Task 3: Theme-Umschaltung und Kopfleisten-Gerüst

**Files:**
- Create: `webui/static/css/theme-cyberpunk.css` (nur Kopfkommentar und `[data-theme="cyberpunk"] {}`; Inhalte in Task 4/5)
- Modify: `webui/templates/index.html` (Kopf-Skript, Stylesheet-Link, `#topbar`, ✶-Knopf in `.sidebar-header`), `webui/static/js/app.js`, `scripts/deploy-utm.py`, `Makefile` (beide Deploy-Blöcke), `make.ps1`
- Test: `tests/test_theme.py`, `tests/test_docs.py::test_every_deploy_path_uploads_the_web_ui_modules`

**Interfaces:**
- Produces:
  - Inline-Skript im `<head>` vor dem ersten Stylesheet: setzt `document.documentElement.dataset.theme` aus `localStorage['tdc-theme']` (`cyberpunk` sonst `classic`), alles in `try/catch`.
  - Markup `<header id="topbar">` mit `#drawer-toggle` (Text `☰ PROCESSES`, darin `#drawer-count`), Logo (`/static/icon.png`) und Schriftzug, `#topbar-nav`, `#topbar-services` (Knopf) mit `#topbar-services-panel`, `#topbar-time`, Help-Knopf, `#theme-toggle-top`. In Classic per CSS `display: none` (Regel in `style.css`: `#topbar { display: none; }`).
  - `#theme-toggle` in `.sidebar-header` neben „? Help“.
  - JS: `THEMES = ['classic', 'cyberpunk']`; `normalizeTheme(value) -> 'classic'|'cyberpunk'`; `nextTheme(theme) -> string`; `currentTheme() -> string`; `setTheme(name)` (setzt `data-theme`, speichert in `try/catch`, ruft `applyThemeLayout`, aktualisiert `title`/`aria-label` beider ✶-Knöpfe auf „Switch to Cyberpunk theme“ bzw. „Switch to Classic theme“, löst `tdc:themechange` aus); `toggleTheme()`; `applyThemeLayout(theme)` hängt `nav.sidebar-tabs` in `#topbar-nav` bzw. zurück hinter `.logo-container`, und `#service-status` in `#topbar-services-panel` bzw. zurück ans Ende von `#sidebar`. Aufruf `applyThemeLayout(currentTheme())` im `DOMContentLoaded` vor `initTabs()`.

- [ ] **Step 1: Failing tests:**
  - `test_normalize_and_next_theme` (Node): `normalizeTheme('cyberpunk') === 'cyberpunk'`, `normalizeTheme('garbage') === 'classic'`, `normalizeTheme(null) === 'classic'`, `nextTheme('classic') === 'cyberpunk'`, `nextTheme('cyberpunk') === 'classic'`.
  - `test_theme_boot_script_runs_before_styles`: in `index.html` steht ein `<script>` mit `tdc-theme` und `try` vor dem ersten `<link rel="stylesheet"`; `theme-cyberpunk.css?v=\d+` ist verlinkt.
  - `test_theme_toggles_and_topbar_exist`: `id="theme-toggle"` und `id="theme-toggle-top"` mit `aria-label`; `id="topbar"`, `id="topbar-nav"`, `id="drawer-toggle"`, `id="topbar-services-panel"`.
  - `test_set_theme_never_reloads`: Quelltext von `setTheme`, `toggleTheme`, `applyThemeLayout` enthält weder `location.reload` noch Aufrufe von `initTabs`/`initGraphControls`/`refreshAll`.
  - `test_cyberpunk_css_is_scoped`: jede Regel in `theme-cyberpunk.css` (außer Inhalten von `@keyframes`) hat in jedem Selektor der Liste das Präfix `[data-theme="cyberpunk"]` bzw. `:root[data-theme="cyberpunk"]` – so kann die Datei Classic nie verändern.
  - `test_no_reference_site_names`: keine Datei unter `webui/`, `docs/`, `README.md`, `tests/` enthält Adresse, Organisation oder Namen der internen Vorbild-Seite (der Test kennt sie nur als SHA-256-Werte, damit auch er sie nicht veröffentlicht).
  - Deploy-Test erweitern: `webui/static/css/theme-cyberpunk.css` (und weiterhin `app.js`, `style.css`) in `deploy-utm.py`, im Vagrant- und im Hyper-V-Deploy-Block.
- [ ] **Step 2:** Tests → FAIL.
- [ ] **Step 3:** Implementieren wie oben.
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`; Asset-Versionen erhöhen.
- [ ] **Step 5: Commit** `feat(ui): theme switch and top bar skeleton`

### Task 4: Cyberpunk-Layout: Kopfleiste, Schublade, Tab-Überlauf, Dienste

**Files:**
- Modify: `webui/static/css/theme-cyberpunk.css`, `webui/static/js/app.js`, `webui/templates/index.html` (Scrim `#drawer-scrim`, „…“-Menü `#topbar-more`)
- Test: `tests/test_theme.py`

**Interfaces:**
- Consumes: `setTheme`, `applyThemeLayout`, Markup aus Task 3.
- Produces:
  - CSS: Kopfleiste fixiert oben, 56 px; `#main-content` volle Breite darunter; `#sidebar` wird Schublade (fest links, Breite 320 px, Start unter der Kopfleiste, verschoben aus dem Bild); offen, wenn `#app.drawer-open`; Scrim dunkelt den Inhalt ab. Kopfleisten-Stil, Navigation als Schalterleiste (aktiver Tab Magenta mit Glow) nach den Global Constraints.
  - JS: `openDrawer()`, `closeDrawer()`, `toggleDrawer()`; schließt bei Esc, Scrim-Klick und nach `openProcessDetail(...)` (nur in Cyberpunk); `#drawer-count` spiegelt `#process-count`.
  - `computeVisibleTabs(widths: number[], available: number, moreWidth: number, activeIndex: number) -> number[]` (Indizes der sichtbaren Tabs; der aktive bleibt immer sichtbar; ist Überlauf nötig, wird `moreWidth` reserviert); `updateTabOverflow()` setzt die Klasse `tab-overflow` und füllt `#topbar-more` mit Menüeinträgen (Text per `textContent`, Klick → `switchTab`); läuft über `ResizeObserver` und nach `switchTab`, nur in Cyberpunk.
  - `updateTopbarServices()`: `#topbar-services` zeigt Punkt + `n/m ONLINE` (Zählung wie `updateServiceStatus`), Klick klappt `#topbar-services-panel` auf, Esc/Außenklick schließt. `#topbar-time` läuft mit der vorhandenen Dashboard-Uhr.
- [ ] **Step 1: Failing test** `test_compute_visible_tabs` (Node): `computeVisibleTabs([100,100,100,100], 450, 40, 0)` → `[0,1,2,3]`; `computeVisibleTabs([100,100,100,100], 330, 40, 0)` → `[0,1]`; mit `activeIndex = 3` → `[0,3]`; `available` 0 → nur `[activeIndex]`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren.
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`; Asset-Versionen erhöhen.
- [ ] **Step 5: Sichtprüfung:** Deploy + Neustart; Headless Chrome mit `localStorage['tdc-theme'] = 'cyberpunk'` bei 1920 × 960 und 1280 × 800: Kopfleiste einzeilig, „…“ bei 1280 mit den übrigen Tabs, Schublade öffnet/schließt (Knopf, Esc, Scrim, Prozess-Klick), Dienste-Aufklappfeld. Screenshots lesen. Zurück auf Classic: Seitenleiste wie vorher.
- [ ] **Step 6: Commit** `feat(ui): cyberpunk layout with drawer and top bar`

### Task 5: Cyberpunk-Stil für alle Komponenten

**Files:**
- Modify: `webui/static/css/theme-cyberpunk.css`
- Test: `tests/test_theme.py`

**Interfaces:**
- Consumes: alle Variablennamen aus Task 1 und 2 (`--bg-*`, `--text-*`, `--accent-*`, `--severity-*`, `--c-*`, `--graph-*`, `--engine-*`, `--pe-*`, `--assess-*`, `--font-*`).
- Produces: Cyberpunk-Werte für jede dieser Variablen; Stil für Hintergrund (Gitter, Scheine), `.content-header` als Kopfbereich (Kicker-Zeile `TDC // DETONATION CHAMBER` per `::before`, grün, Monospace; `h2` mit Verlauf; Untertitel gedämpft), Karten, Kennzahl-Kacheln (`.stat-card` mit 3 px Kante nach Schweregrad), Abschnittstitel, Tabellen (Kopf Cyan auf `#1b1232`, Trennlinien `#251a3d`), Knöpfe, Eingabefelder, Badges, Detailansicht, Hilfe-Modal, Toasts, Graph-Detailansicht, Hex-Editor, Pipes-Tab. Tracing und Graph haben keinen `.content-header`: deren vorhandene Kopfzeilen nur umgestalten.
- [ ] **Step 1: Failing test** `test_cyberpunk_sets_every_palette_variable`: `theme-cyberpunk.css` setzt jede Variable, die `style.css` in `:root` definiert (`--bg-*`, `--text-*`, `--accent-*`, `--severity-*`, `--c-*`, `--graph-*`, `--engine-*`, `--pe-*`, `--assess-*`); fehlende werden aufgelistet. `test_cyberpunk_css_is_scoped` (Task 3) bleibt grün.
- [ ] **Step 2:** → FAIL (Variablen fehlen noch).
- [ ] **Step 3:** Stil schreiben.
- [ ] **Step 4:** Test grün; `make -s unit-test`; Version erhöhen.
- [ ] **Step 5: Sichtprüfung:** Deploy; jeder Tab in Cyberpunk bei 1920 × 960 als Screenshot, zusätzlich offene Alert-Detailansicht, Detonationsergebnis, Hilfe. Jeden Screenshot lesen: keine Fläche in Classic-Blau, Text überall lesbar, Graph-Knoten unterscheidbar. Classic stichprobenartig unverändert.
- [ ] **Step 6: Commit** `feat(ui): cyberpunk styling`

### Task 6: Tab „Alerts“

**Files:**
- Modify: `webui/templates/index.html` (Tab-Knopf nach Dashboard, `#tab-alerts` mit `.content-header`, Filterleiste, Tabelle `#alerts-table`; Hilfe-Tab-Übersicht: Eintrag „Alerts“ nach Dashboard), `webui/static/js/app.js`, `webui/static/css/style.css` (+ Cyberpunk-Ergänzung in `theme-cyberpunk.css`), `README.md` (Tab-Tabelle: Zeile `| **Alerts** | … |` nach Dashboard)
- Test: `tests/test_theme.py`, `tests/test_docs.py` (bestehend)

**Interfaces:**
- Consumes: `state.alerts`, `openAlertDetailById(id)`, `openProcessDetail(key)`, `procKey`.
- Produces:
  - `filterAlerts(alerts, filter) -> alert[]` mit `filter = {severities: string[], engine: string, text: string}`; leere Liste/leerer String = kein Filter; Text sucht case-insensitiv in `rule_name`, Prozessname, Beschreibung; Ergebnis neueste zuerst.
  - `alertRowsHtml(alerts) -> string` (Zeilen: Zeit, Schweregrad-Badge mit `cssToken`, Engine, Regel, Prozess als Link `openProcessDetail(jsArg(key))`, Kurzbeschreibung; Zeilenklick `openAlertDetailById(jsArg(id))`; höchstens 2000 Zeilen, darüber Hinweis „Showing newest 2000 of n“).
  - `openAlertsTab(filter = {})` setzt Filter-UI und wechselt den Tab; `renderAlertsTab()` läuft beim Tab-Wechsel und nach `refreshAlerts`, wenn der Tab aktiv ist. Schweregrad-Chips critical/high/medium/low/info (Mehrfachauswahl), Engine-Auswahl aus den vorhandenen Engines, Textfeld, Anzeige „n of m“.
- [ ] **Step 1: Failing tests:**
  - `test_filter_alerts` (Node): Fixture mit 4 Alerts (critical sigma, high yara, low fibratus, medium sigma mit `rule_name` „Mimikatz“); `{severities:['critical','high']}` → 2; `{engine:'sigma'}` → 2; `{text:'mimi'}` → 1; `{}` → 4, neueste zuerst.
  - `test_alert_rows_escape_hostile_values` (Node): Alert mit `rule_name: '<img src=x onerror=alert(1)>'`, `severity: 'high" onmouseover="x'`, Prozessname mit 300 Zeichen → Ausgabe enthält kein `<img`, kein `onmouseover=`, Prozessname escaped.
  - `test_alerts_tab_is_wired`: `data-tab="alerts"` steht direkt nach `data-tab="dashboard"`; `id="tab-alerts"`, `id="alerts-table"`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren; README-Zeile und Hilfe-Eintrag ergänzen.
- [ ] **Step 4:** Tests grün inkl. `tests/test_docs.py`; `node --check`; `make -s unit-test`; Versionen erhöhen.
- [ ] **Step 5: Commit** `feat(ui): alerts tab`

### Task 7: (i)-Erklärungen und sortierbare Tabellen

**Files:**
- Modify: `webui/templates/index.html` (`data-info` an Überschriften), `webui/static/js/app.js` (Tabellen-Markup und Render-Funktionen), `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`
- Test: `tests/test_theme.py`

**Interfaces:**
- Produces:
  - Info: Überschriften tragen `data-info="…"` (Englisch, 1–2 Sätze, ≤ 300 Zeichen, kein `<`); `initInfoButtons(root = document)` fügt hinter jedes noch nicht versehene `[data-info]` einen `<button class="info-btn" type="button" aria-label="Explain">i</button>` ein; ein gemeinsames `#info-popover` zeigt den Text per `textContent`; Esc/Außenklick schließt. Für per JS gerenderte Karten wird `initInfoButtons(container)` nach dem Rendern aufgerufen.
  - Sortieren: Tabellen mit `data-sortable data-sort-id="<eindeutig>"`; Zellen optional `data-sort-value`; `compareSortValues(a, b) -> number` (beide Zahlen → numerisch; beide als Zeit parsebar (ISO oder `HH:MM:SS`) → chronologisch; sonst case-insensitiv; leere Werte immer zuletzt, unabhängig von der Richtung); `sortRows(rows, col, dir) -> rows` stabil; Klick-Delegation auf `table[data-sortable] th` (aufsteigend → absteigend), Zustand `tableSortState[sortId] = {col, dir}`; `reapplyTableSorts(root)` sortiert nach jedem Neurendern erneut (ein `MutationObserver` mit Schutz gegen Selbstauslösung oder explizite Aufrufe in den Render-Funktionen, Wahl des Implementierers); `aria-sort` am `th`, Anzeige ↕/▲/▼ per CSS.
- [ ] **Step 1: Failing tests:**
  - `test_compare_sort_values` (Node): `['10','9','100']` aufsteigend → `9,10,100`; `['10:00:05','09:59:00']` → `09:59:00` zuerst; `['beta','Alpha']` → `Alpha,beta`; `['', '3', '1']` aufsteigend und absteigend → `''` jeweils zuletzt; `sortRows` stabil bei Gleichstand.
  - `test_every_data_table_is_sortable`: jedes `<table` in `index.html` und `app.js` hat `data-sortable` oder steht in `SORT_EXEMPT` (Liste im Test mit Grund je Eintrag, z. B. Hilfe-Tabellen, Hex-Raster, Schlüssel-Wert-Tabellen der Detailansicht).
  - `test_info_texts_cover_every_tab`: jeder `.content-header` in `index.html` sowie die Kopfzeilen von Tracing und Graph enthalten ein `[data-info]`; alle `data-info`-Werte nicht leer, ≤ 300 Zeichen, ohne `<`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren; Erklärtexte schreiben (Quelle: Hilfe-Modal, README).
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`; Versionen erhöhen.
- [ ] **Step 5: Sichtprüfung:** Deploy; Pipes-Events und Sysmon-Tabelle sortieren, 30 s warten (Polling) → Sortierung bleibt; (i) in beiden Themes.
- [ ] **Step 6: Commit** `feat(ui): explanations and sortable tables`

### Task 8: CHART/TABLE und anklickbare Kacheln

**Files:**
- Modify: `webui/static/js/app.js` (`renderTimeline`, `renderRtraceTimeline`, Severity-Leiste um Zeile ~781, `renderDetectionOverview`, `renderPeAnalysis`, `renderDashboard`), `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`
- Test: `tests/test_theme.py`

**Interfaces:**
- Consumes: `openAlertsTab(filter)` (Task 6), `openDrawer()` (Task 4), `currentTheme()` (Task 3), `openHelp()`, `switchTab()`.
- Produces:
  - `viewToggleHtml(id) -> string` (Knopf `.view-toggle`, Text „TABLE“ in der Diagrammansicht, „CHART“ in der Tabellenansicht), `toggleCardView(id)`, `isTableView(id) -> boolean`; Zustand `cardViewState[id]` bis zum Neuladen. Tabellenansichten (sortierbar nach Task 7): Seitenleisten-Zeitleiste (Zeit, Schweregrad, Regel je Alert), Tracing-Zeitleiste (Ereignistyp, Anzahl), Tracing-Severity-Leiste (Schweregrad, Anzahl), DIE-Übersicht (Abschnitt, Größe, Entropie, Bewertung), PE-Abschnittskarte (Name, Größe, Entropie, Rechte).
  - Kacheln in `renderDashboard`: `.stat-card` mit `role="button" tabindex="0"`, Enter/Klick: TOTAL ALERTS → `openAlertsTab({})`, Tag „high“ → `openAlertsTab({severities:['critical','high']})`, „med“ → `['medium']`, „low“ → `['low','info']` (Tag-Klick stoppt die Weitergabe); PROCESSES TRACKED → `revealProcessList()` (Classic: `#process-list-section` in den Blick scrollen und kurz hervorheben; Cyberpunk: `openDrawer()`); SERVICES ONLINE → `#dashboard-grid` in den Blick scrollen; DETECTION RULES → `openHelp()` und zum Abschnitt mit den Detection Rules springen; SCANNER TOOLS → `switchTab('threatscan')`.
- [ ] **Step 1: Failing tests:**
  - `test_card_view_toggle` (Node): Start `isTableView('timeline') === false`; nach `toggleCardView('timeline')` true; `viewToggleHtml('timeline')` enthält „CHART“.
  - `test_chart_cards_have_view_toggle`: die Quelltexte von `renderTimeline`, `renderRtraceTimeline`, `renderDetectionOverview`, `renderPeAnalysis` und der Severity-Leisten-Funktion rufen `viewToggleHtml(` auf.
  - `test_dashboard_tiles_open_their_views`: Quelltext von `renderDashboard` enthält `openAlertsTab(`, `revealProcessList(`, `switchTab('threatscan')`, `openHelp(` und `role="button"`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren.
- [ ] **Step 4:** Tests grün; `node --check`; `make -s unit-test`; Versionen erhöhen.
- [ ] **Step 5: Commit** `feat(ui): chart/table views and clickable tiles`

### Task 9: Doku, Screenshots, Ende-zu-Ende auf der VM

**Files:**
- Modify: `README.md` (Abschnitt „### Themes“ unter Features: Umschalten mit ✶, Speicherung im Browser, Cyberpunk-Aufbau, Bedienelemente; Demo-Bild), `webui/templates/index.html` (Hilfe: ✶-Knopf und Bedienelemente kurz erklären)
- Create: `static/theme_cyberpunk.png` (Dashboard in Cyberpunk, 1920 × 960, Schublade geschlossen), `static/alerts_tab.png` (Alerts-Tab mit Filter, Classic)
- Test: `tests/test_docs.py` (bestehend)

- [ ] **Step 1:** Deploy + Neustart (`python3 scripts/deploy-utm.py --vm-ip 192.168.64.4 --vm-user tdc --vm-pass tdc --restart`).
- [ ] **Step 2: Ende-zu-Ende (Headless Chrome gegen `http://192.168.64.4:9000`):**
  - jeder Tab in beiden Themes ohne Seitenfehler (`pageerror`/Konsolenfehler);
  - ✶ bei offener Alert-Detailansicht, bei angezeigtem Graph (isometrisch) und bei laufender Pipes-Sitzung (`attach` auf eine Test-Pipe): danach Detailansicht offen, Graph gleich, Sitzung pollt genau einmal pro Sekunde weiter, Filter im Alerts-Tab erhalten;
  - Neuladen in Cyberpunk: kein Classic-Aufblitzen (Screenshot direkt nach `domcontentloaded`);
  - `localStorage['tdc-theme'] = 'xyz'` → Classic ohne Fehler;
  - 1280 × 800 in Cyberpunk: „…“-Menü, Kopfleiste einzeilig.
  - Screenshots lesen.
- [ ] **Step 3:** Screenshots für README aufnehmen, lesen, nach `static/` kopieren; README und Hilfe schreiben.
- [ ] **Step 4:** `make -s unit-test` grün (inkl. `test_docs.py`).
- [ ] **Step 5: Commit** `docs: themes, alerts tab and card controls`
