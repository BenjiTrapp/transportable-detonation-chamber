# Classic als „Telemetry“ – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:**
- Der Classic-Theme übernimmt Fensteraufteilung und Steuerung des Cyberpunk-Themes.
- Er bekommt die Farben der Seite „Glasfaser-Telemetrie“.

**Architecture:**
- **CSS:** Die Layout- und Formregeln wandern aus `theme-cyberpunk.css` in eine neue Datei `webui/static/css/theme-layout.css`, die für beide Themes gilt. Die Palette bleibt in `theme-cyberpunk.css`.
- **Classic-Farben:** Classic definiert in `style.css :root` alle Variablen, die das Layout braucht, mit der Telemetrie-Palette.
- **JS:** Die Weichen für Top-Bar, Drawer und Overflow gelten für beide Themes.

**Tech Stack:** CSS, Vanilla JS, pytest + Node.

**Spec:** `docs/superpowers/specs/2026-11-16-classic-telemetry-design.md`

## Global Constraints

- **Cyberpunk darf sich nicht verändern.** Jede Regel, die heute unter `[data-theme="cyberpunk"]` greift, greift danach mit denselben berechneten Werten. Ausnahme: Regeln, die Cyberpunk-Palettenwerte setzen, bleiben in `theme-cyberpunk.css`.
- **Farben nur als `var(--…)`:**
  - Farbwerte in `style.css` nur in `:root`.
  - `theme-cyberpunk.css` nur unter `[data-theme="cyberpunk"]`.
  - `theme-layout.css` nur unter `[data-theme]` und ohne Farbwerte, außer `transparent` und `currentColor`.
- **Keine gemeinsamen `@keyframes`-Namen** über alle drei Dateien.
- **Classic-Palette, genau diese Werte:**
  - Seite `#07080f`;
  - Panel `#0d0f1c`, Panel 2 `#121528`;
  - Linie `#23284a`, Raster `#1a1e38`;
  - Text `#e8ecff`, Text 2 `#a3abd6`, gedämpft `#6c7399`;
  - Cyan `#00e5ff`, Magenta `#ff2bd6`, Violett `#9b8cff`, Säure `#d4ff00`;
  - Warnung `#ffb000`, Alarm `#ff2b4a`, Orange `#ff7a1a`.
- **Kontrast:** Fließtext mindestens 4.5:1 gegen die Seite und die Panels.
- **Angezeigter Name** des Themes ist `Telemetry`; die ID bleibt `classic`. `localStorage` `tdc-theme` bleibt.
- **Effekte:** Scanlines und Raster mit `pointer-events: none`. Mit `prefers-reduced-motion` gibt es keine Animationen.
- **Assets:** `?v=` erhöhen; `theme-layout.css` geht in alle Deploy-Wege (`deploy-utm.py` FILES, Makefile `deploy`, `make.ps1`; `test_every_deploy_path_uploads_the_web_ui_modules`) und wird in `index.html` nach `style.css` und vor `theme-cyberpunk.css` geladen.
- **Sprache:** Oberfläche, README und Kommentare englisch. Die CI läuft unter `TZ=UTC` und `TZ=Europe/Berlin`. Tests mit `make -s unit-test`.

## Review Focus

1. **Cyberpunk unverändert:** Ein Test vergleicht, für eine Auswahl von Selektoren, die Deklarationen vor und nach der Teilung (Task 1).
2. **Theme-Wechsel zur Laufzeit:** Tabs, Status und Drawer bleiben an Ort und Stelle, und es gibt keinen doppelten Überlauf (Task 1).
3. **Lesbarkeit:** Ein Kontrast-Test für die Textvariablen (Task 2).
4. **Diagramme und Graph** zeigen in Telemetry unterscheidbare Farben (Task 2).
5. **Klicks gehen nicht verloren:** Die Overlay-Effekte bekommen `pointer-events: none` (Task 2).

---

### Task 1: Layout für beide Themes

**Files:**
- Neu: `webui/static/css/theme-layout.css`.
- Ändern:
  - `theme-cyberpunk.css`, `style.css` (Classic-Aliase für die `--cp-*`, die das Layout braucht; vorerst mit Cyberpunk-gleichen Rollen, aber Classic-Werten aus der bisherigen Classic-Palette);
  - `index.html` (Link, `?v=`);
  - `app.js` (Weichen an `app.js:174, 218, 246, 328, 2913, 7458` gelten immer; `THEME_LABELS.classic = 'Telemetry'`);
  - die Deploy-Wege;
  - Tests in `tests/test_theme.py` und `tests/test_docs.py`.

**Interfaces – Produces:** `theme-layout.css` mit Präfix `[data-theme]`; jede Variable, die es nutzt, ist in beiden `:root` definiert.

**Schritte:**
- [ ] **Step 1: Failing tests:**
  - `test_layout_css_is_scoped_and_colourless`;
  - `test_every_layout_variable_is_defined_in_both_themes`;
  - `test_classic_uses_the_topbar_layout`: In Node verschiebt `setTheme('classic')` die Tabs in `#topbar-nav`, und das Overflow-Menü wird gebaut;
  - `test_cyberpunk_rules_unchanged`: Für eine Liste zentraler Selektoren wie `#topbar`, `.sidebar`, `.service-card`, `.content-header`, `.tab-btn` ergeben die Deklarationen aus `theme-layout.css` plus `theme-cyberpunk.css` dieselbe Menge wie die Datei aus `git show e11a9dd:webui/static/css/theme-cyberpunk.css`, wenn man den Präfix normalisiert. Die alte Datei als Fixture unter `tests/samples/theme-cyberpunk-e11a9dd.css` ablegen.
  - Bestehende Tests, die die Sidebar in Classic voraussetzen, umschreiben. Grund im Test-Kommentar.
- [ ] **Step 2:** FAIL. **Step 3:** Umsetzen. Visuell mit `make run` prüfen: Classic hat jetzt die Top-Bar. **Step 4:** `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(theme): classic uses the topbar layout`.

### Task 2: Telemetry-Palette und Effekte

**Files:** `style.css` (`:root` mit der Palette aus den Global Constraints, alle Classic-Variablen inklusive `*-rgb`, Severities, `--c-*`, `--graph-*`, `--skull-*`, `--logs-*` und so weiter, sinnvoll aus der Palette abgeleitet), `theme-layout.css` (Effekte über Variablen, z. B. `--fx-grid`, `--fx-glow-a`, `--fx-glow-b`, `--fx-scanline`, `--panel-accent`; Cyberpunk setzt sie so, dass sein Aussehen gleich bleibt, also ohne Raster und Scanlines, wenn es die heute nicht hat), `README.md` (Classic heißt jetzt Telemetry; Hinweise zu Classic anpassen; neuer Screenshot `static/theme_telemetry.png`, aufgenommen in 1440×900 mit Testdaten oder auf der VM).

**Interfaces – Consumes:** `theme-layout.css` aus Task 1.

**Schritte:**
- [ ] **Step 1: Failing tests:**
  - `test_telemetry_uses_the_spec_values` (die Werte aus den Global Constraints);
  - `test_telemetry_text_contrast`: `--text-primary` und `--text-secondary` mindestens 4.5:1 gegen `--bg-primary`, `--bg-card` und `--bg-secondary`; `--text-muted` mindestens 3:1;
  - `test_effect_layers_ignore_pointer`;
  - `test_reduced_motion_disables_new_animations`;
  - `test_graph_node_kinds_are_distinguishable` muss für Telemetry gelten; den Test entsprechend erweitern, falls er nur Cyberpunk prüft.
  - Bestehende Palettentests (`test_cyberpunk_sets_every_palette_variable` u. a.) bleiben grün.
- [ ] **Step 2:** FAIL. **Step 3:** Umsetzen:
  - Karten mit Verlauf `--bg-secondary` → `--bg-card` und leuchtendem Akzentstrich oben links;
  - Tab-Titel im Verlauf cyan → violett → magenta;
  - Kicker in Säure-Grün;
  - aktiver Tab und primäre Knöpfe in Cyan.
  - Visuell prüfen, in beiden Themes und bei 1440 und 1280 px.
- [ ] **Step 4:** `make -s unit-test` grün.
- [ ] **Step 5: Commit** `feat(theme): telemetry palette for classic`.

### Task 3: Prüfung auf der VM (Controller)

Deploy, Screenshots in beiden Themes für Dashboard, Logs und Alerts; danach Detonator und LitterBox neu starten.
