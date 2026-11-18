# README, Doku und Wiki — Umsetzungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die README wird ein Schaufenster von etwa 400 Zeilen, die Anleitung zieht in `docs/` mit dreizehn Seiten und vier Mermaid-Diagrammen, und `make docs` baut daraus eine einzige HTML-Datei, die auch ohne Netz führt.

**Architecture:** Markdown ist die einzige Quelle. `docs/*.md` tragen die Anleitung, die README verkauft und verweist, und `scripts/build-wiki.py` (reines Python) erzeugt `webui/static/wiki.html` mit Navigation, Suche, eingebetteten Bildern und einer gepinnten Mermaid-Kopie. Die Doku-Tests ziehen mit dem Inhalt um.

**Tech Stack:** Markdown, Mermaid 10 (UMD, gepinnt), Python 3.9 (Standardbibliothek), pytest, Make und `make.ps1`.

**Spec:** `docs/superpowers/specs/2026-11-17-readme-and-docs-design.md`

## Global Constraints

- **Sprache:** README, Doku und Wiki englisch; Code-Kommentare englisch.
- **Nichts erfinden, nichts verlieren:** Jeder Abschnitt der heutigen README steht danach entweder in der README oder in einer Doku-Seite. Inhalt wird verschoben und gekürzt, nicht neu behauptet.
- **Die Seiten:** `docs/README.md` als Index und dreizehn Seiten — `setup.md`, `installation.md`, `configuration.md`, `workflow.md`, `memory.md`, `pipes.md`, `rizin.md`, `logs.md`, `updates.md`, `web-ui.md`, `api.md`, `development.md`, `troubleshooting.md`. Jede Seite beginnt mit einem Satz, was sie beantwortet, und endet mit „Next:" und einem Link.
- **Zwei Leserwege** im Index: „Set it up" (`setup` → `installation` → `configuration`) und „Work with it" (`workflow` → die Werkzeugseiten → `api`).
- **Vier Diagramme** als ```mermaid-Blöcke, jedes mit zwei bis drei Sätzen darunter, die es in Worten sagen: Architektur (README und `docs/README.md`), Detonationskette (`workflow.md`), Verdict-Bildung (`memory.md`), Rizin-Sitzung als `stateDiagram-v2` (`rizin.md`). Der Dateibaum bleibt eingerückter Text.
- **Die README behält:** Kopf und Badges, die zwei Theme-Bilder, das verlinkte Demo-Video, acht bis zehn Features mit je einem Satz und einem Bild, das Architektur-Diagramm, die Dienste-Tabelle, die Tab-Tabelle unter `### Web UI Tabs`, Quick Start in beiden Varianten, Plattform-Hinweise, die Doku-Karte, Security Notes, Credits, License.
- **Das Wiki:** eine Datei `webui/static/wiki.html`, git-ignoriert, erzeugt von `scripts/build-wiki.py`; geht als lose Datei im Browser auf (kein ES-Modul, kein `fetch`, keine Ressource über `http://` oder `https://`); Bilder als `data:`-URI (die 30 PNGs); `demo.gif` wird nur genannt und ins Repository verlinkt; Navigation aus den Überschriften; Suche im Browser; Aussehen in der Palette des Cyberpunk-Themes; Fußzeile mit Baudatum (UTC) und kurzer Commit-Kennung, wenn `git` erreichbar ist.
- **Mermaid:** Version 10 als UMD-Bündel, gepinnt unter `scripts/wiki/mermaid.min.js`, Version und SHA-256 im Generator, die MIT-Lizenz als Datei daneben und eine Zeile in den Credits. `make docs` bricht mit einer Meldung ab, wenn Datei oder Prüfsumme fehlen.
- **Der Generator:** Python 3.9, nur Standardbibliothek, keine Abhängigkeit. Markdown-Umfang: Überschriften, Absätze, Listen (auch verschachtelt), Code-Blöcke mit Sprache, Inline-Code, Fett, Kursiv, Links, Bilder, Tabellen, Blockquotes, horizontale Linien, ```mermaid. Was er nicht kennt, bleibt als Text stehen.
- **Gebaut wird auf dem Host:** `make docs` und `.\make.ps1 docs`. Die VM baut nichts; die drei Deploy-Wege laden `webui/static/wiki.html` hoch, wenn sie existiert.
- **Die Hilfe im Web-UI** bekommt einen Weg zum Wiki samt dem Datum der Datei; fehlt sie, steht dort, wie man sie baut. Die Hilfe selbst wird nicht umgebaut.
- **Tests ziehen mit:** die API-Zeilen nach `docs/api.md`, die Rizin-Zusagen nach `docs/rizin.md`, die MCP-Werkzeuge samt `(N tools` nach `docs/api.md`, der Satz über die Befehlskarte aus `tests/test_logs_ui.py` nach `docs/logs.md`. Die Tab-Tabelle und die Bilder bleiben in der README; jedes PNG in `static/` muss von der README **oder** einer Doku-Seite benutzt werden, und keines fehlen.
- **Repo-Regeln:** keine lokalen Pfade in Dateien; kein Name der früheren Vergleichs-Software des Hex-Editors und keine interne Referenz-Seite; erzeugte Dateien in `.gitignore`.
- **Tests:** `make -s unit-test` grün (Stand vor dieser Arbeit: 1219 bestanden, 1 übersprungen); die volle Suite je einmal unter `TZ=UTC` und `TZ=Europe/Berlin`; Node 20 als erste Stelle im PATH, die Fassung der CI.

## Review Focus

1. **Ein Abschnitt, der beim Umzug verschwindet** — die alte README hat 22 Abschnitte; fehlt einer danach in README und Doku, merkt es niemand. Ein Test, der die Abschnitte der alten README gegen die neue Ablage hält, fängt das (Task 2).
2. **Eine Doku-Seite, die niemand erreicht** — eine Seite ohne Link im Index, ein Link auf eine Datei, die es nicht gibt, ein „Next:" ins Leere (Task 1).
3. **Ein Wiki, das offline nicht aufgeht** — eine Ressource über `http`, ein ES-Modul, ein `fetch` auf eine Datei, ein Bild als Pfad statt als Daten: auf der VM ist alles davon tot (Task 5).
4. **Markdown, das der Generator verschluckt** — eine verschachtelte Liste, eine Tabelle mit `|` im Text, ein Code-Block mit ``` im Inneren, ein `<script>` im Markdown, eine Überschrift mit Backticks: nichts darf verloren gehen oder als HTML ausgeführt werden (Task 5).
5. **Ein Wiki, dessen Alter niemand sieht** — die Datei wird einmal gebaut und bleibt liegen, während die Doku weiterläuft; ohne Datum in der Fußzeile und neben dem Link im Web-UI liest man stillschweigend einen alten Stand (Task 6).

---

### Task 1: Die Doku-Struktur und die Einrichtungs-Hälfte

**Files:**
- Create: `docs/README.md`, `docs/setup.md`, `docs/installation.md`, `docs/configuration.md`, `docs/workflow.md`, `docs/development.md`, `docs/troubleshooting.md`
- Modify: `README.md` (die umgezogenen Abschnitte entfernen, vorläufig eine Doku-Karte einsetzen)
- Test: `tests/test_docs.py`

**Interfaces:**
- **Produces:** die Seitennamen und die Reihenfolge im Index, auf die Task 2 und der Generator aufbauen; die Form einer Seite (erster Satz, Inhalt, `**Next:** [Titel](datei.md)`).

- [ ] **Step 1: Failing tests** in `tests/test_docs.py`

```python
def test_every_docs_page_is_reachable_and_shaped():
    # jede .md unter docs/ (ausser superpowers/) ist von docs/README.md verlinkt,
    # jeder Link des Index zeigt auf eine vorhandene Datei,
    # jede Seite hat eine H1, einen Einleitungssatz und genau ein "**Next:**",
    # dessen Ziel existiert; der Index selbst braucht kein "Next:"

def test_the_index_names_both_reading_paths():
    # docs/README.md nennt "Set it up" mit setup/installation/configuration
    # und "Work with it" mit workflow und api, in dieser Reihenfolge
```

- [ ] **Step 2:** Tests laufen lassen → FAIL (kein `docs/README.md`).
- [ ] **Step 3: Implementieren.** Die sieben Seiten aus den README-Abschnitten Prerequisites, Platform Support, Installation, Quick Start (Langfassung), Configuration, Detection Rules, Usage, Tests, Developer Experience, Troubleshooting, File Structure und VM File Layout. Inhalt übernehmen und kürzen, nicht neu schreiben; Code-Blöcke mit ihrer Sprache versehen (`bash`, `powershell`); Bilder, die mitkommen, als `../static/<name>.png` verlinken. `docs/README.md` trägt die zwei Leserwege, die Seitenliste mit je einem Satz, die Detection Engines und die Dienste-Tabelle. In der README bleibt an den Stellen der umgezogenen Abschnitte nur die Doku-Karte; die endgültige Fassung der README macht Task 4.
- [ ] **Step 4:** Tests grün; `webui/.venv/bin/python -m pytest tests/test_docs.py -q`; `make -s unit-test`.
- [ ] **Step 5: Commit** `docs: the guide moves into docs/, setup half`.

---

### Task 2: Die Werkzeug-Hälfte und die umziehenden Tests

**Files:**
- Create: `docs/memory.md`, `docs/pipes.md`, `docs/rizin.md`, `docs/logs.md`, `docs/updates.md`, `docs/web-ui.md`, `docs/api.md`
- Modify: `README.md` (diese Abschnitte entfernen), `docs/README.md` (die Seitenliste füllen), `tests/test_docs.py`, `tests/test_logs_ui.py`
- Test: `tests/test_docs.py`

**Interfaces:**
- **Consumes:** die Seitenform aus Task 1.
- **Produces:** `docs/api.md` als neue Heimat der API-Tabelle und der MCP-Liste; `docs/rizin.md` als Heimat der Rizin-Zusagen; `docs/logs.md` als Heimat des Satzes über die Befehlskarte.

- [ ] **Step 1: Failing tests** — die vorhandenen Tests umziehen und einen neuen dazu:

```python
# test_docs.py: dieselben Zusagen, neue Quelle
def test_api_page_documents_every_route_and_nothing_else():
    # jede @app.route("/api/...") hat genau eine Zeile in docs/api.md,
    # und docs/api.md nennt keine Route, die es nicht gibt

def test_api_page_lists_every_mcp_tool():
    # alle tdc_*-Werkzeuge aus mcp/server.py und "(N tools" in docs/api.md

def test_rizin_page_rows_say_what_the_server_answers():
    # die Zeilen aus dem heutigen README-Test, jetzt in docs/rizin.md

def test_no_readme_section_was_lost():
    # die Abschnittstitel der alten README (als Liste im Test festgehalten)
    # kommen danach je in der README oder in einer Doku-Seite vor

# test_logs_ui.py: der Satz ueber die Befehlskarte wird in docs/logs.md geprueft
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** Die sieben Seiten aus Live Memory Analysis, Named Pipes, Rizin, Logs, Tool Updates, Features (Charts, ETW, Binary Analysis), Themes, Demo, API Reference und MCP Server. Die Bildergalerie des Demo-Abschnitts geht nach `web-ui.md`, die zwei Theme-Bilder bleiben der README. Die API-Tabelle wandert unverändert in der Zeilenform, die der Test verlangt.
- [ ] **Step 4:** Tests grün; `make -s unit-test`.
- [ ] **Step 5: Commit** `docs: the guide moves into docs/, tool half`.

---

### Task 3: Die vier Mermaid-Diagramme

**Files:**
- Modify: `docs/README.md`, `docs/workflow.md`, `docs/memory.md`, `docs/rizin.md`, `README.md`
- Test: `tests/test_docs.py`

**Interfaces:**
- **Produces:** die vier Blöcke, auf die der Generator trifft (`<pre class="mermaid">` im Wiki).

- [ ] **Step 1: Failing tests**

```python
def test_every_mermaid_block_is_well_formed():
    # jeder ```mermaid-Block in README.md und docs/ beginnt mit einem bekannten
    # Typ (flowchart, graph, stateDiagram-v2, sequenceDiagram), seine runden
    # und eckigen Klammern sind paarweise, und kein Pfeil endet im Leeren

def test_the_four_diagrams_are_where_they_belong():
    # Architektur in README.md und docs/README.md, die Detonationskette in
    # docs/workflow.md, die Verdict-Bildung in docs/memory.md, die
    # Rizin-Sitzung als stateDiagram-v2 in docs/rizin.md;
    # unter jedem Block stehen mindestens zwei Saetze Prosa

def test_no_ascii_box_drawing_is_left():
    # keine Rahmenzeichen (U+2500..U+257F) mehr in README.md oder docs/,
    # ausser im Dateibaum und in der VM-Pfadliste
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** Die vier Diagramme nach der Spec; die ASCII-Architektur entfällt, die drei Prosa-Abläufe (Data Flow, die Verdict-Kette, der Lebenslauf einer Rizin-Sitzung) werden Diagramm plus zwei bis drei Sätze.
- [ ] **Step 4:** Tests grün; `make -s unit-test`.
- [ ] **Step 5: Commit** `docs: four diagrams instead of a box drawing and three lists`.

---

### Task 4: Die README als Schaufenster

**Files:**
- Modify: `README.md`
- Test: `tests/test_docs.py`

**Interfaces:**
- **Consumes:** die Doku-Seiten aus Task 1 bis 3.
- **Produces:** die Doku-Karte, auf die Task 6 den Wiki-Hinweis setzt.

- [ ] **Step 1: Failing tests**

```python
def test_readme_is_a_showcase():
    # weniger als 500 Zeilen; die Abschnitte in dieser Reihenfolge:
    # What it does, Architecture, Web UI Tabs, Quick Start, Platform support,
    # Documentation, Security Notes, Credits, License
    # acht bis zehn Features, jedes mit genau einem Bild und einem Satz

def test_the_documentation_map_links_every_page():
    # der Abschnitt Documentation nennt jede Datei unter docs/ (ausser
    # superpowers/) mit einem Satz, und jeder Link zeigt auf eine vorhandene Datei

def test_readme_tabs_match_the_ui():   # bleibt, wie er ist
def test_readme_images_exist_and_none_are_orphaned():
    # jedes PNG in static/ wird von README.md oder einer Doku-Seite benutzt
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** Die README nach der Tabelle der Spec: Kopf und Badges bleiben, das Demo-Video wird verlinkt statt eingebettet, acht bis zehn Features mit je einem Satz und einem Bild, Quick Start kurz, danach die Wege in die Doku.
- [ ] **Step 4:** Tests grün; `make -s unit-test`.
- [ ] **Step 5: Commit** `docs: the readme sells the tool`.

---

### Task 5: Der Wiki-Generator

**Files:**
- Create: `scripts/build-wiki.py`, `scripts/wiki/mermaid.min.js`, `scripts/wiki/mermaid-LICENSE`, `tests/test_wiki.py`
- Modify: `Makefile`, `make.ps1`, `.gitignore`, `README.md` (Credits-Zeile)
- Test: `tests/test_wiki.py`

**Interfaces:**
- **Consumes:** `docs/*.md` in der Reihenfolge des Index, `static/*.png`.
- **Produces:**
  - `build_wiki(docs_dir, static_dir, mermaid_path, out_path) -> str` (schreibt die Datei, gibt den HTML-Text zurück)
  - `render_markdown(text, images) -> str` (rein; `images` bildet Dateinamen auf `data:`-URIs ab)
  - `page_order(index_text) -> list[str]`, `headings(html) -> list[tuple[int, str, str]]`
  - `make docs` und `.\make.ps1 docs` als Einstiegspunkte

- [ ] **Step 1: Failing tests** in `tests/test_wiki.py`

```python
def test_the_wiki_is_one_file_that_needs_no_network():
    # kein src=, href= eines Stylesheets, import oder fetch auf http(s);
    # jedes <img> ist ein data:-URI; kein type="module";
    # die gepinnte Mermaid-Kopie steht im Dokument;
    # demo.gif ist weder eingebettet noch relativ verlinkt, sondern genannt
    # und ins Repository verlinkt

def test_the_navigation_follows_the_index():
    # die Seiten in der Reihenfolge von docs/README.md, je mit ihren ##-Ueberschriften,
    # jede mit einem Sprungziel, das im Dokument vorkommt

def test_the_search_finds_a_word_from_a_deep_page():
    # der eingebaute Index enthaelt einen Begriff, der nur in docs/rizin.md steht,
    # mit Seite und Ueberschrift

def test_markdown_is_rendered_and_nothing_is_swallowed(tmp_path):
    # verschachtelte Liste, Tabelle mit | im Text, Code-Block mit ``` im Inneren,
    # Ueberschrift mit Backticks, Blockquote, horizontale Linie, Bild, Link:
    # jedes kommt im HTML an; eine unbekannte Zeile bleibt als Text stehen

def test_markdown_cannot_inject_html(tmp_path):
    # <script>alert(1)</script> und <img onerror=...> im Markdown bleiben Text

def test_mermaid_blocks_become_pre_mermaid(tmp_path):
    # ```mermaid wird <pre class="mermaid"> mit escaptem Inhalt

def test_the_build_refuses_a_missing_or_changed_mermaid(tmp_path):
    # fehlende Datei und falsche Pruefsumme -> Fehler mit Meldung, keine Ausgabe

def test_the_footer_carries_the_build_date(tmp_path):
    # Datum in UTC; die Commit-Kennung nur, wenn git erreichbar ist;
    # kein lokaler Pfad und kein Rechnername im Dokument
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** Der Generator nach der Spec; `mermaid.min.js` (Version 10, UMD) von der offiziellen Quelle holen, die SHA-256 im Generator festschreiben, die MIT-Lizenz daneben legen, eine Zeile in die Credits der README. `make docs` und `.\make.ps1 docs` rufen den Generator; `webui/static/wiki.html` in `.gitignore`.
- [ ] **Step 4:** Tests grün; `make docs` erzeugt die Datei; `make -s unit-test`.
- [ ] **Step 5: Sichtprüfung.** Die Datei als lose Datei im eigenen Chrome öffnen (`file://`): Navigation, Suche, die vier Diagramme gezeichnet, Bilder da, nichts aus dem Netz (Netzwerk-Liste leer). PNGs lesen.
- [ ] **Step 6: Commit** `feat(docs): make docs builds a single-file wiki`.

---

### Task 6: Der Weg zum Wiki im Web-UI und auf der VM

**Files:**
- Modify: `webui/app.py`, `webui/templates/index.html`, `webui/static/css/style.css`, `scripts/deploy-utm.py`, `Makefile`, `make.ps1`, `README.md`
- Create: `static/wiki.png`
- Test: `tests/test_docs.py`, `tests/test_wiki.py`

**Interfaces:**
- **Consumes:** `webui/static/wiki.html` aus Task 5.
- **Produces:** `GET /api/wiki` → `{"present": bool, "built": "<ISO-8601 Z>"|null}`; der Hinweis in der Hilfe.

- [ ] **Step 1: Failing tests**

```python
def test_the_wiki_route_says_whether_the_file_is_there(client, tdc, tmp_path):
    # ohne Datei: {"present": false, "built": null}
    # mit Datei: present true und das Datum ihrer letzten Aenderung
    # die Route steht in der API-Tabelle von docs/api.md

def test_the_help_offers_the_wiki_or_says_how_to_build_it():
    # die Hilfe hat einen Link auf /static/wiki.html mit einer Stelle fuer das Datum
    # und einen Satz mit "make docs" fuer den Fall, dass sie fehlt

def test_every_deploy_path_uploads_the_wiki():
    # die drei Deploy-Wege laden webui/static/wiki.html hoch, wenn sie existiert
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implementieren.** Route, Hilfe-Eintrag mit Datum, die drei Deploy-Wege (die Datei fehlt in einem frischen Klon, der Upload darf daran nicht scheitern), ein Bild `static/wiki.png` für die Doku-Karte der README.
- [ ] **Step 4:** Tests grün; `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(docs): the web ui points at the wiki`.

---

### Task 7: Gesamtprüfung

**Files:** nur Korrekturen, die die Prüfung findet.

- [ ] **Step 1: Die Doku lesen.** Jede Seite von vorn bis hinten: stimmt jeder Satz mit dem Code, gibt es jeden Pfad, jeden Befehl, jede Zahl? Was nicht stimmt, wird berichtigt.
- [ ] **Step 2: Das Wiki prüfen.** `make docs`, dann im eigenen Chrome aus `file://` und über `http://127.0.0.1:<port>/static/wiki.html`: Navigation durch alle vierzehn Seiten, Suche mit drei Begriffen, die vier Diagramme, zehn Bilder, die Fußzeile. Die Netzwerk-Liste bleibt leer. Größe der Datei notieren.
- [ ] **Step 3: Links prüfen.** Jeder relative Link in README und Doku zeigt auf eine vorhandene Datei oder eine vorhandene Überschrift.
- [ ] **Step 4: Tests.** `webui/.venv/bin/python -m pytest tests/test_docs.py tests/test_wiki.py -q`; die volle Suite je einmal unter `TZ=UTC` und `TZ=Europe/Berlin`; `make -s unit-test`.
- [ ] **Step 5: Commit** `docs: the readme, the guide and the wiki`.
