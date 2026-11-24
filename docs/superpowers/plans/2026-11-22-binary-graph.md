# Binary-Graph: die Importkette bis zum Syscall — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** TDC baut den Import- und Export-Graphen der System32-Binaries selbst auf, löst Forwarder und API-Sets auf, verbindet ihn über eine kuratierte Win32→Nt-Tabelle mit der Syscall-Baseline und zeigt ihn als eigene Ansicht GRAPH neben der Karte — sodass aus einer Import-Tabelle ein Pfad bis zur Syscall-Nummer wird und ein Direct-Syscall-Treffer vom Hinweis zum Beleg.

**Architecture:** Drei neue Module in `webui/`. `win32_to_nt.py` ist die kuratierte Tabelle mit ihrem Loader — klein, ohne Abhängigkeiten, und allein schon der Nutzen von Stufe 1: sie erweitert die Importmenge eines Samples, womit `syscall_scan` endlich `import_present=False` sagen darf. `binary_graph.py` baut den Graphen (PE-Tabellen über `pefile`, Forwarder, ApiSetMap) und hält den Cache. `binary_graph_query.py` beantwortet Fragen über einen geladenen Graphen und liefert immer dieselbe Knoten-Kanten-Form, die das Frontend zeichnet. Routen und der Hintergrundbau kommen in `webui/app.py`. Das Frontend ist eine zweite Fläche im bestehenden SYSCALLS-Tab: geschichtete Pfade als SVG nach dem Muster von `rizinGraphSvg`, die Erkundung als Canvas mit eigenem Zustandsobjekt auf der vorhandenen Kamera-Maschinerie.

**Tech Stack:** Python 3.12 (Entwicklung 3.9), Flask, pefile, struct, pytest; Vanilla JS mit SVG und Canvas, keine JS-Bibliothek; PowerShell 5.1 für die Bereitstellung.

**Spec:** `docs/superpowers/specs/2026-11-22-syscall-map-design.md`

**Scope:** Dieser Plan deckt Ziel 6 (Binary-Graph) und Ziel 7 (die Verbindung beider Teile) der Spec, dazu die beiden `/api/binary-graph/*`-Routen aus Ziel 8 und ihre Anteile an Ziel 9–11. Ziele 1–5, 7a, 7b sind Plan 1, `2026-11-22-syscalls.md`, und werden hier vorausgesetzt: das Tab-Gerüst mit dem abgeschalteten GRAPH-Umschalter, die Baseline, `syscall_scan`, das Detailpanel und die Abweichungsliste bestehen schon.

**Vorgänger:** Dieser Plan setzt auf dem Branch `feature/syscalls` auf (PR #2), nicht auf `main`.

## Stufen

Die drei Stufen sind die vom Nutzer freigegebene Staffelung. Jede ist für sich lauffähige Software, und bricht man nach einer ab, ist nichts halb gebaut.

1. **Tasks 1–7 — die Datengrundlage.** Kein Pixel Graph. Stufe 1 macht aus jedem Direct-Syscall-Hinweis einen Beleg oder eine Entwarnung und liefert die Abfragen über eine Route.
2. **Task 8 — die Pfad-Ansicht.** Das Bild, das eine Frage beantwortet: wie dieses Sample den Kernel erreicht.
3. **Tasks 9–11 — die Erkundung.** Die BloodHound-artige Ansicht, die Kennzahlen und die Doku.

## Was Task 1 an Aussagen umwirft

Mehrere Stellen sagen heute, `import_present` sei unbekannt und jeder Direct-Syscall-Treffer daher ein Hinweis. Mit Task 1 ist das falsch. Task 1 zieht sie alle nach — die Liste steht in Task 1 unter **Files** und ist dort Teil der Abnahme, nicht eine Fußnote. Zusätzlich gilt: der Text von PR #2 enthält denselben Satz; er wird beim Zusammenführen nachgezogen, nicht hier.

## Global Constraints

- Oberfläche, Code, Kommentare und `docs/` auf Englisch; Spec-Dokumente und dieser Plan auf Deutsch. Ein Test wacht über deutsche Wörter in den Frontend-Dateien.
- Farben nur als `var(--…)`. Farbwerte ausschließlich in `:root` von `webui/static/css/style.css`; Cyberpunk-Werte ausschließlich unter `:root[data-theme="cyberpunk"]` in `theme-cyberpunk.css`. Jede mit Alpha benutzte Farbe braucht ihre `-rgb`-Variante als `"r, g, b"`.
- Keine Farbliterale in `app.js` oder `index.html`. Canvas und SVG lesen Farben über `themeColor(name, alpha)`.
- Alles aus PE-Tabellen, aus einem Sample und aus dem Zielprozess wird mit `escapeHtml` escaped oder als `textContent` gesetzt. Inline-`on*` interpoliert nur `jsArg(...)` oder `jsInt(...)`. Werte in `class=` gehen durch `cssToken()`. Kein `eval`, kein `new Function`. **Ein Modulname aus einer Import-Tabelle ist von Malware bestimmt.**
- `?v=`-Versionen in `webui/templates/index.html` bei jeder CSS- oder JS-Änderung erhöhen.
- Jedes neue `webui/*`-Modul und jede neue Datendatei gehört in alle drei Deploy-Wege: `scripts/deploy-utm.py` `FILES`, `Makefile` (`deploy:` und `deploy-app`), `make.ps1` (`'deploy'` und `'deploy-app'`). `test_every_deploy_path_uploads_the_web_ui_modules` schlägt an, sobald `app.py` das Modul zum ersten Mal `^import`iert — der Deploy-Eintrag gehört daher in dieselbe Task wie dieser Import.
- Jedes neue `webui/*.py` gehört zusätzlich in den Dateibaum unter `## File Structure` in `docs/troubleshooting.md` (`test_the_file_tree_names_every_web_ui_module`).
- Jede neue Route gehört genau einmal in die API-Tabelle in `docs/api.md` und in `#help-api` von `index.html` (`test_api_page_documents_every_route_and_nothing_else`, `test_help_modal_only_mentions_existing_routes`). Die README führt keine API-Tabelle.
- Jedes `data-info` höchstens 300 Zeichen, ein bis zwei Sätze mit Satzzeichen am Ende, ohne `<`, `&`, `${`.
- Jede neue `<table>` braucht `data-sortable` und ein eindeutiges `data-sort-id`. Zellen mit `formatSize`/`formatTime` brauchen `data-sort-value`. Hinweiszeilen mit `colspan` brauchen `data-sort-skip`.
- CSRF- und Host-Header-Schutz gelten für alle neuen Routen. Pfadeingaben gehen durch `_path_within` / `_resolve_within`. Alle neuen POST-Routen liegen unter der Wartungssperre `_reject_during_maintenance`.
- Die CI hat kein Windows, kein System32 und keine `apisetschema.dll`. Jeder Test läuft gegen im Test erzeugte PE-Bytes, gegen im Test gepackte ApiSetMap-Blobs und gegen die Baseline-Fixtures aus Plan 1. Die CI läuft unter `TZ=UTC` und `TZ=Europe/Berlin`, Node 20.
- **Python:** Auf der VM läuft 3.12, die Entwicklungs- und CI-Umgebung auf 3.9. Jedes neue Modul beginnt mit `from __future__ import annotations`. Ohne diese Zeile scheitert eine Signatur wie `-> dict | None` schon bei der Definition.
- **Tests laufen aus der Repo-Wurzel:** `webui/.venv/bin/python -m pytest tests/test_binary_graph.py -v`. Die ganze Suite ist `make -s unit-test` und braucht etwa sieben Minuten; sie läuft im Vordergrund, einmal vor dem Commit einer Task.
- Der Graph bleibt auf `C:\Windows\System32` beschränkt — kein `SysWOW64`, keine Treiber, keine installierten Programme (Nicht-Ziel).
- Kanten auf Funktionsebene aus Disassemblierung sind Nicht-Ziel. Der letzte Sprung Win32→Nt ist kuratiert und **muss** als solcher gezeichnet und benannt werden (Anti-Ziel).

## Review Focus

- **Ein Import-Name, den die kuratierte Tabelle nicht kennt:** `import_present` bleibt `None`, niemals `False`. Sonst gilt ein gewöhnliches Programm als belegte Umgehung, nur weil seine API nicht in der Tabelle steht — ein falscher Beleg ist schlimmer als ein Hinweis. → Task 1, Step 8.
- **Der Cache gehört zu einem anderen Build oder einer anderen Architektur:** Laden verweigern und sagen, statt einen x64-Importgraphen für eine ARM64-VM zu zeichnen. → Task 5, Step 5.
- **Ein Forwarder zeigt im Kreis** (`a!f → b!f → a!f`) oder auf sich selbst: Die Auflösung bricht ab und nennt den Kreis als Endgrund. → Task 4, Step 10.
- **Eine Datei in System32 ist kein PE, gesperrt oder abgeschnitten:** Sie wird übersprungen und mit Grund gezählt, die Extraktion läuft weiter. Bei rund 4.000 Dateien darf eine kaputte den Cache nicht verhindern. → Task 2, Step 10.
- **Die ApiSetMap fehlt oder hat eine unbekannte Version:** Auflösung aus, Kanten enden sichtbar an `api-ms-win-*`, der übrige Graph bleibt nutzbar. → Task 3, Step 9.

---

## File Structure

**Neu:**
- `webui/win32_to_nt.py` — Loader und Abfragen der kuratierten Tabelle. Reine Datenlogik, keine Windows-Aufrufe, keine Abhängigkeit auf `binary_graph`. Eigenes Modul, weil Task 1 vor jeder PE-Extraktion ausliefert und `app.py` es auf dem Stub-Pfad braucht, ohne das schwere PE-Modul zu laden.
- `webui/win32_to_nt.json` — die kuratierte Zuordnung selbst.
- `webui/binary_graph.py` — PE-Import- und -Export-Extraktion, ApiSetMap, Forwarder-Auflösung, Cache bauen/stempeln/laden, CLI für die Bereitstellung.
- `webui/binary_graph_query.py` — die Abfragen aus Ziel 6 und der Abstieg aus Ziel 7, als einheitliche Knoten-Kanten-Form. Getrennt von `binary_graph.py`, weil das eine baut und das andere liest: zwei Verantwortungen, zwei Review-Gates, und jede Datei bleibt lesbar. Die Spec nennt ein Modul; die Teilung ist eine Builder-Entscheidung und ändert nichts an Format oder Verhalten.
- `scripts/build-binary-graph.ps1` — erzeugt den Cache beim Provisionieren.
- `tests/test_binary_graph.py`, `tests/test_binary_graph_ui.py`.

**Geändert:**
- `webui/app.py` — Routen `/api/binary-graph/query` und `/api/binary-graph/node`, Hintergrundbau des Cache, `_update_preconditions`, und die vier Aufrufstellen der Stub-Suche, die `expanded_imports` bekommen.
- `webui/syscall_scan.py` — nur Docstrings, wo sie „die Tabelle fehlt" sagen.
- `webui/memory_evidence.py` — nur Docstrings am `direct_syscall_stub`-Eintrag und an `from_direct_stubs`.
- `webui/static/js/app.js` — Block `// ===== BINARY GRAPH =====`, der GRAPH-Zweig in `syscallSetView`, die Verknüpfung von Karte und Graph über das Detailpanel.
- `webui/templates/index.html` — `#syscall-surface-graph`, die Abfrageleiste, die Kennzahlen-Tabelle, `#help-usage`, `#help-api`, `?v=`.
- `webui/static/css/style.css`, `theme-cyberpunk.css` — Knotenfarben je Art, die Strichart der kuratierten Kante, die Hervorhebung von Suchtreffern.
- `scripts/deploy-utm.py`, `Makefile`, `make.ps1` — Deploy-Wege.
- `Vagrantfile`, `Vagrantfile.utm`, `scripts/setup-macos-utm.sh` — Provisionierung.
- `docs/api.md`, `docs/memory.md`, `docs/troubleshooting.md`, `README.md`, `tests/test_theme.py`.
- `docs/superpowers/specs/2026-11-22-syscall-map-design.md` — die Sätze, die Task 1 umwirft.

---

## Task 1: Die kuratierte Win32→Nt-Tabelle und der Beleg

Stufe 1 trägt hier ihren ganzen Nutzen: ohne ein Pixel Graph wird aus jedem Direct-Syscall-Treffer ein Beleg oder eine Entwarnung.

**Files:**
- Create: `webui/win32_to_nt.py`, `webui/win32_to_nt.json`
- Create: `tests/test_binary_graph.py`
- Modify: `webui/app.py` — `_syscall_stage_file`, `_syscall_stage`, beide Zweige von `api_syscalls_stubs`, Import und Deploy-Wege
- Modify (nur Text): `webui/syscall_scan.py` (`_import_present`, `find_stubs_in_bytes`, `find_stubs_in_process`), `webui/memory_evidence.py` (`KINDS`-Kommentar und `from_direct_stubs`), `webui/static/js/app.js` (Kommentar über der Stub-Liste und der Text für `import_present === null`), `docs/api.md` Zeile zu `/api/syscalls/stubs`, `docs/memory.md` (Tabellenzeile und Abschnitt), `docs/superpowers/specs/2026-11-22-syscall-map-design.md` (Ziel 7a)

**Interfaces:**
- Consumes: `syscall_scan.find_stubs_in_bytes(data, baseline, imports, *, expanded_imports)` und `find_stubs_in_process(reader, baseline, imports, *, expanded_imports)` aus Plan 1 — beide nehmen `expanded_imports` schon und sind der einzige Ort, der `False` erzeugen darf. `app.py:_pe_import_names(data)`, `app.py:_image_path_for_pid(pid)`.
- Produces:
  - `win32_to_nt.load_table(path: str | None = None) -> Table`, einmal geladen und gehalten; `path=None` nimmt `webui/win32_to_nt.json`.
  - `class Table` mit `entries: tuple[Entry, ...]`, `nt_for(win32: str) -> Entry | None` (ohne Rücksicht auf Groß- und Kleinschreibung), `expand(names: set[str] | None) -> set[str] | None` — die Namen plus jedes `nt` einer getroffenen Win32-Funktion, und `None` bleibt `None`; `missing_from(syscall_names: Iterable[str]) -> tuple[str, ...]` — welche `nt`-Namen diese Syscall-Menge nicht hält.
  - `class Entry` mit `win32: str`, `nt: str`, `source: str`, `note: str`.
  - `win32_to_nt.SOURCES = ("zw-alias", "documented", "observed")`.

- [ ] **Step 1: Die Testdatei anlegen und den Fehlschlag schreiben, der die Tabelle fordert**

```python
def test_the_table_maps_the_win32_entry_points_tdc_already_calls_suspicious():
    t = win32_to_nt.load_table()
    assert t.nt_for("VirtualAllocEx").nt == "NtAllocateVirtualMemory"
    assert t.nt_for("WriteProcessMemory").nt == "NtWriteVirtualMemory"
    assert t.nt_for("VirtualProtect").nt == "NtProtectVirtualMemory"
    assert t.nt_for("CreateRemoteThread").nt == "NtCreateThreadEx"
    assert t.nt_for("writeprocessmemory").nt == "NtWriteVirtualMemory"
```

- [ ] **Step 2: Lauf lassen und den Fehlschlag sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_binary_graph.py -v`
Erwartet: FAIL, `ModuleNotFoundError: No module named 'win32_to_nt'`

- [ ] **Step 3: `webui/win32_to_nt.py` und `webui/win32_to_nt.json` schreiben**

Die JSON-Form ist `{"version": 1, "entries": [{"win32": …, "nt": …, "source": …, "note": …}]}`. `note` darf leer sein, `source` nicht und muss aus `SOURCES` kommen.

Welche Einträge: **nur** Win32-Funktionen, die in `app.py:SUSPICIOUS_IMPORTS` stehen, oder deren `nt`-Gegenstück dort steht. Das ist die Grenze aus den Nicht-Zielen — die Tabelle ist kein Win32-Lexikon. Eine Win32-Funktion ohne direktes Nt-Gegenstück (`CreateService` über RPC, `IsDebuggerPresent` liest nur das PEB) bekommt **keinen** Eintrag; der Pfad endet später sichtbar.

`source` bedeutet: `zw-alias` für eine mechanische `Zw`→`Nt`-Umbenennung, `documented` wenn öffentliche Dokumentation den Nt-Aufruf nennt, `observed` wenn die Zuordnung von Hand aus einem Disassembly gelesen wurde. `note` nennt bei `documented` und `observed` die Quelle in einem Halbsatz.

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Die Tabelle gegen sich selbst prüfen**

Vier Tests, die eine falsche Zeile fangen, ohne dass jemand sie liest:

```python
def test_every_nt_name_has_the_shape_of_a_syscall_name():
    # "Nt" + CamelCase, no whitespace, no duplicates: catches a garbled row
def test_every_win32_name_is_one_tdc_already_calls_suspicious():
    # the table is not a win32 dictionary (non-goal): win32 or nt must appear in SUSPICIOUS_IMPORTS
def test_a_zw_alias_entry_is_exactly_that_rename():
    # source "zw-alias" and nt != "Nt" + win32[2:] is a mislabelled source
def test_every_entry_names_a_source_from_the_vocabulary_and_no_win32_name_twice():
    # "documented" and "observed" additionally require a non-empty note: the row
    # carries the citation a human can check, which is the only real guard on a name
```

**Nicht** gegen die Baseline-Fixture prüfen. Die hält sechs Syscalls, und eine auf
die Tabelle hin erweiterte Fixture wäre zirkulär: wer Tabelle und Fixture
schreibt, prüft sich selbst. Die Namen prüft die echte Baseline, über Step 6.

- [ ] **Step 6: `missing_from(syscall_names)` — der Namensprüfer, der auf der VM beißt**

`Table.missing_from(syscall_names: Iterable[str]) -> tuple[str, ...]` nennt jeden
`nt`-Namen, den diese Syscall-Menge nicht hält. Eine Menge von Namen, kein
`Baseline`-Objekt: `win32_to_nt.py` bleibt dadurch abhängigkeitsfrei, und der Aufrufer
schreibt `table.missing_from(baseline.syscalls)`. In der CI gegen eine kleine
synthetische Menge getestet, auf der VM gegen die echte Baseline: dort muss das
Ergebnis leer sein, und Task 11 hält es im Bericht fest. Die Funktion ist kein
Testwerkzeug — Task 7 braucht genau dieses Wissen für sein drittes sichtbares Ende
(„ntdll exportiert sie, aber kein Syscall dieses Builds trägt den Namen").

```python
def test_missing_from_lists_the_nt_names_a_set_of_syscalls_does_not_hold():
def test_missing_from_is_empty_for_a_set_that_holds_them_all():
```

- [ ] **Step 7: Lauf lassen, Zeilen reparieren bis grün**

- [ ] **Step 8: Der Test, der den falschen Beleg verhindert**

Das ist die Zeile aus **Review Focus**. Eine Win32-Funktion ohne Eintrag darf `import_present` nicht auf `False` kippen:

```python
def test_a_sample_whose_api_the_table_does_not_know_is_a_hint_and_not_a_proven_bypass():
    # a stub for a syscall NO row leads to (not in Table.covered): the table cannot
    # name the documented door, so the hit stays import_present None, never False
def test_expand_keeps_none_as_none_and_adds_the_nt_name_of_a_hit():
def test_a_sample_that_imports_the_documented_win32_path_is_not_a_proven_bypass():
    # imports {"VirtualAllocEx"}, stub for NtAllocateVirtualMemory -> import_present True
def test_a_sample_that_imports_no_door_to_a_covered_syscall_is_a_proven_bypass():
    # imports {"GetLastError"}, stub for NtAllocateVirtualMemory -> import_present False
```

Der dritte und vierte Test sind der Kern: genau der Fall, den Plan 1 nicht entscheiden konnte.

**Der Unterschied wird am Ziel entschieden, nicht am Import.** `False` darf nur für
einen Syscall fallen, zu dem **irgendeine** Zeile führt — `Table.covered`, die Menge
der `nt`-Namen der Tabelle. Für jeden anderen Syscall kann die Tabelle die
dokumentierte Tür nicht nennen, also bleibt es `None`. Prüfte man stattdessen, ob der
*Import* des Samples eine Zeile hat, wäre `NtCreateFile` mit `CreateFileW`-Import eine
belegte Umgehung — für ein gewöhnliches Programm.

**Achtung — `expand` darf nicht alles einsammeln.** `Table.expand` fügt nur die
`nt`-Namen der *getroffenen* Win32-Namen hinzu. Ein leerer oder fehlender Treffer darf
nicht dazu führen, dass die ganze Tabelle in die Menge wandert: dann wäre nie etwas
ein Beleg.

**Und `covered` ohne Wahl gibt es nicht.** `expanded_imports` ohne `covered` ist ein
`ValueError`, kein milder Vorgabewert: wer die erweiterte Menge hat, hat die Tabelle
und kann `covered` nennen. Ein stiller Vorgabewert wäre die Zeile, an der ein späterer
Aufrufer die falsche Beschuldigung zurückholt.

- [ ] **Step 9: `expand` und `nt_for` so umsetzen, dass diese vier Tests grün sind**

- [ ] **Step 10: Die vier Aufrufstellen in `app.py` versorgen**

Alle vier bekommen `expanded_imports=win32_to_nt.load_table().expand(imports)`:

| Stelle | `imports` kommt von |
|---|---|
| `_syscall_stage_file` | `_pe_import_names(content)` — bisher wird dort bewusst **nichts** übergeben; der Docstring, der das begründet, wird mit ersetzt |
| `_syscall_stage`, `find_stubs_in_process` | `_pe_import_names` der Datei des Samples, also demselben `path`, den die Stufe schon hat |
| `api_syscalls_stubs`, Zweig `path` | `_pe_import_names(content)`, schon vorhanden |
| `api_syscalls_stubs`, Zweig `pid` | `_pe_import_names` des Prozessabbilds über `_image_path_for_pid(pid)`; ist es nicht lesbar, bleiben beide `None` |

- [ ] **Step 11: Routen- und Stufentests dafür**

```python
def test_the_stubs_route_proves_a_bypass_for_a_file_that_does_not_import_the_path():
def test_the_detonation_stage_proves_a_bypass_for_the_sample_file():
def test_a_process_whose_image_cannot_be_read_keeps_import_present_unknown():
```

- [ ] **Step 12: Deploy-Wege und Dateibaum**

`webui/win32_to_nt.py` und `webui/win32_to_nt.json` in `scripts/deploy-utm.py` `FILES`, `Makefile` (`deploy:` und `deploy-app`), `make.ps1` (`'deploy'` und `'deploy-app'`); das `.py` zusätzlich in den Dateibaum in `docs/troubleshooting.md`.

- [ ] **Step 13: Jede Aussage nachziehen, die jetzt falsch ist**

Je Stelle ein Satz, der sagt, was gilt: ein Beleg entsteht für eine Funktion **mit** Eintrag, und ohne Eintrag bleibt es ein Hinweis. Die Stellen stehen oben unter **Files**. In `docs/memory.md` betrifft es die Tabellenzeile zu `direct_syscall_stub` und den Abschnitt darunter; in der Spec Ziel 7a, wo „wartet daher auf Plan 2" steht.

- [ ] **Step 14: Der Test, der diese Aussagen festnagelt**

```python
def test_no_shipped_text_still_says_the_win32_to_nt_table_is_missing():
    # greps webui/*.py, webui/static/js/app.js, docs/api.md, docs/memory.md for the
    # phrases that Plan 1 left behind, so the next change cannot quietly resurrect them
```

- [ ] **Step 15: Ganze Suite und Commit**

Run: `make -s unit-test` (Vordergrund, einmal)

```bash
git add webui/win32_to_nt.py webui/win32_to_nt.json webui/app.py webui/syscall_scan.py webui/memory_evidence.py webui/static/js/app.js docs scripts/deploy-utm.py Makefile make.ps1 tests/test_binary_graph.py
git commit -m "feat(syscalls): a curated Win32-to-Nt table turns a carried stub from a hint into a proven bypass"
```

---

## Task 2: Import- und Export-Extraktion je Binary

**Files:**
- Create: `webui/binary_graph.py`
- Test: `tests/test_binary_graph.py`

**Interfaces:**
- Consumes: `pefile` (schon im Projekt, siehe `app.py:_pe_import_tree`).
- Produces:
  - `@dataclass(frozen=True) class BinaryInfo`: `name: str` (klein geschrieben, mit Endung), `kind: str` (`"dll"` | `"exe"`, aus dem `IMAGE_FILE_DLL`-Merkmal, nur ersatzweise aus der Endung — eine umbenannte DLL ist im Graphen ein DLL-Knoten), `machine: str` (`"arm64"` | `"x64"` | `"x86"` | `"other"`), `imports: dict[str, tuple[str, ...]]` (Modulname klein → importierte Funktionsnamen, Ordinale als `"#<n>"`), `exports: tuple[str, ...]` (selbst definierte Namen; ein namenloser Export erscheint als `"#<ordinal>"`), `ordinal_names: dict[int, str]` (Ordinal → Name der benannten Exporte, damit Task 4 einen Forwarder auf `#8` und Task 6 einen Import nach Ordinal auflösen kann), `forwarders: dict[str, str]` (Exportname → rohe Forwarder-Zeichenkette, etwa `"NTDLL.RtlAllocateHeap"`), `partial: bool` (`pefile` hat beim Lesen gewarnt, aber Einträge geliefert — die Tabelle ist abgeschnitten, und eine Kante dahinter fehlt stillschweigend; Task 10 zählt diese Dateien).
  - `extract_binary(path: str) -> BinaryInfo` — wirft `ExtractError` mit Grund.
  - `extract_tree(directory: str) -> tuple[list[BinaryInfo], list[tuple[str, str]]]` — die Binaries und die übersprungenen Dateien als `(Dateiname, Grund)`.
  - `class ExtractError(Exception)`.

- [ ] **Step 1: Die vorhandene PE-Werkstatt teilen und erweitern, nicht eine zweite schreiben**

**Sie existiert schon:** `_pe_importing(*names, delay=False, exports=(), code=b"", export_rva=None)`
in `tests/test_syscalls.py` baut ein PE32+ mit Import-, Delay-Load- und
Export-Verzeichnis, Code bei RVA 0x11C0 / Offset 0x3C0. Eine zweite Werkstatt wäre
die Dopplung eines Logikblocks, und der Review liest das als Defekt.

Also: nach `tests/conftest.py` verschieben — dort liegen die geteilten Helfer des
Projekts schon (`make_alert`, `FirewallFake`) —, als `make_pe` benennen und um die
vier Dinge erweitern, die Plan 2 braucht:

```python
def make_pe(*, imports=(), delay=(), exports=(), forwarders=(), code=b"",
            export_rva=None, machine=0x8664, sections=()) -> bytes:
    """A minimal PE whose directories pefile parses.

    imports, delay: (module, (function, ...)) pairs — several modules, not one
    exports:        names this image defines itself
    forwarders:     (name, "MODULE.Function") pairs
    sections:       (name, bytes) pairs, for a section such as ".apiset"
    machine:        0x8664 x64, 0xAA64 arm64
    """
```

**Jeder bestehende Aufruf behält sein Verhalten.** `tests/test_syscalls.py` ruft nur
noch den neuen Namen; kein dortiger Test darf eine andere Zusicherung bekommen. Wird
eine Signatur unbequem, ist das ein Grund zu berichten, nicht einen Test anzupassen.

Zwei Dinge sind nicht offensichtlich und entscheiden, ob die Erweiterung trägt:

- **Ein Forwarder ist ein Export, dessen Adress-RVA innerhalb des
  Export-Daten-Verzeichnisses liegt.** So und nur so meldet `pefile`
  `exp.forwarder`. Die Forwarder-Zeichenketten müssen also in den Bereich gelegt
  werden, den `IMAGE_DIRECTORY_ENTRY_EXPORT` in `Size` angibt — der heute 0x28 ist
  und mitwachsen muss.
- Der heutige Bauer legt `ntdll.dll` als einzigen Importnamen fest. Mehrere Module
  brauchen je einen eigenen Import-Deskriptor; das Array endet mit einem Nulleintrag.

`pefile.PE(data=…)` braucht keine Datei. Für `extract_binary(path)` reicht `tmp_path`.

- [ ] **Step 2: Den Test schreiben, der die erweiterte Werkstatt prüft, bevor etwas sie benutzt**

```python
def test_the_test_pe_builder_produces_an_image_pefile_reads_back():
    # two import modules, an export, a forwarder, a named section and arm64 machine,
    # all read back through pefile
```

- [ ] **Step 3: Lauf lassen — FAIL; die Werkstatt verschieben und erweitern; grün**

Run: `webui/.venv/bin/python -m pytest tests/test_binary_graph.py -k builder tests/test_syscalls.py -v`
Erwartet am Ende: der neue Test grün **und** jeder bestehende Test von
`test_syscalls.py` unverändert grün.

- [ ] **Step 4: Die Tests für `extract_binary` schreiben**

```python
def test_imports_are_grouped_by_module_in_lower_case():
def test_exports_this_image_defines_itself_are_listed_without_the_forwarders():
def test_a_forwarder_is_kept_as_the_raw_string_it_names():
def test_an_import_by_ordinal_is_named_hash_number():
def test_the_machine_of_an_arm64_image_is_arm64_and_of_an_amd64_image_x64():
```

- [ ] **Step 5: Lauf lassen — FAIL, `extract_binary` gibt es nicht**

- [ ] **Step 6: `extract_binary` in `webui/binary_graph.py` umsetzen**

`fast_load=True` und dann gezielt `parse_data_directories` für Import und Export, wie `_pe_import_names` es macht — ein voller Parse über 4.000 Dateien ist zu teuer. `pe.close()` in `finally`, sonst bleiben Speicherabbildungen offen.

- [ ] **Step 7: Lauf lassen — grün**

- [ ] **Step 8: Die Tests für `extract_tree` schreiben**

```python
def test_the_tree_holds_every_pe_of_the_directory_and_names_the_others_as_skipped():
def test_a_name_that_differs_only_in_case_is_one_binary():
```

- [ ] **Step 9: `extract_tree` umsetzen und lauf lassen — grün**

- [ ] **Step 10: Der Test aus Review Focus: eine kaputte Datei unter 4.000**

```python
def test_a_file_that_is_not_a_pe_is_skipped_with_a_reason_and_the_others_still_extract():
def test_a_file_that_cannot_be_opened_is_skipped_with_a_reason():
def test_a_pe_truncated_after_its_headers_is_skipped_and_does_not_raise():
```

- [ ] **Step 11: Umsetzen, lauf lassen — grün**

- [ ] **Step 12: Dateibaum, ganze Suite, Commit**

`webui/binary_graph.py` in `docs/troubleshooting.md`. Deploy-Wege **noch nicht** — `app.py` importiert das Modul erst in Task 6, und der prüfende Test knüpft daran an.

```bash
git commit -m "feat(binary-graph): read the import and export tables of a PE, and skip a broken one with its reason"
```

---

## Task 3: Die ApiSetMap aus `apisetschema.dll`

Ohne diese Tabelle endet jede Kette einen Sprung hinter `kernel32`, weil der Forwarder auf einen `api-ms-win-core-*`-Namen zeigt, zu dem keine Datei existiert.

**Files:**
- Modify: `webui/binary_graph.py`
- Test: `tests/test_binary_graph.py`

**Interfaces:**
- Consumes: `extract_binary` wird hier nicht gebraucht; die Rohbytes der `.apiset`-Sektion genügen.
- Produces:
  - `parse_api_set_map(data: bytes) -> dict[str, tuple[str, ...]]` — Alias klein und ohne `.dll` → Hostmodule in der Reihenfolge der Map. Leeres Dict bei unbekannter Version.
  - `load_api_set_map(path: str) -> dict[str, tuple[str, ...]]` — liest die `.apiset`-Sektion von `apisetschema.dll`; leeres Dict, wenn die Datei oder die Sektion fehlt.
  - `API_SET_SCHEMA_PATH = r"C:\Windows\System32\apisetschema.dll"`.

- [ ] **Step 1: Den Test schreiben, der eine Version-6-Map packt und erwartet, zurückzulesen**

```python
def test_an_api_set_alias_resolves_to_its_host_modules_in_order():
    data = _api_set_map({"api-ms-win-core-memory-l1-1-0": ("kernelbase.dll", "kernel32.dll")})
    assert parse_api_set_map(data)["api-ms-win-core-memory-l1-1-0"] == ("kernelbase.dll", "kernel32.dll")
```

Der Aufbau, den `_api_set_map` packen muss — Version 6, alle Offsets von der Basis der Map, alle Namen UTF-16LE, alle Längen in Bytes:

| Struktur | Felder, je `u32` | Lage |
|---|---|---|
| Header, 28 B | `Version=6`, `Size`, `Flags`, `Count`, `EntryOffset`, `HashOffset`, `HashFactor` | an der Basis |
| Eintrag, 24 B, `Count`-mal | `Flags`, `NameOffset`, `NameLength`, `HashedLength`, `ValueOffset`, `ValueCount` | ab `EntryOffset` |
| Wert, 20 B, `ValueCount`-mal | `Flags`, `NameOffset`, `NameLength`, `ValueOffset`, `ValueLength` | ab `ValueOffset` des Eintrags |

Der Name eines Eintrags ist der Api-Set-Name **ohne** `.dll`; `NameOffset`/`NameLength` des Wertes sind der Importname (meist leer), `ValueOffset`/`ValueLength` das Hostmodul. Die Hash-Tabelle wird nicht gebraucht: über `Count` Einträge zu laufen ist bei wenigen Hundert billig.

- [ ] **Step 2: Lauf lassen — FAIL**

- [ ] **Step 3: `parse_api_set_map` umsetzen**

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Den Test für `load_api_set_map` schreiben**

```python
def test_the_map_is_read_from_the_apiset_section_of_the_schema_dll():
    # _pe(...) with a section named ".apiset" holding the packed map
```

- [ ] **Step 6: `load_api_set_map` umsetzen, lauf lassen — grün**

- [ ] **Step 7: Die Fälle, die nicht in Ordnung sind**

```python
def test_an_alias_is_stored_without_its_dll_suffix_and_in_lower_case():
def test_an_entry_whose_offsets_point_outside_the_map_is_dropped_and_the_rest_survives():
```

- [ ] **Step 8: Umsetzen, lauf lassen — grün**

- [ ] **Step 9: Der Test aus Review Focus: keine Map, unbekannte Version**

```python
def test_an_unknown_api_set_version_gives_an_empty_map_instead_of_raising():
def test_a_missing_schema_dll_gives_an_empty_map():
def test_a_schema_dll_without_an_apiset_section_gives_an_empty_map():
```

Eine leere Map ist kein Fehler: Task 4 lässt die Kette dann sichtbar an `api-ms-win-*` enden, und der übrige Graph bleibt nutzbar.

- [ ] **Step 10: Umsetzen, ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): resolve api-set names from the ApiSetMap, and work without it rather than break"
```

---

## Task 4: Forwarder-Ketten auflösen

**Files:**
- Modify: `webui/binary_graph.py`
- Test: `tests/test_binary_graph.py`

**Interfaces:**
- Consumes: `BinaryInfo` aus Task 2, `parse_api_set_map` aus Task 3.
- Produces:
  - `MAX_HOPS = 16`
  - `@dataclass(frozen=True) class Hop`: `module: str`, `function: str`, `via: str` (`"forwards_to"` | `"resolves_to"`).
  - `@dataclass(frozen=True) class Resolution`: `hops: tuple[Hop, ...]`, `module: str | None`, `function: str | None`, `reason: str` — `reason` ist `"defined"`, `"missing"`, `"cycle"`, `"unresolved-api-set"` oder `"too-many-hops"`. `module`/`function` sind nur bei `"defined"` gesetzt. Dazu `partial: bool = False`: ein Binary auf der Kette hatte eine abgeschnittene Tabelle (`BinaryInfo.partial`), also ist ein `missing` hier **nicht sicher** — Task 7 darf dann nicht „kein Modul definiert sie" sagen, ohne den Schnitt zu nennen.
  - `split_forwarder(raw: str) -> tuple[str, str]` — `"NTDLL.RtlAllocateHeap"` → `("ntdll.dll", "RtlAllocateHeap")`.
  - `resolve_export(binaries: dict[str, BinaryInfo], api_sets: dict[str, tuple[str, ...]], module: str, function: str) -> Resolution`.

- [ ] **Step 1: Den Test für `split_forwarder` schreiben — mit der echten Falle**

```python
def test_a_forwarder_to_a_dll_whose_name_holds_dots_splits_at_the_last_one():
    assert split_forwarder("Windows.Storage.SomeFunction") == (
        "windows.storage.dll", "SomeFunction")
def test_an_api_set_forwarder_keeps_its_hyphenated_name():
    assert split_forwarder("api-ms-win-core-heap-l1-1-0.HeapAlloc") == (
        "api-ms-win-core-heap-l1-1-0.dll", "HeapAlloc")
def test_a_plain_module_forwarder_gains_the_dll_suffix_and_is_lower_cased():
    assert split_forwarder("NTDLL.RtlAllocateHeap") == ("ntdll.dll", "RtlAllocateHeap")
def test_a_forwarder_to_an_ordinal_keeps_the_hash_form():
    assert split_forwarder("NTDLL.#8") == ("ntdll.dll", "#8")
```

Die Falle ist der **erste** Test, nicht der api-set. API-Set-Namen sind mit Bindestrichen
gebaut und tragen genau einen Punkt, also trennen erster und letzter Punkt dort gleich —
ein Test darauf unterscheidet nichts. Was unterscheidet, sind Modulnamen mit Punkten wie
`Windows.Storage.dll`: am ersten Punkt getrennt ergeben sie Unsinn.

- [ ] **Step 2: Lauf lassen und den Fehlschlag sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_binary_graph.py -k forwarder -v`
Erwartet: FAIL, `split_forwarder` gibt es nicht

- [ ] **Step 3: `split_forwarder` umsetzen und die drei Tests grün sehen**

- [ ] **Step 4: Die Tests für die Kette schreiben**

```python
def test_a_chain_over_an_api_set_ends_at_the_module_that_defines_the_function():
    # kernel32!HeapAlloc -> api-ms-win-core-heap-l1-1-0 -> kernelbase -> ntdll (defined)
def test_every_hop_says_whether_it_was_a_forwarder_or_an_api_set():
def test_an_api_set_tries_its_host_modules_in_order_until_one_defines_the_function():
def test_a_function_no_module_defines_ends_as_missing():
def test_an_api_set_with_no_entry_in_the_map_ends_as_unresolved_api_set():
```

- [ ] **Step 5: Lauf lassen — FAIL, `resolve_export` gibt es nicht**

- [ ] **Step 6: `resolve_export` umsetzen**

- [ ] **Step 7: Lauf lassen — grün**

- [ ] **Step 8: Den Test für die gebündelte Auflösung schreiben**

```python
def test_resolving_all_forwarders_answers_each_module_and_function_once():
```

- [ ] **Step 9: `resolve_all(binaries, api_sets) -> dict[tuple[str, str], Resolution]` umsetzen und lauf lassen**

Für alle Forwarder-Exporte aller Binaries, mit Zwischenspeicher je `(module, function)`. Ohne ihn löst der Cache-Bau dieselbe Kette hundertfach auf.

- [ ] **Step 10: Der Test aus Review Focus: Kreise**

```python
def test_a_forwarder_that_points_back_to_itself_ends_as_a_cycle():
def test_a_forwarder_ring_over_three_modules_ends_as_a_cycle_and_names_its_hops():
def test_a_chain_longer_than_max_hops_ends_as_too_many_hops():
```

Ein Kreis darf nicht in `missing` oder `too-many-hops` verschwinden: nur der eigene Grund sagt, dass System32 selbst widersprüchlich ist, und das will man sehen.

- [ ] **Step 11: Umsetzen, ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): follow a forwarder chain through api sets, and name a ring as a cycle"
```

---

## Task 5: Der Cache — bauen, stempeln, laden, bereitstellen

**Files:**
- Modify: `webui/binary_graph.py`
- Create: `scripts/build-binary-graph.ps1`
- Modify: `Vagrantfile`, `Vagrantfile.utm`, `scripts/setup-macos-utm.sh`
- Test: `tests/test_binary_graph.py`

**Interfaces:**
- Consumes: alles aus Tasks 2–4.
- Produces:
  - `@dataclass(frozen=True) class Graph`: `build: str`, `arch: str`, `created: str` (ISO-8601, UTC), `binaries: dict[str, BinaryInfo]`, `api_sets: dict[str, tuple[str, ...]]`, `resolved: dict[tuple[str, str], Resolution]`, `in_degree: dict[str, int]`, `skipped: tuple[tuple[str, str], ...]`.
  - `build_graph(directory: str, api_set_path: str, build: str, arch: str) -> Graph`.
  - `save_graph(graph: Graph, path: str) -> None`, `load_graph(path: str, build: str, arch: str) -> Graph` — wirft `CacheMismatch` bei fremdem Stempel.
  - `cache_name(build: str, arch: str) -> str` → `f"binary-graph-{build}-{arch}.json"`.
  - `find_cache(directory: str, build: str, arch: str) -> str | None`.
  - `class CacheMismatch(Exception)`.
  - CLI: `python binary_graph.py --out <dir> [--system32 <dir>] [--build <b>] [--arch <a>]`, Rückgabewert 0 bei Erfolg, 1 sonst, und eine Zeile je Zahl auf stdout.

- [ ] **Step 1: Die Tests für Bauen und Rundlauf schreiben**

```python
def test_the_graph_holds_every_binary_its_api_sets_and_the_resolved_forwarders():
def test_the_in_degree_of_a_module_counts_the_binaries_that_import_it_not_the_functions():
def test_a_graph_survives_save_and_load_unchanged():
```

`in_degree` ist **je Binary**, nicht je Importeintrag: er trägt in Ziel 6 die Knotengröße, und „wie viele Binaries importieren mich" ist die Aussage, nicht „wie viele Funktionen".

- [ ] **Step 2: Lauf lassen — FAIL, `build_graph` gibt es nicht**

- [ ] **Step 3: `build_graph`, `save_graph` und `load_graph` umsetzen**

Das Format der Datei ist frei (die Spec überlässt es dem Builder), muss aber JSON sein und Build, Architektur und Erzeugungszeit im Kopf tragen. `resolved` hat Tupel als Schlüssel, die JSON nicht kennt — eine Liste von Objekten oder ein zusammengesetzter Zeichenkettenschlüssel, nach Wahl, aber `load_graph` muss genau das zurückgeben, was `save_graph` bekam.

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Der Test aus Review Focus: fremder Stempel**

```python
def test_loading_a_cache_of_another_build_is_refused_with_the_build_it_holds():
def test_loading_a_cache_of_another_architecture_is_refused():
def test_a_cache_whose_json_is_truncated_is_refused_and_does_not_raise_json_errors():
def test_the_cache_name_keeps_it_apart_from_a_syscall_baseline_in_the_same_directory():
```

Der letzte Test ist der Grund für den Präfix: `ntsleuth-<build>-<view>.json` und `binary-graph-<build>-<arch>.json` liegen im gleichen Verzeichnis, und `syscall_baseline.parse_baseline_name` darf den Graph-Cache nicht für eine Baseline halten — und umgekehrt.

- [ ] **Step 6: `CacheMismatch` umsetzen, lauf lassen — grün**

- [ ] **Step 7: Die Tests der CLI schreiben**

```python
def test_the_cli_writes_a_cache_and_reports_the_counts():
def test_the_cli_returns_one_when_the_directory_holds_no_pe():
```

- [ ] **Step 8: Die CLI umsetzen, lauf lassen — grün**

- [ ] **Step 9: `scripts/build-binary-graph.ps1`**

Nach dem Muster der übrigen Install-Skripte: findet den Python der Web-UI, ruft die CLI mit `--out C:\tools\ntsleuth\baseline`, nennt die Zahlen, und **endet mit 0, auch wenn der Bau scheitert** — mit Warnung. Ein fehlender Cache ist ein Zustand, den der Tab behandelt („kein Graph"); eine abgebrochene Provisionierung ist keiner. Nimmt `[switch]$Force`, wie die anderen.

- [ ] **Step 10: Einbinden und der Test dafür**

In `Vagrantfile`, `Vagrantfile.utm` und `scripts/setup-macos-utm.sh`, nach dem Schritt, der die Web-UI installiert, und nach `install-ntsleuth.ps1` — das Verzeichnis muss existieren.

```python
def test_scripts_reach_the_vm  # bestehend, nimmt build-binary-graph.ps1 auf
```

- [ ] **Step 11: Ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): build, stamp and load the import graph cache, and refuse one of another build"
```

---

## Task 6: Die Abfragen und die beiden Routen

**Files:**
- Create: `webui/binary_graph_query.py`
- Modify: `webui/app.py`, `docs/api.md`, `webui/templates/index.html` (`#help-api`), `scripts/deploy-utm.py`, `Makefile`, `make.ps1`, `docs/troubleshooting.md`
- Test: `tests/test_binary_graph.py`

**Interfaces:**
- Consumes: `Graph` aus Task 5, `app.py:SUSPICIOUS_IMPORTS`, `app.py:NTSLEUTH_BASELINE_DIR`.
- Produces:
  - `MAX_NODES = 400`
  - `@dataclass(frozen=True) class Node`: `id: str`, `label: str`, `kind: str` (`"dll"` | `"exe"` | `"function"` | `"syscall"` | `"api-set"`), `in_degree: int`, `category: str` (die `SUSPICIOUS_IMPORTS`-Kategorie oder `""`).
  - **Ein Funktionsknoten trägt sein Modul in der `id`** (`kernel32.dll!WriteProcessMemory`), und es gibt **keine** Kante vom Modul zu seiner Funktion. Die Spec nennt vier Kantenarten — `imports`, `forwards_to`, `resolves_to`, `reaches_syscall` — und das ist Absicht: eine `defines`-Kante wäre erfundene Struktur. Eine `imports`-Kante geht vom importierenden Binary **zum Funktionsknoten**; wer von dort zum Modul will, klappt den Knoten über `node_detail` auf. `in_degree` eines Funktionsknotens ist 0, weil „wie viele Binaries importieren mich" eine Eigenschaft des Moduls ist. Tasks 8, 9 und 10 teilen diese Festlegung, statt sie je neu zu erfinden.
  - `@dataclass(frozen=True) class Edge`: `source: str`, `target: str`, `kind: str` (`"imports"` | `"forwards_to"` | `"resolves_to"` | `"reaches_syscall"`), `origin: str` (`"derived"` | `"curated"`), `label: str`.
  - `@dataclass(frozen=True) class Answer`: `nodes: tuple[Node, ...]`, `edges: tuple[Edge, ...]`, `truncated: bool`, `total: int` (wie viele Teile die Antwort ohne die Obergrenze hätte — strukturiert, nicht nur als Satz in `note`, sonst müssten Tasks 8 und 10 Prosa parsen, um „400 von 4.000" zu zeigen), `note: str`, `roots: tuple[str, ...]`.
  - `importers_of(graph, module, function=None) -> Answer`
  - `imports_of(graph, module) -> Answer`
  - `callers_of_syscall(graph, nt_name) -> Answer`
  - `forwarder_chains(graph, module) -> Answer`
  - `shared_dependencies(graph, a, b) -> Answer`
  - `node_detail(graph, name) -> dict` — Importe, Exporte, Forwarder, `in_degree`, Maschine, und ob der Name ein Binary, ein Api-Set oder nichts davon ist.
  - `QUERIES: dict[str, callable]` — die Namen, die die Route annimmt.

- [ ] **Step 1: Die Tests der fünf Abfragen schreiben**

```python
def test_who_imports_this_names_every_binary_with_an_import_edge_to_it():
def test_who_imports_this_function_narrows_to_the_binaries_that_import_that_name():
def test_the_imports_of_a_binary_carry_the_suspicious_category_on_their_node():
def test_the_normal_callers_of_a_syscall_are_the_modules_whose_chain_reaches_ntdll():
def test_the_forwarder_chains_of_a_module_draw_one_path_per_forwarded_export():
def test_the_shared_dependencies_of_two_binaries_are_the_modules_both_import():
def test_a_binary_that_is_not_in_the_graph_gives_an_empty_answer_with_a_note():
```

- [ ] **Step 2: Lauf lassen — FAIL, `binary_graph_query` gibt es nicht**

- [ ] **Step 3: Die fünf Abfragen umsetzen**

`Answer.note` ist Prosa für den Leser, englisch und ganze Sätze. Das ist bewusst etwas anderes als `Resolution.reason` aus Task 4, das ein Token für den Code ist: die Route gibt beides weiter, und das Frontend zeigt die Prosa.

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Die Obergrenze und ihr Test**

```python
def test_an_answer_over_max_nodes_is_cut_and_says_truncated():
def test_a_truncated_answer_keeps_its_roots_so_the_view_still_has_a_starting_point():
```

Wie `max_nodes` beim Prozessgraphen: nicht scheitern, sondern kürzen und es sagen.

- [ ] **Step 6: Umsetzen, lauf lassen — grün**

- [ ] **Step 7: `node_detail` und sein Test**

```python
def test_the_detail_of_a_node_names_its_imports_exports_forwarders_and_in_degree():
def test_the_detail_of_an_api_set_name_names_its_host_modules():
```

- [ ] **Step 8: Umsetzen, lauf lassen — grün**

- [ ] **Step 9: Die beiden Routen in `app.py`**

- `GET /api/binary-graph/query` — Parameter `q` (ein Name aus `QUERIES`), dazu `module`, `function`, `syscall`, `other` je nach Abfrage. Antwort ist `Answer` als JSON plus `build`, `arch`, `created` des Graphen.
- `GET /api/binary-graph/node` — Parameter `name`, Antwort ist `node_detail`.

Build und Architektur dieses Systems kommen aus `_current_os_build()` und
`binary_graph.host_arch()`. **Nicht `_syscall_default_view()`** und nicht
`platform.machine()`: der Web-UI-Python kann auf ARM64 als emuliertes x64 laufen, und
`platform.machine()` meldet dort `AMD64`. Plan 1 hat genau das auf der VM erlebt und
liest die Architektur deshalb aus der Registry; `host_arch()` tut dasselbe. Es gibt nur
einen Cache, also heißt eine falsche Architektur hier nicht „falsche Sicht", sondern
„kein Graph".

Beide Routen verweigern mit einer Begründung, wenn kein Cache dazu vorliegt — `404` mit `{"error": …, "cache": null}`, nie eine leere Antwort, die wie „keine Kanten" aussieht. Der Graph wird **einmal je Prozess** geladen und gehalten, nie je Anfrage; ein Lock schützt das Laden. Task 5 hat gemessen: rund 38 MB JSON brauchen etwa 0,6 s und ein paar hundert MB Spitzen-RSS, und der echte Bestand wird auf 40–90 MB geschätzt.

- [ ] **Step 10: Der Hintergrundbau und `_update_preconditions`**

Ein Bau auf Abruf, nach dem Muster von `_syscall_extract_state`: ein Zustand mit `running`/`failed`, ein Thread, ein Serialisierungs-Lock, und ein Eintrag in `_update_preconditions` — „A binary graph is being built. Wait until it finishes." Ein Werkzeug-Update, das mitten im Bau Dateien in System32 austauscht, ist das Gegenteil von hilfreich.

- [ ] **Step 11: Die Routentests**

```python
def test_the_query_route_answers_each_query_name_and_refuses_an_unknown_one():
def test_the_query_route_says_so_when_no_cache_matches_this_build():
def test_the_node_route_answers_a_binary_and_four_oh_fours_an_unknown_name():
def test_an_update_is_refused_while_the_binary_graph_is_being_built():
```

- [ ] **Step 12: Umsetzen, lauf lassen — grün**

- [ ] **Step 13: Deploy-Wege, Dateibaum, API-Tabelle, Hilfe**

Jetzt importiert `app.py` `binary_graph` und `binary_graph_query` zum ersten Mal, also greift `test_every_deploy_path_uploads_the_web_ui_modules`: beide Module in `scripts/deploy-utm.py` `FILES`, `Makefile`, `make.ps1`. In den Dateibaum von `docs/troubleshooting.md` gehört nur `binary_graph_query.py` — `binary_graph.py` hat Task 2 schon eingetragen. Die zwei Routen je einmal in die API-Tabelle in `docs/api.md` und in `#help-api`.

- [ ] **Step 14: Der Prozessmodus darf wieder belegen — der richtige Nenner**

Task 1 hat den Beleg im Prozessmodus abgeschaltet, weil privater, ausführbarer Speicher
nicht zuordenbar ist: ein Stub dort kann vom Sample, von einer injizierten Hook-Engine
oder von den Interception-Thunks eines Browser-Brokers stammen. Die Importtabelle eines
einzelnen PE ist dafür die falsche Menge.

Der richtige Nenner ist die Vereinigung der Türen, die **jedes geladene Modul des
Prozesses** importiert — und der Graph-Cache hält diese Importtabellen schon. Also:
`binary_graph_query.imported_doors(graph, module_names, table) -> set[str]` liefert die
erweiterte Importmenge über alle geladenen Module, und `_syscall_stage` sowie der
`pid`-Zweig von `/api/syscalls/stubs` übergeben sie samt `covered` wieder.

Die Modulliste kommt aus dem Leser, der sie für die Messung schon aufzählt. Ein Modul,
das der Cache nicht kennt (ein Sample-eigenes, eine DLL außerhalb System32), lässt den
Nenner **unvollständig**: dann bleibt es bei `None`, nie bei `False`. Eine unvollständige
Vereinigung darf keinen Beleg tragen.

**Exporte zählen nur aus einem Modul, das der Cache kennt.** Nach Ruling 16 hält ein
PE eine Tür über seine Exporte nur, wenn der Export genau den Nt- oder Zw-Namen des
Stubs trägt *und* auf den Fundort auflöst. In der Vereinigung gilt zusätzlich: ein
geladenes Modul, dessen Pfad nicht in System32 liegt oder das der Cache nicht hält,
trägt **keine** Exporte bei — sonst lädt ein Sample eine eigene DLL mit erfundener
Export-Tabelle und schaltet den Beleg für den ganzen Prozess ab.

```python
def test_the_doors_of_every_loaded_module_count_as_the_documented_path():
def test_a_loaded_module_the_cache_does_not_know_keeps_the_answer_unknown():
def test_a_process_whose_modules_import_no_door_still_proves_a_bypass():
def test_a_module_outside_system32_contributes_no_exports_to_the_union():
```

- [ ] **Step 15: Umsetzen, lauf lassen — grün**

- [ ] **Step 16: Ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): five queries over the import graph behind two routes, cut at 400 nodes"
```

---

## Task 7: Der Abstieg — vom Import bis zur Syscall-Nummer

Das ist Ziel 7, „der Weg nach unten", und die Abfrage, um die es im ganzen Plan geht.

**Files:**
- Modify: `webui/binary_graph_query.py`, `webui/app.py`, `docs/api.md`
- Test: `tests/test_binary_graph.py`

**Interfaces:**
- Consumes: `Graph`, `win32_to_nt.Table` aus Task 1 — darin `nt_for` für den letzten Sprung und `missing_from` für das dritte sichtbare Ende —, `syscall_baseline.Baseline` aus Plan 1.
- Produces:
  - `path_to_syscall(graph, table, baseline, module, function) -> Answer` — die Kette als geschichteter Pfad, der letzte Sprung als `Edge` mit `kind="reaches_syscall"` und `origin="curated"`, der Zielknoten mit `kind="syscall"` und `label` aus Name und Nummer.
  - `QUERIES` bekommt `"path-to-syscall"`.
  - `Answer.note` trägt bei einem Abbruch den Grund in Worten: `"no curated transition known"`, `"the chain does not reach ntdll"`, `"ntdll exports it, but no syscall of this build has that name"`.

- [ ] **Step 1: Die Tests des Abstiegs schreiben**

```python
def test_the_path_of_write_process_memory_ends_at_the_syscall_number_of_the_baseline():
    # kernel32!WriteProcessMemory -> kernelbase -> ntdll, curated -> NtWriteVirtualMemory,
    # the baseline gives the number; the last edge is origin "curated"
def test_every_edge_before_the_last_one_is_derived():
def test_the_last_edge_is_the_only_curated_one_and_the_syscall_node_names_its_number():
def test_a_hop_is_a_function_node_so_the_path_says_which_export_carries_it():
def test_a_hop_over_an_api_set_is_an_edge_of_kind_resolves_to():
```

Der zweite und dritte Test sind das Anti-Ziel als Test: die Oberfläche darf eine kuratierte Kante nicht als abgeleitete ausgeben, und das fängt hier an — wenn die Antwort lügt, hilft keine Strichart. Der vierte und fünfte halten die Knoten- und Kantenarten aus Ziel 6 fest: ein Pfad läuft über Funktionsknoten, nicht über Module, und ein Api-Set-Sprung heißt `resolves_to`, nicht `forwards_to`.

- [ ] **Step 2: Lauf lassen — FAIL, `path_to_syscall` gibt es nicht**

- [ ] **Step 3: `path_to_syscall` umsetzen**

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Die drei Arten, sichtbar zu enden**

```python
def test_a_win32_function_without_a_curated_entry_ends_with_no_curated_transition_known():
def test_a_chain_that_never_reaches_ntdll_says_so_and_keeps_the_hops_it_has():
def test_a_curated_nt_name_the_baseline_does_not_hold_says_so_instead_of_dropping_the_path():
def test_a_chain_cut_short_by_a_partial_table_does_not_claim_that_nothing_defines_it():
```

„Sichtbar enden statt stillschweigend verschwinden" ist die Forderung der Spec. Der dritte Fall tritt auf, wenn die Baseline zu einem anderen Build gehört oder `--no-symbols` lief. Der vierte liest `Resolution.partial` aus Task 4: ein `missing`, das aus einer abgeschnittenen Tabelle kommt, ist kein Beweis für „niemand definiert das".

- [ ] **Step 6: Umsetzen, lauf lassen — grün**

- [ ] **Step 7: Der Einstieg über ein Sample**

Die Spec sagt „von einem Import eines Samples oder einer DLL". Für ein Sample ist der Startknoten kein Binary des Graphen, sondern die Datei. `path_to_syscall` nimmt `module` deshalb auch als Namen, den der Graph nicht kennt, und setzt ihn als Wurzelknoten mit `kind="exe"` und `in_degree=0`.

```python
def test_a_start_module_the_graph_does_not_know_is_still_the_root_of_the_path():
```

- [ ] **Step 8: Umsetzen, lauf lassen — grün**

- [ ] **Step 9: Route und Doku**

`q=path-to-syscall` mit `module` und `function`. Die Zeile in `docs/api.md` erweitern — eine Route, ein Eintrag, also wird der bestehende Eintrag um die Abfrage ergänzt.

- [ ] **Step 10: Routentest, ganze Suite, Commit**

```python
def test_the_query_route_answers_a_path_to_syscall_with_the_curated_edge_marked():
```

```bash
git commit -m "feat(binary-graph): the descent from an import to its syscall number, with the last hop marked curated"
```

---

## Task 8: Die GRAPH-Fläche — geschichtete Pfade

**Files:**
- Modify: `webui/templates/index.html`, `webui/static/js/app.js`, `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`, `tests/test_theme.py`
- Test: `tests/test_binary_graph_ui.py`

**Interfaces:**
- Consumes: `GET /api/binary-graph/query` aus Tasks 6 und 7; `rizinLayoutGraph(nodes)` und `rizinGraphSvg(layout, graph, options)` als Vorlage für geschichtete Pfade; `syscallState`, `syscallSetView`, `syscallSetPane`, `syscallSelect(name)`, `renderSyscallDetailPanel()` aus Plan 1; `themeColor(name, alpha)`, `escapeHtml`, `jsArg`, `cssToken`.
- Produces:
  - `const binaryGraphState = { answer: null, query: 'path-to-syscall', module: '', function: '', depth: 1, loading: false, selected: null, note: '', nodes: [], edges: [] }`
  - `binaryGraphRun()`, `renderBinaryGraph()`, `binaryGraphSelect(id)`, `binaryGraphLegend()`
  - Neue Theme-Variablen: `--graph-node-dll`, `--graph-node-exe`, `--graph-node-syscall`, `--graph-node-apiset`, `--graph-edge-curated`, `--graph-match` samt den `-rgb`-Varianten, die mit Alpha gebraucht werden.

- [ ] **Step 1: Die Fläche und die Abfrageleiste in `index.html`**

`#syscall-surface-graph` als Geschwister von `#syscall-surface-map` in `#syscall-work`, mit `hidden`. Darin eine Abfrageleiste (Auswahl der Abfrage, Suchfeld für den Startknoten, Funktionsfeld), die SVG-Fläche und eine Legendenzeile. Der GRAPH-Knopf verliert `disabled` und sein `title="comes with the binary graph"`. Der schmale Umschalter `#syscall-pane-map` heißt nach der aktiven Ansicht, nicht fest „MAP". `?v=` erhöhen, `data-info` für die neue Karte.

- [ ] **Step 2: Die Frontend-Tests schreiben**

Über die Node-Harness (`_function_source`, `_run_node`), wie `tests/test_syscalls_ui.py`. Eigene Datei `tests/test_binary_graph_ui.py`, weil `tests/test_syscalls_ui.py` schon den ganzen Kartenteil trägt; die Spec nennt die kuratierte Kante unter `test_syscalls_ui.py`, erfüllt ist sie hier.

```python
def test_the_graph_button_is_no_longer_disabled_and_switches_the_surface():
def test_a_path_answer_draws_one_layer_per_hop_in_the_order_the_answer_gives():
def test_the_curated_edge_is_drawn_with_its_own_stroke_and_named_in_the_legend():
def test_the_detail_of_a_curated_edge_says_the_mapping_comes_from_a_table():
def test_a_note_from_the_answer_is_shown_instead_of_an_empty_canvas():
def test_a_truncated_answer_says_so_in_the_view():
    # the cap keeps the first parts in name order and never draws half a path, so a
    # missing node means "not shown", never "does not import" — the view must say which
```

Der dritte und vierte Test sind das Anti-Ziel: eine kuratierte Kante sieht anders aus, hat ihre eigene Legendenzeile, und das Detailpanel nennt sie als kuratiert.

- [ ] **Step 3: Lauf lassen — FAIL**

- [ ] **Step 4: `renderBinaryGraph` mit geschichtetem SVG umsetzen**

`rizinLayoutGraph` plus `rizinGraphSvg` sind die Vorlage: Ebenen von links nach rechts, eine Ebene je Hop. Farben über `themeColor`, Texte über `textContent` oder `escapeHtml`.

- [ ] **Step 5: Lauf lassen — grün**

- [ ] **Step 6: Rot bei Abweichungen, anders bei Suchtreffern**

Die Entscheidung des Nutzers, und sie ist der Grund für zwei verschiedene Hervorhebungen: rot heißt auf der Karte schon `patched`. Ein Syscall-Knoten, dessen Stub im letzten Scan abgewichen ist, wird rot, **und der Pfad dorthin** mit; ein Treffer des Filters wird über `--graph-match` hervorgehoben, nicht rot.

```python
def test_a_syscall_node_whose_stub_deviated_in_the_last_scan_is_drawn_in_the_patched_tone():
def test_the_edges_of_the_path_to_a_deviating_syscall_are_drawn_in_that_tone_too():
def test_a_filter_match_is_highlighted_in_its_own_tone_and_not_in_the_deviation_tone():
def test_without_a_scan_no_node_is_drawn_in_a_deviation_tone():
```

- [ ] **Step 7: Umsetzen, lauf lassen — grün**

- [ ] **Step 8: Karte und Graph sprechen über dasselbe Detailpanel**

```python
def test_clicking_a_syscall_node_selects_the_same_cell_in_the_map():
def test_selecting_a_cell_in_the_map_marks_the_same_node_in_the_graph():
```

- [ ] **Step 9: Umsetzen, lauf lassen — grün**

- [ ] **Step 10: Der Escaping-Test**

```python
def test_a_module_name_from_an_import_table_reaches_the_graph_as_text_and_not_as_markup():
def test_the_note_and_the_error_of_an_answer_are_escaped_like_any_node_label():
    # both echo what the user typed for `module` or `name`: safe as JSON, not as HTML
```

Ein Modulname aus einer Import-Tabelle ist von Malware bestimmt — das Anti-Ziel der Spec. `note` und `error` tragen zusätzlich die Eingabe des Nutzers.

- [ ] **Step 11: Farben in `style.css` und `theme-cyberpunk.css`, `tests/test_theme.py` erweitern**

- [ ] **Step 12: Ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): the GRAPH surface draws a layered path, the curated hop as its own stroke"
```

---

## Task 9: Die Explorationsansicht

**Files:**
- Modify: `webui/templates/index.html`, `webui/static/js/app.js`
- Test: `tests/test_binary_graph_ui.py`

**Interfaces:**
- Consumes: `binaryGraphState` aus Task 8; `applyForceLayout(nodes, edges)`, `screenToWorld`, `worldToScreen`, `findNodeAt`, `graphFitView`, `graphZoomIn`, `graphZoomOut` aus dem Graph-Tab — mit **eigenem** Zustandsobjekt, damit der Prozessgraph unberührt bleibt.
- Produces: `binaryGraphExpand(id)`, `binaryGraphSetDepth(n)`, `binaryGraphDraw()`, `binaryGraphOnCanvasClick(ev)`.

- [ ] **Step 1: Die Tests schreiben**

```python
def test_the_explore_mode_starts_from_the_searched_binary_and_nothing_else():
def test_the_depth_control_offers_one_to_three_and_nothing_outside():
def test_expanding_a_node_adds_its_neighbours_and_keeps_what_is_already_drawn():
def test_the_node_size_follows_the_in_degree_so_the_most_imported_dll_is_the_largest():
def test_the_node_colour_follows_the_kind_dll_exe_or_syscall():
def test_an_answer_that_hit_the_node_cap_says_so_on_the_canvas():
def test_the_edges_of_the_selected_node_are_drawn_apart_from_the_others():
def test_the_process_graph_state_is_untouched_by_a_binary_graph_render():
```

Der letzte Test ist der Grund für das eigene Zustandsobjekt: beide Ansichten teilen Funktionen, aber keinen Zustand.

- [ ] **Step 2: Lauf lassen — FAIL**

- [ ] **Step 3: Canvas und Steuerung umsetzen**

`applyForceLayout` rechnet über 150 Knoten die Abstoßung über Gitterzellen; bei der Obergrenze von 400 trägt das.

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): explore the graph node by node, sized by in-degree and capped at 400"
```

---

## Task 10: Kennzahlen über den ganzen Bestand

**Files:**
- Modify: `webui/binary_graph_query.py`, `webui/app.py`, `webui/templates/index.html`, `webui/static/js/app.js`, `docs/api.md`
- Test: `tests/test_binary_graph.py`, `tests/test_binary_graph_ui.py`

**Interfaces:**
- Consumes: `Graph` aus Task 5, `win32_to_nt.Table` aus Task 1.
- Produces:
  - `metrics(graph, table) -> dict` mit `binaries`, `edges`, `api_sets_resolved`, `forwarders`, `isolated`, `circular_pairs`, `curated_transitions`, `most_imported` (Liste aus `{name, in_degree}`), `skipped`.
  - `metric_members(graph, table, name) -> Answer` — die Liste hinter einer Zahl.
  - `QUERIES` bekommt `"metric"`.

- [ ] **Step 1: Die Tests schreiben**

```python
def test_the_metrics_count_binaries_edges_forwarders_and_resolved_api_sets():
def test_an_isolated_binary_is_one_nothing_imports_and_that_imports_nothing_of_system32():
def test_a_circular_pair_is_two_binaries_that_import_each_other():
def test_the_curated_transitions_count_the_entries_of_the_win32_to_nt_table():
def test_the_members_behind_a_metric_are_the_binaries_it_counted():
def test_an_unknown_metric_name_is_refused():
```

- [ ] **Step 2: Lauf lassen — FAIL, `metrics` gibt es nicht**

- [ ] **Step 3: `metrics` und `metric_members` umsetzen**

- [ ] **Step 4: Lauf lassen — grün**

- [ ] **Step 5: Die Tabelle in der GRAPH-Fläche**

Eine `<table data-sortable data-sort-id="binary-graph-metrics">` unter der Zeichenfläche, eine Zeile je Kennzahl. Als Knotenwolke wären sie unlesbar — die Spec will sie als Tabelle. Eine Zahl anzuklicken zeigt ihre Liste im gemeinsamen Detailpanel, und eine Zeile dort führt in den Graphen.

- [ ] **Step 6: Die Frontend-Tests**

```python
def test_the_metrics_table_is_sortable_and_has_a_unique_sort_id():
def test_clicking_a_metric_opens_its_list_in_the_shared_detail_panel():
def test_a_row_of_that_list_starts_an_exploration_from_that_binary():
def test_a_metric_of_zero_is_a_row_without_a_link_rather_than_an_empty_list():
```

- [ ] **Step 7: Umsetzen, lauf lassen — grün**

- [ ] **Step 8: Ganze Suite, Commit**

```bash
git commit -m "feat(binary-graph): the stock's figures as a sortable table, each number opening its list"
```

---

## Task 11: Doku, Hilfe, Screenshot und die VM-Prüfung

**Files:**
- Modify: `README.md`, `webui/templates/index.html` (`#help-usage`), `docs/api.md`, `docs/memory.md`, `docs/troubleshooting.md`, `docs/configuration.md`
- Create: `webui/static/syscalls-graph.png`

- [ ] **Step 1: README**

Der Abschnitt zu Syscalls bekommt die GRAPH-Ansicht: was sie zeigt, dass der Graph lokal entsteht und dass der letzte Sprung kuratiert ist. WinGraph steht in den Credits (Plan 1) — hier nur der Satz, dass nur verlinkt und nichts abgefragt wird. Die Tab-Tabelle ändert sich nicht, der Tab ist nicht neu.

- [ ] **Step 2: Hilfe**

Im Tab-Guide `#help-usage` ein Absatz unter dem bestehenden `<h4>` für SYSCALLS: der Umschalter, die Abfragen, die kuratierte Kante.

- [ ] **Step 3: `docs/configuration.md` und `docs/troubleshooting.md`**

Der Cache: wo er liegt, wie er neu entsteht (`scripts/build-binary-graph.ps1`), wie lange der Bau dauert, und was der Tab sagt, wenn er fehlt oder zu einem anderen Build gehört.

- [ ] **Step 4: Lauf lassen**

Run: `webui/.venv/bin/python -m pytest tests/test_docs.py tests/test_theme.py -v`
Erwartet: PASS — die Tests über API-Tabelle, Hilfe-Modal, README-Tab-Tabelle und Dateibaum liegen in `tests/test_docs.py`; die Farb- und Asset-Tests in `tests/test_theme.py`.

- [ ] **Step 5: Screenshot**

`webui/static/syscalls-graph.png`, Cyberpunk, 1920×960, echte Daten von der VM: ein Pfad von `WriteProcessMemory` bis zur Nummer, mit der kuratierten Kante sichtbar.

- [ ] **Step 6: Ganze Suite, Commit**

```bash
git commit -m "docs(binary-graph): the GRAPH view in the README, the help and the operator docs"
```

- [ ] **Step 7: Auf der VM prüfen**

Deploy über `scripts/deploy-utm.py`, dann von Hand:

1. `scripts/build-binary-graph.ps1` läuft durch und nennt Zahlen, die plausibel sind — rund 4.000 Binaries, und `api_sets_resolved` ist nicht 0. **Unter Windows PowerShell 5.1**, die in der CI nie lief: dort wurde das Skript nur unter pwsh 7 auf macOS geprüft, mit ausgetauschten Registry-Lesungen.
2. **Welches System32 sieht der Web-UI-Python?** Er kann auf ARM64 als emuliertes x64 laufen. Prüfen, ob `C:\Windows\System32` dann umgeleitet wird (wie WOW64 es für x86 tut) oder nicht — und ob `host_arch()` aus der Registry `arm64` liefert, während `platform.machine()` `AMD64` sagt. Stimmt die Architektur nicht, heißt das nicht „falsche Sicht", sondern **kein Graph**.
3. **`load_api_set_map(binary_graph.API_SET_SCHEMA_PATH)` gibt mehrere hundert Einträge**, und ein bekannter Alias löst auf: `api-ms-win-core-memory-l1-1-0` muss auf `kernelbase.dll` oder `kernel32.dll` zeigen — über den Familien-Rückfall (Entscheidung 23), denn die Map selbst führt auf `26200.9974` `api-ms-win-core-memory-l1-1-9`, nicht `-l1-1-0`. Das ist die erste Prüfung des Version-6-Layouts gegen eine echte Datei — in der CI steht nur ein selbst gepackter Blob, und ein Packer, der sich mit seinem eigenen Parser einig ist, kann mit Windows trotzdem uneinig sein. Schlägt es fehl, endet jede Kette einen Sprung hinter `kernel32`, und der Graph ist fast wertlos. Drei Zusicherungen, die eine Fehldeutung auffliegen lassen, weil ein falscher Offset Müll-UTF-16 liefert und keinen Beinahetreffer:
   - jeder Alias passt auf `^(api|ext)-[a-z0-9-]+$`, jedes Hostmodul ist nicht leer und hat eine Endung (nicht „endet auf `.dll`": auf `26200.9974` sind 14 Hosts Treiber, etwa `clfs.sys`, `clipsp.sys`, `cmimcext.sys`, `dxgkrnl.sys`, `globmerger.sys` — Kernel-API-Sets haben zu Recht `.sys`-Hosts);
   - `len(result)` gleicht dem `Count` des Headers — so stand die Zusicherung, und **sie war falsch**. Auf `26200.9974` stand 841 gegen 985, und die Messung der 144 fehlenden Einträge widerlegte die Diagnose, die zuerst hier stand: alle 144 haben einen einzigen Wert (`vcount=1`) mit leerem Importeur **und** leerem Host, Flag `0x1` — API-Sets, die diese Edition nicht hostet. Ihr Verwerfen über die Regel für `value[0]` ist richtig, denn auch der Loader löst sie nicht auf. Entscheidung 66 (ein leerer Host in einem **späteren** Wert fällt allein weg) behebt also keinen gemessenen Fehler; sie hat auf diesem Build keinen Fall und ist ein Modell für einen Fall, den die echte Map derzeit nicht enthält. **Die Zusicherung hat ihren Platz trotzdem verdient, aus dem richtigen Grund:** sie hat nicht einen Fehler des Lesers gefunden, sondern dass 841 ≠ 985 richtig ist und sie selbst falsch war. Sie lautet daher: jeder fehlende Eintrag hat einen leeren Host in `value[0]` oder ist ein doppelter Alias;
   - `Version` ist 6, und `EntryOffset` liegt innerhalb der Map (`28 <= EntryOffset` und `EntryOffset + 24 * Count <= Size`). Nicht „`EntryOffset` ist 28": der Kopf ist 28 Bytes lang, aber das Format verspricht nicht, dass die Einträge direkt dahinter beginnen — auf `26200.9974` ist `EntryOffset` 152. Der Leser liest ab `EntryOffset`, und das ist richtig;
   - **und: zählen, wie oft der Versions-Rückfall aus Task 4 greift.** Über alle Forwarder aller System32-Binaries: wie viele nennen einen API-Set-Namen, den die Map **exakt** nicht hält, aber am letzten `-` gekürzt schon? Ist die Zahl 0, war der Rückfall unnötig; ist sie größer, hat er genau so viele Ketten gerettet, die sonst als `unresolved-api-set` gestorben wären.
3. **`table.missing_from(baseline.syscalls)` gegen die echte Baseline ist leer.** Das ist die einzige Prüfung, die die kuratierten Nt-Namen wirklich beurteilt: in der CI kann nur die Form geprüft werden, hier die Namen. Jeder genannte Name ist entweder ein Tippfehler in der Tabelle oder eine Funktion, die dieser Build nicht hat — beides gehört in den Bericht, mit welcher der beiden Ursachen es war. Auf `26200.9974` kam eine dritte Ursache heraus: vier Namen je Sicht (arm64 `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtUnmapViewOfSection`, `NtAdjustPrivilegesToken`; x64 `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtQueueApcThread`, `NtSetContextThread`) fehlen, weil `parse_baseline` für eine Nummer nur einen Namen behält und hier die `Zw`-Form zuerst kam. Kein Tippfehler und keine fehlende Funktion — behoben durch Entscheidung 69: `missing_from` zählt ein `Nt`-Name als vorhanden, wenn die Baseline seine `Zw`-Form hält.
4. `GET /api/binary-graph/query?q=path-to-syscall&module=kernel32.dll&function=WriteProcessMemory` endet bei `NtWriteVirtualMemory` mit der Nummer, die die Baseline nennt.
5. **Eine echte `C:\Windows\System32\ntdll.dll` als Datei durch `POST /api/syscalls/stubs` schicken, in beiden Sichten.** Diese Prüfung hat den Fehler gefunden, der den Merge sperrte: in der x64-Sicht las die unveränderte ntdll mit 9 `False` als MALICIOUS 8.0, weil die Exporttabelle eines ARM64X-Images (Maschine ARM64) nur dessen native Sicht beschreibt. Nach Entscheidung 70 und 71 gilt:
   - **x64-Sicht** (nicht die Maschine der Datei): jeder Treffer `import_present` `None`, keiner `False`, `own_export` überall `false`, `doors_complete` `false`, und `doors_note` nennt die Maschine der Datei und die gesuchte Sicht („the file's machine is arm64 and the view searched is x64: …"). Kein Treffer darf `True` über einen Export bekommen: die Exporttabelle beschreibt diese Sicht nicht.
   - **arm64-Sicht** (die eigene der Datei): die exportierten Stubs `True` mit `own_export` `true`, auch ein Stub innerhalb seines Exports wie `NtUnmapViewOfSection` bei `0x8e0`; kein `False`; `doors_complete` `true`.
   In der CI nicht prüfbar, hier in zwei Aufrufen.
6. **Der Prozess-Beleg auf einem emulierten x64-Sample.** Auf ARM64 bekommt eine x64-Sicht **keinen** Beleg aus dem Prozessspeicher, weil die Importtabellen im Cache aus der nativen Sicht der ARM64X-Dateien stammen und die EC-Sicht anders importieren kann. Das ist die sichere Seite, trifft aber auf dieser Kammer den **Normalfall** (siehe Plan 1: ein emuliertes x64-Sample ist hier die Regel). Prüfen, dass der Tab das sagt und dass der Beleg über die **Datei** weiterhin entsteht — das ist die Quelle, die ohnehin zählt.
7. **Liegt auf dem Kammer-Abbild ein Modul direkt in `C:\Windows\System32`, das Stubs in privaten Speicher schreibt?** Das ist der einzige Weg, auf dem die Vereinigung vollständig sein kann und der Stub trotzdem einem anderen Autor gehört: ein Hook-Engine-Trampolin importiert keine Tür, weil es die Stub-Bytes **kopiert** statt die API zu rufen. Liegt die DLL außerhalb System32 — der Normalfall für EDR —, ist die Vereinigung schon unvollständig und das Ergebnis `None`. Zu prüfen: die geladenen Module eines gewöhnlichen Prozesses auflisten, jedes in System32 gegen den Cache halten, und für einen sauberen Prozess bestätigen, dass kein Treffer `import_present=False` trägt. `PayloadRestrictions.dll` (Exploit Protection) ist der erste Kandidat. Ein Fund hier wäre das erste Anti-Ziel der Spec — „jeder EDR-Hook erzeugt einen Befund" — in neuem Gewand.

   **Dieser Punkt sperrt den Merge.** Das fünfte Residual ist **nicht** gemindert: ein Stub-Befund ist am Prozess verschlüsselt, in dem er gefunden wurde, also passt kein Baseline-Eintrag eines anderen Programms, und nichts schreibt je einen Stub-Befund in die Host-Baseline — der Sweep misst nur Hooks, und „Sweep as baseline" fährt die Syscall-Stufe gar nicht. Solange dieser Punkt nicht gemessen ist, ist ein 4.0-Befund gegen einen sauberen Host nicht ausgeschlossen.

   Prüfen ist dabei auch: dass `modules_whole()` auf der echten VM wirklich `None` gibt, wenn der Leser ein Modul auslassen musste. Der Win32-Zweig, der ausgelassene Module zählt, ist in der CI nie gelaufen.
8. Beide Themes, 1920 und 1280 px, echte Eingaben über CDP in eigenem Chrome mit frischem Profil.
9. Ein Sample mit einem Direct-Syscall-Stub zeigt jetzt **einen Beleg** statt eines Hinweises — und ein gewöhnliches Programm, das die Win32-Funktion importiert, zeigt weiterhin keinen.

Punkt 9 ist die Abnahme des ganzen Plans. Was dort gemessen wird, gehört in den Prüfbericht, nicht nur ins Protokoll.
