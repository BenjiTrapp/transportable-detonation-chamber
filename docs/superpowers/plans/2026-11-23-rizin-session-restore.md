# Die Emulationssitzung wiederherstellen — Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein Patch in entschlüsselten Code richtet beim Wiederöffnen keinen Schaden mehr an, und die Sitzung, in der er Sinn hatte, lässt sich auf einen Knopfdruck nachspielen — mit einem SHA-256 als Beweis, dass dieselben Bytes herauskamen.

**Architecture:** Das Projekt speichert nicht das Ergebnis, sondern den Weg: eine geordnete Zeitachse der Aktionen (Start, Läufe, übersprungene Calls, Patches), den Startstand der drei Assistenz-Zähler und je entschlüsseltem Bereich einen SHA-256 über die Bytes, wie der Lauf sie hinterließ. Ein Patch über Lauf-Bytes wird beim Öffnen **zurückgehalten** statt in verschlüsselte Bytes geschrieben. Ein Knopf spielt die Zeitachse nach, prüft den Hash und stellt bei Abweichung den Zustand des Öffnens wieder her. Die reine Logik liegt in `rizin_emulation.py`, die Pipe-Arbeit in `rizin_sessions.py`, eine Route in `app.py`.

**Tech Stack:** Python 3 / Flask (`webui/app.py`, `webui/rizin_sessions.py`, `webui/rizin_emulation.py`), Vanilla JS (`webui/static/js/app.js`), pytest, Node 20 für die Frontend-Tests, rizin 0.9.1 über die Pipe.

**Spec:** `docs/superpowers/specs/2026-11-23-rizin-session-restore-design.md`

## Global Constraints

- rizin ist **0.9.1**; es wird nie mit `-w` gestartet, das Original-Sample wird nie geschrieben, `wci` und `wc+` bleiben überall verboten.
- Kein Prozess startet: kein `d`-Befehl, der ausführt oder sich anhängt.
- Das Nachspielen schickt **nur** Befehle, die der Server ohnehin selbst baut. Keine Zeichenkette aus dem Projekt wird je Teil eines Befehls.
- Das Projekt ist **feindlich**: jede Adresse der Aufzeichnung wird gegen `omlj` geprüft, jede Lauf-Art gegen `rizin_emulation.STEP_COMMANDS`, jeder Wert gegen sein Zahlenformat. Ein Projekt darf **keine Sitzung kosten** (`_replay_patches`' bestehende Regel).
- Die Aufzeichnung zählt gegen **dasselbe** Budget wie die Patch-Liste: `PROJECT_PATCH_CHARS` = 32 · 1024 Zeichen. **Die Patches haben Vorrang**; passt beides nicht, fällt die Aufzeichnung ganz, nie halb.
- `_read_project_meta` liest nur die **letzten 64 KB** der Projektdatei. Unbekannte Schlüssel werden in `meta` gelesen und beim Zurückgeben ignoriert, ein neuer Schlüssel ist also in beide Richtungen verträglich.
- Adressen in JSON-Antworten sind Integer, **außer** den Maschinenwörtern der Emulationsroute, die exakte `"0x…"`-Strings sind (R52). Im Browser ist eine Adresse immer ein `"0x…"`-String, nie eine JS-Zahl.
- `esil.timeout` ist 5 s (`ESIL_TIMEOUT`) und bleibt deutlich unter `CONSOLE_TIMEOUT` (60 s).
- Alles aus rizin ist feindlich: `escapeHtml` oder `textContent`.
- Routen-Doku in `docs/api.md`, genau eine Zeile pro (Methode, Route) — `tests/test_docs.py::test_api_page_documents_every_route_and_nothing_else` erzwingt es.
- Jede neue Funktion auf oberster Ebene in `RIZIN_FUNCTIONS`, jede Konstante in `RIZIN_CONSTS` (`tests/test_rizin_ui.py`); `RIZIN_LETS` bleibt leer; jedes neue Zustandsfeld wird in `rizinReset()` gelöscht.
- Farben nur als `var(--…)`, Werte nur in `:root` von `style.css`; jedes neue farbtragende Selektor braucht sein `[data-theme]`-Gegenstück in `theme-layout.css` — **das gilt auch für Classic**, weil das Boot-Skript `data-theme` immer setzt.
- Asset-Versionen in `webui/templates/index.html` bei jeder CSS- und JS-Änderung erhöhen.
- `docs/rizin.md` und die Hilfe im Tab müssen übereinstimmen; `tests/test_docs.py::test_the_help_and_the_guide_say_the_same_where_they_say_it_twice` pinnt die gemeinsamen Phrasen, und `tests/test_theme.py::test_info_texts_cover_every_tab` begrenzt einen `(i)`-Text auf 300 Zeichen.
- Die Hinweisbox ist das bestehende `note`-Feld des Sitzungsstatus (`rizin_sessions.py:1390`), das das Statusband zeigt (`app.js:21883`). **Kein Toast, keine neue Fläche.** Notizen werden nach Dringlichkeit geordnet.
- Tests laufen ohne rizin: `tests/fake_rizin.py` steht dafür ein. **Jede server-seitige Task fügt mindestens einen `@pytest.mark.skipif(not REAL_RIZIN)`-Test hinzu**, der das rizin-Verhalten pinnt, das ihr Fake nachbaut (`REAL_RIZIN` und `MINGW` in `tests/test_rizin.py:271-273`).
- Gebaut wird auf einem **frischen Branch von `main`** (`642f5d8`). Ausgangsstand der Suite: **2784 passed, 1 skipped** (`tests/test_mcp.py:14`, MCP-Abhängigkeiten fehlen). `pytest.ini` setzt `addopts = -q`, die Summenzeile erscheint also nur **ohne** weiteres `-q`.

## Review Focus

Fünf Fälle, die die Spec verlangt, die aber kein Happy Path berührt. Jeder bekommt seinen Test in der Task, die den Code besitzt.

1. **Ein Projekt von vorher**, dessen Patch-Einträge keine Herkunft tragen: sie werden **wie heute** angewandt, nicht zurückgehalten. Sonst würde diese Änderung bestehende Projekte stillschweigend entwerten. Test in Task 1.
2. **Eine Aufzeichnung, die nicht ins Budget passt:** die Patches gewinnen, die Aufzeichnung fällt **ganz** weg, und die Hinweisbox sagt es. Eine halb geschriebene Aufzeichnung wäre schlimmer als keine. Test in Task 4.
3. **Eine feindliche Aufzeichnung** aus einem von Hand bearbeiteten Projekt — eine Adresse außerhalb jeder Map, eine unbekannte Lauf-Art, ein Wert, der keine Zahl ist: wird abgewiesen, und der Start der Sitzung geht trotzdem weiter. Test in Task 4.
4. **Das Nachspielen erzeugt andere Bytes:** es wird **nichts** angewandt, der Zustand des Öffnens wird wiederhergestellt, und die Box sagt es. Ohne diesen Fall wäre der SHA-256 Dekoration. Test in Task 5.
5. **Ein Lauf mit `timeout` in der Zeitachse:** die Aufzeichnung ist verdorben und wird nie angeboten, weil das Ergebnis an der Wanduhr hängt. Test in Task 3.

---

## File Structure

| Datei | Zuständigkeit | Änderung |
|-------|---------------|----------|
| `webui/rizin_emulation.py` | Reine Logik: die Zeitachse und ihre Serialisierung, das Lesen und Prüfen einer Aufzeichnung, der SHA-256 über die Bytes des Laufs | Modify |
| `webui/rizin_sessions.py` | Die Aufzeichnung mitschreiben und verderben, sie speichern und zurücklesen, Patches zurückhalten, das Nachspielen, die Notizen | Modify |
| `webui/app.py` | `POST /api/rizin/<sid>/restore`; `POST /patch` um die Form „einen wartenden anwenden"; `DELETE /patch` um „einen wartenden verwerfen" | Modify |
| `webui/static/js/app.js` | Wartende Patches in der Liste, ✕ und „Jetzt anwenden", der Knopf **Lauf wiederherstellen**, die Hinweisbox | Modify |
| `webui/templates/index.html`, `style.css`, `theme-layout.css` | Markup, Stil, Asset-Versionen | Modify |
| `docs/rizin.md`, `docs/api.md`, die Hilfe im Tab | Doku | Modify |
| `tests/fake_rizin.py` | Die neuen Befehlsfolgen und ein Modell für „das Nachspielen erzeugt andere Bytes" | Modify |
| `tests/test_rizin_emulation.py`, `tests/test_rizin.py`, `tests/test_rizin_ui.py`, `tests/test_docs.py` | Tests | Modify |

---

### Task 1: Ein Patch über Lauf-Bytes wird zurückgehalten

Das ist der Teil, der den stillen Schaden beseitigt, und er muss auch dann stehen, wenn alles andere entfällt.

**Files:**
- Modify: `webui/rizin_sessions.py` (`_saved_cache` `:3036`, `_patches_line` `:966`, `_read_patches` `:1031`, `_replay_patches` `:2764`, `patches()` `:1800`), `webui/app.py` (die `/patches`-Antwort), `docs/api.md`
- Test: `tests/test_rizin.py`, `tests/test_rizin_emulation.py`

**Interfaces:**
- Consumes: `rizin_emulation.patch_rows`' `over_run` (vorhanden), `self._mine`, `self._lost`.
- Produces:
  - Das Patch-Format im `/tdc`-Namensraum trägt eine Herkunft: ein Eintrag ist `<addr>:<hex>` wie heute **oder** `<addr>:<hex>:r` für „über Bytes gesetzt, die ein Lauf geschrieben hat". `_read_patches` liefert `[(addr, after_hex, over_run: bool)]`; ein Eintrag ohne Marke hat `False`.
  - `RizinSession.patches()` antwortet zusätzlich `"waiting": [{"addr": int, "after": str, "reason": str}]` — die zurückgehaltenen.
  - `self._waiting`: die zurückgehaltenen Einträge der Sitzung, die jeder Speichervorgang wie `self._lost` behält.

- [ ] **Step 1: Die scheiternden Tests schreiben**

In `tests/test_rizin_emulation.py` für das Format, in `tests/test_rizin.py` für den Weg über die Routen. Die `_Api`-Fixture (`tests/test_rizin.py:1745`) bindet: `rz.session()`, `rz.read`, `rz.send`, `rz.get`/`rz.post`, `rz.project`, `monkeypatch.setenv` vor dem Öffnen.

```python
def test_read_patches_takes_an_entry_with_and_without_a_provenance_mark():
    # Review Focus 1: ein Eintrag ohne Marke stammt aus einem Projekt von vorher und
    # wird wie heute angewandt. Die Marke ist die einzige Quelle für over_run nach dem Öffnen.
    assert rizin_sessions._read_patches("1000:90,2000:9090:r") == [(0x1000, "90", False), (0x2000, "9090", True)]
    assert rizin_sessions._read_patches("1000:90:x,:90,1000:9") == []


def test_a_patch_over_a_runs_bytes_is_held_back_when_the_file_is_opened_again(rz, monkeypatch):
    # Der Schaden: _replay_patches laeuft vor jedem Lauf, der Patch landet in verschluesselten
    # Bytes, und die naechste Entschluesselung XORt darueber. Er wird deshalb nicht angewandt.
    ...

def test_a_patch_without_a_provenance_mark_is_applied_as_before(rz, monkeypatch):
    # Review Focus 1 am Routenweg: ein Projekt, dessen patches=-Zeile keine Marke traegt.
    ...

def test_the_note_names_the_held_back_patches_once_when_the_file_is_opened(rz, monkeypatch):
    ...

@pytest.mark.skipif(not REAL_RIZIN, reason="needs rizin")
def test_real_rizin_a_patch_over_a_runs_bytes_would_be_xored_again(...):
    # Warum es zurueckgehalten wird, an der Binary gemessen: ein wx in einen entschluesselten
    # Bereich, dann der Lauf erneut -- die Patch-Bytes gehen durch den xor und kommen falsch heraus.
    ...
```

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py tests/test_rizin_emulation.py -k "held_back or provenance or read_patches" -v`
Expected: FAIL

- [ ] **Step 3: Die Herkunft ins Format**

`_patches_line` schreibt `:r` für einen Eintrag, dessen Zeile `over_run` trug; `_TDC_PATCH_RE` und `_read_patches` lesen beide Formen. `_saved_cache` gibt die Herkunft mit, die `patch_rows` ohnehin berechnet. Das Budget zählt die längere Form.

- [ ] **Step 4: Zurückhalten in `_replay_patches`**

Ein Eintrag mit `over_run` wird **nicht** geschrieben, sondern in `self._waiting` gelegt und in der Notiz benannt — dieselbe Mechanik, mit der die Funktion heute einen Patch benennt, der keinen Platz in der Datei hat. Der Start geht weiter.

- [ ] **Step 5: `waiting` in die Antwort und in `docs/api.md`**

`patches()` liefert `waiting`; die `GET /patches`-Zeile in `docs/api.md` beschreibt es, samt der Aussage, dass ein wartender Patch **nicht** im Cache steht und deshalb auch nicht exportiert wird.

- [ ] **Step 6: Tests laufen lassen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py tests/test_rizin_emulation.py tests/test_docs.py -q`
Expected: PASS

- [ ] **Step 7: Committen**

```bash
git add webui/rizin_sessions.py webui/app.py docs/api.md tests/test_rizin.py tests/test_rizin_emulation.py
git commit -m "fix(rizin): hold back a patch over a run's bytes instead of writing it into encrypted ones"
```

---

### Task 2: Die Zeitachse als reine Logik

**Files:**
- Modify: `webui/rizin_emulation.py`
- Test: `tests/test_rizin_emulation.py`

**Interfaces:**
- Consumes: `STEP_COMMANDS` (vorhanden), `parse_cache`/`patch_rows`' Zeilenform, `run_only_ranges`.
- Produces:
  - `RESTORE_KINDS = ("start", "run", "skip", "patch")` — die Aktionsarten der Zeitachse.
  - `restore_line(record) -> tuple[str, bool]` — die Aufzeichnung als Wert einer `/tdc`-Zeile, und ob sie ins mitgegebene Budget passte. Passt sie nicht, ist der Wert `""`.
  - `read_restore(value) -> dict | None` — die Aufzeichnung aus der Zeile; `None`, sobald irgendetwas nicht stimmt (unbekannte Art, Adresse kein Hex, Wert keine Zahl, Reihenfolge ohne `start` am Anfang).
  - `run_digests(rows, ranges) -> list[dict]` — je Bereich `{"start": int, "end": int, "sha256": str}` über die Bytes, **wie der Lauf sie hinterließ**: für eine Stelle, die ein `mine`-Patch später überschrieb, das `before` dieser Zeile, nicht der Patch.

- [ ] **Step 1: Die scheiternden Tests schreiben**

```python
def test_restore_line_and_read_restore_round_trip_a_timeline():
    ...

def test_read_restore_refuses_a_hand_edited_record():
    # Review Focus 3 auf der reinen Ebene: unbekannte Art, Adresse kein Hex, Wert keine Zahl,
    # eine Folge ohne start am Anfang -> None, nie ein halb gelesener Datensatz.
    ...

def test_restore_line_says_when_it_does_not_fit():
    # Review Focus 2: ueber dem Budget gibt es "" und False, nie eine halbe Zeile.
    ...

def test_run_digests_hash_the_bytes_the_run_left_not_the_patch():
    # Der schaerfste Befund des Builder-Checks: run_only_ranges nimmt jedes Byte heraus, das
    # ein mine-Row bedeckt. Gehasht wird das before der Patch-Zeile, sonst waere der Beweis
    # genau dort stumm, wo der Nutzer hinschaut.
    ...
```

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_emulation.py -k "restore or digest" -v`
Expected: FAIL

- [ ] **Step 3: Implementieren**

Vier Funktionen in `rizin_emulation.py`, neben den bestehenden Cache-Helfern, jede mit einem Kommentar im Stil der Nachbarn, der **warum** sagt. Die Serialisierung ist kompakt und enthält keine Zeichenkette, die je in einen Befehl gelangt.

- [ ] **Step 4: Laufen lassen und committen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_emulation.py -q`
Expected: PASS

```bash
git add webui/rizin_emulation.py tests/test_rizin_emulation.py
git commit -m "feat(rizin): the timeline of a restorable emulation session, as data"
```

---

### Task 3: Die Zeitachse mitschreiben, und sie verderben

**Files:**
- Modify: `webui/rizin_sessions.py` (`emulation_start` `:1470`, `emulation_run` `:1537`, `call_skip`, `patch` `:1692`, `patch_op` `:1714`, `emulation_register` `:1521`, `unpatch` `:1756`, `console` `:1382`)
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: `rizin_emulation.RESTORE_KINDS`, `run_digests` aus Task 2.
- Produces:
  - `self._restore`: `{"counters": {...}, "actions": [...], "tainted": str | None}` — die Zeitachse der Sitzung, begonnen beim **ersten** `emulation_start`.
  - `RizinSession.restore_offer() -> dict` — `{"actions": int, "tainted": str | None, "digests": int}`, was das Pane braucht, um den Knopf anzubieten oder zu begründen, warum nicht.

- [ ] **Step 1: Die scheiternden Tests schreiben**

```python
def test_the_timeline_records_what_the_emulation_routes_did(rz):
    # start, zwei runs, ein skip mit seinem angewandten Wert, ein patch -- in dieser Reihenfolge.
    ...

def test_a_run_that_ended_in_a_timeout_taints_the_timeline(rz, monkeypatch):
    # Review Focus 5: das Ergebnis haengt an der Wanduhr, also ist die Aufzeichnung nicht
    # reproduzierbar und wird nie angeboten. FAKE_RIZIN_ESIL_RUNAWAY erzeugt den Fall.
    ...

def test_a_hand_set_register_or_a_console_write_taints_the_timeline(rz):
    ...

def test_taking_something_out_of_the_cache_discards_the_timeline(rz):
    ...

def test_a_second_emulation_start_is_an_action_of_the_same_timeline(rz):
    ...

@pytest.mark.skipif(not REAL_RIZIN, reason="needs rizin")
def test_real_rizin_the_recorded_skip_value_is_what_was_applied(...):
    ...
```

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py -k "timeline or taint" -v`
Expected: FAIL

- [ ] **Step 3: Die Haken setzen**

Jede Emulationsroute hängt ihre Aktion an; `emulation_register`, ein schreibender Konsolenbefehl, eine Breakpoint-Änderung zwischen zwei Aktionen und ein Lauf mit `stopped == "timeout"` setzen `tainted` mit ihrem Grund. `unpatch` und das Leeren des Caches **verwerfen** die Zeitachse. Der Startstand der drei Assistenz-Zähler wird beim ersten `emulation_start` festgehalten.

- [ ] **Step 4: Laufen lassen und committen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py -q`
Expected: PASS

```bash
git add webui/rizin_sessions.py tests/test_rizin.py
git commit -m "feat(rizin): record what the emulation did, and say when it cannot be replayed"
```

---

### Task 4: Die Aufzeichnung speichern und zurücklesen

**Files:**
- Modify: `webui/rizin_sessions.py` (`_sanitize_project` `:891`, `_finish_save`, `_saved_cache`, `_read_project_meta` `:1029`, `_boot`/`_recover`)
- Test: `tests/test_rizin.py`

**Interfaces:**
- Consumes: `restore_line`, `read_restore`, `run_digests` aus Task 2; `self._restore` aus Task 3.
- Produces: eine `restore=`-Zeile im `/tdc`-Namensraum; `_read_project_meta` liefert `"restore"`; `_sanitize_project` nimmt die Aufzeichnung als weiteres Argument und gibt zurück, ob sie passte.

- [ ] **Step 1: Die scheiternden Tests schreiben**

```python
def test_the_timeline_survives_a_save_and_comes_back_on_open(rz):
    ...

def test_the_patches_win_the_budget_and_the_record_falls_away_whole(rz, monkeypatch):
    # Review Focus 2: monkeypatch auf PROJECT_PATCH_CHARS, sodass beides nicht passt.
    # Die patches=-Zeile ist vollstaendig, restore= fehlt ganz, und die Notiz sagt es.
    ...

def test_a_hand_edited_record_is_refused_and_the_session_still_starts(rz):
    # Review Focus 3 am Routenweg: ein Projekt, dessen restore=-Zeile Unsinn traegt.
    ...

def test_the_record_and_the_waiting_patches_survive_a_rizin_restart(rz, monkeypatch):
    ...

@pytest.mark.skipif(not REAL_RIZIN, reason="needs rizin")
def test_real_rizin_the_project_round_trips_the_record(...):
    # Ps, neu oeffnen, Poo -- die Aufzeichnung ist unveraendert da und rizin laedt das Projekt.
    ...
```

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py -k "record or budget" -v`
Expected: FAIL

- [ ] **Step 3: Schreiben, lesen, prüfen**

`restore=` wird nach `patches=` geschrieben, zählt gegen denselben Rest des Budgets und fällt **ganz** weg, wenn er nicht reicht. Beim Lesen geht der Wert durch `read_restore`; `None` heißt: keine Aufzeichnung, und die Notiz sagt warum.

- [ ] **Step 4: Laufen lassen und committen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py tests/test_docs.py -q`
Expected: PASS

```bash
git add webui/rizin_sessions.py tests/test_rizin.py
git commit -m "feat(rizin): keep the way back in the project, and drop it whole when it does not fit"
```

---

### Task 5: Das Nachspielen

**Files:**
- Modify: `webui/rizin_sessions.py`, `webui/app.py`, `docs/api.md`
- Test: `tests/test_rizin.py`, `tests/fake_rizin.py`

**Interfaces:**
- Consumes: alles aus Tasks 1-4.
- Produces:
  - `RizinSession.restore_run(wait=2.0) -> dict` — spielt die Zeitachse nach, prüft die Hashes, setzt danach die wartenden Patches; `{"restored": bool, "reason": str | None, "state": …, "patches": …}`.
  - `RizinSession.patch_waiting(addr, wait) -> dict` und `RizinSession.drop_waiting(addr, wait) -> dict` — die zwei Auswege.
  - `POST /api/rizin/<sid>/restore`; `POST /patch` zusätzlich in der Form `{addr, waiting: true}`; `DELETE /patch` zusätzlich mit `waiting: true`. Alle drei rufen `_rizin_forget(session)`.

- [ ] **Step 1: Die scheiternden Tests schreiben**

```python
def test_restoring_replays_the_timeline_and_applies_the_waiting_patches(rz):
    ...

def test_restoring_refuses_when_the_cache_is_not_the_one_from_opening(rz):
    ...

def test_a_replay_that_produces_other_bytes_applies_nothing_and_says_so(rz, monkeypatch):
    # Review Focus 4: der Fake laesst den Lauf andere Bytes schreiben (FAKE_RIZIN_*).
    # Danach: kein Patch im Cache, der Zustand des Oeffnens wieder da, der Grund in der Antwort.
    ...

def test_a_replay_that_fails_midway_keeps_the_patches_waiting(rz, monkeypatch):
    ...

def test_apply_now_is_refused_until_a_runs_bytes_cover_the_address(rz):
    # Die Entscheidung des Nutzers: der Ausweg erscheint erst, wenn der Patch wieder Sinn hat.
    ...

def test_dropping_a_waiting_patch_takes_it_out_of_the_project(rz):
    ...

@pytest.mark.skipif(not REAL_RIZIN, reason="needs rizin")
def test_real_rizin_a_replayed_timeline_gives_the_same_bytes(...):
    ...
```

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py -k "restor or apply_now or waiting" -v`
Expected: FAIL

- [ ] **Step 3: Die Maschine**

`restore_run` weist ab, wenn der Cache nicht der des Öffnens ist oder eine Emulation läuft; setzt die Assistenz-Zähler auf den Startstand; führt die Aktionen der Reihe nach über die **bestehenden** Methoden aus; prüft `run_digests` gegen die gespeicherten; stellt bei Abweichung den Zustand des Öffnens wieder her (`wc-*`, dann die Patches des Öffnens) und gibt den Grund zurück. Die Höchstzahl der Aktionen begrenzt die Dauer.

- [ ] **Step 4: Die Routen**

Nach dem Muster von `webui/app.py` (`_rizin_call`, `_rizin_body`, `_rizin_address`), mit ihren Zeilen in `docs/api.md`.

- [ ] **Step 5: Laufen lassen und committen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin.py tests/test_docs.py -q`
Expected: PASS

```bash
git add webui/rizin_sessions.py webui/app.py docs/api.md tests/fake_rizin.py tests/test_rizin.py
git commit -m "feat(rizin): replay a recorded session and prove it gave the same bytes"
```

---

### Task 6: Das Frontend

**Files:**
- Modify: `webui/static/js/app.js` (das `EMULATION`-Pane, `rizinEmuPatchesHtml`, `rizinOnEmuPaneClick`), `webui/templates/index.html`, `webui/static/css/style.css`, `webui/static/css/theme-layout.css`
- Test: `tests/test_rizin_ui.py`

**Interfaces:**
- Consumes: `waiting` aus `/patches`, `restore_offer` aus dem Status, die drei Routen aus Task 5.
- Produces: `rizinRestoreRun()`, `rizinApplyWaiting(addr)`, `rizinDropWaiting(addr)`; eine dritte Gruppe **WAITING** in der Patch-Liste; der Knopf **Lauf wiederherstellen** im Kopf des `EMULATION`-Reiters.

- [ ] **Step 1: Die scheiternden Tests schreiben**

Im `_scripted`-Harness, mit Absichts-Kommentar vor den Zusicherungen. Die Namen:

```python
@needs_node
def test_rizin_waiting_patches_are_a_group_of_their_own_with_two_ways_out(): ...

@needs_node
def test_rizin_apply_now_appears_only_when_a_runs_bytes_cover_the_address(): ...

@needs_node
def test_rizin_the_restore_button_says_why_it_is_not_offered(): ...

@needs_node
def test_rizin_the_notice_says_what_was_restored_and_what_was_not(): ...
```

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_ui.py -k "waiting or restore" -v`
Expected: FAIL

- [ ] **Step 3: Rendern, klicken, stylen**

Die dritte Gruppe trägt ihre eigene Überschrift und den Grund je Zeile; „Jetzt anwenden" wird nur gezeigt, wenn der Server es anbietet — das Frontend entscheidet es nicht selbst. Der Knopf im Kopf ist abgeblendet mit dem Grund im `title`, wenn keine Aufzeichnung da oder verdorben ist. Asset-Versionen erhöhen.

- [ ] **Step 4: Laufen lassen und committen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_ui.py tests/test_theme.py tests/test_frontend.py -q`
Expected: PASS

```bash
git add webui/static/js/app.js webui/templates/index.html webui/static/css/style.css webui/static/css/theme-layout.css tests/test_rizin_ui.py
git commit -m "feat(rizin): the waiting patches and the restore button in the EMULATION pane"
```

---

### Task 7: Doku

**Files:**
- Modify: `docs/rizin.md`, `webui/templates/index.html` (die Hilfe), `docs/api.md` (Durchsicht)
- Test: `tests/test_docs.py`

- [ ] **Step 1: Den scheiternden Test schreiben**

```python
def test_the_guide_says_what_a_waiting_patch_is_and_how_a_session_comes_back():
    # Die vier Faelle der Hinweisbox, die zwei Auswege, und warum die entschluesselten
    # Bytes nicht gespeichert werden (64 KB Lesefenster, 32 KB Budget).
    ...
```

- [ ] **Step 2: Schreiben**

In `docs/rizin.md` und der Hilfe, wörtlich übereinstimmend bei den gemeinsamen Phrasen: was ein wartender Patch ist und warum er wartet; die zwei Auswege; dass die Wiederherstellung ein Knopfdruck ist und warum nicht automatisch; dass der SHA-256 der Beweis ist; was die Aufzeichnung verdirbt; und dass die entschlüsselten Bytes **nicht** gespeichert werden, mit den beiden Zahlen.

- [ ] **Step 3: Die ganze Suite**

Run: `webui/.venv/bin/python -m pytest tests/ -q`
Expected: PASS

- [ ] **Step 4: Committen**

```bash
git add docs/rizin.md docs/api.md webui/templates/index.html tests/test_docs.py
git commit -m "docs(rizin): waiting patches, the way back, and why the bytes are not kept"
```

---

## Selbstprüfung

- **Deckung:** Jedes Ziel der Spec hat seine Task — das Zurückhalten (1), die Zeitachse (2, 3), das Speichern (4), der Knopf samt Beweis und die zwei Auswege (5), die Oberfläche (6), die Doku (7). Die sieben Nachträge des Builder-Checks liegen in 1 (Herkunft, alte Projekte), 2 (der Hash über die Bytes des Laufs), 3 (die Zeitachse als eine Folge, die Verderb-Regeln, die Zähler), 4 (das Budget) und 5 (Atomarität, wann der Knopf darf).
- **Schritte:** Jeder Schritt lässt genau eine vernünftige Umsetzung zu. Wo eine Wahl offen bleibt (die Serialisierungsform, die Höchstzahl der Aktionen, das Aussehen der dritten Gruppe), steht in der Spec unter „Dem Builder überlassen", woran sie gemessen wird.
- **Namen:** `RESTORE_KINDS`, `restore_line`, `read_restore`, `run_digests` werden in Task 2 definiert und in 3, 4 und 5 unter denselben Namen benutzt; `waiting` heißt in der Antwort, im Pane und in der Doku gleich.
- **Review Focus:** fünf Fälle, in Tasks 1, 2/4, 4, 5 und 3, jeder mit seinem Test.
- **Verhältnis:** Der Plan ist etwa so lang wie die Spec und enthält keine Funktionskörper außer den Testzusicherungen; die vier Node-Tests stehen als Name plus Absicht, weil ihre Körper je 50+ Zeilen eingebettetes JS wären.
- **Geprüft statt angenommen:** die `/tdc`-Zeilen entstehen in `_sanitize_project:921` als `\n/tdc\nlevel=…\nmode=…\ndone=…\npatches=…\n`, `_read_project_meta` liest unbekannte Schlüssel in `meta` und ignoriert sie beim Zurückgeben — ein neuer Schlüssel ist also in beide Richtungen verträglich. Die Testform für reine Funktionen ist `_run(script, SORT_DOM + _rizin_prelude())`; es gibt **keinen** `_call`-Helfer.
