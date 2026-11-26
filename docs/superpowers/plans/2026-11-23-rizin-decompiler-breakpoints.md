# Breakpoints in der DECOMPILER-Ansicht — Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eine Randspalte in jeder C-Zeile des DECOMPILER, die mit einem Klick einen Breakpoint auf der **niedrigsten** Adresse der Zeile setzt und entfernt — „vor dieser Zeile" — und die nicht veraltet.

**Architecture:** Reines Frontend. Die Adressen jeder C-Zeile liegen schon auf der Leitung (`offset`, `offsets`), die Breakpoint-Liste liegt im Frontend in der `marks`-Ansicht. Eine reine Funktion rechnet pro Zeile aus, worauf ein Klick wirkt und ob dort ein Breakpoint sitzt; die Ansicht rendert daraus dieselbe Zelle wie die Disassembly und aktualisiert sie, wenn sich die Liste ändert. Kein Server-Code, keine neue Route.

**Tech Stack:** Vanilla JS in `webui/static/js/app.js`, CSS custom properties in `style.css` und `theme-layout.css`, pytest mit Node für das Frontend (`tests/test_rizin_ui.py`).

**Spec:** `docs/superpowers/specs/2026-11-23-rizin-decompiler-breakpoints-design.md`

## Global Constraints

- Funktionen auf oberster Ebene, Präfix `rizin`, Konstanten `RIZIN_`. Jede neue Funktion gehört in `RIZIN_FUNCTIONS`, jede Konstante in `RIZIN_CONSTS` in `tests/test_rizin_ui.py`, sonst scheitert `test_rizin_lists_cover_the_block`. `RIZIN_LETS` bleibt leer.
- Jedes neue Zustandsfeld wird in `rizinReset()` gelöscht.
- Adressen im Browser immer `"0x…"`-Strings, nie JS-Zahlen; keine Adressarithmetik in JS.
- Farben nur als `var(--…)`, Werte nur in `:root` von `style.css`; jedes neue farbtragende Selektor braucht sein `[data-theme]`-Gegenstück in `theme-layout.css`, sonst scheitert `tests/test_theme.py`.
- Asset-Versionen in `webui/templates/index.html` hochzählen (Stand: `style.css?v=88`, `theme-layout.css?v=11`, `app.js?v=130`).
- Alles, was aus rizin kommt, ist feindlich: `escapeHtml` oder `textContent`.
- Die Zelle darf den C-Code **nicht verschieben** und bei 1280 px nicht unlesbar machen.
- `docs/rizin.md` und die Hilfe in `index.html` müssen übereinstimmen: `tests/test_docs.py::test_the_help_and_the_guide_say_the_same_where_they_say_it_twice` pinnt 21 Phrasen in beiden.
- Kein Server-Code, keine neue Route, keine neue Zeile in `docs/api.md`.
- Die volle Suite steht bei **2777 passed, 1 skipped** (`tests/test_mcp.py:14`, MCP-Abhängigkeiten fehlen).

## Review Focus

Fünf Fälle, die das Design verlangt, die aber kein Happy Path berührt. Jeder bekommt seinen Test in der Task, die den Code besitzt.

1. **Ein Breakpoint, der woanders gesetzt wurde** (Konsole, Disassembly) und **mitten** in einer C-Zeile liegt, nicht auf ihrer niedrigsten Adresse: die Zeile muss `●` zeigen und ein Klick muss **genau diesen** entfernen, nicht einen zweiten auf `offsets[0]` setzen. Test in Task 1.
2. **Eine C-Zeile, deren `offset` nicht ihre niedrigste Adresse ist** (rizins Annotationsreihenfolge, gemessen im Modell: `0x1400015BF` vor `0x1400015B9`): der Klick muss die niedrigste nehmen, der Sprung weiter `offset`. Test in Task 1.
3. **Ein Befehl, der zu mehreren C-Zeilen gehört:** alle tragen `●`, und ein Klick auf jede entfernt denselben Breakpoint. Test in Task 1.
4. **Ein Klick, während eine Anfrage noch draußen ist** (`marks.busy`): er wird verworfen, und der Zeiger sagt das — auch in diesem Panel, nicht nur in der Disassembly. Test in Task 2.
5. **Ein Breakpoint-Wechsel, der den Zeilen-Neubau nicht auslöst:** die Marke darf nicht veralten, und der Scroll-Stand und die `current`-Marke dürfen dabei nicht verloren gehen. Test in Task 2.

---

## File Structure

| Datei | Zuständigkeit | Änderung |
|-------|---------------|----------|
| `webui/static/js/app.js` | `rizinDecompilerStops` (reine Zuordnung), die Zelle in `rizinDecompilerHtml`, der Klick-Zweig in `rizinOnDecompilerClick`, die nicht veraltende Aktualisierung in `rizinRenderDecompiler`, das Panel in `rizinToggleBreakpoint` | Modify |
| `webui/static/css/style.css` | `.rizin-dec-gutter` | Modify |
| `webui/static/css/theme-layout.css` | das Cyberpunk-Gegenstück | Modify |
| `webui/templates/index.html` | Asset-Versionen, der Hilfetext zur Randspalte | Modify |
| `docs/rizin.md` | der Breakpoints-Abschnitt | Modify |
| `tests/test_rizin_ui.py` | die Tests beider Tasks, `RIZIN_FUNCTIONS` | Modify |
| `tests/test_docs.py` | die gepinnten Phrasen, falls eine sich ändert | Modify |

---

### Task 1: Die Zuordnung Zeile → Adresse

**Files:**
- Modify: `webui/static/js/app.js` (neben `rizinDecompilerMark`, ~`:24390`)
- Test: `tests/test_rizin_ui.py` (bei den vorhandenen Decompiler-Tests, `:4296` ff.)

**Interfaces:**
- Consumes: `rizinLineOffsets(line)` (vorhanden, liefert alle Adressen einer Zeile als Zahlen), `rizinHex(value)` (vorhanden, formatiert als `"0x…"`-String).
- Produces:
  - `rizinDecompilerStops(lines, breakpoints) -> Array<{addr: string, set: boolean} | null>` — ein Eintrag pro Zeile, in derselben Reihenfolge. `null`, wenn die Zeile keine eigene Adresse hat. `addr` ist die Adresse, auf die ein Klick wirkt: die **niedrigste** Adresse der Zeile, die einen Breakpoint trägt, sonst ihre niedrigste überhaupt. `set` ist `true`, wenn auf `addr` ein Breakpoint sitzt. `breakpoints` ist die Liste aus `rizinState.marks.breakpoints` (Zahlen).

- [ ] **Step 1: Die scheiternden Tests schreiben**

In `tests/test_rizin_ui.py` neben `test_rizin_decompiler_marks_a_line_of_code_at_the_place` (`:4296`), in **genau dessen Form**: `_run(r"""…""", SORT_DOM + _rizin_prelude())` mit eingebettetem JS, das sein Ergebnis mit `console.log(JSON.stringify({…}))` zurückgibt, und den Zusicherungen in Python auf dem Ergebnis. Dort steht auch der Helfer `cline(text, ...addrs)`, der eine Zeile baut und `offsets` sortiert — für diesen Test ist er **nicht** verwendbar, weil er `offset` auf die niedrigste Adresse setzt und genau der Unterschied geprüft wird; die Zeilen also von Hand bauen. Die Adressen stammen aus dem Modell echter `pdgj`-Ausgabe in `tests/fake_rizin.py` (`CODE`).

```python
@needs_node
def test_rizin_decompiler_stops_pick_the_address_a_click_acts_on():
    """Review Focus 1, 2 und 3. `offset` ist die erste Annotation in rizins Reihenfolge, nicht die
    niedrigste Adresse der Zeile (gemessen im Modell: 0x1400015BF steht vor 0x1400015B9), also nimmt
    ein Klick die niedrigste: "vor dieser Zeile". Trägt irgendeine Adresse der Zeile schon einen
    Breakpoint, wirkt der Klick auf diese, damit ein zweiter Klick nicht einen weiteren setzt.
    Gehört ein Befehl zu mehreren C-Zeilen, tragen alle die Marke."""
    r = _run(r"""
        const brace = { text: '{', offset: null, offsets: [] };
        const iff = { text: '    if (argc < 3) {', offset: 0x1400014c5, offsets: [0x1400014c5, 0x1400014c8] };
        const pipe = { text: '    hPipe = CreateNamedPipeA(lpName);', offset: 0x1400015bf,
                       offsets: [0x1400015b9, 0x1400015bf] };
        const only = { text: '    y = 1;', offset: 0x1000 };
        const shared = [{ text: '    if (x) {', offset: 0x1000, offsets: [0x1000] },
                        { text: '        y = 1;', offset: 0x1000, offsets: [0x1000, 0x1004] }];
        console.log(JSON.stringify({
            none: rizinDecompilerStops([brace, iff, pipe], []),
            high: rizinDecompilerStops([pipe], [0x1400015bf]),
            low: rizinDecompilerStops([pipe], [0x1400015b9]),
            both: rizinDecompilerStops([pipe], [0x1400015b9, 0x1400015bf]),
            elsewhere: rizinDecompilerStops([only], [0x9000]),
            offsetOnly: rizinDecompilerStops([only], []),
            shared: rizinDecompilerStops(shared, [0x1000]),
        }));
    """, SORT_DOM + _rizin_prelude())
    assert r["none"] == [None, {"addr": "0x1400014c5", "set": False}, {"addr": "0x1400015b9", "set": False}], \
        "a line without an address is clickable, or the click does not take the line's lowest address"
    assert r["high"] == [{"addr": "0x1400015bf", "set": True}], "a breakpoint inside the line is not found"
    assert r["low"] == [{"addr": "0x1400015b9", "set": True}]
    assert r["both"] == [{"addr": "0x1400015b9", "set": True}], \
        "with two set the lowest must win, or one stays behind after a click"
    assert r["elsewhere"] == [{"addr": "0x1000", "set": False}], "a breakpoint of another function marks a line"
    assert r["offsetOnly"] == [{"addr": "0x1000", "set": False}], "a line with only `offset` is skipped"
    assert r["shared"] == [{"addr": "0x1000", "set": True}, {"addr": "0x1000", "set": True}], \
        "an instruction that belongs to two C lines marks only one of them"
```


- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_ui.py -k decompiler_stops -v`
Expected: FAIL, `rizinDecompilerStops is not defined`

- [ ] **Step 3: `rizinDecompilerStops(lines, breakpoints)` in `webui/static/js/app.js` implementieren**

Neben `rizinDecompilerMark`, mit einem Kommentar im Stil der Nachbarn, der sagt **warum** die niedrigste Adresse gilt und warum mehrere Zeilen dieselbe Marke tragen dürfen. Die Adressen einer Zeile aufsteigend sortieren, `breakpoints` in ein `Set` legen, nichts in JS-Zahlen rechnen außer dem Vergleich der Adressen, die der Server als Zahlen liefert.

- [ ] **Step 4: In `RIZIN_FUNCTIONS` eintragen und laufen lassen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_ui.py -k "decompiler_stops or lists_cover" -v`
Expected: PASS

- [ ] **Step 5: Committen**

```bash
git add webui/static/js/app.js tests/test_rizin_ui.py
git commit -m "feat(rizin): work out which address a click in the decompiler's gutter acts on"
```

---

### Task 2: Die Randspalte in der Ansicht

**Files:**
- Modify: `webui/static/js/app.js` — `rizinDecompilerHtml` (`:24377`), `rizinOnDecompilerClick` (`:24556`), `rizinRenderDecompiler` (`:24502`, Aufrufstelle `:24535`), `rizinToggleBreakpoint` (Panel-Wahl)
- Modify: `webui/static/css/style.css` (bei `.rizin-dec-line`, `:9872`), `webui/static/css/theme-layout.css`, `webui/templates/index.html`, `docs/rizin.md`
- Test: `tests/test_rizin_ui.py`, `tests/test_docs.py`

**Interfaces:**
- Consumes: `rizinDecompilerStops` aus Task 1; `rizinState.marks.breakpoints` (die Liste, die die `marks`-Ansicht hält); `rizinToggleBreakpoint(addr)` (vorhanden, setzt und entfernt); `rizinLineOffsets`, `rizinDecompilerMark`, `rizinScrollAnchor`, `rizinRestoreScroll` (vorhanden).
- Produces: `rizinDecompilerHtml(lines, options)` nimmt in `options` zusätzlich `breakpoints` (Standard `[]`), wie `rizinDisasmHtml` es schon tut. Die Zelle trägt `data-rizin-gutter="0x…"` und die Klasse `rizin-dec-gutter`, mit `on`, wenn gesetzt.

- [ ] **Step 1: Die scheiternden Tests schreiben**

Im `_scripted`/`SCRIPTED.serve`-Harness der Datei, mit Absichts-Kommentar vor den Zusicherungen.

```python
@needs_node
def test_rizin_decompiler_gutter_toggles_a_breakpoint_without_seeking():
    # Die Zelle steht in jeder C-Zeile mit Adresse und in keiner ohne; ein Klick darin
    # setzt den Breakpoint auf der niedrigsten Adresse der Zeile, springt nicht, und ein
    # zweiter Klick entfernt ihn. Ein Klick auf die Zeile daneben springt weiter auf
    # `offset`, nicht auf die niedrigste.
    ...

@needs_node
def test_rizin_decompiler_gutter_follows_the_disassembly_and_the_console():
    # Ein in der DISASSEMBLY oder der Konsole gesetzter Breakpoint zeigt sich hier, und
    # umgekehrt: beide lesen dieselbe Liste, keiner holt sie ein zweites Mal.
    ...

@needs_node
def test_rizin_decompiler_gutter_does_not_go_stale_on_a_toggle():
    # Review Focus 5: der Zeilen-Neubau hängt an [sid, dec.gen] und ein Breakpoint-Wechsel
    # ändert das nicht. Nach einem Klick trägt die Zeile die Marke, der Scroll-Stand und
    # die `current`-Marke stehen noch, und die C-Zeilen wurden nicht neu geholt.
    ...

@needs_node
def test_rizin_decompiler_gutter_drops_a_click_while_a_request_is_out():
    # Review Focus 4: bei `marks.busy` wird der Klick verworfen und der Zeiger sagt es --
    # in diesem Panel, nicht nur in der Disassembly.
    ...
```

Dazu in den Stil-Tests: die Ruhe- und Hover-Regel der neuen Zelle in **beiden** Stylesheets, und dass die Zelle den Code nicht verschiebt (die Adresse einer Zeile mit und ohne Marke an derselben Stelle).

- [ ] **Step 2: Laufen lassen, um das Scheitern zu sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_ui.py -k "decompiler_gutter" -v`
Expected: FAIL

- [ ] **Step 3: Die Zelle rendern**

In `rizinDecompilerHtml` `breakpoints` aus `options` nehmen, `rizinDecompilerStops` einmal pro Aufruf rechnen und pro Zeile die Zelle **vor** dem Zeilentext ausgeben: `rizin-dec-gutter` mit `data-rizin-gutter` und `title`, der die Adresse nennt, die der Klick verwendet. Eine Zeile ohne Adresse bekommt die Zelle als leeren Platzhalter ohne `data-rizin-gutter`, damit der Code aller Zeilen auf derselben Spalte beginnt. Die Aufrufstelle `:24535` übergibt `breakpoints: rizinState.marks.breakpoints || []`.

- [ ] **Step 4: Den Klick-Zweig einhängen**

In `rizinOnDecompilerClick` **vor** dem `[data-addr]`-Zweig auf `[data-rizin-gutter]` prüfen und `rizinToggleBreakpoint(...)` aufrufen, dann zurückgeben — wie `rizinOnDisasmClick` es tut. Der Sprung-Zweig bleibt unverändert.

- [ ] **Step 5: Die Marke aktuell halten**

`rizinRenderDecompiler` baut die Zeilen nur neu, wenn sich `[sid, dec.gen]` ändert. Die Breakpoint-Marke muss trotzdem folgen: entweder gehen die Marken in die Signatur (dann hält der vorhandene `rizinScrollAnchor`/`rizinRestoreScroll`-Pfad den Scroll-Stand) oder die Zellen werden im schrittweisen Pfad gesetzt, wie es dort schon mit `current` passiert. Die Wahl liegt beim Bauenden; verlangt ist, dass der Test aus Step 1 hält.

- [ ] **Step 6: Das Panel in `rizinToggleBreakpoint`**

Die Funktion setzt `rizin-gutter-busy` fest auf `document.getElementById('rizin-disasm')`. Der Zeiger muss auch im Decompiler-Panel etwas sagen; die Funktion soll beide Panels bedienen, statt eines zu erraten.

- [ ] **Step 7: Stil und Versionen**

`.rizin-dec-gutter` in `style.css` bei `.rizin-dec-line`, mit dem `[data-theme]`-Gegenstück in `theme-layout.css`. Dieselben Glyphen und Farben wie `.rizin-gutter`: blasses `○` im Ruhezustand, stärker unter dem Zeiger, rotes fettes `●`, wenn gesetzt. Wo sich die Regeln mit `.rizin-gutter` deckten, lieber einen gemeinsamen Selektor als eine Kopie. Asset-Versionen hochzählen.

- [ ] **Step 8: Doku**

Den Breakpoints-Abschnitt in `docs/rizin.md` und den entsprechenden Satz in der Hilfe in `index.html` ergänzen: die Randspalte gibt es auch im DECOMPILER, ein Klick setzt dort auf die **niedrigste** Adresse der Zeile („vor dieser Zeile"), der Tooltip nennt sie, und gehört ein Befehl zu mehreren C-Zeilen, tragen alle die Marke. Beide Seiten müssen übereinstimmen; `tests/test_docs.py` prüft das.

- [ ] **Step 9: Alles laufen lassen**

Run: `webui/.venv/bin/python -m pytest tests/test_rizin_ui.py tests/test_theme.py tests/test_frontend.py tests/test_docs.py -q`, dann die ganze Suite `webui/.venv/bin/python -m pytest tests/ -q`
Expected: PASS, 2777 + die neuen Tests, 1 skipped

- [ ] **Step 10: Committen**

```bash
git add webui/static/js/app.js webui/static/css/style.css webui/static/css/theme-layout.css webui/templates/index.html docs/rizin.md tests/test_rizin_ui.py tests/test_docs.py
git commit -m "feat(rizin): breakpoints in the decompiler's gutter"
```

---

## Selbstprüfung

- **Deckung:** Jedes Ziel des Designs hat seine Task — die Zelle, die niedrigste Adresse, der Tooltip, „irgendeine Adresse gilt als gesetzt", die Zeile ohne Adresse, und die Nicht-Ziele sind als solche benannt (der Sprung-Zweig bleibt, keine zweite Marken-Regel, keine Tastaturbedienung).
- **Schritte:** Jeder Schritt lässt genau eine vernünftige Umsetzung zu. Step 5 und Step 7 lassen bewusst eine Wahl offen und sagen, woran sie gemessen wird.
- **Namen:** `rizinDecompilerStops` ist in Task 1 definiert und wird in Task 2 unter demselben Namen benutzt; `breakpoints` in `options` heißt wie in `rizinDisasmHtml`.
- **Review Focus:** fünf Fälle. Die ersten drei liegen in Task 1 und teilen sich einen Test, dessen Zusicherungen sie einzeln benennen; die beiden anderen liegen in Task 2 mit je einem eigenen Test.
- **Verhältnis:** Der Plan ist etwa doppelt so lang wie das Design und enthält keine Funktionskörper außer den Testzusicherungen.
- **Geprüft statt angenommen:** Die Testform ist `_run(script, SORT_DOM + _rizin_prelude())` mit eingebettetem JS und `console.log(JSON.stringify(…))`, nicht ein erfundener `_call`-Helfer; der vorhandene `cline`-Helfer ist für Task 1 ausdrücklich unbrauchbar, weil er `offset` auf die niedrigste Adresse setzt und genau das geprüft wird. Die Zeilennummern in den Files-Blöcken stammen aus dem heutigen Stand von `app.js`.

