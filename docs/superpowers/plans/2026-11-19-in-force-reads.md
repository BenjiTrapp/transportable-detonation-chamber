# Modulfreies in-Kraft-Lesen — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `Profiles` liest beide Firewall-Stores ohne das NetSecurity-Modul, und
beweist bei jedem Aufruf, dass der Store, nach dem es gefragt hat, auch
geliefert wurde.

**Architecture:** `webui/firewall_rules.ps1` bekommt einen CIM-Leser, der
`-PolicyStore` als **Operationsoption** setzt
(`CimOperationOptions.SetCustomOption('PolicyStore', <store>, $false)` auf einer
Sitzung aus `[Microsoft.Management.Infrastructure.CimSession]::Create('.')`).
Weil die Option sich nicht erzwingen lässt, liest er zuerst einen Store, den es
nicht geben kann: **gelingt** dieser Prüfstein, wird die Option ignoriert und der
Leser wirft. Jeder Zweifel landet auf dem heutigen Cmdlet-Weg und wird in der
Antwort vermerkt. `Compare` bekommt seine Profilhälfte zurück und ist das Gate.

**Tech Stack:** PowerShell 5.1 (`firewall_rules.ps1`), Python 3 (nur die
Protokollzeile), pytest.

**Spec:** `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`

## Global Constraints

- Keine neue Abhängigkeit. Kommentare und Commit-Nachrichten auf Englisch.
- Die **JSON-Verträge** von `Profiles` (`Name`, `Enabled`,
  `DefaultOutboundAction`, `Configured`), `List` und `Get` bleiben unverändert.
  Der beste Beweis: die vorhandenen Tests bleiben **ohne Änderung** grün.
- **Schreibvorgänge unangetastet:** `Create`, `Cut`, `Remove`,
  `SetDefaultOutbound`, `DisableAllowOut`, `EnableAllowOut`, `RemoveIsolate`,
  `Enable`.
- **`AllowOut` bleibt bei den Cmdlets.**
- `firewall_rules.ps1` baut aus Argumenten nie etwas anderes als die Parameter
  *eines* Aufrufs; kein `-Command`, kein `Invoke-Expression`.
- **Die beiden Stores werden nie vermischt:** `ActiveStore` füllt nur `Enabled`
  und `DefaultOutboundAction`, `PersistentStore` nur `Configured`.
- **Kein Wert wird geraten.** Jede Zahl und jede Schreibweise ist
  ausgeschrieben; was nicht in der Zuordnung steht, wirft und fällt zurück.
- **Kein stiller Rückfall:** jede Antwort sagt, welcher Weg sie erzeugt hat, und
  bei einem Rückfall warum.
- Kein Test liest das echte Netz, die echte Uhr, die Umgebung oder das
  Dateisystem außerhalb eines tmp-Verzeichnisses.
- Gemessene Werte (unbelastete VM): beide Stores per Cmdlet 1,20 s, mit der
  Option **0,61 s**; Prüfstein 140 ms, Lesevorgang danach 34 ms; `Profiles`
  heute 1,16 s, `List` 1,43 s; Ruhelast heute 6 Aufrufe und 19,5 % je 100 s.
- Jeder neue Wächter-Test wird **als scheiternd bewiesen**: die verbotene
  Änderung in einer Kopie unter tmp einspielen, rot sehen, zurücknehmen.

## Review Focus

1. **Die Option wird ignoriert und niemand merkt es** — der konfigurierte Wert
   erscheint als in Kraft, und die Oberfläche meldet „geschlossen", während der
   Ausgang offen ist. → Task 1, Prüfstein, und das `Compare`-Gate im
   Richtlinien-Zustand.
2. **Der Prüfstein steht hinter dem ersten verwertbaren Wert** statt davor, oder
   sein Scheitern wird verschluckt. → Task 1, Schritt 1.
3. **Ein Store füllt das Feld des anderen**, so wie es dieses Projekt schon
   zweimal ausgeliefert hat. → Task 1, die Wächter.
4. **`List` sagt `fast`, obwohl eine Hälfte zurückfiel** — ein Rückfall, der nur
   als Langsamkeit auffällt. → Task 2.
5. **Eine Testbegründung, die nicht mehr stimmt:**
   `test_allowout_stays_on_the_cmdlets_because_cim_cannot_read_the_activestore`
   behauptet ab jetzt etwas Widerlegtes. → Task 2.

---

### Task 1: Der Options-Leser mit Prüfstein, `Profiles`, und `Compare`s Profilhälfte

**Files:**
- Modify: `webui/firewall_rules.ps1` (Kopfkommentar; neue Funktion
  `Read-FastProfileStates`; `Get-ProfileStates` bei Zeile 140; der
  `'Compare'`-Zweig bei Zeile 441)
- Test: `tests/test_firewall_rules.py`

**Interfaces:**
- Produces:
  - `Read-FastProfileStates` → dieselben Zeilen wie `Get-ProfileStates` heute
    (`Name`, `Enabled` als `[bool]`, `DefaultOutboundAction`, `Configured`),
    oder wirft.
  - `Get-ProfileStates` → `{Rows, Via, Fallback}`; `Rows` ist, was `Profiles`
    heute ausgibt. Task 2 verlässt sich auf genau diese drei Felder.
  - `Compare` → `{ok, rules, checked: {profiles, displayNames, names, fields}, differences}`.
- Consumes: `Get-ShortReason` (Zeile 126) für den einzeiligen Grund.

- [ ] **Step 1: Die scheiternden Tests schreiben**

```python
def test_the_sentinel_store_is_read_before_any_value_is_trusted():
    """The option cannot be forced (mustComply is refused), so a store that
    cannot exist must be read FIRST: if it answers, the option is ignored."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    lines = [l for l in fast.splitlines() if l.strip() and not l.strip().startswith("#")]
    sentinel = next(i for i, l in enumerate(lines) if "Sentinel" in l or "NoSuchStore" in l)
    active = next(i for i, l in enumerate(lines) if "ActiveStore" in l)
    assert sentinel < active, "the sentinel must be read before the ActiveStore"

def test_a_sentinel_that_answers_makes_the_fast_way_refuse():
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    assert re.search(r"throw .*(ignor|sentinel|NoSuchStore)", fast, re.I), \
        "a sentinel that answers must throw, not be noted and passed"

def test_the_activestore_never_fills_the_configured_field():
    """Shipped twice: an in-force value restored as the configured one leaves
    the host's firewall configured differently from how it was found."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    assigns = [l.strip() for l in fast.splitlines() if re.search(r"\.?Configured\s*=", l, re.I)]
    assert len(assigns) == 1, "Configured is assigned in exactly one place: %s" % assigns
    assert "$configured[" in assigns[0], assigns[0]
    for line in fast.splitlines():
        if re.search(r"\$configured\s*\[.*\]\s*=", line, re.I):
            assert "ActiveStore" not in line and "$inForce" not in line, line

def test_every_cim_number_and_name_is_written_out():
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    for token in ("'0'", "'2'", "'4'", "'NotConfigured'", "'Allow'", "'Block'"):
        assert token in fast, "the action map lost %s" % token
    assert "ContainsKey" in fast and "throw" in fast

def test_enabled_is_mapped_by_the_two_numbers_that_were_measured():
    """0 and 1 on this path, measured with the Public firewall switched off -
    not the WMI convention 1/2. Anything else falls back."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    assert re.search(r"CimEnabled\s*=\s*@\{[^}]*'0'[^}]*'1'[^}]*\}", fast)
    assert "'2'" not in re.search(r"CimEnabled\s*=\s*@\{[^}]*\}", fast).group(0)

def test_profiles_reads_cim_with_the_option_and_never_com():
    """COM reads the local store, which is why the previous attempt was
    reverted; the profile read must not go back to it."""
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    assert "SetCustomOption" in fast and "MSFT_NetFirewallProfile" in fast
    assert "FwPolicy2" not in fast, "the profiles must not be read over COM"
    assert "Create('.')" in fast, "Create($null) fails with 'Der Parameter ist ungueltig'"

def test_mustcomply_is_not_used_and_the_script_says_why():
    fast = _function_body(_ps1(), "Read-FastProfileStates")
    assert re.search(r"SetCustomOption\([^)]*\$false\s*\)", fast)

def test_compare_counts_the_profiles_on_their_own():
    branch = _op_branch(_ps1(), "Compare")
    assert re.search(r"profiles\s*=\s*0", branch), \
        "an empty profile pass must be visible in checked"
```

Dazu ein Helfer `_function_body(script, name)`, der den Rumpf einer Funktion aus
dem Skript schneidet — in der Art der vorhandenen `_op_branch` (Zeile 2882).

- [ ] **Step 2: Laufen lassen, Rot sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py -k "sentinel or activestore_never or cim_number or enabled_is_mapped or reads_cim_with or mustcomply or compare_counts" -v`
Expected: FAIL — `Read-FastProfileStates` gibt es nicht

- [ ] **Step 3: `Read-FastProfileStates` bauen**

Signatur: `Read-FastProfileStates` ohne Parameter, gibt die Zeilen von
`Get-ProfileStates` zurück oder wirft.

Reihenfolge im Rumpf, und sie ist die Sicherheit dieses Entwurfs:
erst der Prüfstein (ein Store-Name, den es nicht geben kann; **gelingt** er,
`throw`), dann der ActiveStore für `Enabled` und `DefaultOutboundAction`, dann
der PersistentStore für `Configured`. Eine Hilfsfunktion mit Store-Parameter
liest je Store; die beiden Aufrufer schreiben in **getrennte** Tabellen, damit
kein Aufrufer die Stores verwechseln kann.

Die Zuordnungen ausgeschrieben, je Zahl und je Name, `ContainsKey` davor,
`throw` dahinter — wie `Read-FastRuleViews` es vormacht (Zeile 187):
`$CimOutbound = @{ '0' = 'NotConfigured'; '2' = 'Allow'; '4' = 'Block'; 'NotConfigured' = 'NotConfigured'; 'Allow' = 'Allow'; 'Block' = 'Block' }`
(beide Darstellungen sind gemessen: Zahlen auf diesem Weg, Namen auf dem Weg,
den das Skript vorher nahm) und `$CimEnabled = @{ '0' = $false; '1' = $true }`.
Groß-/Kleinschreibung exakt prüfen, weil eine PowerShell-Hashtable sie ignoriert.

Fehlt ein Profil, ist eine Antwort leer oder steht eine Zahl nicht in ihrer
Zuordnung, wird geworfen — nichts wird ausgegeben, bevor alle drei Profile
gelesen sind.

- [ ] **Step 4: `Get-ProfileStates` auf Abkürzung plus Rückfall umstellen**

`Get-ProfileStates` gibt ab jetzt `{Rows, Via, Fallback}`: erst
`Read-FastProfileStates`, bei jedem Fehler der heutige Cmdlet-Rumpf (Zeile
141–152, unverändert übernommen) mit `Via = 'cmdlet'` und
`Fallback = Get-ShortReason $_`.

Der `'Profiles'`-Zweig (Zeile 438) gibt `Rows` aus, jede Zeile um `Via` und — bei
einem Rückfall — `Fallback` ergänzt, genau wie es die zurückgenommene Fassung
tat (`git show 0714d5c -- webui/firewall_rules.ps1` zeigt die Form, die die
Python-Seite und die Protokollzeile schon lesen).

Jeder andere Aufrufer von `Get-ProfileStates` im Skript nimmt `.Rows`.

- [ ] **Step 5: `Compare` um die Profile erweitern**

Je Profil `Enabled`, der in Kraft befindliche und der konfigurierte Wert, auf
beiden Wegen **unabhängig** gelesen (`Read-FastProfileStates` gegen die
Cmdlets), über `Test-SameValue` (Zeile 301) verglichen. `checked` bekommt
`profiles` als ersten Zähler. Ein Fehler des schnellen Wegs ist eine Differenz,
mit `Get-ShortReason` gekürzt.

- [ ] **Step 6: Kopfkommentar nachziehen**

Der Abschnitt „Profiles stays on the cmdlets" (Zeile 75–96) beschreibt ab jetzt
den gebauten Weg: dass COM und die beiden abgelehnten CIM-Routen weiter nicht
gehen und **warum**, dass die Operationsoption geht, mit den gemessenen Zahlen
aus dem Richtlinien-Zustand, dass `mustComply` vom Plug-In abgelehnt wird, und
dass der Prüfstein dessen Ersatz ist. Die Zeile, die die Option „unmessen" nennt,
ist falsch und muss weg.

- [ ] **Step 7: Tests laufen lassen**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py tests/test_firewall_api.py -v`
Expected: PASS, **ohne Änderung an einem vorhandenen Test**

- [ ] **Step 8: Wächter als scheiternd beweisen**

In einer Kopie unter tmp: den Prüfstein hinter den ActiveStore-Lesevorgang
schieben; sein `throw` in eine Notiz verwandeln; `Configured` aus dem
ActiveStore füllen (auch groß geschrieben, `$Configured[...]`); eine Zahl aus
der Zuordnung entfernen. Jede Änderung einzeln, jedes Mal rot, danach
zurücknehmen. Die Ausgabe in den Bericht.

- [ ] **Step 9: Committen**

```bash
git add webui/firewall_rules.ps1 tests/test_firewall_rules.py
git commit -m "perf(firewall): Profiles reads both stores over CIM with the PolicyStore operation option, proved per call by a sentinel store"
```

---

### Task 2: `List` erzählt beide Hälften, und `AllowOut`s Begründung wird wahr

**Files:**
- Modify: `webui/firewall_rules.ps1` (der `'List'`-Zweig; der Kommentar über
  `Get-ForeignAllowOut`, Zeile 348)
- Modify: `tests/test_firewall_rules.py` (die beiden Pin-Tests bei Zeile 3188
  und 3236)
- Modify: `webui/firewall_rules.py` nur, falls die Protokollzeile den
  zusammengesetzten Grund nicht schon trägt

**Interfaces:**
- Consumes: Task 1s `{Rows, Via, Fallback}` aus `Get-ProfileStates` und das
  vorhandene `{Views, Via, Fallback}` aus `Get-OurRuleViews` (Zeile 288).

- [ ] **Step 1: Die scheiternden Tests schreiben**

```python
def test_list_says_fast_only_when_both_halves_were_fast():
    branch = _op_branch(_ps1(), "List")
    assert re.search(r"profiles.*Via.*fast.*rules.*Via.*fast|-and", branch), \
        "Via must depend on both halves"
    assert "profiles:" in branch and "rules:" in branch, \
        "a fallback must say which half fell back"

def test_list_keeps_both_reasons_when_both_halves_fall_back():
    branch = _op_branch(_ps1(), "List")
    assert re.search(r"-join", branch), "two reasons must both survive"

def test_allowout_stays_on_the_cmdlets_because_the_gain_does_not_pay_for_the_risk():
    """The old name said CIM cannot read the ActiveStore. Measured on
    2026-11-19 that is FALSE - the operation option reads it and finds the same
    136 rules, with the policy rule's PolicyStoreSourceType 2. It stays on the
    cmdlets because it saves 0.4 s on a call that never appears in the steady
    state, and it is the verb where a mistake reports closed while traffic
    still goes out."""
    branch = _op_branch(_ps1(), "AllowOut")
    assert "FwPolicy2" not in branch and "SetCustomOption" not in branch
    assert "PolicyStoreSourceType" in _ps1()
```

Der alte `test_allowout_..._because_cim_cannot_read_the_activestore` wird durch
diesen ersetzt, und
`test_profiles_stays_on_the_cmdlets_because_com_reads_the_local_store_not_what_is_in_force`
durch Task 1s `test_profiles_reads_cim_with_the_option_and_never_com` — beide
alten Namen behaupten ab jetzt Widerlegtes. **Das sind die einzigen vorhandenen
Tests, die dieser Plan anfassen darf**; jede weitere Änderung an einem
vorhandenen Test ist ein Grund, anzuhalten und zu berichten.

- [ ] **Step 2: Laufen lassen, Rot sehen**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py -k "both_halves or both_reasons or does_not_pay" -v`
Expected: FAIL

- [ ] **Step 3: `List` umbauen**

`Via` ist `fast`, wenn beide Hälften `fast` sind, sonst `cmdlet`. `Fallback`
nennt jede zurückgefallene Hälfte mit Präfix (`profiles: …`, `rules: …`), die
beiden mit `; ` verbunden.

- [ ] **Step 4: `AllowOut`s Begründung im Skript richtigstellen**

Der Kommentar über `Get-ForeignAllowOut` und der entsprechende Absatz im
Kopfkommentar nennen ab jetzt den gemessenen Grund: der ActiveStore **ist**
über die Operationsoption lesbar (136 Regeln wie das Cmdlet, die
Richtlinien-Regel mit `PolicyStoreSourceType=2`, 1,29 s gegen 1,69 s), aber der
Verb kommt in der Ruhelast nicht vor und ein Fehler darin meldet „geschlossen",
während Verkehr rausgeht.

- [ ] **Step 5: Tests laufen lassen**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py tests/test_firewall_api.py -v`
Expected: PASS

- [ ] **Step 6: Ganze Suite**

Run: `make -s unit-test`
Expected: grün

- [ ] **Step 7: Committen**

```bash
git add webui/firewall_rules.ps1 webui/firewall_rules.py tests/test_firewall_rules.py
git commit -m "fix(firewall): List says fast only when both halves were, and AllowOut's reason for staying on the cmdlets is the measured one"
```

---

### Task 3: Auf der VM beweisen, und aufschreiben

**Files:**
- Modify: `docs/superpowers/plans/2026-11-16-firewall-tab-handover.md`
- Modify: `docs/superpowers/specs/2026-11-19-in-force-reads-design.md` (ein
  „Nach dem VM-Lauf"-Abschnitt)

- [x] **Step 1: `Compare` in vier Zuständen, einer davon neu**

Je mit `-Op Compare`: nichts isoliert mit stehenden Regeln; Schnitt steht;
konvergiert; **und der Zustand, den es vorher nicht gab** — eine lokale
Gruppenrichtlinie, die den Stores widerspricht
(`Set-NetFirewallProfile -PolicyStore $env:COMPUTERNAME -Profile Domain -DefaultOutboundAction Allow`
über einem lokalen `Block`), denn genau dort ist COM durchgefallen. Jeder Lauf
muss Exit 0 geben; der Richtlinien-Zustand ist der, der zählt.

- [x] **Step 2: Vorher/Nachher messen**

Zeiten je Verb im frischen Prozess und die Ruhelast über 100 s. Erwartung:
`Profiles` 0,6 s statt 1,16 s, `List` unter 1 s statt 1,43 s, Ruhelast unter
den 18 % von vor dieser ganzen Spur. **Wird sie nicht erreicht, steht das so in
den Dokumenten** — wie beim Vorgänger.

- [x] **Step 3: Alles zurückstellen und prüfen**

Richtlinien-Store leeren, Profile auf `NotConfigured`, `gpupdate`, keine
TDC-Regeln übrig, Netz wieder da.

- [x] **Step 4: Dokumente nachziehen**

Der Richtlinien-Zustand als Pflichtprüfung in den Handover, mit der Begründung,
warum die drei alten Zustände ihn nicht ersetzen. Die gemessenen Zahlen in die
Aufruf-Bilanz. Die drei neu belegten Zuordnungen (CIM `2` = Allow,
`Enabled` `0`/`1`, `PolicyStoreSourceType` `2` = GroupPolicy) aus der Liste der
unbestätigten streichen. Und die beiden Punkte, die diese Messung nebenbei
geschlossen hat: die Local/GroupPolicy-Trennung für Regeln (ActiveStore 539,
PersistentStore 538) und dass COM eine Richtlinien-Regel nicht sieht.

- [x] **Step 5: Committen**

```bash
git add docs/
git commit -m "docs(firewall): the policy state is a mandatory Compare check, with the measured before and after"
```
