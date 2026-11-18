# Modulfreie Lesevorgänge — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die vier Lese-Verben der Firewall antworten in einem Spawn und unter
einer Sekunde, ohne das NetSecurity-Modul — und beweisen auf der VM, dass sie
dasselbe sagen wie die Cmdlets.

**Architecture:** `webui/firewall_rules.ps1` behält Verbnamen, Parameter und
JSON-Ausgabe. Jedes Lese-Verb bekommt davor einen schnellen Weg: **COM**
(`HNetCfg.FwPolicy2`) für die in Kraft befindlichen Werte und die Regelliste,
**CIM** (`MSFT_NetFirewall*`) für den konfigurierten Store und
`PolicyStoreSourceType`. Bei jedem Zweifel fällt der Verb auf die Cmdlets
zurück und vermerkt das im Ergebnis. Ein neues Verb `Compare` stellt beide Wege
feldweise gegenüber und ist das Gate.

**Tech Stack:** PowerShell 5.1 (`firewall_rules.ps1`), Python 3 (unverändert),
pytest.

**Spec:** `docs/superpowers/specs/2026-11-18-module-free-reads-design.md`

## Global Constraints

- Keine neue Abhängigkeit. Kommentare und Commit-Nachrichten auf Englisch.
- **Die Python-Seite wird nicht geändert.** Der beste Beweis, dass der Vertrag
  hält, sind die vorhandenen Tests, die ohne Änderung grün bleiben.
- **Schreibvorgänge bleiben unangetastet:** `Create`, `Cut`, `Remove`,
  `SetDefaultOutbound`, `DisableAllowOut`, `EnableAllowOut`, `RemoveIsolate`,
  `Enable`.
- `firewall_rules.ps1` baut aus Argumenten nie etwas anderes als die Parameter
  *eines* Aufrufs; kein `-Command`, kein `Invoke-Expression`.
- **Die beiden Stores werden nie vermischt:** *in Kraft* (ActiveStore, von COM)
  beantwortet „ist es jetzt zu?"; *konfiguriert* (PersistentStore, von CIM)
  beantwortet „was muss zurück?". COM kennt `NotConfigured` nicht und darf
  deshalb den konfigurierten Store nie beantworten.
- **Kein Wert wird geraten.** Eine Zahl außerhalb der bekannten Zuordnung löst
  einen Rückfall aus, keine Vermutung.
- **Kein stiller Rückfall:** jede Antwort sagt, welcher Weg sie erzeugt hat, und
  bei einem Rückfall warum.
- Kein Test liest das echte Netz, die echte Uhr, die Umgebung oder das
  Dateisystem außerhalb eines tmp-Verzeichnisses.
- Gemessene Ausgangswerte (unbelastete VM): nacktes `powershell.exe` 0,36 s;
  `Get-NetFirewallRule` 1,65 s; COM 538 Regeln 0,52 s; CIM Profile 0,52 s; CIM
  gefilterte Regeln 0,85 s; ein Spawn mit COM+COM+CIM 0,64 s.

## Review Focus

1. **Eine vertauschte Zahlenzuordnung**, die „geschlossen" meldet, wo nichts
   geschlossen ist — der Fehler, den dieses Feature drei Mal hatte. → Task 1, 3
   und das `Compare`-Gate.
2. **Der konfigurierte Store von COM beantwortet**, wodurch `NotConfigured` zu
   `Allow` wird und TDC die Firewall anders zurückgibt, als es sie vorfand. → Task 1.
3. **Eine Regel aus einer Gruppenrichtlinie als lokal gemeldet**, wodurch
   ISOLATED versucht, etwas abzuschalten, was sich nicht abschalten lässt, und
   `allowed_out` falsch wird. → Task 3.
4. **Ein Rückfall, der dauernd passiert und nur als Langsamkeit auffällt.** → Task 1.
5. **COM oder CIM nicht verfügbar** (abgeschalteter Dienst, gehärtete VM): jeder
   Verb muss dann vollständig auf dem alten Weg funktionieren. → Task 1–3.

---

### Task 1: `Profiles` ohne Modul, mit Rückfall und `Compare`

**Files:**
- Modify: `webui/firewall_rules.ps1` (Kopfkommentar, `ValidateSet` von `$Op`,
  `Get-ProfileStates`, der `'Profiles'`-Zweig; neues Verb `Compare`)
- Test: `tests/test_firewall_rules.py`

**Interfaces:**
- Produces: `Profiles` gibt dieselbe JSON-Liste wie heute
  (`Name`, `Enabled`, `DefaultOutboundAction`, `Configured`), plus ein Feld, das
  den benutzten Weg nennt (`Via` = `fast` oder `cmdlet`, bei Rückfall mit
  `Fallback` = Grund). `Compare` gibt `{ok, checked, differences[]}` und endet
  mit 0 oder 1.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_profiles_verb_names_the_way_it_was_answered():
    script = _ps1()
    assert "'Compare'" in _validate_set(script), "Compare is not an accepted op"
    # the contract the Python side reads must be unchanged
    assert '"Configured"' in script and '"DefaultOutboundAction"' in script

def test_com_never_answers_the_configured_store():
    """COM cannot express NotConfigured, so it must not feed Configured."""
    branch = _op_branch(_ps1(), "Profiles")
    com = _lines_mentioning(branch, "FwPolicy2")
    assert com, "the fast path for Profiles is missing"
    assert not any("Configured" in l for l in com), \
        "COM must not answer the configured store: %s" % com

def test_an_unknown_number_falls_back_instead_of_guessing():
    branch = _op_branch(_ps1(), "Profiles")
    assert "Fallback" in branch or "fallback" in branch
    # every mapped number is named explicitly, no arithmetic on the enum
    assert "NotConfigured" in branch

def test_the_ops_the_module_emits_are_the_ops_the_script_accepts():
    # the existing test, extended: Compare is accepted but Python never emits it
    ...
```

Dazu in `tests/test_firewall_rules.py` ein Helfer, der den Zweig eines Verbs aus
dem Skript schneidet (`_op_branch`), und einer für das `ValidateSet`
(`_validate_set`) — die Datei prüft das Skript schon als Text, dieselbe Art.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py -k "profiles_verb or configured_store or unknown_number" -v`
Expected: FAIL — `Compare` ist kein Verb, es gibt keinen schnellen Weg

- [ ] **Step 3: Implement the fast path for `Profiles`**

`Get-ProfileStates` bekommt zwei Quellen statt einer: die in Kraft befindlichen
Werte und `Enabled` aus COM (`$p.FirewallEnabled($t)`,
`$p.DefaultOutboundAction($t)` für `$t` in 1 = Domain, 2 = Private, 4 = Public),
den konfigurierten Wert aus CIM (`MSFT_NetFirewallProfile`, Feld
`DefaultOutboundAction`). Beide Zahlenmengen werden über **ausgeschriebene**
Zuordnungen in die heutigen Zeichenketten übersetzt; eine Zahl, die dort nicht
steht, löst den Rückfall aus. Scheitert irgendetwas — Ausnahme, fehlendes
Profil, unbekannte Zahl, leere Antwort — läuft der heutige Cmdlet-Weg und das
Ergebnis trägt `Via = "cmdlet"` samt Grund.

Der Kopfkommentar des Skripts bekommt den Abschnitt, warum zwei Quellen nötig
sind: COM kann `NotConfigured` nicht, rohes CIM erreicht den ActiveStore nicht
(`PolicyStore='ActiveStore'` wird mit „Die Anfrage ist ungültig" abgelehnt).

- [ ] **Step 4: Implement the `Compare` verb, for the profiles**

`Compare` liest die Profile auf **beiden** Wegen und vergleicht je Profil
`Enabled`, den in Kraft befindlichen und den konfigurierten Wert. Ausgabe
`{ok, checked, differences: [{what, fast, cmdlet}]}`, Exit 0 bei Gleichheit,
sonst 1. Es schreibt nichts und ändert nichts.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py tests/test_firewall_api.py -v`
Expected: PASS, **ohne Änderung an den vorhandenen Tests** — der Vertrag hält

- [ ] **Step 6: Commit**

```bash
git add webui/firewall_rules.ps1 tests/test_firewall_rules.py
git commit -m "perf(firewall): Profiles reads COM for what is in force and CIM for what is configured, and says which way answered"
```

---

### Task 2: `List` und `Get` ohne Modul

**Files:**
- Modify: `webui/firewall_rules.ps1` (`'List'`, `'Get'`, die Regel-Projektion)
- Test: `tests/test_firewall_rules.py`

**Interfaces:**
- Consumes: Task 1 (die Rückfall-Form und das `Via`-Feld).
- Produces: `List` und `Get` geben dieselben Felder wie heute
  (`Name`, `Enabled`, `Action`, `Direction`, `Profile`, `Program`,
  `RemoteAddress`, `RemotePort`, `Protocol`), plus `Via`.

- [ ] **Step 1: Write the failing test**

```python
def test_list_keeps_every_field_the_python_side_reads():
    branch = _op_branch(_ps1(), "List")
    for field in ("Name", "Enabled", "Action", "Direction", "Profile",
                  "Program", "RemoteAddress", "RemotePort", "Protocol"):
        assert f'"{field}"' in branch, f"List lost {field}"

def test_list_asks_com_only_for_tdc_rules():
    """538 rules stand on this VM; only TDC-FW-* are ever reported."""
    branch = _op_branch(_ps1(), "List")
    assert "TDC-FW-" in branch and "FwPolicy2" in branch
```

- [ ] **Step 2: Run it to verify it fails**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py -k "list_keeps or list_asks" -v`
Expected: FAIL

- [ ] **Step 3: Implement**

`List` holt `$p.Rules` über COM und projiziert nur die `TDC-FW-*`-Regeln in die
heutige Form; `Direction` und `Action` über ausgeschriebene Zuordnungen
(COM: `1` = In, `2` = Out; `0` = Block, `1` = Allow), `Profiles` als Bitmaske in
die heutige Darstellung. `Get` nimmt denselben Weg für eine Regel — oder bleibt
beim Cmdlet, wenn der Gewinn den Aufwand nicht trägt; dann steht die Begründung
im Bericht. Rückfall wie in Task 1.

- [ ] **Step 4: Run the tests**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py tests/test_firewall_api.py -v`
Expected: PASS, vorhandene Tests unverändert

- [ ] **Step 5: Commit**

```bash
git add webui/firewall_rules.ps1 tests/test_firewall_rules.py
git commit -m "perf(firewall): List and Get read the rules over COM, with the same fields and a fallback"
```

---

### Task 3: `AllowOut` ohne Modul — mit der Store-Quelle

**Files:**
- Modify: `webui/firewall_rules.ps1` (`'AllowOut'`, `Get-ForeignAllowOut`, `Compare`)
- Test: `tests/test_firewall_rules.py`

**Interfaces:**
- Consumes: Task 1, Task 2.
- Produces: `AllowOut` gibt wie heute `{profiles, rules: [{Name, DisplayName, Group, Source}]}`.

- [ ] **Step 1: Write the failing test**

```python
def test_allowout_takes_the_store_source_from_cim_not_com():
    """COM has no PolicyStoreSourceType; without it a GroupPolicy rule would
    be reported as local and ISOLATED would try to switch off what it cannot."""
    branch = _op_branch(_ps1(), "AllowOut")
    assert "PolicyStoreSourceType" in branch
    cim = _lines_mentioning(branch, "PolicyStoreSourceType")
    assert not any("FwPolicy2" in l for l in cim)

def test_allowout_keeps_its_four_fields():
    branch = _op_branch(_ps1(), "AllowOut")
    for field in ("Name", "DisplayName", "Group", "Source"):
        assert f'"{field}"' in branch

def test_compare_covers_the_allow_out_set_and_its_source():
    branch = _op_branch(_ps1(), "Compare")
    assert "AllowOut" in branch and "Source" in branch
```

- [ ] **Step 2: Run it to verify it fails**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py -k "allowout" -v`
Expected: FAIL

- [ ] **Step 3: Implement**

`AllowOut` fragt CIM nach `MSFT_NetFirewallRule` und filtert auf ausgehend,
Allow, aktiviert (gemessen: `Direction 2`, `Action 2`, `Enabled 1` ergibt die
135, die der heutige Weg auch findet). `Source` kommt aus
`PolicyStoreSourceType` über eine ausgeschriebene Zuordnung (`1` = `Local`);
jeder andere Wert wird als der Zahlenwert *durchgereicht*, nicht geraten, und
gilt damit als nicht lokal. Rückfall wie in Task 1.

`Compare` wird um die Regeln und die Allow-Out-Menge erweitert: je
`TDC-FW-*`-Regel alle Felder von `List`, und für `AllowOut` die **Namen** und
die **Store-Quelle** als Mengen.

- [ ] **Step 4: Run the tests**

Run: `webui/.venv/bin/python -m pytest tests/test_firewall_rules.py tests/test_firewall_api.py -v`
Expected: PASS

- [ ] **Step 5: Run the whole suite**

Run: `make -s unit-test`
Expected: alles grün, vorhandene Tests unverändert

- [ ] **Step 6: Commit**

```bash
git add webui/firewall_rules.ps1 tests/test_firewall_rules.py
git commit -m "perf(firewall): AllowOut reads over CIM and keeps the store source that tells a local rule from a policy one"
```

---

### Task 4: Auf der VM beweisen, und aufschreiben

**Files:**
- Modify: `docs/superpowers/plans/2026-11-16-firewall-tab-handover.md`

- [ ] **Step 1: `Compare` in drei Zuständen fahren**

Auf der VM, je mit `-Op Compare`: nichts isoliert; Schnitt steht
(`TDC-FW-ISO-cut`); konvergiert (Default auf Block, Allow-Regeln ab). Jeder Lauf
muss `ok` und Exit 0 geben. Weicht ein Feld ab, ist der schnelle Weg falsch und
dieser Plan ist nicht fertig.

- [ ] **Step 2: Vorher/Nachher messen**

Die Aufrufzeiten je Verb und die Ruhelast über 100 s, wie im Handover
beschrieben. Erwartung aus der Messung: ein Lesevorgang 0,5–0,9 s statt 1,65 s,
und die Ruhelast deutlich unter den heutigen 18 %.

- [ ] **Step 3: Handover nachziehen**

`Compare` als Pflichtcheck in die Liste, mit den drei Zuständen und dem Grund,
warum kein Test auf macOS ihn ersetzt. Die gemessenen Vorher/Nachher-Werte in
den Abschnitt zur Aufruf-Bilanz, und der residente Prozess dort als **verworfen**
mit Begründung.

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "docs(firewall): Compare is a mandatory VM check, with the measured before and after"
```
