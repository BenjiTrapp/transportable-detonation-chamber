# Modulfreie Lesevorgänge der Firewall

Erweiterung zu `docs/superpowers/specs/2026-11-16-firewall-tab-design.md` und
`docs/superpowers/specs/2026-11-17-panic-cut-design.md`. Betrifft nur das
**Lesen** des Firewall-Zustands, nicht das Schreiben.

## Absicht und das Warum

Jeder Firewall-Aufruf von TDC startet `powershell.exe` und lädt das
NetSecurity-Modul. Auf der VM gemessen, **unbelastet**:

| Weg | Zeit |
|---|---|
| nacktes `powershell.exe -Command exit` | 0,36 s |
| `Get-NetFirewallRule` (also mit Modul) | 1,65 s |
| COM `HNetCfg.FwPolicy2`, 538 Regeln gezählt | **0,52 s** |
| CIM `MSFT_NetFirewallProfile` | **0,52 s** |
| CIM `MSFT_NetFirewallRule`, gefiltert | 0,85 s |
| **ein** Spawn: COM-Regeln + COM-Profile + CIM-Profile | **0,64 s** |

Die Zeit steckt fast vollständig im **Modul-Laden**, nicht im Prozessstart. Und
`Get-NetFirewallProfile` ist eine **CDXML-Funktion** aus NetSecurity — das Modul
ist nur eine Hülle um denselben CIM-Anbieter, den man direkt ansprechen kann.

Unter Last ist derselbe Aufruf 2–3,5 s, weil mehrere `powershell.exe`
gleichzeitig laufen und sich gegenseitig bremsen (das Aufruf-Log zeigt
`wait_ms=0`: keine Sperre, reine Gleichzeitigkeit). Weniger und kürzere Aufrufe
wirken deshalb doppelt.

**Warum nicht der residente Prozess.** Er wäre der größere Hebel (~0,2 s je
Aufruf), aber er stellt eine stundenlang lebende, **erhöhte** PowerShell-Sitzung
in eine Malware-Kammer — ein privilegiertes Ziel, das es heute nicht gibt, denn
jeder Aufruf ist jetzt ein kurzlebiges `powershell.exe -File` mit Argumenten.
Dazu käme, dass eine lange Sitzung Zustand sammelt (`$ErrorActionPreference`,
Variablen, Fehlerzustände), während heute jeder Aufruf frischen Zustand hat —
und der nächste Befehl könnte der Panikschnitt sein. Der Nutzer hat die
Ausfallsicherheit zu Recht in Frage gestellt; die beste Ausfallsicherheit ist,
das anfällige Ding nicht zu brauchen.

## Ziele

1. Ein Lesevorgang kostet **einen** Spawn und deutlich unter einer Sekunde.
2. Die Zwei-Store-Unterscheidung bleibt **exakt** erhalten: *in Kraft* und
   *konfiguriert* werden weiter getrennt gelesen und nie vermischt.
3. Der schnelle Weg ist eine **Abkürzung, keine Abhängigkeit**: scheitert er,
   liefert der alte Weg die Antwort, und der Aufruf ist nur langsam.
4. Kein Wert wird geraten. Jede Zahlenzuordnung ist auf der VM gegen die
   Cmdlet-Antwort geprüft.

## Nicht-Ziele

- **Schreibvorgänge bleiben bei den Cmdlets.** `Create`, `Cut`, `Remove`,
  `SetDefaultOutbound`, `DisableAllowOut`, `EnableAllowOut`, `RemoveIsolate`,
  `Enable` werden nicht angefasst. Sie sind selten; die Last sind die
  Lesevorgänge.
- Kein residenter Prozess, keine neue Abhängigkeit, keine neue Route.
- Die Python-Seite wird **nicht** geändert.

## Anti-Ziele — was dies zum Fehlschlag macht

- **Eine falsche Zahlenzuordnung, die „geschlossen" meldet, wo nichts
  geschlossen ist.** COM und CIM kodieren anders als die Cmdlets
  (COM: `0`/`1` für Block/Allow; CIM: `0`/`2`/`4` für
  NotConfigured/Allow/Block). Eine vertauschte Zuordnung wäre genau der
  Fehler, den dieses Feature drei Mal hatte — eine Oberfläche, die etwas
  behauptet, das nicht stimmt.
- **Die beiden Stores zu vermischen.** COM kennt `NotConfigured` *nicht* und
  kann es nicht melden; es antwortet immer mit dem in Kraft befindlichen Wert.
  Würde man damit den konfigurierten Store beantworten, käme genau der Bug
  zurück, der auf der VM gefunden wurde: `NotConfigured` wird zu `Allow`, und
  TDC gibt die Firewall anders zurück, als es sie vorfand.
- Ein stiller Rückfall. Wenn der schnelle Weg nicht konnte, muss das
  **sichtbar** sein, nicht nur langsam.

## Beschränkungen

- Keine neue Abhängigkeit. Kommentare und Oberflächentext auf Englisch.
- `firewall_rules.ps1` baut aus Argumenten nie etwas anderes als die Parameter
  *eines* Aufrufs; kein `-Command`, kein `Invoke-Expression`.
- Jede geschriebene Regel wird weiter zurückgelesen; was nicht zurückgelesen
  wurde, heißt nie `verified`.
- Kein Test liest das echte Netz, die echte Uhr, die Umgebung oder das
  Dateisystem außerhalb eines tmp-Verzeichnisses.

## Der Entwurf

### Die Verträge bleiben, die Umsetzung wechselt

Die vier **Lese**-Verben von `firewall_rules.ps1` behalten Namen, Parameter und
**JSON-Ausgabe**: `Profiles`, `List`, `Get`, `AllowOut`. Nur ihr Inneres
bekommt einen schnellen Weg davor. Damit ändert sich auf der Python-Seite
nichts — kein Aufrufer, kein Docstring, kein Test der Python-Seite — und die
Fläche des Eingriffs ist eine Datei.

### Wer welche Frage beantwortet, und warum nicht einer allein

| Frage | Quelle | gemessen |
|---|---|---|
| Regeln mit Name, Enabled, Action, Direction, Program, RemoteAddress, Protocol | **COM** `HNetCfg.FwPolicy2.Rules` | 0,52 s für alle 538 |
| Profile *in Kraft* (ActiveStore) | **COM** `FirewallEnabled`, `DefaultOutboundAction` | 0,47 s |
| Profile *konfiguriert* (PersistentStore) | **CIM** `MSFT_NetFirewallProfile` | 0,52 s |
| Ausgangs-Allow-Regeln **mit Store-Quelle** | **CIM** `MSFT_NetFirewallRule` + `PolicyStoreSourceType` | 0,85 s, findet 135 |

Keiner der beiden reicht allein, und das ist der Kern dieses Entwurfs:

- **COM kann den konfigurierten Store nicht.** Gemessen: COM sagt `defOut=1`
  (Allow), während der konfigurierte Wert `NotConfigured` ist. COM hat für
  `NotConfigured` keine Darstellung.
- **Rohes CIM kann den ActiveStore nicht.** Gemessen:
  `PolicyStore='ActiveStore'` in der Abfrage → „Die Anfrage ist ungültig".
  Rohes CIM antwortet aus dem PersistentStore (`Domain=0` = `NotConfigured`).
- **COM hat kein `PolicyStoreSourceType`**, das `AllowOut` braucht, um eine
  lokale Regel (abschaltbar) von einer Gruppenrichtlinien-Regel (nicht
  abschaltbar) zu unterscheiden.

Die Aufteilung ist also keine Optimierung, sondern die einzige, die beide
Stores und die Store-Quelle korrekt liefert.

### Der Rückfall, und dass er zu sehen ist

Jeder Lese-Verb versucht den schnellen Weg und fällt bei **jedem** Zweifel auf
die Cmdlets zurück: eine Ausnahme, ein fehlendes Feld, ein Zahlenwert außerhalb
der bekannten Zuordnung, eine leere Antwort, wo etwas stehen müsste.

Der Rückfall ist **nicht still**: die JSON-Antwort trägt ein Feld, das sagt,
welcher Weg sie erzeugt hat, und bei einem Rückfall den Grund. Das Aufruf-Log
schreibt es mit, so wie es Wartezeit und Laufzeit mitschreibt. Ein Rückfall, der
dauernd passiert, ist damit auffindbar statt nur spürbar.

### Die Zahlenzuordnung wird geprüft, nicht gelesen

Dies ist die eine Stelle, an der ein Fehler teuer ist, deshalb bekommt sie ihre
eigene Absicherung: ein **Differenz-Verb** `Compare`, das beide Wege nebeneinander
ausführt und ihre Ergebnisse feldweise vergleicht. Es ist kein Testgerüst,
sondern Teil des Skripts, damit es auf jeder VM läuft, auch auf einer mit
Gruppenrichtlinien, die hier keine hat.

Was es vergleicht:

- je Profil: `Enabled`, `DefaultOutboundAction` **in Kraft**,
  `DefaultOutboundAction` **konfiguriert**
- je `TDC-FW-*`-Regel: alle Felder, die `List` ausgibt
- die Menge der aktivierten Ausgangs-Allow-Regeln: Namen **und** Store-Quelle

Stimmen alle überein, endet es mit `0` und einer Zusammenfassung. Weicht ein
Feld ab, endet es mit `1` und nennt Feld, schnellen Wert und Cmdlet-Wert.

**Das ist das Gate dieses Entwurfs**: `Compare` muss auf der VM grün sein, und
zwar in mindestens drei Zuständen — nichts isoliert, Schnitt steht, und
konvergiert (Default auf Block, Allow-Regeln ab). Die bekannten
Zahlenzuordnungen (COM `0`/`1`; CIM `0`/`2`/`4`; CIM `Direction 2` = ausgehend,
`Action 2` = Allow, `Enabled 1` = wahr; `PolicyStoreSourceType 1` = lokal) sind
aus der Messung abgeleitet und gelten erst als bestätigt, wenn `Compare` sie
bestätigt — nicht, weil sie hier stehen.

### Was Tests auf macOS hier können und was nicht

Testbar: dass jeder Lese-Verb bei einer Ausnahme des schnellen Wegs auf den
alten zurückfällt und das im Ergebnis vermerkt; dass die JSON-Ausgabe
unverändert ist (die vorhandenen Tests der Python-Seite müssen ohne Änderung
grün bleiben — das ist der beste Beweis, dass der Vertrag hält); dass eine
unbekannte Zahl einen Rückfall auslöst statt einer Vermutung.

**Nicht testbar:** ob COM und CIM auf echtem Windows dasselbe sagen wie die
Cmdlets. Genau dafür ist `Compare` da, und es gehört als Pflichtcheck in
`docs/superpowers/plans/2026-11-16-firewall-tab-handover.md`.

## Was dem Builder überlassen bleibt

- Die Form des schnellen Wegs im Skript (eigene Funktionen je Verb oder eine
  gemeinsame Hilfsschicht), solange der JSON-Vertrag unverändert bleibt.
- Wie der benutzte Weg im Ergebnis heißt, solange er im Aufruf-Log auftaucht.
- Ob `Get` (eine einzelne Regel) den schnellen Weg überhaupt braucht: es ist
  der kleinste Aufruf, und die Antwort darf „nein, nicht der Mühe wert" sein —
  dann mit Begründung im Bericht.

## Entscheidungen des Autors, die der Nutzer prüfen sollte

1. **Schreibvorgänge bleiben unangetastet.** Der Panikschnitt behält damit
   seine 2,4–3,6 s für `Cut`; der Druck wird schneller, weil sein *Profil*-Lesen
   billiger wird, nicht sein Schreiben.
2. **Der residente Prozess ist verworfen**, nach der Messung und wegen der
   erhöhten Dauer-Sitzung in der Kammer.
3. **`Compare` lebt im Skript, nicht im Testordner** — damit es auf jeder VM
   läuft, auch auf einer mit Gruppenrichtlinien.
