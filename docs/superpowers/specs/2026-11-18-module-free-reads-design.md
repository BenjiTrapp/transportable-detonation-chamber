# Modulfreie Lesevorgänge der Firewall

> **Teilweise überholt durch
> `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`.** Dieses Dokument
> bleibt als Stand des Wissens vom 18.11. stehen; vier Schlüsse daraus gelten
> nicht mehr:
>
> - „`List` lädt das Modul für seine Profile weiter“ — **falsch**: `List` ist
>   vollständig modulfrei.
> - „`Profiles` liest deshalb wieder beide Stores über die Cmdlets, `Compare`
>   vergleicht keine Profile mehr, und ein Pin-Test hält das fest“ — **falsch**:
>   `Profiles` liest beide Stores über CIM mit der Operationsoption, `Compare`
>   vergleicht wieder neun Profilfelder, und der Pin-Test ist **gelöscht**.
> - „Nicht gemessen ist der Weg … Operationsoption“ — **gemessen**, und es ist
>   der Weg, der ausgeliefert wird.
> - `AllowOut` zurückgenommen, „weil rohes CIM den ActiveStore nicht lesen
>   kann“ — die Option **kann** ihn lesen. `AllowOut` bleibt bei den Cmdlets aus
>   einem anderen, schwächeren Grund: 0,4 s auf einem Aufruf, der in der
>   Ruhelast nie vorkommt, und es ist der Verb, bei dem ein Fehler „geschlossen“
>   meldet, während Verkehr rausgeht.
>
> Die betroffenen Abschnitte unten sind einzeln als überholt markiert. Das
> Leistungsziel bleibt **unerreicht**: die Ruhelast liegt über drei saubere
> Fenster gemessen bei 18,6 % gegen 19,5 % vorher. Gewonnen ist die Zeit je
> Aufruf, nicht die Ruhelast.

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

## Amended after the VM run — Nachtrag nach dem VM-Lauf

**Dieser Abschnitt geht allem oben vor.** Oben steht der Entwurf, wie er
geplant war; der VM-Lauf hat zwei seiner vier Verben zurückgenommen. Wo der
Text oben von „den vier Lese-Verben“, von CIMs `PolicyStoreSourceType` als
„die einzige, die die Store-Quelle korrekt liefert“, von `Compare` über die
Allow-Out-Menge oder von „Die Python-Seite wird nicht geändert“ spricht, gilt
das Folgende.

### Das Leistungsziel wurde nicht erreicht

*Teilweise überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: `List` und `Profiles` laden kein Modul mehr, und die Zeit je Lesevorgang hat sich halbiert. **Der Satz in der Überschrift gilt weiter**: die Ruhelast liegt bei 18,6 % gegen 19,5 % — die Ursache ist nur eine andere als damals vermutet, nämlich die Startgebühr von `powershell.exe` aus `python.exe` (1,40–1,65 s gegen 0,35 s), die kein Skript berührt. Die Zahlen unten stimmen für den Stand nach dem ersten Rückbau.*

Ziel 1 oben (deutlich unter einer Sekunde je Lesen) gilt nur für `Get`. Das
Ziel dieser Arbeit, einen ruhigeren Tab im Dauerbetrieb, wurde **verfehlt**:
100 s eines beobachtenden Tabs, vorher 5 Aufrufe und 18 % eines
`powershell.exe`, jetzt 6 Aufrufe (`Profiles` ×4, `List` ×2) und **19,5 %**.
Die beiden Lesevorgänge, die den Ruhezustand bestimmen, müssen das Modul der
Richtigkeit wegen laden: `Profiles`, weil COM den lokalen Store liest und nicht
den gültigen, `List`, weil es die Profile mit zurückgibt. Eine frühere Angabe
von 2 Aufrufen und 3,3 % wurde gemessen, als `Profiles` noch umgestellt war, und
ist zurückgezogen.

Gewonnen wurde stattdessen (je Verb, frischer Prozess, drei Läufe; der Boden für
alles, was das Modul lädt, liegt bei 1,08 s, ein nacktes `powershell.exe` bei
0,37 s):

| Verb | jetzt | Cmdlet-Entsprechung |
|---|---|---|
| `Profiles` | 1,16 s | 1,08 s |
| `List` | 1,43 s | 1,70 s |
| `Get` | **0,63 s** | 1,08 s |
| `AllowOut` | 1,69 s | 1,70 s |

`Get` ist modulfrei und spart 0,45 s genau dort, wo Reaktionsfähigkeit zählt
(`cut_stands` alle 10 s unter ISOLATED, das Zurücklesen jedes Schreibvorgangs);
`List` spart 0,27 s; `Compare` hat drei Annahmen widerlegt, darunter die, COM
melde, was in Kraft ist; und die Rücknahme von `AllowOut` und `Profiles` ist
durch Tests festgehalten, die nach dem Grund benannt sind. Der große Gewinn
dieser Arbeitsreihe bleibt der frühere: 42 % und 16 Aufrufe je 100 s, bevor
`/rules` aufhörte, ein Lesen zu erzwingen. Zahlen zu Rückfällen in diesem
Fenster wurden nicht aufgeschrieben.

### Was umgestellt ist

*Geschichte, überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: `List` ist vollständig modulfrei, die Aussage „lädt das Modul für seine Profile weiter“ gilt nicht mehr.*

Nur **`List` und `Get`** lesen TDCs eigene Regeln über COM
(`HNetCfg.FwPolicy2.Rules`), mit der geschriebenen Zuordnung, dem Rückfall auf
die Cmdlets und `Via`/`Fallback` im Aufruf-Log. Ohne Modul läuft damit nur
`Get` (0,63 s); `List` lädt das Modul für seine Profile weiter. Für Regeln
lesen beide Wege denselben Store: COM liest den lokalen Store (siehe unten),
`Get-NetFirewallRule` ohne `-PolicyStore` den PersistentStore, und dorthin
schreiben `Create` und `Cut`. Deshalb stimmte `Compare` feldweise überein. Der
begrenzte Rest: eine `TDC-FW-*`-Regel aus einer Gruppenrichtlinie liegt nicht
im PersistentStore; zeigt COM sie (für Regeln nicht gemessen), sieht nur der
schnelle Weg sie, und `Compare`s Prüfung der Namensmenge meldet das.

### `AllowOut` zurückgenommen

*Geschichte, überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: die Rücknahme gilt weiter, ihr Grund nicht — die Operationsoption kann den ActiveStore lesen; sie bleibt bei den Cmdlets, weil sie 0,4 s auf einem Aufruf spart, der in der Ruhelast nicht vorkommt, und weil dort ein Fehler „geschlossen“ meldet, während Verkehr rausgeht.*

`AllowOut` muss den ActiveStore lesen, Gruppenrichtlinie eingeschlossen. Rohes
CIM gab auf der VM alle 538 Regeln aus dem PersistentStore; die Zählungen
stimmten (135/135/135) nur, weil die VM keine Richtlinien-Regeln hat. Auf einem
Host mit solchen Regeln fehlten sie in `allowed_out`, und ISOLATED meldete
„zu“, während sie Verkehr hinauslassen. COM hat kein `PolicyStoreSourceType`.
`AllowOut` liest deshalb wie vorher `Get-NetFirewallRule -PolicyStore
ActiveStore`; ein Pin-Test hält das fest.

### `Profiles` zurückgenommen — mit dem Experiment

*Geschichte, überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: die Messung („COM liest den lokalen Store, nicht den gültigen“) stimmt weiter und ist der Grund für den Zustand D; die Folgerung nicht. `Profiles` liest beide Stores über CIM mit der Operationsoption, `Compare` vergleicht wieder neun Profilfelder, und der Pin-Test ist gelöscht.*

Der schnelle Weg nahm den *in Kraft* befindlichen Wert von COM. Belegt war nur,
dass COM **nicht** der konfigurierte Store ist (COM `Allow`, wo der
PersistentStore `NotConfigured` sagte); ein COM, der den lokalen Store liest
und `NotConfigured` zu seinem Standard auflöst, antwortet genauso. Beide
unterscheiden sich nur, wo eine Richtlinie einen anderen Wert setzt.
`Set-NetFirewallProfile -PolicyStore $env:COMPUTERNAME` schreibt den lokalen
GPO-Store und baut genau diesen Zustand:

| Store | Domain, ausgehend |
|---|---|
| lokale GPO | `Allow` |
| PersistentStore | `Block` |
| ActiveStore (in Kraft; die Richtlinie gewinnt) | `Allow` |
| COM | `0` = `Block` |

**COM liest den lokalen Store, nicht den gültigen.** `Compare` hat es selbst
gefunden (`exit=1`, `profile Domain DefaultOutboundAction`, schnell `Block`,
Cmdlet `Allow`). Auf einem Host, auf dem eine Richtlinie `Allow` setzt,
während ISOLATED lokal `Block` schreibt, hätte der schnelle Weg „zu“ gemeldet,
während der Ausgang offen ist — das erste Anti-Ziel oben. `verified`, das
ISOLATED-Band und `startup_state` ruhen auf diesem Wert. Die konfigurierte
Hälfte aus CIM war richtig, aber die gültige braucht die Cmdlets und lädt das
Modul ohnehin; es bleibt nichts zu sparen. `Profiles` liest deshalb wieder
beide Stores über die Cmdlets, `Compare` vergleicht keine Profile mehr, und ein
Pin-Test hält das fest. Die VM wurde danach zurückgesetzt.

### Wie weit „rohes CIM erreicht den ActiveStore nicht“ reicht

*Geschichte, überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: der hier „nicht gemessene“ Weg, `-PolicyStore` als CIM-Operationsoption, ist gemessen und wird ausgeliefert.*

Versucht wurden zwei Wege: ein Namespace (`root/standardcimv2/ActiveStore`,
„Ungültiger Namespace“) und ein Abfragefilter (`PolicyStore='ActiveStore'`,
„Die Anfrage ist ungültig“). Nicht gemessen ist der Weg, den die
NetSecurity-CDXML vermutlich nimmt: `-PolicyStore` als CIM-**Operationsoption**
(`CimOperationOptions.SetCustomOption`). Ihn zu messen ist das Einzige, was ein
schnelles Lesen des gültigen Werts zurückbringen könnte, für `Profiles` und
`AllowOut`.

### Die Python-Seite

Sie **wurde** geändert, und nur dafür, was dieser Entwurf selbst verlangt: dass
ein Rückfall im Aufruf-Log steht. `firewall_rules.py` liest `Via` und
`Fallback` aus der Antwort (bei einem `Get` ohne Regel von stderr) und gibt sie
an `CALL_OBSERVER`; `app.py` schreibt sie in die Aufruf-Zeile. Kein Aufrufer,
kein JSON-Vertrag und kein vorhandener Test der Python-Seite wurde geändert.

### `Compare` heute

*Geschichte, überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: `Compare` vergleicht wieder Profile (neun Profilfelder), nicht mehr nur Regeln.*

Es vergleicht nur TDCs Regeln, wie `List` und wie `Get` sie schnell lesen,
gegen die Cmdlets, dazu die Namensmenge und `DisplayName = Name`. Die Ausgabe
zählt getrennt: `{"ok","rules","checked":{"displayNames","names","fields"},
"differences"}`. `rules: 0` heißt: nichts verglichen, was auch immer `ok` sagt.

Der Lauf nach dem Rückbau, alle drei mit Exit 0:

| Zustand | `rules` | `displayNames` / `names` / `fields` |
|---|---|---|
| A: TCP/IPv4-, TCP/IPv6- und **UDP**-Regel, je mit Port und Programm | 3 | 3 / 6 / 54 |
| B: A plus der Rundumschnitt | 4 | 4 / 8 / 72 |
| C: keine Regeln | 0 | 0 / 0 / 0 |

Damit ist Protokoll `17` (UDP) bestätigt, ebenso beide Adressfamilien, Ports und
Programmpfade. Nicht bestätigt bleiben, was in der Übergabe unter „Mapped but
not confirmed“ steht (Richtung eingehend, Profilmasken `1` bis `6`, Aktion
Allow an einer Regel, eine deaktivierte Regel).

### Entscheidung 1 oben

*Geschichte, überholt durch `docs/superpowers/specs/2026-11-19-in-force-reads-design.md`: der Druck liest die Profile wieder schnell, über CIM mit der Operationsoption.*

„Der Druck wird schneller, weil sein Profil-Lesen billiger wird“ gilt nicht
mehr: der Druck liest die Profile wieder über die Cmdlets.
