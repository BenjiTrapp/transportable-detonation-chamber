# Modulfreies Lesen dessen, was in Kraft ist

Nachfolger von `docs/superpowers/specs/2026-11-18-module-free-reads-design.md`.
Dort wurde `Profiles` umgestellt und **zurückgenommen**, weil kein modulfreier
Weg zum ActiveStore bekannt war. Dieser Entwurf baut auf dem einen Weg, der
damals offen blieb und jetzt gemessen ist.

## Absicht und das Warum

Der Vorgänger endete mit einem verfehlten Ziel: die Ruhelast eines zuschauenden
Tabs lag vorher bei 18 %, danach bei 19,5 %. Der Grund war eine Rücknahme, nicht
ein Rechenfehler — `Profiles` musste zurück auf die Cmdlets, weil COM **den
lokalen Store** liest und nicht, was in Kraft ist. Auf einem Host, wo eine
Gruppenrichtlinie ausgehend `Allow` setzt, während ISOLATED lokal `Block`
schreibt, hätte der schnelle Weg „geschlossen" gemeldet, während der Ausgang
offen ist.

Damit blieben vier von sechs Aufrufen der Ruhelast `Profiles`, und `List` lädt
das Modul nur noch für seine Profilhälfte.

Offen blieb damals **ein** Weg, ausdrücklich als unmessen im Skript vermerkt:
`-PolicyStore` als **CIM-Operationsoption**. Der ist jetzt gemessen, und er
trägt.

### Was gemessen wurde

Das CDXML des NetSecurity-Moduls deklariert `<Option OptionName="PolicyStore">` —
die Option ist also der Mechanismus des Moduls selbst, nicht einer, der hier
erfunden wird. Dieselbe Option direkt gesetzt, auf der VM, mit einer lokalen
Gruppenrichtlinie, die den Stores widerspricht:

| Weg | Domain | Regeln | entspricht |
|---|---|---|---|
| ohne Option | `4` = Block | 538 | PersistentStore |
| **Option `ActiveStore`** | **`2` = Allow** | **539** | **ActiveStore, was in Kraft ist** |
| Option `PersistentStore` | `4` = Block | 538 | PersistentStore |
| COM | `0` = Block | 538 | lokal (wie belegt) |
| Cmdlet-Wahrheit | ActiveStore `Allow`, Persistent `Block` | 539 / 538 | — |

Kosten, frischer Prozess, unbelastete VM:

| | heute | mit der Option |
|---|---|---|
| beide Stores lesen (was `Profiles` braucht) | 1,20 s | **0,61 s** |
| davon im Prozess | 738 ms | **213 ms** (zweiter Store nur +39 ms) |
| Prüfstein + echter Lesevorgang | — | **0,57 s** (140 ms + 34 ms) |
| NetSecurity geladen | ja | **nein** |

Nebenbei belegt, gegen die Cmdlet-Wahrheit geprüft: CIM `0`/`2`/`4` =
NotConfigured/Allow/Block (alle drei, auch `2`); `Enabled` ist auf diesem Weg
**`0`/`1`**, nicht die WMI-Konvention 1/2, mit abgeschalteter Public-Firewall
belegt; `PolicyStoreSourceType` **`2` = GroupPolicy**, bisher war nur `1` = Local
bekannt.

### Der eine Vorbehalt, und warum er beherrschbar ist

`mustComply = $true` wird vom WS-Man-WMI-Plug-In **abgelehnt**
(„unterstützt das angegebene OptionSet-Element nicht"). Die Option lässt sich
also nicht erzwingen, und ein Anbieter, der sie stillschweigend ignoriert, würde
den **konfigurierten** Wert liefern, den TDC dann als *in Kraft* ausgäbe. Das ist
genau die Richtung, die „geschlossen" meldet, während offen ist.

Gemessen ignoriert dieser Anbieter sie nicht: ein Lesevorgang auf einen Store,
den es nicht geben kann, **scheitert** („Der Netzwerkpfad wurde nicht
gefunden"), in 140 ms. Daraus wird der **Prüfstein**: vor jedem schnellen
Profil-Lesen wird ein unmöglicher Store gelesen, und *gelingt* er, hat sich der
schnelle Weg selbst disqualifiziert. Das ist ein Beweis **je Aufruf**, keine
Zusicherung der API.

## Ziele

1. `Profiles` liest beide Stores modulfrei, in einem Spawn, deutlich unter einer
   Sekunde — und damit wird `List` vollständig modulfrei, weil nur noch seine
   Profilhälfte das Modul lud.
2. Die Ruhelast fällt messbar unter die 18 % von vor dieser ganzen Spur.
3. Die Zwei-Store-Trennung bleibt **exakt**: der ActiveStore beantwortet nur
   „ist es jetzt zu?", der PersistentStore nur „was muss zurück?".
4. Ein schneller Weg, der die Option nicht erzwingen kann, **beweist je Aufruf**,
   dass sie befolgt wird, oder antwortet nicht.
5. Der schnelle Weg bleibt eine **Abkürzung, keine Abhängigkeit**.

## Nicht-Ziele

- **`AllowOut` bleibt bei den Cmdlets.** Es ist über die Option erreichbar
  (gemessen: 136 Regeln wie das Cmdlet, die Richtlinien-Regel mit
  `PolicyStoreSourceType=2`), spart aber nur 0,4 s auf einem Aufruf, der in der
  Ruhelast **gar nicht vorkommt** — und es ist der Verb, bei dem ein Fehler
  „geschlossen" meldet, während Verkehr rausgeht. Seine Korrektheit wird nicht
  besser; sie ist heute schon richtig.
- Schreibvorgänge werden nicht angefasst.
- Kein residenter Prozess, keine neue Abhängigkeit, keine neue Route.

## Anti-Ziele — was dies zum Fehlschlag macht

- **Einen konfigurierten Wert als „in Kraft" ausgeben.** Entweder weil die
  Option ignoriert wird (dagegen der Prüfstein) oder weil im Code der falsche
  Store das falsche Feld füllt (dagegen dieselben Wächter, die schon einmal
  gegen 22 verbotene Änderungen geprüft wurden).
- **Eine vertauschte Zahlenzuordnung**, die „geschlossen" meldet, wo nichts
  geschlossen ist.
- **Ein stiller Rückfall.** Ein schneller Weg, der dauernd scheitert, muss
  auffindbar sein, nicht nur spürbar.
- **Eine Testbegründung, die nicht mehr stimmt.** Der Pin-Test heißt heute
  `test_allowout_stays_on_the_cmdlets_because_cim_cannot_read_the_activestore`.
  Dieser Satz ist ab jetzt **falsch**. Ein Test, dessen Name eine widerlegte
  Behauptung trägt, ist Dokumentation, die lügt — und das ist in diesem Projekt
  der am häufigsten wiederholte Fehler.

## Beschränkungen

- Keine neue Abhängigkeit. Kommentare und Commit-Nachrichten auf Englisch.
- `firewall_rules.ps1` baut aus Argumenten nie etwas anderes als die Parameter
  *eines* Aufrufs; kein `-Command`, kein `Invoke-Expression`.
- Die **JSON-Verträge** von `Profiles`, `List` und `Get` bleiben unverändert;
  die vorhandenen Tests der Python-Seite müssen ohne Änderung grün bleiben.
- Kein Wert wird geraten: eine Zahl oder Schreibweise außerhalb der
  ausgeschriebenen Zuordnung löst den Rückfall aus.
- Kein Test liest das echte Netz, die echte Uhr, die Umgebung oder das
  Dateisystem außerhalb eines tmp-Verzeichnisses.

## Der Entwurf

### Wer welche Frage beantwortet

| Frage | Quelle |
|---|---|
| Profile **in Kraft** (`Enabled`, `DefaultOutboundAction`) | CIM, Operationsoption `PolicyStore = ActiveStore` |
| Profile **konfiguriert** (`Configured`) | CIM, Operationsoption `PolicyStore = PersistentStore` |
| TDC-Regeln | COM, unverändert |
| Fremde Ausgangs-Allow-Regeln (`AllowOut`) | Cmdlets, unverändert |

Die Sitzung kommt aus `[Microsoft.Management.Infrastructure.CimSession]::Create('.')`.
`Create($null)` scheitert mit „Der Parameter ist ungültig" — das war der Fehler,
der diesen Weg in der ersten Messung als tot erscheinen ließ. Ein Rechnername,
`localhost` oder `.` funktionieren alle; keiner lädt ein Modul.

### Der Prüfstein

Vor dem ersten verwertbaren Wert liest der schnelle Weg einen Store, den es
nicht geben kann. Scheitert er, ist die Option befolgt und die beiden echten
Lesevorgänge dürfen gelten. **Gelingt** er, wird die Option ignoriert, und der
schnelle Weg wirft — fällt also auf die Cmdlets zurück, statt einen
konfigurierten Wert als in Kraft auszugeben.

**Sein Name entscheidet, ob er bezahlbar ist**, und das ist gemessen. Ein
unbekannter Store wird als **Rechnername** behandelt — was logisch ist, denn
`-PolicyStore <Rechnername>` *ist* die Adresse des lokalen Richtlinien-Stores.
Ein Name, der ein legaler Rechnername ist, schickt also eine Namensauflösung los,
in der Kammer, deren Verkehr TDC aufzeichnet:

| Prüfstein-Name | min / Mittel / max | DNS-Spur | Fehler |
|---|---|---|---|
| `TDC-NoSuchStore` | 24 / 545 / **5205** ms | **ja** | Netzwerkpfad nicht gefunden |
| `not-a-store.invalid` | 34 / 78 / 362 ms | **ja** | Netzwerkpfad nicht gefunden |
| **`TDC\|NoSuchStore`** | 27 / **46** / **160** ms | **nein** | Syntax des Datei- oder Verzeichnisnamens ist falsch |

Der Name trägt deshalb ein Zeichen, das in keinem Rechner- und keinem
Pfadnamen vorkommen kann. Er wird dennoch **vom Anbieter** abgelehnt, nicht vom
Client: der Fehler kommt als „Fehler beim Durchlaufen einer Auflistung", also
während der Aufzählung, und dass ein legaler Name einen Rechner zu erreichen
*versucht*, zeigt, dass der Wert durchgereicht wird. Ein Wert, den der Client
vorher abwiese, würde nichts beweisen.

Bleibender Vorbehalt, ehrlich benannt: auf einer Maschine, deren Client solche
Werte selbst abweist, wäre der Prüfstein leer — er würde scheitern, ohne den
Anbieter gefragt zu haben. Dagegen steht `Compare` im Richtlinien-Zustand, das
genau dann eine Differenz zeigt.

### Der Rückfall, und dass `List` ihn ganz erzählt

Jeder Zweifel — Ausnahme, fehlendes Profil, unbekannte Zahl, leere Antwort, ein
gelungener Prüfstein, CIM gar nicht verfügbar — führt auf den heutigen
Cmdlet-Weg, und die Antwort sagt, welcher Weg sie erzeugt hat.

`List` hat jetzt **zwei** schnelle Hälften (Profile und Regeln). Sein `Via` ist
`fast` nur, wenn **beide** schnell gelesen wurden; `Fallback` nennt **jede**
Hälfte, die zurückfiel, mit ihrem Grund. Heute kann eine der beiden Begründungen
verloren gehen, weil `Via` nur die Regeln beschrieb; das wird mit derselben
Änderung geschlossen.

### `Compare` bekommt seine Profilhälfte zurück

Mit zwei Wegen gibt es wieder etwas zu vergleichen: je Profil `Enabled`, der in
Kraft befindliche und der konfigurierte Wert, **unabhängig** auf beiden Wegen
gelesen. `checked` bekommt einen eigenen Zähler dafür, damit ein Durchlauf ohne
Regeln weiterhin als leer zu erkennen ist.

`Compare` bleibt das **Gate**: kein Test auf macOS kann bestätigen, dass CIM mit
der Option dasselbe sagt wie die Cmdlets.

### Was Tests auf macOS können und was nicht

Testbar: dass der Prüfstein vor jedem verwertbaren Wert steht; dass der
ActiveStore nie `Configured` füllt und der PersistentStore nie die in Kraft
befindlichen Felder; dass jede Zuordnung ausgeschrieben ist und eine unbekannte
Zahl zurückfällt; dass `List` nur `fast` sagt, wenn beide Hälften schnell waren;
dass die JSON-Verträge unverändert sind.

**Nicht testbar:** ob die Option auf echtem Windows wirklich den ActiveStore
liefert. Dafür ist `Compare` da, und dieses Mal gehört in die Pflichtprüfung ein
Zustand, den es vorher nicht gab: **eine lokale Gruppenrichtlinie, die den
Stores widerspricht** — der Zustand, der COM überführt hat. Ein schneller Weg,
der dort nicht genau die Cmdlet-Antwort gibt, ist falsch.

## Was dem Builder überlassen bleibt

- Die Form des Lesers (eine Funktion mit Store-Parameter oder zwei), solange
  kein Aufrufer die beiden Stores verwechseln kann.
- Der Name des unmöglichen Stores, solange er nicht wie ein echter aussieht.
- Wie `List` seine beiden Gründe zusammenfügt, solange beide lesbar bleiben.

## Entscheidungen des Autors, die der Nutzer prüfen sollte

1. **`AllowOut` bleibt zurückgenommen**, obwohl es jetzt ginge — 0,4 s auf einem
   seltenen Aufruf rechtfertigen den gefährlichsten Verb nicht.
2. **Der Prüfstein kostet einen zusätzlichen CIM-Aufruf je Profil-Lesen.** Er ist
   mit 140 ms bezahlt und ersetzt eine Zusicherung, die die API verweigert.
3. **`mustComply` wird nicht verwendet**, weil das Plug-In jeden Aufruf damit
   ablehnt — nicht, weil es unerwünscht wäre.

## Nach dem VM-Lauf

**Ergebnis: der Entwurf trägt, und das Ziel ist erreicht.** Die Ruhelast eines
zuschauenden Tabs liegt bei **11,0 %** und **12,9 %** eines `powershell.exe`
(4 Aufrufe je 100 s, zweimal gemessen; im zweiten Fenster alle vier auf dem
schnellen Weg, `{'fast': 4}`), gegen 18 % vor der ganzen Spur und 19,5 % nach den
Rückbauten des Vorgängers. Je Verb, frischer Prozess, unbelastete VM: `Profiles`
1,16 s → **0,62 s**, `List` 1,43 s → **0,65 s**, `Get` 0,63 s → 0,53 s,
`AllowOut` 1,69 s → 1,77 s (unverändert, bei den Cmdlets).

**`Compare` in sechs Zuständen, alle Exit 0.** A: nichts isoliert, IPv4, IPv6 und
**UDP** stehen (`profiles 9, displayNames 3, names 6, fields 54`); B: der Schnitt
steht (`… 4, 8, 72`); C: konvergiert (`… 3, 6, 54`); **D: eine lokale
Gruppenrichtlinie widerspricht dem lokalen Store**; E: D plus eine Regel der
Richtlinie; F: normal, nach dem Zurückstellen (D bis F: `profiles 9`, Regeln 0).
D ist der Zustand, der zählt: in Kraft `Allow, Allow, Block`, konfiguriert
Domain `Block`, und `Profiles` meldete `Allow` mit `Configured: Block` — genau
die Spaltung, bei der COM `Block` sagte. Ein Durchlauf durch das Isolieren
danach: Schnitt geschlossen (`out=000`, Loopback 200), konvergiert zu `isolated`
mit `verified=True`, sauber verlassen, die Firewall zurück auf `NotConfigured`,
keine TDC-Regeln übrig, Netz wieder bei 200.

**Der Prüfstein hat einen Namen, der gemessen werden musste.** Ein unbekannter
Store gilt als Rechnername, und ein legaler Name schickt eine Namensauflösung
los: `TDC-NoSuchStore` 24 / 545 / **5205** ms mit einer DNS-Spur,
`not-a-store.invalid` 34 / 78 / 362 ms mit einer, **`TDC|NoSuchStore`** 27 / **46**
/ **160** ms **ohne** (je zehn Lesevorgänge, DNS-Cache vorher geleert; ein
getrennter Lauf des alten Namens über zwanzig Lesevorgänge gab 35 / 319 / 5429
ms). Nach 5
und nach 6 `Profiles`-Aufrufen blieb die DNS-Spur leer. Außerdem zählt nur eine
`CimException` mit `NativeErrorCode` `Failed` als Ablehnung (über acht Läufe
stabil; ein falscher Namespace gibt `InvalidNamespace`). Der Vorbehalt bleibt:
`Failed` ist ein allgemeiner Anbieterfehler, die Lücke wird also verengt, nicht
geschlossen, und `Compare` im Richtlinien-Zustand ist die Rückendeckung. Ein
**leerer** Storename antwortet wie keine Option mit allen drei Profilen und darf
deshalb nie der Wert des Prüfsteins sein.

**Zwei Fehler, die erst die VM fand.**

1. **`List` lieferte `"profiles": null`** und behauptete bei jedem Aufruf `Via:
   cmdlet` mit leerer Begründung, im Leerlauf wie unter Last. Der `List`-Zweig
   schrieb in `$profiles`, und der `param()`-Block des Skripts deklariert
   `[string]$Profiles`: PowerShell unterscheidet bei Variablen Groß- und
   Kleinschreibung nicht, der `switch` läuft im selben Gültigkeitsbereich wie die
   Parameter, die Zeile schrieb also in den typisierten Parameter und machte aus
   dem Objekt dessen `ToString()`. Der Verbraucher verschluckte es:
   `webui/firewall_rules.py` fängt das fehlerhafte `profiles` ab und setzt
   `states = None`, ohne ein Wort.
2. **Vier `foreach ($name in …)`-Schleifen in `Compare`** schrieben ebenso in
   `[string]$Name`. Heute harmlos, weil sie nur Zeichenketten durchlaufen, aber
   dieselbe Falle. Ein Test verbietet jetzt jeden Schreibvorgang des Skripts auf
   einen Parameternamen, die Parameterliste aus dem Skript selbst gelesen, und er
   ist an fünf Mutationen erprobt.

**Daraus wird eine neue Pflichtprüfung.** `Compare` übt die **Leser**, nicht die
**Zweige der Verben**; ein kaputter Zweig bleibt ihm unsichtbar — der erste
Beweislauf war ganz grün, während `List` `null` lieferte. Die Pflichtprüfung auf
der VM muss deshalb das **JSON jedes Verbs selbst lesen** (`Profiles`, `List`,
`Get`, `AllowOut`), nicht nur `Compare` laufen lassen. Sie steht im Handover.

**Was das Entwurfsurteil bestätigt:** `AllowOut` bleibt bei den Cmdlets, und der
Grund ist der wahre — die Option *kann* den ActiveStore lesen (136 aktivierte
ausgehende Allow-Regeln, wie das Cmdlet, die Richtlinien-Regel mit
`PolicyStoreSourceType = 2`), spart aber 0,4 s auf einem Aufruf, der in der
Ruhelast nicht vorkommt, und ist der Verb, bei dem ein Fehler „geschlossen“
meldet, während Verkehr rausgeht. Die Zuordnungen CIM `0`/`2`/`4`, `Enabled`
`0`/`1` und `PolicyStoreSourceType` `2` = GroupPolicy sind damit belegt; ebenso
die Trennung Local/GroupPolicy bei Regeln (ActiveStore 539, PersistentStore 538)
und dass COM eine Richtlinien-Regel nicht sieht (538 mit und ohne). Die
Zahlen und das Vorher/Nachher stehen im Handover.
