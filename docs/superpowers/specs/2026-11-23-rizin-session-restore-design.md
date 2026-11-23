# Die Emulationssitzung wiederherstellen

## Absicht

Ein Patch, den man in **entschlüsselten** Code setzt, ist der Kern des
Entpack-Ziels: man lässt die Entschlüsselung laufen, liest den Code, und knipst
den Anti-VM-Check darin aus. Heute geht dieser Patch beim Wiederöffnen der Datei
still kaputt, und zwar schlimmer als „er fehlt":

`_replay_patches` läuft beim Öffnen, **vor** jedem Lauf. Der Patch landet damit
in den noch verschlüsselten Bytes. Lässt man die Entschlüsselung dann erneut
laufen, XORt sie über die Patch-Bytes statt über die der Datei — der Patch ist
weg **und** die entschlüsselte Ausgabe an dieser Stelle ist falsch. Genau dort,
wo man lesen wollte. Die ⚠-Marke, die den Patch in der Sitzung als „über
Lauf-Bytes gesetzt" kennzeichnet, fehlt dabei auch, weil sie aus dem lebenden
Cache berechnet wird und nach dem Öffnen kein fremder Schreibvorgang existiert,
gegen den sie entstehen könnte.

**Wer es nutzt:** der Nutzer selbst, im Browser, beim Entpacken.

**Vom Nutzer entschieden:**

- Der Patch soll beim Wiederöffnen **zurückkommen**, nicht nur gemeldet werden —
  „sonst geht der Nutzer von einer falschen Annahme aus".
- **Die Sitzung soll persistiert werden, soweit es geht**; klar kommuniziert
  wird nur, was *nicht* wiederherstellbar ist.
- Wiederhergestellt wird **auf einen Druck** (Ansatz B), nicht von selbst beim
  Öffnen.
- Der Hinweis ist eine **Hinweisbox, kein Toast**.

## Befunde (im Code nachgelesen, Zahlen nachgeprüft)

| Befund | Bedeutung fürs Design |
|--------|----------------------|
| `_replay_patches` läuft beim Sitzungsstart (`rizin_sessions.py:1345`, `:2964`), vor jedem Lauf | Der Patch wird in verschlüsselte Bytes geschrieben. Das ist die Ursache des stillen Schadens, nicht die fehlende Marke |
| `over_run` entsteht in `patch_rows` aus dem **lebenden** Cache: ein eigener Schreibvorgang über einem fremden, der vorher kam | Nach dem Öffnen gibt es keinen fremden Schreibvorgang; die Marke ist nicht herleitbar, nicht bloß vergessen |
| Ins Projekt geht pro Patch nur `addr:hex` (`_TDC_PATCH_RE`) | Die Herkunft eines Patches wird heute nicht gespeichert |
| `_read_project_meta` liest nur die **letzten 64 KB** der Projektdatei; die Patch-Liste hat `PROJECT_PATCH_CHARS` = **32 KB Zeichen** Budget | Die entschlüsselten **Bytes** können nicht ins Projekt: eine Sektion ist als Hex schnell einige hundert KB. Das ist Arithmetik, nicht Geschmack — und genau der Grund, den §6 des alten Designs nennt |
| Nichts hält fest, *was* gelaufen ist: `self._emulation_ranges` merkt sich nur die Speicherbereiche der Emulation, für den Ausschluss bei der Neuanalyse | Ein Nachspielen braucht eine neue, bewusst kleine Aufzeichnung |
| `_assist_tick`, `_assist_handle` und `_assist_pseudo` rücken bei **jeder** Anwendung vor, und der Rückgabewert ist von Hand änderbar | Ein Lauf an API-Calls vorbei ist nur reproduzierbar, wenn die **angewandten Werte** mitgeschrieben werden. Werden sie es, spielen die Zähler keine Rolle mehr — der aufgezeichnete Wert wird gesetzt, nicht neu erfunden |
| `self._lost` bleibt im Projekt, wird **nicht** angewandt, und `_replay_patches` benennt in einer Notiz, was es weggelassen hat | „Aufgehoben, nicht angewandt, benannt" existiert im Code schon. Das neue Verhalten ist dessen Geschwister, kein neues Muster |
| Die Sitzung trägt `"note"` in ihrem Status (`rizin_sessions.py:1390`), das Frontend zeigt es im Statusband (`app.js:21883`) | Die Hinweisbox gibt es schon. Es braucht keinen Toast und keine neue Fläche |
| Das Projekt hängt an der SHA-256 der Datei | Die Bytes, gegen die der Lauf gerechnet hat, sind beim Wiederöffnen dieselben. Der Lauf ist damit überhaupt reproduzierbar |
| `esil.timeout` ist 5 s pro Befehl, und jeder Lauf ist eine blockierende Anfrage | Ein Nachspielen kann mehrere Sekunden kosten und scheitern. Beim Öffnen wäre das ein blockierter Tab |

## Ziele

### 1. Der Patch richtet keinen Schaden mehr an

- Ein Patch, der über Bytes gesetzt wurde, die ein Lauf geschrieben hat, wird
  beim Öffnen **nicht** in den Cache geschrieben. Er bleibt im Projekt und
  wartet.
- Die Patch-Liste zeigt ihn als wartend, mit seiner Adresse, seinen Bytes und
  dem Grund.
- Die Hinweisbox sagt es **einmal beim Öffnen**, nicht erst, wenn es wehtut.

### 2. Die Sitzung wird so weit wiederhergestellt, wie es ohne die Bytes geht

Das Projekt merkt sich nicht das Ergebnis, sondern **den Weg dorthin**:

- die Startadresse der Emulation,
- die Folge der Lauf-Aktionen in der Reihenfolge, in der sie gemacht wurden
  (Art und, wo nötig, die Adresse),
- pro übersprungenem API-Call den **angewandten** Wert und die Stack-Korrektur,
- und je entschlüsseltem Bereich **einen SHA-256 über die Bytes**, die der Lauf
  dort hinterlassen hat.

### 3. Ein Knopf stellt wieder her, und er beweist es

- Ein Knopf **Lauf wiederherstellen** im `EMULATION`-Reiter spielt die
  aufgezeichnete **Zeitachse** nach — Start, Läufe, übersprungene Calls und
  Patches in der Reihenfolge, in der sie gemacht wurden (siehe Nachtrag 1: die
  Patches stehen *in* der Folge, nicht dahinter).
- **Danach wird der SHA-256 geprüft.** Stimmen die Bytes, sagt die Hinweisbox,
  dass die Sitzung wiederhergestellt ist. Stimmen sie nicht, wird der Zustand
  des Öffnens wiederhergestellt und sie sagt, dass das Nachspielen zu anderen
  Bytes geführt hat.
- Scheitert das Nachspielen unterwegs (Timeout, Trap, ungültiger Befehl), sagt
  sie das mit dem Grund, den der Lauf selbst nennt, und die Patches bleiben
  weiter zurückgehalten.

### 4. Was nicht wiederherstellbar ist, wird benannt

- Passt die Aufzeichnung nicht ins Budget, wird sie **nicht halb** gespeichert:
  die Patches bleiben, die Aufzeichnung fällt weg, und das Projekt sagt beim
  Öffnen, dass der Weg zum Zustand nicht aufgehoben werden konnte.
- Dasselbe, wenn der Nutzer Register von Hand gesetzt hat, die der Lauf gelesen
  hat: das ist nicht aufgezeichnet, also ist der Zustand nicht beweisbar
  reproduzierbar. Lieber nichts anbieten als falsch wiederherstellen.

## Nicht-Ziele

- **Die entschlüsselten Bytes speichern.** Arithmetisch ausgeschlossen (64 KB
  Lesefenster, 32 KB Zeichen Budget) und im alten Design mit Grund
  ausgeschlossen.
- **Beim Öffnen von selbst nachspielen.** Es würde Sample-Code ausführen, weil
  man eine Datei geöffnet hat, und ein Timeout würde den Tab beim Öffnen
  blockieren. §1 macht EMULATE bewusst zu einem Knopfdruck.
- **Eine Ausführungshistorie zum Durchblättern.** Aufgezeichnet wird, was der
  Nutzer getan hat — jeder Lauf ist ohnehin eine Anfrage —, nicht jeder Schritt
  innerhalb eines Laufs, und sie wird nirgends als Liste angeboten.
- **Den vollen Emulationszustand speichern** (Register, Stack, PC). Nur der Weg,
  und nur so weit, wie er beweisbar zum selben Ergebnis führt.
- **Ein Nachspielen über eine geänderte Datei.** Das Projekt hängt an der
  SHA-256; eine andere Datei hat ein anderes Projekt.
- **Den Patch trotzdem anwenden, wenn das Nachspielen scheitert.** Dann bleibt
  er wartend.

## Anti-Ziele (Misserfolg, auch wenn es läuft)

- **Eine Wiederherstellung, die still andere Bytes erzeugt.** Ohne den SHA-256
  wäre das das wahrscheinlichste Scheitern und das schlimmste: der Nutzer liest
  Code, der nie so entschlüsselt wurde.
- Ein Patch, der in verschlüsselte Bytes geschrieben wird und die nächste
  Entschlüsselung verdirbt. Das ist der heutige Zustand.
- Ein Hinweis, der erst kommt, wenn der Schaden da ist.
- Der Öffnen-Pfad hängt an einem Lauf.
- Eine halb gespeicherte Aufzeichnung, die beim Nachspielen irgendwo abbricht
  und einen Zustand hinterlässt, den niemand benannt hat.
- Die Patch-Liste wird unübersichtlich, weil wartende und angewandte Patches
  nicht auseinanderzuhalten sind.

## Rahmenbedingungen

- **Server:** `webui/rizin_sessions.py` (die Aufzeichnung, das Speichern, das
  Zurückhalten, das Nachspielen) und eine Route unter `/api/rizin/...` in
  `webui/app.py` nach dem dortigen Muster. Die Route bekommt ihre Zeile in
  `docs/api.md` — `tests/test_docs.py::test_api_page_documents_every_route_and_nothing_else`
  verlangt genau eine pro (Methode, Route).
- **Das Projekt-Format:** die Aufzeichnung geht in den `/tdc`-Namensraum, den
  `_sanitize_project` und `_read_project_meta` schon tragen, und zählt gegen
  **dasselbe** Budget wie die Patch-Liste (`PROJECT_PATCH_CHARS`, 32 KB
  Zeichen). Die Patches haben Vorrang: passt beides nicht, fällt die
  Aufzeichnung.
- **Ein geladenes Projekt ist feindlich.** `_make_safe` entwaffnet es heute
  schon. Die Aufzeichnung wird beim Lesen genauso geprüft wie die Patch-Liste:
  jede Adresse gegen die Maps, jede Lauf-Art gegen `STEP_COMMANDS`, jeder Wert
  gegen das Zahlenformat — und ein Nachspielen schickt **nur** Befehle, die der
  Server ohnehin selbst baut.
- **Frontend:** Vanilla JS in `webui/static/js/app.js`, Funktionen auf oberster
  Ebene mit Präfix `rizin`, Konstanten `RIZIN_`, jede neue in `RIZIN_FUNCTIONS`
  bzw. `RIZIN_CONSTS` in `tests/test_rizin_ui.py`. Jedes neue Zustandsfeld wird
  in `rizinReset()` gelöscht.
- **Die Hinweisbox ist die bestehende**: das `note`-Feld des Sitzungsstatus,
  das das Statusband zeigt. Kein Toast, keine neue Fläche. Notizen werden nach
  Dringlichkeit geordnet (R59 des alten Plans).
- **Adressen** im Browser immer `"0x…"`-Strings; die Maschinenwörter der
  Emulationsroute sind exakte `"0x…"`-Strings (R52).
- **Farben** nur als `var(--…)`, Werte nur in `:root` von `style.css`, jedes
  neue Selektor mit `[data-theme]`-Gegenstück in `theme-layout.css` — das gilt
  auch für Classic, weil das Boot-Skript `data-theme` immer setzt.
- **Asset-Versionen** in `index.html` bei jeder CSS- und JS-Änderung erhöhen.
- `docs/rizin.md` und die Hilfe im Tab müssen übereinstimmen; ein Drift-Test
  pinnt die gemeinsamen Phrasen.
- **Tests:** die CI kennt kein rizin; `tests/fake_rizin.py` muss die neuen
  Befehlsfolgen beantworten. Jede server-seitige Task bekommt mindestens einen
  `@pytest.mark.skipif(not REAL_RIZIN)`-Test, der das rizin-Verhalten pinnt,
  das ihr Fake nachbaut (R15 des alten Plans).
- **Neuer Branch von `main`.** Der Vorgänger ist gemergt (`origin/main` =
  `642f5d8`).

## Ansätze

1. **Zurückhalten und benennen (verworfen als Endstand, enthalten als Teil).**
   Der Patch wird nicht angewandt, sondern benannt. Beseitigt den stillen
   Schaden vollständig und kostet fast nichts — stellt aber nichts wieder her,
   und der Nutzer baut den Zustand von Hand nach. *Es ist der Teil von Ansatz 2,
   ohne den auch das Nachspielen nichts hilft.*
2. **Rezept mitschreiben, auf einen Druck wiederherstellen (gewählt).** Das
   Projekt merkt sich Startadresse, Lauf-Folge, die angewandten Assistenz-Werte
   und einen SHA-256 je entschlüsseltem Bereich; ein Knopf spielt nach und
   beweist das Ergebnis. *Kosten:* kehrt das Nicht-Ziel „Emulationszustand im
   Projekt speichern" um, begrenzt auf den Weg statt der Bytes; das Nachspielen
   kann scheitern und muss das sagen.
3. **Beim Öffnen von selbst nachspielen (verworfen).** Unterscheidet sich von 2
   nur durch den fehlenden Knopfdruck — und der ist das Einzige, was verhindert,
   dass das Öffnen einer Datei Sample-Code ausführt und ein Timeout den Tab
   blockiert.

Der Nutzer hat Ansatz 2 gewählt, mit dem Hinweis als Box statt als Toast.

## Entscheidungen des Assistenten (zur Prüfung)

- **Der zurückgehaltene Patch ist der Kern, nicht die Marke.** Die Aufgabe begann
  als „die ⚠ verschwindet beim Wiederöffnen". Der eigentliche Schaden ist, dass
  der Patch in verschlüsselte Bytes geschrieben wird und die nächste
  Entschlüsselung verdirbt. Selbst wenn alles andere entfällt, muss das
  Zurückhalten kommen.
- **Der SHA-256 je Bereich ist nicht optional.** Er ist der Unterschied zwischen
  einer Wiederherstellung und einer Behauptung. 32 Byte pro Bereich, verglichen
  mit einigen hundert KB für die Bytes selbst.
- **Die angewandten Assistenz-Werte aufzuzeichnen löst das Zählerproblem**, statt
  es zu verwalten: wird der Wert gesetzt, den der Nutzer damals angewandt hat,
  spielt es keine Rolle, wo `_assist_tick` oder `_assist_handle` inzwischen
  stehen.
- **Ein von Hand gesetztes Register macht den Lauf nicht beweisbar
  reproduzierbar.** Dann wird keine Aufzeichnung angeboten, und die Box sagt es.
  Das ist das „lieber nichts anbieten als falsch raten" des alten Designs.
- **Die Patches haben Vorrang über die Aufzeichnung** im gemeinsamen Budget: ein
  Patch ist Arbeit des Nutzers, die Aufzeichnung ist Bequemlichkeit.
- **Die Hinweisbox ist das bestehende `note`-Feld.** Ein Toast wäre eine neue
  Fläche für etwas, das der Tab schon kann — und der Nutzer hat ausdrücklich
  keine gewollt.

## Nachträge aus dem Builder-Check

Ein Builder-Prüfer hat das Dokument gelesen und acht Stellen genannt, an denen
er raten müsste. Sieben sind hier entschieden — **als meine Entscheidungen, nicht
als abgestimmte** —, eine ging an den Nutzer zurück.

### 1. Die Aufzeichnung ist **eine** Zeitachse, und Patches stehen darin

Der Prüfer hat den schwersten Fehler des ersten Entwurfs gefunden: §3 sagte
„spielt den Lauf nach und setzt **danach** die zurückgehaltenen Patches", aber
die Absicht ist die umgekehrte Reihenfolge — man patcht den entschlüsselten
Check und läuft dann **weiter**. Käme der Patch erst am Ende, liefe das
Nachspielen durch den ungepatchten Check, nähme den Anti-VM-Zweig, und die
Bytes wären andere: der SHA-256 würde scheitern, und zwar genau im Hauptfall.

Also: die Aufzeichnung ist **eine geordnete Folge von Aktionen** — Start, Läufe,
übersprungene Calls **und Patches** — in der Reihenfolge, in der sie gemacht
wurden. Das Nachspielen führt sie der Reihe nach aus.

**Die Zusage „stimmen die Bytes nicht, wird nichts angewandt" bleibt**, und sie
wird dadurch möglich, dass der Zustand beim Öffnen bekannt ist: der Cache trägt
dann nur die *angewandten* Patches. Scheitert der SHA-256, stellt der Server
genau diesen Zustand wieder her (`wc-*`, dann die Patches des Öffnens erneut) und
sagt es. Das Nachspielen ist damit atomar, ohne einzelne Schreibvorgänge
zurückrollen zu müssen.

### 2. Beim Nachspielen werden die Assistenz-Zähler zurückgesetzt, nicht verwaltet

Der Prüfer hat gezeigt, dass „den angewandten Wert aufzeichnen" **nicht reicht**:
`call_skip` legt außerdem Puffer mit `aeim` an, kopiert Bytes und schreibt
Aus-Parameter, deren Bytes aus `plan["clock"]` kommen — also aus
`_assist_tick + TICK_STEP`. Ein neu geplanter SKIP bekäme eine andere Uhr.

Entscheidung: die Aufzeichnung merkt sich **einmal** den Startstand der drei
Zähler (`_assist_tick`, `_assist_handle`, `_assist_pseudo`) und je SKIP den
**angewandten Wert** samt Stack-Korrektur. Das Nachspielen setzt die Zähler auf
den Startstand und plant dann neu. Damit ist jede Ableitung wieder
deterministisch — gleiche Zähler, gleiche Maps, gleicher Speicher, gleiche Uhr —
und es muss nichts über Puffer, Kopien oder Aus-Parameter gespeichert werden.
Nach dem Nachspielen stehen die Zähler dort, wo das Nachspielen sie hinterlässt.

### 3. Lebenszyklus

- **Mehrere Starts:** die Zeitachse beginnt beim **ersten** Start der Sitzung,
  und ein weiterer `emulation_start` ist selbst eine Aktion darin. Er ist
  reproduzierbar (`aei`, `aeim`, `aepc`), also braucht er keine Sonderrolle.
- **Etwas aus dem Cache entfernt** (`unpatch`, „Clear rizin's whole cache"): die
  Zeitachse erzeugt den jetzigen Zustand nicht mehr. Sie wird **verworfen**, und
  die Hinweisbox sagt, dass der Weg zum Zustand nicht mehr aufgehoben ist.
  *Kosten:* ein einzelnes Zurücknehmen kostet die Aufzeichnung der ganzen
  Sitzung. Die Alternative — die Zeitachse mitschneiden lassen — hieße, das
  Entfernen selbst zu einer Aktion zu machen, deren Nachspielen wieder Bytes
  erzeugt, die niemand geprüft hat.
- **Speichern, während etwas wartet:** die Aufzeichnung und die
  zurückgehaltenen Patches überleben Speichervorgänge wie `self._lost` es tut.
  Ersetzt wird die Aufzeichnung erst, wenn eine neue Zeitachse beginnt.
- **rizin startet neu** (`_recover`): dieselbe Behandlung wie beim Öffnen —
  Patches über Lauf-Bytes werden zurückgehalten und die Wiederherstellung wird
  angeboten.

### 4. Was die Aufzeichnung verdirbt

Der Prüfer hat recht, dass §4 zu kurz war. Die Regel ist jetzt: **aufgezeichnet
wird nur, was die Emulationsrouten des Servers selbst getan haben; alles andere,
was die Emulation oder den Cache angefasst hat, verdirbt die Aufzeichnung.**
Konkret verdorben durch

- ein von Hand gesetztes Register (`/emulation/register`),
- einen Konsolenbefehl, der schreibt oder setzt (`w*`, `ar`, `aeim`, `e esil.*`),
- eine Breakpoint-Änderung zwischen zwei Aktionen der Zeitachse,
- und **einen Lauf, der mit `timeout` endete** — dieses Ergebnis hängt an der
  Wanduhr und ist grundsätzlich nicht reproduzierbar.

Eine verdorbene Aufzeichnung wird nicht angeboten, und die Hinweisbox sagt
warum. Das ist das „lieber nichts anbieten als falsch raten" des alten Designs.

### 5. Der SHA-256 deckt die Bytes **des Laufs**, auch die später gepatchten

Der schärfste Befund des Prüfers: `run_only_ranges` nimmt **jedes** Byte heraus,
das eine `mine`-Zeile bedeckt — also genau die Bytes, um die es geht. Ein
SHA-256 über diese Bereiche wäre dort stumm, wo der Nutzer hinschaut.

Entscheidung: gehasht werden die Bytes, **wie der Lauf sie hinterlassen hat**.

> **Korrektur, an rizin 0.9.1 nachgemessen (Task 2, 2026-11-23).** Dieser
> Abschnitt sagte ursprünglich: „für eine später überschriebene Stelle also das
> `before` der Patch-Zeile, nicht der Patch." **Das ist falsch.** rizins `before`
> ist der Zustand des Caches **zum Zeitpunkt des Schreibens** — nicht die Datei
> und nicht der Lauf. Es antwortet nur in dem einen Fall richtig, den dieser
> Abschnitt sich vorgestellt hat. Zwei Messungen:
>
> - **Zwei Patches übereinander:** `wx 41424344 @ 0x1000`, dann `wx 90 @ 0x1002`,
>   dann `wx cc @ 0x1002` gibt `before` = `43` (der Lauf) für den ersten Patch,
>   aber `before` = `90` (**Patch 1**) für den zweiten. Der Lauf hinterließ `43`.
> - **Ein Patch *vor* dem Lauf, über dieselbe Adresse:** `wx 90 @ 0x1002`, dann
>   `wx 41424344 @ 0x1000` gibt für die Patch-Zeile `before` = `ff`, das Byte der
>   **Datei**. `run_only_ranges` nimmt die Stelle trotzdem heraus (es ist
>   reihenfolgenblind), und die Regel hätte das Datei-Byte in den Beweis gelegt,
>   wo der Lauf `43` hinterließ.
>
> **Die richtige Regel, die implementiert ist:** das `after` der **letzten
> nicht-`mine`-Zeile** über jedem Byte. Sie stimmt in beiden Fällen, in denen die
> alte Regel falsch war, und in dem Fall, den dieser Abschnitt beschrieb, mit ihr
> überein.
>
> **Folge, die Tasks 4 und 5 binden:** die Regel braucht die Zeilen in
> **Schreibreihenfolge** (`patches_made()` / `ordered=True`), nicht nach Adresse.
> `_saved_cache` liest heute `_patch_list(pipe)` mit `ordered=False`, also nach
> Adresse sortiert — gemessen: `wx ee @ 0x1101`, dann `wx aabbccdd @ 0x1100`
> liest als `aabbccdd`, nach Adresse sortiert ergäbe der Digest `aaeeccdd`, ein
> falscher, aber plausibler SHA-256, **lautlos**. `run_digests` kann den Verstoß
> nicht erkennen, also muss ein Test ihn abriegeln.

Der Hash entsteht beim Speichern, wo der Cache noch lebt, und wird
mit der Aufzeichnung aufgehoben; beim Öffnen wird er nicht neu berechnet, weil
der Cache dann leer ist.

### 6. Wann der Knopf laufen darf

Nur, wenn der Cache nichts außer den beim Öffnen angewandten Patches trägt und
keine Emulation läuft; sonst weist er mit Grund ab. Das Nachspielen ist **eine**
Anfrage, die das Gate hält wie ein Lauf — begrenzt durch die Höchstzahl an
Aktionen, die eine Aufzeichnung tragen darf. Diese Höchstzahl ist der Hebel
gegen eine Wiederherstellung, die Minuten dauert, und sie bleibt dem Builder
überlassen.

### 7. Projekte von vorher

Ein Patch-Eintrag ohne Herkunft (aus einem Projekt, das vor dieser Änderung
geschrieben wurde) wird **wie heute** angewandt. Mehr ist nicht zu wissen, und es
ist genau das heutige Verhalten — also keine Verschlechterung. Neue Einträge
tragen ihre Herkunft; die Form dafür bleibt dem Builder überlassen.

### 8. Zwei Auswege für einen Patch, der nie wiederherstellbar wird — **vom Nutzer entschieden**

Ein zurückgehaltener Patch kann dauerhaft unwiederherstellbar sein: die
Aufzeichnung passte nicht ins Budget, sie wurde verdorben, sie wurde durch ein
Zurücknehmen verworfen, oder das Nachspielen ist gescheitert. Dann darf er nicht
für immer als „wartet" liegen bleiben.

Es gibt **genau zwei** Auswege, und keinen dritten:

- Das **✕** nimmt ihn aus der Liste und aus dem Projekt, wie bei jedem anderen
  Patch.
- **„Jetzt anwenden"** erscheint **nur dann**, wenn die Bytes unter seiner
  Adresse wieder von einem Lauf stammen — also wenn der Nutzer selbst
  entschlüsselt hat und der Patch wieder sinnvoll ist. Der Server prüft das
  daran, ob eine fremde Cache-Zeile die Adresse bedeckt; er muss nichts raten.

**Ausdrücklich nicht:** ein „Jetzt anwenden", das immer verfügbar ist. Das wäre
der heutige Schaden mit einem Knopf davor.

## Dem Builder überlassen

- Die genaue Form der Aufzeichnung im `/tdc`-Namensraum, innerhalb dessen, was
  `_sanitize_project` und `_read_project_meta` tragen, und wie sie gegen das
  Budget gezählt wird.
- Ob die Lauf-Folge zusammengefasst wird (zehn STEPs hintereinander als einer),
  solange das Nachspielen dieselben Bytes erzeugt und der SHA-256 es beweist.
- Wo der Knopf im `EMULATION`-Reiter sitzt und wie ein wartender Patch in der
  Liste aussieht.
- Der Wortlaut der Hinweisbox in ihren vier Fällen (wiederhergestellt, andere
  Bytes, unterwegs gescheitert, nichts aufgezeichnet).
- Ob der Bereich für den SHA-256 die Lauf-Bereiche aus `run_only_ranges` sind
  oder eine eigene Zusammenfassung.
- Wie viele Aktionen eine Aufzeichnung höchstens trägt, bevor sie als „zu lang"
  gilt.
