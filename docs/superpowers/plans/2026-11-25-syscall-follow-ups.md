# Syscalls: was diese Arbeit bewusst offen gelassen hat

Stand 25.11.2026, nach PR #2 (Syscall-Map), dem Binärgraphen, der Graph-Fläche und
PR #4 (Detonationsstufe und vergangene Messung).

Diese Datei existiert, weil der Projekt-Wissensspeicher sie nicht halten konnte: drei
Einträge wurden dort abgelegt und waren danach nicht mehr abrufbar, ein erneutes
Speichern schlug fehl. Eine versionierte Datei überlebt das.

Jeder Punkt nennt, was gemessen wurde, warum er liegen blieb, und die Richtung — keine
Entscheidung ist getroffen.

## 1. Der Ergebnis-Cache schlägt nach Datei-Hash vor PID nach — behoben am 27.11.2026

**Behoben, und schmaler als die Notiz annahm.** `lookup` bevorzugt den Hash nicht: es nimmt den
**neueren** von Hash- und PID-Treffer. Mein Fall trat auf, weil der neue Lauf noch nichts
gespeichert hatte — zwischen dem Absenden und dem Moment, in dem die Stufe schreibt, ist der
einzige Eintrag unter diesem Hash der des vorigen Laufs, und die Detonationsansicht fragt nach
einer bestimmten PID.

Der Fix ist die Spiegelung der Prüfung, die es für die umgekehrte Richtung schon gab („mit einem
SHA256 wird ein PID-Eintrag eines anderen Samples ignoriert"): ein Hash-Treffer darf nicht für
eine PID sprechen, zu der er nicht gehört. Ein Eintrag ohne PID gilt weiter für jeden Lauf
derselben Datei (ein Scan der Datei allein hat keine), und eine Abfrage **ohne** PID bleibt
unberührt — so findet die Einsendungs-Historie überhaupt ein Ergebnis.

Es war **keine** Entwurfsentscheidung: die Regel ist für alle sechs Werkzeuge dieselbe, und nur
eine Route fragt mit PID und Hash zugleich (`/api/detonation/results`); die Evidenz-Route fragt
nur mit PID. Die Änderung engt ein: wo vorher ein fremder Lauf antwortete, antwortet jetzt
nichts — „noch nicht" statt einer falschen Zuordnung.

Der Befund, wie er stand:

`_beacon_results_cache.lookup` sucht zuerst `f"{tool}_{sha256}"`, dann die PID. Detoniert
man dieselbe Datei erneut, zeigt die Ansicht darum das Ergebnis des **vorigen** Laufs, bis
das neue gespeichert ist.

Gemessen: `injectsim.exe` eingesandt als PID 5540, die Syscall-Stufe meldete „the
architecture of process 5092 is unknown" — 5092 war die PID des Laufs davor. Auffällig
wurde es nur, weil der Text eine PID nennt.

Gilt für **jedes** Werkzeug im Cache, nicht nur Syscalls, und ist so dokumentiert („With a
SHA256, a PID entry from a different sample is ignored"). Richtung: beim Nachschlagen eine
gegebene PID verlangen, statt den Hash-Treffer zu bevorzugen — das berührt alle Werkzeuge
und braucht eine eigene Runde.

## 2. Der Vorbehalt auf der Graph-Leinwand kreuzt die Zeichnung — behoben am 26.11.2026

**Behoben.** Beide Texte, die über der Zeichnung liegen (der Vorbehalt und `Opening…`), bekommen
zuerst einen Streifen in `--bg-secondary` hinter sich: so breit wie der Text misst, plus 4 px auf
jeder Seite, und 18 px hoch. Der dritte Text der Leinwand, die Zeile des leeren Zustands, bekommt
keinen — dort ist keine Zeichnung, die er kreuzen könnte. In Chrome gegen die VM nachgemessen, 400 Knoten, beide Themes: die Zeile des Streifens
ist über 1200 px **eine** flache Farbe (`20,13,36` in Cyberpunk, `18,21,40` in Classic), 40 px
darunter sind es 42 bis 44 Farben — dort liegt die Zeichnung. Der Streifen ist absichtlich
deckend: der Vorbehalt sagt, dass eine Zahl eine Untergrenze ist, und wer ihn nicht lesen kann,
ist schlechter dran als wer ein Stück schwenken muss.

**Noch offen, keine Entscheidung getroffen:** der HTML-Status über der Leinwand
(`#binary-explore-status`) sagt denselben Vorbehalt noch einmal, in fünf Zeilen zu ~470 Zeichen.
Die Dopplung ist gewollt (der HTML-Status kann aus dem Blick scrollen, der auf der Leinwand
nicht), aber beide zusammen sind viel Text.

Der Befund, wie er stand:

Er wird mit `ctx.fillText` bei (12, 10) auf die Leinwand gezeichnet, damit er beim
Schwenken und Zoomen nicht wegscrollt. Seit die Fläche gewachsen ist (240 → 661 px),
kollidiert er mit Knoten und Labels — gesehen bei 1920×1080 mit 400 Knoten: der orange Text
kreuzt das Label `bi.dll`.

Richtung: ein Füllstreifen in Hintergrundfarbe hinter dem Text, bevor er gezeichnet wird.
Der Vorbehalt bleibt, die Kollision geht. Etwa zehn Zeilen in `binaryGraphDraw` plus ein
Test, danach auf der VM in beiden Themes nachsehen.


## 3. Drei zurückgestellte Minors aus dem Gesamt-Review des Binärgraphen

Alle drei wurden dort als „safe to follow the merge" eingeordnet.

**M2 — ein umbenennender Forwarder auf eine Tür ist für die namensbasierte Türmenge
unsichtbar: gemessen und behoben am 27.11.2026.**

Auf `26200.9974` (arm64) gemessen: von 4.944 System32-Forwardern benennen 1.538 um, und 234
davon zeigen auf eine Tür — einen `Nt`/`Zw`-Namen der Baseline oder einen kuratierten
Win32-Namen. 229 sind nur über ein Ordinal exportiert; **fünf tragen einen echten Namen**
(`gdi32` dreimal `D3DKMT…` auf `WIN32U.NtGdiDdDDI…`, und `kernel32` wie `kernelbase`
`FlushProcessWriteBuffers` auf `NTDLL.NtFlushProcessWriteBuffers`), und acht System32-Binaries
importieren genau die.

**Null** davon führen zu einem Syscall, den die kuratierte Tabelle abdeckt — nur für die darf
sie über eine Abwesenheit sprechen. Eine Fehlbeschuldigung war also heute nicht möglich; sie
wäre es in dem Moment, in dem jemand eine Zeile für einen dieser Syscalls hinzufügt.

Behoben wurde es trotzdem, weil die Richtung stimmt: eine unvollständige Türmenge heißt eine
fehlende Tür, und eine fehlende Tür heißt `false`. Und der Fix war keine Erfindung — der
**Ordinal**-Pfad löste schon auf (`_add_ordinal` ruft `resolve_export` und nimmt jeden Sprung
mit); nur der benannte tat es nicht. Jetzt tun beide dasselbe.

Die Kosten wurden gegen den alten Code auf derselben VM gemessen, drei Prozesse, je drei Läufe,
Minimum: **0,34–0,41 s vorher**. Jeden benannten Import aufzulösen hätte 1,05–1,64 s gekostet,
und 3.551 von 3.671 Auflösungen über zwölf Module galten Namen hinter einem API-Set, die dessen
Host selbst definiert. Da ein Umbenennen nur an einem Forwarder-Sprung passieren kann, genügt
die Frage an den Host, den der Loader nimmt — **0,39–0,56 s** bei gleichem Türbestand (4.817),
und 358 statt 3.671 Auflösungen.

Entscheidung 33 bleibt daneben bestehen: ein Ordinal, das der Graph nicht benennen kann, lässt
die Vereinigung weiterhin unvollständig.

**M3 — das erste Laden des Cache läuft auf dem Request-Thread.** 28,2 MB JSON: die erste
Abfrage nach einem Neustart blockiert ihren Worker. Richtung: beim Start vorladen oder an
die bestehende Hintergrund-Bau-Zustandsmaschine hängen.

**M4 — Prüfung „laufen Tool-Updates?" und Start des Baus sind nicht atomar.** Ein Update
kann dazwischen beginnen. Folge ist ein verworfener Bau, keine falsche Aussage.

## 4. Vom Review der vergangenen Messung angenommen, nicht behoben

Vier Punkte, die ein Reviewer geprüft und als „Information verloren, nichts falsch"
eingeordnet hat:

- Der Baseline-Lesevorgang der Schleife wird bei BACK TO LIVE oder einer zweiten Auswahl
  nicht abgebrochen. Nichts wird gemischt; der schlechteste Fall ist eine ehrlich
  etikettierte Ansicht oder ein Hinweis.
- Das Known-Hooks-Modell setzt `scan: null` für eine vergangene Messung, darum erscheint
  deren eigener Hinweis „allowlist not applied" nicht.
- Ein Verweigerungs-Hinweis „baseline could not be loaded" bleibt stehen, nachdem die
  Baseline doch geladen ist.
- Die Liste der Messungen nennt den Build nicht, darum sieht eine Messung eines fremden
  Builds wie jede andere aus, bis man sie öffnet.

## 5. Was gemessen und bewusst so gelassen wurde

Kein Handlungsbedarf, nur damit niemand es für einen Fehler hält:

- **Der Prozessmodus belegt praktisch nie.** `kernelbase.dll` ist überall geladen und
  importiert die Nt-Funktionen direkt, also ist die Türmenge fast immer gefüllt. Der Beleg
  kommt aus der **Datei** des Samples. Dokumentiert, nicht umgangen.
- **Eine Messung, deren Zellen nicht platzierbar sind**, zeigt ihre eigenen Zahlen in der
  Legende über einer leeren Karte. Der Banner sagt genau das; ein Reviewer hat es als
  ehrlich beurteilt.
- **`test_rizin.py::test_an_older_open_that_ends_later_leaves_the_newer_session_of_its_tab`
  ist lastabhängig** und gehört nicht zu dieser Arbeit: er fällt unter Last auch auf dem
  Abzweigpunkt `780cc18` in einem eigenen Worktree und besteht auf ruhiger Maschine
  wiederholt. Die CI (Europe/Berlin und UTC) ist auf beiden PRs grün.
