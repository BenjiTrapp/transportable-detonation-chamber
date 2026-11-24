# Binary-Graph: die Entscheidungen, die ohne Rückfrage fielen

Begleitdokument zu `2026-11-22-binary-graph.md`. Während der Ausführung lagen 54
Entscheidungen an, die der Plan nicht beantwortete. Ich habe sie getroffen, damit die
Arbeit nicht stehenblieb, und jede hier festgehalten — mit dem, was sie kostet, wenn sie
falsch war. Wer eine davon anders will, findet hier die Stelle.

Die Nummern stammen aus den Dispatch-Briefen und wiederholen sich zwischen Tasks; die
Gruppierung unten ist nach Sache, nicht nach Zeit. Vollständige Begründungen samt
Testbelegen stehen im Ledger (`.superpowers/sdd/2026-11-22-binary-graph/progress.md`),
das aber gitignoriert ist und mit dem Worktree verschwindet.

## Der Fehlbeschuldigungs-Pfad

Ein `import_present: False` ist ein struktureller Befund mit Gewicht 4.0, der keine
Bestätigung braucht. Ein falsches `False` beschuldigt ein sauberes Programm. **Fünf
verschiedene Wege dorthin** sind während dieses Plans gefunden worden, drei erst nachdem
ein Reviewer sie reproduziert hat.

| Entscheidung | Kosten, wenn falsch |
|---|---|
| **Die Deckung wird am Ziel entschieden, nicht am Import.** `False` nur für einen Syscall in `Table.covered`. Mein Plantext sagte das Gegenteil und war falsch — belegt mit `NtCreateFile`-Stub plus `CreateFileW`-Import, der unter Plan 1s Regel als belegte Umgehung las. | Nichts wird je ein Beleg, weil fast jedes PE `GetProcAddress` importiert. |
| **`expanded_imports` ohne `covered` ist ein `ValueError`**, kein milder Vorgabewert. | Neun Testzeilen Arbeit. |
| **Die Grenze wählt Syscalls, nicht Türen.** Ob ein Syscall gedeckt ist, entscheidet `SUSPICIOUS_IMPORTS`; ist er gedeckt, gehört **jede** Tür dazu. Das Anti-Ziel schlägt das Nicht-Ziel „kein Win32-Lexikon". | Eine fehlende Tür beschuldigt ein sauberes Programm. |
| **Ein Win32-Name darf zu mehreren Syscalls führen.** Eindeutigkeit gilt für das Paar. | Ein Wrapper mit zwei Syscalls erzeugt einen falschen Beleg. |
| **Eine Tür ist eine API, deren dokumentierter Vertrag die Operation dieses Syscalls auf den Operanden des Aufrufers ausführt** — nicht jede API, die ihn intern erreicht. Daraus: der Heap bleibt draußen, `LoadLibrary* → NtProtectVirtualMemory` fiel weg. | Zu streng beschuldigt sie ein sauberes Programm, zu weit belegt sie nie etwas. Die Spec zeigt streng. |
| **Die Restgefahr der Deckungsregel ist aufgeschrieben:** eine seltene Tür zu einem gedeckten Syscall liest als Umgehung. | Ein sauberes Programm wird beschuldigt — benannt statt verborgen. |
| **Im Prozessmodus wurde der Beleg abgeschaltet** (mein Plan schrieb den falschen Nenner vor: privater Speicher ist nicht zuordenbar). | Ein gepacktes Sample bleibt bis Task 6 ein Hinweis — ein verlorener Beleg, kein falscher. |
| **Wiederhergestellt als Vereinigung der Türen jedes geladenen Moduls**, jede Lücke erzwingt `None`. Das Hauptabbild trägt bei, jedes andere ungecachte Modul macht die Vereinigung unvollständig. | Malware, die eine eigene DLL lädt, bekommt `None`. Die ehrliche Antwort. |
| **Eine ausgedünnte Modulliste ist keine vollständige** — `modules_whole()` sichert nur zu, wenn der Leser nichts ausgelassen hat. | Ein Beleg über einem Nenner, von dem niemand weiß, ob er vollständig war. |
| **Imports nach Ordinal werden über den Cache aufgelöst**, in beiden Modi; ein unauflösbares Ordinal ist eine unbekannte Tür. | Eine per Ordinal importierte Tür las als nicht importiert. |
| **Der Prozessmodus belegt praktisch nie**, weil `kernelbase` — in jedem Win32-Prozess geladen — die Nt-Funktionen direkt importiert. Der Nenner bleibt **unverändert**; der Satz wird gesagt. | Den Nenner zu ändern hieße: ein Prozess, dessen dokumentierter Weg wirklich in kernelbase liegt, liest als Umgehung. |
| **`partial` heißt „ein Verzeichnis war nicht vollständig lesbar", nicht „pefile hat irgendetwas gewarnt."** pefiles „typical of packed executables" ist eine Beobachtung, kein Lesefehler — und schaltete den Datei-Beleg genau für Loader ab. Ausschlussliste benannt, alles andere zählt weiter als Schnitt. **Entscheidung 67** setzt pefiles „Damaged Import Table information" dazu, das auf `26200.9974` 851 von 3994 System32-Binaries als abgeschnitten zählen ließ — aber nur, wenn beide genannten Thunk-Tabellen wirklich leer sind (RVA 0 oder erster Thunk null). Dieselben Worte fallen, wenn pefile eine Tabelle als unsinnig verwirft (ein Ordinal über `0xFFFF`), und dann sind die Funktionen des Deskriptors ungelesen verloren. | Eine Umformulierung bei pefile führt zu Über-, nie zu Untermeldung. Ohne die Leerprüfung importierte ein präpariertes Sample seine Tür unsichtbar, und ein mitgebrachter Stub läse als belegte Umgehung. |
| **Das fünfte Residual ist nicht gemindert**, und meine behauptete Minderung existierte nicht: ein Stub-Befund ist am Prozess verschlüsselt, und nichts schreibt ihn je in die Host-Baseline. **Darum sperrt VM-Punkt 7 den Merge.** | Ein 4.0-Befund gegen einen sauberen Host, falls ein System32-Modul Stubs schreibt. |

## Das Anti-Ziel: eine kuratierte Kante darf nicht als abgeleitete lesen

| Entscheidung | Kosten, wenn falsch |
|---|---|
| **Keine `defines`-Kante.** Die Spec nennt vier Kantenarten; eine fünfte wäre erfundene Struktur. Ein Funktionsknoten trägt sein Modul in der `id`. | Tasks 8–10 hätten je eine eigene Lösung erfunden. |
| **Eine `imports`-Kante darf keine Ableitung behaupten, die sie nicht hat.** Ein unbekanntes Startmodul bekommt keine Kante. | Das Anti-Ziel im Kleinen. |
| **Ein Nt-benannter Import erreicht seinen Syscall allein aus Daten** — `derived`, und aus „genau eine kuratierte Kante" wurde „höchstens eine". | Der saubere Pfad las als unbekannt. |
| **Die Zw→Nt-Kante ist `curated`** mit `zw-alias`, in **beiden** Abfragen. Ein mechanischer Namenswechsel ist nichts, was aus einer Binary gelesen wurde. | Die Richtung des Anti-Ziels. |
| **Eine unbekannte Herkunft liest als unbekannt, nicht als `derived`.** | Heute unsichtbar — das ist der Punkt: die Richtung, in die der Vorgabewert fällt. |
| **Aggregation darf keine Herkunft waschen:** eine zusammengefasste Kante ist nur `derived`, wenn jede dahinter es ist. | Die Erkundungsansicht hätte das Anti-Ziel neu geöffnet. |
| **Eine umgeschriebene Regel braucht einen Test.** Der Kennzahl-Listen-Ausnahme folgte ein Test über 400+ Antworten aus jeder Abfrage. | Die Regel war vorher unerzwungen und wäre es geblieben. |
| **T8 schreibt eigenes SVG nach dem Muster von `rizinGraphSvg`**, ruft es nicht auf. | Jemand verbiegt `rizinGraphSvg` für zwei Aufrufer und bricht den Rizin-Tab. |

## Falsche Aussagen, korrigiert statt umgangen

Elf. Jede einzelne kam aus einem Review, keine aus einer Selbstmeldung.

1. Spec Ziel 7 erzählte von einer Kette „über kernel32 und kernelbase **zu ntdll**", während Ziel 6 selbst sagt, kernelbase **ruft** `NtWriteVirtualMemory` und leitet nicht weiter.
2. „Der Loader probiert die Hosts der Reihe nach" — eine Behauptung über `ApiSetResolveToHost`, die keiner von uns geprüft hatte. Gestrichen, nicht umgedreht.
3. `#help-api`: „its last edge is curated, **not derived**" — seit der Nt-Import-Regel falsch.
4. README und `#help-usage`: „GRAPH switched off until the binary graph exists" — Plan 1 schrieb es, als es stimmte; Task 8 schaltete den Knopf frei.
5. README: „Every edge is derived … except the last hop" — die Zw-Kante ist auch kuratiert.
6. `docs/memory.md`: „except one kind", dann zwei aufgezählt.
7. Die Kennzahl `partial` hieß „import table cut short", zählt aber drei Verzeichnisarten — an sechs Stellen, plus vier weiteren im Nachgang.
8. Der Tooltip sagte „The sample imports this function as well" für einen Prozesstreffer, wo `true` „ein geladenes Modul" heißt.
9. Ein Docstring: „an api-set name has dots of its own (`api-ms-win-core-heap-l1-1-0`)" — das eigene Beispiel hat keine.
10. Tooltip und Detailpanel einer `zw-alias`-Kante sagten „from the Win32 to Nt table", was keine Tabellenzeile stützt.
11. Eine Fixture packte `HashedLength` nach Vermutung, gegen zwei dokumentierte Quellen — unbenutzt, und darum eine Zeile wert.

Dazu zwei ungemessene Zahlen, die wie gemessene lasen: „a few hundred MB" (ohne jede
Quelle, gestrichen) und „a build takes a few minutes über ~4.000 Dateien" (jetzt als
Erwartung, bis die VM misst).

## Ehrlichkeit als Regel, nicht als Stil

| Entscheidung | Kosten, wenn falsch |
|---|---|
| **Ein fehlender Knoten heißt „nicht gezeigt", nie „importiert nicht."** Zweimal brach das: ein übersprungener Teil mit schon gezeichnetem Kopf, dann ein verworfener Kopf, der später erschien. Lösung: nicht passende Teile werden **ganz** gehalten und freigegeben, wenn ihre Enden da sind. | Zwei sichtbare Knoten ohne Kante lesen als „importiert nicht". |
| **Eine Kennzahl-Liste nimmt ihre Zahl aus der Kennzahl**, mit `ValueError`, wenn sie abweichen. | Zwei Zahlen für eine Tatsache. |
| **`Answer` trägt `total` und `partial` strukturiert**, nicht als Satz in der Prosa. | Drei Frontend-Tasks müssten Prosa parsen. |
| **Die Warnung zeigt auf die Zahl**, statt dauernd sichtbar zu sein; die konservative Regel bleibt. | Eine dauernde Warnung erzieht zum Ignorieren. Die engere Regel wäre eine schwächere Behauptung als die Wahrheit. |
| **Der Hinweis muss das Ende nennen, das wirklich eintrat** — nicht eine fehlende Baseline einer kuratierten Zeile anlasten. | Der Analyst handelt nach dem falschen Grund. |
| **Ein leerer Host verwirft seinen API-Set-Eintrag nur, wenn er in `value[0]` steht** (Entscheidung 66, ersetzt 20 nach der VM-Messung). Die alte Regel verwarf auch einen leeren Host nach dem Standard und verlor so 144 von 985 echten Einträgen, darunter die zwei meistimportierten. Ein leerer späterer Wert fällt allein weg, die übrigen behalten ihre Reihenfolge. | Ein Override rutscht auf den Platz der Vorgabe — das geht nur über `value[0]`, und dort bleibt die Regel streng. |
| **Ein Teil-Parse wird sichtbar** (`BinaryInfo.partial`), statt still eine abgeschnittene Tabelle zu behalten. | Eine Kante hinter dem Schnitt fehlt stillschweigend. |
| **Eine Fixture darf keinen Wert packen, den wir für falsch halten**, auch einen unbenutzten. | Der nächste Leser glaubt ihm. |
| **Die Doors-Fixture wurde realistisch gemacht** — und zwölf Prozessmodus-Tests fielen um. Das war der Beweis, dass die Fixture sie grün hielt. | Ein Mechanismus, der nur gegen ein unmögliches System32 funktioniert. |

## Technische Festlegungen

| Entscheidung | Kosten, wenn falsch |
|---|---|
| **Die Architektur des Graphen kommt aus der Registry**, nicht aus `platform.machine()` — das meldet `AMD64` für ein emuliertes x64-Python auf ARM64, was Plan 1 auf der VM erlebt hat. Es gibt **einen** Cache, also heißt falsche Architektur „kein Graph". | Der Tab sagt für immer „kein Graph", während eine gute Datei unter dem anderen Namen liegt. |
| **Ein API-Set-Lookup fällt auf den am letzten `-` gekürzten Familiennamen zurück**, wie `HashedLength` es vorzeichnet. | Exakt-nur tötet eine Kette bei Versions-Drift; der Rückfall löst über eine Nachbarversion derselben Familie auf. |
| **Ein Cache, der nicht lädt, wird im Hintergrund neu gebaut**, mit Zehn-Minuten-Sperre und **drei** Versuchen, dann Abweisung mit Hinweis auf `-Force`. | Ein Graph-Bau liest 4.000 Dateien; eine endlose Schleife konkurriert mit dem Sample um CPU. |
| **Ein Fehlereintrag verschwindet, sobald ein brauchbarer Cache da ist**, egal wer die Datei schrieb. | Plan 1 hat das Gegenteil ausgeliefert: eine Antwort meldete eine geladene Baseline und den Fehlschlag, sie zu erzeugen. |
| **Die eigene Abschnittsprüfung fiel weg** — übersprungen wird nur, was `pefile` selbst verweigert. | Eine legitime System32-Datei verschwindet still aus dem Graphen. |
| **`kind` kommt aus `IMAGE_FILE_DLL`**, nur ersatzweise aus der Endung. | Eine umbenannte DLL wäre im Graphen ein EXE-Knoten. |
| **`BinaryInfo` trägt Ordinale** (`ordinal_names`). | Task 4 bricht an einer Ordinal-Forwarder-Kette ab. |
| **Die Erkundung ist eine Ansicht auf Modulebene.** Ein Exe mit 300 Importen aus 20 DLLs hätte die 400er-Grenze bei **einem** Aufklappen gesprengt. Zusammenfassen ist Aggregation, keine Erfindung. | Die Ansicht wäre beim Ersten unbrauchbar, was ein Analyst tut. |
| **Aufklappen läuft über die Abfrage-Route**, in beiden Richtungen. | Nur nach vorn hätte den Explorer bei `ntdll` blind gemacht — dem interessantesten Knoten. |
| **Die eigene Kamera der Erkundung ist angenommen**, statt sechs Funktionen des Prozessgraphen umzubauen. | Vierzig Zeilen Dopplung gegen das Risiko, einen funktionierenden Tab zu brechen. |
| **`pefile` wird nicht gepinnt**, und sein Warntext wird nur für die benannten Notizen gelesen (Entscheidungen 65 und 67); jede andere Warnung zählt als Schnitt, ohne gelesen zu werden. | Eine abgeschnittene Datei läge als „importiert nichts" im Graphen. |
| **Der Visited-Schlüssel ist `(module, function)`** und ist festgenagelt. | Nur am Modul geschlüsselt hätte eine legitime Kette `a!F → b!X → a!G` als Zyklus gegolten. |

## Vorgehen

| Entscheidung | Kosten, wenn falsch |
|---|---|
| **Task 6 lief als zwei Dispatches mit je eigenem Review.** Sie mischte Routinearbeit mit der Wiederherstellung des Belegs im Prozessmodus — und genau diese Mischung hat in Plan 1 einen falschen Beleg durch dreizehn Reviews getragen. | Ein Review-Sitz mehr. |
| **Der Wächter über die kuratierten Nt-Namen war zirkulär und ist ersetzt.** Eine auf die Tabelle hin erweiterte Fixture hätte sich selbst geprüft; die Namen beurteilt `missing_from` gegen die echte Baseline auf der VM. | Ein falscher Nt-Name überlebt bis zur VM-Prüfung — sichtbar, nicht still. |
| **Die Test-Werkstatt wird geteilt und erweitert, nicht neu gebaut.** Sie existierte schon in `tests/test_syscalls.py`. | Eine zweite Werkstatt wäre die Dopplung eines Logikblocks. |
| **Die ganze Suite muss grün sein, bevor ein Review läuft.** | Ein Zustand mit zwei Fehlschlägen ist nicht reviewbar. |
| **Der Dateibaum wird von der Task eingetragen, die das Modul anlegt.** | Ein doppelter Eintrag. |
| **`QUERIES` hält Adapter `(ctx, params) -> Answer`**, nicht die Abfragefunktionen. | Die Route hätte einen `if`-Baum über ungleiche Signaturen. |
