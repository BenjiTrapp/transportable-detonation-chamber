# Syscalls im Web-UI: Baseline, Messung und Binary-Graph

## Absicht

TDC prüft heute den Speicher laufender Prozesse mit Aether: Thread-Startadressen,
Heap-API-Tabellen, private RWX-Bereiche, ein Disk-vs-Memory-Diff. Zwei Lücken
bleiben:

1. **ntdll ist ein blinder Fleck.** In `memory.zig` setzt `SYSTEM_SKIP_PREFIXES`
   alles unter `c:\windows\` auf `is_system`, und der Zweig für Hook-Prologe,
   geänderten Code und Disk-Diff verlangt `!is_system`. `ntdll.dll` wird also
   nie gehook-scannt und nie gegen die Platte verglichen. Dazu liefert Aethers
   Disk-Diff nur ein `bool` — keine RVA, keine Bytes, keinen Funktionsnamen.
2. **TDC kennt keine Syscalls.** Im ganzen Repo gibt es keinen Begriff dafür.
   Eine Abweichung an einem Syscall-Stub kann TDC heute weder sehen noch benennen
   noch bewerten.

NTSleuth (`xaitax/NTSleuth`, BSD-3-Clause) schließt die erste Hälfte: Es zieht
die Syscalls aus `ntdll.dll` und `win32u.dll` mit Nummer, RVA,
Rückgabetyp, Parametern samt SAL-Annotationen und den Stub-Bytes, und gibt das
als JSON aus. Das ist die Referenz, gegen die sich ein laufender Prozess messen
lässt. **Wie viele es sind, hängt von Build und Sicht ab.** Auf Build
`26200.9974`, ARM64, hält die arm64-Sicht 1.991 (490 aus `ntdll.dll`, 1.501 aus
`win32u.dll`), die x64-Sicht 490 und **keinen** aus `win32u.dll`. Jede Zahl in
diesem Dokument ist ein Beispiel, keine Konstante.

Der Nutzer will daraus drei Dinge, und einen vierten Teil dazu:

- **Nachschlagen:** Syscalls durchsuchen, Signatur und Parameter lesen.
- **Messen:** die Stubs eines laufenden Prozesses gegen die Baseline halten und
  Abweichungen benennen, bewerten und in die Score-Historie bringen.
- **Regelwerk erweitern:** aus Abweichungen Erkennungsregeln erzeugen.
- **Kontext zur Windows-Binary:** eine BloodHound-artige Visualisierung der
  Import- und Export-Beziehungen der System32-Binaries, **neben** der Heatmap,
  nachgebaut im Projekt statt über eine fremde Schnittstelle.

**Wer es nutzt:** der Nutzer selbst, im Browser. MCP-Werkzeuge für Agenten
kommen später.

**Gewählt hat der Nutzer im Mockup** Variante C: Die Karte ist die Hauptfläche,
Katalog und Messung hängen daran. Für den Leser der Stub-Bytes Variante 1
(ctypes im Web-UI-Prozess). Für den Binary-Graph den vollständigen Nachbau als
eigene Visualisierung parallel zur Heatmap.

## Ziele

### 1. Neuer Tab „SYSCALLS"

Oberfläche englisch. Aufbau von oben nach unten:

- **Kopf** wie die anderen Tabs: `.content-header` mit Kicker, Titel,
  `.content-subtitle` und `.header-actions`. Der Untertitel nennt den Bestand:
  Anzahl Syscalls, je Modul, Build-Nummer und Architektur der Baseline.
- **Werkzeugleiste in einer Zeile:**
  - **Umschalter MAP / GRAPH** als `.oc-segmented`-artige Gruppe. Beide
    Ansichten teilen das Detailpanel rechts und die Abweichungsliste unten.
  - **Ziel:** eine Prozessauswahl (PID und Name, aus `/api/processes`), dazu
    **SCAN**. Ohne Ziel zeigt die Karte nur die Baseline.
  - **Filter** (Name, Nummer, Modul) wirkt auf beide Ansichten.
  - **Modul-Umschalter** ntdll / win32u / beide — angeboten werden nur die
    Module, für die die geladene Baseline Einträge hat. Eine Wahl, die nur jede
    Zelle dimmen könnte, gibt es nicht.
- **Hauptfläche links, Ansicht MAP:**
  - Eine Zelle je Syscall, nach Syscall-Nummer sortiert, in einem Band je
    Modul — `ntdll.dll` und `win32u.dll` —, jedes mit Überschrift und Anzahl.
    Ein Modul, für das die geladene Baseline keinen Eintrag hat, bekommt kein
    leeres Band.
  - Farbe ist der Zustand: intakt, hooked (dateigedecktes Modul), gepatcht,
    abweichend, kein Stub lesbar.
    Ohne Scan sind alle Zellen im Baseline-Ton.
  - Eine Legende nennt jeden Zustand mit seiner Anzahl.
  - Hover zeigt Name und Nummer, Klick lädt das Detailpanel.
  - Der Filter dimmt nicht passende Zellen statt sie zu entfernen, damit die
    Position einer Zelle über die Zeit stabil bleibt.
- **Hauptfläche links, Ansicht GRAPH:** siehe Ziel 6.
- **Detailpanel rechts** für den gewählten Syscall:
  - Name, Nummer (hex und dezimal), Modul, RVA, Rückgabetyp, Aufrufkonvention.
  - Die Parameter als Tabelle: Position, Typ, Name, SAL-Annotation.
  - Die Signatur als zusammenhängender Text zum Kopieren.
  - Die Stub-Bytes: Baseline und, nach einem Scan, die gelesenen, mit markierten
    Unterschieden.
  - Bei einer Abweichung: Klassifikation, Sprungziel und wem es gehört.
  - Links hinaus: `ntdoc.m417z.com` für den Syscall, WinGraph für das Modul.
  - **Open in Rizin** für die Adresse des Stubs, wenn eine Sitzung möglich ist.
- **Abweichungsliste unten**, nach einem Scan: je Abweichung der Name, die
  Nummer, erwartete und gelesene Bytes, die Klassifikation, das Sprungziel und
  der Beitrag zum Evidence-Score. Dazu je Zeile **Regel erzeugen**.
- **Höhe:** Die Arbeitsfläche füllt die Fensterhöhe, jede Liste scrollt in sich.
  Unter etwa 1400 px werden Hauptfläche und Detailpanel zu Reitern.

### 2. Baseline

- `ntsleuth.exe --auto-params` läuft **einmal beim Provisionieren** und legt
  seine JSON-Ausgabe unter `C:\tools\ntsleuth\baseline\` ab, benannt nach
  Build-Nummer und Sicht, als `ntsleuth-<build>-<view>.json`, etwa
  `ntsleuth-26220.5770-arm64.json`. Der Präfix hält sie vom Binary-Graph-Cache
  im selben Verzeichnis auseinander.
- Das Web-UI lädt die passende Datei beim Start und hält sie im Speicher. Die
  Daten sind pro Build konstant; es gibt keinen Grund, sie je Anfrage neu zu
  ziehen.
- **Ungültig** wird die Baseline, wenn die Build-Nummer des laufenden Systems
  nicht mehr zur Datei passt. Dann zieht TDC sie im Hintergrund neu und sagt es
  im Tab. NTSleuth braucht dafür unter 4 Sekunden.
- **Ein Fehlschlag gilt nur, bis ihn eine Baseline widerlegt.** Sobald eine
  brauchbare Baseline für Build und Sicht eines fehlgeschlagenen Versuchs
  vorliegt, ist dessen Eintrag gelöscht — gleich, wer die Datei geschrieben hat;
  der Installer schreibt sie ohne das Web-UI. Sonst meldete
  `/api/syscalls/status` in einer Antwort eine geladene Baseline und den
  Fehlschlag, sie zu erzeugen, und hielte einen neuen Versuch zurück.
- **Eine Baseline je Sicht, nicht je Prozess-Architektur.** Auf einer ARM64-VM
  bildet `System32\ntdll.dll` als ARM64X-Datei zwei Sichten ab: die native
  ARM64- und die x64/EC-Sicht. Beide haben eigene RVAs und eigene Stub-Bytes.
  Die Baseline muss also sagen, für welche Sicht ihre RVAs gelten.
  - **Darum werden auf ARM64 beide Binaries installiert**, `ntsleuth-arm64.exe`
    und `ntsleuth-x64.exe`, und beide erzeugen ihre Baseline; die x64-Variante
    läuft dafür unter Emulation. Ohne die x64-Sicht wäre die Messung wertlos,
    denn ein emuliertes x64-Sample ist auf einer ARM64-VM der Normalfall (siehe
    README, Abschnitt zur Emulation). Auf einer x64-VM entfällt die
    ARM64-Baseline.
  - **Die Sicht eines Zielprozesses bestimmt `_process_machine(pid)`** in
    `webui/app.py`. Diese Funktion liest den PE-Header des Images und liefert
    `x64`, `ARM64`, `ARM64EC`, `x86`. **Nicht `IsWow64Process2`:** ihr eigener
    Kommentar hält fest, dass die auf ARM64 x64-Prozesse als native meldet und
    sie deshalb nicht unterscheiden kann.
  - Fehlt die passende Baseline, sagt der Tab das und misst nicht.
- **Neu ziehen ohne Netz.** `--auto-params` holt Parameter zum Teil aus PDBs vom
  Microsoft-Symbolserver; ein neuer Build heißt neue PDBs, und die Kammer läuft
  netzgetrennt. Ist der Symbolserver nicht erreichbar, zieht TDC die Baseline mit
  `--no-symbols` neu und sagt im Tab, dass die Parametertabelle unvollständig
  ist. **Die Messung bleibt davon unberührt:** Nummern, RVAs und Stub-Bytes
  stammen aus der Disassemblierung, nicht aus Symbolen. Nur das Nachschlagen
  verliert Komfort, nicht die Richtigkeit.
- Fehlt NTSleuth ganz, zeigt der Tab „NTSleuth not installed" mit dem Pfad, wie
  es die anderen Werkzeuge tun, und bleibt ansonsten bedienbar.

### 3. Messung

Neues Modul `webui/syscall_scan.py`, reines ctypes, kein zusätzliches Binary.

- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, …)`.
- `EnumProcessModulesEx(…, LIST_MODULES_ALL)` und `GetModuleFileNameExW` liefern
  die geladenen Module mit Basisadresse und Größe. Daraus die Basis von
  `ntdll.dll`, und, wenn vorhanden, `win32u.dll`.
- Für jeden Syscall der Baseline die Bytes an `base + rva` lesen, und zwar so viele, wie die Sicht zur Erkennung braucht — auf ARM64 mehr als zum Vergleich, weil ein Hook der Form `ADRP; ADD; BR` erst in 12 Byte und `MOVZ` mit drei `MOVK` und Sprung erst in 20 Byte erkennbar ist.
- **Den Eigentümer des Sprungziels in zwei Schritten bestimmen.** Folgt die Zieladresse direkt aus den Bytes (relativer Sprung oder eingebettete absolute Adresse), wird sie damit erfragt. Liest die Hook-Form ihr Ziel erst aus dem Speicher (`FF 25` auf x64, `LDR`+`BR` und `ADRP`+`LDR`+`BR` auf ARM64), ist aus den Bytes nur die Adresse des **Zeigers** bestimmbar; dort wird das Zeigerwort gelesen und erst dessen Ziel nach dem Eigentümer gefragt. Ohne diesen zweiten Schritt käme die häufigste EDR-Hook-Form immer als `diverged` durch, und `hooked` wäre für den Normalfall unerreichbar — womit die Trennung aus Ziel 4 ihren Zweck verlöre.
- **Nur das Stub-Präfix vergleichen, nicht NTSleuths ganzes Fenster.**
  `stub_bytes` ist ein festes 32-Byte-Fenster, das über die Funktion
  hinausläuft: NTSleuths eigenes Beispiel für `NtCreateProcessEx` enthält hinter
  `SVC`/`RET` erst Füllbytes und dann **den Stub des nächsten Syscalls**. Würde
  TDC alle 32 Bytes vergleichen, ließe ein Hook seinen Nachbarn mitleuchten und
  jede Zählung wäre zu hoch. Verglichen wird daher eine Präfixlänge je
  Architektur — auf ARM64 die 8 Bytes von `SVC` und `RET`, auf x64 die Länge des
  tatsächlichen Stubs, der je nach WOW64-Prüfung variiert. Diese Länge erscheint
  im Detailpanel, bestimmt die Diff-Markierung und steht in den Tests.
- **Gebündelt lesen.** Die RVAs werden sortiert und in zusammenhängenden Spannen
  gelesen, nicht einzeln. Ein Aufruf von `ReadProcessMemory` je Stub, bei
  einer arm64-Baseline rund 2.000, ist unnötig; die Stubs liegen dicht
  beieinander.
- Ein Lesefehler ist kein Abbruch: die betroffene Zelle wird „kein Stub lesbar".
- **Ein Scan, der keinen Stub messen konnte, ist nie `CLEAN`.** Ein Stub
  `unreadable` ist keiner, der gemessen wurde. Hat ein Scan nur solche (oder gar
  keinen), heißt sein Urteil NOT OBSERVED — beim Knopf SCAN, in der
  Detonationsstufe, im Verlauf und im Urteil der Detonation —, und der Sweep
  zählt den Prozess nicht als gescannt. Ein Befund aus der Stub-Suche hebt das
  Urteil trotzdem.
- **Nur lesen.** Kein `WriteProcessMemory`, kein Debugger-Attach, keine
  Injektion. Der Zielprozess bleibt unverändert, wie bei den übrigen
  Live-Memory-Werkzeugen.
- **Standardmäßig nur ntdll.** `win32u`-Stubs gibt es nur in GUI-Prozessen; sie
  erzeugen sonst Rauschen. win32u ist im Tab zuschaltbar — sofern die geladene
  Baseline win32u-Einträge hat. Hat sie keine, ist der Schalter aus und sagt
  warum. Das entscheiden die Daten, nicht die Sicht: Die x64-Sicht des Builds
  `26200.9974` auf ARM64 hat keine, ein anderer Build oder ein x64-Host kann
  sie haben.
- **Zeitlimit** für den ganzen Scan, wie bei den Scan-Routen. Ein Scan darf das
  Web-UI nicht blockieren.

### 4. Klassifikation einer Abweichung

**Fünf** Zustände je Syscall: `intact`, `hooked`, `patched`, `diverged`,
`unreadable`. Die Karte hat entsprechend fünf Farben, die Legende fünf Zeilen.

Der Unterschied zwischen `hooked` und `patched` ist **wem das Sprungziel
gehört**, nicht das Befehlsmuster:

- Zeigt es in ein geladenes, auf der Platte hinterlegtes Modul, das nicht
  `ntdll` ist, heißt das `hooked`. Das ist der Normalfall bei installiertem EDR.
- Zeigt es in privaten, nicht von einer Datei gedeckten Speicher oder in eine
  gemappte Ansicht einer Datei, die kein geladenes Modul ist, heißt das
  `patched`. Das ist das Signal — gemeint ist der **letzte** Eigentümer nach dem
  folgenden Punkt, nicht der erste Sprung.
- **Ein erster Sprung in privaten Speicher ist für sich noch kein Befund.**
  MinHook und Microsoft Detours, die beiden verbreitetsten x64-Hook-Bibliotheken,
  schreiben `E9 rel32` in den Stub und landen auf einem Relay, das sie mit
  `VirtualAlloc` nahe am Ziel anlegen — privatem Speicher. Erst das Relay springt
  (`FF 25`) in die Hook-DLL. ARM64-Hooker brauchen ein Relay zwangsläufig, weil
  `B` nur ±128 MB reicht. EDRs, Overlay- und Aufnahme-Software und die Sandboxen
  von Chromium/Edge und Firefox hooken so. Darum gilt: Liegt das erste Ziel in
  privatem oder nicht dateigedecktem Speicher und sind seine Bytes eine der
  bekannten Sprungformen, folgt die Messung diesem Sprung, **höchstens zwei
  Sprünge weit**, und entscheidet nach dem **letzten** Eigentümer. Die
  durchlaufenen Relays stehen im Ergebnis. Privater Code, der kein Sprung ist,
  bleibt `patched`, ebenso eine Kette, die nach zwei Sprüngen noch in privatem
  Speicher steht. Ist ein Relay nicht lesbar oder sein Ziel nicht erfragbar,
  wird nicht geraten: der Stub ist `diverged` und zählt als fehlgeschlagene
  Eigentümer-Abfrage.
- **Der Decoder ist nicht vollständig.** Ein privates Relay, dessen Sprungform
  er nicht kennt, gilt als „privater Code, der kein Sprung ist", also
  `patched`. Diese Richtung ist gewollt und wird hier ausgesprochen: Unbekannten
  privaten Code stattdessen nicht zu werten, gäbe Malware einen freien Ausgang
  — sie schriebe Code, den der Decoder nicht kennt, und nichts zählte. Der Rest
  ist daher ein **falsch positiver Befund bei einer unbekannten Hook-Form, nie
  ein falsch negativer bei Malware.** Jede neue, in der Praxis gesehene Form
  erweitert den Decoder; die Regel ändert sie nicht.
- Zeigt es **direkt** in `ntdll` selbst oder in das Modul des Stubs, heißt das
  `diverged`: `hooked` ist für ein fremdes, dateigedecktes Modul reserviert und
  `patched` für privaten Speicher. Ein modulinterner Sprung — oder ein Fehler
  der Baseline — ist keins von beidem und wird nicht geraten. **Über ein Relay**
  dorthin ist es `patched`: ein Sprung aus dem Modul in privaten Speicher und
  zurück ist weder ein eigener Sprung des Moduls noch ein Fehler der Baseline.
- Weichen die Bytes ab, ist das Ziel aber nicht auflösbar, heißt das `diverged`.
  Dieser Fall wird nie stumm als `intact` geführt.

**Die Besitzfrage braucht eine Region-Abfrage.** `OpenProcess`,
`EnumProcessModulesEx`, `GetModuleFileNameExW` und `ReadProcessMemory` genügen
dafür nicht — sie können „privat, nicht dateigedeckt" nicht von „in einem Modul"
unterscheiden. `webui/syscall_scan.py` braucht daher zusätzlich `VirtualQueryEx`
und `GetMappedFileNameW`. Der Weg über die bloße Modulliste wäre kürzer, würde
aber Speicher, den der Angreifer selbst angelegt hat, nicht von einem Modul
unterscheiden. **Ein überschriebenes Modul erkennt auch die Region-Abfrage
nicht:** Module Stomping behält `MEM_IMAGE` und den Pfad, und
`GetMappedFileNameW` nennt die Datei, nicht ihren Inhalt. `hooked` heißt darum
nur „ein dateigedecktes Modul hält das Ziel" — ein EDR, aber ebenso eine vom
Sample geladene oder eine überschriebene DLL — und wird so beschriftet, nicht
als EDR-Hook. Ein Ziel in einem Windows-Kernmodul (`kernelbase.dll`,
`kernel32.dll`, `win32u.dll` und wenige andere, in denen kein Hook-Produkt seinen
Handler ablegt) ist eine Code-Cave und gilt als `patched`. Der für die Tests
injizierte Leser muss diese Schicht mit abbilden.

**Was die Region-Abfrage zurückgibt, wird über dem Leser entschieden.** Ein
`MEM_MAPPED`-Bereich ohne Dateinamen (ein vom Pagefile gedeckter Abschnitt, das
klassische Ziel von `NtMapViewOfSection`) ist nicht dateigedeckt und zählt als
privat. Ein `MEM_IMAGE`-Bereich ohne Namen ist eine **fehlgeschlagene**
Abfrage — ein Image ist per Definition dateigedeckt, und unter dem
eingeschränkten Zugriffsrecht scheitert `GetMappedFileNameW` leicht — und wird
wie jede fehlgeschlagene Eigentümer-Abfrage gezählt. Ein `MEM_MAPPED`-Bereich
**mit** Dateinamen ist eine Datenansicht und kein geladenes Modul — geladene
Module sind `MEM_IMAGE` —, gleich welche Datei er abbildet, auch eine
Datenkopie von `ntdll.dll`. Kein Hook-Produkt führt seinen Handler aus einer
solchen Ansicht aus. Sein Eigentümer heißt `mapped`, nicht der Dateiname, und
er wird wie privater Speicher behandelt: `patched`, und als Relay verfolgt.
Sonst hinge der Zustand derselben Ansicht davon ab, ob `GetMappedFileNameW`
ihren Namen liefern konnte — ohne Namen wäre sie privat, mit Namen ein
Modulname, der keiner ist.

Die Befehlsmuster sind **pro Architektur** zu prüfen:

- **x64:** Der saubere Stub beginnt `4C 8B D1 B8 <ssn:4>` und endet mit `0F 05`.
  Hook-Muster: `E9` (JMP rel32), `FF 25` (JMP [rip+disp32]),
  `48 B8 <imm64> FF E0`, `49 BB <imm64> 41 FF E3`, `68 <imm32> C3` und der
  14-Byte-Absolutsprung `68 <imm32> C7 44 24 04 <imm32> C3`.
- **ARM64:** Der saubere Stub ist `SVC #imm` gefolgt von `RET`, in NTSleuths
  Ausgabe etwa `01 18 00 d4 c0 03 5f d6`. Hook-Muster: ein unbedingtes `B`
  (Opcode-Maske `0x14000000`), `LDR Xn, literal` + `BR Xn` für jedes Register
  n, `ADRP` + `ADD` + `BR`, `ADRP Xn` + `LDR Xt, [Xn, #imm]` + `BR Xt` und
  `MOVZ Xn` mit bis zu drei `MOVK Xn` + `BR Xn`. Statt `BR` darf jede dieser
  Formen mit einem Sprung mit Zeiger-Authentifizierung enden (`BRAA`, `BRAB`,
  `BRAAZ`, `BRABZ`), den Windows auf ARM64 verwendet; gefragt wird dann nach der
  Adresse ohne die PAC-Bits darüber, also nach den unteren **47** Bits. Eine
  Windows-Nutzeradresse endet bei `0x7FFF'FFFFFFFF`, 47 Bits tragen jede davon,
  gleich ob der Nutzerbereich 47 oder 48 Bits hat. Mit 48 gehörte Bit 47 unter
  47 Bits zur PAC, die der Signierende wählt: ein Zeiger, der es setzt, ergäbe
  keine Adresse, eine fehlgeschlagene Abfrage, `diverged` — ungewertet, wo das
  Relay vorher `patched` war. `BLR` ist keine Sprungform: es ist ein
  Aufruf, und ein Relay, das aufruft, kehrte nicht durch den Stub zurück.
  Das Register ist nicht fest: Der übliche EDR-Hook nimmt x16, Microsoft
  Detours x17 für beide Formen (`LDR x17, #8; BR x17` und
  `ADRP x17; LDR x17, [x17, #off]; BR x17`). Ein Relay in einer dieser Formen
  nicht zu erkennen hieße, es als privaten Code ohne Sprung zu lesen und den
  Hook `patched` zu nennen.
- Die Syscall-Nummer im Stub muss zur Nummer der Baseline passen. Weicht nur
  die Nummer ab, ist das ein eigener, besonders deutlicher Befund.

Zusätzlich hält die Messung fest, wem das Sprungziel gehört, als Modulname oder
als „privat". Dieser Wert steht in der Abweichungsliste und entscheidet über die
Unterdrückung nach Ziel 5.

### 5. Regelwerk erweitern

Drei Ziele, in dieser Rangfolge:

1. **`webui/syscall_signatures.json`** — neu, projekteigen, versioniert, nach dem
   Muster von `webui/pipe_signatures.json`: ein Array von Einträgen mit Familie,
   Muster, Match-Art, Gewicht und Notiz, geladen von einem Loader, der jeden
   Eintrag gegen ein Schema prüft, defekte Einträge überspringt und das Gewicht
   nach oben begrenzt, damit ein einzelner Treffer nie allein MALICIOUS erreicht.
   Hier leben die Hook- und Patch-Muster.

   **Die Arbeitsteilung mit dem Code ist festgelegt, damit nichts doppelt lebt:**
   Die Erkennung einer Form bleibt im Code (`classify_stub` muss das
   Displacement *dekodieren*, nicht nur Bytes vergleichen). Die Datei liefert
   **Familienname und Notiz** zu einer erkannten Form, also was der Analyst
   liest. Ihr `weight` ist **beratend und nicht der Score** — der kommt aus
   `memory_evidence.KINDS`. Ein Test pinnt die Muster der Datei gegen die des
   Codes, damit die beiden nicht auseinanderlaufen; die Datei sagt das über sich
   selbst, damit niemand sie für die Bewertungsquelle hält. Ob ein Eintrag eine
   Abweichung schon abdeckt, wird an **allen gelesenen Bytes** geprüft
   (`read`, `READ_LEN`), nicht am verglichenen Präfix: auf ARM64 sind das 8
   Bytes, und `ADRP; LDR; BR` braucht 12, `MOVZ/MOVK; BR` bis zu 20.

   Ein Eintrag darf zusätzlich eine `view` nennen: ein x64-Opcode ist auf ARM64
   eine andere Anweisung, ein Muster ohne Sicht wäre also mindestens zur Hälfte
   falsch.
2. **Generierte YARA-Regeln** nach `rules/yara/`. Der wertvolle Fall sind
   Samples, die **eigene** Syscall-Stubs mitbringen, statt ntdll zu rufen. Erst
   die Baseline macht so eine Regel benennbar: aus „hier steht ein Stub mit
   Nummer 0x3A" wird „hier steht ein Stub für `NtWriteVirtualMemory`". Die
   erzeugte Regel trägt die Hausform der bestehenden Regeln, also
   `author = "DetonationChamber"`, Beschreibung, Severity, ATT&CK-Tags, und sie
   nennt die Build-Nummer, für die die Nummer gilt.
3. **`memory_evidence.KINDS`** — kein Regelwerk, sondern die Verdrahtung. Ein
   neuer Eintrag genügt, damit ein Befund Gewicht, Evidenzklasse, Korroboration,
   Score-Historie und die bestehenden Diagramme erbt. Vorgeschlagen:
   `syscall_stub_patched`, strukturell, Gewicht in der Größe von
   `disk_mem_diff` (4.0), ohne Korroborationspflicht;
   `syscall_stub_hooked`, behavioral, kleines Gewicht, korroborationspflichtig;
   `syscall_stub_renumbered`, strukturell, 4.0, ohne Korroborationspflicht,
   für einen Stub intakter Form mit fremder Nummer (Ziel 4) — er braucht kein
   Sprungziel und hat keine harmlose Erklärung;
   und `direct_syscall_stub` aus Ziel 7a, strukturell, mit dem höheren Gewicht,
   wenn die zugehörige Import-Kette im Sample fehlt.

   **Kein `baseline_exempt`.** Das Flag tut das Gegenteil des Erwarteten: in
   `memory_evidence.score()` gibt `known()` für einen solchen Befund immer
   `False` zurück, er ist also **immun gegen die Baseline** und würde ewig
   zählen. Genau das wäre das erste Anti-Ziel dieses Dokuments.

   **Die normale Baseline kann EDR-Hooks ohnehin nicht unterdrücken.**
   `MemoryFinding` nimmt die Prozessidentität in jeden Schlüssel auf
   (`proc_key`), also kann ein in `explorer.exe` aufgenommener Hook denselben
   Hook in `sample.exe` nie bedecken. Und `/api/memory/baseline/capture` ruft
   nur Aether; Syscall-Befunde kämen dort nie hinein.

   **Darum ein eigener, prozessunabhängiger Mechanismus:** eine
   Hook-Eigentümer-Liste, aufgenommen einmal auf dem sauberen Host, als Paare
   aus Syscall-Name und besitzendem Modul, abgelegt neben der Baseline. Ein
   Hook, dessen Eigentümer auf dieser Liste steht, **wird gar nicht erst zum
   Befund** — er bleibt in Karte und Abweichungsliste sichtbar, erreicht aber
   den Scorer nicht. Gefiltert wird an der Quelle, nicht im Scorer; damit bleibt
   `MemoryBaseline` unberührt. Die Liste wird über eine eigene Route aufgenommen
   und ist im Tab sichtbar und löschbar.

**Eine Regel gibt es nur für einen Stub.** Die Oberfläche hat keine Anmeldung,
und die CSRF-Sperre lässt Clients ohne Header durch: Malware in der VM kann die
Routen rufen. Entwurf und Übernahme verlangen darum, dass die Bytes genau ein
Stub der Form ihrer Sicht sind und die genannte Nummer laden, und dass der
Regelname der aus Syscall, Sicht und Bytes gebildete ist. Das Verzeichnis nimmt
höchstens `RULES_MAX` Regeldateien, und ist es selbst ein Link oder eine
Junction, wird nicht hindurch geschrieben.

**Nichts wird ungefragt geschrieben.** „Regel erzeugen" zeigt den Entwurf, der
Nutzer übernimmt ihn. Erzeugte Regeln sind als erzeugt markiert und nennen
Herkunft, Zeitpunkt, Build **und Sicht**. Die Sicht gehört dazu, weil die
Stub-Form selbst von ihr abhängt: ein x64-Stub beginnt `4C 8B D1 B8`, ein
ARM64-Stub ist `SVC` mit `RET`. Eine Regel ohne diese Angabe wäre auf der
falschen Sicht stumm und niemand wüsste, warum.

**Wohin eine übernommene YARA-Regel geht.** `rules/yara/` ist ein Pfad im Repo
auf dem Host; auf der VM landen Regeln nur beim Provisionieren, und
`install-detection-rules.ps1` richtet Rustinel anschließend auf ein anderes
Verzeichnis (`C:\tools\detection-rules\yara-combined`). Eine Regel ins Repo zu
schreiben, hieße also, dass sie auf der laufenden VM niemand lädt. Darum
**beides**:

- **Übernehmen** schreibt in das Verzeichnis, aus dem Rustinel tatsächlich
  liest. Dessen `[reload]` ist aktiv (`debounce_ms = 2000`), die Regel greift
  also nach etwa zwei Sekunden, ohne Neustart. Dieses Verzeichnis kommt als
  schreibbare Wurzel zu `_path_within` hinzu, eng gefasst wie beim Hex-Schreiben.
- **Herunterladen** liefert dieselbe Regel als Datei, damit der Nutzer sie im
  Repo unter `rules/yara/` ablegen und versionieren kann. Nur so übersteht sie
  ein neu aufgesetztes System — dasselbe Argument, mit dem dieses Dokument
  Aethers Regelverzeichnis ausschließt.

**Aethers Regelverzeichnis wird nicht angefasst.** `C:\tools\Aether\rules\` kommt
aus dem Upstream-Klon; `build-aether.sh` ersetzt es, `install-aether.ps1`
kopiert darüber. Dort erzeugte Regeln wären verloren.

Ebenso **keine generierten Sigma-Regeln:** Sigma beschreibt Ereignisse, und ein
gepatchter Stub erzeugt kein Ereignis. Eine Sigma-Regel wäre hier eine Attrappe.

### 6. Binary-Graph, nachgebaut

Neues Modul `webui/binary_graph.py`. Die Fähigkeit von WinGraph wird im Projekt
nachgebaut, nicht angebunden.

**Warum nachbauen:** WinGraph hat kein öffentliches Repo und keine REST-API;
alle `/api/*`-Pfade antworten 404, die Next.js-App arbeitet über Server Actions.
Eine Anbindung hieße, undokumentierte Aufrufe nachzubilden. Dazu zwei
inhaltliche Gründe: Die Kammer muss offline arbeiten, und der Importgraph ist
pro Build und Architektur verschieden — ein fremder x64-Datensatz wäre für eine
ARM64-VM der falsche. Nach WinGraph wird nur verlinkt.

- **Extraktion:** Import- und Export-Tabellen aller PE-Dateien in
  `C:\Windows\System32` (`*.dll`, `*.exe`). Das Projekt nutzt dafür schon
  `pefile`; `_pe_import_tree` und `_pe_export_tree` in `webui/app.py` zeigen das
  Muster.
- **Forwarder auflösen.** Das ist der Teil, den es noch nicht gibt:
  `_pe_export_tree` ignoriert `exp.forwarder`. Ohne Forwarder bricht jeder Pfad
  schon bei `kernel32` ab.
- **API-Sets auflösen.** Viele System32-Forwarder zeigen auf
  `api-ms-win-core-*`-Namen, zu denen **keine Datei auf der Platte** gehört.
  Ohne Auflösung endet die Kette dort, nur einen Sprung später. Die Zuordnung
  kommt einmalig aus der ApiSetMap in `apisetschema.dll` und liegt als Tabelle
  im Cache. Das ist eine Extraktion, keine Analyse.
- **Knoten** sind Binaries und, eine Ebene tiefer, Funktionen. **Kanten** sind
  `imports`, `forwards_to`, `resolves_to` (API-Set) und `reaches_syscall`.
  Woher eine Kante kommt, steht an ihr: `derived` oder `curated`.

**Die Grenze der Kanten, und wie der Graph damit umgeht.** Import- und
Export-Tabellen beweisen Beziehungen **auf Modulebene**: „kernelbase importiert
diesen Export von ntdll". Sie beweisen nicht, welche *Funktion* von kernelbase
ihn ruft. `kernelbase!WriteProcessMemory` **ruft** `NtWriteVirtualMemory`, es
leitet nicht dorthin weiter, und aus dem Namen ist das nicht ableitbar. Die
Wahrheit auf Funktionsebene bräuchte Disassemblierung, und die ist hier
Nicht-Ziel.

Der Graph arbeitet daher so:

- **Alle aus PE-Tabellen abgeleiteten Kanten sind Modulkanten** und als solche
  gezeichnet.
- **Der letzte Sprung von einer Win32-Funktion zu ihrem Nt-Gegenstück kommt aus
  einer kuratierten Tabelle**, neu und projekteigen als
  `webui/win32_to_nt.json`: Win32-Name, Nt-Name, Quelle der Zuordnung. Sie
  deckt nicht ganz Win32 ab, sondern die APIs, die TDC ohnehin interessieren —
  `SUSPICIOUS_IMPORTS` in `webui/app.py` führt diesen Katalog schon.
- **Kuratierte Kanten sehen anders aus** als abgeleitete: eigene Strichart,
  eigene Legendenzeile, und das Detailpanel nennt sie als kuratiert. Die
  Oberfläche behauptet an keiner Stelle, ein kuratierter Sprung sei aus den
  Daten gewonnen.
- Fehlt für eine Win32-Funktion ein Eintrag, endet der Pfad sichtbar mit
  „kein kuratierter Übergang bekannt" statt stillschweigend zu verschwinden.
- **Cache:** einmal beim Provisionieren erzeugt, als JSON unter
  `C:\tools\ntsleuth\baseline\` neben der Syscall-Baseline, mit derselben
  Build-Nummer gestempelt. Rund 4.000 Binaries sind zu viel, um sie je Anfrage
  zu parsen.
- **Knoten** sind Binaries und, eine Ebene tiefer, Funktionen. **Kanten** sind
  `imports`, `forwards_to` und `reaches_syscall`.

**Ansicht GRAPH im Tab**, abfragegetrieben wie BloodHound. Eine Auswahl von
Abfragen, dazu ein Suchfeld für einen Startknoten:

- **Pfad zum Syscall:** von einem Import eines Samples oder einer DLL bis zur
  Syscall-Nummer, über alle Forwarder.
- **Wer importiert das?** die Umkehrung, für eine DLL oder eine Funktion.
- **Importe eines Samples**, mit den verdächtigen Einträgen hervorgehoben.
  `SUSPICIOUS_IMPORTS` in `webui/app.py` führt diesen Katalog schon.
- **Normale Aufrufer eines Syscalls:** welche System32-DLLs diesen Syscall
  üblicherweise erreichen. Ein ungewöhnlicher Aufrufer fällt dadurch auf.
- **Forwarder-Ketten** einer DLL.
- **Geteilte Abhängigkeiten** zweier Binaries.

Ein Klick auf einen Syscall-Knoten wählt dieselbe Zelle in der Karte, und
umgekehrt. Beide Ansichten sprechen über dasselbe Detailpanel.

**Wie 4.000 Binaries bedienbar bleiben.** Der ganze Bestand wird nie gezeichnet.
Die Ansicht arbeitet wie BloodHound: ein Einstieg über Suche oder Abfrage, dann
Knoten für Knoten aufklappen.

- **Einstieg** ist ein gesuchtes Binary oder das Ergebnis einer Abfrage.
- **Tiefe** ist einstellbar (1 bis 3). **Aufklappen** holt die Nachbarn eines
  Knotens nachträglich dazu.
- **Obergrenze 400 Knoten**, wie `max_nodes` beim Prozessgraphen. Wird sie
  erreicht, sagt die Ansicht das, so wie `truncated` dort.
- **Die Knotengröße ist der Eingangsgrad** — wie viele Binaries dieses Modul
  importieren. Damit ist „Most Imported DLLs" keine eigene Abfrage mehr, sondern
  im Bild zu sehen.
- **Knotenfarbe** ist die Art: DLL, EXE, Syscall. Kanten zum gewählten Knoten
  heben sich ab.
- Die vorhandene `applyForceLayout` trägt das: 120 Durchläufe, und über 150
  Knoten rechnet sie die Abstoßung über Gitterzellen statt über alle Paare.

**Kennzahlen über den ganzen Bestand** gehören nicht in den Graphen, sondern in
eine eigene Fläche als Tabelle: am meisten importiert, Anzahl Binaries, Kanten,
aufgelöste API-Sets, Forwarder, isolierte Binaries, zirkuläre Paare und die
Anzahl kuratierter Win32→Nt-Übergänge. Als Knotenwolke wären sie unlesbar. Eine
Zahl anzuklicken öffnet sie als Liste, und von dort führt der Weg in den
Graphen.

### 7. Die Verbindung beider Teile

Der eigentliche Gewinn liegt im Zusammenspiel:

- **Der Weg nach unten:** Ein Sample importiert `WriteProcessMemory`. Der Graph
  führt über `kernel32` und `kernelbase` zu `ntdll`, die kuratierte Tabelle
  nennt `NtWriteVirtualMemory`, und die Baseline nennt dessen Nummer. Aus einer
  Import-Tabelle wird so ein Pfad bis zur Syscall-Nummer — mit dem letzten
  Sprung als kuratiert markiert, nach Ziel 6.
- **Der Weg über die Abwesenheit:** Fehlt diese Import-Kette, und liegt im
  Sample trotzdem ein Stub mit genau dieser Nummer, hat es die Kette
  übersprungen. Das ist Direct-Syscall-Umgehung, sichtbar gemacht dadurch, dass
  der normale Weg fehlt. Was diesen Stub findet, steht in Ziel 7a.

### 7a. Stubs außerhalb von ntdll

Eigener Teil, weil Ziel 3 ausschließlich ntdll an Baseline-RVAs liest und einen
mitgebrachten Stub daher nie sähe.

- **Zwei Quellen:**
  - **statisch** die Bytes der eingereichten Datei;
  - **dynamisch** die privaten, ausführbaren Regionen des Zielprozesses. Die
    Region-Schicht aus Ziel 4 (`VirtualQueryEx`, `GetMappedFileNameW`) liefert
    sie schon; hier werden sie nicht nur nach Besitzer gefragt, sondern
    durchsucht.
- **Gesucht wird die Stub-Form der jeweiligen Architektur mit einer für diesen
  Build gültigen Syscall-Nummer.** Diese Bedingung macht den Befund scharf:
  Ohne Baseline wäre „irgendwo steht `SVC`" wertlos, mit ihr heißt es „hier
  steht ein Stub für `NtWriteVirtualMemory`". Nummern, die es in diesem Build
  nicht gibt, sind kein Treffer, sondern ein eigener Hinweis — ein Stub mit
  fremder Nummer deutet auf eine für einen anderen Build gebaute Probe.
- **Eigener Befund** `direct_syscall_stub`, strukturell. Er wiegt schwerer, wenn
  das Sample dieselbe Funktion **nicht** importiert, denn dann ist die Umgehung
  belegt und nicht nur möglich. Importiert es sie auch, ist es ein schwächerer
  Hinweis.
- **Der starke Anspruch braucht die Win32→Nt-Kette und wartet daher auf Plan 2.**
  Ein Sample, das `VirtualAllocEx` importiert und einen Stub für
  `NtAllocateVirtualMemory` trägt, importiert den Nt-Namen nicht — gegen die rohe
  Importtabelle geprüft sähe das wie eine belegte Umgehung aus, obwohl der
  dokumentierte Weg vorhanden ist. Solange die kuratierte Tabelle fehlt, ist
  `import_present` daher **unbekannt** und jeder Treffer gilt als Hinweis, nicht
  als Beleg. Plan 2 schaltet den Beleg frei, indem er die Importmenge über
  `win32_to_nt.json` erweitert. Ein Befund darf nie mehr behaupten, als die
  Daten tragen.
- **Eigene Route** `POST /api/syscalls/stubs` mit `pid` oder `path`.
- Dieser Befund ist die Eingabe für die generierte YARA-Regel aus Ziel 5.2.

### 7b. Stufe in der Detonation

Der Scan läuft nicht nur von Hand im Tab, sondern als Stufe einer Detonation.

- Eine neue Stufe in der Liste der Live-Memory-Werkzeuge
  (`_run_memory_scans_async`, **nicht** `api_submit` — das führt keine
  Stufenliste und liefert kein `scans`), nach Aether und vor Process Dump.
- Ihre Befunde gehen durch `memory_evidence.collect()` in den Gesamt-Score,
  erscheinen im VERDICT FLOW und in der Score-Historie.
- Der System-Sweep (`/api/memory/sweep`) nimmt den Syscall-Scan als weiteres
  Werkzeug auf, **aber nur auf Anfrage** (`"syscalls": true`). Ohne diesen
  Schlüssel bleibt er aus: SWEEP und „Sweep as baseline" senden ihn nicht, und
  eine Baseline-Aufnahme darf keine Syscall-Befunde in die Host-Baseline
  schreiben, solange nicht gezeigt ist, dass eine saubere VM damit sauber
  durchläuft.
- Ein Teilergebnis der Stufe (`partial`, fehlgeschlagene Eigentümer-Abfragen,
  eine unvollständige Stub-Suche) und eine Zahl von `diverged`-Stubs erscheinen
  in den Gründen des Urteils, wie NOT OBSERVED: keins davon ist ein Beleg für
  einen sauberen Prozess. Die Stufe hat im Memory-Reiter der Detonation einen
  eigenen Block, mit dem Grund, wenn sie sich übersprungen hat.
- `_update_preconditions` in `webui/app.py` muss einen laufenden Syscall-Scan
  **und eine laufende Baseline-Extraktion** kennen, damit ein Werkzeug-Update
  keins von beiden unterbricht.
- **Zum Messen genügt die Baseline-Datei.** NTSleuth selbst wird nur gebraucht,
  um eine Baseline zu *erzeugen*. Die Stufe prüft daher auf die passende
  Baseline, nicht auf die Anwesenheit des Binaries — ein System mit Baselines
  und ohne NTSleuth kann messen.
- **Die Stufe startet nie eine Extraktion**, sondern fragt die Baseline ohne
  Erzeugungsauftrag: eine Detonation darf nicht auf einen externen
  Extraktionslauf warten, und ein Werkzeug-Update, das mitten darin die
  `ntsleuth-*.exe` tauscht, wäre das Gegenteil von hilfreich.
- Die Stufe ist abschaltbar, über eine Umgebungsvariable wie
  `TDC_NO_BACKGROUND` es vormacht, nicht je Einreichung. Fehlt die passende
  Baseline, überspringt sie sich mit Hinweis statt die Detonation scheitern zu
  lassen.

### 8. Routen

Unter `/api/syscalls/…`, nach dem Muster der bestehenden Scan-Routen:

- `GET /api/syscalls/status` — ist NTSleuth installiert, welche Baselines liegen
  vor, Build und Architektur, Alter des Binary-Graph-Cache.
- `GET /api/syscalls/baseline` — der Katalog, filterbar und seitenweise.
- `GET /api/syscalls/<name>` — ein Syscall mit Parametern und Stub.
- `POST /api/syscalls/scan` — Messung einer PID. Parameter: `pid`, `modules`.
- `POST /api/syscalls/stubs` — Suche nach Stubs außerhalb von ntdll, nach
  Ziel 7a. Parameter: `pid` oder `path`.
- `GET`, `POST`, `DELETE /api/syscalls/hook-baseline` — die
  Hook-Eigentümer-Liste aus Ziel 5 lesen, auf dem sauberen Host aufnehmen,
  verwerfen.
- `POST /api/syscalls/rule` — Entwurf einer Regel aus einer Abweichung,
  **ohne** zu schreiben.
- `POST /api/syscalls/rule/apply` — den Entwurf übernehmen.
- `GET /api/syscalls/rule/download` — den Entwurf als Datei für das Repo.
- `GET /api/binary-graph/query` — eine der Abfragen aus Ziel 6.
- `GET /api/binary-graph/node` — ein Knoten mit Importen, Exporten, Forwardern.

Jede neue Route gehört in die README-API-Tabelle und in `#help-api`, sonst
schlagen `test_readme_documents_every_api_route_and_nothing_else` und
`test_help_modal_only_mentions_existing_routes` fehl.

### 9. Bereitstellung

- Neues Skript `scripts/install-ntsleuth.ps1`, nach dem Muster von
  `install-capa.ps1` und `install-rizin.ps1`:
  - lädt die Release-Assets, die diese VM braucht: auf x64 nur
    `ntsleuth-x64.exe`, auf ARM64 **beide**, `ntsleuth-arm64.exe` und
    `ntsleuth-x64.exe` (siehe Ziel 2 — ohne die x64-Sicht gibt es keine Messung
    an emulierten Samples),
  - prüft jeden SHA-256 gegen `checksums.txt` der Release,
  - installiert nach `C:\tools\ntsleuth\`,
  - prüft sich selbst (`ntsleuth-<view>.exe --lookup NtCreateProcess` liefert
    eine Nummer),
  - schreibt **danach** einen Marker `tdc-release.txt` mit Tag und Prüfsummen,
  - erzeugt je installiertem Binary eine Baseline,
  - und prüft auf ARM64, dass die beiden Baselines sich **unterscheiden**:
    wären sie byteweise gleich, läge die x64-Variante nicht die x64-Sicht vor,
    und die Messung emulierter Samples wäre still wirkungslos. Sind sie gleich,
    wird die x64-Baseline **gelöscht** — eine fehlende Baseline behandeln
    Tasks 7 und 9 anständig, eine falsche nicht.
  - **Die Form der Stubs entscheidet unabhängig davon.** Eine Baseline, deren
    Stubs nicht überwiegend die Form ihrer Sicht haben (x64: `4C 8B D1 B8`,
    ARM64: `SVC`), wird weder gespeichert noch geladen. Das hängt weder von der
    Reihenfolge der Extraktionen noch davon ab, dass die Datei der anderen Sicht
    existiert, und deckt eine nicht löschbare Doppelgängerin ab.
  - **Derselbe Schutz muss zur Laufzeit gelten.** Die Extraktion auf Abruf
    (Ziel 2) würde die gelöschte Datei sonst beim nächsten Tab-Besuch mit
    demselben falschen Inhalt neu schreiben. Eine x64-Extraktion, deren
    Fingerabdruck dem der arm64-Baseline gleicht, wird daher nicht gespeichert,
    und der Tab sagt, warum.
  - **Die Architektur wird aus der Registry bestimmt, nicht aus
    `$env:PROCESSOR_ARCHITECTURE`.** Der Updater läuft als emuliertes
    x64-Python, und die Umgebungsvariable meldete dort `AMD64` auch auf einer
    ARM64-Maschine — die arm64-Baseline entstünde dann nie.
  - Nimmt `[switch]$Force` und `-Version`, wie die anderen.
  - Die Binaries sind statisch gelinkt; ein VC-Redist ist nicht nötig.
- **Rückgabewerte:** Ein fehlgeschlagener Download oder eine nicht passende
  Prüfsumme beenden das Skript mit einem Fehler — das Werkzeug läuft als SYSTEM
  auf einer Maschine, auf der auch Malware läuft, und eine ungeprüfte Datei wird
  nie installiert. Eine **fehlgeschlagene Baseline-Erzeugung nach geprüfter
  Installation** ist dagegen nur eine Warnung mit Rückgabewert 0: die Kammer
  provisioniert weiter, der Tab meldet „keine Baseline", und Tasks 7 und 9
  behandeln genau diesen Fall schon. Die Stufe ist eine Ergänzung der Kammer,
  keine neue Abhängigkeit — das ist ein Anti-Ziel dieses Dokuments.
- **Der Binary-Graph-Cache gehört zu Plan 2** (Ziel 6) und wird hier nicht
  gebaut.
- **Native für ARM64 vorhanden.** Anders als Aether, Rizin und BeaconEye gibt es
  NTSleuth als ARM64-Binary. Nur die zweite, x64-Baseline entsteht unter
  Emulation.
- Eintrag in `webui/tool_updates.py` `CATALOG` als `kind="release"`,
  Repo `xaitax/NTSleuth`, mit Marker und Skript. Das Release trägt ein
  Datums-Tag (`v2025.08.30-2e15c17`), kein Semver — der Vergleich läuft daher
  über den Marker, wie bei Rizin, nicht über `version_cmd`.
  Der Eintrag gehört zusätzlich in die Tabelle in
  `docs/superpowers/specs/2026-11-13-tool-updates-design.md`, sonst schlägt
  `test_catalog_ids_are_unique_and_match_spec` fehl.
- Einbinden in `Vagrantfile`, `Vagrantfile.utm` und
  `scripts/setup-macos-utm.sh`, wie die übrigen Install-Skripte.
- **Die neuen Dateien gehen in alle drei Deploy-Wege:** `scripts/deploy-utm.py`
  `FILES`, `Makefile` (`deploy:` und `deploy-app`) und `make.ps1` (`'deploy'`
  und `'deploy-app'`). Betroffen sind `webui/syscall_scan.py`,
  `webui/binary_graph.py`, `webui/syscall_signatures.json` und
  `webui/win32_to_nt.json`. Sonst schlägt
  `test_every_deploy_path_uploads_the_web_ui_modules` fehl.

### 10. Doku

- README: Zeile in der Tabelle `### Web UI Tabs`, ein Abschnitt zu Syscalls, die
  neuen Routen in der API-Tabelle, das Install-Skript in der Dateistruktur,
  NTSleuth und WinGraph in den Credits mit ihren Lizenzen.
- Hilfe: ein `<h4>` im Tab-Guide `#help-usage`, die Routen in `#help-api`.
- `data-info` für den Tab und jede neue Karte: höchstens 300 Zeichen, ein bis
  zwei Sätze, ohne `<`, `&`, `${`.
- Screenshot `static/syscalls.png` (Cyberpunk, 1920×960, echte Daten).

### 11. Tests

Nach Hausmuster: Backend über den Flask-Testclient, Frontend über die
Node-Harness (`_function_source`, `_run_node`).

- `tests/test_syscalls.py` — Baseline laden, Katalog filtern, Klassifikation
  je Architektur gegen feste Byte-Folgen, die fünf Zustände, Präfixlänge,
  Hook-Eigentümer-Liste, Score-Beitrag, Regel-Entwurf.
- `tests/test_syscalls_ui.py` — Karte, Legende, Detailpanel, Abweichungsliste,
  Escaping, und dass eine kuratierte Kante als solche gezeichnet wird.
- `tests/test_binary_graph.py` — Import- und Export-Parsing,
  Forwarder-Auflösung über eine künstliche Kette, API-Set-Auflösung, die
  Abfragen aus Ziel 6, Zyklen, und ein Pfad, dem der kuratierte Übergang fehlt.
- `tests/test_syscall_stubs.py` — der Scanner aus Ziel 7a: Treffer mit gültiger
  Nummer, Nummer aus einem fremden Build, kein Treffer bei harmlosen Bytes, und
  das höhere Gewicht bei fehlender Import-Kette.
- **Die CI hat kein Windows und kein NTSleuth.** Die Tests laufen gegen
  abgelegte JSON-Ausgaben in `tests/samples/` und gegen eine nachgebaute
  Lesefunktion, die statt `ReadProcessMemory` und `VirtualQueryEx` aus einem
  Dictionary liest. Die ctypes-Schicht ist deshalb so zu schneiden, dass der
  Leser austauschbar ist — wie `tool_updates.Env` die Umgebung injiziert.
- **Die Detonationsstufe** wird gegen einen gefälschten Scanner geprüft, samt
  dem Fall „NTSleuth fehlt, Stufe überspringt sich".
- **Zählungen anpassen:** `test_info_texts_cover_every_tab` zählt heute 12
  `.content-header` und 14 `.tab-content`. Mit dem neuen Tab sind es 13 und 15.
- Weiter betroffen: `test_readme_tabs_match_the_ui`,
  `test_help_tab_guide_covers_every_tab`, `test_every_data_table_is_sortable`
  (neue Tabellen brauchen `data-sortable` und `data-sort-id`),
  `test_rows_that_hold_no_data_are_marked`,
  `test_formatted_times_and_sizes_sort_by_their_value`,
  `test_scripts_reach_the_vm`, und die Farbtests in `tests/test_theme.py`.
- Die CI läuft unter `TZ=UTC` und `TZ=Europe/Berlin`.

## Nicht-Ziele

- NTSleuth als Bibliothek einbinden oder seinen C++-Code übersetzen. Es wird als
  Binary aufgerufen.
- Die Stubs eines Prozesses verändern, Hooks entfernen, ntdll neu laden.
- Ein Debugger-Attach an ein Sample.
- Syscalls zur Laufzeit mitschneiden. Das ist Tracing und gehört zu Rustinel,
  nicht hierher. Diese Ansicht vergleicht Zustände, sie beobachtet keine Aufrufe.
- **Kanten auf Funktionsebene aus Disassemblierung gewinnen.** Welche Funktion
  einer DLL einen Syscall ruft, wäre nur so zu beweisen. Der Graph bleibt auf
  Modulebene und markiert den letzten Sprung als kuratiert (Ziel 6).
- Die kuratierte Win32→Nt-Tabelle über die APIs hinaus führen, die TDC ohnehin
  als verdächtig kennt. Sie ist kein Win32-Lexikon.
- WinGraph anbinden, abfragen oder seine Daten spiegeln. Nur verlinken.
- Den Importgraph über System32 hinaus ausdehnen, etwa auf `SysWOW64`,
  Treiber oder installierte Programme.
- MCP-Werkzeuge für Agenten.
- Generierte Sigma-Regeln (siehe Ziel 5).
- Schreiben in Aethers Regelverzeichnis.

## Anti-Ziele (Misserfolg, auch wenn es technisch läuft)

- **Jeder EDR-Hook erzeugt einen Befund.** Auf einem Host mit EDR sind Hooks in
  ntdll normal. Zählt TDC sie als Beweis, ist der Score wertlos. Deshalb die
  Trennung nach dem Besitzer des Sprungziels und die Baseline-Unterdrückung.
- **Ein Name oder eine Byte-Folge aus einem Sample landet als HTML oder
  JavaScript im Browser.** Malware bestimmt diese Texte.
- **Die Oberfläche gibt eine kuratierte Kante als abgeleitete aus.** Der letzte
  Sprung von Win32 zu Nt stammt aus einer Tabelle, nicht aus den Daten. Wer das
  verwechselt, zieht aus dem Graphen falsche Schlüsse.
- Die Karte wird zur Tapete: rund 2.000 bunte Zellen ohne Aussage. Ohne Scan muss sie
  ruhig sein, und eine Abweichung muss auffallen.
- Ein Scan oder eine Graph-Abfrage friert das Web-UI ein.
- **Die Detonationsstufe lässt eine Detonation scheitern**, weil NTSleuth fehlt
  oder die Baseline nicht passt. Sie muss sich überspringen.
- Der Zielprozess wird durch die Messung verändert.
- Eine erzeugte Regel landet ungefragt im Regelwerk oder passt nicht zur
  Build-Nummer, für die ihre Syscall-Nummer gilt.
- Die Baseline gehört zu einem anderen Build oder einer anderen Architektur als
  der gemessene Prozess, und niemand merkt es.
- Der Tab ist ohne Netz oder ohne NTSleuth kaputt statt eingeschränkt.

## Rahmenbedingungen

- **Server:** Flask-App `webui/app.py` auf der VM, als SYSTEM über die geplante
  Aufgabe `DetonationChamberUI`. Neue Logik in eigene Module
  (`webui/syscall_scan.py`, `webui/binary_graph.py`), Routen in `app.py`.
- **Frontend:** Vanilla JS in `webui/static/js/app.js`, keine Bibliothek,
  Funktionen auf oberster Ebene. Ein neuer Block `// ===== SYSCALLS =====` und
  ein Zweig in `switchTab`.
- **Zeichnen:** Die Karte als Canvas, wie der Prozessgraph. Der Binary-Graph
  nutzt die vorhandene Canvas-Maschinerie des Graph-Tabs weiter — Kamera,
  `screenToWorld`, `worldToScreen`, `findNodeAt`, `graphFitView`,
  `graphZoomIn|Out`, `applyForceLayout` — mit eigenem Zustandsobjekt, damit
  der Prozessgraph unberührt bleibt. Für geschichtete Pfade ist
  `rizinLayoutGraph` plus `rizinGraphSvg` die fertige Vorlage.
- **Farben** nur als `var(--…)`. Farbwerte nur in `:root` von `style.css`,
  Cyberpunk nur unter `:root[data-theme="cyberpunk"]`. Canvas liest Farben über
  `themeColor()`. Jede Farbe mit Alpha braucht ihre `-rgb`-Variante.
- **Escaping:** Alles aus NTSleuth, aus dem Zielprozess und aus PE-Tabellen wird
  escaped oder als `textContent` gesetzt. Inline-`on*` interpoliert nur `jsArg`
  und `jsInt`. Werte in `class=` gehen über `cssToken()`.
- **Sicherheit:** CSRF- und Host-Header-Schutz gelten auch hier. Pfadeingaben
  gehen durch `_path_within` / `_resolve_within`. Die Wartungssperre
  (`_reject_during_maintenance`) gilt für die neuen POST-Routen.
- **Asset-Versionen** `?v=` in `index.html` bei jeder CSS- oder JS-Änderung
  erhöhen.
- **Prüfung auf der VM** (UTM, 192.168.64.4): beide Themes, bei 1920 und
  1280 px, echte Eingaben über CDP, eigenes Chrome mit frischem Profil, Deploy
  über `scripts/deploy-utm.py`.
- **Lizenzen:** NTSleuth ist BSD-3-Clause und wird als unverändertes Binary
  aufgerufen. WinGraph wird nur verlinkt; von dort kommen keine Daten ins
  Projekt.

## Ansätze

### Der Leser der Stub-Bytes

1. **ctypes im Web-UI-Prozess (gewählt).** Die Flask-App läuft schon als SYSTEM
   auf der VM und ruft dort Werkzeuge auf. Ein Modul mit `OpenProcess`,
   `EnumProcessModulesEx` und `ReadProcessMemory` genügt. Kein neues Binary,
   keine zweite Build-Kette, architekturneutral — Bytes an einer RVA zu lesen
   hat nicht das Problem, das Aether auf ARM64 hat. Mit einem injizierten Leser
   ohne Windows testbar.
   *Kosten:* ctypes-Strukturen müssen auf ARM64 stimmen, und das Lesen muss
   gebündelt werden.
2. **Eigenes Helper-Binary (verworfen).** Ein `tdc-syscalls.exe` über
   `prebuilt/`, nativ und schnell. Kostet aber eine weitere Cross-Compile-Kette,
   ein weiteres gepinntes Binary im Tool-Updater und muss selbst ARM64-korrekt
   bleiben — für etwas, das ctypes auch kann.
3. **Aether erweitern (verworfen).** Der natürliche Ort, aber Aether ist
   Upstream: `build-aether.sh` macht `git reset --hard origin/main`, ein Patch
   wäre bei jedem Update verloren. Dazu läuft Aether auf Apple Silicon emuliert
   als x86_64 und könnte ARM64-Stubs gar nicht korrekt lesen.
4. **Rizin als Leser (verworfen).** Ein Debugger-Attach verändert den Prozess
   (Debug-Port, `BeingDebugged`); die Kammer hält Live-Memory-Werkzeuge bewusst
   nur lesend. Rizin bleibt als Drill-in auf eine Adresse.

### Der Binary-Graph

1. **Lokal nachbauen (gewählt).** Siehe Ziel 6: offline, build- und
   architekturgleich, mit `pefile` auf vorhandener Grundlage, und es verbindet
   sich mit der Syscall-Baseline.
   *Kosten:* Forwarder-Auflösung und die Graph-Abfragen sind eigener Code, und
   die Extraktion über ~4.000 Binaries braucht einen Cache.
2. **WinGraph anbinden (verworfen).** Kein Repo, keine REST-API, nur Server
   Actions; die Kammer müsste online sein, und der fremde Datensatz passt
   weder zu Build noch zu Architektur der VM.
3. **Rizin je Binary fragen (verworfen).** Rizin kann Imports und Exports
   nennen, aber 4.000 Sitzungen sind kein Weg, und Forwarder bekäme man damit
   auch nicht geschenkt.

### Vom Nutzer entschieden

Nach dem Builder-Check lagen drei Fragen vor, die den Umfang ändern. Der Nutzer
hat so entschieden:

1. **Tiefe der Import-Kette: Modulebene plus kuratierte Win32→Nt-Tabelle.**
   Nicht die Disassemblierung der Nt-nahen Exporte, die der Assistent empfohlen
   hatte. Die Kette bleibt damit beweisbar bis `ntdll` und ist im letzten Sprung
   kuratiert. Daraus folgt die Markierungspflicht in Ziel 6 und das Anti-Ziel,
   eine kuratierte Kante nicht als abgeleitete auszugeben.
2. **Der Scanner für Stubs außerhalb von ntdll ist dabei**, nicht in einer
   späteren Phase. Daher Ziel 7a, ein eigener `KINDS`-Eintrag
   (`direct_syscall_stub`) und eine eigene Route.
3. **Der Scan läuft als Stufe einer Detonation**, nicht nur von Hand. Daher
   Ziel 7b mit Stufenliste, `collect()`, VERDICT FLOW, Sweep und
   `_update_preconditions`.

## Gestaltung

- **Vorlage** ist Variante C des Mockups: Karte als Hauptfläche, Detailpanel
  rechts, Abweichungen darunter. Der Umschalter MAP / GRAPH kam auf Wunsch des
  Nutzers hinzu, damit der Graph eine eigene Visualisierung neben der Heatmap
  ist und nicht in ihr aufgeht.
- **Zustandsfarben** folgen den vorhandenen Bedeutungen: intakt in der Farbe für
  „sauber", hooked (dateigedecktes Modul) in der Warnfarbe, gepatcht in der kritischen Farbe, kein
  Stub gedämpft. Sie kommen aus den Theme-Variablen, nicht aus neuen Werten.
- **Dichte der Karte:** Ohne Scan ruhig und gedämpft, damit der Blick nichts
  sucht. Nach einem Scan heben sich Abweichungen deutlich ab, auch einzelne
  Zellen unter rund 2.000.
- **Classic/Telemetry** zeigt denselben Aufbau in den Classic-Variablen.

## Dem Builder überlassen

- Die genaue Zellgröße und Spaltenzahl der Karte, solange die Zellen einer
  Baseline (auf ARM64 rund 2.000; die Tests nehmen 2.461) bei 1920 px lesbar
  bleiben und eine einzelne Abweichung auffällt.
- Wie die Spannen beim Lesen gebündelt werden und wie groß sie sind.
- Das Anordnungsverfahren des Binary-Graphen, solange Pfade ohne Überlappung
  und mit wenigen Kreuzungen lesbar sind.
- Ob der Binary-Graph-Cache als eine Datei oder mehrere liegt, und sein genaues
  Format.
- Die Seitengrößen der Katalog- und Graph-Antworten.
- Wie der Leser für die Tests injiziert wird (Protokoll oder Parameter).
- Ob das Detailpanel die Stub-Bytes selbst zeigt oder in den Hex-Tab springt.
- Die genauen Gewichte innerhalb der in Ziel 5 genannten Größenordnung, mit
  Tests.

## Entscheidungen des Assistenten (zur Prüfung)

- Tabname **SYSCALLS**, mit MAP und GRAPH als Umschalter darin, statt zweier
  Tabs. Beide teilen Filter, Ziel und Detailpanel.
- Die Baseline entsteht beim Provisionieren und ist mit Build-Nummer und Sicht
  gestempelt; bei neuem Build zieht TDC sie neu, ohne Netz mit `--no-symbols`
  und sichtbarem Hinweis.
- Eine Baseline je **Sicht** (ARM64 und x64/EC), nicht je Prozess-Architektur,
  und auf ARM64 werden beide NTSleuth-Binaries installiert. Die Sicht eines
  Prozesses bestimmt `_process_machine(pid)`, nicht `IsWow64Process2` — der Code
  hält schon fest, dass die das auf ARM64 nicht kann.
- Verglichen wird ein Stub-**Präfix** je Architektur, nicht NTSleuths 32-Byte-
  Fenster, weil das in den nächsten Stub hineinreicht.
- Fünf Zustände statt vier: `diverged` für „Bytes weichen ab, und nichts
  unterscheidet Hook von Patch" — kein Sprung, ein nicht auflösbares Ziel oder
  ein direkter Sprung in `ntdll` oder das Modul des Stubs —, damit dieser Fall
  nicht stumm als `intact` durchgeht.
- Der Live-Scan nimmt standardmäßig nur `ntdll`; `win32u` ist zuschaltbar.
- `hooked` gegen `patched` wird am **letzten** Besitzer des Sprungziels
  entschieden, nach höchstens zwei privaten Relays, und dafür kommen
  `VirtualQueryEx` und `GetMappedFileNameW` dazu. Ein überschriebenes Modul
  (Module Stomping) sieht auch diese Abfrage nicht; `hooked` heißt darum
  „dateigedecktes Modul", nicht „EDR-Hook".
- Drei neue `KINDS`-Einträge für die Messung statt eines —
  `syscall_stub_patched`, `syscall_stub_hooked` und `syscall_stub_renumbered` —,
  weil Hook, Patch und ein Stub mit fremder Nummer verschieden wiegen. Dazu
  kommt `direct_syscall_stub` aus Ziel 7a, vom Nutzer entschieden; zusammen
  sind es vier.
- **Kein `baseline_exempt`** — das Flag macht einen Befund immun gegen die
  Baseline. EDR-Hooks werden stattdessen über eine eigene,
  prozessunabhängige Hook-Eigentümer-Liste schon vor dem Scorer gefiltert, weil
  `MemoryFinding` die Prozessidentität in den Schlüssel nimmt und die
  vorhandene Baseline sie darum nie bedecken könnte.
- Regeln nach `webui/syscall_signatures.json` und `rules/yara/`, nicht nach
  Aethers Verzeichnis, und keine Sigma-Regeln.
- Regeln werden nur nach Vorschau übernommen, nie stumm geschrieben, und tragen
  Herkunft, Build und Zeitpunkt. Übernehmen schreibt in das Verzeichnis, aus dem
  Rustinel liest; zusätzlich gibt es die Regel als Datei für das Repo.
- Der Binary-Graph wird lokal erzeugt; WinGraph wird nur verlinkt, wie NTSleuth
  auf `ntdoc.m417z.com` verlinkt.
- Der Graph bleibt auf `C:\Windows\System32` beschränkt.
- Die vorhandene Canvas-Maschinerie des Graph-Tabs wird mit eigenem
  Zustandsobjekt weiterverwendet, statt eine zweite zu schreiben.
- Der Vergleich im Tool-Updater läuft über den Marker, weil das Release ein
  Datums-Tag statt Semver trägt.
