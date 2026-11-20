# Emulation und Patching im RIZIN-Tab

## Absicht

Der RIZIN-Tab ist heute reine statische Analyse. Das war eine bewusste
Entscheidung: `docs/superpowers/specs/2026-11-12-rizin-design.md` führt
„Debugging oder dynamische Analyse mit Rizin" und „Dateien patchen" als
Nicht-Ziele, weil das Web-UI auf der VM als SYSTEM und ohne Login läuft.

Der Nutzer möchte jetzt drei Dinge, die damit nicht gehen:

- **entpackten Code durchlaufen** — eine Entschlüsselungs- oder Entpackroutine
  bis zu ihrem Ergebnis laufen lassen und das Ergebnis lesen;
- **Anti-VM-Checks umgehen** — den Check ausknipsen, und zwar so, dass der
  Patch bleibt, exportiert und detoniert werden kann;
- **Breakpoints setzen**, um an einer bestimmten Stelle anzuhalten und
  weiterzuarbeiten.

**Wer es nutzt:** der Nutzer selbst, im Browser.

**Der Weg dorthin ist rizins ESIL-VM, nicht ein Debugger.** Die Emulation
führt den Code interpretiert aus; es startet nie ein Prozess. Damit bleiben
beide Anti-Ziele des alten Designs gültig: kein Programm startet auf der VM,
und das Original-Sample wird nicht verändert. Patches leben in rizins
`io.cache`, also im Speicher; die Platte bleibt unberührt. Eine *Kopie* mit
den Patches entsteht nur auf ausdrücklichen Export.

**Vom Nutzer entschieden:**

- Oberfläche: **Variante C** — eine Lauf-Zeile über dem Code, die nur im
  Emulationsmodus erscheint, plus ein `EMULATION`-Reiter im Dock für den
  vollen Zustand.
- API-Calls: **Assistenz *und* Eingriff von Hand**, nicht eines von beidem.
- Patches: **bleiben**, sind **exportierbar** und das Ergebnis muss
  **detonierbar** sein.
- Exportiert wird **nur, was von Hand gepatcht wurde** — nicht, was ein
  Emulationslauf in den Speicher geschrieben hat.
- Entschlüsselten Code **neu analysieren** gehört dazu.
- Der API-Assistent deckt **x86-64 und x86-32** ab.
- Bau: **Ansatz 1** (siehe Ansätze).

## Befunde (lokal mit rizin 0.9.1 nachgemessen)

Diese Messungen tragen das ganze Design. Sie liefen gegen rizin 0.9.1
(dieselbe Version, die `install-rizin.ps1` auf die VM bringt) an einem
x86-64-Blob mit einer XOR-Entschlüsselungsschleife und einem `call` ins Leere.

| Befund | Bedeutung fürs Design |
|--------|----------------------|
| Die ganze ESIL-Oberfläche liegt in Familie `a`: `aei`, `aeim`, `aepc`, `aes [N]`, `aeso`, `aess`, `aesu <addr>`, `aesuo <optype>`, `aec`, `aecc`, `aecu`, `aesb` | Die Allowlist erlaubt `a` bereits; Emulation braucht **keine** neue Befehlsfamilie |
| Register: **`ar`**, nicht `dr`. `dr` scheitert mit „Failed to read registers" ohne echte Debug-Sitzung | `ar` lesen, `ar rax=0x41` schreiben |
| `aesu 0x19` lief die ganze Schleife und hielt genau dort | „Laufen bis Adresse" ist ein nativer Befehl |
| `px 8 @ 0x1000` zeigte nach dem Lauf die **entschlüsselten** Bytes | HEX und DISASSEMBLY zeigen das Ergebnis von allein — keine neue Plumbing-Schicht. **FUNCTIONS und STRINGS nicht:** die baut rizin beim Laden aus den Sektionen (siehe §7) |
| **Ohne `io.cache=true` sind die Schreibzugriffe verloren** (`px` zeigte weiter das Original) | `io.cache=true` ist für die Emulation *zwingend*, nicht optional. Emulation und Patching hängen am selben Mechanismus |
| SHA-256 der Datei vor und nach dem Lauf **identisch** | Das Anti-Ziel „Sample wird auf der Platte verändert" hält |
| `wcj` liefert pro **Schreibvorgang** eine Zeile (nicht pro Byte): `wx 9090 @ 0x0e` gibt eine mit `size 2`, `before 8036`, `after 9090`, vier Einzelbyte-Schreibvorgänge geben vier | Die Patch-Ansicht zeigt Schreibvorgänge, und die Zeilen tragen `size` samt vollem Hex in `before`/`after` |
| `wc-` **löscht blockweise, nicht einzeln**: nach Patches auf 0x100, 0x180 und 0x300 entfernte `wc- 0x100` auch den bei 0x180 (der ganze 0x100-Block), 0x300 blieb. Die Bereichsform `wc- 0x100 0x101` trifft genau einen | Einen Patch zurücknehmen heißt `wc- <addr> <addr+1>`. Mit `wc- <addr>` allein hätte das Zurücknehmen eines Patches bis zu 255 fremde Bytes stumm mitgelöscht |
| `wc-*` setzt alles zurück | Alles zurücknehmen ist nativ |
| **`wcj` ist in 0.9.1 kein gültiges JSON**: kommagetrennte Objekte ohne umschließende `[ ]` | Die Liste wird als Text gelesen und selbst geparst, nicht mit `cmdj` *(Korrektur: eine frühere Messung notierte „als JSON", obwohl ihre eigene Ausgabe die Klammern schon nicht zeigte)* |
| `pdj` nennt kein `mnemonic` | Die Patch-Bytes werden aus `size`, `bytes` und `type` berechnet |
| `db @ <addr>` setzt, `dblj` listet als JSON (`addr`, `enabled`, `cond`, `hw`), `aec` hält an: `[ESIL] hit breakpoint at 0x14` | Echte Breakpoints, vom ESIL-Motor beachtet. `db` **ohne** `@` nimmt kein Argument |
| `aec` von einem Breakpoint aus läuft **weiter**, er trifft ihn nicht erneut: Haltepunkt auf 0x19 (einmal erreicht), das erste `aec` hält dort, das zweite läuft bis `esil.timeout`. rizin prüft Breakpoints *nach* dem Befehl | **Kein Step-off nötig.** *(Korrektur einer früheren Messung, die den Haltepunkt mitten in eine vierfache Schleife setzte und die vier Durchläufe als vier Treffer derselben Stelle las.)* |
| `dbd` verhindert das Anhalten **nicht** — nur `db-` entfernt einen Breakpoint wirksam | Ein ausgeschalteter Breakpoint hält trotzdem: die Oberfläche bietet kein „aus" an, oder löst es über `db-` |
| `aecc` läuft über `call qword [import]` (Typ `ircall`) **hinweg** und ignoriert `esil.timeout`: ohne Call lief es über 15 s | `aecc` ist unbrauchbar. „Bis zum nächsten Call" baut der Server aus `aesu`-Sprüngen, begrenzt durch `ESIL_TIMEOUT` |
| `aess` und `aeso` behandeln `ircall` ebenfalls falsch und laufen in den Aufgerufenen hinein | Bei einem `ircall` setzt der Server den PC selbst: `aepc` für SKIP, `aesu <pc+size>` für OVER |
| `esil.exectrap` vor `aei` gesetzt wirkt nicht | Die Schutzschalter werden vor jedem Lauf erneut gesetzt |
| Ohne `esil.verbose=1` hält ein I/O-Trap `aec` **stumm** an | `esil.verbose=1` gehört zu den Startwerten, sonst nennt kein Lauf diesen Grund |
| `aesb` stellt Register wieder her, **aber nicht den Speicher**. Der Schritt danach **führt den Befehl aus, ohne den PC zu bewegen**: nach `aesb` auf 0x7 lief `aes` den `xor` erneut (rsi änderte sich, rip blieb 0x7), ein weiteres `aes` noch einmal | **BACK fällt ganz weg** (R20). Ein Rückwärtsschritt, der den Speicher nicht zurücknimmt und dessen Folgeschritt die Entschlüsselung doppelt anwendet, ist keine Funktion, sondern eine Falle |
| `aess` übersprang den `call` (rip 0x1a → 0x1f) | So kommt man an einem API-Call vorbei |
| `aes` *in* einen `call` auf nicht gemappten Speicher läuft **stumm weiter** und „emuliert" Nullen | Ohne Schutz lügt die Oberfläche; siehe die nächsten zwei Zeilen |
| `esil.breakoninvalid`, `esil.exectrap`, `esil.iotrap`, `esil.nonull` | Damit **hält** die Emulation an, statt ins Nichts zu laufen |
| `esil.timeout=3` beendete ein `jmp $` nach 3,02 s mit „esil: timeout exceeded", rizin lebte weiter | Native Endlosschleifen-Sicherung — der Server braucht keine eigene Schrittzähler-Schleife |
| `aets+` startet die Trace-Sitzung, die `aesb` braucht | Nur noch Hintergrund: BACK fällt weg (siehe die Zeile oben) |
| **`esil.verbose=1` flutet stderr**: ein `int3`/`int N` druckt `WARNING: $ returned 0` je Ausführung — 148 025 Zeilen in einer Sekunde gemessen. `_stderr_until` behält die **ersten** 64 KB, also fiel die abschließende `timeout exceeded`-Zeile heraus und der Lauf meldete „step" | Der Haltegrund wird am **Ende** von stderr gesucht, nicht am Anfang. `int3`-Schleifen sind Standard-Anti-Debug in genau diesen Samples |
| **`dbw` (Watchpoint) + `aec` hängt rizin endlos** (im `timeout` gestorben) | Watchpoints bleiben draußen |
| **`Ps` speichert den Patch-Cache nicht** (nur `io.cache=true` landete im Projekt, keine Bytes) | TDC muss Patches selbst behalten |
| **rizin 0.9.1 hat kein `wt`/`wtf`** (nur `wu`, `wf` — beide lesen Dateien) | Der Export entsteht in Python |
| `aepc <addr>` wird von der heutigen Allowlist-Regel `aep` fälschlich mitgeblockt | Fehlalarm, der zu beheben ist |
| `esil.romem` und `io.cache` sind beide standardmäßig `false` | Die Startwerte stimmen; der Server setzt beide bewusst |
| `af @ <addr>` analysiert die Funktion dort und folgt den Calls; `/zj` sucht Strings in einem Bereich. **Beide passieren die heutige Allowlist bereits** | Die Neuanalyse eines entschlüsselten Bereichs braucht keine Öffnung (nur `aa*` ist gesperrt, und das zu Recht) |
| `dbg.backend` kennt kein `esil` (nur bochs, dmp, gdb, io, native, null, qnx, winkd) | Es gibt keinen Weg, die `d`-Familie versehentlich auf die Emulation umzubiegen — und keinen Grund, sie zu öffnen |
| Es gibt **keine Möglichkeit, einen laufenden Befehl abzubrechen** (so schon im Design von 2026-11-12: rizin bräuchte dafür unter Windows ein Konsolensignal) | **STOP** kann einen laufenden `aec` nicht unterbrechen; es verlässt den Emulationsmodus. `esil.timeout` begrenzt den Lauf stattdessen |

## Ziele

### 1. Emulationsmodus im RIZIN-Tab

- Ein Knopf in der Werkzeugleiste startet die Emulation für die offene Datei.
  Er setzt `io.cache=true`, die `esil.*`-Schutzschalter, `aei`, `aeim` und
  `aepc` auf die aktuelle Adresse.
- **Lauf-Zeile**, die *nur* im Emulationsmodus über dem Code erscheint:
  - **CONT**, **STEP**, **OVER**, **SKIP**, **TO CALL**, **STOP**;
  - der PC;
  - die Register, die der **letzte Schritt verändert hat** — beim Steppen
    zählt, was sich bewegt hat, nicht achtzehn unveränderte Werte.
- **STOP verlässt den Emulationsmodus**, es bricht keinen laufenden Befehl ab.
  Das kann rizin unter Windows nicht (siehe Befunde), und mit `esil.timeout`
  endet ein Lauf ohnehin nach wenigen Sekunden von selbst. Die Oberfläche darf
  deshalb kein Abbrechen versprechen.
- **Es gibt kein BACK.** `aesb` stellt den Speicher nicht zurück, und der
  Schritt danach führt den Befehl erneut aus, ohne den PC zu bewegen — auf
  einer Entschlüsselungsschleife würde das den `xor` doppelt anwenden und
  dabei einen sauberen Zustand melden (beides gemessen). Die Lauf-Zeile trägt
  also **CONT, STEP, OVER, SKIP, TO CALL, STOP** und keinen Rückwärtsschritt.
- **Laufen bis hierher**: Im Rechtsklick-Menü der Disassembly, über
  `aesu <addr>` — der natürliche Partner der Breakpoints.
- **PC-Markierung** in der Disassembly (eigene Markierung, deutlich von der
  heutigen „aktuellen Zeile" unterschieden), und der Block des PC im Graph.
- Die Ansichten folgen dem PC: ein Schritt bewegt DISASSEMBLY, GRAPH,
  DECOMPILER und HEX mit. Das Prinzip „ein Ort überall" aus dem alten Design
  bleibt damit erhalten; der PC *ist* der aktuelle Ort.
- Der Nutzer kann weiterhin frei woanders hinspringen; der PC bleibt dabei
  stehen und ist als Markierung weiter sichtbar. Ein Knopf **GO TO PC** holt
  ihn zurück.
- **Angehalten, und warum:** Die Lauf-Zeile sagt immer, weshalb die Emulation
  steht — Breakpoint, Schritt fertig, `esil.timeout`, ungültiger Befehl,
  ungültiger Speicherzugriff oder Sprung in nicht ausführbaren Speicher. Nie
  nur „fertig".

### 2. Der `EMULATION`-Reiter im Dock

Neben CONSOLE, XREFS, STRINGS und IMPORTS, mit dem vollen Zustand:

- **Register**, alle, mit dem geänderten hervorgehoben; jeder Wert direkt
  editierbar (→ `ar <name>=<wert>`).
- **Stack**, ab dem Stackzeiger (`rsp` bzw. `esp`) abwärts, mit Adresse, Wert
  und — wo es passt — dem Hinweis, dass der Wert auf eine bekannte Funktion
  oder einen String zeigt.
- **Breakpoints**, als Liste mit Adresse, Funktion und Löschen — ohne „an/aus",
  weil `dbd` das Anhalten nicht verhindert (gemessen, siehe Befunde).
- **Patches**, als Liste mit Adresse, before/after, einzeln zurücknehmen,
  und den Knöpfen **Export** und **Alle zurücknehmen**.

### 3. Breakpoints

- Ein Klick in die Randspalte der Disassembly setzt und entfernt einen.
- Server: `db @ <addr>`, `db- @ <addr>`, `db-*`, `dbl`/`dblj` zum Lesen.
- **Kein An- und Ausschalten.** `dbd` verhindert das Anhalten nicht
  (gemessen), also gibt es in der Oberfläche kein „aus": ein Breakpoint ist
  gesetzt oder entfernt.
- **CONT ist ein einfaches `aec`.** Ein Step-off davor braucht es nicht:
  rizin prüft Breakpoints nach dem Befehl, also läuft `aec` von einem
  Haltepunkt aus weiter (gemessen; eine frühere Messung hatte das Gegenteil
  behauptet, weil ihr Haltepunkt in einer Schleife lag).
- **TO CALL baut der Server selbst**, aus `aesu`-Sprüngen über `pdj`, begrenzt
  durch `ESIL_TIMEOUT`. `aecc` ist unbrauchbar: es läuft über einen
  `call qword [import]` hinweg und ignoriert `esil.timeout` (über 15 s
  gemessen), was die Sitzung beenden würde.
- Breakpoints **bleiben** wie die Patches (siehe 5).
- **Keine Watchpoints** (`dbw` hängt rizin, gemessen).
- **Kein** `dbc`, `dbC`, `dbx` — sie führen rizin-Befehle aus, wenn ein
  Breakpoint trifft. Das ist dieselbe Gefahr wie die `cmd.*`-Hooks, die das
  heutige Design beim Laden eines Projekts schon zurücksetzt.

### 4. Der API-Assistent

Das ist der Kern des Entpack-Ziels. ESIL emuliert **keine Windows-API**. Ein
`aes` in einen `call` auf `VirtualAlloc` läuft stumm in nicht gemappten
Speicher weiter — gemessen. Der Assistent macht aus diesem Loch einen
bedienbaren Schritt:

- Steht der PC auf einem `call`, dessen Ziel ein Import ist, zeigt die Zeile
  **vorab, was passieren wird**, z. B. `; skip → rax = 0x140008000 (neuer
  Puffer, 64 KB)`.
- **SKIP** führt es aus: `aess`, dann `ar <ret>=<wert>`, bei Speicher-APIs
  zusätzlich ein `aeim <addr> <size> <name>` für den Puffer.
- **Jeder angebotene Wert ist editierbar**, bevor er angewandt wird, und ein
  Register lässt sich jederzeit im `EMULATION`-Reiter von Hand setzen. Das ist
  das „beides", das der Nutzer wollte: Vorschlag **und** Eingriff.
- **Abgedeckt sind x86-64 und x86-32.** Das ist keine Kleinigkeit und nicht
  symmetrisch:
  - Unter **x86-64** (Microsoft-x64) stehen die ersten Argumente in `rcx`,
    `rdx`, `r8`, `r9`, der Rückgabewert in `rax`. Der Aufrufer räumt den Stack.
  - Unter **x86-32 stdcall** — die Konvention der Win32-API — stehen die
    Argumente **auf dem Stack**, und der *Aufgerufene* räumt sie ab. Ein
    `aess` über so einen Call räumt nichts: der Stack bleibt um die Argumente
    zu tief, und jeder weitere Schritt rechnet daneben. **SKIP muss den Stack
    also selbst korrigieren** (`esp` um die Argumentbytes erhöhen), und dazu
    muss die Tabelle pro API ihre Argumentzahl kennen. `cdecl`-Importe
    (`memcpy` und Freunde aus der CRT) räumt dagegen der Aufrufer, dort darf
    nicht korrigiert werden.
  - Die Argumente selbst liest der Assistent entsprechend aus Registern oder
    vom Stack — er braucht sie für die Puffergröße, den Namen bei
    `GetProcAddress` und die drei Werte von `memcpy`.
  - Eine Datei mit einer anderen Architektur (ARM, ein Dump mit gemischtem
    Code) schaltet den Assistenten **ab**: er bietet nichts an und sagt das.
    Emulation, Breakpoints und Patchen funktionieren dort weiter. Lieber
    nichts anbieten als falsch raten — das ist das Anti-Ziel „die Oberfläche
    lügt".
- Die Tabelle deckt die Gruppen ab, die beim Entpacken und bei Anti-VM
  vorkommen:

  | Gruppe | Beispiele | Angebotene Antwort |
  |--------|-----------|--------------------|
  | Speicher | `VirtualAlloc`, `VirtualAllocEx`, `HeapAlloc`, `LocalAlloc`, `GlobalAlloc`, `malloc` | Ein frisch gemappter Puffer in der ESIL-Speicherkarte, seine Adresse im Rückgaberegister |
  | Speicherschutz | `VirtualProtect` | Erfolg; die Karte bleibt beschreibbar |
  | Loader | `LoadLibraryA/W`, `GetModuleHandleA/W`, `GetProcAddress` | Ein Pseudo-Handle bzw. die Adresse des Imports, wenn die Datei ihn kennt, sonst eine erkennbare Pseudo-Adresse |
  | Anti-Debug | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` | „nicht beobachtet" |
  | Zeit | `GetTickCount`, `GetTickCount64`, `QueryPerformanceCounter`, `GetSystemTimeAsFileTime` | Ein plausibel steigender Wert, so dass Zeitmessungen keinen Debugger vermuten |
  | Umgebung | `GetComputerNameA/W`, `GetUserNameA/W`, `GetVolumeInformation` | Unauffällige Werte, keine VM-Artefakte |
  | Kopieren | `memcpy`, `memmove`, `RtlMoveMemory` | Kopiert in der ESIL-Speicherkarte wirklich, damit entpackte Daten entstehen |

- **Haltung der Tabelle:** Sie antwortet wie eine **saubere, nicht analysierte
  Maschine**. Genau das ist die Umgehung der Anti-VM-Checks, ohne dass etwas
  gepatcht werden muss — und wer den Patch *dauerhaft* will, patcht zusätzlich
  (siehe 5).
- Was die Tabelle nicht kennt, sagt sie: der Import wird genannt, `SKIP` lässt
  das Rückgaberegister unverändert, und das Feld steht zum Eintippen bereit.

### 5. Patching

- **Nur Bytes.** Die Oberfläche schreibt `wx`. Assemblieren (`wa`) bleibt
  draußen, weil rizin es an nasm oder as übergeben kann — das weist das alte
  Design ab, und der Grund gilt weiter.
- Für die Fälle, die beim Anti-VM zählen, gibt es **Knöpfe statt Hex-Tippen**,
  die intern Bytes schreiben. Sie sitzen im **Rechtsklick-Menü der
  Disassembly**, neben „Rename function…" und „Comment…", und wirken auf
  **den Befehl unter dem Zeiger** — DISASSEMBLY hat heute keine Auswahl, und
  eine einzuführen wäre eine eigene Oberfläche, die Variante C nicht verlangt:
  - **NOP ausfüllen** — den Befehl mit `nop` seiner Länge überschreiben;
  - **Sprung umdrehen** — `jz` ↔ `jnz`, `je` ↔ `jne` und die übrigen Paare;
  - **Sprung immer nehmen** — bedingten Sprung zu `jmp`;
  - **Call ausknipsen** — den `call` zu `nop`s, Länge erhalten.
  Dazu ein Feld für Bytes von Hand, das auch über mehrere Befehle reicht.
- **Patch-Liste** aus `wcj`: Adresse, Größe, before, after, die Funktion
  dazu. Einzeln zurücknehmen (`wc- <addr> <addr+1>` — die Bereichsform, weil
  `wc- <addr>` allein einen ganzen 0x100-Block löscht), alle (`wc-*`).
- Patches und Emulations-Schreibzugriffe landen **im selben Cache** — rizin
  hat nur einen. Die Liste **muss deshalb beide auseinanderhalten**: TDC kennt
  die Adressen seiner eigenen `wx`-Aufrufe, alles andere im Cache kommt vom
  Lauf. Die Unterscheidung ist nicht kosmetisch, sie entscheidet darüber, was
  exportiert wird und was bleibt (§6 und §8).
- Dass ein Lauf Bytes ändert, ist dabei ein *Feature*: nach einer
  Entschlüsselung lässt sich der entpackte Bereich neu analysieren (§7).
- **Die Originaldatei wird nie geschrieben.** `wci` und `wc+` (Cache
  committen) bleiben verboten — auch und besonders in der Konsole.

### 6. Was bleibt und was nicht

- **Von Hand gesetzte Patches und Breakpoints bleiben.** Sie werden im
  **`/tdc`-Namensraum des rizin-Projekts** gespeichert, dort, wo heute schon
  `level`, `mode` und `done` stehen (`_sanitize_project`). Das rizin-Projekt
  selbst speichert den Cache nicht — gemessen.
- Beim Öffnen derselben Datei werden sie mit `wx` bzw. `db` wieder angewandt,
  bevor die Ansichten laden.
- Ein Projekt entsteht damit künftig auch durch einen Patch oder einen
  Breakpoint, nicht mehr nur durch Umbenennen oder Kommentieren.
- **Was ein Emulationslauf geschrieben hat, bleibt nicht.** Es gehört zum
  Lauf, nicht zur Datei, und es ist kein Byte, das jemals in der Datei stand —
  es still wieder einzubacken würde das Anti-Ziel brechen, den Überblick zu
  verlieren, welche Bytes woher kommen. Dazu käme, dass
  `_read_project_meta` nur die letzten 64 KB des Projekts liest; der Cache
  eines XOR-Laufs über eine Sektion würde das wortlos sprengen.
- **Die Oberfläche muss das sagen**, bevor es wehtut: Wer eine halbe Stunde
  lang entpackt hat, darf nicht beim Schließen überrascht werden. Der
  `EMULATION`-Reiter trennt die beiden Gruppen sichtbar und nennt bei den
  Lauf-Bytes, dass sie mit der Sitzung enden.
- **Der Emulationszustand selbst bleibt auch nicht** — Register, Stack und PC
  gehören zum Lauf. Eine Sitzung, die neu startet, beginnt mit angewandten
  Patches und gesetzten Breakpoints, aber ohne laufende Emulation.

### 7. Entschlüsselten Code lesbar machen

Nach einem Lauf zeigen HEX und DISASSEMBLY die entschlüsselten Bytes von
allein — `px` liest durch den Cache (gemessen). **FUNCTIONS und STRINGS nicht:**
die baut rizin beim Laden aus den Sektionen der Datei. Ohne diesen Schritt
endet das Entpacken mit Bytes, die man nicht als Code liest — und damit würde
das Hauptziel auf halbem Weg stehen bleiben.

- Ein Knopf **analysiert den Bereich neu**, den der Lauf verändert hat (seine
  Grenzen kennt TDC aus der Lauf-Gruppe der Patch-Liste):
  - `af @ <addr>` analysiert die Funktion dort und folgt den Calls;
  - `/zj` sucht die Strings im Bereich.
- **Beide passieren die heutige Allowlist bereits** (gemessen) — nur die
  `aa*`-Befehle sind gesperrt, und das bleibt so: eine ganze Neuanalyse
  gehört weiter hinter den Full-analysis-Knopf.
- Danach entwertet der Server die betroffenen Caches
  (`_rizin_forget(session)`), damit FUNCTIONS, STRINGS und die Tab-Ergänzung
  der Konsole die neuen Namen zeigen.
- Die so gefundenen Funktionen und Strings gehören zum Lauf. Sie sind nach
  einem `wc-*` oder einer neuen Sitzung wieder weg, wie die Bytes, auf denen
  sie beruhen.

### 8. Export und Detonation

- **Exportiert werden nur die von Hand gesetzten Patches.** Die Kopie ist das
  Original mit den bewussten Änderungen — nichts, was ein Lauf geschrieben
  hat. Damit ist die Kopie klein, nachvollziehbar und immer erklärbar.
- **Export** legt sie neben die Uploads (`%TEMP%\rizin_uploads`), mit einem
  Namen, der sie als gepatcht erkennbar macht, und einer Notiz daneben:
  SHA-256 von Original und Kopie, Pfad des Originals, Zeit, und die
  Patch-Liste mit before/after.
- **Gebaut wird die Kopie in Python**, nicht von rizin: Original kopieren,
  dann die Patch-Bytes an ihren **physischen** Offsets setzen. Die
  Umrechnung von virtueller auf Datei-Adresse gibt es schon
  (`_rizin_paddr`, `ol.j` + `oml.j`). rizin schreibt dabei keine Datei.
- Ein Patch, der auf keinen Datei-Offset zeigt — von Hand gesetzt in einem
  Puffer, den erst die Emulation angelegt hat —, **kann nicht exportiert
  werden**. Der Export nennt die betroffenen Adressen und schreibt die
  übrigen, statt still etwas Falsches zu erzeugen.
- **Detonation:** Ein Knopf übergibt die Kopie dem **Submit-Tab**, mit der
  Datei vorbelegt; dort wählt der Nutzer das Ziel (Agent, LitterBox, beides)
  und löst aus. `/api/submit` nimmt heute nur ein Multipart-`file` und keinen
  Pfad — und das bleibt so: eine Route, die eine Datei **nach Pfad** auf der
  VM ausführt, wäre eine neue Fähigkeit des Web-UIs und das Gegenteil von
  „der RIZIN-Tab wird kein eigener Starter".
- Die gepatchte Kopie taucht im Submit-Verlauf so auf, dass sie vom Original
  unterscheidbar ist.

### 9. Schutzschalter

Beim Start der Emulation **und vor jedem Lauf** setzt der Server:

| Einstellung | Wert | Wofür |
|-------------|------|-------|
| `io.cache` | `true` | Ohne sie sind die Schreibzugriffe verloren (gemessen) |
| `esil.timeout` | ein paar Sekunden | Endlosschleife beendet den Lauf, nicht die Sitzung (gemessen: 3 s → 3,02 s) |
| `esil.breakoninvalid` | `true` | Hält an einem ungültigen Befehl, statt Nullen zu emulieren |
| `esil.exectrap` | `true` | Hält, wenn der PC in nicht ausführbaren Speicher läuft |
| `esil.iotrap` | `true` | Hält bei ungültigem Lesen oder Schreiben |
| `esil.nonull` | `true` | Hält beim Nullzeiger, statt weiterzulaufen |
| `esil.verbose` | `1` | Ohne sie hält ein I/O-Trap `aec` **stumm** an (gemessen), und der Lauf könnte seinen Grund nicht nennen |
| `esil.romem` | `false` | Sonst könnte die Emulation nichts entschlüsseln |

`esil.mdev.range` bleibt unberührt: es hängt an `cmd.esil.mdev`, das
rizin-Befehle ausführt und wie die übrigen `cmd.*`-Hooks leer bleibt.

Vor **jedem** Lauf erneut, nicht nur beim Start: `esil.exectrap` wirkt nicht,
wenn es vor `aei` gesetzt wurde (gemessen), und die Konsole kann `io.cache`
jederzeit abschalten — ein Lauf ohne sie schreibt nichts und sähe aus, als
täte die Entschlüsselung nichts.

### 10. Konsole und Allowlist

Die Server-Routen bauen ihre Befehle selbst und gehen **nicht** durch
`check_console_command` — der Filter schützt nur die Konsole. Für das Feature
ist also keine Öffnung nötig. Trotzdem soll die Konsole mitkommen, damit man
weiterarbeiten kann, wo die Oberfläche aufhört:

- **Schon heute erlaubt, nichts zu tun** (gemessen): die `ae*`-Lauf- und
  Schrittbefehle (`aei`, `aeim`, `aes`, `aeso`, `aess`, `aesu`, `aesuo`,
  `aec`, `aecc`, `aets+`, `aesb`), `ar` zum Lesen und Setzen, und die
  Neuanalyse mit `af` und `/zj`.
- **Neu zu erlauben:** die Schreibbefehle, die in den Cache gehen (`wx`,
  `wo`, `wz`, `w`), die Cache-Befehle `wc` und `wc-`, die Breakpoint-*Liste*
  (`db`, `db-`, `dbl`, `dbd`, `dbe`, `dbs`, `dbn`), und `esil.*` sowie
  `io.cache` unter den setzbaren Einstellungen.
- **Weiter verboten:** `wci` und `wc+` (schreiben in die Datei), `wa`
  (assemblieren), `wu`/`wf` (lesen Dateien), `dbc`/`dbC`/`dbx` (führen
  rizin-Befehle aus, wenn ein Breakpoint trifft — dieselbe Gefahr wie die
  `cmd.*`-Hooks), `dbw` (hängt rizin, gemessen), `aa*` (ganze Neuanalysen
  gehören hinter den Knopf), und die ganze übrige `d`-Familie, also alles, was
  einen Prozess startet oder sich an einen hängt (`ood`, `dp`, `dc`, `ds`,
  `dm`, `dk`, `dd`, `dbt` …).
- **Fehlalarm beheben:** `aepc` ist heute von der `aep`-Regel mitgeblockt.
  `aep*` (ESIL-Pin-Befehle) bleibt verboten, `aepc` wird erlaubt.
- Die Tabelle „Console without a shell" im README wird entsprechend
  umgeschrieben: aus „kein Schreiben, kein Debugging" wird „kein Schreiben in
  die Datei, kein echtes Debugging, Emulation ja".

### 11. Doku

- README: die Tab-Tabelle, ein Abschnitt zu Emulation und Patching, die neuen
  API-Zeilen, die umgeschriebene Allowlist-Tabelle, der Sicherheitsabschnitt,
  und die Zeile unter „Limitations", die heute „Static analysis only: no
  debugging, no patching" sagt.
- Die `(i)`-Texte und die Hilfe im Tab.
- Ein Screenshot wie die übrigen.

## Nicht-Ziele

- **Echtes natives Debugging.** Kein `ood`, kein Anhängen an einen Prozess,
  keine `d`-Befehle, die etwas ausführen. Samples laufen weiter über die
  Detonation von TDC.
- **Einen laufenden Befehl abbrechen.** Geht nicht (siehe Befunde);
  `esil.timeout` begrenzt stattdessen.
- **Watchpoints** (`dbw` hängt rizin, gemessen).
- **Assemblieren** (`wa`), weil rizin es an ein externes Programm übergeben
  kann. Die Knöpfe für NOP und Sprung-Umdrehen schreiben Bytes.
- **Den Cache in die Originaldatei committen** (`wci`, `wc+`).
- **Was ein Emulationslauf geschrieben hat, exportieren oder behalten.** Die
  entschlüsselten Bytes sind im Tab lesbar und analysierbar (§7), aber sie
  verlassen ihn nicht als Datei und überleben die Sitzung nicht.
- **Einen entschlüsselten Puffer als eigene Datei herausschreiben**
  (Stage-2-Dump). Für ein vollständiges entpacktes Abbild bleibt der Weg,
  den TDC schon hat: detonieren, Process Dump, den Dump im RIZIN-Tab öffnen.
- **Eine Auswahl über mehrere Befehle in der Disassembly.** Die Patch-Knöpfe
  wirken auf einen Befehl; für mehr gibt es das Byte-Feld.
- **Eine Route, die eine Datei nach Pfad detoniert.** Der Export geht durch
  den Submit-Tab.
- **Windows-API-Semantik über die Tabelle hinaus.** Kein Nachbau von Dateien,
  Registry, Netzwerk oder Threads. Wo die Tabelle nicht trägt, greift der
  Nutzer ein.
- **Andere Architekturen als x86-64 und x86-32 im Assistenten.** Dort schaltet
  er ab; Emulation, Breakpoints und Patchen bleiben nutzbar.
- **Den Emulationszustand im Projekt speichern.** Nur die von Hand gesetzten
  Patches und die Breakpoints bleiben.
- **Eine Trace-Ansicht.** `aesb` geht einen Schritt zurück; eine
  Ausführungshistorie zum Durchblättern ist nicht Teil davon.
- **MCP-Werkzeuge** für Agenten.
- **Mehrere Emulationen** in einer Sitzung.

## Anti-Ziele (Misserfolg, auch wenn es technisch läuft)

- Das Original-Sample wird auf der Platte verändert.
- Über die Konsole startet ein Programm auf der VM oder wird eine Datei
  geschrieben. Das Web-UI läuft als SYSTEM und hat keinen Login.
- Ein Lauf friert das Web-UI ein oder tötet die Sitzung. `esil.timeout` muss
  deutlich unter dem Zeitlimit der Pipe liegen.
- Eine gepatchte Kopie ist später nicht mehr vom Original zu unterscheiden,
  oder man weiß nicht, was an ihr geändert wurde.
- **Die Oberfläche lügt:** Die Emulation ist nach einem übersprungenen Call
  ins Nichts gelaufen, aber Register und Speicher werden weiter als Ergebnis
  gezeigt. Deshalb die Trap-Schalter und das verpflichtende „warum
  angehalten".
- Man verliert den Überblick, welche Bytes aus der Datei kommen und welche der
  Lauf oder ein Patch geschrieben hat.
- Der Tab wird gedrungen. Die Lauf-Zeile darf bei 1920 px nicht die Hälfte
  der Werkzeugleiste fressen und muss bei 1280 px noch lesbar sein.

## Rahmenbedingungen

- **Server:** `webui/rizin_sessions.py` und die Routen unter `/api/rizin/...`
  in `webui/app.py`, nach dem dortigen Muster: `_rizin_call(sid, view)` für
  die Fehlerabbildung, `_rizin_body()` und `_rizin_address()` für die
  Eingaben, `_rizin_forget(session)` wo ein Schritt die Caches entwertet.
- Jeder neue Routenname, der die Pipe **nicht** anfasst, muss zusätzlich in
  `rizinUsesPipe()` im Frontend eingetragen werden.
- **Frontend:** Vanilla JS in `webui/static/js/app.js`, Funktionen auf
  oberster Ebene, Namenspräfix `rizin`, Konstanten `RIZIN_`. Der Dreiklang
  pro Ansicht gilt: `rizinXHtml()` → `rizinLoadX(force)` →
  `rizinRenderX()`, dazu `rizinXHolds()` und `rizinOnXClick()`. Jede neue
  Funktion und Konstante muss in `RIZIN_FUNCTIONS` bzw. `RIZIN_CONSTS` in
  `tests/test_rizin_ui.py` eingetragen werden, sonst scheitert
  `test_rizin_lists_cover_the_block`. Jeder neue Zustand muss in
  `rizinReset()` gelöscht werden.
- Neue Ansichten, die dem Ort folgen sollen, gehören in `RIZIN_VIEWS`.
- **Farben:** nur `var(--…)`, Werte nur in `:root` von `style.css`,
  Cyberpunk-Regeln nur unter dem Theme-Selektor in `theme-layout.css`. Jede
  neue Regel braucht ihr Gegenstück im Layout-Sheet.
- **Escaping:** Alles aus rizin wird escaped oder als `textContent` gesetzt.
  Register- und Speicherwerte sind Zahlen, aber Import- und Funktionsnamen
  kommen aus der Datei und sind feindlich.
- **Adressen** sind im Browser immer `"0x…"`-Strings, nie JS-Zahlen.
- **Asset-Versionen** in `index.html` bei jeder CSS- und JS-Änderung erhöhen.
- **Sicherheit:** CSRF- und Host-Schutz gelten für die neuen Routen
  automatisch; die neuen POST-Routen fallen damit auch unter die
  Wartungssperre bei Tool-Updates.
- **Tests:** Die CI kennt kein rizin. `tests/fake_rizin.py` muss die neuen
  Befehle beantworten (`aei`, `aeim`, `aepc`, `aes`, `aeso`, `aess`, `aesu`,
  `aec`, `aecc`, `aesb`, `ar`, `db`, `dblj`, `wx`, `wcj`, `wc-`, `af`,
  `/zj`), mitsamt den gemessenen Eigenheiten: `aec` trifft denselben
  Breakpoint wieder, ein `aes` in nicht gemappten Speicher läuft weiter,
  `esil.timeout` greift, und ohne `io.cache` ist ein Schreibzugriff verloren.
  Ein 32-bit-Modus gehört dazu, sonst ist die Stack-Korrektur ungetestet.
  Die Filter-Tests brauchen neue Angriffs-Eingaben für die geöffneten
  Familien, besonders für `wci`, `wc+`, `wa`, `dbc`, `dbC`, `dbx` und `dbw`.
  Frontend über `_run_node` und den `SCRIPTED`-Harness; `serve()` dort
  braucht die neuen Routen. Die README-Tabellen-Tests in
  `tests/test_docs.py` greifen auch für die neuen Zeilen.
- **Prüfung auf der VM** (UTM), beide Themes, bei 1920 und 1280 px, mit
  `scripts/deploy-utm.py`. `webui/rizin_sessions.py` steht schon in der
  Dateiliste von `deploy-utm.py`.

## Ansätze

1. **Emulation als Ansicht, dünner Server (gewählt).**
   - Jede Route ist eine kurze Befehlsfolge gegen die Pipe, genau wie `pdfj`
     oder `afl` heute. Der Zustand wird jedes Mal aus rizin gelesen: `ar`,
     `dblj`, `wcj`. Die Lauf-Befehle gehen durchs bestehende `_Gate`.
   - Möglich ist das nur, weil `esil.timeout` den Lauf **nativ** begrenzt
     (gemessen). Der Server braucht keine eigene Schrittzähler-Schleife.
   - *Kosten:* Ein CONT ist eine blockierende Anfrage bis zu `esil.timeout`;
     Ansichten sagen währenddessen „busy", wie bei einem Analyseschritt. Das
     ist bestehendes, dem Nutzer bekanntes Verhalten.
   - *Dafür:* keine zweite Zustandsmaschine, keine zweite Instanz, die die
     Pipe hält, und der bestehende Test-Harness trägt es direkt.
2. **Eigener Lauf mit Thread (verworfen).** Ein `Emulation`-Objekt in der
   Sitzung mit PC, Breakpoints, Laufstatus und einem Thread für lange Läufe,
   wie die Analyse, das Frontend pollt. Lange Läufe blockieren nichts und ein
   Stopp-Knopf wäre echt — aber es ist eine zweite Zustandsmaschine neben der
   Analyse, zwei Dinge können die Pipe halten, und „busy" muss an deutlich
   mehr Stellen stimmen. Mit `esil.timeout` ist der Gewinn klein. Nachrüstbar,
   falls Läufe sich zäh anfühlen.
3. **Erst Patchen, dann Emulation (verworfen).** Zwei Lieferungen. Für
   Anti-VM allein hätte die Patch-Werkbank genügt, aber das Hauptziel —
   entpackten Code durchlaufen — hätte auf die zweite Lieferung gewartet, und
   beide teilen denselben Cache, die Trennung wäre künstlich.

*Ein echter Debugger kam nicht in Frage:* Er würde das Sample unter dem
Web-UI als SYSTEM ausführen, und das ist das erste Anti-Ziel des bestehenden
Designs. `dbg.backend` kennt in rizin 0.9.1 ohnehin kein `esil`.

## Gestaltung

- **Variante C**, vom Nutzer im Mockup gewählt:
  - Die Lauf-Zeile sitzt zwischen Werkzeugleiste und Arbeitsfläche und
    erscheint erst im Emulationsmodus. Sie trägt die Lauf-Knöpfe, den PC und
    die Register, die der letzte Schritt verändert hat.
  - Der volle Zustand liegt im `EMULATION`-Reiter im Dock, neben CONSOLE,
    XREFS, STRINGS und IMPORTS.
  - FUNCTIONS, CODE und GRAPH behalten ihre Breite; der Graph wird nicht
    schmaler.
- **PC und Breakpoint** brauchen eigene, klar unterscheidbare Marken. Die
  Randspalte der Disassembly nimmt den Breakpoint auf und ist anklickbar.
- **Geänderte Register** werden hervorgehoben, nicht nur anders gefärbt —
  die Farbe allein trägt die Information nicht.
- **Classic und Cyberpunk** wie überall; keine Farbwerte außerhalb von
  `:root`.

## Dem Builder überlassen

- Der genaue Wert von `esil.timeout` und ob er einstellbar ist. Pflicht ist,
  dass er deutlich unter dem Zeitlimit der Pipe liegt.
- Wo `aeim` den Stack hinlegt und wie groß, und ob `esil.stack.addr` und
  `esil.stack.size` dafür gesetzt werden.
- Wie die Puffer des Speicher-Assistenten adressiert werden, damit sie weder
  mit der Datei noch mit dem Stack kollidieren.
- Die genaue Aufteilung der Routen: eine Route pro Lauf-Befehl oder eine mit
  einer Aktion im Body. Das Muster von `/seek` und `/console` ist die
  Vorlage.
- Ob der Zustand nach einem Schritt in einer Antwort zurückkommt oder in
  einer eigenen Route gelesen wird. Ein Schritt soll nicht mehr
  Pipe-Umläufe kosten als nötig.
- Die genaue Form der `/tdc`-Einträge für Patches und Breakpoints, innerhalb
  dessen, was `_sanitize_project` und `_read_project_meta` tragen.
- Der Name der exportierten Kopie und das Format der Notiz daneben.
- Wie viele Stack-Zeilen und Patch-Zeilen die Ansichten zeigen, und ab wann
  sie seitenweise kommen.
- Die genaue Liste der APIs in der Assistenz-Tabelle, innerhalb der Gruppen
  oben. **Als Daten, nicht als Code:** jeder Eintrag braucht Name,
  Konvention, Argumentzahl (für die Stack-Korrektur bei stdcall) und die
  angebotene Antwort — das ist eine Tabelle, die wächst, und sie soll ohne
  Codeänderung wachsen können.
- Wie die Neuanalyse die Grenzen des veränderten Bereichs bestimmt, wenn ein
  Lauf an vielen verstreuten Stellen geschrieben hat.
- Ob die Lauf-Zeile unter 1400 px zu einer zweiten Zeile umbricht oder sich
  auf die Knöpfe verkürzt.

## Entscheidungen des Assistenten (zur Prüfung)

- **Emulation statt echtem Debugging.** Der Unterschied ist nicht kosmetisch:
  ESIL startet keinen Prozess, und damit bleiben die Anti-Ziele des
  bestehenden Designs gültig. Für ein vollständig entpacktes Abbild bleibt
  der Weg, den TDC schon hat — detonieren, Process Dump, den Dump im
  RIZIN-Tab öffnen.
- **`io.cache=true` als Teil des Emulationsstarts**, weil die Emulation ohne
  sie nichts schreiben kann (gemessen). Damit sind Emulation und Patching
  technisch dasselbe.
- **Patchen nur in Bytes, mit Knöpfen für die gängigen Fälle.**
  Assemblieren bleibt draußen.
- **STOP verlässt den Emulationsmodus, es bricht nichts ab.** Ansatz 1 kann
  einen laufenden Befehl nicht unterbrechen, und rizin unter Windows auch
  nicht. Die Oberfläche darf es deshalb nicht versprechen. *(Diese
  Entscheidung korrigiert einen Widerspruch, den der Builder-Check gefunden
  hat.)*
- **Die Patch-Knöpfe wirken auf einen Befehl**, im bestehenden
  Rechtsklick-Menü, nicht auf eine Auswahl. DISASSEMBLY hat keine Auswahl,
  und eine einzuführen wäre eine eigene Oberfläche.
- **„Laufen bis hierher" kommt ins Rechtsklick-Menü** (`aesu`). Es ist fast
  umsonst, nutzt eine Geste, die es schon gibt, und ist der natürliche
  Partner der Breakpoints.
- **Die Detonation läuft über den Submit-Tab**, mit der Datei vorbelegt. Eine
  Route, die eine Datei nach Pfad ausführt, entsteht nicht — `/api/submit`
  nimmt weiter nur ein Multipart-`file`.
- **Von Hand gesetzte Patches bleiben, Lauf-Bytes nicht**, und die Oberfläche
  sagt das, bevor es wehtut.
- **Die Assistenz-Tabelle antwortet wie eine saubere Maschine** — das ist die
  eigentliche Anti-VM-Umgehung, und sie braucht keinen Patch.
- **Bei x86-32 korrigiert SKIP den Stack**, bei anderen Architekturen als
  x86-64 und x86-32 schaltet der Assistent ab statt zu raten.
- **Die Neuanalyse nutzt `af` und `/zj`**, die die Allowlist bereits erlaubt;
  `aa*` bleibt hinter dem Full-analysis-Knopf.
- **Die Konsole bekommt die Emulation mit**, aber nicht `wci`, `wa`,
  `dbc`/`dbC`/`dbx`, `dbw` oder die ausführende `d`-Familie.
- **Keine Watchpoints**, weil `dbw` rizin bei der Messung endlos hängen ließ.
- **Jedes Anhalten nennt seinen Grund.** Ohne das kann die Oberfläche nach
  einem übersprungenen Call nicht mehr ehrlich sein.
