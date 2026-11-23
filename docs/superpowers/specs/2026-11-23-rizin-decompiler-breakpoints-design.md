# Breakpoints in der DECOMPILER-Ansicht

**Größe: kleine Änderung.** Kurzes Design, kein Builder-Check.

## Absicht

Die Randspalte der DISASSEMBLY setzt und entfernt einen Breakpoint mit einem
Klick. Im **DECOMPILER** gibt es das nicht, obwohl man im C-Code schneller
sieht, wo man anhalten will als in vierzig Zeilen Assembler. Der Nutzer will
dort dieselbe Geste.

**Wer es nutzt:** der Nutzer selbst, im Browser, beim Entpacken.

**Vom Nutzer entschieden:** Ein Breakpoint auf einer C-Zeile hält **vor dieser
Zeile**, nicht an der Stelle in ihr, die ihn interessiert.

## Befunde (im Code nachgelesen)

| Befund | Bedeutung |
|--------|-----------|
| Jede C-Zeile kommt vom Server mit `offsets` (alle Adressen ihrer Offset-Annotationen, **sortiert**) und `offset` | Die Daten für eine Randspalte liegen schon auf der Leitung; es braucht keinen neuen Server-Aufruf und keine neue Route |
| `offset` ist die **erste Annotation in rizins Reihenfolge**, nicht die niedrigste Adresse (`_rizin_code_lines` in `webui/app.py`) | Im Modell echter `pdgj`-Ausgabe trägt `hPipe = CreateNamedPipeA(lpName);` die Adressen `0x1400015BF` und `0x1400015B9` in dieser Reihenfolge. Ein Klick auf die Zeile springt heute auf `0x15BF` — hinter den Call, um den es der Zeile geht |
| Der Renderer hängt `offset` schon als `data-addr` an die Zeile und listet alle Adressen im Tooltip (`rizinDecompilerHtml`) | Der Klick-zum-Springen bleibt unverändert; er spiegelt rizins eigenes `pdgo` |
| Eine C-Zeile ohne Annotation (`{`, `}`, die Signatur, ein Kommentar) hat **keine** Adresse | Dort gibt es nichts zu setzen |
| Mehrere C-Zeilen können dieselbe Adresse tragen | Die Rückrichtung — welche Zeile die Marke trägt — ist nicht eindeutig |
| `rizinDecompilerMark` löst genau diese Mehrdeutigkeit heute schon für die *aktuelle* Zeile: von den Zeilen mit der nächstgelegenen Adresse bei oder vor der gesuchten die erste Code-Zeile | Dieselbe Regel trägt die Breakpoint-Marke, statt eine zweite zu erfinden |
| Die Breakpoint-Liste liegt im Frontend bereits vor (die `marks`-Ansicht aus Task 12 hält sie) | Kein zusätzlicher Abruf, und die Ansicht ist mit der Randspalte der Disassembly automatisch synchron |
| Der PC wird in DECOMPILER **schon** markiert: ein Lauf setzt den Seek auf den PC, und die Ansicht markiert die Zeile dazu | Es fehlt wirklich nur der Breakpoint |

## Ziele

- Eine Randspalte in jeder C-Zeile, wie in der DISASSEMBLY: dieselbe Zellbreite,
  dasselbe blasse `○` im Ruhezustand, dasselbe rote `●`, wenn gesetzt, derselbe
  Klick, der setzt und entfernt, und kein Sprung beim Klick in die Spalte.
- **Ein Klick setzt den Breakpoint auf `offsets[0]`**, die niedrigste Adresse
  der Zeile. Das ist „vor dieser Zeile" und das, was jeder Debugger auf
  Quellcode-Ebene tut.
- **Der Tooltip nennt die Adresse**, die der Klick verwendet, damit nie unklar
  ist, wo der Breakpoint wirklich sitzt.
- Eine Zeile gilt als gesetzt, wenn **irgendeine** ihrer Adressen einen
  Breakpoint trägt — auch einer, der in der Disassembly oder der Konsole gesetzt
  wurde. Ein Klick entfernt dann genau diesen.
- Eine Zeile ohne Adresse hat keine klickbare Zelle und kein `○`.

**Korrektur dieses Dokuments (beim Ausarbeiten der Signaturen gefunden):** Eine
frühere Fassung schrieb zusätzlich, die Rückrichtung solle „dieselbe Regel
nehmen, die `rizinDecompilerMark` heute für die aktuelle Zeile benutzt". Das
widerspricht der Regel eine Zeile darüber. `rizinDecompilerMark` wählt **genau
eine** Zeile aus, weil genau eine „hier" sein kann; ein Breakpoint gehört aber
ehrlich zu **jeder** C-Zeile, die den Befehl enthält, und ein Klick auf jede von
ihnen entfernt ihn. Die „irgendeine ihrer Adressen"-Regel gilt, das Spiegeln von
`rizinDecompilerMark` fällt weg — und damit auch die Annahme, die Rückrichtung
sei die eigentliche Arbeit. Sie ist es nicht; die eigentliche Arbeit ist, dass
die Marke beim Setzen nicht veraltet (siehe Rahmenbedingungen).


## Nicht-Ziele

- **Pro Zeile alle ihre Adressen setzen.** Ein Klick ergäbe mehrere Einträge im
  Pane, und das Entfernen müsste alle finden. Das bricht die Regel „ein Klick,
  ein Breakpoint", die die Disassembly gesetzt hat.
- **Die Adresse raten**, also bevorzugt den Call der Zeile nehmen. Raten ist das,
  was dieses Feature überall sonst vermeidet.
- **Den Klick-zum-Springen ändern.** Er benutzt weiter `offset` und spiegelt
  damit rizins `pdgo`.
- **Tastaturbedienung.** Die Disassembly-Zeilen sind auch nicht erreichbar; das
  ist eine eigene Aufgabe für beide Ansichten zusammen.
- **Eine zweite Marken-Regel.** Die Rückrichtung nimmt die bestehende.

## Anti-Ziele (Misserfolg, auch wenn es läuft)

- **Ein `●` auf einer Zeile, deren Code nicht dort ist, wo der Lauf hält.** Das
  ist „die Oberfläche lügt" in dieser Ansicht.
- Ein Klick, der mehr Breakpoints setzt als der Nutzer sieht.
- Eine Zeile, die als gesetzt gilt, sich aber nicht zurücksetzen lässt.
- Die C-Ansicht wird gedrungen: die Spalte darf den Code nicht verschieben, und
  bei 1280 px muss er lesbar bleiben.

## Rahmenbedingungen

- Vanilla JS in `webui/static/js/app.js`, Funktionen auf oberster Ebene mit
  Präfix `rizin`, Konstanten `RIZIN_`. Jede neue Funktion gehört in
  `RIZIN_FUNCTIONS`, jede Konstante in `RIZIN_CONSTS` in `tests/test_rizin_ui.py`.
- Farben nur als `var(--…)`, Werte nur in `:root` von `style.css`, jedes neue
  Selektor-Paar braucht sein `[data-theme]`-Gegenstück in `theme-layout.css`.
- Asset-Versionen in `webui/templates/index.html` hochzählen.
- Adressen im Browser immer `"0x…"`-Strings.
- `docs/rizin.md` und die Hilfe im Tab müssen übereinstimmen; 21 Phrasen sind
  durch `test_the_help_and_the_guide_say_the_same_where_they_say_it_twice`
  gepinnt.
- **`rizinRenderDecompiler` hat zwei Pfade:** einen vollen `innerHTML`-Neubau,
  wenn sich die Signatur `[sid, dec.gen]` geändert hat, und sonst eine
  schrittweise Aktualisierung, die nur die `current`-Klasse umsetzt. Ein
  Breakpoint-Wechsel löst heute keinen der beiden aus — die Marke in der
  Randspalte würde also veralten. Das ist die eigentliche Arbeit dieser
  Änderung, und es ist dieselbe Klasse von Fehler, die den Breakpoint-Mechanismus
  schon einmal einen Durchgang gekostet hat (eine veraltete Liste überschrieb
  eine neuere). Der Scroll-Stand darf dabei nicht verloren gehen.
- Kein Server-Code, keine neue Route, kein neues `docs/api.md`-Zeile.


## Ansätze

1. **`offsets[0]`, die niedrigste Adresse der Zeile (gewählt).** „Vor dieser
   Zeile", wie jeder Quellcode-Debugger. Ein Klick, ein Breakpoint, eine
   Adresse. *Kosten:* wer bei einem Call in der Mitte der Zeile halten will,
   geht dafür in die Disassembly — einen Klick entfernt.
2. **`offset`, was der Klick heute zum Springen nimmt (verworfen).** Wäre
   konsistent mit dem Sprung, hält aber im gemessenen Beispiel hinter dem Call
   der Zeile, und die Marke stünde trotzdem an der Zeile.
3. **Alle Adressen der Zeile setzen (verworfen).** Immer „irgendwo in dieser
   Zeile" halten, aber ein Klick ergibt mehrere Breakpoints; das Pane zeigt
   Einträge, die der Nutzer nicht gesetzt hat.

Der Nutzer hat Ansatz 1 gewählt.

## Entscheidungen des Assistenten (zur Prüfung)

- **Dieselbe Randspalte, nicht eine eigene:** Zellbreite, Glyphen, Farben und
  die Klick-Behandlung kommen aus der Disassembly, damit die beiden Ansichten
  nicht auseinanderlaufen.
- **Die Arbeit liegt darin, dass die Marke nicht veraltet.** `rizinRenderDecompiler`
  baut die Zeilen nur neu, wenn sich `[sid, dec.gen]` ändert; ein Breakpoint-Wechsel
  tut das nicht. Ohne diesen Punkt zeigt die Randspalte einen Stand von vorher.
- **Mehrere `●` für einen Breakpoint sind richtig, nicht ein Fehler.** Gehört ein
  Befehl zu drei C-Zeilen, tragen alle drei die Marke, und ein Klick auf jede
  entfernt ihn. Alles andere müsste eine Zeile zur „richtigen" erklären.
- **Es bleibt auf dem Branch `feature/rizin-emulation`.** Der Branch ist noch
  nicht gemergt, die Sichtbarkeits-Korrektur der Randspalte liegt schon dort,
  und diese Änderung fasst dieselbe Stelle an. Ein eigener Branch wäre ohne
  diesen nicht mergebar. *Kosten:* der Diff des Branches wächst über seinen
  Plan hinaus, und ein Review sieht mehr, als der Plan angekündigt hat.


## Dem Builder überlassen

- Ob die Randspalte in DECOMPILER eine eigene Zelle bekommt oder die bestehende
  Zeilenstruktur erweitert, solange der Code nicht verrutscht.
- Wie der Tooltip die Adresse nennt.
- Ob eine Zeile, deren Breakpoint woanders gesetzt wurde und nicht auf
  `offsets[0]` liegt, das im Tooltip unterscheidet.
- Ob es in dieser Ansicht eine Patch-Markierung (`≠`) gibt. Das Design verlangt
  sie nicht.
