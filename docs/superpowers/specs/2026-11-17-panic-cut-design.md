# Panikschnitt — Isolation in einer Sekunde, mit einem Knopf

Erweiterung zu `docs/superpowers/specs/2026-11-16-firewall-tab-design.md`
(Abschnitt *Durchsetzung*, Unterabschnitt *Isolated*). Wo dieses Dokument und
das dortige Isolated widersprechen, gilt dieses.

## Absicht und das Warum

ISOLATED tut heute das Richtige, aber zu langsam. Auf der echten VM gemessen:
**38,5 s zum Einschalten**, 41,4 s zum Ausschalten. Der Grund steht in der
Ursprungs-Spec und ist keine Nachlässigkeit, sondern eine Korrektur: „default
deny" ist nicht „deny". `Set-NetFirewallProfile -DefaultOutboundAction Block`
regelt nur Verkehr, auf den *keine Regel passt* — Windows liefert aktivierte
Ausgangs-Allow-Regeln mit (Core Networking: DNS, DHCP, Teredo; Store-Apps;
Gruppenrichtlinien), auf dieser VM 135. ISOLATED schaltet sie deshalb einzeln ab,
und das kostet die 38 Sekunden.

Der Anlass für diese Erweiterung ist der Satz des Nutzers: der Knopf ist „gedacht
für eine sofortige Netzwerk-Isolation bzw. eine Art Panic Button um die VM in
Isolated zu setzen, um z. B. einen Outbreak zu verhindern". In einem Ausbruch
sind 38 Sekunden 38 Sekunden Ausbruch. Ein Panikknopf, der eine halbe Minute
braucht, ist keiner.

Die Lösung steht in derselben Spec, drei Abschnitte weiter oben: **in der
Windows-Firewall schlägt eine Block-Regel jede Allow-Regel.** Eine *einzige*
Catch-all-Block-Regel schließt den Ausgang also in einem `New-NetFirewallRule`,
und die 135 Allow-Regeln sind dabei gleichgültig. Sie überstimmt sogar
Allow-Regeln aus einer Gruppenrichtlinie, die sich lokal nicht abschalten lassen
und heute als „bleibt offen" in `allowed_out` stehen.

**Auf der VM gemessen, vor diesem Entwurf** (das ist keine Herleitung, sondern
ein Lauf):

| Gemessen | Ergebnis |
|---|---|
| Eine Catch-all-Block-Regel schreiben und zurücklesen, ein PowerShell-Aufruf | **2,13 s** |
| `curl https://1.1.1.1` mit stehender Regel | `http=000`, **sofort**, kein Timeout |
| `curl http://127.0.0.1:9000` mit stehender Regel | `http=200` — die Oberfläche bleibt da |
| DNS mit stehender Regel | **tot** |
| Nach dem Entfernen | `http=301`, DNS wieder da |

Und zwar **während alle 135 Allow-Regeln aktiviert blieben** und
`DefaultOutboundAction` auf `NotConfigured` stand. Genau die Wirkung, die kein
Test auf macOS zeigen kann.

Was das Geld kostet, ist nicht der Prozessstart (nacktes `powershell.exe -Command
exit` ist 0,26 s), sondern das Laden des NetSecurity-Moduls: jeder einzelne
Aufruf von `firewall_rules.ps1` liegt bei 1,1–2,2 s. **Vier getrennte Aufrufe
(Profile, Create, Get, Profile) wären also 6–7 s und könnten das Versprechen nie
halten.** Der Schnitt braucht deshalb *einen* Aufruf, der alles tut.

Deshalb ist dieser Entwurf keine zweite Betriebsart neben ISOLATED, sondern
**die neue erste Hälfte von ISOLATED**: es schneidet zuerst hart, und holt die
gründliche Arbeit danach nach.

## Ziele

1. Von einem Knopfdruck bis „nichts geht mehr raus" **in etwa dreieinhalb
   Sekunden** (Obergrenze für den Test: 5 s), und zwar nachweisbar — die Regel
   wird zurückgelesen, DNS stirbt.

   *Korrektur nach der Messung am fertigen Verb:* der Entwurf rechnete mit
   2,13 s, weil er eine einzige PowerShell-Runde annahm. Es sind zwei: der
   Rückweg (`outbound_before`, Marker) muss **vor** jeder Änderung gemerkt
   werden, und sein Wert kommt aus einem Profil-Lesen (1,13 s) vor dem Schnitt
   (2,49 s gemessen). Die Alternative — zuerst schneiden, dann merken — wäre
   schneller und ist **verworfen**: sie erlaubt eine stehende Catch-all-Regel
   ohne Marker, also eine abgesperrte VM ohne Aufzeichnung des Rückwegs, und die
   Glaubwürdigkeit dieses Features hängt an „die Firewall kommt exakt zurück".
   Gegen 38,5 s ist der Unterschied zwischen 2 s und 3,6 s nicht der zwischen
   Panikknopf und keinem.

   Steht eine **verfälschte** Regel und muss repariert werden, dauert der
   Schnitt länger (gemessen 5,92 s für eine deaktivierte, 3,38 s für eine
   verengte Regel). Die Oberfläche darf in diesem Fall keine zwei Sekunden
   behaupten.
2. Ein großer, unübersehbarer Knopf an der Stelle, auf die der Nutzer gezeigt
   hat: in der rechten Spalte unter SUMMARY, in der Bildsprache des
   `UPDATE ALL`-Skull-Knopfes.
3. Dieser Knopf und der Schalter in der Kopfzeile sind **ein** Zustand, zweimal
   gezeigt. Sie können sich nie widersprechen.
4. Die Oberfläche sagt zu jedem Zeitpunkt, *wie* geschlossen es ist — und
   insbesondere, ob TDC noch eine Probe sichern kann.
5. Das Verlassen gibt die Firewall weiter exakt so zurück, wie sie vorgefunden
   wurde, einschließlich `NotConfigured`. Diese Eigenschaft ist auf der VM
   bewiesen und darf nicht verloren gehen.

## Nicht-Ziele

- **„Allow Everything" wird nicht gebaut.** Es hat keinen Zustand zum Umschalten
  („erlaubt" ist die Abwesenheit einer Regel), und was es sollte, gibt es
  zweimal: Update-Hosts (`UPDATE_HOSTS`) werden per Entwurf nie zu einer
  Entscheidung, und `ASK: Off` fragt gar nicht mehr. Ein dritter globaler
  Schalter über denselben Dingen ist der wahrscheinlichste Weg, diese
  Oberfläche dazu zu bringen, etwas Falsches zu behaupten.
- **Keine Aktion „Detonation beenden".** Der Nutzer hat sie als Option erwogen
  und sich dann gegen sie entschieden. `KILL` pro Prozess bleibt, wie es ist.
- Eingehender Verkehr wird nicht angetastet. Der Host erreicht Port 9000 weiter.
- Kein Teil-B-Proxy, keine Bandbreitenmessung.

## Anti-Ziele — was dies zum Fehlschlag macht, auch wenn es „funktioniert"

- **Ein Knopf, der sagt „geschnitten", während etwas noch rausgeht.** Alles in
  diesem Feature hängt an diesem einen Maßstab, und er wurde in diesem Projekt
  schon zweimal verletzt (das ursprüngliche „default deny", der Loopback-Block
  mit `verified: true`). Was nicht zurückgelesen werden konnte, heißt nicht
  „geschnitten".
- **Ein Zustand, in dem TDC seinen eigenen Fetcher aussperrt, ohne es zu
  sagen.** Solange die Catch-all-Regel steht, kann `allow_fetch` nicht wirken —
  eine Block-Regel schlägt die per-Fetch-Allow-Regel genauso wie jede andere.
  Das muss auf dem Schirm stehen, nicht nur im Docstring.
- **Zwei Schalter, zwei Wahrheiten.** Wenn der große Knopf und der
  Kopfzeilen-Schalter je verschiedene Zustände anzeigen können, ist der Entwurf
  falsch.
- Eine Firewall, die nach dem Verlassen anders konfiguriert ist als vorher.

## Beschränkungen

- Keine neue Abhängigkeit, keine Bibliothek von außen, kein CDN.
- Farbliterale nur in `:root` von `style.css`.
- Jeder Text aus der VM escaped; Hostnamen und URLs defanged, niemals Links.
- MCP bleibt lesend: **keine** Werkzeuge zum Schneiden, Isolieren oder Beenden.
- Kein Test liest das echte Netz, die echte Uhr, die Umgebung oder das
  Dateisystem außerhalb eines tmp-Verzeichnisses.
- Kommentare, Dokumentation, Commit-Nachrichten und Oberflächentext auf
  Englisch; dieses Dokument und der Plan auf Deutsch.
- Regelnamen bleiben `TDC-FW-<Buchstaben, Ziffern, Bindestriche>`; alles, was
  das Verlassen aufräumen muss, heißt `TDC-FW-ISO-*`, denn `RemoveIsolate` und
  `scripts/tdc-unisolate.ps1` räumen genau dieses Muster.
- Eine Regel schreiben setzt voraus, dass die drei Profile an sind (`Create`
  endet sonst mit Code 3). Der Panikschnitt ist davon nicht ausgenommen.

## Ansätze

Drei Wege, den Ausgang schnell zu schließen; einer bleibt übrig.

### A — Profil-Default zuerst, Allow-Regeln danach

`DefaultOutboundAction Block` ist ein Aufruf und damit schnell; die 135 Regeln
folgen im Hintergrund.

*Dagegen:* nach dem schnellen Teil ist der Ausgang **nicht zu**. Genau die
aktivierten Allow-Regeln, die noch stehen, lassen DNS, DHCP und die Store-Apps
raus — das ist der Fehler, den das Abschluss-Review schon einmal gefunden hat.
Der Knopf würde 37 Sekunden lang behaupten, was nicht stimmt. Verworfen aus
genau dem Grund, der dieses ganze Feature bestimmt.

### B — Eine Catch-all-Block-Regel, und sonst nichts

Eine Regel, ausgehend, jedes Programm, jede Adresse, `Action Block`. Fertig in
etwa einer Sekunde, geschlossen gegen *alles*, auch gegen Gruppenrichtlinien.

*Dagegen:* solange sie steht, kann TDC selbst nichts holen — die per-Fetch-Regel
ist eine Allow-Regel und verliert. Das Sichern einer Stufe 2 ist in diesem
Zustand unmöglich. Für einen Panikschnitt richtig, als Dauerzustand von ISOLATED
ein Verlust gegenüber heute.

### C — B, dann hinüberwechseln (**gewählt**)

Erst die Catch-all-Regel (≈2 s, hart zu). Dann im Hintergrund das heutige
ISOLATED: Allow-Regeln des lokalen Stores ab, Default auf Block. Ist danach
`allowed_out` leer, fällt die Catch-all-Regel weg — der Zustand ist das heutige
ISOLATED, und eine einzelne per-Fetch-Ausnahme ist wieder möglich. Ist
`allowed_out` **nicht** leer (Gruppenrichtlinie), bleibt die Catch-all-Regel
stehen, denn sie ist dort das Einzige, was tatsächlich schließt — und die
Oberfläche sagt, dass in diesem Zustand nicht geholt werden kann.

*Preis:* ein Zustandsautomat mit zwei Stufen und Hintergrundarbeit, statt eines
Umschaltens. Das ist der Preis dafür, in zwei Sekunden ehrlich geschlossen zu
sein und am Ende trotzdem dort zu landen, wo ISOLATED heute schon richtig ist.
Auf einer Maschine mit Gruppenrichtlinien-Allows ist C **stärker** als das
heutige ISOLATED: dort war `verified` bisher nie erreichbar.

Gewählt: **C**. Der Nutzer hat diesen Weg gewählt, nachdem der Preis
(kein Sichern, solange hart geschnitten ist) ausgesprochen war.

### D — Dasselbe, aber mit `netsh advfirewall` statt der Cmdlets (verworfen)

`netsh` ist ein natives Programm und lädt kein Modul. Gemessen: **0,80 s** für
den ganzen Aufruf, 0,18 s für `netsh` allein — also fast drei mal schneller als
die Cmdlets, und es schließt genauso (`http=000`, DNS tot, Loopback 200).

*Verworfen, und zwar wegen eines gemessenen Details:* `netsh ... name="…"` setzt
den **DisplayName**, nicht den `Name`. Der `Name` der entstandenen Regel ist eine
GUID. Im Lauf ist genau das passiert: `Get-NetFirewallRule -Name TDC-FW-ISO-cut2`
fand **nichts**. Damit wäre die gefährlichste Regel des ganzen Systems die
einzige, die TDCs namensbasierte Maschinerie nicht findet: nicht `Get -Name`,
nicht `Remove -Name`, nicht `RemoveIsolate` mit seinem `TDC-FW-ISO-*`, nicht der
Notausgang `scripts/tdc-unisolate.ps1`. Eine verwaiste Catch-all-Block-Regel, die
kein TDC-Weg mehr entfernt, nimmt die VM dauerhaft vom Netz.

1,3 Sekunden sind das nicht wert. Gegen 38,5 s sind sowohl 2,1 s als auch 0,8 s
„sofort"; ein zweites Namensschema für diese eine Regel ist es nicht. *Dies ist
eine Entscheidung des Autors — siehe die Liste am Ende.*

## Der Entwurf

### Zwei Stufen, zwei Namen

| Stufe | Was steht | Geht etwas raus? | Kann TDC holen? | Wie lange bis dahin |
|---|---|---|---|---|
| `CUT` | die Catch-all-Regel | nein | **nein** | ≈2 s |
| `ISOLATED` | Default Block, Windows' Allow-Regeln ab, Catch-all weg | nein | ja, eine Adresse pro Fetch | ≈40 s |
| `CUT (policy)` | Catch-all bleibt, weil `allowed_out` nicht leer ist | nein | **nein** | ≈40 s |

Beide „geschlossen"-Stufen sind echt geschlossen. Der Unterschied, den die
Oberfläche nennen muss, ist allein: *kann TDC in diesem Zustand eine Probe
sichern?*

### Die Catch-all-Regel

- Name `TDC-FW-ISO-cut`. Ein `ISO`-Name, damit `RemoveIsolate` und
  `scripts/tdc-unisolate.ps1` sie ohne Änderung mitnehmen.
- Ausgehend, `Action Block`, `Profile Any`, kein `-Program`, kein
  `-RemoteAddress` (also jede Adresse), kein Port, kein Protokoll. Der
  vorhandene `Create`-Verb schreibt genau das schon heute — im Messlauf kam
  `{"Name":"TDC-FW-ISO-cuttest","Enabled":true,"Action":"Block",`
  `"Direction":"Outbound","Profile":"Any","Program":"Any","RemoteAddress":["Any"]}`
  zurück, und der Ausgang war zu.
- **Geschrieben wird sie aber über einen neuen Verb `Cut`**, der Profilprüfung,
  `New-NetFirewallRule` und Rücklesen in **einem** PowerShell-Aufruf erledigt
  (2,13 s gemessen). Vier getrennte Aufrufe wären 6–7 s; das ist der ganze Grund
  für diesen Verb. Er schreibt nur diese eine Regel unter diesem einen Namen und
  nimmt keine Adress-, Programm- oder Portparameter an — es gibt an ihm nichts
  zu parametrisieren und damit nichts zu missbrauchen.
- **Loopback ist in dieser Adressmenge enthalten, und das ist unschädlich:**
  die Windows-Firewall filtert Loopback nicht (im Messlauf blieb
  `http://127.0.0.1:9000` bei `http=200`, während `https://1.1.1.1` sofort
  `000` gab). Die Oberfläche bleibt erreichbar. Das ist derselbe Befund, der TDC
  verbietet, eine *gezielte* Loopback-Regel zu schreiben — dort wäre sie
  wirkungslos und würde als „bestätigt" gemeldet; hier ist die Wirkungslosigkeit
  auf Loopback die Voraussetzung dafür, dass man beim Zusehen bleibt.
- Sie wird im selben Aufruf **zurückgelesen**. Wird sie nicht gefunden oder
  steht sie anders als geschrieben, heißt der Zustand nicht `CUT`, sondern nennt
  das Problem.
- Eingehend bleibt unberührt, also erreicht der Host Port 9000 weiter.
- Ist ein Profil aus, endet `Cut` mit Code 3 und der Schnitt **verweigert** und
  ändert nichts, mit der vorhandenen Begründung („erst die Firewall
  einschalten"). Ein Panikknopf, der in diesem Fall „geschnitten" sagte, wäre
  genau der Fehler aus den Anti-Zielen.

### Der Ablauf beim Einschalten

1. **Profile lesen** (`Profiles`, 1,13 s), nicht die Allow-Regeln. Ist eines
   aus: verweigern, nichts ändern. **Nicht** `AllowOut`: vor dem Schnitt wird
   keine Allow-Regel abgeschaltet, es gibt also noch nichts aufzuschreiben, und
   *was offen bliebe* ist für den Schnitt bedeutungslos — er schließt, weil
   Block jede Allow-Regel schlägt. `allow_disabled` wird in `converge` notiert,
   direkt bevor dort abgeschaltet wird, und dort bleibt auch die Weigerung,
   etwas zu ändern, wenn die Liste nicht lesbar ist.
2. `outbound_before` und Marker mit `settings.set` sichern. Scheitert das, wird
   **nichts** angefasst.
3. `TDC-FW-ISO-cut` schreiben (oder eine verfälschte Regel reparieren) und
   zurücklesen — ein Aufruf, 2,49 s gemessen. Ab hier ist der Ausgang zu.
   `stage: "cut"` wird **danach** gesichert, denn vorher wäre es eine Stufe, die
   noch nicht gilt; der Marker aus Schritt 2 ist das, was ein Absturz hier
   hinterlässt, und den zeigt der Start an.
4. Antworten. Der Knopfdruck ist hier fertig, nach rund 3,6 s.
5. Im Hintergrund, in *einem* Arbeiter: `allowed_out` lesen (nicht lesbar ⇒
   nichts ändern), `allow_disabled` notieren, die Allow-Regeln des lokalen
   Stores abschalten, Default auf Block, dann `allowed_out` zurücklesen.
6. Ist `allowed_out` leer: `TDC-FW-ISO-cut` entfernen, `stage: "isolated"`.
   Sonst: Regel stehen lassen, `stage: "cut_policy"`, und `allowed_out` nennen.
7. Scheitert Schritt 5, **bleibt die Catch-all-Regel stehen**. Der Zustand ist
   weiter geschlossen, `stage` bleibt `cut`, und die Oberfläche sagt, dass der
   gründliche Teil nicht durchkam und warum. Der Rückweg, der heute schon beim
   Scheitern zurückrollt, rollt nur das zurück, was er selbst geändert hat.

**`verified` heißt in den Schnitt-Stufen: die Catch-all-Regel wurde
zurückgelesen** — und nichts weiter. Sie schließt unabhängig davon, ob die
Allow-Liste lesbar war, denn Block schlägt Allow; auf der VM war der Ausgang zu,
*während alle 135 Allow-Regeln aktiviert blieben*. Eine unlesbare Allow-Liste
entscheidet nicht, ob geschlossen ist, sondern nur, ob die Regel fallen darf —
und das darf sie dann nicht.

**`converge` prüft selbst, ob der Marker noch steht**, und tut nichts, wenn
nicht. Sonst könnte ein Arbeiter, der nach einem Verlassen noch läuft, Windows'
Allow-Regeln wieder abschalten, die das Verlassen gerade eingeschaltet hat.

Die Reihenfolge in 6 ist bewusst: die Allow-Regeln sind schon ab und der
Default steht auf Block, *bevor* die Catch-all-Regel fällt. Zu keinem Zeitpunkt
ist etwas offen.

### Der Ablauf beim Verlassen

Unverändert gegenüber heute, plus: `RemoveIsolate` nimmt `TDC-FW-ISO-cut` mit.
Die heutige Sicherheitseigenschaft bleibt und ist der Grund, dass ein
abgebrochener Hintergrundlauf ungefährlich ist: **`allow_disabled` wird
notiert, bevor etwas abgeschaltet wird.** Das Verlassen stellt deshalb immer
wieder her, was notiert ist, auch wenn der Arbeiter mitten in seiner Arbeit
abgebrochen wurde.

**Verlassen ist jederzeit möglich, auch mitten in der Konvergenz.** Das ist die
Bedingung dafür, dass der Schnitt ohne Rückfrage auskommt: ein Fehldruck ist in
zwei Sekunden rückgängig zu machen, nicht erst nach vierzig. Dafür

- prüft der Arbeiter **zwischen** seinen PowerShell-Aufrufen eine Abbruchmarke,
  und bricht ab, sobald sie steht;
- setzt `on: false` diese Marke, wartet den *laufenden* Aufruf ab (zwei
  gleichzeitige Regelläufe gibt es nie) und läuft dann den normalen
  Verlassen-Weg;
- ist der normale Weg auch für einen halb erledigten Zustand richtig, weil er
  aus `allow_disabled` herstellt, und das steht vollständig da, bevor der erste
  Schalter umgelegt wurde.

Welche Form Marke und Warten bekommen (der vorhandene Lock der Sweep-Schleife
oder ein eigener), ist dem Builder überlassen, solange nachweislich nie zwei
Läufe gleichzeitig laufen und die Marke zwischen *jedem* Paar von Aufrufen
gesehen wird.

### Neustart, Absturz, Notausgang

**Ein Neustart ändert nie die Durchsetzung** — das ist die vorhandene Regel
dieses Features und sie gilt hier weiter. Steht beim Start ein Marker, wird er
angezeigt und nicht aufgelöst.

**Daran muss der vorhandene Startcode geändert werden**, sonst entsteht genau
das, was Schritt 3 verhindern soll: `startup_state` hält heute „Marker gesetzt,
aber kein Profil auf Block" für *veraltet*, schaltet die Allow-Regeln zurück und
löscht den Marker. Nach einem Absturz in Stufe `cut` ist aber genau das der
Zustand — die Catch-all-Regel steht, der Default ist noch nicht Block. Der
Starttest muss deshalb **auch nach `TDC-FW-ISO-cut` sehen**: steht sie, ist die
Durchsetzung in Kraft, der Marker ist nicht veraltet, die Stufe ist `cut`, und
der Start sagt es, statt aufzuräumen. Die Konvergenz wird **nicht** von selbst
fortgesetzt; der Analyst entscheidet, ob er verlässt oder weitermachen lässt.

Der Notausgang `scripts/tdc-unisolate.ps1` braucht keine Änderung: er räumt
`TDC-FW-ISO-*`, und die Regel heißt deshalb so.

### Die Stufe wird gemeldet, nicht nachgeregelt

Wird `allowed_out` **später** nicht mehr leer, während Stufe `isolated` steht
(eine Richtlinienaktualisierung, Windows oder das Sample schaltet eine
Ausgangs-Allow-Regel ein), dann **schreibt TDC nicht von selbst**. Es meldet:
`verified` wird falsch, das Band nennt die Regel und ihren Store, und der große
Knopf bietet den Schnitt als Abhilfe mit einem Druck an.

Grund: TDC ändert die Durchsetzung nur auf einen Druck — es schaltet aus
demselben Grund nicht einmal die Firewall von selbst ein. Ein Hintergrundwächter,
der Regeln schreibt, wäre die erste Stelle, an der etwas ohne Zutun passiert, und
das widerspricht dem Feature. Das Anti-Ziel („nie geschlossen sagen, während
etwas rausgeht") ist damit erfüllt: der Zustand *sagt* dann nicht mehr
geschlossen.

### Die Oberfläche

**Der große Knopf.** In der rechten Spalte, unter der SUMMARY-Karte, als eigene
Karte. Aufbau wie `updateAllButtonHtml`: `btn-skull` mit `skullButtonSvg()`,
Label darunter. Statt des Zählers in `.btn-skull-badge` trägt er den Zustand.

| Zustand | Label | Was der Knopf tut |
|---|---|---|
| nicht isoliert | `CUT THE NETWORK` | schneidet, ohne Rückfrage |
| `stage: cut`, Arbeiter läuft | `CUT · SECURING…` | **verlässt** (mit Rückfrage); der Arbeiter bricht ab |
| `stage: cut`, Arbeiter gescheitert | `CUT · NOT SECURED` | verlässt; das Band sagt, was nicht durchkam |
| `stage: isolated` | `ISOLATED` | verlässt (mit Rückfrage) |
| `stage: isolated`, `allowed_out` nicht mehr leer | `ISOLATED · OPEN` | schneidet erneut (ein Druck) |
| `stage: cut_policy` | `CUT · NO FETCH` | verlässt (mit Rückfrage) |
| Firewall aus | `CUT THE NETWORK`, deaktiviert | nichts; der Grund im Titel |

`aria-pressed` spiegelt den Zustand, `aria-live` meldet den Wechsel. Kein
Pulsieren; `prefers-reduced-motion` wird respektiert wie im restlichen Tab. Der
Knopf ist nur in dem einen Fall deaktiviert, in dem er nichts tun *kann* (die
Firewall ist aus) — nie, weil TDC gerade beschäftigt ist: ein Panikknopf, der
vierzig Sekunden lang nicht loslässt, ist das Gegenteil von dem, wofür er da
ist.

**Ein Zustand, zwei Orte.** Der Knopf und `#firewall-isolated` in der Kopfzeile
lesen beide `fwState.isolate` und rufen beide `fwToggleIsolated()`. Beide sind
während des Umschaltens gesperrt. Der Kopfzeilen-Schalter bleibt, weil er immer
sichtbar ist: die rechte Spalte scrollt mit der Seite, und ein Panikknopf, den
man erst suchen muss, ist der schlechtere von beiden. Er bekommt zusätzlich die
Stufe (`ISOLATED` / `CUT`) als Text.

**Rückfrage: beim Schneiden keine, beim Verlassen ja.** Das ist der Sinn eines
Panikknopfes — ein Druck. Der Schnitt ist sicher (er sperrt nur, er zerstört
nichts) und in zwei Sekunden rückgängig zu machen, zu jedem Zeitpunkt, auch
mitten in der Konvergenz. Das Verlassen behält die heutige
`tdcConfirm`-Rückfrage, denn dort läuft ein Sample wieder ins Netz.
*Entscheidung des Autors, nicht des Nutzers — bitte prüfen.*

**Das Band** (`#firewall-bands`) nennt die Stufe und, wenn gehalten werden muss,
warum: welche Allow-Regeln aus welchem Store offen geblieben wären, und den
Satz, dass TDC in diesem Zustand keine Probe sichern kann. Der vorhandene
`residual`-Hinweis gilt nur in `stage: isolated`, denn nur dort gibt es
überhaupt eine per-Fetch-Ausnahme.

**Was ausgegraut wird.** In `stage: cut` und `cut_policy` ist
`KAPPEN + SELBST HOLEN` deaktiviert, mit dem Grund im Titel. Eine
Download-Entscheidung, deren Frist in diesem Zustand abläuft, sperrt — und sagt,
dass sie nicht holen konnte, statt eine Sicherung zu behaupten.

### API

Keine neue Route. `POST /api/firewall/isolate {on: true}` antwortet nach
Schritt 4, also in etwa zwei Sekunden, mit `stage: "cut"`, `verified` (die
zurückgelesene Catch-all-Regel) und `converging: true`.
`GET /api/firewall/isolate` bekommt `stage`, `converging`, `can_fetch` und
behält alles Heutige. `on: false` bleibt, wie es ist, und bricht einen
laufenden Arbeiter ab.

Damit wird auch der Kopfzeilen-Schalter schnell — es gibt keinen zweiten,
langsamen Weg mehr, den jemand aus Versehen nimmt.

### Tests, und was Tests hier nicht können

Normal testbar: dass die Regel mit genau diesen Parametern geschrieben und im
selben Aufruf zurückgelesen wird; dass ein ausgeschaltetes Profil verweigert und
nichts schreibt; der Zustandsautomat über alle Stufen aus der Knopf-Tabelle;
dass `allowed_out != []` die Catch-all-Regel stehen lässt; dass das Verlassen
`TDC-FW-ISO-cut` mitnimmt und `NotConfigured` zurückgibt; dass ein Abbruch
zwischen zwei Aufrufen des Arbeiters nichts Unaufgeräumtes hinterlässt und das
Verlassen danach alles aus `allow_disabled` herstellt; dass ein Start mit
stehender Catch-all-Regel die Stufe `cut` findet und **nichts** aufräumt; dass
der große Knopf und der Kopfzeilen-Schalter nie verschiedene Zustände zeigen
können.

**Nicht testbar, und das gehört ausgeschrieben:** der Fake-Runner modelliert
nicht, dass eine Block-Regel eine Allow-Regel schlägt. Kein Test auf macOS kann
beweisen, dass die Catch-all-Regel wirkt — genau diese Blindheit hat das
ursprüngliche „default deny" durchgelassen. Für diesen Entwurf ist die Wirkung
vorab auf der VM gemessen (siehe die Tabelle oben), und sie bleibt ein
**VM-Pflichtcheck** in
`docs/superpowers/plans/2026-11-16-firewall-tab-handover.md`: nach dem Druck
muss DNS tot und `1.1.1.1:443` unerreichbar sein, während die Oberfläche
erreichbar bleibt, die Zeit bis `stage: cut` unter 3 s liegen, und der Rundlauf
am Ende `NotConfigured` und alle Regelnamen exakt zurückgeben.

## Was dem Builder überlassen bleibt

- Die Form der Hintergrundarbeit (Thread, vorhandene Sweep-Schleife), der
  Abbruchmarke und des Wartens beim Verlassen — solange nie zwei Regelläufe
  gleichzeitig laufen und die Marke zwischen jedem Paar von Aufrufen gesehen
  wird.
- Die genauen Texte der Bänder und Titel, im Ton des übrigen Tabs.
- Die Aufteilung der Karte in der rechten Spalte und die Abstände.
- Ob `stage` als eigenes Feld in `Settings` liegt oder aus dem Vorhandenen
  abgeleitet wird; nur muss ein Neustart die Stufe richtig wiederfinden.

## Entscheidungen des Autors, die der Nutzer prüfen sollte

1. **Der Schnitt fragt nicht zurück, das Verlassen schon.** Tragbar, weil
   Verlassen jederzeit geht: ein Fehldruck kostet zwei Sekunden, nicht vierzig.
2. **Cmdlets statt `netsh`: 2,1 s statt 0,8 s.** Gemessen. Der Grund gegen
   `netsh` ist, dass seine Regel einen GUID-`Name` bekommt und TDCs
   namensbasierte Entfernung und der Notausgang sie nicht finden würden. Wer
   „sofort" strenger auslegt, kann das umdrehen — dann braucht die Regel ein
   zweites Identitätsschema in `RemoveIsolate` und in `tdc-unisolate.ps1`.
3. **Der Kopfzeilen-Schalter bleibt** zusätzlich zum großen Knopf, weil die
   rechte Spalte mitscrollt und ein Panikknopf, den man sucht, der schlechtere
   ist.
4. **Auf einer Maschine mit Gruppenrichtlinien-Allows bleibt die
   Catch-all-Regel dauerhaft stehen** — geschlossen, aber ohne Sichern. Die
   Alternative wäre, dort `verified: false` zu melden und offen zu bleiben; das
   wäre schlechter.
5. **Kein Nachregeln im Hintergrund:** wird `allowed_out` später wieder nicht
   leer, meldet TDC das und schneidet nicht von selbst nach.
