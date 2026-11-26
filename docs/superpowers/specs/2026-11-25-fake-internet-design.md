# Fake-Internet und Netzwerk-Analyse – Design

## Wunsch

Detoniert man heute ein Sample über `/api/submit`, weiß TDC am Ende, **dass**
ein Prozess nach draußen telefoniert hat — Ziel-IP, Port und Domain aus Sysmon
EID 3 und 22 — aber nicht, **was** dabei über die Leitung ging. Der
Tracing-Tab hat Unterkarten für `HTTP REQUESTS`, `CONNECTIONS` und
`DNS REQUESTS`; sie stehen immer auf `0`, weil es nie eine Quelle dafür gab.

Zwei Dinge soll das ändern:

1. **Fremde Malware so weit bringen, dass sie ihr Verhalten zeigt** — und sie
   so beschreiben können, dass man sie wiedererkennt. Viele Samples (gerade
   die aus dem mitgelieferten theZoo) sprechen mit C2-Servern, die seit Jahren
   tot sind: sie brechen nach dem ersten fehlgeschlagenen Connect ab, und die
   EDRs sehen vom eigentlichen Verhalten nichts.
2. **Eigene Implantate debuggen** — ein selbst gebautes Beacon soll seinen
   Teamserver erreichen, taskbar sein, und man will daneben sehen, was die
   Telemetrie dazu sagt.

**Vorbild** ist NetLens (https://github.com/FzRsLLaSheR/NetLens) — als Beweis,
dass der Ansatz trägt, und als Maßstab, was ein Bericht leisten muss. Es wird
**nicht gebündelt, nicht mitlaufen gelassen und nicht portiert**: aus NetLens
kommt kein Code, keine Regel, kein Fixture (siehe *Herkunft*). Gebaut wird in
TDC, als Python-Module in `webui/`, neben `pipe_proxy.py`, angehängt an
`/api/submit` und `/api/detonation/results`.

## Ziele

- Nach einer Detonation ist sichtbar, welcher Prozess mit welchem Namen
  gesprochen hat, über welches Protokoll, mit welchem Inhalt — HTTPS im
  Klartext, wo der Client unser Zertifikat annimmt.
- Zwei Betriebsarten, **pro Detonation wählbar**: abgeschottet (TDC beantwortet
  alles selbst) und online (die VM redet echt, TDC schneidet mit).
- Ein C2-Listener in zwei Spielarten: fremde Beacons am Leben halten und
  ausmessen; eigene Beacons an den echten Teamserver durchreichen.
- **Die zweite Stufe eines Loaders sichern**, ohne sie ihm auszuliefern — und
  sie als eigene, verknüpfte Detonation anbieten.
- Ein Fingerprint pro Lauf, der über Läufe hinweg vergleichbar bleibt und
  einen Snapshot-Rollback überlebt, weil er exportierbar ist.
- Die Befunde laufen in **dasselbe** Evidence- und Verdict-System wie Memory
  und Named Pipes. Ein Verdict, nicht zwei.
- Läuft auf beiden Plattformen: Hyper-V x64 und QEMU/UTM ARM64.

## Nicht-Ziele

- **Der Loader bekommt seine Stage nicht ausgeliefert.** Er erhält im
  abgeschotteten Modus unsere Antwort und bricht dort meist ab. Die Stage
  selbst ist aber **nicht verloren**: TDC holt sie und sichert sie (siehe
  *Stage-Sicherung*). Sie im Kontext des Loaders auszuführen bleibt
  ausgeschlossen — sie wird stattdessen als eigene Detonation angeboten.
- **Kein Brechen von Certificate Pinning** und keine Zertifikate für Clients
  mit eigenem Truststore (Python `certifi`, Firefox, Go). Für die bleiben SNI,
  JA3 und JA4 übrig.
- **Kein Entschlüsseln fremder C2-Protokolle**, deren Schlüssel wir nicht
  haben. Ein Cobalt-Strike-Beacon verschlüsselt seine Metadaten mit dem
  RSA-Public-Key seines echten Teamservers; ohne den privaten Schlüssel kann
  unser Listener es annehmen und am Leben halten, aber nicht tasken.
- **Kein VM-Verstecken.** Erkennt ein Sample die Analyseumgebung und tut
  nichts, zeigt TDC das (kurze Lebensdauer, kein Verkehr, Exit-Code) und
  bekämpft es nicht.
- **Kein zweiter Regelsatz für Host-Verhalten.** Die neuen YAML-Regeln sehen
  nur Netzwerk-Events; Prozess, Registry und Datei bleiben bei Sigma/Rustinel.

## Anti-Ziele

Daran scheitert die Arbeit, auch wenn sie technisch funktioniert:

- Eine Detonation im Online-Modus läuft anders als heute. Der bestehende Pfad
  muss unverändert bleiben, wenn der Modus `online` ist.
- Die Web UI ist während einer abgeschotteten Session vom Host nicht
  erreichbar. Port 9000 und WinRM müssen durchgehend stehen.
- Die VM bleibt nach einem abgebrochenen Lauf ohne Netz oder mit einer
  fremden CA im Truststore zurück. Aufräumen muss garantiert sein — wie es
  `_exit_capture_watch` (`webui/app.py:6919`) mit `finally` schon macht —
  plus Aufräumen von Resten beim nächsten Start.
- Es entsteht ein zweites Scoring neben `memory_evidence`.
- Die Fingerprint-Datenbank liegt nur in der VM und ist beim nächsten
  Snapshot-Rollback weg.

## Randbedingungen

| Fakt | Folge |
|---|---|
| Web UI läuft **im Gast** (`C:\DetonationChamberUI`, Scheduled Task, SYSTEM, Port 9000) | Die Fake-Server laufen im selben Prozessraum wie die UI, als Threads |
| Zielplattformen Hyper-V **x64** und QEMU/UTM **ARM64** | Kein Kernel-Treiber. WinDivert hat keinen ARM64-Build, und ein `.sys` lässt sich nicht emulieren wie die x64-Userland-Tools |
| Das Sample wird vom **DetonatorAgent** (`127.0.0.1:8080`) gestartet, nicht von uns | Das Netz muss **vor** dem Start stehen, analog zu `_exit_capture_arm` |
| Python **3.12** im Gast, Flask, kein Build-Step, Vanilla JS | Neue Module in `webui/`, neue Endpoints in `app.py`, UI in `app.js` + `index.html` |
| `pefile` vorhanden; `dpkt`, `pyyaml`, `cryptography`, `pyzipper` neu | Alle als reine Python-Wheels oder mit ARM64-Wheel verfügbar |
| Die VM braucht echtes Internet für Tool-Updates | Abschottung gilt nur für die Dauer einer Detonation, nie dauerhaft |
| Snapshots werden pro Sample zurückgerollt | Fingerprints und Reports müssen exportierbar sein |

## Ansätze

Ein Fake-Internet braucht einen Punkt, an dem die Verbindung abgefangen und
selbst beantwortet wird. Windows hat kein `iptables`; transparentes Umlenken
beliebiger Ziel-Adressen braucht normalerweise einen Kernel-Treiber.

### A — Im Gast, ohne Treiber *(gewählt)*

Die Umlenkung entsteht aus der **Namensauflösung**: Ein eigener DNS-Server
antwortet auf jeden Namen mit einer eigenen Adresse aus `198.18.0.0/15`
(RFC 2544, nicht geroutet — derselbe Bereich, den NetLens benutzt). Diese
Adressen werden als **sekundäre Adressen auf dem echten Adapter** registriert
(`netsh interface ipv4 add address <if> <ip> 255.255.255.255
skipassource=true`); Windows behandelt eigene Adressen als lokal, ein Listener
auf `0.0.0.0` nimmt sie damit an. `skipassource=true` verhindert, dass sie als
Quelladresse für ausgehenden Verkehr auftauchen. Zusätzlich wird der
System-Proxy gesetzt, dem WinINet- und WinHTTP-Malware folgt.

> Windows hat **kein** Loopback-Aliasing wie Linux: `127.0.0.1` lässt sich
> nicht um `198.18.x.x` erweitern, und der KM-TEST-Loopback-Adapter wäre eine
> Treiberinstallation — also genau das, was Ansatz C ausgeschlossen hat.
> Deshalb der Weg über den echten Adapter.

- **Abdeckung:** alles, was DNS oder den System-Proxy benutzt — die große
  Mehrheit.
- **Lücke:** fest eingebaute IP-Adressen ohne Proxy. Die werden gesehen und
  geblockt, aber nicht beantwortet. Sie sind damit nicht still: Adresse, Port
  und Prozess stehen als IOC im Report.
- **Nebengewinn:** Pro Name eine eigene Adresse heißt, der Server weiß aus der
  Ziel-Adresse, welcher Name gemeint war — unabhängig von SNI oder
  `Host`-Header.
- **Schwäche:** läuft im Gast. Ein Sample mit Adminrechten könnte die
  Fake-Server sehen oder die Firewall-Regel entfernen.
- **Offenes Risiko:** ob eine Adresse pro Name praktikabel ist, hängt daran,
  wie schnell `netsh` pro Adresse ist und wie viele der Adapter trägt. Das
  gehört als **Spike vor den Diverter-Entwurf** (Phase 2). Trägt es nicht,
  ist der Rückfall eine einzige Adresse mit Namenszuordnung über SNI und
  `Host`-Header — dann entfällt der Nebengewinn für rohe Protokolle ohne Namen
  im Protokoll, und der Catch-all weiß nicht mehr, wer gemeint war.

### B — Eigenes Gateway außerhalb der VM *(mitgeplant, nicht gebaut)*

Eine zweite, kleine Linux-VM hängt als Gateway im isolierten Netz und lenkt
dort mit nftables alles auf Catch-all-Server, egal welche Adresse oder welcher
Port. Deckt auch fest eingebaute IP-Adressen, und das Sample kann das
Fake-Internet nicht sehen. Preis: zweite VM, isoliertes Netz von Hand,
transportabel ist es dann kaum noch, und die Prozess-Zuordnung geht nur über
Zeit-, IP- und Port-Korrelation mit Sysmon.

**Entscheidung:** A wird gebaut, der Umlenkpunkt aber von Anfang an
austauschbar — ein `Diverter`-Protokoll mit `GuestDiverter` als erster
Implementierung. B kann später als `GatewayDiverter` dazukommen, ohne dass
Server, Analyse, Regeln oder UI sich ändern.

### C — WinDivert, wie NetLens es macht *(verworfen)*

Vollständige Abdeckung und die genaueste Prozess-Zuordnung, weil der Treiber
die Socket-Ereignisse direkt sieht. Verworfen, weil WinDivert ein
x64-Kernel-Treiber ist und es keinen ARM64-Build gibt: der Weg über UTM auf
Apple Silicon fiele komplett weg. Außerdem wäre es wieder ein gebündeltes
Fremdbinary, also genau das, was nicht gewollt ist.

## Wie es funktioniert

### Betriebsarten

Ein neues Feld im Submit-Tab, neben `Target` und `EDR Mode`:

| Modus | Netz | C2 |
|---|---|---|
| `online` *(Default, heutiges Verhalten)* | VM redet echt | echter C2 des Samples |
| `isolated` | TDC beantwortet jede ausgehende Verbindung | Listener hält den Beacon am Leben |
| `isolated+passthrough` | wie `isolated`, mit Allowlist | die Allowlist geht echt raus (dein Teamserver) |

Bei `online` ändert sich am bestehenden Ablauf **nichts** außer einer
zusätzlichen passiven Auswertung dessen, was Sysmon schon liefert.

*Nebenbei:* `#submit-edr` (`webui/templates/index.html:1574`) wird im
Frontend nirgends gelesen — ein toter Steuerknopf. Beim Einbauen des
Modus-Feldes mit aufräumen.

### Lebenszyklus einer Session

`/api/submit` ist synchron und kehrt zurück, sobald der Agent den Start
quittiert hat; TDC kennt heute kein Signal „Detonation vorbei". Die zwei
Vorbilder im Code widersprechen sich: Exit Capture nimmt ein festes Fenster
(`EXIT_CAPTURE_WINDOW = 120`, `webui/app.py:6769`), `pipe_proxy` hat
Start/Stop über die API, `max_duration` und einen Reaper.

Für Netzwerk reicht ein festes Fenster von 120 s **nicht**: ein Beacon mit
60 s Sleep liefert darin zwei Check-ins, eines mit stündlichem Sleep keines.
Intervall und Jitter zu messen ist aber das Kernversprechen. Das Fenster ist
außerdem die Zeit, in der die ganze VM vom Netz getrennt ist.

**Festgelegt: dynamisch, mit Operator-Kontrolle.** Eine feste Zahl ist bei
einem Sample, das nach vier Sekunden stirbt, zu lang, und bei einem Beacon mit
fünf Minuten Sleep zu kurz. Die Session richtet sich deshalb nach dem, was
sie beobachtet:

| Regel | Wert | Warum |
|---|---|---|
| Startbudget | 300 s | NetLens' Erfahrung: drei bis fünf Minuten, viele Familien warten vor dem ersten Kontakt |
| Ruhe-Ende | 60 s ohne Netz-Ereignis, frühestens nach 90 s | Ein Sample, das die Analyseumgebung erkannt hat und aufgibt, hält die VM nicht fünf Minuten vom Netz |
| Verlängerung | erkanntes periodisches Muster → mindestens vier Intervalle plus Puffer | Jitter lässt sich erst über mehrere Check-ins messen; das Intervall kennt die Session zu diesem Zeitpunkt selbst |
| Harte Obergrenze | 30 min, Reaper | Damit ein vergessener Lauf die VM nicht dauerhaft abschneidet |
| Operator | Stoppen und Verlängern jederzeit, Restzeit sichtbar | Die Automatik darf niemandem das Ruder aus der Hand nehmen |

Die Verlängerung ist das Stück, das eine feste Zahl nicht leisten kann: Wird
ein Beacon mit 300 s Sleep erkannt, dehnt die Session sich auf etwa 20 Minuten
statt mit zwei Datenpunkten aufzuhören. Jede Verlängerung wird geloggt und
steht im Report, damit nachvollziehbar ist, warum ein Lauf so lang war.

**Festgelegt:** Es läuft **immer nur eine** Netzwerk-Session. Ein DNS-Port 53,
eine Firewall-Regel, eine Session-CA — das lässt sich nicht für `online` und
`isolated` gleichzeitig halten. Eine zweite Einreichung wird abgelehnt,
solange eine Session läuft, nach dem Muster von `/api/lock/status` des Agents.

### Abschottung

Zur Laufzeit umschaltbar, also **im Gast per Windows-Firewall**: eine
Outbound-Block-Regel für alles, mit Ausnahmen für `198.18.0.0/15`, das
Loopback, die Service-Ports und WinRM. Die Regel trägt einen eigenen Namen und
wird beim Stop und beim nächsten Start entfernt.

Die Hypervisor-Variante (QEMU `restrict=on`, privater Hyper-V-Switch) ist die
härtere Isolation, aber eine Boot-Option und nicht pro Detonation
umschaltbar. Sie wird als Härtung dokumentiert, nicht als Mechanismus
benutzt. **Das ist bewusst ein Kompromiss:** die Firewall-Regel ist von einem
Sample mit Adminrechten entfernbar.

### Die Fake-Server

Ein Thread-Pool im UI-Prozess, Fake-Server für HTTP, HTTPS, SMTP, FTP, IMAP,
POP3, DNS-over-HTTPS, WebSocket und einen Catch-all, der unbekannte Protokolle
mitschreibt und profiliert (Framing, Trennzeichen, Entropie, Heartbeat).

Dazu glaubwürdige Antworten für die Dienste, die Malware zuerst prüft
(IP-Lookup, Geolokalisierung, Telegram, Discord-Webhooks) — sonst kommen die
Samples nie zum interessanten Teil.

**Ports:** Alle 65535 Ports zu binden ist nicht praktikabel. Gebunden wird
eine Liste gängiger Ports; sieht der Diverter einen Verbindungsversuch auf
einen anderen Port (über `GetExtendedTcpTable` im Zustand `SYN_SENT`), bindet
er ihn nach. Der TCP-Stack des Samples wiederholt den SYN über mehrere
Sekunden, was dafür reicht. Die Liste und das Nachbinden sind beides
beobachtbar und werden geloggt.

**UDP** hat kein Äquivalent zu diesem Trick — es gibt keinen Zustand, den man
vor der ersten Zustellung sieht. Entscheidung: UDP wird nur auf vorab
gebundenen Ports beantwortet (53, 123, 137, 161, 500, 1900, 5353 und die
C2-üblichen); alles andere wird als `udp`-Event geloggt, aber nicht
beantwortet. Das ist eine bewusste Lücke und steht so im Report.

### Rauschen und Baseline

Jeder Hebel in Ansatz A wirkt **maschinenweit**: DNS-Konfiguration,
Firewall-Regel, Truststore, WinHTTP-Proxy. Im abgeschotteten Modus landen
deshalb auch NCSI (`msftconnecttest.com`), Windows Update, Defender,
Zeitabgleich, Brave, LitterBox und TDCs eigener Tool-Update-Prüfer bei den
Fake-Servern — und weil die Session-CA im Maschinenspeicher liegt, nehmen
diese Clients unsere Zertifikate sogar an. Ohne Gegenmaßnahme meldet jeder
Lauf Dutzende IOCs, die Windows gehören.

**Entscheidung:** aufgenommen wird **alles**, nicht nur der Prozessbaum des
Samples. Injizierter Code, der in einem Host-Prozess läuft, ist der
interessante Fall; ein Filter auf den Prozessbaum würde genau den verlieren.
Die Trennung passiert danach, auf drei Wegen:

1. **Prozessbaum-Markierung.** Jedes Event trägt, ob es zum Sample gehört
   (Kind, injiziert, über WMI oder Task gestartet, Kopie des Samples) — wie
   `_compute_verdict` es für Alerts schon tut. Nur markierte Events zählen
   fürs Verdict, der Rest steht in den Notizen.
2. **Netzwerk-Baseline**, nach dem Muster von `_memory_baseline`
   (`webui/app.py:6744`) und `/api/memory/sweep`: eine Aufnahme auf der
   sauberen VM, die festhält, welche Namen, Ziele und Muster dort ohnehin
   auftreten. Was in der Baseline steht, wird unterdrückt und gezählt — nicht
   gelöscht.
3. **Eigene Dienste** (Tool-Updates, LitterBox, der UI-Prozess selbst) über
   eine Prozess-Allowlist ausgenommen, weil wir sie kennen.

Das ist ein eigenes Stück Arbeit und gehört in **Phase 1**, nicht
hintendran: ohne Baseline ist Phase 2 nicht benutzbar.

### TLS

Eine CA pro Session, erzeugt mit `cryptography`, pro Servername ein
Zertifikat. Die CA liegt nur für die Dauer der Session im Windows-Truststore.
Entfernt wird sie im `finally` des Session-Stops und zusätzlich beim Start der
nächsten Session, falls eine Leiche übrig ist.

### Prozess-Zuordnung

Der Fake-Server kennt Quell-Adresse und -Port der Verbindung. Direkt beim
Accept liefert `GetExtendedTcpTable` (ctypes, Muster aus
`webui/pipe_backends.py`) die PID. Fällt das Zeitfenster zu knapp aus, wird
über Zeit, Port und Ziel gegen Sysmon EID 3 korreliert
(`_sysmon_network_events`, `webui/app.py:4497`).

Der Prozessbaum kommt aus dem, was TDC schon hat (Sysmon, Graph-Tab). Ein
eigener ETW-Tracer wird **nicht** gebaut.

### Der C2-Listener

**Fremde Beacons.** Der Catch-all antwortet protokollgerecht mit „keine
Aufgabe" — bei HTTP ein `200` mit leerem Body. Das Beacon stirbt nicht,
sondern beacont weiter, und damit werden Intervall, Jitter, URI-Muster,
User-Agent und Header-Reihenfolge messbar. Bei Familien mit offen
reversiertem Protokoll (AsyncRAT, njRAT, Quasar) kann ein familienspezifischer
Responder dazukommen; das ist pro Familie Arbeit und gehört nicht in die erste
Phase.

**Eigene Beacons.** Eine Allowlist aus Host, IP und Port wird nicht gefälscht,
sondern durchgereicht — echt hinaus oder auf eine feste Adresse umgebogen
(dein Teamserver, typisch auf dem Host). Damit lässt sich tasken, während die
Telemetrie daneben mitläuft.

**Die Beacon-Config als Eingabe.** BeaconEye zieht heute schon die
Beacon-Konfiguration aus dem Prozessspeicher, inklusive `C2Server`; TDC
benutzt sie nur als Beweisstück (`from_beaconeye`, `webui/memory_evidence.py:913`). Der Listener
liest sie mit und vergleicht erwartete gegen beobachtete Werte: erwarteter
Host, erwartetes Sleep, erwarteter Jitter gegen das, was tatsächlich auf der
Leitung passiert. Eine Abweichung ist selbst ein Befund.

### Stage-Sicherung

Das größte Zugeständnis eines Fake-Internets ist, dass ein Loader seine
zweite Stufe nie bekommt: man sieht die URL und hat nichts in der Hand. Das
kehrt dieses Feature um.

Fragt ein Prozess eine Datei ab, bekommt er **sofort die Fake-Antwort** —
und daneben läuft der echte Abruf. Was zurückkommt, landet als `.bin` bei den
Artefakten des Laufs, mit Hash, Quell-URL, Größe und dem Prozess, der danach
gefragt hat. Nie geöffnet, nie ausgeführt.

**Asynchron, nicht blockierend.** Erst die echte Datei zu holen und dann zu
antworten würde die Verbindung des Loaders sekundenlang hängen lassen; manche
brechen bei Timeout ab, und dann hat man weder Stage noch Verhalten.

**Pro Detonation einschaltbar, Default aus.** Ein abgeschotteter Modus, der
im Hintergrund doch nach draußen telefoniert, wäre eine böse Überraschung.
Ist es an, sagt die UI das deutlich — im Submit-Formular und im Report.

**Die Leitung ist einstellbar:** direkter Abruf als Default, optional über
einen HTTP- oder SOCKS-Proxy, damit Tor oder ein VPN davorhängen kann.

> **Was der Abruf kostet:** Er verrät dem Betreiber, dass sein Sample
> analysiert wird. Er sieht die Adresse, von der geholt wird, kann sie
> sperren oder ab sofort etwas Harmloses ausliefern. Deshalb Default aus und
> die Leitung konfigurierbar.

**Die Kette, Stufe für Stufe.** Eine gesicherte Stage erscheint in den
Ergebnissen mit einem Knopf, sie als **eigene Detonation** zu starten. Der
neue Lauf wird mit dem verknüpft, aus dem die Stage kam: die Submission trägt
die Herkunft (Eltern-Lauf, Quell-URL, welcher Prozess sie geholt hat), und die
Ergebnisse zeigen die Kette in beide Richtungen.

Das ist bewusst **kein** Durchreichen an den Loader. Jede Stufe läuft für
sich, mit eigenem Verdict, eigener Prozesszuordnung und eigenen
Memory-Befunden — im Loader-Kontext ausgeführt wäre beides vermischt und
schwerer zu lesen. Und es bleibt eine bewusste Handlung: TDC startet nichts
von selbst nach.

Dazu eine neue Evidence-Art:

| Art | Gewicht | Klasse | Begründung |
|---|---|---|---|
| `payload_staging` | 4.0 | strukturell | Ein nachgeladenes ausführbares Objekt, als Datei belegt — nicht bloß eine URL |

> **Nachtrag (26.11.):** Diese Art ist **schon gebaut**, in Phase 1
> (`webui/memory_evidence.py:239`, Gewicht 4.0, strukturell,
> `corroborate: False`), weil ein im Mitschnitt gefundener Download sie
> ebenso braucht wie eine echt abgeholte Stufe. Phase 3 fügt sie nicht hinzu,
> sondern speist sie aus der gesicherten Stage.

### Analyse, Events und Regeln

Dieselben Event-Typen, wie sie sich aus den Protokollen ergeben: `dns`,
`conn`, `conn_failed`, `tls`, `http`, `udp`, `raw`, `ftp`, `smtp`,
`websocket`, `download`, `upload`, `decoded`, `beacon`, `retry`, `fanout`.
Die Feldnamen richten sich am bestehenden Alert-Schema (`parse_rustinel_alert`, `webui/app.py:971`)
aus. Jeder Lauf schreibt `events.json` mit allen Feldern — das ist das
Material, aus dem man Regeln schreibt.

Dazu Entschlüsselung dessen, was Malware auf die Leitung legt: Base64, Hex,
URL-kodierte Formularfelder und Antworten, aber nur wenn das Ergebnis
sinnvoll ist (Text oder ein bekannter Dateityp).

**Regeln** liegen als YAML in `rules/network/`. Die Sprache wird für TDC
entworfen (siehe Herkunft: aus NetLens wird nichts übernommen) und lehnt sich
an das an, was im Projekt schon gelesen wird — Sigma-ähnliche Feldausdrücke,
damit wer `rules/sigma/` kennt sich nicht umstellen muss. Sie braucht
Vergleiche auf Feldern, Mengenprüfungen, Zähl- und Zeitbedingungen sowie
Verknüpfungen über mehrere Regeln hinweg. Sigma selbst reicht nicht: es hat
keine Event-Kategorie für HTTP-Bodies oder dekodierte Felder.

**Die Arbeitsteilung zwischen Python und YAML, damit das eindeutig ist:**

- Die **Evidence-Arten entstehen in Python**, in eingebauten Analysatoren.
  Dort liegt die Kalibrierung, dort greifen Baseline, Supersede und
  Confidence. Die Gewichte sind nicht aus einer Regeldatei verschiebbar.
- Die **YAML-Regeln sind die erweiterbare Schicht darüber.** Ohne `kind:`
  annotiert eine Regel nur: Familie („sieht aus wie …"), ATT&CK-Technik,
  Rolle, Beschreibung, und macht einen Befund im Report lesbar. Mit einem
  optionalen `kind:` ordnet sie ihren Treffer einer bestehenden Evidence-Art
  zu — die Art bestimmt dann das Gewicht, nicht die Regel.

So bleibt die Bewertung an einer Stelle, und man kann trotzdem eine eigene
Regel für eine Kampagne schreiben, ohne Python anzufassen. `rules/` enthält
heute nur `sigma/` und `yara/`; `rules/network/` kommt mit einem
Startregelsatz dazu.

### Einhängen in das Evidence-Modell

`webui/memory_evidence.py` ist schon tool-agnostisch und hat mit
`c2_beaconing` (`:142`) und `beacon_config` (`:146`) genau die passenden
Arten. Netzwerk-Befunde kommen als neue `KINDS` dazu und werden über
`evidence_findings` eingespeist — demselben Weg, den `network_beaconing` und
`named_pipes` in `_compute_verdict` (`webui/app.py:4806`) schon nehmen.

Vorgeschlagene neue Arten (Gewichte sind Vorschläge und wollen an echten
Läufen kalibriert werden):

| Art | Gewicht | Klasse | Begründung |
|---|---|---|---|
| `c2_checkin` | 4.0 | strukturell | Ein Check-in mit Antwort, nicht bloß ein Connect |
| `exfil_upload` | 4.0 | strukturell | Daten raus, Größe und Ziel belegt |
| `credential_in_transit` | 4.5 | strukturell | Zugangsdaten im Klartext auf der Leitung |
| `fallback_rotation` | 3.0 | behavioral | Reihum durch Ersatzdomains |
| `dead_c2_retry` | 2.0 | behavioral | Wiederholte Versuche an ein totes C2 |
| `recon_service` | 1.0 | behavioral | IP-Lookup, Geolokalisierung |
| `tls_ja3_known` | 2.5 | strukturell | JA3/JA4 trifft einen katalogisierten Client |
| `dga_pattern` | 2.0 | behavioral | Namen mit DGA-Charakter, NXDOMAIN-Salven |

> **Nachtrag (26.11.):** Alle acht sind in Phase 1 gebaut, mit **genau diesen
> Gewichten und Klassen** — keine wurde verschoben. Dazugekommen ist, was die
> Tabelle nicht vorsah: `corroborate` je Art (`exfil_upload`,
> `credential_in_transit`, `dga_pattern` stehen allein; die übrigen brauchen
> eine zweite Quelle) und `supersedes` bei `c2_checkin`.
>
> **Die Kalibrierung ist damit aber nicht erledigt, sondern offen.** Phase 1
> hat nur Mitschnitte gelesen; echte Läufe, an denen die Tabelle kalibriert
> werden wollte, gibt es erst ab Phase 2. Dass die Zahlen im Code stehen,
> heißt nur, dass der Vorschlag umgesetzt wurde — nicht, dass er geprüft ist.
> Wer Phase 2 abschließt, soll sie an den ersten echten Läufen nachmessen.

**Doppelzählung muss verhindert werden, sonst bricht „ein Verdict" leise.**
`_network_beaconing_for_pid` liefert heute schon `c2_beaconing` (3.0) aus
Sysmon EID 3. Im abgeschotteten Modus sind **wir** der Grund, warum die
Check-ins gelingen — dieselbe Beacon-Schleife würde zusätzlich `c2_checkin`
(4.0) auslösen. Zusammen 7.0, über `VERDICT_MALICIOUS = 6.0`, aus einem
einzigen Phänomen. `SATURATION_CAP` greift nicht, weil es pro Art und Prozess
zählt.

Zwei Festlegungen:

- **Supersede:** `c2_checkin` absorbiert `c2_beaconing` für denselben Prozess
  und denselben Endpunkt. Die Beobachtung aus Sysmon bleibt als Bestätigung
  stehen, zählt aber nicht zweimal. Das braucht eine
  Verdrängungsbeziehung zwischen Arten, die `memory_evidence` heute nicht hat.
  > **Nachtrag (26.11.):** gebaut. `KINDS` trägt jetzt ein `supersedes`-Feld
  > (`c2_checkin` verdrängt `c2_beaconing`), und die Entscheidung fällt pro
  > zusammenhängender Gruppe über die ganze Befundmenge statt gierig — gierig
  > war nicht monoton und hing von der Reihenfolge ab.
- **Confidence je Modus:** Im abgeschotteten Modus belegen `exfil_upload` und
  `credential_in_transit`, dass das Sample es **versucht** hat — unser eigener
  Server hat die Daten angenommen, kein echtes C2. Sie bekommen dort einen
  Confidence-Faktor unter 1.0, im Online-Modus den vollen Wert.

Beides berührt ein geteiltes Modul mit eigener Testsuite
(`tests/test_memory.py`) und wirkt auf Memory- und Pipe-Verdicts zurück.
Deshalb wird es **in Phase 1 entworfen**, zusammen mit der Baseline, und nicht
in Phase 3 nachgepatcht.

### Fingerprint

Pro Lauf ein JSON-Objekt in `webui/network_fingerprints.json` (newest-first,
begrenzt, atomar geschrieben — wie `submissions.json`, `_record_submission` (`webui/app.py:853`) und `_save_submissions` (`:808`)):

- JA3 und JA4 des Clients, TLS-Versionen, Cipher-Reihenfolge
- Beacon-Intervall und Jitter, gemessen statt behauptet
- URI-Muster, User-Agent, Header-Namen in ihrer Reihenfolge
- kontaktierte Namen, normalisiert, und die Reihenfolge der ersten Kontakte
- Protokollprofil des unbekannten Verkehrs
- erwartete Werte aus der Beacon-Config, wo vorhanden

Der Vergleich ist ein Ähnlichkeitsmaß über diese Merkmale, gewichtet, mit
Begründung („deckt sich zu 94 %: gleicher JA3, gleiches URI-Muster, Intervall
30 s gegen 30 s"). **Keine Blackbox:** es muss nachlesbar sein, warum zwei
Läufe als verwandt gelten.

**Im- und Export** als ZIP mit Passwort, Default `infected`, beim Import
angebbar. Python `zipfile` kann verschlüsselte ZIPs nur **lesen** — zum
Schreiben kommt `pyzipper` (reines Python-Wheel, AES-256, also auch auf
ARM64); fehlt es, wird auf das im Gast vorhandene 7-Zip zurückgefallen
(`scripts/install-prerequisites.ps1:96`). Der Export enthält Fingerprints,
`events.json`, den pcap und die übertragenen Dateien — deshalb überhaupt das
Passwort.

**Sicherung gegen den Rollback.** Beide Vagrantfiles deaktivieren
`synced_folder` (`Vagrantfile:53`, `Vagrantfile.utm:151`), es gibt also keinen
host-sichtbaren Pfad: der Gast kann nichts auf den Host legen. Die Sicherung
muss daher vom Host **geholt** werden, über die bestehende HTTP-Schnittstelle
(`WEBUI_URL`, `Makefile:56`):

- `make submit FILE=…` holt nach dem Lauf automatisch ab und legt die Datei
  host-seitig ab. Für den CLI-Weg ist damit nichts zu vergessen.
- `make fingerprints-pull` holt alles, was noch nicht gesichert ist — für
  Läufe, die über die Web UI gestartet wurden.
- Die Web UI zeigt im NETWORK-Tab an, **wie viele Läufe ungesichert** sind,
  mit dem Befehl zum Abholen daneben. Ein Zähler, der nicht auf Null steht,
  ist die Erinnerung, die ein Export-Knopf allein nicht leistet.

Beides gehört in `Makefile`, `make.ps1` und — wenn eine neue Datei entsteht —
in `scripts/deploy-utm.py`.

**Ehrlich dazugesagt:** vollständig automatisch wäre nur, was ohne Host
läuft. Solange die Web UI im Gast sitzt und es keinen gemeinsamen Ordner gibt,
ist „automatisch" auf die Wege begrenzt, an denen der Host beteiligt ist. Der
Zähler schließt die Lücke, indem er sichtbar macht, was fehlt.

### Artefakte pro Lauf

```
C:\dumps\network\<zeit>_<sha256-prefix>\
  capture.pcap        selbst geschrieben: was das Sample sendete, wie es auf
                      einem echten Netz aussähe
  events.json         jedes Event mit allen Feldern
  report.json         Befunde, IOCs, Fingerprint, Herkunft der Kette
  files\*.bin         was über die Leitung ging, nie geöffnet, nie ausgeführt
  stages\*.bin        echt abgeholte zweite Stufen, mit Quell-URL und Hash
                      in report.json, nie geöffnet, nie ausgeführt
  session.log
```

Gekürzt wie die anderen Sammlungen (`NETWORK_KEEP`, Muster
`_exit_capture_prune`, `webui/app.py:6896`).

## UI

Gewählt wurde die Rollenteilung: **Panel im Submit-Tab plus eigener
NETWORK-Tab**.

### Panel im Submit-Tab

In `renderDetonationPanels()` (`webui/static/js/app.js:9715`) ein Eintrag
`Network` im `tabs`-Array, und im Ergebnisbereich ein kompaktes Panel neben
`LIVE MEMORY`: was beantwortet wurde, was der C2-Listener getan hat, was
**nicht** beantwortet wurde (die festen IP-Adressen), und der
Fingerprint-Vergleich mit einem Link in den Tab. Das ist die Antwort auf „was
ist passiert?" an der Stelle, wo man nach dem Detonieren sowieso hinschaut.

Dazu die **gesicherten Stages**, wenn es welche gibt: Quell-URL, Hash, Größe,
der Prozess, der sie geholt hat, und der Knopf, die Stage als eigene
Detonation zu starten. Kam der Lauf selbst aus einer Stage, steht die Herkunft
oben — welcher Lauf, welche URL.

### NETWORK-Tab

Neuer Top-Level-Tab zwischen `PIPES` und `SYSMON`, mit Unterkarten:
`OVERVIEW`, `CONNECTIONS`, `DNS`, `HTTP`, `TLS`, `FILES`, `IOCs`,
`FINGERPRINT`. Dort liegt die Tiefe: Streams, TLS im Klartext, dekodierte
Felder, IOC-Liste, Fingerprint-Vergleich, Im- und Export — und der Import
eines fremden pcap, der durch dieselbe Analyse läuft. `FILES` trennt dabei,
was über die Leitung ging, von den **echt abgeholten Stages**, und zeigt die
Kette der Läufe, die daraus entstanden sind.

### Tracing

`HTTP REQUESTS`, `CONNECTIONS` und `DNS REQUESTS`
(`webui/templates/index.html:407-409`) ziehen aus derselben Quelle, statt
weiter auf `0` zu stehen. Die Heuristik, die heute Netzwerk-Events nach Port
80/443 filtert (`renderRtraceEventTable`, `webui/static/js/app.js:5421`), wird durch echte HTTP-Events
ersetzt, wo es welche gibt.

### Pflichten beim neuen Tab

Aus `docs/superpowers/plans/2026-11-22-syscalls.md:1086` (Task 11, „Tab und Karte“): Tab-Button und
`tab-content` mit `data-info`, Eintrag in `#help-usage` an derselben Position,
neue Routen in `#help-api`, `?v=`-Versionen hochzählen, Farben nur über
`themeColor()`, Werte in `style.css :root` **und**
`theme-cyberpunk.css`, Formen in `theme-layout.css`, Zeile in der
README-Tabelle `### Web UI Tabs` in derselben Reihenfolge, jede Route genau
einmal in der API-Tabelle, neue Dateien in alle drei Deploy-Pfade
(`scripts/deploy-utm.py:39`, `Makefile` `deploy`, `make.ps1` `'deploy'`).

Diese Tests brechen garantiert und müssen mit:
`tests/test_theme.py:3136` (Tab-Zahlen), `tests/test_docs.py:116`, `:128`,
`:138`, `tests/test_frontend.py:148`.

## Herkunft: NetLens ist Vorbild, nicht Quelle

**Entscheidung des Betreibers: aus NetLens wird nichts übernommen.**
Apache-2.0-Material soll gar nicht einfließen. Das ist strenger als die Lizenz
verlangt und macht die Sache einfach: **keine Datei, kein Codefragment, keine
Regel, kein Fixture** aus NetLens wird kopiert, angepasst oder übersetzt.

> **Nachtrag (26.11.):** Bei dieser Entscheidung war TDC noch lizenzlos und
> privat. `main` hat seither eine `LICENSE` eingebracht — TDC ist MIT und
> öffentlich. An der Entscheidung ändert das nichts, aber am Gewicht: was im
> privaten Repo eine Vorsichtsmaßnahme war, ist im veröffentlichten
> MIT-Projekt eine Aussage, auf die sich Dritte verlassen.

Was dennoch unproblematisch ist, weil es nicht NetLens gehört:

- **Die Event-Typen** (`dns`, `conn`, `tls`, `http`, `ftp`, `smtp`, …) folgen
  aus den Protokollen selbst, nicht aus NetLens. Die Feldnamen werden aus
  TDCs eigenen Daten abgeleitet und am bestehenden Alert-Schema
  (`parse_rustinel_alert`, `webui/app.py:971`) ausgerichtet, nicht an NetLens' Schema.
- **`198.18.0.0/15`** ist RFC 2544, kein fremdes Werk.
- **Der Ansatz** — Namen fälschen, Protokolle beantworten, TLS terminieren,
  Verhalten über Zeit bewerten — ist Allgemeingut der Malware-Analyse
  (FakeNet-NG, INetSim gehen genauso vor).

Die YAML-Regelsprache wird **neu entworfen**, nach TDCs eigenen Bedürfnissen,
nicht als Nachbau von NetLens' Format. Sie lehnt sich stattdessen an das an,
was im Projekt schon gelesen wird: Sigma-ähnliche Feldausdrücke, damit wer
`rules/sigma/` kennt sich nicht umstellen muss. Der Startregelsatz in
`rules/network/` wird aus eigenen Läufen geschrieben — aus dem `events.json`,
das Phase 1 produziert.

**In die README gehört trotzdem ein Satz**, dass NetLens die Idee geliefert
hat. Rechtlich nicht gefordert, wenn nichts übernommen wird, aber richtig.

Nicht nachgebaut wird ohnehin: Qt-GUI, WinDivert und alles darauf, ein eigener
ETW-Tracer, eine eigene Memory-Inspektion — Prozessbaum und Memory hat TDC
schon, und doppelt wäre schlechter als einmal.

> **Nebenwirkung der Lizenzlage — inzwischen entschieden:** Ohne
> `LICENSE`-Datei wäre TDC „alle Rechte vorbehalten" gewesen, und das schließt
> auch aus, dass andere beitragen. `main` hat die Wahl bewusst getroffen: MIT.

## Phasen

Die Teile hängen voneinander ab, deshalb eine Reihenfolge, nicht vier
Projekte:

1. **Sehen, ohne zu fälschen.** Analyse, Events, Protokoll-Parser,
   Regel-Engine, pcap-Import, NETWORK-Tab — und die beiden Umbauten, die
   später nicht nachzuholen sind: die **Netzwerk-Baseline** und die
   **Supersede/Confidence-Erweiterung** in `memory_evidence`. Prüfbar an
   fremden pcaps, ohne VM und ohne Risiko.
2. **Das Fake-Internet.** Zuerst der Spike zur Adressvergabe, dann Diverter,
   DNS, Fake-Server, TLS, Prozess-Zuordnung, Modus im Submit-Tab,
   Session-Steuerung, Aufräumen.
3. **Der C2-Listener und die Stage-Sicherung.** Am Leben halten, Allowlist
   zum Durchreichen, Beacon-Config als Eingabe — und der echte Abruf der
   zweiten Stufe samt Verkettung zu einer eigenen Detonation.
4. **Fingerprint.** Merkmale, Vergleich, Im- und Export als
   passwortgeschütztes ZIP.

Phase 1 ist für sich nützlich: sie macht die drei leeren Tracing-Unterkarten
lebendig und erlaubt, fremde pcaps auszuwerten.

## Was dem Builder überlassen bleibt

- Die Aufteilung in Module. Vorschlag: `webui/net_capture.py` (Diverter,
  Server, Session), `webui/net_analyze.py` (Flows, Parser, Dekodierung),
  `webui/net_rules.py` (Regel-Engine), `webui/net_fingerprint.py`.
  > **Nachtrag (26.11.):** Phase 1 hat feiner geteilt als vorgeschlagen.
  > `net_analyze.py` ist nur die Orchestrierung; Flows, Parser und
  > Dekodierung liegen je für sich (`net_flows`, `net_events`, `net_dns`,
  > `net_http`, `net_tls`, `net_mail_ftp`, `net_raw`, `net_decode`), dazu
  > `net_behavior`, `net_evidence` und `net_baseline`. `net_rules.py` heißt
  > wie vorgeschlagen. `net_capture.py` (Phase 2) und `net_fingerprint.py`
  > (Phase 4) gibt es noch nicht.
- Die Liste der vorab gebundenen Ports und die glaubwürdigen Antworten.
- Die Gewichte der neuen Evidence-Arten — die Tabelle oben ist ein
  Startpunkt, kalibriert wird an echten Läufen.
- Die Merkmalsgewichte des Ähnlichkeitsmaßes.
- Ob der pcap mit `dpkt` geschrieben oder von Hand serialisiert wird.

## Entscheidungen, die ich getroffen habe

Ohne dass danach gefragt wurde, als Vorschlag erkennbar:

- Abschottung per Windows-Firewall statt per Hypervisor, damit sie pro
  Detonation umschaltbar ist — mit der Schwäche, dass Admin-Malware sie
  entfernen kann.
- `online` bleibt der Default, damit niemand ungewollt in einem anderen
  Netzmodell landet.
- Immer nur eine Netzwerk-Session gleichzeitig.
- Die Stage-Sicherung ist pro Detonation einschaltbar und standardmäßig
  **aus**, mit einstellbarer Leitung (direkt oder über Proxy). Der echte
  Abruf verrät dem Betreiber die Analyse — das darf nicht unbemerkt
  passieren.
- Eine gesicherte Stage wird dem Loader nie durchgereicht, sondern als eigene
  verknüpfte Detonation angeboten; TDC startet sie nicht von selbst.
- Aufgenommen wird alles, getrennt wird danach: Prozessbaum-Markierung,
  Netzwerk-Baseline, Allowlist für TDCs eigene Dienste.
- Supersede zwischen Evidence-Arten und ein Confidence-Faktor je Modus, beides
  in Phase 1 entworfen statt später nachgepatcht.
- Evidence-Arten entstehen in Python, YAML-Regeln annotieren und ordnen zu.
- Sekundäre Adressen auf dem echten Adapter mit `skipassource=true`; eine
  Adresse pro Name steht unter Spike-Vorbehalt.
- UDP nur auf vorab gebundenen Ports.
- Eigene YAML-Regeln nur für Netzwerk-Events, Host-Verhalten bleibt bei Sigma.
- Die Regelsprache lehnt sich an Sigma an, nicht an NetLens — weil aus
  NetLens nichts übernommen wird und `rules/sigma/` im Projekt schon gelesen
  wird.
- Kein eigener ETW-Tracer und keine eigene Memory-Inspektion.
- `pyzipper` als Weg zum verschlüsselten ZIP, 7-Zip als Rückfall.
- „Automatisch" bei der Fingerprint-Sicherung heißt: der Host holt ab, wo er
  beteiligt ist, und ein Zähler zeigt, was noch fehlt. Ohne gemeinsamen
  Ordner geht mehr nicht.
- Austauschbare Nähte für Firewall, Truststore und TCP-Tabelle, obwohl beide
  VMs verfügbar sind — damit die Logik host-seitig testbar bleibt.
- Die Passthrough-Allowlist ist ein freies Feld in der UI, nicht eine
  server-seitig vorgenehmigte Liste. Die UI hat kein Login, darf aber schon
  heute Malware starten (`webui/app.py:88`: „lab tool on an isolated
  network"); eine strengere Regel nur für die Allowlist wäre inkonsistent.
- Der tote `#submit-edr`-Knopf wird beim Einbauen des Modus-Feldes aufgeräumt.

## Noch offen

Nichts. Die vier Punkte, die der Betreiber entscheiden musste, sind
beantwortet und oben eingearbeitet:

| Frage | Antwort |
|---|---|
| Wann endet eine Session? | Dynamisch, Startbudget 300 s, Ruhe-Ende, Verlängerung am erkannten Intervall, Obergrenze 30 min, Operator kann jederzeit stoppen und verlängern |
| Lizenz von TDC | Zur Zeit der Antwort: keine, privat. Inzwischen MIT und öffentlich (`LICENSE` aus `main`) — aus NetLens wird weiterhin **nichts** übernommen |
| VM zum Verifizieren | Beide, UTM/ARM64 und Hyper-V/x64 |
| Fingerprints gegen Rollback | Host holt automatisch ab, plus Zähler für ungesicherte Läufe |

## Prüfen und verifizieren

Beide Hypervisoren stehen zur Verfügung, also gibt es echte Rauchtests —
und sie sind nötig, weil x64 und ARM64 sich beim Netz anders verhalten
können (sekundäre Adressen, `GetExtendedTcpTable` unter Emulation,
Firewall-Regeln).

Trotzdem bleiben die OS-Berührungen hinter austauschbaren Nähten:
`Diverter`, Firewall, Truststore und die TCP-Tabelle bekommen je ein
schmales Protokoll mit einer Attrappe für die Tests. Nicht aus Zwang,
sondern weil `tests/` host-seitiges pytest ist und bleiben soll: die Logik
gehört dorthin, die VM prüft das Zusammenspiel. Dieselbe Naht trägt später
`GatewayDiverter` für Ansatz B.

Pro Phase ein Rauchtest-Skript, auf beiden Plattformen zu fahren, mit einem
harmlosen Testprogramm statt eines Samples für alles außer dem letzten
Schritt.
