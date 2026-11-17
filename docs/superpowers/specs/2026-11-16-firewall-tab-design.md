# Tab „FIREWALL“: Verbindungen sehen, kappen und Samples greifen – Design

## Absicht

Der Chamber soll zeigen, mit wem eine Probe spricht, und es soll möglich sein,
darauf zu reagieren, während sie läuft. Vorbild ist Little Snitch: ein Prozess,
darunter seine Endpunkte, je mit Allow/Deny, dazu eine Weltkarte der Ziele.

Drei Dinge treiben das:

1. **C2 erkennen.** Beaconing, hartkodierte IPs, DGA-Namen, Dead-Drop-Dienste —
   sichtbar und markiert, nicht nur als Zeile im Log.
2. **Dropper entwaffnen.** Wenn ein detonierter Loader Stage 2 holen will, soll
   das Sample bei TDC landen, aber **nie beim Loader**. Es wird gesichert, nicht
   ausgeführt.
3. **Informiert bleiben und eingreifen.** Ein Toast mit ACCEPT/DECLINE, und ein
   **Isolated**-Modus, der jeden Weg nach außen zumacht außer dem, was TDC
   selbst zum Arbeiten braucht.

Dazu Hinweise, wie man mit dem Gesehenen im Tab LOGS weiterjagt, und ein Klick,
der genau dorthin wechselt — mit gesetzter Query und gesetztem Zeitfenster.

## Ziele

- Ein Reiter `FIREWALL` mit Prozessbaum, Weltkarte und Summary.
- Jede Verbindung mit ihrer Bewertung: woher sie kommt, wohin sie geht, was
  daran verdächtig ist.
- Kappen und Sperren aus der Oberfläche, pro Verbindung, pro Endpunkt, pro
  Prozess.
- `Isolated`: alles nach außen dicht, TDC bleibt bedienbar.
- Beim Download eines detonierten Prozesses: Toast mit Entscheidung, und auf
  Wunsch holt TDC die Datei selbst und legt sie weg.
- Perspektivwechsel in LOGS auf Klick, plus Hunting-Hinweise im Tab.

## Nicht-Ziele

- **Kein Kernel-Treiber.** Ein echtes „frag vor dem Connect“ für alle
  Protokolle bräuchte einen WFP-Callout-Treiber. Verworfen (siehe Approaches).
- **Kein PCAP.** Keine Paketmitschnitte, kein tshark, kein npcap.
- **Keine Städte auf der Karte.** Land und AS-Organisation, nicht „Manchester“.
- **Keine Online-Abfragen.** Kein VirusTotal, kein RDAP, kein passives DNS. Die
  Chamber fragt niemanden nach einer IP, die sie gerade von Malware gesehen hat.
- **Kein zweiter Alerts-Tab.** Signaturtreffer bleiben in ALERTS; FIREWALL zeigt
  sie nur als Markierung an der Verbindung.
- **Kein Ausführen gesicherter Samples.** Auch nicht auf Knopfdruck. Wer eine
  Capture detonieren will, lädt sie im Tab SUBMIT bewusst neu hoch.

## Anti-Ziele

Das Projekt ist gescheitert, auch wenn es technisch funktioniert, wenn:

- der Toast so oft kommt, dass er weggeklickt wird (hunderte Verbindungen pro
  Detonation);
- ein Klick auf DENY oder Isolated dem Analysten den eigenen Zugang zur Chamber
  abschneidet;
- die Karte schön ist, aber nichts weiter führt;
- der Toast „will verbinden“ behauptet, wo die Verbindung längst stand;
- eine gesicherte Capture aus Versehen doch läuft.

## Randbedingungen

Aus dem Bestand, nicht verhandelbar:

- **Keine Fremdbibliothek, kein CDN.** Die Oberfläche zeichnet ihre Diagramme
  selbst als SVG. Die Weltkarte auch.
- **Zwei Themes.** Farbliterale nur in `:root` von `style.css`, sonst `var(--…)`.
  Canvas-Zeichnungen über `themeColor()` neu malen; SVG färbt sich selbst um.
- **Alles aus der VM ist Malware-Text** und wird escaped. URLs werden nie zu
  einem `<a href>`.
- **Python nur mit Bordmitteln.** `webui/requirements.txt` hat vier Zeilen und
  bleibt bei vier (Flask, requests, watchdog, pefile). Der Proxy in Teil B
  kommt mit `socket`, `ssl`, `http.client`.
- **Pflichten eines neuen Tabs** (von Tests erzwungen): README-Tabellenzeile in
  Nav-Reihenfolge, Help-Eintrag in derselben Reihenfolge, `data-info` ≤ 300
  Zeichen, API-Zeilen in README *und* `#help-api`, neue `webui/*.py` in allen
  drei Deploy-Pfaden (`Makefile`, `make.ps1`, `scripts/deploy-utm.py`), `?v=`
  erhöhen, Zählwerte in `tests/test_theme.py` (12 → 13 Content-Header, 14 → 15
  Tab-Contents).

Aus der Umgebung:

- Der Gast hängt an NAT (Hyper-V Default Switch, UTM „Shared“ 192.168.64.0/24,
  QEMU SLIRP 10.0.2.0/24) und hat Internet. Der Host erreicht das Web-UI auf
  Port 9000 **eingehend**; eine Ausgangssperre trifft das nicht.
- TDC braucht zur Laufzeit nach außen: **nichts**, außer die Tool-Updates
  (api.github.com, download.sysinternals.com, chocolatey, winget, `git fetch`).
  Alles andere läuft über Loopback (Detonator 8000, Agent 8080, LitterBox 1337,
  Fibratus 8180).
- Das Web-UI läuft als SYSTEM, `%TEMP%` ist `C:\WINDOWS\TEMP`.

## Approaches

Die Achse ist: **wie sitzt TDC im Netzpfad?**

| | A · Beobachten und kappen | B · TDC im Pfad (Proxy) | C · WFP-Callout-Treiber |
|---|---|---|---|
| Erkennung | Sysmon 3/22, `pfirewall.log`, PowerShell 4104, BITS | der Proxy sieht alles selbst | Kernel, alle Protokolle |
| Zeitpunkt | **nachher**, ~1 s | **vorher**, hält die Anfrage | vorher |
| URL sichtbar | nur bei Skript-Loadern | immer (HTTP/S) | nein (nur IP:Port) |
| Bytes pro Prozess | nein | ja | ja |
| Durchsetzung | `New-NetFirewallRule` | Antwort ersetzen + Firewall | Kernel-Verdict |
| Preis | — | MITM-CA im Gast, von Malware erkennbar | signierter Treiber |

**C ist verworfen.** Nur ein eigener Kernel-Treiber kann auf Windows wirklich vor
dem Connect fragen. Treiberentwicklung, Signatur, Risiko für die VM — steht in
keinem Verhältnis zum Gewinn gegenüber B.

**Gewählt: A, dann B**, als zwei Lieferungen hinter derselben Oberfläche. A
bringt Tab, Karte, Markierung, Isolated, Perspektivwechsel und das
Dropper-Capture für Skript-Loader vollständig und ist für sich testbar. B schiebt
sich dahinter: Tab, API-Form und Toast-Komponente bleiben, es ändern sich nur
Wortlaut und Genauigkeit.

---

# Teil A · Beobachten und kappen

## Woher die Daten kommen

**Entscheidung — eigener Store, nicht der von LOGS.** Der `netflow`-Ring im
LOGS-Store ist für diesen Zweck verlustbehaftet: er bündelt sofort und wird bei
jedem Tick komplett ersetzt (`replace_netflows`), und er liest nur EID 3 und 22.
Der Tab braucht aber **Einzelverbindungen** (für die Beaconing-Erkennung, die
`(ts, ip, port)` je Verbindung erwartet) und **EID 1** (Startzeit, Elternkette,
Kommandozeile — für `newborn`, `detonated` und `download`).

Also ein eigenes `webui/firewall_store.py` mit eigenen `EventRecordID`-Cursorn
für EID 1, 3 und 22, eigenem Ring (50 000 Verbindungen, 7 Tage) und eigenem
Thread. `log_store.py` und seine `SOURCES` bleiben unangetastet — die LOGS-Tests
sollen von diesem Projekt nichts merken. Doppeltes Lesen derselben Ereignisse
ist der Preis; es sind zwei `wevtutil`-Aufrufe alle 10 s.

Der schnelle Takt (1 s im Detonations-Fenster) ist derselbe Thread mit kürzerem
Schlaf, kein zweiter — `tick` ist nicht threadsicher, und das soll so bleiben.

**Entscheidung — BITS.** Der BITS-Kanal ist heute nur eine Abfrage auf Zuruf.
Der Firewall-Collector liest ihn im Detonations-Fenster mit (EID 59/60, `url`),
außerhalb nicht. Es ist eine Quelle für den Download-Fall, keine Dauerlast.

**Entscheidung — TDCs eigener Verkehr.** Eine Selbstausschluss-Liste: das
`python.exe` der Web-UI-venv, Detonator, DetonatorAgent, LitterBox, Fibratus,
Rustinel, der Pipe-Proxy, `git.exe`. Diese Prozesse werden **nie automatisch
gesperrt** und lösen **nie** einen Toast aus. Sie verschwinden aber nicht: sie
stehen in einer eingeklappten Gruppe `TDC` im Baum und werden normal getaggt —
ein blinder Fleck, in den man Code injizieren kann, wäre schlimmer als etwas
Rauschen. Spricht TDCs python zu einem Endpunkt, der nicht auf seiner kurzen
Erwartungsliste steht (Loopback, api.github.com, download.sysinternals.com,
chocolatey, winget, die Fetch-Ziele), gibt es ein Tag `tdc-anomaly` mit hohem
Schweregrad.

## Das Verbindungsmodell

Eine **Verbindung** im Tab ist ein gebündelter Flow, nicht ein einzelnes
Sysmon-Ereignis. Schlüssel wie beim bestehenden `netflow` im LOGS-Store, ohne
Quellport:

```
(image, pid, protocol, src_ip, dst_ip, dst_port)
```

Felder:

| Feld | Herkunft |
|---|---|
| `image`, `pid`, `protocol`, `src_ip`, `dst_ip`, `dst_port` | Sysmon EID 3 |
| `count`, `first_seen`, `last_seen` | Bündelung |
| `dst_hostname` | Sysmon `DestinationHostname`, sonst aus der EID-22-Karte (s. u.) |
| `fw_records`, `fw_allowed`, `fw_dropped` | `pfirewall.log`, gleicher Schlüssel |
| `geo` | `{cc, country, lat, lon, asn, as_org, scope}` aus der Offline-Tabelle |
| `tags` | die Markierung (s. u.), je mit Schweregrad |
| `state` | `allowed` \| `blocked` \| `pending` |
| `rule_id` | die TDC-Regel, die sie sperrt, falls `blocked` |
| `capture_ids` | gesicherte Samples zu dieser Verbindung |

**Entscheidung — Namen zu IPs:** `DestinationHostname` ist bei Sysmon oft leer.
Aus EID 22 (`QueryName` → `QueryResults`) wird eine IP→Name-Karte gebaut
(letzter Gewinner, 20 000 Einträge, TTL 24 h) und als Fallback benutzt. Das ist
gleichzeitig die Grundlage für die Markierung `direct-ip`.

**Entscheidung — wie `pfirewall.log` angehängt wird.** Das Firewall-Log hat
keinen Imagenamen und in der Vorgabespalten-Belegung auch keine PID. Der Join
geht deshalb nur über das Vierer-Tupel `(protocol, src_ip, dst_ip, dst_port)`,
Protokollschreibweise normalisiert (`tcp`/`TCP`/`6`). Die Zahlen gehören damit
dem **Endpunkt**, nicht dem Prozess: `fw_records`, `fw_allowed` und
`fw_dropped` stehen in der Endpunkt-Gruppe, nicht in der Prozesszeile, die
Spalte heißt `FW (Endpunkt)`, und das Tag `dropped` sitzt am Endpunkt. Sonst
behauptete die Oberfläche, Prozess X sei abgewiesen worden, obwohl es Prozess Y
war.

**Entscheidung — keine Byte-Zahlen in Teil A.** Das Mockup zeigt „3,2 MB
gesendet“; diese Zahl gibt es aus Sysmon nicht, und das `size`-Feld von
`pfirewall.log` ist pro Datensatz und meist `-`. Echte Zähler bräuchten eine
Echtzeit-ETW-Sitzung auf `Kernel-Network` — das ist Teil B über den Proxy. Teil A
zeigt stattdessen **Verbindungen und Firewall-Datensätze**; die Balken im
Prozessbaum und die Linienbreite auf der Karte skalieren mit `count`. Die
Summary sagt in einem Satz, warum dort keine Bytes stehen.

**Entscheidung — Aktualität:** der bestehende Collector tickt alle 10 s. Im
Detonations-Fenster (es gibt eine Submission mit laufendem PID) tickt ein
zusätzlicher, schlanker Lauf nur für EID 3/22 **jede Sekunde**, höchstens 60 s
über das Ende hinaus. Außerhalb bleibt es bei 10 s.

## Geo, offline

**Entscheidung — Quelle:** `ip2asn-v4.tsv` und `-v6` von iptoasn.com (CC0,
abgeleitet aus RouteViews). Eine Datei liefert Bereich → ASN, AS-Name **und**
Ländercode. Keine Lizenzfalle, frei weiterverteilbar.

**Entscheidung — Form im Repo:** `webui/data/ip2asn-v4.tsv.gz` und `-v6.tsv.gz`
(~1,5 MB zusammen) liegen **im Git**. Das ist der ganze Sinn der Sache: ein
frischer Clone kann offline Geo auflösen, und Provisioning braucht dafür kein
Internet. `make geoip` holt sie nur neu. Beim ersten Start baut
`webui/geoip.py` daraus eine Binärdatei mit festen Satzlängen (`start`, `end`,
`asn`, `cc`) nach `%TEMP%\tdc-geoip\` und liest sie per `mmap` + `bisect` — nicht
neben die Quelle, denn das Installationsverzeichnis wird von `deploy`
überschrieben. Neu gebaut wird nur, wenn Größe oder mtime der Quelle sich
geändert haben. Kein messbarer Speicherverbrauch, Lookup in µs. AS-Namen stehen
in einer eigenen kleinen Tabelle, nur bei Bedarf geladen.

**Entscheidung — fehlen die Dateien,** arbeitet der Tab weiter: Baum, Tags,
Sperren und Perspektivwechsel brauchen kein Geo. Die Karte zeigt dann die
Landmaske mit dem Hinweis „keine Geo-Daten — `make geoip`“, und `geo` ist in der
API `null`. Die Tests bringen eine winzige eigene Tabelle als Fixture mit,
damit `tests/test_firewall.py` den Lookup auf macOS prüfen kann, ohne die große
Datei zu lesen.

**Entscheidung — Deploy.** `webui/data/` ist das erste Datenverzeichnis, das
mitgeliefert werden muss. Die drei Deploy-Pfade kopieren heute einzelne
benannte Dateien; sie bekommen das Verzeichnis als Ganzes dazu — eine Zeile pro
Pfad, vom bestehenden Doku-Test erfasst.

**Entscheidung — Koordinaten:** eine Tabelle Ländercode → Name, Schwerpunkt
(lat/lon) und Region, ~250 Zeilen, direkt im Repo (`webui/data/countries.tsv`).
Mehrere Endpunkte im selben Land würden übereinander liegen; sie werden
**deterministisch aus der IP gestreut** (Hash → Winkel und Radius bis ~2°), damit
dieselbe IP immer am selben Fleck sitzt.

**Entscheidung — nicht öffentliche Adressen:** RFC1918, Loopback, Link-Local,
CGNAT und Multicast bekommen `scope: local` und erscheinen **nicht** auf der
Karte, sondern in einer eigenen Gruppe „lokal“ im Prozessbaum.

## Markierung: was gilt als verdächtig

Reine Funktionen in einem neuen Modul `webui/firewall.py` — ohne I/O, ohne
Windows, damit sie unter pytest auf macOS laufen. Eingabe: die gebündelten
Flows, die DNS-Karte, die Alert-Liste, die Submissions, die IOC-Listen.

| Tag | Schweregrad | Bedingung |
|---|---|---|
| `ioc` | kritisch | `dst_ip` in `ioc/ips.txt` oder `dst_hostname` in `ioc/domains.txt` (Rustinel-Listen, liegen schon da) |
| `beacon` | kritisch | `memory_evidence.beaconing_from_connections` findet einen Rhythmus (bestehender Code, wiederverwendet) |
| `sigma` | hoch | ein Rustinel-/Fibratus-Alert nennt dieses `ip:port` (`raw.destination.*`, `raw.network.destination.*`) |
| `detonated` | hoch | der Prozess oder ein Vorfahr ist eine Submission (bestehende PID→Submission-Fenster) |
| `direct-ip` | hoch | weder eine DNS-Antwort in der Karte noch Sysmons eigenes `DestinationHostname` erklärt diese IP — hartkodiertes Ziel. Sysmon füllt das Feld aus dem DNS-Cache, ein gesetzter Name ist also Beleg, dass ein Name im Spiel war; ohne diese Ausnahme würde jede zwischengespeicherte Auflösung als „hartkodiertes C2" durchgehen |
| `download` | hoch | zu dieser Verbindung wurde eine URL auf eine ausführbare Datei gesehen |
| `lolbin` | mittel | `image` in der LOLBin-Liste (certutil, bitsadmin, mshta, regsvr32, rundll32, curl, wscript, powershell …) |
| `dga` | mittel | der auflösende Name hat hohe Entropie oder viele Ziffern. **Nicht** „blieb ohne Ergebnis": wo keine Antwort kam, gibt es keine Adresse und damit keine Verbindung zum Markieren — unauflösbare DGA-Namen zeigt der Hunting-Hinweis `source=dns result="-" \| top query` |
| `risky-tld` | mittel | `.onion`, `.bit`, `.top`, `.xyz`, `.tk`, `.ml`, `.ga`, `.cf` |
| `dead-drop` | mittel | bekannter Ablage-Dienst (telegram, pastebin, discord, raw.githubusercontent, transfer.sh …) |
| `rare-port` | mittel | Port außerhalb der üblichen Liste, oder einer der Klassiker 4444/5555/6666/8888/9999/31337 |
| `newborn` | niedrig | der Prozess lief weniger als 60 s, als die Verbindung entstand |
| `dropped` | info | die Firewall hat Pakete verworfen |

Die Farbe einer Zeile und einer Kartenlinie ist der höchste Schweregrad ihrer
Tags. Die Schwellen (Entropie, Ports, Listen) stehen als Konstanten oben im
Modul, nicht verstreut.

**Entscheidung:** die Listen (LOLBins, Dead-Drops, TLDs, Ports) stehen in
`webui/firewall.py` als Literale, nicht in einer Konfigurationsdatei. Sie ändern
sich selten, und eine Datei mehr wäre eine Datei, die niemand pflegt.

## Durchsetzung

Ein eigenes Modul `webui/firewall_rules.py` für alles mit Nebenwirkung —
getrennt von der reinen Bewertung, damit Tests die eine Hälfte ohne Windows
prüfen können.

Jede Regel trägt den Namenspräfix `TDC-FW-`, damit sie auffindbar und als Ganzes
entfernbar ist.

| Aktion | Umsetzung |
|---|---|
| Endpunkt sperren | `New-NetFirewallRule -DisplayName "TDC-FW-<id>" -Direction Outbound -Program <image> -RemoteAddress <ip> [-RemotePort <p> -Protocol <t>] -Action Block` |
| Endpunkt für alle sperren | dasselbe ohne `-Program` — eigener Knopf, nicht die Vorgabe |
| Prozess sperren | `-Program <image>` ohne `-RemoteAddress` |
| Sperre lösen | `Remove-NetFirewallRule -DisplayName "TDC-FW-<id>"` |
| Prozess beenden | `taskkill /PID <pid> /F` — der Hammer, eigener Knopf |
| Isolated an/aus | `Set-NetFirewallProfile -All -DefaultOutboundAction Block` plus Ausnahmen |

**Entscheidung — die automatische Sperre gilt dem Loader, nicht dem Endpunkt.**
In der Windows-Firewall schlägt eine Block-Regel jede Allow-Regel. Eine Sperre
auf `-RemoteAddress <ip>` ohne `-Program` würde deshalb auch TDCs eigenen
Fetcher aussperren — genau den, der die Datei gleich holen soll. Die
automatische Sperre bekommt daher immer `-Program <image des Loaders>`. „Für
alle Prozesse sperren“ gibt es als zweiten, ausdrücklichen Knopf, und solange so
eine Regel steht, ist `KAPPEN + SELBST HOLEN` an diesem Endpunkt ausgegraut mit
dem Grund im Tooltip.

**Entscheidung — wie eine stehende Verbindung stirbt.** Eine Ausgangs-Blockregel
greift in WFP sofort, auch auf einen laufenden Flow. Es gibt kein RST: die
Verbindung verhungert. Aus Sicht der Malware sieht das wie ein Netzausfall aus —
genau richtig, denn ein RST verrät, dass jemand zugehört hat. Der Toast sagt das
so.

**Entscheidung — ist die Firewall aus, beißt keine Regel.** Mit abgeschaltetem
Profil gehen `New-NetFirewallRule` und `DefaultOutboundAction` durch, ohne zu
wirken — die Oberfläche würde `blocked` zeigen, und nichts wäre gesperrt. Das
ist der schlimmste denkbare Fehler dieses Tabs. Also:

- `firewall_rules.py` prüft die Profile (der Code dafür existiert:
  `_firewall_is_off()`), bevor er irgendetwas anbietet.
- Ist ein Profil aus, sind `ISOLATED` und alle Deny-Schalter **deaktiviert**,
  mit dem Grund im Tooltip, und der Kopf trägt ein rotes Band
  `Windows-Firewall ist aus — keine Durchsetzung möglich`.
- Daneben ein Knopf `Firewall einschalten`, der im Bestätigungsdialog sagt, was
  er ändert. TDC schaltet sie **nicht** von sich aus ein: das verändert, was die
  Malware sieht, und das entscheidet der Analyst.
- Nach jedem Setzen einer Regel wird gegengeprüft (`Get-NetFirewallRule`), und
  der Zustand `blocked` wird erst gesetzt, wenn die Regel wirklich steht.

**Entscheidung — Isolated.** Ausnahmen, und nur diese:

- **Loopback braucht keine.** Die Windows-Firewall filtert Loopback-Verkehr gar nicht, eine Allow-Regel dafür wäre also eine Behauptung über etwas, das ohnehin nicht blockiert werden kann. Und ihre IPv6-Hälfte ließ sich nicht einmal schreiben: Windows lehnt `::1` als Regeladresse ab („Es wurde eine nicht definierte Multicast-, Broadcast- oder Loopback-IPv6-Adresse angegeben") — der erste Lauf auf einer echten VM scheiterte an genau dieser Regel, bevor irgendetwas isoliert war. Sie ist entfallen.
- **Kein stehendes Recht für den Fetcher.** Ein Dauer-Allow auf das `python.exe` der Web-UI-venv wäre ein Loch von der Größe „alles, was dieses python starten kann, darf raus" — und ein Interpreter lässt sich zu allem überreden. Stattdessen öffnet `allow_fetch` unmittelbar vor einem Nachladen **eine Regel auf genau die beobachtete Adresse** und nimmt sie danach wieder weg, ob der Fetch gelingt oder nicht; Reste räumt der Start auf.
- Damit ist die per-Fetch-Regel die **einzige** Ausnahme, die Isolated überhaupt schreibt. Kein DNS, kein NTP, keine Updates.

**Korrektur: „default deny" ist nicht „deny".** `Set-NetFirewallProfile -All -DefaultOutboundAction Block` regelt nur Verkehr, auf den **keine Regel passt**. Windows liefert aktivierte Ausgangs-Allow-Regeln mit (Core Networking: DNS, DHCP, Teredo, IP-HTTPS, Gruppenrichtlinien; die Regeln der Store-Apps), und die gelten weiter. Dieser Entwurf hat eine Isolation versprochen, die er nie geliefert hat — das Abschluss-Review hat es gefunden, kein Test konnte es, weil der eingesetzte Fake-Runner außer TDCs eigenen Regeln keine kennt.

Isolated schaltet deshalb **zusätzlich jede aktivierte Ausgangs-Allow-Regel des lokalen Stores** (`PolicyStoreSourceType = Local`) ab, die nicht `TDC-FW-*` ist. Vor der ersten Änderung merkt es ihre Namen in `firewall_state.json` (`allow_disabled`), neben dem vorherigen Default. Beim Verlassen schaltet es genau diese wieder ein — und `scripts/tdc-unisolate.ps1` tut dasselbe, es liest dieselbe Liste. Eine Regel, die sich nicht wieder einschalten lässt, bleibt vermerkt und wird erneut versucht.

**Und es sagt, was offen bleibt.** Eine Regel aus einem anderen Store, vor allem aus einer Gruppenrichtlinie, lässt sich lokal nicht abschalten. Nach dem Umschalten liest TDC zurück, welche Ausgangs-Allow-Regeln noch aktiv sind (`allowed_out`). Das Band und `GET /api/firewall/isolate` nennen sie, und Isolated gilt erst als **geschlossen** (`verified`), wenn diese Liste leer ist. „Kein DNS" stimmt nur dann. Lassen sich die Regeln vor dem Umschalten nicht lesen, verweigert Isolated und ändert nichts; lassen sie sich danach nicht lesen, sagt das Band, dass unbekannt ist, ob Isolated geschlossen ist.

**Nebenwirkung, die in den Befund gehört:** Isolated kappt auch die Cloud-Abfragen und die Telemetrie des getesteten EDR. Seine Urteile sind danach nur mit anderen isolierten Läufen vergleichbar.

**Restrisiko, ausgeschrieben:** während ein Fetch läuft, könnte etwas, das dieses python ausführen kann, dieselbe eine Adresse erreichen — für die Sekunden des Fetches. Das steht im Isolated-Band der Oberfläche, im Docstring von `firewall_rules` und als `residual` in `GET /api/firewall/isolate`. Teil B schließt es: dort ist der einzige erlaubte Weg nach draußen der Proxy, und der führt keinen fremden Code aus.

Eingehend bleibt unberührt: `DefaultOutboundAction Block` betrifft die Antworten
auf eingehende Sitzungen nicht, der Host erreicht Port 9000 weiter.

**Entscheidung — Rückweg.** Der alte Wert von `DefaultOutboundAction` wird vor
dem Umschalten in `webui/firewall_state.json` gemerkt und beim Ausschalten
zurückgesetzt. Steht beim Start des Dienstes dort noch ein Isolated-Marker, ohne
dass der Nutzer ihn gesetzt hat, wird er **nicht** automatisch aufgelöst, sondern
im Tab und als Toast gezeigt — ein Absturz mitten in einer Detonation soll die
Sperre nicht aufheben. Dazu ein Notausgang `scripts/tdc-unisolate.ps1`, im README
dokumentiert, und ein Bestätigungsdialog (`tdcConfirm`, existiert) vor dem
Einschalten.

**Entscheidung — Tool Updates.** In Isolated verweigert das Update-Panel die
Arbeit mit dem Hinweis `Isolated mode is on`; der Hintergrund-Check (alle 24 h)
pausiert. Sonst würde TDC selbst gegen die eigene Sperre laufen und sie als
„offline“ fehldeuten.

## Der Download-Fall

**Wann überhaupt gefragt wird.** Nur wenn der Prozess im Detonations-Kontext
steht (er oder ein Vorfahr ist eine Submission) **und** eine URL auf eine Datei
sichtbar wurde. Alles andere wird markiert und geloggt, aber nicht gefragt. Im
Kopf des Tabs steht ein Schalter `ASK: Detonation | Alles | Aus`; Vorgabe
`Detonation`.

**Entscheidung — was die drei Stellungen bedeuten.** Der Schalter steuert
Sperren *und* Fragen gemeinsam, sonst wäre er nicht zu verstehen. Er liegt
**auf dem Server** (in `webui/firewall_state.json`), nicht im Browser — er
entscheidet über Sperren, die auch ohne offenen Browser gelten.

| Stellung | Verhalten |
|---|---|
| `Detonation` (Vorgabe) | Download aus dem Detonations-Kontext: sperren und fragen. Alles andere: nur markieren. |
| `Alles` | Jeder Download-Fund sperrt und fragt, außer von Prozessen der Selbstausschluss-Liste. |
| `Aus` | Nichts wird gesperrt, nichts gefragt — nur markiert und geloggt. Für die Detonation, die man ungestört laufen lassen will. Der Kopf zeigt das dauerhaft an, damit niemand glaubt, er sei geschützt. |

**Woher die URL kommt** (in Teil A):

| Quelle | Feld |
|---|---|
| PowerShell 4104/4103 | URL aus dem Skripttext |
| Sysmon EID 1 | URL aus `CommandLine` (`certutil -urlcache`, `bitsadmin /transfer`, `curl`, `wget`, `mshta http://…`) |
| BITS-Client-Kanal | `data["url"]` aus EID 59/60 — heute schon als Durchreiche vorhanden, wird jetzt ausgelesen |

Ein kompilierter Loader über `WinHttpSendRequest` ist hier nicht dabei. Das ist
die bekannte Lücke von Teil A, und der Grund für Teil B.

**Entscheidung — erst sperren, dann fragen.** In Teil A ist die Verbindung beim
Erkennen schon gelaufen; eine Frist, nach der gekappt wird, käme zu spät. Also
umgekehrt: TDC **sperrt den Endpunkt sofort** und fragt danach. `ZULASSEN` hebt
die Sperre wieder auf. Der Toast formuliert das ehrlich („gesperrt — zulassen?“),
nicht als Vorab-Frage. In Teil B dreht sich das, weil der Proxy wirklich halten
kann; die Komponente bleibt dieselbe.

**Der Toast.** Der vorhandene `showToast(type, title, detail, duration)` bekommt
eine zweite Form `showDecisionToast(options)`:

- bleibt stehen, bis entschieden wurde (kein Auto-Dismiss), mit Countdown auf die
  **Vorgabeaktion** `KAPPEN + SELBST HOLEN`;
- Knöpfe: `KAPPEN + SELBST HOLEN`, `NUR KAPPEN`, `ZULASSEN`, dazu `in LOGS ▸`;
- mehrere offene Entscheidungen stapeln sich, höchstens drei sichtbar, der Rest
  als „+ n weitere“ mit Sprung in den Tab;
- die Throttle-Logik von `showToast` (15 s pro Titel) gilt hier **nicht**, sonst
  verschwinden Entscheidungen.

**Entscheidung — wo die Entscheidung lebt.** Nicht im Browser. Offene
Entscheidungen stehen in `webui/pending.json` (atomar geschrieben wie
`submissions.json`), mit `id`, Fund, Frist und Ergebnis. Daraus folgt:

- Ein Neustart des Dienstes mitten in der Detonation verliert nichts: die
  Sperren stehen in der Firewall, die Entscheidungen in der Datei.
- Zwei offene Browser-Tabs sehen dieselbe Liste, weil beide `/api/firewall/pending`
  abfragen. Wer zuerst klickt, gewinnt; `decide` ist idempotent und antwortet auf
  eine zweite Antwort mit dem bereits gefallenen Ergebnis statt mit einem Fehler.
- Eine beantwortete Entscheidung bleibt 24 h als Verlauf stehen und ist im Tab
  nachlesbar — „wer hat was wann zugelassen“ ist bei einer Analyse die halbe
  Arbeit.

**Entscheidung — TDC holt unbeaufsichtigt nach.** Läuft die Frist ab, sperrt TDC
und **holt die Datei selbst** (`block_fetch`). Der Grund: eine Stage-2-URL ist
oft ein Einmal-Link, und ein verpasstes Sample kommt nicht zurück. Der Preis ist
bewusst in Kauf genommen: die Chamber kontaktiert dabei ohne Aufsicht einen C2.
Daraus folgt:

- Die Frist ist **serverseitig**. Sie läuft weiter, auch wenn kein Browser offen
  ist; der Countdown im Toast zeigt nur, was der Server sowieso tun wird.
- Vorgabe 30 s, einstellbar über `TDC_FIREWALL_DECIDE_SECONDS`. `0` bedeutet
  sofort holen, ohne zu fragen — für die unbeaufsichtigte Detonation.
- Jedes unbeaufsichtigte Nachladen erzeugt einen eigenen Eintrag im Verlauf und
  einen Info-Toast beim nächsten Öffnen der Oberfläche („3 Samples in deiner
  Abwesenheit gesichert“). Es passiert nichts still.
- In `ASK: Aus` gilt das nicht: dort wird weder gesperrt noch geholt.

**Das Nachladen.** `POST /api/firewall/decide` mit `action: block_fetch`:

- Der Gast holt, nicht der Host. Sonst stünde die echte IP des Analysten im Log
  des Angreifers.
- Die Allow-Regel des Fetchers macht das auch in Isolated möglich.
- Grenzen: höchstens 64 MB, 30 s Zeitlimit **für den ganzen Fetch** (nicht pro Lesevorgang — ein Server, der die Bytes tröpfeln lässt, soll keinen Arbeiter dauerhaft binden), höchstens 3 Weiterleitungen, und die Ziel-IP **und der Port** müssen auf jedem Sprung die beobachteten sein (kein erneutes DNS).
- Die eigene Seite der VM ist tabu: Loopback, unspezifiziert, Multicast, Link-Local, Reserved, die eigenen Interface-Adressen und die Default-Gateways werden abgelehnt. **Private Adressen sind standardmäßig ebenfalls abgelehnt** und nur mit `TDC_FIREWALL_FETCH_LAN=1` erlaubt (für Labore mit INetSim). Grund: der Host erreicht den Gast über genau so eine Adresse, und in Isolated wäre der Fetcher der einzige Weg dorthin — das würde den Sinn umdrehen, dass der Gast holt und nicht der Host.
- Der User-Agent des Loaders wird mitgeschickt, wenn er bekannt ist (aus dem
  Skripttext), sonst ein neutraler. Was gesendet wurde, steht in den Metadaten.
- Das Ergebnis wird **nie** ausgeführt und nie automatisch irgendwohin gemeldet.

**Entscheidung — Schutz gegen Missbrauch.** `/api/firewall/decide` nimmt **keine
URL**, sondern nur die `id` einer offenen Entscheidung, die der Detektor angelegt
hat; die id ist einmalig verwendbar. Sonst wäre das ein Loch, durch das Malware
im Gast TDC als eigenen Proxy benutzt — gerade in Isolated, wo nur TDC rausdarf.

## Der Sample-Store

- Verzeichnis `C:\tdc\samples\<sha256[:2]>\<sha256>`, Metadaten in
  `webui/captures.json` (gleiches atomares Schreiben wie `submissions.json`,
  höchstens 500 Einträge).
- Felder: `id`, `sha256`, `size`, `url` (defanged gespeichert? nein — roh
  gespeichert, defanged **angezeigt**), `dst_ip`, `geo`, `pid`, `image`,
  `fetched_at`, `origin` (`fetch` in A, `proxy` in B), `content_type`, `magic`
  (`MZ`, `ELF`, `PK`, `#!`, …), `submission_id`, `executed: false`.
- **Entscheidung — Defender:** `C:\tdc\samples` kommt in die
  Defender-Ausnahmen, wie `scan_uploads` heute schon. Ohne das frisst Defender
  die Stage-2-Datei, bevor sie jemand ansieht. Es ist ein TDC-eigenes
  Verzeichnis, nicht der Detonationspfad — die EDR-Tests bleiben aussagekräftig.
  **Zweimal eingetragen:** im Provisioning (`install-webui.ps1`, wie bisher)
  *und* beim Start des Web-UI selbst, idempotent über `Add-MpPreference`. Nur so
  funktioniert das Feature auch auf einer VM, die schon steht und nur ein
  `make deploy` bekommt.
- Das Verzeichnis kommt in `_readable_roots`, damit `/api/file/download` die
  Datei an den Host geben kann, und **nicht** in die Schreib-Allowlist.
- Knöpfe an der Capture: `RIZIN`, `HEX`, `THREATSCAN` — alle drei haben schon
  einen Einsprung über einen Pfad.

## Die Oberfläche

**Reiter:** `FIREWALL` zwischen `SYSMON` und `LOGS`. Entscheidung: dort, weil
der Perspektivwechsel nach LOGS geht und die beiden zusammengehören.

**Kopf:** `FIREWALL` + (i), rechts `LIVE`, `ASK: Detonation ▾`, `ISOLATED` (mit
Bestätigung, im aktiven Zustand rot und dauerhaft sichtbar), Zeitbereich
`15m 1h 4h 24h 7d All`.

**Links, der Prozessbaum.** Suchfeld über Prozess, Domain, IP. Pro Prozess eine
Zeile: Name, Aktivitätsbalken (Verbindungen über die Zeit), Allow/Deny-Schalter.
Aufgeklappt darunter seine Endpunkte, je mit Tag-Chip und eigenem Schalter. Eine
Gruppe „lokal“ am Ende. Detonierte Prozesse sind hinterlegt und tragen
`DETONIERT`.

**Mitte, die Karte.** Umschalter `MAP | LIST | ASN`.

- **Entscheidung — Grundkarte:** eine vereinfachte Natural-Earth-110m-Landmaske
  (public domain) als `webui/static/data/world.json`, Koordinatenpaare in
  Zehntelgrad als Ganzzahlen, ~120 KB. Gezeichnet als SVG in der Machart des
  bestehenden Chart-Kits (`stackedBarsSvg` & Co.), damit sie sich beim
  Theme-Wechsel von selbst umfärbt. Projektion: äquidistant zylindrisch, von
  82° N bis 58° S beschnitten.
- Von der **Chamber** aus geht ein Bogen zu jedem Ziel. Sie ist **kein Punkt der
  Karte**, sondern ein eigenes Gerät in einem Streifen unter ihr, mit eigenem
  Hintergrundton, Trennlinie und der Beschriftung `LOCATION NOT DETERMINED`.
  Grund: der Standort des Hosts ist unbekannt und wird **nicht** ermittelt — das
  hieße, irgendeinen Dienst zu fragen, wo diese Maschine steht, und die Chamber
  fragt niemanden nach einer Adresse. Ein Punkt mitten in der Projektion
  behauptet aber trotzdem einen Standort: die Mitte dieses Ausschnitts ist
  0°/12° N, also Burkina Faso, und genau so hat der erste Nutzer die Karte
  gelesen („ich bin nicht in Afrika"). Die Position des Geräts wird deshalb
  ausschließlich aus der Kartengröße gerechnet, nie über `project()` aus
  Längen- und Breitengrad — ein Test hält das fest. Breite der Bögen nach
  `count`, Farbe nach höchstem Tag.
- Hover zeigt Prozess, Endpunkt, AS-Organisation, Tags. Klick wechselt die
  Perspektive.
- **Entscheidung — Bewegung:** gesperrte Bögen pulsieren nicht. Es gibt eine
  einzige Animation, ein laufender Strich auf Bögen mit offener Entscheidung, und
  die ist unter `prefers-reduced-motion` aus (die Datei hat schon einen Block
  dafür).
- `LIST` ist dieselbe Menge als sortierbare Tabelle (`data-sortable`), `ASN`
  gruppiert nach AS-Organisation — dort fällt auf, wenn fünf „verschiedene“ IPs
  demselben Bulletproof-Hoster gehören.

**Unten, die Summary.** Verbindungen, gesperrt, offene Entscheidungen,
gesicherte Samples; Top-Prozesse, Top-Endpunkte, Top-Länder. Ab ~1400 px
Fensterbreite wandert sie als dritte Spalte nach rechts, wie im Vorbild.

**Hunting-Hinweise.** Ein Block `So jagst du weiter` am ausgewählten Eintrag,
vier bis sechs Zeilen, jede eine fertige Query und ein Klick:

- `dst_ip="…" | top image` — wer sonst mit diesem Endpunkt spricht
- `source=netflow image="…" | timechart span=1m count by dst_ip` — der Rhythmus
- `source=firewall action=DROP | stats count by dst_ip, dst_port` — was abgewiesen wurde
- `source=dns result="-" | top query` — Namen ohne Auflösung, DGA-Verdacht
- `source=powershell "http" | head 50` — Download-Cradles im Klartext

Dieselben Hinweise stehen im Help-Modal und in einem README-Abschnitt.

## Perspektivwechsel

Neu in `app.js`:

```
openLogsTab(query, earliest, latest, back)
```

Setzt Limit zurück, Zeitbereich und Query, wechselt den Tab, sucht. Wichtig:
`initLogs()` überschreibt die Query beim **ersten** Öffnen mit der letzten
gespeicherten — also erst `switchTab('logs')`, dann setzen, oder auf `logsReady`
prüfen. Der Rückweg steht in LOGS als Chip `← FIREWALL`.

Umgekehrt bekommen die Netzwerk-Knoten im Tab GRAPH und die Tracing-Konsole
einen Knopf `FIREWALL`, der dort auf diesen Endpunkt filtert. Das ist billig und
schließt den Kreis.

## API

| Methode | Route | Zweck |
|---|---|---|
| GET | `/api/firewall/connections` | gebündelte Flows mit Tags und Geo; `since`, `until`, `process`, `tag`, `state`, `max` |
| GET | `/api/firewall/summary` | Summen, Top-Prozesse, Top-Endpunkte, Top-Länder |
| GET | `/api/firewall/geo` | `ip=` → ein Lookup, für Tooltips in anderen Tabs |
| GET | `/api/firewall/rules` | die `TDC-FW-*`-Regeln, die stehen |
| POST | `/api/firewall/block` | `{scope: "endpoint"\|"process", ip, port, protocol, image}` |
| POST | `/api/firewall/unblock` | `{rule_id}` |
| GET | `/api/firewall/isolate` | Zustand, inklusive gemerktem Vorzustand |
| POST | `/api/firewall/isolate` | `{on: bool}` |
| GET | `/api/firewall/pending` | offene Entscheidungen, mit Restfrist |
| POST | `/api/firewall/decide` | `{id, action: "allow"\|"block"\|"block_fetch"}` |
| POST | `/api/firewall/ask` | `{mode: "detonation"\|"all"\|"off"}` |
| GET | `/api/firewall/captures` | gesicherte Samples |
| GET | `/api/firewall/capture/<id>` | eine Capture mit Metadaten |

Alles über `_json_response` (`allow_nan=False`), Fehler als `{error}` mit 400
oder 500, lange Zeichenketten gekappt wie im LOGS-Store.

**MCP, Entscheidung:** nur lesend. `tdc_firewall_connections(...)` und
`tdc_firewall_captures(...)`. `isolate`, `block` und `decide` bleiben draußen —
ein Modell soll die Chamber nicht von sich aus vom Netz nehmen oder eine Sperre
lösen.

## Sicherheit

- URLs und Hostnamen werden **defanged angezeigt** (`hxxp://`, `example[.]com`),
  nie als Link, immer kopierbar. Gespeichert wird das Original.
- Jede Aktion (block, unblock, isolate, decide, fetch) landet im `access`-Log und
  damit in LOGS — nachvollziehbar, wer was wann zugelassen hat.
- Das Web-UI hat keine Anmeldung; das ist Laborlage und bleibt so. Die
  zerstörerischen Knöpfe hängen deshalb am Bestätigungsdialog.
- `/api/firewall/decide` nimmt nur ids, keine URLs (s. o.).
- Eine gesicherte Capture wird niemals ausgeführt und liegt ohne
  Ausführungsrecht-Pfad im UI.

---

# Teil B · TDC im Pfad

Skizze — die ausführliche Fassung entsteht, wenn A steht.

- Ein neues Modul `webui/proxy.py`: HTTP und `CONNECT`, eigene CA (beim
  Provisioning erzeugt, in den Gast-Root-Store gelegt), Leaf-Zertifikate pro
  Host im Cache. Nur `socket`, `ssl`, `http.client`.
- Firewall-Form: in Isolated darf **nur** der Proxy-Prozess nach außen. Damit
  ist „proxy-unaware“ Malware automatisch geblockt — und der Block ist selbst das
  Signal.
- Systemproxy im Gast über `netsh winhttp set proxy` und die
  WinINet-Registry-Werte.
- Was B dazugibt: URL, Methode, Header, Body; echte Byte-Zähler pro Prozess und
  Endpunkt; TLS-Fingerabdruck (JA3) als weiteres Tag; das **Halten** der Anfrage
  bis zur Entscheidung; bei DECLINE behält TDC die Bytes und der Loader bekommt
  eine 404.
- Was sich in der Oberfläche ändert: der Toast heißt „will verbinden“ statt
  „gesperrt — zulassen?“, die Byte-Spalten füllen sich, der Hinweis in der
  Summary verschwindet. Tab-Aufbau, API-Form und Komponenten bleiben.
- Grenze: Raw-Socket-C2 geht nicht durch den Proxy. In Isolated wird es
  geblockt, außerhalb bleibt es bei der Sicht aus Teil A.

---

## Was dem Builder offen bleibt

- Die genaue Zerlegung von `webui/firewall.py` in Funktionen, solange die
  Bewertung rein bleibt (keine I/O, lauffähig unter pytest auf macOS).
- Die Entropieschwelle für `dga` und die Portliste für `rare-port` — Startwerte
  im Modul, dann an echten Detonationen nachziehen.
- Wie die Karte Bögen entwirrt, wenn zwanzig Ziele im selben Land sitzen
  (Streuung, Bündelung oder beides).
- Ob `LIST` und `ASN` eine eigene Tabelle bekommen oder dieselbe mit anderer
  Gruppierung.
- Reihenfolge der Arbeit innerhalb von A: der Plan entsteht als nächstes.

## Pflichten zum Abschluss

- README: Tabellenzeile `FIREWALL` in Nav-Reihenfolge, ein Abschnitt
  `## Firewall` mit dem Hunting-Teil und dem Notausgang, die API-Zeilen.
- **Entscheidung — Screenshots.** Die entstehen nur auf einer laufenden
  Windows-VM und sind von der Entwicklungsmaschine nicht erreichbar. Der
  Doku-Test verbietet nur *verwaiste* PNGs, nicht fehlende — also referenziert
  das README in dieser Arbeit **keinen** neuen Screenshot. Die letzte Aufgabe
  des Plans ist eine Übergabenotiz, welche drei Bilder zu machen sind (Tab mit
  Karte, Toast mit offener Entscheidung, Isolated aktiv) und in welche
  README-Stellen sie dann gehören. „Fertig“ ist damit ohne VM erreichbar.
- Help-Modal: `#help-usage`-Eintrag in derselben Reihenfolge, `#help-api`-Zeilen.
- Deploy-Listen: `Makefile`, `make.ps1`, `scripts/deploy-utm.py` für
  `firewall.py`, `firewall_store.py`, `firewall_rules.py`, `geoip.py` und das
  Verzeichnis `webui/data/`.
- `?v=` auf `style.css`, `theme-layout.css`, `theme-cyberpunk.css`, `app.js`.
- `tests/test_theme.py`: 12 → 13 und 14 → 15.
- Neue Tests: `tests/test_firewall.py` (Bewertung, Bündelung, Geo-Lookup,
  Regelnamen, Isolated-Zustandswechsel) und `tests/test_firewall_ui.py` (Node,
  nach dem Muster von `tests/test_logs_ui.py`).
