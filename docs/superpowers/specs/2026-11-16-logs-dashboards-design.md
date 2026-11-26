# Entwurf: Befehlskarte, Visualisierung und eigene Dashboards

Datum: 2026-11-16 · Status: Entwurf zur Freigabe

## Warum

Der LOGS-Tab durchsucht sechs Quellen mit einer kleinen Splunk-Sprache. Zum Analysieren fehlen drei
Dinge:

1. **Die Sprache ist nicht greifbar.** Die Syntax steht in einem Tooltip am `?`-Knopf, der beim
   Hover aufblitzt und verschwindet. Wer sich eine Pipe nicht merkt, verliert den Faden.
2. **Zahlen bleiben Zahlen.** Jede Auswertung mit Pipe kommt als Tabelle. Anteile und Verläufe
   erkennt man darin erst, wenn man sie selbst ausrechnet.
3. **Jeder Fund ist flüchtig.** Nach dem Tab-Wechsel ist die Suche weg. Wer ein Dashboard für einen
   Fall will — „Beacon-Jagd", „PowerShell" —, muss seine Suchen jedes Mal neu tippen.

Dieser Entwurf deckt alle drei ab: eine stehende Befehlskarte, eine Formwahl für das Ergebnis, und
Kacheln, die auf einer eigenen Dashboard-Seite liegen.

## Ziele

1. **Befehlskarte (COMMANDS).** Eine Karte im LOGS-Tab, die beim Scrollen stehen bleibt, die Sprache
   in Gruppen zeigt und auf Klick den Befehl in die Suche schreibt. Sie löst den `?`-Tooltip ab.
2. **Formwahl.** Über dem Ergebnis die Reiter EVENTS, STATISTICS und VISUALIZATION; im letzten die
   Formen Tabelle, Kreis, Balken, Linie und Senkey, soweit die Spalten sie zulassen.
3. **Eigene Dashboards.** Eine Auswertung lässt sich als Kachel speichern. Auf der Dashboard-Seite
   wählt eine Leiste zwischen SERVICES (der heutigen Seite) und den eigenen Dashboards. Eine Kachel
   merkt sich Suche, Form und Zeitraum, rechnet beim Öffnen der Seite neu und hat einen Knopf zum
   Nachladen.

## Nicht-Ziele

- **Kein neuer Tab.** Die eigenen Dashboards sind Unterseiten des Dashboard-Tabs.
- **Keine Kacheln aus anderen Tabs.** Nur Log-Suchen werden Kacheln (siehe Wege, Weg 2).
- **Kein Verschieben per Maus.** Die Reihenfolge der Kacheln ist die Reihenfolge des Speicherns;
  umsortiert wird über das Kachel-Menü (nach vorn / nach hinten).
- **Keine Freigabe nach außen,** kein Export als PDF oder Bild, keine geplanten Berichte, keine
  Alarme auf Schwellenwerte.
- **Keine neue Suchsprache.** Kacheln speichern genau die Abfrage, die im LOGS-Tab lief.
- **Kein Login, keine Benutzer.** „Eigene" heißt eigene pro Chamber, nicht pro Person.

## Anti-Ziele

Daran wäre die Arbeit gescheitert, auch wenn sie technisch läuft:

- **Die Dashboard-Seite wird langsam oder bremst die VM.** Acht Kacheln sind acht Suchen über bis zu
  10.000 Treffer, auf derselben VM, die detoniert und scannt.
- **Eine Kachel zeigt etwas, das nicht mehr stimmt,** ohne dass man es sieht: kein Zeitstempel, kein
  Hinweis auf einen Fehler, ein leeres Bild statt einer Begründung.
- **Rohtext aus einem Sample landet unkontrolliert auf der Startseite** oder wird als Markup
  interpretiert.
- **Die heutige SERVICES-Seite verändert sich.** Wer Dienste, Kacheln und Alarm-Diagramme sehen will,
  sieht sie wie bisher.
- **Die Befehlskarte verdeckt die Analyse,** statt ihr zu dienen (zu groß, nicht wegklappbar,
  überschreibt die Suche beim Klick).

## Randbedingungen

- **Bestand.** Alle Zeichner liegen in `app.js`: `donutSvg`, `pieSvg`, `chartLegendHtml`,
  `stackedBarsSvg`, `verdictBarsSvg` (Balken nebeneinander), `layoutSankey` + `sankeySvg`,
  `chartEmptyHtml`, `_chartColor`. Eine **Linie über mehrere Reihen fehlt** und kommt neu dazu;
  `sparklineSvg` zeichnet nur eine Reihe ohne Achsen.
- **Suche.** `GET /api/logs/search?q&earliest&latest&limit` liefert
  `{type: "events"|"table"|"timechart", events, columns, rows, count, matched, truncated, histogram,
  fields, took_ms}`; Fehler `400 {error, pos}`. `limit` 1–1000 (Standard 200), höchstens 10.000
  Treffer gehen in die Pipes, Werte werden bei 65.536 Zeichen geschnitten.
- **Farben nur in `:root`** von `style.css`. Wie sich das Aussehen auf die Theme-Dateien verteilt,
  richtet sich nach dem Stand von `main` zu Beginn der Umsetzung: Gibt es dann eine gemeinsame
  Layout-Datei (`theme-layout.css`, an der eine andere Sitzung arbeitet), gehört das Aussehen beider
  Themes dorthin, jede Regel unter `[data-theme]` und ohne Farbliterale; gibt es sie nicht, geht das
  Aussehen wie heute nach `style.css` und die Cyberpunk-Regeln nach `theme-cyberpunk.css`, jede
  unter `:root[data-theme="cyberpunk"]`. **Entscheidung des Nutzers:** nicht auf die andere Sitzung
  warten, sondern gegen den heutigen `main` bauen und die Konflikte beim Merge auflösen. In `app.js`
  kein Farbliteral, sondern `var(--x)` im Markup oder `themeColor('--x')`.
- **Sicherheit.** Jeder Text vom Server geht durch `escapeHtml`; Inline-Handler nur mit `jsArg`,
  `jsInt`; Klassen aus Daten über `cssToken`. Der CSRF- und Host-Schutz greift für neue Routen
  von selbst (`_block_cross_site_requests`).
- **Wartung.** `_reject_during_maintenance` lehnt jede schreibende Anfrage außerhalb
  `/api/updates/` ab, während ein Tool-Update läuft. Speichern einer Kachel scheitert dann mit
  503 — das ist gewollt und wird im UI als Hinweis gezeigt.
- **Doku-Tests.** Jede neue Route braucht genau eine Zeile in der API-Tabelle der README; jedes neue
  `webui/*.py` muss in allen drei Deploy-Wegen stehen (`scripts/deploy-utm.py`, `Makefile`,
  `make.ps1`); `<code>/api/…</code>` in der Hilfe darf nur echte Routen nennen.
- **Theme-Tests.** Neue Funktionen und Konstanten, die ein Node-Test braucht, gehören in die Listen
  in `tests/test_theme.py` (`CHART_FUNCTIONS`, `CHART_CONSTS`, `DASHBOARD_CHART_FUNCTIONS`,
  `DASHBOARD_CHART_CONSTS`); `tests/test_logs_ui.py` findet `logs*`-Funktionen von selbst.
  `.content-header` bleibt bei 12, `.tab-content` bei 14 — es kommt kein Tab dazu.
- **(i)-Texte** höchstens 300 Zeichen, 1–2 Sätze, Ende mit `.`, `!` oder `?`.
- **Asset-Versionen** in `index.html` erhöhen; Tests prüfen, dass der alte Wert weg ist.
- **Die VM** hat 8 GB RAM und läuft unter x64-Emulation; das Web-UI läuft als SYSTEM ohne Login.

## Wege

**Weg 1 — in den vorhandenen Tabs, eine Suche pro Kachel (gewählt).**
LOGS bekommt Reiter und Formwahl, die Dashboard-Seite eine Umschaltleiste. Jede Kachel ruft
`/api/logs/search` mit ihrer gespeicherten Suche; gespeichert wird in `webui/dashboards.json`.
*Preis:* Kacheln entstehen nur aus Log-Suchen, nicht aus den Alarm-Diagrammen.

**Weg 2 — eine allgemeine Kachel-Schicht für alle Tabs.**
Jede Karte des Web-UIs ließe sich speichern, auch die SEVERITY-Donuts oder der Sysmon-Fluss.
*Preis:* deutlich größer, jede Quelle braucht ihre eigene Nachrechnen-Funktion, und der Nutzen liegt
heute fast nur bei den Log-Suchen.

**Weg 3 — nur im Browser speichern (`localStorage`).**
Keine Server-Routen. *Preis:* nach einem Browser-Wechsel weg, nicht im Backup der VM, für niemanden
sonst sichtbar.

**Gewählt: Weg 1.** Er nutzt, was da ist, bleibt klein genug für eine saubere Prüfung, und lässt
Weg 2 offen: Eine Kachel, die ihre Suche kennt, ist der Spezialfall einer Kachel, die eine
Rechenvorschrift kennt.

## 1. Befehlskarte (COMMANDS)

**Platz.** Oben in der linken Spalte des LOGS-Tabs, über FIELDS, in der Spalte mit
`position: sticky; top: 0`. Sie bleibt beim Scrollen der Ergebnisse stehen. Zugeklappt ist sie eine
Zeile hoch.

**Inhalt.** Eine Konstante `LOGS_COMMANDS` in `app.js` trägt die Gruppen; die Karte wird daraus
gezeichnet, nicht aus Fließtext:

| Gruppe | Zeilen (Auszug) |
|---|---|
| SEARCH | `word`, `"a phrase"`, `field=value`, `field!=value`, `field>5`, `AND` / `OR` / `NOT`, `( )`, `*` |
| PIPES | `\| head 20`, `\| tail 20`, `\| sort -count`, `\| dedup field`, `\| table f1, f2`, `\| fields f1`, `\| stats count by field`, `\| top field`, `\| rare field`, `\| timechart span=5m count by source` |
| TIME | `earliest=-15m`, `latest=now` |
| SOURCES | `source=powershell` … `source=firewall` (die sechs Namen) |

Jede Zeile hat den Befehl in Schreibmaschinenschrift und einen Halbsatz dahinter, was er tut. Die
Texte sind kurz genug, dass die Karte ohne Scrollen in die Spalte passt, wenn eine Gruppe offen ist;
die Gruppen sind einzeln aufklappbar, offen bleibt zuletzt geöffnete (in `localStorage`).

**Klickverhalten.** Ein Klick **fügt ein, statt zu ersetzen**: Ein Befehl mit Pipe wird an die
Abfrage angehängt (`… | stats count by `), ein Suchbegriff oder ein `field=` an der Cursorstelle
eingesetzt, ein `source=…` wie heute über `logsAddSource` vor die erste Pipe. Danach steht der Cursor
hinter dem Eingefügten; **die Suche läuft nicht von selbst los** — man will meist noch den Feldnamen
tippen. Enter sucht, wie bisher.

**Der `?`-Knopf** bleibt stehen und klappt die Karte auf und zu. `LOGS_SYNTAX_HINT` entfällt; sein
Inhalt lebt in `LOGS_COMMANDS` weiter.

**Schmale Fenster.** Unter 1100 px Fensterbreite liegt die Karte nicht in der Spalte, sondern über
den Ergebnissen und ist zugeklappt voreingestellt.

## 2. Formwahl im LOGS-Tab

**Reiter.** Über dem Ergebnis eine Reiterzeile (`role="tablist"`): **EVENTS**, **STATISTICS**,
**VISUALIZATION**. Welche benutzbar sind, hängt am Ergebnis:

| `type` | EVENTS | STATISTICS | VISUALIZATION |
|---|---|---|---|
| `events` | die Trefferliste | gesperrt: „needs a pipe such as \| stats count by field" | gesperrt, gleicher Grund |
| `table` | gesperrt: „the pipes made a table; remove them to see events" | die Tabelle | die Formen unten |
| `timechart` | gesperrt, gleicher Grund | die Tabelle | Linie und Balken |

Ein gesperrter Reiter ist `aria-disabled`, grau und nennt im `title` den Grund. Der gewählte Reiter
hält, solange die Spalten dieselben bleiben; wird er unbenutzbar, fällt die Anzeige auf den ersten
benutzbaren zurück.

**Formen.** In VISUALIZATION eine Schalterreihe. Was wählbar ist, entscheidet die Form der Spalten.
**Spalten lesen** (Entscheidung, weil der Server Gruppenwerte nicht als Text zurückgibt): Spalte 0
ist der Name, die **erste Spalte danach, deren Werte alle Zahlen sind**, ist der Wert; weitere
Spalten bleiben unbenutzt. Damit trägt `top f` (Spalten `[f, count, percent]`) den `count` und nicht
den Prozentwert, und `stats count by status` funktioniert, obwohl beide Spalten Zahlen enthalten.
Gibt es keine Zahlenspalte, sind die Bild-Formen gesperrt. Eine leere Antwort (`rows: []`) sperrt
nichts: Die Spalten sagen, was geht, und das Bild zeigt `chartEmptyHtml`.

| Form | Bedingung | Zeichner |
|---|---|---|
| TABLE | immer | `logsTableHtml` |
| PIE | Typ `table`, eine Namensspalte und eine Zahlenspalte | `pieSvg` + `chartLegendHtml` |
| BARS | Typ `table` wie PIE, oder Typ `timechart` | `verdictBarsSvg` bzw. `stackedBarsSvg` |
| LINE | Typ `timechart` (erste Spalte `_time`) | **neu:** `lineSvg` |
| SANKEY | Typ `table`, zwei Namensspalten und eine Zahlenspalte (`stats count by a, b`) | `layoutSankey` + `sankeySvg` |

**BARS zeichnet, was zur Antwort passt** (Entscheidung): gestapelte Balken über die Zeit bei
`timechart` — wie der heutige TIMECHART —, Balken nebeneinander bei einer Namensspalte. Die Kachel
speichert nur `bars`; welcher Zeichner läuft, entscheidet der Typ der Antwort beim Zeichnen.

**Voreinstellung je Antwort** (Entscheidung, damit nichts von heute hinter einem Klick verschwindet):
`events` öffnet in EVENTS; `table` in STATISTICS, also der Tabelle wie heute; `timechart` in
VISUALIZATION als **LINE**. Die Karte EVENTS OVER TIME bleibt über den Reitern stehen — sie
beschreibt die Treffer, nicht das Ergebnis der Pipes.

Eine nicht passende Form ist ein gesperrter Schalter mit Begründung im `title` („needs one name
column and one number column") — lieber ein grauer Knopf als ein leeres Bild.

**Grenzen in der Darstellung.** PIE und BARS zeigen die zwölf größten Werte, der Rest wird zu
`other` (`topWithOther`). SANKEY nimmt je Seite die zwölf größten, der Rest je Seite zu `other`.
LINE zeichnet die Reihen, die der Server liefert (höchstens zehn plus `OTHER`). Über diesen Grenzen
steht unter dem Bild eine Zeile, was zusammengefasst wurde.

**Unvollständige Gruppenlisten** (Entscheidung des Nutzers: warnen und weiterzeichnen, nicht
sperren). `stats` sortiert nach Gruppennamen, nicht nach Häufigkeit, und der Server gibt standardmäßig
200 Zeilen zurück. Ein Kreis daraus zeigte sonst zwölf beliebige Gruppen plus ein falsches `other`.
Deshalb:

- Für die Bild-Formen fragt der Tab mit `limit=1000` (die Decke des Servers), für EVENTS und
  STATISTICS bleibt es bei 200 beziehungsweise bei dem, was „Show up to 1000" setzt.
- Fehlt trotzdem etwas — `count > rows.length` oder `truncated` —, steht unter dem Bild und später
  auf der Kachel eine Zeile wie „only 1,000 of 5,312 groups shown — add `| sort -count | head 20`".
  Der Text ist anklickbar und hängt genau diese Pipe an die Abfrage.

**`lineSvg(series, opts)` — neu in der CHARTS-Abteilung.** Eingabe
`[{key, label, color, points: [[tMs, value], …]}]`, `opts {width, height, unit, step}`. Zeichnet
Achse, Gitter, je Reihe einen Pfad in ihrer Farbe, Punkte nur bei wenigen Werten, `<title>` je Reihe,
und gibt `''` zurück, wenn nichts zu zeichnen ist — wie die anderen Zeichner. Reihenfolge und Farben
kommen über `_chartColor`, damit Legende und Bild zusammenpassen.

**SAVE.** Rechts in der Reiterzeile. Ohne gespeichertes Dashboard heißt der Knopf trotzdem SAVE und
legt beim Speichern das erste an. Er ist gesperrt, solange das Ergebnis keine Form hat (also bei
`events` ohne `| table`).

**Der Dialog** (`#logs-save`, Aufbau wie das Hilfefenster: Backdrop und Inhalt, Escape schließt,
Fokus bleibt im Dialog):

| Feld | Vorbelegung |
|---|---|
| Name | aus der Abfrage abgeleitet (die `by`-Felder oder das erste Wort), überschreibbar, höchstens 60 Zeichen |
| Dashboard | die vorhandenen als Schalterreihe, dazu „+ New" mit Namensfeld |
| Form | die gerade gewählte |
| Zeitraum | **relativ** („last 24 h", der Zeitraum des Tabs) oder **fest** (das aktuelle Fenster als `earliest`/`latest` in UTC) |

Nach dem Speichern eine Meldung über `showToast` mit dem Namen des Dashboards; der Dialog schließt.

## 3. Eigene Dashboards

**Aufbau der Seite.** Die Kopfzeile von `#tab-dashboard` bleibt, wie sie ist — „Service Dashboard"
steht nie über „Beacon-Jagd" (Entscheidung). Direkt darunter kommt die Leiste `.dashboard-pages`:
Knöpfe für **SERVICES** und je ein Knopf pro eigenem Dashboard, dahinter **+ NEW**. Darunter liegen
zwei Geschwister: die heutige `.dashboard-body` (unverändert, `hidden`, wenn ein eigenes Dashboard
gewählt ist) und neu `.dashboard-own` mit einem Kopf (Name des Dashboards, Uhrzeit des letzten
Rechnens, `⋯`) und den Kacheln. Die Kinderliste von `.dashboard-body` bleibt damit so, wie
`tests/test_charts.py` sie festhält, und es kommt keine `.content-header` dazu.

Das `⋯` am Kopf des offenen Dashboards (Entscheidung) öffnet **Rename** und **Delete**; das Löschen
fragt einmal zurück und nennt die Zahl der Kacheln („Delete 'Beacon-Jagd' and its 7 tiles?").
Erreichbar ist es auch mit der Tastatur.

Der **Refresh**-Knopf der Kopfzeile tut weiter, was er heute tut (Dienste und Uhr), und rechnet auf
einer eigenen Seite zusätzlich deren Kacheln neu. Auf SERVICES ändert sich dadurch nichts.

Die Wahl steht in `localStorage` (`tdc.dashboard.page`), damit das Dashboard beim nächsten Öffnen
dasselbe zeigt. Ist das gespeicherte Dashboard weg, fällt die Seite auf SERVICES zurück.

**Eine Kachel.** Eine `.chart-card`:
- Kopf: Name, der Zeitraum („last 24 h" oder das feste Fenster), die Uhrzeit des letzten Rechnens,
  ein `↻` und ein `⋯`.
- Körper: die gespeicherte Form. Tabelle, Linie und Senkey nehmen die ganze Breite, Kreis und Balken
  die halbe; das Raster ist zweispaltig und wird unter 1100 px einspaltig.
- Fuß: die Abfrage in Schreibmaschinenschrift, gekürzt, mit dem ganzen Text im `title`.
- Das `⋯` öffnet: **Open in LOGS** (Tab-Wechsel mit Abfrage und Zeitraum), **Rename**, **Change
  form** (die erlaubten Formen der aktuellen Spalten), **Move up** / **Move down**, **Delete**
  (mit Rückfrage).

**Rechnen.** Beim Öffnen der Seite — also beim Tab-Wechsel auf Dashboard und beim Wechsel der
Unterseite — laufen die Kacheln **eine nach der anderen**, nicht gleichzeitig: Jede wartet auf die
Antwort der vorherigen. Vor dem Ergebnis zeigt die Kachel „Loading…"; eine Kachel, die noch nicht
dran war, zeigt „Queued". Der **Refresh**-Knopf oben in der Kopfzeile rechnet alle Kacheln neu
(ebenfalls hintereinander), das `↻` in der Kachel nur diese eine. Von selbst rechnet nichts nach;
die Uhrzeit im Kopf sagt, wie alt die Zahlen sind.

Das `limit` einer Kachel hängt an ihrer Form: 200 für eine Tabelle, 1000 für ein Bild (siehe
„Unvollständige Gruppenlisten"); eine Tabellenkachel zeigt höchstens 20 Zeilen (siehe unten). Jede
Kachel bringt ihr eigenes `AbortController`-Signal mit, damit ein Unterseiten-Wechsel laufende
Anfragen abbricht.

**Fehler und Leere.** Eine Kachel, deren Suche `400` ergibt, zeigt die Meldung des Servers als Text
und bleibt bedienbar (umbenennen, löschen, in LOGS öffnen). Eine leere Antwort zeigt
`chartEmptyHtml('No events in this range')`. Eine Form, die zu den Spalten nicht mehr passt — weil
der Server die Spalten anders liefert als beim Speichern —, zeigt die Tabelle und darunter die Zeile
„saved as <form>, which needs <Bedingung>".

**Trefferlisten als Kachel.** Erlaubt, aber nur über `| table f1, f2, …` und mit höchstens 20
Zeilen. So steht nie unbegrenzter Rohtext aus einem Sample auf der Startseite. Eine Abfrage ohne
Pipe lässt sich nicht speichern (SAVE ist gesperrt).

**Daten.** Neues Modul `webui/dashboards.py` mit einem `DashboardStore` nach dem Muster von
`submissions.json`: ein `threading.Lock`, Schreiben über `.tmp`, `flush`, `fsync` und `os.replace`
mit zehn Versuchen gegen `PermissionError`, defensives Lesen (jeder Satz wird geprüft, ein kaputter
Satz fällt weg, eine kaputte Datei ergibt eine leere Liste). Datei: `webui/dashboards.json`.

```
{"dashboards": [
  {"id": "d-<12 hex>", "name": "Beacon-Jagd", "created": "<ISO-8601 Z>",
   "panels": [
     {"id": "p-<12 hex>", "name": "Dropped ports", "query": "source=firewall action=DROP | top dst_port",
      "form": "pie", "earliest": "-24h", "latest": "", "created": "<ISO-8601 Z>"}
   ]}
]}
```

**Grenzen:** höchstens 10 Dashboards, 12 Kacheln je Dashboard, Name 1–60 Zeichen (Steuerzeichen
abgewiesen), Abfrage höchstens 4000 Zeichen wie in der Suche, `form` aus
`{table, pie, bars, line, sankey}`, `earliest`/`latest` höchstens 40 Zeichen. Namen dürfen sich
wiederholen; die `id` ist der Schlüssel.

**Routen** (alle schreibenden Routen fallen von selbst unter CSRF-, Host- und Wartungsprüfung):

| Methode | Route | Körper → Antwort |
|---|---|---|
| GET | `/api/dashboards` | – → `{dashboards: [...]}` |
| POST | `/api/dashboards` | `{name}` → `201 {dashboard}` |
| PATCH | `/api/dashboards/<id>` | `{name}` → `{dashboard}` |
| DELETE | `/api/dashboards/<id>` | – → `{deleted: true}` |
| POST | `/api/dashboards/<id>/panels` | `{name, query, form, earliest, latest}` → `201 {panel}` |
| PATCH | `/api/dashboards/<id>/panels/<pid>` | `{name?, form?, move?}` (`move`: `"up"`/`"down"`) → `{panel}` |
| DELETE | `/api/dashboards/<id>/panels/<pid>` | – → `{deleted: true}` |

Fehler im Hausstil: `400 {"error": "<Grund>"}` bei falschem Körper oder gerissener Grenze,
`404 {"error": "Dashboard not found."}` bzw. `"Panel not found."`, `507` nicht nötig — ein
Schreibfehler ergibt `500 {"error": "The dashboards could not be saved; see the web UI log."}`.
Kein Rechnen auf dem Server: Die Kacheln holen ihre Zahlen über `/api/logs/search`, das bereits als
Poll gilt und damit den Zugriffs-Ring nicht mit Nicht-Poll-Einträgen flutet.

## Tests

- **`tests/test_dashboards.py`** (neu, Server): Anlegen, Umbenennen, Löschen, Kachel anlegen,
  ändern, verschieben, löschen; jede Grenze (10 Dashboards, 12 Kacheln, Namenslänge,
  Steuerzeichen, unbekannte Form, zu lange Abfrage, unbekannte Felder im Körper); defensives Lesen
  (kaputte Datei, kaputter Satz, fehlende Felder); atomares Schreiben (ein Fehler beim Schreiben
  lässt die alte Datei stehen); CSRF greift; 503 während einer Wartung.
- **`tests/test_logs_ui.py`** (erweitert, Node): die Befehlskarte zeichnet alle Gruppen und fügt
  statt zu ersetzen ein; der `?`-Knopf klappt sie; die Reiter sperren mit Begründung; die Formwahl
  erlaubt genau die passenden Formen je Spaltenform; `lineSvg` und der Senkey aus zwei
  Namensspalten; ein Ergebnis mit Markup und 30.000 Zeichen bleibt Text; der SAVE-Dialog schickt
  genau die gewählte Form und den Zeitraum.
- **`tests/test_dashboards_ui.py`** (neu, Node): die Seitenleiste wechselt und hält die Wahl; die
  Kacheln laufen hintereinander, nicht gleichzeitig; `↻` lädt nur eine; ein Fehler in einer Kachel
  lässt die anderen laufen; das `⋯`-Menü; eine Form, die nicht mehr passt, fällt auf die Tabelle
  zurück; ein Kachelname mit `<script>` bleibt Text.
- **`tests/test_docs.py`** bleibt grün: sieben neue API-Zeilen in der README, das neue Modul in allen
  drei Deploy-Wegen.
- **`tests/test_theme.py`** bleibt grün: beide Themes gestalten Karte, Reiter, Formwahl und
  Kacheln; keine Farbe außerhalb `:root`; die neuen Funktionen stehen in den Listen.

## Was der Baumeister entscheidet

- Die genauen Halbsätze der Befehlskarte und der (i)-Texte, solange sie die Regeln einhalten.
- Wie die Reiter und die Formschalter im Markup aussehen (vorhandene Muster: `.chart-range`
  für Schalterreihen, `.view-toggle` für Umschalter), und ob die Formwahl eine eigene Zeile bekommt.
- Innenleben und Achsenbeschriftung von `lineSvg`, solange es `''` ohne Daten liefert und keine
  Farbe setzt, die nicht aus `_chartColor` kommt.
- Wie der Name einer Kachel aus der Abfrage vorbelegt wird.
- Ob der Kachel-Kopf die Uhrzeit oder „vor 3 min" zeigt (eines von beiden, nicht beides).
- Namen von Dateien, Funktionen, Konstanten und CSS-Klassen im Stil des Hauses.
