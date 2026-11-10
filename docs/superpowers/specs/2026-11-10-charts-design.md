# Diagramme: Dashboard, Alerts, weitere Ansichten und Sankeys

## Absicht

Die Detonation Chamber zeigt ihre Daten bisher fast nur als Zahlen und
Tabellen. Der Nutzer möchte sie grafisch aufbereitet sehen: auf dem
Dashboard ein Überblick, wie viel wann und wie schwer gemeldet wurde; im
Alerts-Tab Diagramme, mit denen man die Liste per Klick eingrenzt; in weiteren
Ansichten dort Grafiken, wo sie eine Frage schneller beantworten als die
Tabelle. Sankey-Diagramme zeigen, wohin sich Mengen verteilen (welche Engine
meldet welche Regel auf welchem Prozess; woraus ein Detonationsurteil
entsteht).

Gewählt hat der Nutzer anhand von Mockups mit echten Daten der VM:
Dashboard-Variante **B**, Alerts-Variante **A**, die als sinnvoll/mittel
eingeschätzten weiteren Ansichten und alle drei Sankeys.

## Ziele

1. **Dashboard (Variante B)**
   - Kennzahl-Kacheln bekommen einen Mini-Verlauf (Sparkline) über die
     letzten 45 Tage: TOTAL ALERTS (Alerts je Tag) und PROCESSES TRACKED
     (neu gesehene Prozesse je Tag, aus `first_seen`). Kacheln ohne
     Verlaufsdaten (Dienste, Regeln, Scanner) bleiben ohne.
   - Neue Karte **ALERT ACTIVITY** über den Dienstkarten, breit: gestapelte
     Balken je Zeitabschnitt nach Schweregrad. Zeitraum-Schalter
     **24H / 7D / 30D / ALL** (Standard **ALL**); im Diagramm lässt sich ein
     Bereich aufziehen, der den Zeitraum setzt. Ein Klick auf einen Balken
     öffnet den Alerts-Tab, gefiltert auf diesen Abschnitt.
   - Daneben untereinander zwei Donuts für den gewählten Zeitraum:
     **SEVERITY** und **CATEGORY**, je mit Legende (Name, Anzahl, Anteil).
     Ein Klick auf ein Segment öffnet den Alerts-Tab mit diesem Filter.
   - Die Dienstkarten bleiben darunter wie heute.
2. **Alerts-Tab (Variante A)**
   - Reihenfolge von oben: Diagrammleiste, Sankey-Karte, Filterleiste,
     Tabelle. Der Tab scrollt als Ganzes (die Tabelle verliert ihr eigenes
     Scrollen); die Filterleiste bleibt beim Scrollen oben stehen
     („sticky“), damit gesetzte Filter immer sichtbar sind.
   - Diagrammleiste: **SEVERITY** (Pie), **OVER TIME** (gestapelte Balken,
     doppelt so breit), **ENGINE** (Pie), etwa 170 px hoch.
   - Die Diagramme zeigen immer die Alerts des aktuellen Filters. Ein Klick
     auf ein Segment oder einen Balken setzt bzw. ergänzt den Filter
     (Schweregrad-Chip, Engine-Auswahl, neuer Zeitraum-Filter).
   - Darunter der **Sankey Engine → Regel → Prozess** des aktuellen Filters:
     die häufigsten Regeln und Prozesse einzeln, der Rest gesammelt als
     „other rules“ / „other processes“. Standard ist die gestauchte Breite
     (Wurzel), damit kleine Ströme lesbar bleiben; ein Schalter **LINEAR**
     zeigt echte Proportionen. Ein Klick auf einen Knoten oder Strom setzt den
     passenden Filter (Engine, Regel, Prozess).
3. **Sysmon-Tab**
   - Wie im Alerts-Tab: die Diagrammreihe steht über Filterleiste und
     Tabelle, der Tab scrollt als Ganzes, die Filterleiste bleibt stehen.
   - Karte **EVENTS OVER TIME**: gestapelte Balken der geladenen Ereignisse
     nach Event-Typ, Abschnittsgröße passend zur Zeitspanne. Ein Klick auf
     einen Balken grenzt die Tabelle auf diesen Abschnitt ein.
   - Karte **PROCESS → EVENT TYPE**: Sankey der geladenen Ereignisse
     (häufigste Images einzeln, Rest gesammelt).
4. **ThreatScan (Scan-Verlauf)**: Punktdiagramm **SCORE HISTORY** über die
   Scans des Verlaufs: ein Punkt je Scan mit Score, gefärbt nach Urteil,
   gestrichelte Schwellen SUSPICIOUS 2 und MALICIOUS 6; Tooltip mit Werkzeug,
   Ziel und Score; ein Klick öffnet den Eintrag in der Verlaufsliste. Scans
   ohne Score (z. B. Process Dump, ThreatCheck, capa) stehen in einer eigenen
   Spur „no score“ unter der Achse, ebenfalls nach Urteil gefärbt; die
   Tabellenansicht listet alle Scans.
5. **Submit (Einreichungsverlauf)**: Balken je Einreichung über der
   Verlaufstabelle, Höhe = Score, Farbe = Urteil. Dafür speichert der Server
   das berechnete Urteil (Label und Score) in der Einreichung, sobald
   `/api/detonation/results` es berechnet. Alte Einreichungen ohne
   gespeichertes Urteil erscheinen grau als „not evaluated“.
6. **Prozess-Detail im Graph-Tab** (Detailfeld eines Prozessknotens, dort
   stehen heute die Zähler Threats/Network/DNS/File/Registry/Injection):
   Donut **ACTIVITY MIX** aus den echten Sysmon-Aktivitäten dieser
   Prozessinstanz in den Graph-Daten von `/api/process-graph` (Netzwerk, DNS,
   Datei, Registry, Named Pipes, Injection). Die Alerts (Threats) sind kein
   Segment, sondern stehen als eigene Zahl daneben – die heutigen
   Aktivitätszähler zählen Alerts je Kategorie und würden sonst doppelt
   gezählt. Die rechte Prozess-Detailansicht bleibt unverändert.
7. **Detonationsergebnis (Submit-Tab und Detailansicht)**: Sankey
   **Prozess → Aktivität → Urteil**: links die Prozesse der Detonation, in
   der Mitte die Arten der Funde (EDR-Alerts, Speicherfunde, Netzwerk-Beaconing,
   Named Pipes, Exit Capture), rechts, was davon ins Urteil eingeht (das
   Urteils-Label) und was nicht zählt (schwach, Baseline, nicht korroboriert).
8. **Für alle Diagramme**: (i)-Erklärung und CHART/TABLE-Schalter wie bei den
   bestehenden Grafiken; die Tabellenansicht zeigt dieselben Zahlen,
   sortierbar. Beide Themes; Farben aus den Theme-Variablen, sodass ✶ die
   Diagramme ohne Neuladen umfärbt.

## Nicht-Ziele

- Keine Diagramm-Bibliothek, kein Build-Schritt.
- Keine Diagramme für ETW, Hex, FileMap und Pipes.
- Keine Heatmap Wochentag × Stunde (gehörte zur nicht gewählten Variante C).
- Keine MITRE-ATT&CK-Auswertung: die Alerts der VM tragen keine Tags.
- Kein Ausblenden von „Rauschen“ (z. B. der Run-Key-Regel auf `MsMpEng.exe`,
  64 % aller Alerts) in dieser Runde; die Diagramme sollen es gerade sichtbar
  machen, und der Filter grenzt ein.
- Kein Export der Diagramme als Bild.
- Keine neuen Server-Schnittstellen für Statistiken; einzige Server-Änderung
  ist das Speichern des Urteils je Einreichung.

## Anti-Ziele (Misserfolg, auch wenn es technisch läuft)

- Diagramme und Tabellen zeigen unterschiedliche Zahlen für denselben Filter
  oder Zeitraum.
- Diagramme bremsen das Polling (Alerts alle 5 s, Dashboard alle 10 s) oder
  das Umschalten der Tabs spürbar aus.
- Regel-, Prozess- oder Dateinamen (Angreiferdaten) können über Diagramm-
  Beschriftungen, Tooltips oder Tabellenansichten HTML einschleusen.
- Classic verändert sich über die neuen Karten hinaus.
- Ein Klick auf ein Diagramm setzt einen Filter, den man in der Filterleiste
  nicht sieht oder nicht zurücknehmen kann.
- Leere Daten (keine Alerts, Sysmon aus, kein Scan) erzeugen kaputte oder
  irreführende Grafiken statt eines Hinweises.

## Rahmenbedingungen

- Frontend: Vanilla-JS in `webui/static/js/app.js`, Funktionen auf oberster
  Ebene (die Tests ziehen sie per `_function_source` heraus und führen sie in
  Node aus); `webui/static/css/style.css` nur mit Variablen aus `:root`;
  `webui/static/css/theme-cyberpunk.css` nur unter `[data-theme="cyberpunk"]`;
  `webui/templates/index.html`. Keine neuen Abhängigkeiten.
- Vorhandene Bausteine: `state.alerts` (alle Alerts, vom Server aufsteigend
  nach Zeit), `filterAlerts(alerts, {severities, engine, text})` mit
  Groß-/Kleinschreibung-unabhängigem Vergleich und `unknown` → info,
  `openAlertsTab(filter)`, `newestAlerts`, die Bedienelemente
  `viewToggleHtml`/`cardViewAttrs`/`toggleCardView`, `data-info` mit (i),
  `table[data-sortable][data-sort-id]` mit Sortierung über einen
  MutationObserver, `themeColor`, `tdc:themechange`, Escaping-Helfer
  `escapeHtml`/`jsArg`/`jsInt`/`cssToken`.
- Echte Daten der VM: 9 620 Alerts (14. Juli – 9. November, stark gebündelt
  Juli–September), Schweregrade medium 6 720 / high 2 700 / critical 196 /
  low 4, Engines Sigma 9 415 / Yara 195 / Fibratus 10, Kategorien als Liste
  oder Text (`["registry"]`, `process`), 20 Regeln, 363 Prozesse, 51 Scans im
  Verlauf, 43 Einreichungen (Urteil bisher nie gespeichert, Feld `verdict`
  ist `null`).
- Sysmon-Ereignisse kommen aus `/api/sysmon` (Parameter `max`, `event_id`,
  `pid`, `since`, `until`); ein großer Teil sind Pipe-Ereignisse der Web UI
  selbst (`python.exe`).
- Oberfläche und README Englisch; Asset-Versionen erhöhen; Prüfung auf der
  VM mit eigenem Headless-Chrome.

## Ansätze

1. **Eigene SVG-Diagramme in `app.js` (gewählt).** Ein kleiner Baukasten
   (gestapelte Balken mit Bereichsauswahl, Donut/Pie, Sparkline, Punkte,
   Sankey) erzeugt SVG als Markup; Farben als `var(--…)` im SVG, Daten im
   Browser aus `state.alerts` und den vorhandenen Schnittstellen
   zusammengezählt. *Kosten:* eigener Code, vor allem Sankey-Anordnung und
   Bereichsauswahl. *Gewinn:* keine Abhängigkeit, passt zu Themes, Escaping,
   (i), CHART/TABLE und den Node-Tests.
2. **Diagramm-Bibliothek mitliefern** (ECharts, Chart.js + Sankey-Plugin).
   Verworfen: erste Frontend-Abhängigkeit (200 KB – 1 MB), Theme-Anbindung
   per JavaScript, Tabellenansicht und Bedienelemente müssten angepasst werden.
3. **Server rendert Bilder.** Verworfen: kein Klick-Filter, keine
   Bereichsauswahl, kein sofortiges Umfärben bei ✶.

## Gestaltung

- Aussehen wie in den Mockups: Karten im Stil der bestehenden Karten,
  Abschnittstitel in Großbuchstaben, Legenden mit Farbe, Name, Anzahl,
  Anteil; Schweregradfarben aus `--severity-*`; Kategorie-, Engine- und
  Sankey-Farben aus der Palette des Themes.
- Tooltips über SVG-`<title>` bzw. ein schwebendes Feld; Beschriftungen
  werden gekürzt (Ellipse), der volle Text steht im Tooltip.
- Leere Daten: die Karte zeigt einen kurzen Hinweis statt einer leeren
  Grafik („No alerts in this range“, „Sysmon not available“, …).

## Dem Builder überlassen

- Abschnittsgrößen der Zeitachsen (Stunde/Tag/Woche) je nach Zeitspanne.
- Anzahl der einzeln gezeigten Regeln/Prozesse/Images im Sankey (mindestens
  sechs), Knotenreihenfolge, Abstände.
- Genaue Zuordnung der Detonationsfunde zu den Sankey-Spalten, solange die
  Summen zu den Zahlen der Ergebnisansicht passen.
- Wie die Bereichsauswahl bedient wird (Ziehen mit der Maus; Tastatur über
  die Zeitraum-Schalter genügt).
- Ob die Diagrammfunktionen in einem Block von `app.js` gesammelt werden.

## Entscheidungen des Assistenten (zur Prüfung)

- Zeitraum-Standard auf dem Dashboard ist **ALL**, weil die Daten der VM
  gebündelt in der Vergangenheit liegen und 30D heute fast leer wäre.
- Sparklines nur für TOTAL ALERTS und PROCESSES TRACKED (für Dienste,
  Regeln und Scanner gibt es keinen Verlauf).
- Sankey standardmäßig gestaucht (Wurzel) mit Schalter LINEAR.
- Kein eigener Rauschfilter; Eingrenzen über die vorhandenen Filter.
- Submit: Einreichungen ohne gespeichertes Urteil grau als „not evaluated“.
- Sysmon-Sankey als eigene Karte neben der Zeitachse statt als dritte
  Ansicht derselben Karte.
- Alerts- und Sysmon-Tab scrollen als Ganzes mit stehender Filterleiste
  (statt eigener Tabellen-Scrollfläche), damit Diagramme und Tabelle Platz
  haben.
- ACTIVITY MIX sitzt im Graph-Detailfeld und nutzt die Sysmon-Daten des
  Graphen; Alerts zählen dort nicht als Segment.
- Scans ohne Score bekommen eine eigene Spur „no score“.
