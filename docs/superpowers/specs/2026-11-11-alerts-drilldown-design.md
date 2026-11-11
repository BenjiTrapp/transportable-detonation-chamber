# Drilldown im Alerts-Tab: Bereich aufziehen, Pfad und BACK

## Absicht

Im Alerts-Tab grenzt ein Klick auf einen Balken von OVER TIME die Liste auf
dessen Zeitraum ein. Danach steht nur ein kleiner Chip „× 27 Jul“ unter der
Filterleiste. Der Nutzer hat ihn erst gefunden, als man ihn darauf hinwies.
Zurück geht es nur über das ×, und das springt gleich zu allen Alerts.

Der Nutzer möchte die Alerts in mehreren Schritten eingrenzen:
- In OVER TIME zieht er einen Bereich auf, mit dem gestrichelten Kasten wie
  in ALERT ACTIVITY auf dem Dashboard.
- Danach zeigt der ganze Tab nur noch diesen Bereich.
- Über den Diagrammen steht **BACK**. Hat er mehrfach eingegrenzt, geht es
  damit jeweils einen Schritt zurück. Nach dem letzten Schritt ist die
  Eingrenzung ganz aufgehoben.

Gewählt hat der Nutzer im Mockup mit echten Daten der VM die Variante **A**:
eine Drilldown-Leiste über den Diagrammen („genau das, was ich möchte“).

## Ziele

1. **Bereich aufziehen in OVER TIME** (Alerts-Tab)
   - Drücken auf die Balken und Ziehen um mindestens 5 px zeichnet den
     gestrichelten Kasten. Er geht über die ganze Höhe und rastet an ganzen
     Balken ein, wie auf dem Dashboard.
   - Loslassen setzt den Zeitraum vom Anfang des ersten bis zum Ende des
     letzten überstrichenen Balkens. Das ist ein Drilldown-Schritt.
   - Danach zeigen alle Karten und die Tabelle nur diesen Zeitraum, und die
     Balken teilen genau diesen Zeitraum neu auf.
   - Ein Klick ohne Ziehen auf einen Balken grenzt wie bisher auf diesen
     Balken ein, jetzt ebenfalls als Schritt. Leere Balken bleiben wie
     bisher ohne Wirkung.
   - Unter den Balken steht ein Hinweis wie auf dem Dashboard: „Drag across
     the bars to narrow the range · click a bar to show only its period“.
2. **Feinere Balken beim Eingrenzen**
   - OVER TIME nutzt die feinen Abschnitte, die `binByTime` mit der Option
     `fine` für den Sysmon-Tab schon kennt. Bei einer Spanne bis etwa 20
     Stunden sind die Abschnitte 1 s bis 30 min lang, höchstens 40 Balken.
     Längere Spannen behalten Stunden, Tage und Wochen.
   - Das gilt für jede Spanne, ob sie aus einem Drilldown stammt oder aus
     den Alerts selbst. Die Tabellenansicht (CHART/TABLE) folgt denselben
     Abschnitten.
   - Beispiel mit echten Daten: Der 27. Jul zeigt 24 Stundenbalken, 10:00–12:00
     zeigt 24 Balken zu je 5 Minuten.
   - Liegt ein Zeitraum nicht auf vollen Minuten, nennen ihn Pfad und Chip
     mit Sekunden. Tooltips tun das schon.
3. **Drilldown-Schritte und BACK**
   - **Was ein Schritt ist:**
     - ein Klick auf einen Balken oder ein aufgezogener Bereich in OVER TIME;
     - ein Klick auf ein Segment oder eine Legendenzeile in SEVERITY oder
       ENGINE;
     - ein Klick auf einen Knoten oder ein Band in FLOW;
     - der Sprung vom Dashboard in den Tab mit einem Filter (Kacheln,
       Schweregrad-Tags, Balken, Donut-Segmente über `openAlertsTab`). Die
       Kachel TOTAL ALERTS setzt keinen Filter und erzeugt keinen Schritt.
   - **Was ein Schritt speichert:** welche Filter er geändert hat und welchen
     Wert sie vorher hatten. Ein Klick, der nichts ändert, wird kein Schritt.
   - **BACK** setzt die vorherigen Werte des letzten Schritts wieder ein und
     entfernt ihn. Ist auch der erste Schritt zurückgenommen, bleibt kein
     Filter aus dem Drilldown übrig, und die Leiste verschwindet. BACK bleibt
     im Alerts-Tab, auch nach einem Sprung vom Dashboard.
   - **Ein Klick auf einen Schritt im Pfad** springt direkt zum Stand nach
     diesem Schritt, nimmt also alle späteren zurück. „ALL ALERTS“ nimmt alle
     zurück.
   - **Was selbst eingestellt ist, fasst BACK nicht an:** Schweregrad-Chips,
     Engine-Auswahl und Suche in der Filterleiste sowie das × an einem Chip.
     Das sind keine Schritte.
     - Ändert der Nutzer selbst einen Filter, den ein Schritt gesetzt hatte,
       vergessen die Schritte diesen Filter.
     - Ein Schritt, der dann keinen Filter mehr hat, fällt aus dem Pfad.
     - So zeigt der Pfad nur, was noch wirkt, und BACK überschreibt nie eine
       eigene Einstellung.
   - **Ein Sprung vom Dashboard** beginnt einen neuen Pfad. Er ersetzt den
     bisherigen Pfad durch genau einen Schritt, auch wenn sich dabei nichts
     ändert.
     - Als „vorher“ gilt für diesen Schritt: kein Filter. BACK zeigt danach
       alle Alerts.
     - Was `openAlertsTab` beim Sprung an eigenen Einstellungen löscht
       (Suche, Engine, Chips), bleibt wie heute gelöscht.
     - Der Schritt heißt nach dem, was der Sprung gesetzt hat.
     - Ein Sprung ohne Filter (Kachel TOTAL ALERTS) hinterlässt einen leeren
       Pfad.
   - Die Schritte bleiben bis zum Neuladen der Seite erhalten, wie heute alle
     Filter.
4. **Drilldown-Leiste (Variante A)**
   - Die neue Leiste steht zwischen der Überschrift des Tabs und den
     Diagrammen. Sie erscheint nur, solange es mindestens einen Schritt gibt.
   - Von links nach rechts enthält sie:
     - den Knopf **‹ BACK**, gut sichtbar in der Akzentfarbe;
     - die gedämpfte Beschriftung „DRILLDOWN“;
     - den Pfad, etwa `ALL ALERTS › 27 Jul › 27 Jul 10:00–12:00`. Der letzte
       Schritt ist der aktuelle und nicht anklickbar;
     - rechts die Anzahl, etwa „1,345 of 9,620 alerts“.
   - **Beim Scrollen** bleibt die Leiste oben stehen, die Filterleiste direkt
     darunter, der Tabellenkopf unter beiden. Die heutige Regel, dass die
     erste Zeile unter der Filterleiste beginnt, rechnet die Leiste mit ein.
     Keine Zeile darf verdeckt werden.
   - **Benennung der Schritte:**
     - ein Zeitraum wie der Chip (`chartRangeLabel`);
     - Schweregrade in Großbuchstaben mit „ + “ verbunden;
     - eine Engine mit ihrem Namen;
     - Kategorie, Regel und Prozess als `category: …`, `rule: …`,
       `process: …`;
     - mehrere Filter eines Schritts mit „ · “ verbunden;
     - ein Sprung vom Dashboard mit dem Vorsatz „Dashboard: “.
   - Lange Namen werden mit „…“ gekürzt, der volle Text steht im Tooltip.
   - **Eine Zeile:** Passt der Pfad nicht, fallen frühere Schritte zu „…“
     zusammen (ihr Tooltip nennt sie). BACK, „ALL ALERTS“ und der aktuelle
     Schritt bleiben immer sichtbar.
   - **Chips:** Die Chips in der Filterleiste bleiben mit ihrem ×, werden aber
     sichtbarer: größer und mit Rand in der Akzentfarbe, wie im Mockup.
   - **Themes:** Cyberpunk wie im Mockup, Classic in seinen Farben.
5. **Doku**
   - **README „Charts“:** Tabelle und Erläuterungen beschreiben das Aufziehen
     in OVER TIME, die feineren Balken, die Drilldown-Leiste, BACK und den
     Sprung über den Pfad.
   - **Weitere Texte:** einen Absatz in der Hilfe und die (i)-Texte von OVER
     TIME und der Alerts-Überschrift anpassen.
   - **Screenshot:** neu `static/alerts_drilldown.png` (Cyberpunk, 1920×960,
     Pfad `ALL ALERTS › 27 Jul › 27 Jul 10:00–12:00`), mit Bildunterschrift
     im Demo-Teil der README.
   - **Bestehende Screenshots** werden nur dann neu aufgenommen, wenn sie
     jetzt etwas anderes zeigen würden.

## Nicht-Ziele

- Schritte in der Browser-Adresse oder im Browser-Verlauf, also kein
  Zurück-Knopf des Browsers, kein Erhalt beim Neuladen, keine teilbaren Links.
- Änderungen am Dashboard. Sein Aufziehen grenzt weiter nur die Donuts ein,
  das × am Chip führt zum Preset zurück.
- Änderungen am Sysmon-Tab. Seine Balken bleiben Übersicht mit markiertem
  Zeitfenster.
- Eine Auswahl in zwei Richtungen. Der Kasten geht immer über die ganze Höhe
  und wählt nur Zeit.
- Ein Tastenkürzel für BACK, ein Rückgängig für selbst gesetzte Filter,
  Zoomen mit dem Mausrad.

## Anti-Ziele (Misserfolg, auch wenn es technisch läuft)

- BACK setzt etwas zurück, das der Nutzer selbst eingestellt hat.
- Der Pfad nennt einen Schritt, der nicht mehr wirkt.
- Die Leisten verdecken beim Scrollen Tabellenzeilen.
- Die Leiste ist wieder leicht zu übersehen, so klein wie heute der Chip.
- Ziehen löst zusätzlich einen Balkenklick aus. Mit echter Maus in Chrome
  funktioniert es nicht (siehe Rahmenbedingungen). Oder das Aufziehen auf
  dem Dashboard funktioniert danach schlechter.
- Nach dem Aufziehen zählt die Tabelle andere Alerts als die markierten
  Balken.
- Neue Alerts beim 5-Sekunden-Abruf zeichnen das Diagramm während des
  Ziehens neu, und der Kasten geht verloren.

## Rahmenbedingungen

- **Grundlage:** Vanilla JavaScript in `webui/static/js/app.js`, keine
  Bibliothek, Funktionen auf oberster Ebene. Es baut auf dem noch nicht
  gemergten Branch `feature/charts` auf.
- **Tests:** in `tests/test_charts.py`, ausgeführt in Node (`_function_source`,
  `_run_node`). Die CI läuft mit Node 20 unter `TZ=UTC` und
  `TZ=Europe/Berlin`.
- **Bestehende Tests:** Tests, die im Alerts-Tab für kurze Spannen
  Stundenbalken erwarten, werden auf die feinen Abschnitte umgestellt. Das
  Dashboard behält seine Stunden.
- **Farben:**
  - Farben nur als `var(--…)`.
  - In `style.css` stehen Farbwerte nur in `:root`.
  - `theme-cyberpunk.css` enthält nur Regeln unter `[data-theme="cyberpunk"]`.
  - Classic ändert sich nur durch die neue Leiste, die deutlicheren Chips
    und den Hinweis unter OVER TIME.
- **Escaping:** Die Namen im Pfad stammen aus den Alerts (Regeln, Prozesse).
  Sie werden escaped oder als `textContent` gesetzt. Klicks laufen über einen
  delegierten Handler, der eine Nummer aus einem `data-`-Attribut liest.
  Namen stehen nie in Inline-JavaScript.
- **Bedienbarkeit:**
  - BACK und die Schritte sind `<button>`.
  - Der aktuelle Schritt trägt `aria-current="step"`.
  - Die Leiste ist eine `nav` mit `aria-label="Drilldown"`.
- **Aufziehen:**
  - Dashboard und Alerts-Tab nutzen eine gemeinsame Umsetzung.
  - Die Lehren aus dem Dashboard bleiben erhalten:
    - Pointer-Capture erst ab 5 px Bewegung;
    - ein ruhiger Druck öffnet bzw. setzt den gedrückten Balken, egal wohin
      Chrome den Klick schickt;
    - Abbruch bei `!(event.buttons & 1)` und bei `contextmenu`;
    - der Klick nach einem Ziehen wird genau einmal unterdrückt.
  - Die bestehenden Dashboard-Tests müssen weiter bestehen.
  - Ein aufgezogener Bereich, der nur leere Balken enthält, setzt nichts,
    wie ein leerer Balken.
- **Neuzeichnen:** Alerts kommen alle 5 s neu. Während gezogen wird, zeichnet
  OVER TIME nicht neu, wie auf dem Dashboard. Nach dem Loslassen holt es das
  nach.
- **Einstiegspunkte im Code:**
  - Alerts-Tab: `onAlertsChartClick`, `selectAlertsSeverity`,
    `_applyAlertsChartFilter`, `setAlertsFilters`, `removeAlertsFilter`,
    `toggleAlertsSeverity`, die Engine-Auswahl (`onchange`), `openAlertsTab`,
    `renderAlertsCharts` (`alertSeverityBins`), `_drawAlertsTime`,
    `initAlertsTab`, `_followBarHeight`, `_alertsListTop` / `_tabListTop`.
  - Aufziehen auf dem Dashboard: `initDashboardCharts`,
    `onDashboardBrushStart`, `onDashboardBrushMove`, `onDashboardBrushEnd`,
    `onDashboardBrushCancel`, `_dashboardBrushStop`, `_dashboardBrushMark`,
    `_dashboardBinAt`, `_dashboardReleased` in `onDashboardChartClick`.
  - Abschnitte und Beschriftungen: `binByTime` (`fine`), `_chartFineStep`,
    `chartTimeBins`, `chartRangeLabel`.
- **Sonstiges:**
  - Die Oberfläche ist englisch.
  - Bei jeder Änderung an CSS oder JS werden die Asset-Versionen in
    `index.html` erhöht.
  - Den gesperrten Fremdnamen aus den Projektregeln nirgends verwenden.
  - Name und Adresse der internen Referenzseite kommen nie ins Repo.
- **Prüfung auf der VM:** auf der UTM-VM 192.168.64.4 in beiden Themes, bei
  1920 und 1280 px, mit echten Eingaben über CDP (`Input.dispatchMouseEvent`).
  Dafür startet der Builder ein eigenes Chrome mit frischem Profil. Er hängt
  sich nie an einen schon laufenden Debugging-Port.

## Ansätze

1. **Eine Liste der Schritte im Alerts-Tab (gewählt).**
   - Jeder Drilldown merkt sich, welche Filter er geändert hat und ihre
     vorherigen Werte. BACK und ein Klick auf einen Schritt setzen genau diese
     Werte wieder ein, die Leiste wird aus der Liste gezeichnet.
   - Das Aufziehen wird aus dem Dashboard in ein gemeinsames Stück verlegt.
     Die feinen Abschnitte gibt es schon.
   - *Kosten:* Die Schritte leben nur im Browser. Nach dem Neuladen sieht man
     wieder alle Alerts, wie heute bei allen Filtern.
2. **Vor jedem Schritt alle Filter speichern.**
   - BACK würde den kompletten Stand von vorher zurückholen.
   - Verworfen: Es nähme auch zurück, was der Nutzer nach dem Drilldown
     selbst eingestellt hat, etwa eine Suche. Das widerspricht der Vorgabe.
3. **Die Schritte in die Browser-Adresse schreiben.**
   - Damit gingen der Zurück-Knopf des Browsers, das Neuladen und Links.
   - Verworfen, aber später möglich: Die Web-UI speichert bisher nichts in
     der Adresse, nicht einmal den offenen Tab. Das wäre ein eigenes, viel
     größeres Vorhaben.

## Gestaltung

- **Vorlage:** Variante A im Mockup
  `.superpowers/brainstorm/59047-1794382864/content/drilldown-v1.html`.
  - Es enthält die drei Schritte mit echten Daten und die Leiste über den
    Diagrammen.
  - Darunter steht der Stand beim Scrollen: oben die Leiste, darunter die
    Filterleiste, dann die Tabelle.
  - Das Mockup liegt nur lokal (git-ignored). Es wurde mit
    `/private/var/folders/z1/5108m1hd4lx_m3__94n64bz40000gn/T/opencode/charts/drill.py`
    erzeugt.
- **Cyberpunk:**
  - Leiste: dunkle Kartenfläche mit pinkem Rand und leichtem Leuchten.
  - BACK: pink gefüllter Knopf.
  - Schritte: cyan und unterstrichen, der aktuelle weiß.
  - „DRILLDOWN“ und die Anzahl: gedämpft.
- **Classic:** gleicher Aufbau in den Classic-Variablen, mit Akzentrand.
  BACK sieht dort aus wie ein Hauptknopf.

## Dem Builder überlassen

- Datenstruktur der Schritte, Namen der Funktionen und die Schnittstelle des
  gemeinsamen Aufziehens.
- Genaue Formulierungen im Pfad innerhalb der Regeln oben und wie lange
  Pfade zusammenfallen.
- Genaues Aussehen der deutlicheren Chips, des Hinweises und des Cursors über
  den Balken.
- Aufteilung der Tests.

## Entscheidungen des Assistenten (zur Prüfung)

- Der Kasten rastet an ganzen Balken ein. So listet die Tabelle genau, was
  die Balken gezählt haben.
- Feine Abschnitte gelten für Spannen bis etwa 20 Stunden, wie im
  Sysmon-Tab.
- Jeder Klick in SEVERITY, ENGINE und FLOW ist ein Schritt, ebenso der
  Sprung vom Dashboard. So verstehe ich das Wort „Drilldown“.
- Ändert der Nutzer einen Filter selbst, vergessen die Schritte diesen
  Filter. Ein Schritt ohne Filter fällt aus dem Pfad.
- Nach einem Sprung vom Dashboard führt BACK zu allen Alerts. Was der Sprung
  an eigenen Einstellungen gelöscht hat, kommt nicht zurück. So hebt BACK am
  Ende die Filterung auf, wie gewünscht.
- Ein aufgezogener Bereich nur aus leeren Balken setzt nichts.
- Ein zu langer Pfad fällt in der Mitte zu „…“ zusammen.
- Die Chips werden deutlicher, und die Anzahl steht rechts in der Leiste,
  wie im Mockup.
- Ein neuer README-Screenshot `static/alerts_drilldown.png`.
