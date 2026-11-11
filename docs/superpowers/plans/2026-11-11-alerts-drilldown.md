# Drilldown im Alerts-Tab – Implementierungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Im Alerts-Tab lässt sich in OVER TIME ein Bereich aufziehen. Jeder Drilldown ist ein Schritt in einer gut sichtbaren Leiste über den Diagrammen, mit **‹ BACK** und anklickbarem Pfad. Beim Eingrenzen werden die Balken feiner.

**Architecture:**
- Eine Liste der Schritte im Alerts-Tab. Jeder Schritt merkt sich, welche Filter er geändert hat und welchen Wert sie vorher hatten. BACK und der Pfad setzen genau diese Werte wieder ein.
- Das Aufziehen des Dashboards wird zu einer gemeinsamen Umsetzung für beide Balkendiagramme.
- Die feinen Abschnitte (`binByTime` mit `fine`) gibt es schon im Sysmon-Tab; sie werden für OVER TIME eingeschaltet.

**Tech Stack:** Vanilla JS (`webui/static/js/app.js`, kein Build), SVG, CSS, pytest + Node.

**Spec:** `docs/superpowers/specs/2026-11-11-alerts-drilldown-design.md`

**Mockup (Vorlage, Variante A):** `.superpowers/brainstorm/59047-1794382864/content/drilldown-v1.html`, erzeugt von `/private/var/folders/z1/5108m1hd4lx_m3__94n64bz40000gn/T/opencode/charts/drill.py`.

## Global Constraints

- **Grundlage:** Vanilla JS in `webui/static/js/app.js`, keine Bibliothek, Funktionen auf oberster Ebene.
- **Tests:**
  - in `tests/test_charts.py`, ausgeführt in Node (`_function_source`, `_run_node`);
  - neue Funktionen, Konstanten und `let` kommen in die Listen in `tests/test_theme.py` (`ALERTS_TAB_FUNCTIONS`, `ALERTS_TAB_CONSTS`, `ALERTS_TAB_LETS`, `DASHBOARD_CHART_*`);
  - die CI läuft mit Node 20 unter `TZ=UTC` und `TZ=Europe/Berlin`. Node 20 liegt unter `/Users/derbenji/.npm/_npx/ebaba8b9e55fd0a9/node_modules/node/bin`.
- **Farben:**
  - Farben nur als `var(--…)`.
  - In `style.css` stehen Farbwerte nur in `:root`.
  - `theme-cyberpunk.css` enthält nur Regeln unter `[data-theme="cyberpunk"]`.
  - Classic ändert sich nur durch die neue Leiste, die deutlicheren Chips und den Hinweis unter OVER TIME.
- **Escaping:** Die Namen im Pfad werden escaped (`escapeHtml`) oder als `textContent` gesetzt. Klicks laufen über einen delegierten Handler, der eine Nummer aus einem `data-`-Attribut liest. Namen stehen nie in Inline-JavaScript.
- **Bedienbarkeit:**
  - BACK und die Schritte sind `<button>`.
  - Der aktuelle Schritt trägt `aria-current="step"`.
  - Die Leiste ist eine `nav` mit `aria-label="Drilldown"`.
- **Aufziehen:**
  - Dashboard und Alerts-Tab nutzen eine gemeinsame Umsetzung.
  - Pointer-Capture erst ab 5 px Bewegung.
  - Ein ruhiger Druck setzt den gedrückten Balken, egal wohin Chrome den Klick schickt.
  - Abbruch bei `!(event.buttons & 1)` und bei `contextmenu`.
  - Der Klick nach einem Ziehen wird genau einmal unterdrückt.
  - Die bestehenden Dashboard-Tests bestehen weiter.
- **Feine Abschnitte:** nur in OVER TIME im Alerts-Tab. Spannen bis etwa 20 h bekommen Schritte von 1 s bis 30 min, höchstens 40 Balken. Das Dashboard behält seine Stunden.
- **Neuzeichnen:** Während gezogen wird, zeichnet OVER TIME nicht neu. Nach dem Loslassen holt es das nach.
- **Sonstiges:**
  - Die Oberfläche ist englisch.
  - Bei jeder Änderung an CSS oder JS werden die Asset-Versionen in `index.html` erhöht.
  - Den gesperrten Fremdnamen aus den Projektregeln nirgends verwenden.
  - Name und Adresse der internen Referenzseite kommen nie ins Repo.
- **Prüfung auf der VM:**
  - auf der UTM-VM 192.168.64.4, beide Themes, bei 1920 und 1280 px;
  - echte Eingaben über CDP (`Input.dispatchMouseEvent`);
  - ein eigenes Chrome mit frischem Profil starten, nie an einen schon laufenden Debugging-Port hängen, danach beenden und das Profil löschen;
  - Deploy: `python3 scripts/deploy-utm.py --vm-ip 192.168.64.4 --vm-user tdc --vm-pass tdc --restart`.

## Review Focus

1. **Neue Alerts während eines Drilldowns** (Abruf alle 5 s): Pfad und Schritte bleiben, die Anzahl in der Leiste und die Tabelle folgen den neuen Alerts. Während des Ziehens bleibt der Kasten stehen. Tests in Task 4 und Task 5.
2. **Feindselige oder sehr lange Namen im Pfad** (Regel oder Prozess mit `<`, `"` oder 300 Zeichen): Sie bleiben Text, und die Leiste bleibt einzeilig. Test in Task 5.
3. **Sommerzeit beim Eingrenzen** (Europe/Berlin, Nacht zum 25. Okt 2026): Die 15-Minuten-Balken folgen lückenlos aufeinander, Namen in Ortszeit. Test in Task 2.
4. **Scrollen mit sichtbarer Leiste:** Nach einem Filterwechsel im Tab beginnt die erste Zeile unter beiden Leisten und ist nicht verdeckt. `openAlertsTab` springt nach oben. Test in Task 5.
5. **Eigene Änderungen mitten im Pfad:** zum Beispiel × am Bereichs-Chip zwischen zwei Bereichsschritten und einem Regelschritt, oder die Engine-Auswahl nach einem Engine-Schritt. Der Pfad nennt danach nur noch, was wirkt, und BACK überschreibt nichts Eigenes. Test in Task 3.

---

## Dateistruktur

| Datei | Verantwortung |
|---|---|
| `webui/static/js/app.js` | gemeinsames Aufziehen (Abschnitt Dashboard), Drilldown-Schritte, Leiste, OVER TIME (Abschnitt Alerts-Tab), `chartRangeLabel` (Abschnitt CHARTS) |
| `webui/templates/index.html` | Leiste im `#tab-alerts`, Engine-Auswahl `onchange`, (i)-Texte, Hilfe, Asset-Versionen |
| `webui/static/css/style.css` | Leiste, stehende Leisten, deutlichere Chips, Hinweis, Aufziehen in OVER TIME |
| `webui/static/css/theme-cyberpunk.css` | Cyberpunk-Aussehen der Leiste und der Chips |
| `tests/test_charts.py`, `tests/test_theme.py` | Verhalten und Listen der Funktionen |
| `README.md`, `static/alerts_drilldown.png` | Doku und Screenshot |

---

### Task 1: Gemeinsames Aufziehen für Balkendiagramme

**Files:**
- `webui/static/js/app.js`: Dashboard-Abschnitt ~1237–1376; dazu `renderDashboardCharts`, `redrawDashboardChartsOnResize` und `onDashboardChartClick`.
- `tests/test_theme.py`: `DASHBOARD_CHART_FUNCTIONS`, `DASHBOARD_CHART_LETS`.
- `tests/test_charts.py`.

**Interfaces – Produces:**
- **Host:** `{ view: '<id des Elements mit den Balken>', bins() -> [{start, end, total}], onRange(first, last, bins), onStop() }`.
  - `bins()` liefert die gezeichneten Abschnitte, und zwar beim Drücken. Die Aufziehung behält diese bis zum Loslassen.
  - `onRange` erhält die Nummern des ersten und letzten überstrichenen Balkens.
  - `onStop` ist optional: Der Druck ist vorbei, gezogen oder nicht, auch bei Abbruch.
- `const DASHBOARD_BARS_BRUSH`: der Host für ALERT ACTIVITY. Sein `onRange` ruft `setDashboardRange('custom', bins[first].start, bins[last].end)` auf, wie heute.
- `initBarsBrush(host)`:
  - meldet `pointerdown` auf `host.view` an, einmal je Host;
  - meldet `pointermove`, `pointerup`, `pointercancel` und `contextmenu` auf `document` in der Capture-Phase an, einmal je Seite.
- `barsBrushActive(host) -> boolean`: Auf den Balken dieses Hosts wird gerade gezogen.
- `barsClickPeriod(event, host) -> {from, to} | null`: wofür der Klick auf die Balken steht.
  - Nach einem Ziehen: `null`, genau einmal.
  - Nach einem ruhigen Druck: der Zeitraum des gedrückten Balkens, egal wohin der Klick ging.
  - Ohne Druck: der Zeitraum des angeklickten Balkens.
  - Ein Balken ohne Alerts gibt immer `null`.
- `_binPeriod(bin) -> {from, to} | null` ersetzt `_dashboardBinPeriod`.
- `onBarsBrushStart(event, host)`, `onBarsBrushMove`, `onBarsBrushEnd`, `onBarsBrushCancel`, `_barsBrushStop(release)`, `_barsBrushMark(brush)`, `_barsBinAt(svg, clientX, n)` und `let _barsBrush`, `let _barsReleased` ersetzen die `_dashboardBrush*`- und `onDashboardBrush*`-Gegenstücke.
- `initDashboardCharts()` ruft `initBarsBrush(DASHBOARD_BARS_BRUSH)` auf.
- `renderDashboardCharts` und `redrawDashboardChartsOnResize` prüfen `barsBrushActive(DASHBOARD_BARS_BRUSH)`.

- [ ] **Step 1: Failing test** `test_bars_brush_serves_two_charts_apart`. Zwei Hosts auf zwei Ansichten im Fake-DOM, mit Chromes Capture-Verhalten wie in `test_dashboard_bars_take_a_range_drawn_across_them`. Erwartet:
  - Ein Ziehen auf A von Balken 2 bis 5 ruft nur `A.onRange(2, 5, bins)` auf.
  - `barsBrushActive(A)` ist nur während dieses Ziehens `true`, `barsBrushActive(B)` nie.
  - Ein ruhiger Druck auf B gibt `barsClickPeriod(click, B)` = Zeitraum des gedrückten Balkens; der Klick dazu gibt für A `null`.
  - Nach zwei `initBarsBrush`-Aufrufen ist jeder `document`-Listener genau einmal angemeldet.
  - `onStop` läuft genau einmal je Druck, auch bei `pointercancel`.
- [ ] **Step 2:** Den Test laufen lassen, er schlägt fehl (`initBarsBrush` fehlt).
- [ ] **Step 3:** Umbauen; das Verhalten des Dashboards bleibt gleich.
  - Die Prüfung in `test_a_range_being_drawn_ends_when_its_button_is_gone`, die nach `addEventListener('contextmenu', onDashboardBrushCancel, true)` in `initDashboardCharts` sucht, wird zu `addEventListener('contextmenu', onBarsBrushCancel, true)` in `initBarsBrush`.
  - Sonst bleiben die Dashboard-Tests, wie sie sind.
- [ ] **Step 4:** Ausführen:
  - `webui/.venv/bin/python -m pytest tests/test_charts.py tests/test_theme.py -q`, mit Node 20 unter `TZ=UTC` und `TZ=Europe/Berlin`;
  - `node --check webui/static/js/app.js`;
  - `make -s unit-test`.

  Alles muss grün sein.
- [ ] **Step 5: Commit** `refactor(charts): shared range drawing for bar charts` (Asset-Version `app.js` erhöhen).

### Task 2: Feinere Balken und Sekunden in Bereichsnamen

**Files:**
- `webui/static/js/app.js`:
  - `renderAlertsCharts` ~1791: `alertSeverityBins(list, { from, to, fine: true })`;
  - `_alertsTimeBarsSvg` ~1924: zusätzlich `step: time.step`;
  - `chartRangeLabel` ~2726.
- `tests/test_charts.py`.

**Interfaces – Produces:**
- OVER TIME im Alerts-Tab teilt Spannen, für die `_chartFineStep(span) > 0`, in Sekunden- oder Minutenschritte (`unit` `'second'` oder `'minute'`, mit `step`). Die Tabellenansicht folgt denselben Abschnitten. ALERT ACTIVITY auf dem Dashboard bleibt bei Stunden, Tagen und Wochen.
- `chartRangeLabel(from, to)` nennt Zeiten mit Sekunden, sobald eine Grenze nicht auf einer vollen Minute liegt (lokale Sekunden oder Millisekunden ≠ 0). Alles andere bleibt unverändert.

- [ ] **Step 1: Failing tests**
  - `test_alerts_over_time_gets_finer_for_short_spans(zone)` für die Zonen `UTC` und `Europe/Berlin`:
    - Alerts am 27. Jul zwischen 10:00 und 12:00 Ortszeit, Filter `setAlertsFilters({from: 10:00, to: 12:00})`.
    - Ergebnis: 24 Abschnitte zu `300000` ms, der erste beginnt bei `from`, der letzte endet bei `to`. Die Summe der Abschnitte ist gleich der Trefferzahl. Eine Zeile der Tabellenansicht heißt `27 Jul 2026, 10:10–10:15`.
    - Der Bereich 27. Jul 00:00 bis 28. Jul 00:00 behält 24 Stundenbalken.
    - Das Dashboard mit `24H` behält `unit` `hour`.
    - In `Europe/Berlin`: Der Bereich 24. Okt 2026 22:00 bis 25. Okt 2026 06:00 Ortszeit (über die Umstellung) gibt lückenlose Abschnitte zu `900000` ms; der erste beginnt bei `from`, der letzte endet bei `to`.
  - `test_chart_range_label_names_seconds_when_needed(zone)`:
    - `chartRangeLabel(27 Jul 11:45:10, 27 Jul 11:45:40)` ergibt `27 Jul 11:45:10–11:45:40`.
    - `(11:45:00, 12:00:00)` ergibt `27 Jul 11:45–12:00`.
    - `(27 Jul 00:00, 28 Jul 00:00)` ergibt `27 Jul`.
    - `(27 Jul 23:59:30, 28 Jul 00:00:30)` ergibt `27 Jul 23:59:30 – 28 Jul 00:00:30`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren. Bestehende Tests, die im Alerts-Tab für Spannen bis 20 h Stundenbalken erwarten, werden auf die feinen Abschnitte umgestellt; ihr Zweck bleibt.
- [ ] **Step 4:** Tests grün (Node 20, beide Zonen), dazu `node --check` und `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(alerts): finer bars for short ranges` (Asset-Version erhöhen).

### Task 3: Drilldown-Schritte (Modell und Anbindung)

**Files:**
- `webui/static/js/app.js`, Abschnitt Alerts-Tab:
  - neuer Zustand und neue Funktionen;
  - angepasst werden `onAlertsChartClick` (Zweig `time`), `_applyAlertsChartFilter`, `selectAlertsSeverity`, `toggleAlertsSeverity`, `removeAlertsFilter` und `openAlertsTab`.
- `webui/templates/index.html`: Engine-Auswahl `onchange="onAlertsEngineChange()"`.
- `tests/test_theme.py` (Listen), `tests/test_charts.py`.

**Interfaces – Produces:**
- `const alertsDrilldown = []`: die Schritte, älteste zuerst. Ein Schritt ist `{ dashboard: boolean, before: {<art>: wert}, after: {<art>: wert} }`. Die Arten:
  - `range`: `{from, to}`;
  - `severities`: Liste in der Reihenfolge von `ALERT_SEVERITIES`;
  - `engine`: Text, `''` für keine;
  - `category`, `rule`, `process`: Text oder `null`.
- `alertsDrillValues() -> {range, severities, engine, category, rule, process}`: die aktuellen Werte, aus den Bedienelementen und `alertsExtraFilter`.
- `drillAlerts(change) -> boolean`:
  - `change` hat Filterfelder wie `filterAlerts`: `{from, to}`, `{severities}`, `{engine}`, `{category}`, `{rule}`, `{process}`, auch kombiniert.
  - Setzt diese Felder, die anderen bleiben.
  - Legt einen Schritt mit `before` und `after` der Arten an, die sich geändert haben. Verglichen wird wie in den Filtern: Engine und Namen über `_alertsNameKey`, Schweregrade als Menge, der Bereich über beide Zahlen.
  - Ändert sich nichts, entsteht kein Schritt, und die Funktion gibt `false` zurück.
  - Zeichnet den Tab neu (`renderAlertsTab`).
- `alertsDrillBack()`: setzt `before` des letzten Schritts wieder ein, entfernt ihn und zeichnet neu.
- `alertsDrillTo(index)`: nimmt alle Schritte nach `index` zurück, den neuesten zuerst; `-1` nimmt alle zurück. Zeichnet neu.
- `forgetAlertsDrill(kinds)`: Die Schritte vergessen diese Arten; ein Schritt ohne Arten fällt heraus.
- `alertsStepLabel(step) -> string`:
  - Reihenfolge der Arten: range, severities, engine, category, rule, process.
  - `range` über `chartRangeLabel`.
  - Schweregrade in Großbuchstaben, mit ` + ` verbunden.
  - Die Engine mit ihrem Namen.
  - Die anderen als `category: …`, `rule: …`, `process: …`.
  - Mehrere Arten mit ` · ` verbunden; ein Sprung vom Dashboard mit `Dashboard: ` davor.
- `onAlertsEngineChange()`: vergisst `engine` und zeichnet neu.
- **Anbindung:**
  - Balkenklick → `drillAlerts({from, to})`.
  - Engine-Segment → `drillAlerts({engine})`.
  - `selectAlertsSeverity(key)` → `drillAlerts({severities: [key]})`.
  - Sankey: `_applyAlertsChartFilter(change)` → `drillAlerts(change)`.
  - `toggleAlertsSeverity` vergisst `severities`, `removeAlertsFilter(kind)` vergisst `range` bzw. `kind`.
  - `openAlertsTab(filter)` leert `alertsDrilldown`. Setzt der Sprung einen Filter, legt er genau einen Schritt `{dashboard: true}` an, auch wenn sich nichts ändert. Dessen `before` ist für jede gesetzte Art „kein Filter“ (`range` `{from: null, to: null}`, `severities` `[]`, `engine` `''`, Namen `null`), sein `after` sind die gesetzten Werte. `openAlertsTab({})` hinterlässt keinen Schritt.

- [ ] **Step 1: Failing tests**
  - `test_drilldown_steps_back_and_jump(zone)` mit `ALERT_CHARTS_FIXTURE`:
    - Balkenklick auf einen Tag, dann `drillAlerts` auf 10:00–12:00, dann ein Regelknoten (`_applyAlertsChartFilter({rule: 'Run Key'})`).
    - Die Labels heißen `[<Tag>, '<Tag> 10:00–12:00', 'rule: Run Key']`.
    - `alertsDrillBack()` stellt genau Zählung und Zeilen des zweiten Stands wieder her (`rule` ist `null`).
    - `alertsDrillTo(0)` lässt nur den Tag übrig.
    - `alertsDrillTo(-1)` hinterlässt keine Schritte, keine Filter und `count === '2345 of 2345'`.
    - Das Severity-Segment `high` heißt `HIGH`, das Engine-Segment `Sigma` (erste Schreibweise).
    - Ein zweiter Klick auf dasselbe Segment oder dieselbe Engine legt keinen Schritt an.
  - `test_drilldown_leaves_own_settings_alone()`:
    - Eine Suche nach Schritt 1 bleibt nach BACK erhalten.
    - Ein Schweregrad-Chip, der nach einem Severity-Schritt umgeschaltet wird, nimmt diesen Schritt aus der Liste; BACK überspringt ihn.
    - Eine Engine-Auswahl nach einem Engine-Schritt wird vergessen.
    - Zwei Bereichsschritte, dann ein Regelschritt, dann × am Bereichs-Chip: Übrig bleibt nur der Regelschritt. BACK setzt die Regel auf `null`, der Bereich bleibt leer.
  - `test_dashboard_jump_starts_a_new_path()`:
    - Bei zwei vorhandenen Schritten ergibt `openAlertsTab({severities: ['critical', 'high']})` genau einen Schritt `Dashboard: CRITICAL + HIGH`.
    - BACK hinterlässt keine Schritte und keinen gedrückten Chip, der Tab bleibt `alerts`, die Suche bleibt leer.
    - `openAlertsTab({category: 'registry', from, to})` heißt `Dashboard: 14 Jul – 20 Jul · category: registry`.
    - Derselbe Sprung zweimal ergibt genau einen Schritt. `openAlertsTab({})` ergibt keinen.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren. Bestehende Tests der Klick-Filter (`test_alerts_chart_clicks_set_visible_filters`, Chips, `selectAlertsSeverity`) bleiben grün.
- [ ] **Step 4:** Tests grün (Node 20, beide Zonen), dazu `node --check` und `make -s unit-test`.
- [ ] **Step 5: Commit** `feat(alerts): drilldown steps` (Asset-Versionen erhöhen).

### Task 4: Aufziehen in OVER TIME

**Files:**
- `webui/static/js/app.js`: `ALERTS_BARS_BRUSH`, `initAlertsTab`, `onAlertsChartClick` (Zweig `time`), `_drawAlertsTime`.
- `webui/templates/index.html`: (i) von OVER TIME.
- `webui/static/css/style.css`: `#alerts-time-chart` bekommt `user-select: none`, `touch-action: pan-y` und Stile für den Hinweis.
- `tests/test_charts.py`, `tests/test_theme.py`.

**Interfaces:**
- **Consumes:** `initBarsBrush`, `barsBrushActive`, `barsClickPeriod` (Task 1); `drillAlerts` (Task 3).
- **Produces:** `const ALERTS_BARS_BRUSH = { view: 'alerts-time-chart', bins, onRange, onStop }`.
  - `bins` sind die gezeichneten Abschnitte aus `_alertsChartsDrawn.time.bins`.
  - `onRange(first, last, bins)` ruft `drillAlerts({from: bins[first].start, to: bins[last].end})` auf, aber nur, wenn einer dieser Balken `total > 0` hat. Sonst passiert nichts.
  - `onStop` zeichnet OVER TIME aus `_alertsChartsDrawn` neu, wenn das während des Ziehens ausgelassen wurde.
- **Zeichnen:** `_drawAlertsTime` zeichnet nicht, solange `barsBrushActive(ALERTS_BARS_BRUSH)`. Der Balkenklick nutzt `barsClickPeriod(event, ALERTS_BARS_BRUSH)`.
- **Hinweis** unter den Balken, nur wenn Balken da sind: `Drag across the bars to narrow the range · click a bar to show only its period`.
- **(i) von OVER TIME:** `The alerts of the current filters per period, stacked by severity; alerts without a time are noted below the bars. Drag across the bars or click a bar to narrow the tab to that period, BACK above the charts goes back a step.`

- [ ] **Step 1: Failing tests**
  - `test_alerts_bars_take_a_range_drawn_across_them()`: mit Chromes Capture-Verhalten.
    - Ein Ziehen von Balken 2 bis 5 ergibt genau einen Schritt von `bins[2].start` bis `bins[5].end`. Die Zählung `n of m` ist gleich der Summe dieser vier Balken. Der Klick nach dem Ziehen legt keinen zweiten Schritt an.
    - Ein ruhiger Druck auf einen Balken mit Alerts ergibt einen Schritt auf diesen Balken, auch wenn der Klick nach einem Abrutschen auf das `<svg>` geht.
    - Ein Ziehen nur über leere Balken legt keinen Schritt an.
    - Neue Alerts plus `renderAlertsTab()` während des Ziehens lassen `<svg>` und Kasten stehen.
    - Nach einem abgebrochenen Ziehen zeigt OVER TIME die neuen Alerts.
    - Ein Ziehen auf dem Dashboard legt im Alerts-Tab keinen Schritt an.
  - `test_alerts_over_time_hint_and_info()`:
    - Der Hinweis steht unter den Balken.
    - Er fehlt, wenn keine Alerts passen.
    - Der (i)-Text enthält `Drag across the bars`.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren.
- [ ] **Step 4:** Tests grün (Node 20, beide Zonen), dazu `node --check` und `make -s unit-test`.
- [ ] **Step 5: Sichtprüfung auf der VM:** Deploy (siehe Global Constraints), dann:
  - beide Themes, bei 1920 und 1280 px;
  - echt ziehen und klicken: Tag 27 Jul, dann 10:00–12:00 ergibt 24 Balken zu 5 Minuten;
  - ein Dashboard-Ziehen funktioniert weiter;
  - jedes PNG lesen.
- [ ] **Step 6: Commit** `feat(alerts): draw a range across OVER TIME` (Asset-Versionen erhöhen).

### Task 5: Drilldown-Leiste mit BACK

**Files:**
- `webui/templates/index.html`:
  - Leiste zwischen `.content-header` und `#alerts-charts` im `#tab-alerts`;
  - (i) der Leiste;
  - (i) der Überschrift „Alerts“, soll stimmen und höchstens 300 Zeichen haben.
- `webui/static/js/app.js`: `renderAlertsTab`, `initAlertsTab`, `_alertsListTop`.
- `webui/static/css/style.css`, `webui/static/css/theme-cyberpunk.css`.
- `tests/test_charts.py`. In `tests/test_theme.py` werden diese Tests angepasst, ihr Zweck bleibt:
  - `test_the_alerts_tab_scrolls_as_a_whole_under_a_standing_filter_bar`;
  - `test_the_alerts_table_head_stands_under_the_filter_bar` (jetzt mit den neuen Abständen).

**Interfaces:**
- **Consumes:** `alertsDrilldown`, `alertsDrillBack`, `alertsDrillTo`, `alertsStepLabel` (Task 3).
- **Produces:**
  - **Gerüst (statisch):**
    ```html
    <nav class="alerts-drill" id="alerts-drill" aria-label="Drilldown" hidden onclick="onAlertsDrillClick(event)">
      <button type="button" class="alerts-drill-back" data-drill="back">‹ BACK</button>
      <span class="alerts-drill-label" data-info="…">DRILLDOWN</span>
      <span class="alerts-drill-path" id="alerts-drill-path"></span>
      <span class="alerts-drill-count" id="alerts-drill-count"></span>
    </nav>
    ```
    - Das `data-info` heißt: `Each click on a chart and each range drawn across OVER TIME is a step here. BACK goes back one step, a step goes back to it, ALL ALERTS takes every step off.`
  - `const ALERTS_DRILL_VISIBLE = 3`.
  - `renderAlertsDrillBar(shown, total)`:
    - Die Leiste ist `hidden`, solange es keine Schritte gibt.
    - **Pfad:** zuerst `<button class="alerts-drill-step" data-drill-step="-1">ALL ALERTS</button>`, dann ältere Schritte als `<span class="alerts-drill-more" title="<Label › Label>">…</span>`, dann die letzten `ALERTS_DRILL_VISIBLE` Schritte. Frühere Schritte sind `<button class="alerts-drill-step" data-drill-step="<i>">`. Der letzte ist ein `<span class="alerts-drill-step is-current" aria-current="step">`.
    - Jeder Schritt hat `title` = volles Label. Dazwischen steht `<span class="alerts-drill-sep" aria-hidden="true">›</span>`.
    - **Zählung:** `${_chartNumber(shown)} of ${_chartNumber(total)} alerts`.
    - `renderAlertsTab` ruft die Funktion nach jedem Neuzeichnen mit seiner Trefferzahl auf.
  - `onAlertsDrillClick(event)`:
    - `[data-drill="back"]` → `alertsDrillBack()`.
    - `[data-drill-step]` → `alertsDrillTo(Number(...))`.
    - Alles andere bewirkt nichts.
    - Verschwindet die Leiste, während der Fokus in ihr liegt, geht er an `#alerts-filter-text`. Wird ein Schritt im Fokus neu gezeichnet, geht er an BACK.
  - **Stehende Leisten:**
    - `.alerts-drill`: `position: sticky; top: 0`, `z-index` über dem der Filterleiste, Hintergrund deckend.
    - `.alerts-filters` im Alerts-Tab: `top: var(--alerts-path-height)`.
    - Tabellenkopf: `top: calc(var(--alerts-path-height) + var(--alerts-bar-height))`.
    - `--alerts-path-height: 0px` in `:root`.
    - `initAlertsTab` setzt den Wert über `_followBarHeight(leiste, #tab-alerts, '--alerts-path-height')` (Border-Box).
    - `_alertsListTop` zieht die Höhen beider Leisten ab. Die Sysmon-Filterleiste bleibt bei `top: 0`.
  - **Aussehen:** wie im Mockup, Variante A, in beiden Themes.
    - Leiste: einzeilig (`white-space: nowrap`, `overflow: hidden`).
    - Schritte: `max-width: 28ch`, mit Ellipse.
    - BACK: in der Akzentfarbe gefüllt.
    - `.alerts-filter-chip`: größer, mit Rand in der Akzentfarbe.

- [ ] **Step 1: Failing tests**
  - `test_drilldown_bar_shows_the_path()`:
    - Ohne Schritte ist die Leiste `hidden`.
    - Nach zwei Schritten heißt der Pfad `['ALL ALERTS', '14 Jul', '14 Jul 10:00–12:00']`. Der letzte hat `aria-current="step"` und ist kein `<button>`. Die anderen haben `data-drill-step` `-1` und `0`.
    - Die Zählung entspricht der Tabelle (`'1,234 of 2,345 alerts'`-Form).
    - Nach fünf Schritten heißt der Pfad `['ALL ALERTS', '…', s3, s4, s5]`; `…` hat den Titel `s1 › s2`.
    - Ein Regel- oder Prozessname aus `EVIL`/`QUOTE` (auch mit 300 Zeichen) bleibt Text: keine Tags, Attribute unverändert.
    - Nach neuen Alerts folgt die Zählung, die Schritte bleiben.
  - `test_drilldown_bar_clicks()`:
    - BACK nimmt einen Schritt weniger.
    - Ein Schritt mit `data-drill-step="0"` lässt nur Schritt 1 übrig.
    - `ALL ALERTS` hinterlässt keine Schritte, die Leiste ist `hidden`, und der Fokus wandert von der Leiste an `alerts-filter-text`.
    - Ein Klick auf `›` oder `DRILLDOWN` bewirkt nichts.
  - `test_drilldown_bar_stands_at_the_top()`:
    - Die CSS-Regeln wie oben, in beiden Themes deckend.
    - Die Leiste hat `white-space: nowrap` und `overflow: hidden`; ein Schritt hat `max-width: 28ch` und `text-overflow: ellipsis`.
    - `[hidden]` bedeutet `display: none`.
    - `initAlertsTab` beobachtet die Leiste mit `{box: 'border-box'}`.
    - `_alertsListTop` ergibt bei 40 px Leiste und 60 px Filterleiste die Oberkante der Liste minus 100.
    - Nach einem Filterwechsel mit gescrolltem Tab liegt die erste Zeile unter beiden Leisten.
- [ ] **Step 2:** → FAIL.
- [ ] **Step 3:** Implementieren.
- [ ] **Step 4:** Tests grün (Node 20, beide Zonen), dazu `node --check` und `make -s unit-test`.
- [ ] **Step 5: Sichtprüfung auf der VM** (beide Themes, 1920 und 1280 px):
  - Pfad, BACK und Sprung über den Pfad;
  - Scrollen in der Tabelle: beide Leisten bleiben oben, und keine Zeile wird verdeckt;
  - ✶ bei sichtbarer Leiste;
  - jedes PNG lesen.
- [ ] **Step 6: Commit** `feat(alerts): drilldown bar with back` (Asset-Versionen erhöhen).

### Task 6: Doku, Screenshot und Gesamtprüfung auf der VM

**Files:**
- `README.md`:
  - Tabelle „Charts“ (Zeile Alerts: OVER TIME aufziehen) und Erläuterungen;
  - neuer Punkt **Drilldown**: Schritte, BACK, Pfad, eigene Einstellungen und Dashboard-Sprung;
  - Demo: Bild `static/alerts_drilldown.png` mit Bildunterschrift.
- `webui/templates/index.html`: Hilfe, Abschnitte Overview und Usage Guide zum Alerts-Tab.
- `static/alerts_drilldown.png` (neu).
- Bestehende Screenshots nur neu aufnehmen, wenn sie jetzt etwas anderes zeigen würden.

- [ ] **Step 1: Gesamtprüfung auf der VM** mit echten Eingaben, beide Themes, 1920 und 1280 px. Prüfen:
  - **Drilldown:** Balken 27 Jul ergibt `ALL ALERTS › 27 Jul`. Ziehen über 10:00–12:00 ergibt 24 Balken zu 5 Minuten, und die Zählung entspricht den gezogenen Balken. Ein Regelknoten im Sankey kommt als Schritt dazu. Dreimal BACK führt zu allen Alerts, die Leiste verschwindet. Der Sprung über den Pfad funktioniert.
  - **Dashboard:** Das Tag `high` ergibt `Dashboard: CRITICAL + HIGH`; BACK führt zu allen Alerts im Alerts-Tab. Dashboard-Ziehen und Dashboard-Balkenklick funktionieren weiter.
  - **Eigene Änderungen:** × am Bereichs-Chip mitten im Pfad.
  - **Darstellung:** Scrollen ohne verdeckte Zeilen, ✶ bei sichtbarer Leiste. Sechs Sekunden Halten beim Ziehen behalten den Kasten.
  - **Fehler:** Die Seite meldet keine Fehler.
  - **Messung:** Renderzeit von OVER TIME bei 9.620 Alerts messen.
- [ ] **Step 2: Screenshot** `static/alerts_drilldown.png`: Cyberpunk, 1920×960, Pfad `ALL ALERTS › 27 Jul › 27 Jul 10:00–12:00`, echte VM-Daten, ohne offene Schublade, Detailansicht oder Hilfe. Die Bildunterschrift nennt die Zahlen, die man sieht.
- [ ] **Step 3: Doku** schreiben. `webui/.venv/bin/python -m pytest tests/test_docs.py tests/test_charts.py -q` und `make -s unit-test` müssen grün sein. Kein Bild darf ohne Verweis bleiben.
- [ ] **Step 4: Commit** `docs: alerts drilldown`.
