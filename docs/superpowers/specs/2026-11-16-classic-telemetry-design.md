# Classic-Theme im Stil „Glasfaser-Telemetrie“ – Design

## Wunsch

Der blaue Theme (intern `classic`) wird überarbeitet:
- **Farben** kommen aus https://becker.koeln/ai/nc-traffic-auswertung.html.
- **Fensteraufteilung und Steuerung** kommen vom Cyberpunk-Theme: Top-Bar mit Tabs und „…“-Menü, Services-Panel, Prozess-Drawer, Tab-Köpfe und Karten.

**Entscheidung:** Übernommen wird nur das Farbdesign der Seite, nicht ihre Formen (keine abgeschrägten Ecken), Schriften oder Webfonts. Die VM ist oft offline; die Schriften bleiben die des Cyberpunk-Themes.

## Palette der Vorlage

| Rolle | Wert |
|---|---|
| Seite | `#07080f` |
| Panel unten / oben | `#0d0f1c` / `#121528` |
| Linie | `#23284a` |
| Raster | `#1a1e38` |
| Text / Text 2 / gedämpft | `#e8ecff` / `#a3abd6` / `#6c7399` |
| Cyan (rx) | `#00e5ff` |
| Magenta (tx) | `#ff2bd6` |
| Violett (Verlaufsmitte) | `#9b8cff` |
| Säure-Grün (acid) | `#d4ff00` |
| Warnung | `#ffb000` |
| Alarm-Rot | `#ff2b4a` |

## Farb-Effekte der Vorlage, die übernommen werden

- **Seitenhintergrund:**
  - 40-px-Raster in der Rasterfarbe;
  - ein magenta Lichthof oben rechts und ein cyan Lichthof links;
  - feine Scanlines über allem (`pointer-events: none`).
- **Panels und Karten:** Verlauf von Panel oben nach unten, 1 px Linie und ein 60 px langer, leuchtender Akzentstrich oben links.
  - Der Strich ist meist cyan. Im Wechsel, z. B. für die Stat-Kacheln, ist er magenta oder säure-grün.
- **Überschriften:** Große Kopfzeilen (Tab-Titel) mit einem Verlauf cyan → violett → magenta als Textfarbe. Kicker-Zeilen („TDC // …“) und kleine Labels in Säure-Grün oder Gedämpft, mit Großbuchstaben und Sperrung.
- **Sonstiges:**
  - Aktiver Tab und primäre Knöpfe in Cyan mit Glow.
  - Tooltips auf Seitenfarbe mit cyan Rand.
- **Daten-Farben:**
  - Severities: critical Alarm-Rot, high Orange (`#ff7a1a`), medium Warnung `#ffb000`, low Säure-Grün, info Cyan.
  - Weitere Serienfarben: aus Cyan, Magenta, Violett, Grün und Gelb der Vorlage, mit klar unterscheidbaren Tönen.

## Ansätze

1. **Classic bekommt die Cyberpunk-Layout-Regeln (gewählt).**
   - `theme-cyberpunk.css` wird geteilt:
     - Die Palette bleibt in `theme-cyberpunk.css`, nur für `cyberpunk`.
     - Die Layout- und Formregeln gehen in eine neue Datei `theme-layout.css` mit dem Präfix `[data-theme]`, für beide Themes.
   - Die `--cp-*`-Variablen, die diese Regeln nutzen, bekommt Classic in `style.css :root` mit der Telemetrie-Palette.
   - Die JS-Weichen (`theme === 'cyberpunk'` für Top-Bar, Drawer und Overflow) gelten für beide Themes.
   - Die bisherige Sidebar-Ansicht gibt es danach nicht mehr.
2. **Ein dritter Theme `telemetry`:** Mehr Pflege, und der alte Classic bliebe ungenutzt. Der Nutzer will Classic überarbeiten, nicht ergänzen.
3. **Classic-Regeln einzeln nachbauen:** Das verdoppelt rund 2900 Zeilen.

## Folgen

- **Umschalten:** `✶` wechselt weiter zwischen beiden Themes, und `localStorage` `tdc-theme` bleibt. Der zweite ✶-Knopf in der Sidebar entfällt nicht. Er sitzt jetzt im Drawer, der die Sidebar enthält.
- **Name:** **Entscheidung:** Der angezeigte Name wird `Telemetry` (`THEME_LABELS`); die interne ID bleibt `classic`, damit gespeicherte Einstellungen gelten.
- **Tests und Doku:** Tests, die die Sidebar-Ansicht in Classic voraussetzen, werden angepasst. README-Texte zu Classic werden angepasst. Ein neuer Screenshot `static/theme_telemetry.png` kommt hinzu.

## Nicht-Ziele

- Keine neuen Schriften.
- Keine Änderung am Cyberpunk-Aussehen.
- Keine abgeschrägten Ecken.

## Anti-Ziele

- Cyberpunk sieht danach anders aus als vorher.
- Ein Text wird auf dem neuen Hintergrund schlecht lesbar (Kontrast unter 4.5:1 für Fließtext).
- Die Scanlines fangen Klicks ab.
