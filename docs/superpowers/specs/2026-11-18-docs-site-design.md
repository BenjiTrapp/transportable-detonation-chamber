# Entwurf: das Handbuch als Website auf GitHub Pages

Datum: 2026-11-18 · Status: Entwurf zur Freigabe

## Warum

Das Handbuch liegt seit `78e13cf` in `docs/` — vierzehn Markdown-Seiten, vier Mermaid-Diagramme,
29 Screenshots. Wer es heute im Netz liest, liest es als Markdown auf github.com: kein Register,
keine Suche, keine Seitenwahl, und die Bilder stehen in Originalgröße untereinander. Das Offline-Wiki
(`make docs`) löst das für die VM, taugt aber nicht fürs Web: 15,5 MB in einer Datei, weil alle Bilder
als `data:`-URI eingebettet sind, und keine Adresse für eine einzelne Seite.

Der Nutzer will das Handbuch bequem lesbar im Web haben, in der Form seiner anderen Seite
(`benjitrapp.github.io/MostShittyEDR/`): Kopfzeile mit Logo und Navigation, Startseite mit Hero und
Karten, je Thema eine eigene Adresse, gezeichnete Diagramme.

Der Entwurf vom 17. November nannte GitHub Pages ausdrücklich als Nicht-Ziel. Diese Entscheidung ist
damit überholt; der Rest jenes Entwurfs bleibt gültig.

## Ziele

1. **Eine Handbuch-Website** auf `https://benjitrapp.github.io/transportable-detonation-chamber/`:
   Startseite, Register des Handbuchs und je Doku-Seite eine eigene Adresse, die man verlinken,
   teilen und als Lesezeichen behalten kann.
2. **Lesbar statt roh:** gesetzter Text, Navigation mit der aktuellen Stelle, Suche über alle Seiten,
   Bilder in Seitenbreite, Diagramme gezeichnet, Code-Blöcke wie im Produkt.
3. **Eine Quelle.** Die Seite entsteht aus denselben `docs/*.md` und derselben `README.md`, aus denen
   das Offline-Wiki entsteht. Kein Satz wird für die Website ein zweites Mal geschrieben.
4. **Von selbst aktuell:** Ein Workflow baut und veröffentlicht die Seite bei jedem Push auf `main`.
   Wer die Doku ändert, veröffentlicht sie damit.
5. **Die Markdown-Dateien bleiben unangetastet** — kein YAML-Kopf, keine umgeschriebenen Bildpfade.
   Auf github.com liest sich `docs/` weiter wie heute.

## Nicht-Ziele

- **Kein Jekyll**, kein fremdes Theme, kein Ruby im CI.
- **Keine Versionierung** der Doku, kein Wechsel zwischen Stand A und Stand B.
- **Keine eigene Domain**, kein `CNAME`.
- **Keine Zählpixel, keine Cookies, keine Kommentare, keine Fremddienste zur Laufzeit.**
- **Kein Suchserver.** Die Suche läuft im Browser über einen erzeugten Index.
- **Kein Umbau des Offline-Wikis.** Es bleibt, wie es ist, und bekommt auf der Seite einen
  Download-Platz.
- **Kein neuer Inhalt.** Was die Seite zeigt, steht in `docs/` und in der README.
- **Keine Hilfe-Änderung im Web-UI.** Die VM hat kein Netz; dort bleibt das Wiki der Weg.

## Anti-Ziele

Daran wäre die Arbeit gescheitert, auch wenn sie technisch läuft:

- **Eine Seite, die hinter dem Markdown herläuft.** Sie ist erzeugt und wird bei jedem Push
  veröffentlicht; sie wird nie von Hand gepflegt.
- **Zwei Quellen für denselben Satz.** Die Startseite zitiert die README nicht, sie wird aus ihr
  gebaut.
- **Eine Seite, die zur Laufzeit ein CDN braucht.** Der Mermaid-Renderer kommt von derselben Seite,
  gepinnt wie im Wiki.
- **Interne Papiere im Netz.** `docs/superpowers/` enthält deutsche Entwürfe und Pläne; nichts davon
  wird veröffentlicht.
- **Ein kaputtes Offline-Wiki.** Beide Ausgaben kommen aus einem Generator; die vorhandenen Tests
  des Wikis bleiben grün.
- **Eine Seite, die nur auf GitHub funktioniert.** Sie muss auch aus einem lokalen Ordner heraus
  aufgehen (`python3 -m http.server` im Bauordner), damit man sie vor dem Veröffentlichen ansieht.

## Randbedingungen

- **Bestand:** `scripts/build-wiki.py` (1112 Zeilen, Python 3.9, nur Standardbibliothek) mit einem
  geprüften Markdown-Parser, Suchindex-Bau (`search_records`), Überschriften-Auslese (`headings`),
  Bild-Einbettung und dem Prüfsummen-Tor für `scripts/wiki/mermaid.min.js` (10.9.3, SHA-256
  gepinnt). `tests/test_wiki.py` (1101 Zeilen) hält das alles fest.
- **Die 29 Bildverweise** der Doku lauten `../static/<name>.png` — relativ zu `docs/`, also außerhalb
  jedes Jekyll-Quellordners. Der Generator schreibt sie um; die Markdown-Dateien behalten sie.
- **Die Form der Seiten** ist durch Tests festgelegt: H1 in Zeile 1, ein Einleitungssatz, genau ein
  `**Next:**` als letzte Zeile. Darauf baut die Vor-/Zurück-Führung der Website auf.
- **`docs/README.md`** gibt die Reihenfolge der Seiten vor (`page_order`) und trägt die zwei
  Leserwege.
- **GitHub Pages** ist für dieses öffentliche Repository noch nicht aktiviert. Die Quelle wird
  „GitHub Actions"; der Nutzer hat das Einschalten freigegeben.
- **Die Seite liegt unter einem Unterpfad** (`/transportable-detonation-chamber/`). Absolute Pfade
  (`/assets/...`) wären dort tot.
- **Repo-Regeln:** englische Doku und Oberfläche; deutsche Entwürfe; keine lokalen Pfade; kein Name
  der früheren Vergleichs-Software des Hex-Editors und keine interne Referenz-Seite; erzeugte
  Dateien in `.gitignore`.

## Wege

**Weg A — eigener Generator (gewählt).** `scripts/build-wiki.py` lernt eine zweite Ausgabe: eine
HTML-Datei je Doku-Seite plus gemeinsame Beiwerke. Markdown bleibt unangetastet, der Parser ist schon
geprüft, Wiki und Website kommen aus einer Quelle. *Preis:* etwa 300 Zeilen Generator mehr und ihre
Tests; kein fremdes Theme-Ökosystem.

**Weg B — Jekyll wie auf der Vergleichsseite.** `docs/` wird Jekyll-Quelle, GitHub baut selbst.
*Preis:* YAML-Kopf in jeder Seite (der Test „H1 in Zeile 1" fällt, und github.com zeigt über jeder
Seite eine Kopf-Tabelle), und die 29 Bildverweise müssen umgeschrieben werden oder die Bilder doppelt
liegen.

**Weg C — Jekyll, aber erzeugt.** Ein Workflow kopiert, setzt Köpfe, schreibt Pfade um, Jekyll baut.
*Preis:* zwei Werkzeuge statt einem, Ruby im CI, für ein Ergebnis, das A auch liefert.

**Gewählt: Weg A**, vom Nutzer.

## 1. Die Seiten

| Adresse | Woher | Inhalt |
|---|---|---|
| `/` | `README.md` | die README, vollständig gesetzt: Hero, die zehn Features, Architektur, Tabs, Quick Start, Plattformen, Doku-Karte, Security Notes, Credits, License |
| `/guide/` | `docs/README.md` | das Register, vollständig gesetzt: die zwei Leserwege, die Seitenliste, Architektur, Engines, Dienste |
| `/setup/` … `/troubleshooting/` | die dreizehn Doku-Seiten | je eine Seite, Inhalt unverändert |

Dreizehn Doku-Seiten plus Register plus Startseite: fünfzehn Adressen. `docs/superpowers/` ist
ausgeschlossen.

**Entscheidung (meine): beide Übersichtsseiten werden gesetzt, nicht zusammengestellt.** Die
Startseite ist die gerenderte `README.md`, das Register die gerenderte `docs/README.md` — kein
Abschnitt wird ausgewählt, umgestellt oder weggelassen. Das kostet nichts und löst vier Dinge auf
einmal: `theme_telemetry.png` und `wiki.png` (die nur die README benutzt) bleiben gebraucht statt zu
verwaisen; die eigenen Sprungmarken der README (`#quick-start`, `#what-it-does`, `#web-ui-tabs`,
`#credits`) und die Marken, auf die sie ins Register zeigt (`#detection-engines`), bleiben heil;
Credits und License — wo Mermaid (MIT), Aether (GPL-3.0), rizin (LGPL-3.0) und das fehlende
Lizenzdokument stehen — stehen auf der einen öffentlichen Seite, auf der sie hingehören; und es
entsteht kein zweiter Textzusammensteller neben dem Parser, der später hinter der README herläuft.

**Das Karten-Aussehen ist Darstellung, nicht Auswahl.** Im Abschnitt `## What it does` erkennt der
Generator das Muster der zehn Feature-Blöcke — fetter Name, ein Satz, ein zentriertes Bild — und legt
jeden in eine Karte. Nichts daran wählt aus, und ein elftes Feature in der README wird von selbst
eine elfte Karte.

**Drei Eigenheiten der README** muss die Website-Ausgabe dafür können:

1. **Die zentrierten HTML-Blöcke.** Logo, Titel, der eine fette Satz und jedes Feature-Bild stehen in
   rohem `<p align="center">` bzw. `<h1 align="center">`, das der Parser heute zu Text entschärft.
   Die Ausgabe versteht genau diese zwei Formen — ein zentriertes Bild und eine zentrierte Zeile —
   und sonst keine; alles andere bleibt Text wie bisher. `tdc-logo.png` liegt im Wurzelverzeichnis,
   nicht in `static/`, und wird mit kopiert.
2. **Die Abzeichen.** Sie sind Bilder von `img.shields.io`, also ein Fremddienst zur Laufzeit, den
   die Nicht-Ziele ausschließen. Die Website lässt die Bilder weg und behält ihre Links als
   beschriftete Knöpfe, vom CSS gesetzt. Damit bleiben die Sprungmarken heil und es geht keine
   Anfrage nach außen. Das neue Abzeichen aus Abschnitt 6 betrifft nur das Lesen auf github.com.
3. **Die Verweise.** In der Website-Ausgabe wird `docs/x.md` zu `../x/`, `docs/README.md` zu
   `../guide/`, `../static/x.png` zu `../assets/img/x.png`, eine Sprungmarke bleibt eine
   Sprungmarke, und jeder Verweis auf eine andere Datei des Repositorys (`Vagrantfile.utm`,
   `tdc-logo.png` als Link) geht auf github.com — mit demselben Hinweis „braucht Netz", den das Wiki
   schon setzt, nur hier ohne Not, weil die Website ohnehin im Netz steht: dort entfällt er.

## 2. Wie eine Seite aussieht

- **Kopfzeile**, auf jeder Seite gleich: Logo und Titel links (führt auf `/`), rechts die Navigation
  — Guide, GitHub, Offline-Handbuch — und das Suchfeld.
- **Register links** auf jeder Handbuch-Seite: alle vierzehn Seiten, die aktuelle markiert, darunter
  ihre `##`-Überschriften als Sprungziele. Auf dem Telefon klappt es über einen Knopf auf.
- **Inhalt** in Lesebreite: Bilder in Seitenbreite statt Originalgröße, Tabellen mit eigenem
  Querlauf, Code-Blöcke wie im Web-UI, Diagramme gezeichnet und per Klick vergrößerbar — wie im Wiki.
- **Vor und Zurück** am Fuß jeder Seite, aus der `**Next:**`-Kette der Doku; die Kette ist schon
  durch einen Test vollständig und zyklisch geschlossen.
- **Fußzeile:** Baudatum (UTC), kurze Commit-Kennung, ein Link auf dieselbe Seite im Repository.
- **Aussehen:** die Cyberpunk-Palette des Produkts, wie das Wiki sie schon trägt. Kein Umschalter.

## 3. Was mitgeliefert wird

- `assets/img/*.png` — die Screenshots als Dateien; der Generator schreibt `../static/x.png` in
  `../assets/img/x.png` um. **Keine** `data:`-URIs: im Web wird jedes Bild einzeln und erst bei
  Bedarf geladen.
- `assets/demo.gif` — das Demo-Video (10 MB), von der Startseite verlinkt. Im Web ist das in Ordnung;
  im Wiki ist es bewusst nur genannt.
- `assets/mermaid.min.js` — **Entscheidung (meine):** die gepinnte Kopie aus dem Repository, von
  derselben Seite ausgeliefert, nicht aus einem CDN wie auf der Vergleichsseite. Gründe: dieselbe
  geprüfte Version wie im Wiki, kein Fremddienst zur Laufzeit, keine Version, die sich unter der Hand
  ändert. Eingebunden wird sie nur auf den **fünf** Seiten, die ein Diagramm tragen: `/` und
  `/guide/` (beide tragen das Architektur-Diagramm, in der README und im Register byte-gleich),
  `/workflow/`, `/memory/` und `/rizin/`.
- `assets/style.css`, `assets/site.js` — gemeinsam für alle Seiten, also einmal geladen.
- `search.json` — der Suchindex aus `search_records`, beim ersten Tippen geholt.
- `wiki.html` — das Offline-Handbuch, zum Herunterladen.
- `.nojekyll` — damit GitHub die erzeugten Dateien nicht noch durch Jekyll schiebt.

**Entscheidung (meine):** Alle Verweise zwischen den Seiten sind **relativ** (`../rizin/`), nicht
absolut. So funktioniert die Seite unter dem Unterpfad von GitHub Pages, aus einem lokalen Ordner und
in einer Vorschau gleichermaßen.

## 4. Bauen und veröffentlichen

- **Lokal:** `make site` (und `.\make.ps1 site`) baut nach `site/`, git-ignoriert.
  **Entscheidung (meine):** `site` baut das Wiki vorher mit (`site` hängt an `docs`), denn
  `webui/static/wiki.html` ist git-ignoriert und in einem frischen Klon nicht da — sonst zeigte der
  Download-Platz der Website ins Leere, und die Vorschau wäre nicht das, was veröffentlicht wird. Der
  Wiki-Bau dauert eine halbe Sekunde, also kostet das nichts. `make docs` allein bleibt, wie es ist.
  Ein Ziel `make site-serve` (und dasselbe in `make.ps1`) startet einen lokalen Server im Bauordner,
  damit man vor dem Veröffentlichen hineinsieht.
- **In der CI:** ein zweiter Workflow `.github/workflows/pages.yml`, nur auf Push nach `main`:
  Python 3.12, `make site` (das `make docs` mitnimmt), `actions/upload-pages-artifact`,
  `actions/deploy-pages`, Rechte `pages: write` und `id-token: write`, eine `concurrency`-Gruppe,
  damit zwei Pushes sich nicht überholen. `tests.yml` bleibt unberührt.
- **Das Prüfsummen-Tor gilt weiter:** Fehlt `scripts/wiki/mermaid.min.js` oder stimmt die Prüfsumme
  nicht, bricht der Bau ab — in der CI sichtbar, statt eine Seite ohne Diagramme zu veröffentlichen.
- **Pages ist eingeschaltet** (am 18. November erledigt, Quelle „GitHub Actions", Adresse
  `https://benjitrapp.github.io/transportable-detonation-chamber/`, noch nichts veröffentlicht). Der
  Workflow braucht also kein `enablement`, nur `configure-pages`; der erste Push nach `main`
  veröffentlicht.

## 5. Die Tests

Neu in `tests/test_site.py` (das vorhandene `tests/test_wiki.py` bleibt, wie es ist):

- **Eine Datei je Adresse:** fünfzehn Seiten, `index.html` in je einem eigenen Ordner, und keine Seite
  aus `docs/superpowers/`.
- **Jeder Verweis trägt:** jeder relative Link zeigt auf eine erzeugte Datei oder ein mitgeliefertes
  Beiwerk; kein Link beginnt mit `/`; kein `../static/` und kein `.md` bleibt stehen; die
  Sprungmarken der Startseite und des Registers zeigen auf Überschriften, die es dort gibt.
- **Jedes Bild liegt da:** jedes `<img src>` zeigt auf eine Datei in `assets/img/`, und jede Datei
  dort wird von mindestens einer Seite gebraucht. Keine `data:`-Bilder, kein `img.shields.io`, und
  überhaupt keine Anfrage nach außen: dieselbe Prüfung auf Ressourcen-Formen, die das Wiki schon hat
  (`url(`, `import(`, `EventSource`, `sendBeacon`, `.src =`), nur über jede Seite der Website.
- **Die Startseite ist die README:** jede Überschrift der README kommt auf `/` vor, die zehn
  Features stehen in Karten, und der Hero trägt Logo und den fetten Satz. Ändert man einen
  Feature-Namen in der README, ändert sich die Seite (der Test liest beide).
- **Das Register ist `docs/README.md`:** jede Überschrift kommt vor, inklusive Architektur-Diagramm
  und Seitenliste.
- **Das Register markiert die aktuelle Seite**, und Vor/Zurück folgt der `**Next:**`-Kette.
- **Die Suche:** ein Wort, das nur auf einer tiefen Seite steht, steht mit seiner Seite und seiner
  Überschrift in `search.json`, und jedes Sprungziel darin gibt es auf der genannten Seite.
- **Mermaid nur, wo nötig:** die fünf Seiten mit Diagramm binden das Bündel ein, die anderen zehn
  nicht; die eingebundene Version ist die gepinnte, und ihre Prüfsumme wird beim Bauen geprüft.
- **Markdown wird nicht lebendig:** ein `<script>` und ein `onerror=` aus einer Doku-Seite bleiben
  Text — derselbe Parser wie im Wiki, aber in der neuen Ausgabe noch einmal geprüft.
- **Kein lokaler Pfad, kein Rechnername** in der Ausgabe; die Fußzeile trägt Datum (UTC) und
  Commit-Kennung.
- **Beide Ausgaben aus einem Lauf:** `make docs` und `make site` nacheinander, beide Ergebnisse da,
  und `tests/test_wiki.py` bleibt grün.
- **Der Workflow:** er baut beides und lädt den Ordner hoch; ein Test liest die Workflow-Datei, damit
  ein umbenanntes Ziel nicht still die Veröffentlichung abschaltet.

## 6. Was in der README und im Register dazukommt

Eine Zeile mit dem Link auf die Seite — in der README über der Doku-Karte und in `docs/README.md` im
ersten Absatz. Dazu ein Abzeichen im Kopf der README, wie die vorhandenen. Mehr nicht: die Seite ist
ein Weg zum Handbuch, kein neues Produkt.

## Was der Baumeister entscheidet

- Das CSS: Raster, Karten, Lesebreite, Abstände, wie das Register auf dem Telefon aufklappt.
- Die Suche im Einzelnen: ab wie vielen Zeichen, wie viele Treffer, Tastaturkürzel.
- Die Dateinamen der Beiwerke und die Aufteilung von `site.js`.
- Ob Vor/Zurück auch oben steht, und ob jede Seite einen „auf GitHub bearbeiten"-Link bekommt.
- Wie die Startseite den Quick Start zeigt (Reiter, zwei Spalten oder untereinander).
- Ob `make site` den Bauordner vorher leert oder hineinschreibt.
