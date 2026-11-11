"""Themes: every colour of the Classic theme comes from a CSS variable, and
the theme switch (✶) changes theme without reloading the page.

Regressions covered:
  * a colour written as a literal outside :root, which a second theme
    cannot override by setting the variables
  * a colour variable that is not defined (typo, missing -rgb in rgba()):
    the declaration silently falls back to its initial value
  * an "r, g, b" triplet that is not the colour of its hex partner
  * a colour hard-coded in app.js (canvas drawings, inline styles in HTML
    strings) or in index.html, which stays Classic in every theme
  * a canvas colour read from an undefined variable: the canvas ignores the
    empty value and keeps painting with the previous colour
  * canvas drawings keeping the old theme's colours after a switch (cache),
    file maps among them, or a switch that loads their file again
  * a colour or font of Classic that Cyberpunk does not set, a Cyberpunk
    value that is not the one of the design spec, graph node kinds that look
    alike, a severity tinted with another colour than its text
  * the stored theme applied only after the first paint (Classic flashes),
    or an empty, invalid or blocked localStorage breaking the page
  * a switch that reloads or re-initialises the UI, re-creates the tab bar
    (its click handlers are lost) or leaves the sidebar in another order
  * transitions running during a switch (the drawer slides away)
  * a Cyberpunk rule that also matches in Classic
  * the internal site the Cyberpunk look is modelled on named in any file of
    the repo: its address or organisation in any case, glued to other
    characters or with the words apart, its name (an ordinary word otherwise)
    in capitals
  * Cyberpunk top bar in a narrow window: tabs that do not fit are lost
    instead of moving into the "…" menu, or the active tab is hidden
  * the drawer or a drop-down of the top bar that does not close (Esc, a
    click beside it, picking a process) or survives a theme switch; the
    closed drawer's scrim catching clicks; the keyboard focus lost in the
    "…" menu or hidden by an outline: none; a click in the explanation of a
    drawer title closing the drawer; the focus lost when Esc closes it
  * decorative generated text (the kicker above the tab titles, the caret of
    the services button) read aloud by screen readers
  * the top bar counting services or processes differently from the sidebar
  * a missing element stopping the start-up
  * the Alerts tab: a filter missing alerts written in another case ("High",
    "Sigma"), rows in list order instead of newest first, hostile rule,
    process or severity values reaching the markup, a 300-character name
    widening the table, more than 2000 rows, a process link to the newest
    holder of a reused PID, filters or the place in the list lost when a
    refresh re-renders it, a re-render while the tab is closed
  * sortable tables: numbers sorted as text ("100" before "9"), times by
    their text (a clock time after midnight before one of the evening),
    empty cells first when the order turns, ties shuffled, a polling render
    (Alerts, Sysmon, Pipes) that drops the order, a note, a detail row or a
    rowspan group torn from its place, a data table nobody made sortable
  * (i) explanations: a tab head without one, a text that is long, markup
    or built from data, the popover showing the text as markup, outside the
    window, staying open (Esc, a click beside it, its button gone), or the
    click on (i) also clicking the card around it
  * CHART / TABLE: a chart card without its switch, a table that shows other
    numbers than its chart, hostile names reaching the markup, a refresh
    that drops the chosen view, the sort order or the switch (and its focus),
    a switch that changes another card; the inline file map's table or tree
    filled by the late load of the file analysed before
  * dashboard tiles: counts that miss "High" or "Critical" or leave out
    alerts the Alerts tab counts as info, a tile or a count that opens the
    wrong view, a count that also opens the whole list, a tile that does not
    take Enter or Space
  * the sidebar timeline and Recent Activity showing the oldest alerts
    (/api/alerts lists them oldest first, by their text) or the newest by
    their text instead of their time
  * the Tracing event grid: its heads do not sort, numbers or times sort as
    text, the order is lost when the alerts poll renders it again
"""

import hashlib
import json
import os
import re
import subprocess
from html.parser import HTMLParser

import pytest

from test_frontend import _function_source, _run_node, needs_node

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STYLE_CSS = os.path.join(ROOT, "webui", "static", "css", "style.css")
THEME_CSS = os.path.join(ROOT, "webui", "static", "css", "theme-cyberpunk.css")
APP_JS = os.path.join(ROOT, "webui", "static", "js", "app.js")
INDEX_HTML = os.path.join(ROOT, "webui", "templates", "index.html")

LITERAL_COLOR = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\(\s*[\d.]")
ROOT_BLOCK = re.compile(r":root\s*\{[^}]*\}")
# Not colours: HTML character references (&#9673;) and in-page anchors (href="#x").
NOT_A_COLOR = re.compile(r"&#\d+;|href=([\"'])#[^\"']*\1")


def _strip_comments(css):
    """Comments removed; line breaks kept so line numbers stay valid."""
    return re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), css, flags=re.S)


def _without_first_root_block(css):
    m = ROOT_BLOCK.search(css)
    assert m, "no :root block in style.css"
    return css[:m.start()] + "\n" * m.group(0).count("\n") + css[m.end():]


def _literal(line, m):
    """The whole literal for the report (`rgba(1, 2, 3, .5)`, not `rgba(1`)."""
    if m.group(0).startswith("#"):
        return m.group(0)
    end = line.find(")", m.end())
    return line[m.start():end + 1] if end >= 0 else line[m.start():]


def test_style_css_has_no_literal_colors_outside_root():
    css = _without_first_root_block(_strip_comments(open(STYLE_CSS, encoding="utf-8").read()))
    hits = [
        f"line {lineno}: {_literal(line, m)}"
        for lineno, line in enumerate(css.split("\n"), 1)
        for m in LITERAL_COLOR.finditer(line)
    ]
    assert not hits, (f"{len(hits)} colour literals outside :root in style.css "
                      f"(first 20):\n" + "\n".join(hits[:20]))


# Read but defined nowhere, on purpose: the .etw-* rules of Classic have always
# named --border (their borders never render); defining it would change Classic.
UNDEFINED_ON_PURPOSE = {"--border"}


def _var_problems(text, defined):
    """Per line: a var(--x) without a fallback (and any --c-* or *-rgb one)
    whose variable is not defined, and rgba() of a variable that is not an
    r, g, b triplet."""
    problems = []
    for lineno, line in enumerate(text.split("\n"), 1):
        names = re.findall(r"var\(\s*(--[\w-]+)\s*\)", line)
        names += re.findall(r"var\(\s*(--c-[\w-]+|--[\w-]+-rgb)\s*,", line)
        problems += [f"line {lineno}: {name} is not defined" for name in names
                     if name not in defined and name not in UNDEFINED_ON_PURPOSE]
        problems += [f"line {lineno}: rgba() needs an r, g, b variable, not {name}"
                     for name in re.findall(r"rgba?\(\s*var\(\s*(--[\w-]+)", line) if not name.endswith("-rgb")]
    return problems


def test_style_css_colour_variables_are_defined():
    """Every variable a rule or a drawing reads is defined: in Classic by
    :root of style.css, in Cyberpunk also by theme-cyberpunk.css (all of its
    rules apply in Cyberpunk only). Undefined, a var() without a fallback
    silently becomes the initial value. (Quoted names in app.js and
    index.html: test_app_js_and_index_html_colour_variables_are_defined.)"""
    css = _strip_comments(_read(STYLE_CSS))
    theme = _strip_comments(_read(THEME_CSS))
    classic = set(re.findall(r"(--[\w-]+)\s*:", ROOT_BLOCK.search(css).group(0)))
    cyberpunk = classic | set(re.findall(r"(--[\w-]+)\s*:", theme))
    problems = [f"style.css {p}" for p in _var_problems(_without_first_root_block(css), classic)]
    problems += [f"theme-cyberpunk.css {p}" for p in _var_problems(theme, cyberpunk)]
    problems += [f"app.js {p}" for p in _var_problems(_strip_js_comments(_read(APP_JS)), classic)]
    assert not problems, "\n".join(problems[:20])


def _read(path):
    return open(path, encoding="utf-8").read()


def _root_values():
    """name -> value of every variable in the first :root block of style.css."""
    block = ROOT_BLOCK.search(_strip_comments(_read(STYLE_CSS))).group(0)
    return {name: value.strip() for name, value in re.findall(r"(--[\w-]+)\s*:([^;]*);", block)}


def _strip_js_comments(js):
    """Comments removed, line breaks kept. A `//` right after a colon belongs
    to a URL (http://...), not a comment."""
    js = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), js, flags=re.S)
    return re.sub(r"(?<!:)//[^\n]*", "", js)


def _literal_colors(text):
    text = NOT_A_COLOR.sub(lambda m: " " * len(m.group(0)), text)
    return [
        f"line {lineno}: {_literal(line, m)}"
        for lineno, line in enumerate(text.split("\n"), 1)
        for m in LITERAL_COLOR.finditer(line)
    ]


def test_app_js_has_no_literal_colors():
    hits = _literal_colors(_strip_js_comments(_read(APP_JS)))
    assert not hits, (f"{len(hits)} colour literals in app.js (first 20); canvas code uses "
                      f"themeColor('--x'), HTML strings var(--x):\n" + "\n".join(hits[:20]))


def test_index_html_has_no_literal_colors():
    html = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), _read(INDEX_HTML), flags=re.S)
    hits = _literal_colors(html)
    assert not hits, f"{len(hits)} colour literals in index.html (first 20):\n" + "\n".join(hits[:20])


def test_app_js_and_index_html_colour_variables_are_defined():
    defined = set(_root_values())
    problems = []
    for path, text in ((APP_JS, _strip_js_comments(_read(APP_JS))), (INDEX_HTML, _read(INDEX_HTML))):
        where = os.path.basename(path)
        for lineno, line in enumerate(text.split("\n"), 1):
            names = re.findall(r"var\(\s*(--[\w-]+)", line) + re.findall(r"""['"`](--[\w-]+)['"`]""", line)
            problems += [f"{where}:{lineno}: {n} is not defined in :root" for n in names if n not in defined]
    assert not problems, "\n".join(problems[:20])


# --- Cyberpunk palette ---------------------------------------------------------

CYBERPUNK_ROOT = re.compile(r""":root\[data-theme=(["'])cyberpunk\1\]\s*\{([^}]*)\}""")
# A colour: hex, an "r, g, b" triplet, rgb()/rgba() or a gradient
COLOUR_VALUE = re.compile(r"#[0-9a-fA-F]{3,8}\b|^\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*$|rgba?\(|gradient\(")
# The same in every theme
NEUTRAL_COLOURS = {"--c-white", "--c-white-rgb", "--c-black", "--c-black-rgb"}


def _cyberpunk_values():
    """name -> value of every variable that theme-cyberpunk.css sets on
    :root[data-theme="cyberpunk"], i.e. for the whole page in Cyberpunk."""
    values = {}
    for m in CYBERPUNK_ROOT.finditer(_strip_comments(_read(THEME_CSS))):
        values.update((name, value.strip()) for name, value in re.findall(r"(--[\w-]+)\s*:([^;]*);", m.group(2)))
    return values


def _resolve(values):
    """The values with every var(--x) replaced by the value of --x."""
    def resolve(name, seen):
        assert name in values and name not in seen, f"var({name}) is not defined or refers to itself"
        return re.sub(r"var\(\s*(--[\w-]+)\s*\)", lambda m: resolve(m.group(1), seen | {name}), values[name])
    return {name: resolve(name, set()) for name in values}


def _cyberpunk_palette():
    """The values in effect in Cyberpunk: theme-cyberpunk.css over :root."""
    return _resolve({**_root_values(), **_cyberpunk_values()})


def _palette_names(values):
    """The variables a theme has to set: its colours and fonts. Sizes such
    as --radius may stay as they are."""
    return {name for name, value in values.items() if name.startswith("--font-") or COLOUR_VALUE.search(value)}


def _same_value(a, b):
    return re.sub(r"\s+", "", a).lower() == re.sub(r"\s+", "", b).lower()


def test_cyberpunk_sets_every_palette_variable():
    classic, cyberpunk = _root_values(), _cyberpunk_values()
    missing = sorted(_palette_names(classic) - set(cyberpunk))
    assert not missing, (f"{len(missing)} colours and fonts of style.css :root that theme-cyberpunk.css does not "
                         f"set; they stay Classic in Cyberpunk:\n" + "\n".join(missing))
    effective = _cyberpunk_palette()
    same = sorted(name for name in _palette_names(classic) - NEUTRAL_COLOURS
                  if _same_value(effective[name], classic[name]))
    assert not same, "set to their Classic value in Cyberpunk:\n" + "\n".join(same)


# The values of the design spec (docs/superpowers/specs/2026-11-09-cyberpunk-theme-design.md)
CYBERPUNK_SPEC = {
    "--bg-primary": "#0b0716", "--bg-card": "#140d24", "--bg-tertiary": "#1b1232", "--border-primary": "#251a3d",
    "--text-primary": "#f3eefc", "--text-secondary": "#c9bfe3", "--text-muted": "#8a7fb0",
    "--accent-pink": "#ff4fd8", "--accent-cyan": "#37e0ff", "--accent-green": "#39d98a",
    "--severity-critical": "#ff3b3b", "--severity-high": "#ff7a1a", "--severity-medium": "#ffb000",
    "--severity-low": "#39d98a", "--severity-info": "#37e0ff",
    "--font-mono": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    "--font-sans": 'system-ui, -apple-system, "Segoe UI", sans-serif',
}


def test_cyberpunk_uses_the_spec_values():
    effective = _cyberpunk_palette()
    wrong = {name: effective.get(name) for name, value in CYBERPUNK_SPEC.items()
             if not _same_value(effective.get(name, ""), value)}
    assert not wrong, wrong
    theme = _strip_comments(_read(THEME_CSS))
    kicker = re.search(r"""\[data-theme="cyberpunk"\] \.content-header::before\s*\{[^}]*content:\s*"([^"]*)"[^}]*\}""",
                       theme)
    assert kicker and kicker.group(1) == "TDC // DETONATION CHAMBER", "no kicker line above the tab titles"
    # Tiles: a 3 px edge on the left, red for the alert count as the critical tile edge
    edge = re.search(r"""\[data-theme="cyberpunk"\] \.stat-card::before\s*\{([^}]*)\}""", theme)
    assert edge and re.search(r"\bwidth:\s*3px", edge.group(1)), "no 3 px tile edge"
    alerts = re.search(r"""\[data-theme="cyberpunk"\] \.stat-card\.stat-alerts::before\s*\{[^}]*background:\s*"""
                       r"""var\((--[\w-]+)\)""", theme)
    assert alerts and _same_value(effective[alerts.group(1)], "#d03b3b")


def _hex_rgb(value):
    digits = value.strip().lstrip("#")
    if len(digits) in (3, 4):
        digits = "".join(c * 2 for c in digits[:3])
    return tuple(int(digits[i:i + 2], 16) for i in (0, 2, 4))


def _triplet_problems(values):
    """*-rgb variables that are no r, g, b triplet or not the colour of
    their hex partner (--x-rgb next to --x)."""
    problems = []
    for name, value in sorted(values.items()):
        if not name.endswith("-rgb"):
            continue
        m = re.fullmatch(r"\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*", value)
        if not m or max(map(int, m.groups())) > 255:
            problems.append(f"{name}: {value!r} is not r, g, b")
            continue
        partner = values.get(name[:-len("-rgb")], "")
        if re.fullmatch(r"\s*#[0-9a-fA-F]{3,8}\s*", partner) and _hex_rgb(partner) != tuple(map(int, m.groups())):
            problems.append(f"{name}: {value} is not {name[:-len('-rgb')]} ({partner.strip()})")
    return problems


def test_rgb_triplets_match_their_colours():
    """rgba(var(--x-rgb), a) is the colour --x with an alpha: the triplet
    has to be the same colour in each theme."""
    problems = [f"style.css: {p}" for p in _triplet_problems(_root_values())]
    problems += [f"theme-cyberpunk.css: {p}" for p in _triplet_problems(_cyberpunk_palette())]
    assert not problems, "\n".join(problems)


def test_theme_color_with_alpha_has_an_rgb_variable():
    """themeColor('--x', alpha) reads --x-rgb: without it the canvas gets
    'rgba(, alpha)' and keeps its previous colour."""
    names = re.findall(r"themeColor\(\s*'(--[\w-]+)'\s*,", _strip_js_comments(_read(APP_JS)))
    assert names, "no themeColor('--x', alpha) call found: the pattern is out of date"
    missing = [f"{name}-rgb in {where}" for name in sorted(set(names))
               for where, values in (("style.css :root", _root_values()), ("theme-cyberpunk.css", _cyberpunk_values()))
               if name + "-rgb" not in values]
    assert not missing, "\n".join(missing)


def test_severity_text_and_tint_share_a_colour():
    """A rule that writes a severity in --severity-X takes its tint from
    --severity-X-rgb as well; a tint from an accent would keep the accent's
    colour where a theme gives the severities their own."""
    problems = []
    for prelude, body in _css_blocks(_without_first_root_block(_strip_comments(_read(STYLE_CSS)))):
        severities = set(re.findall(r"var\(\s*--severity-(\w+)\s*\)", body or ""))
        tints = set(re.findall(r"rgba\(\s*var\(\s*(--[\w-]+)-rgb\s*\)", body or ""))
        foreign = sorted(t for t in tints if t not in {f"--severity-{s}" for s in severities})
        if severities and foreign:
            problems.append(f"{prelude}: {', '.join(sorted(severities))} with a tint of {', '.join(foreign)}")
    assert not problems, "\n".join(problems)


# The severity colours of the design spec; tints come from the same colour
SPEC_SEVERITY = {"critical": "#ff3b3b", "high": "#ff7a1a", "medium": "#ffb000", "low": "#39d98a", "info": "#37e0ff"}
SEVERITY_TOKEN = re.compile(r"\.(?:sev-|severity-|lb-risk-)?(critical|high|medium|med|low|info)(?![\w-])")
DATA_SEV = re.compile(r"""\[data-sev="(critical|high|medium|low|info)"\]""")
# Named like a severity, but no severity
NOT_A_SEVERITY = {".elf-entropy-fill.high": "the fill of an entropy bar: a level of the entropy scale (data colour)"}
# Colour properties and the part of the box each one paints
COLOUR_SLOTS = {"color": "color", "background": "background", "background-color": "background",
                "border": "border", "border-color": "border", "border-left": "border-left",
                "border-left-color": "border-left", "box-shadow": "box-shadow", "outline-color": "outline"}


def _colour_slots(body):
    """slot -> (value, important) of the colour declarations of a rule body."""
    slots = {}
    for prop, value in re.findall(r"([\w-]+)\s*:\s*([^;]+)", body or ""):
        if prop.strip() in COLOUR_SLOTS:
            slots[COLOUR_SLOTS[prop.strip()]] = (value.strip(), "!important" in value)
    return slots


def _colours_in(value, palette):
    """The r, g, b of every colour in a value, its variables resolved."""
    value = re.sub(r"var\(\s*(--[\w-]+)\s*\)", lambda m: palette.get(m.group(1), m.group(0)), value)
    found = [_hex_rgb(h) for h in re.findall(r"#[0-9a-fA-F]{3,8}\b", value)]
    found += [tuple(map(int, t)) for t in re.findall(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", value)]
    return found


def _severity_of(selector):
    """The one severity a selector colours (data-sev before classes), or None."""
    words = set(DATA_SEV.findall(selector)) or {"medium" if w == "med" else w for w in SEVERITY_TOKEN.findall(selector)}
    return words.pop() if len(words) == 1 and selector not in NOT_A_SEVERITY else None


def test_cyberpunk_severity_indicators_use_the_spec_colours():
    """Every rule that colours a severity (critical, high, medium, low,
    info) paints, in Cyberpunk, in the spec's colour of that severity only:
    text, tint, edge and glow. That holds for the rules of style.css, as the
    theme leaves or overrides them, and for the theme's own. Classic shows
    "high" partly in the red of critical and "low" in blue; Cyberpunk keeps
    them apart."""
    palette = _cyberpunk_palette()
    prefix = '[data-theme="cyberpunk"] '
    overrides, problems, checked = {}, [], 0
    # The shared accents (.sev-critical { border-color: ... !important } ...)
    # colour every border of any element with that class: they beat an edge
    # set without !important, whatever its specificity.
    shared = {}
    for prelude, body in _css_blocks(_without_first_root_block(_strip_comments(_read(STYLE_CSS)))):
        for selector in (_selectors(prelude) if body else []):
            if re.fullmatch(r"\.sev-\w+", selector):
                shared[selector] = _colour_slots(body).get("border")
    for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS))):
        for selector in (_selectors(prelude) if body else []):
            if re.fullmatch(re.escape(prefix) + r"\.sev-\w+", selector) and "border" in _colour_slots(body):
                shared[selector[len(prefix):]] = _colour_slots(body)["border"]

    def effective(selector, slot, value, important):
        """The value an edge really gets: a shared !important border of
        the element (the last compound) wins over one that is not."""
        if slot.startswith("border") and not important:
            subject = re.split(r"[\s>+~]+", selector.strip())[-1]
            for token in re.findall(r"\.sev-\w+", subject):
                if shared.get(token) and shared[token][1]:
                    return shared[token][0]
        return value

    def check(selector, severity, slot, value):
        nonlocal checked
        checked += 1
        colours = _colours_in(value, palette)
        if not colours or any(c != _hex_rgb(SPEC_SEVERITY[severity]) for c in colours):
            problems.append(f"{selector} {slot}: {value} is not {severity} {SPEC_SEVERITY[severity]}")

    for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS))):
        for selector in (_selectors(prelude) if body else []):
            if not selector.startswith(prefix):
                continue
            slots = _colour_slots(body)
            overrides.setdefault(selector[len(prefix):], {}).update(slots)
            severity = _severity_of(selector[len(prefix):])
            for slot, (value, important) in (slots.items() if severity else ()):
                check(selector, severity, slot, effective(selector[len(prefix):], slot, value, important))
    for prelude, body in _css_blocks(_without_first_root_block(_strip_comments(_read(STYLE_CSS)))):
        if not body or prelude.startswith("@"):
            continue
        for selector in _selectors(prelude):
            severity = _severity_of(selector)
            for slot, (value, important) in (_colour_slots(body).items() if severity else ()):
                theirs = overrides.get(selector, {}).get(slot)
                if theirs and (theirs[1] or not important):
                    value, important = theirs
                check(selector, severity, slot, effective(selector, slot, value, important))
    assert checked > 150, checked
    assert not problems, f"{len(problems)} severity colours off the spec in Cyberpunk:\n" + "\n".join(problems)


# The newest alerts first, as the sidebar timeline and Recent Activity take them
NEWEST_ALERTS_FUNCTIONS = ["newestAlerts", "filterAlerts", "alertSeverity", "alertRuleName", "alertProcessName",
                           "alertCategory", "_alertsTimeBound", "_alertsNameKey", "_alertNameIs"]


@needs_node
def test_dashboard_activity_tells_critical_from_high():
    """The feed groups critical with high (class sev-high, as in Classic);
    data-sev names the severity, so Cyberpunk can colour critical on its own.
    The engines write "High" as well as "high": the case does not matter."""
    r = _run_node(["renderDashboard", "escapeHtml"] + NEWEST_ALERTS_FUNCTIONS, r"""
        const els = {};
        globalThis.document = { getElementById: id => (els[id] = els[id] || { innerHTML: '' }) };
        globalThis.renderDashboardCharts = () => {};          // the charts have tests of their own
        const alert = (severity, i) => ({ severity, rule_name: 'r', process_name: 'p', pid: 1,
                                          timestamp: new Date(Date.UTC(2026, 10, 9, 10, 0, 0) - i * 1000).toISOString() });
        const feed = severities => {
            // Oldest first, as /api/alerts lists them: the feed, newest first, shows them in the order given
            const alerts = severities.map(alert).reverse();
            globalThis.state = { serviceStatus: {}, rustinelInfo: {}, processes: {}, alerts };
            renderDashboard();
            return [...els['dashboard-activity-feed'].innerHTML.matchAll(/<div class="activity-entry ([^"]*)" data-sev="([^"]*)">/g)]
                .map(m => [m[1], m[2]]);
        };
        console.log(JSON.stringify([feed(['critical', 'high', 'medium', 'low', 'info', 'x" onmouseover="y']),
                                    feed(['High', 'CRITICAL', 'Medium', 'unknown', undefined])]));
    """)
    assert r[0] == [["sev-high", "critical"], ["sev-high", "high"], ["sev-med", "medium"], ["sev-low", "low"],
                    ["sev-low", "low"], ["sev-low", "low"]]
    assert r[1] == [["sev-high", "high"], ["sev-high", "critical"], ["sev-med", "medium"], ["sev-low", "low"],
                    ["sev-low", "low"]], "a severity in upper case falls back to low"


@needs_node
def test_recent_activity_shows_the_eight_newest_alerts():
    """/api/alerts lists the alerts oldest first, sorted by their text. The
    feed shows the eight latest by time, newest first: an alert written with
    a time zone offset sorts by its text where its time does not put it."""
    r = _run_node(["renderDashboard", "escapeHtml"] + NEWEST_ALERTS_FUNCTIONS, r"""
        const els = {};
        globalThis.document = { getElementById: id => (els[id] = els[id] || { innerHTML: '' }) };
        globalThis.renderDashboardCharts = () => {};          // the charts have tests of their own
        const alert = (rule, timestamp) => ({ severity: 'low', rule_name: rule, process_name: 'p', pid: 1, timestamp });
        const alerts = [];
        for (let i = 0; i < 12; i++) alerts.push(alert('rule ' + i, new Date(Date.UTC(2026, 10, 9, 10, i)).toISOString()));
        // 10:30 UTC, the newest; by its text it comes before 10:00Z, where the server puts it
        alerts.unshift(alert('offset', '2026-11-09T09:30:00-01:00'));
        globalThis.state = { serviceStatus: {}, rustinelInfo: {}, processes: {}, alerts };
        renderDashboard();
        console.log(JSON.stringify([...els['dashboard-activity-feed'].innerHTML
            .matchAll(/<span class="activity-rule">([^<]*)<\/span>/g)].map(m => m[1])));
    """)
    assert r == ["offset", "rule 11", "rule 10", "rule 9", "rule 8", "rule 7", "rule 6", "rule 5"], \
        "the feed shows other alerts than the eight newest, or in another order"


@needs_node
def test_newest_alerts_go_by_time():
    """The newest alerts in the order of the Alerts tab: by time, not by the
    text the server sorts by (time zones differ); the same time in reverse
    list order, alerts without a time last. Neither end of the server's list
    is the answer."""
    r = _run_node(NEWEST_ALERTS_FUNCTIONS, r"""
        const a = (id, timestamp) => ({ id, timestamp });
        // In the order of /api/alerts: by their text
        const alerts = [a('no-time', ''), a('09:00Z', '2026-11-09T09:00:00Z'), a('09:30Z', '2026-11-09T09:30:00Z'),
                        a('09:45Z-1', '2026-11-09T09:45:00Z'), a('09:45Z-2', '2026-11-09T09:45:00Z'),
                        a('08:30Z', '2026-11-09T10:30:00+02:00')];
        const ids = list => list.map(alert => alert.id);
        console.log(JSON.stringify({ three: ids(newestAlerts(alerts, 3)), all: ids(newestAlerts(alerts, 10)),
                                     kept: ids(alerts), none: [newestAlerts([], 8), newestAlerts(undefined, 8)] }));
    """)
    assert r["three"] == ["09:45Z-2", "09:45Z-1", "09:30Z"]
    assert r["all"] == ["09:45Z-2", "09:45Z-1", "09:30Z", "09:00Z", "08:30Z", "no-time"]
    assert r["kept"] == ["no-time", "09:00Z", "09:30Z", "09:45Z-1", "09:45Z-2", "08:30Z"], "the list itself was sorted"
    assert r["none"] == [[], []]


THEME_PRELUDE = "const _themeColorCache = new Map();"


@needs_node
def test_theme_color_reads_css_variables():
    r = _run_node(["themeColor"], r"""
        globalThis.getComputedStyle = () => ({getPropertyValue: n => ({'--accent-red': ' #ef4444', '--accent-red-rgb': '239, 68, 68'})[n] || ''});
        globalThis.document = {documentElement: {}};
        console.log(JSON.stringify([themeColor('--accent-red'), themeColor('--accent-red', 0.2)]));
    """, THEME_PRELUDE)
    assert r == ["#ef4444", "rgba(239, 68, 68, 0.2)"]


@needs_node
def test_theme_change_redraws_with_the_new_colours():
    r = _run_node(["themeColor", "onThemeChange"], r"""
        let vars = {'--accent-red': '#ef4444'};
        globalThis.getComputedStyle = () => ({getPropertyValue: n => vars[n] || ''});
        globalThis.document = {documentElement: {}};
        let calls = [];
        for (const f of ['renderGraph', 'renderRtraceTimeline', 'renderTimeline', 'renderDashboard'])
            globalThis[f] = () => calls.push(f + ' ' + themeColor('--accent-red'));
        globalThis.FileMapView = { repaint: () => calls.push('FileMapView.repaint') };
        themeColor('--accent-red');                  // painted while Classic was active
        vars = {'--accent-red': '#ff3b3b'};          // <html data-theme> switched
        const cached = themeColor('--accent-red');
        const redraw = tab => { state.activeTab = tab; calls = []; onThemeChange(); return calls.sort(); };
        console.log(JSON.stringify({cached, dashboard: redraw('dashboard'), graph: redraw('graph'),
                                    tracing: redraw('tracing')}));
    """, THEME_PRELUDE + "const state = {activeTab: 'dashboard'};")
    assert r["cached"] == "#ef4444"
    # The sidebar timeline is not redrawn: its bars take their colours from CSS
    # classes, and a redraw would give them new random widths on every switch.
    # File maps are repainted in every tab: a hidden one is shown again later.
    assert r["dashboard"] == ["FileMapView.repaint", "renderDashboard #ff3b3b"]
    assert r["graph"] == ["FileMapView.repaint", "renderDashboard #ff3b3b", "renderGraph #ff3b3b"]
    assert r["tracing"] == ["FileMapView.repaint", "renderDashboard #ff3b3b", "renderRtraceTimeline #ff3b3b"]


def _module_source(name):
    """A top-level `const NAME = (() => { ... })();` module of app.js."""
    m = re.search(r"^const %s = \(\(\) => \{$.*?^\}\)\(\);$" % re.escape(name), _read(APP_JS), re.M | re.S)
    assert m, f"module {name} not found in app.js"
    return m.group(0)


# Just enough DOM and canvas for FileMapView: every fillStyle a canvas is
# given is recorded; innerHTML leaves one child, as markup would.
FILEMAP_DOM = r"""
const painted = [];
const ctx = { set fillStyle(v) { painted.push(v); }, get fillStyle() { return ''; }, fillRect() {}, putImageData() {},
              createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }) };
class FakeEl {
    constructor(tag) { Object.assign(this, { tagName: tag.toUpperCase(), children: [], style: {}, dataset: {},
                                             classes: new Set(), parentElement: null }); }
    get classList() {
        const c = this.classes;
        return { add: (...n) => n.forEach(x => c.add(x)), remove: (...n) => n.forEach(x => c.delete(x)),
                 contains: n => c.has(n) };
    }
    get className() { return [...this.classes].join(' '); }
    set className(v) { this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
    appendChild(c) { this.children.push(c); c.parentElement = this; return c; }
    set innerHTML(v) { this.children = []; if (v) this.appendChild(new FakeEl('div')); }
    get firstChild() { return this.children[0] || null; }
    get clientWidth() { return 900; }
    addEventListener() {}
    getContext() { return ctx; }
    *walk() { yield this; for (const c of this.children) yield* c.walk(); }
}
const body = new FakeEl('body');
globalThis.document = { documentElement: {}, body, createElement: tag => new FakeEl(tag),
    querySelectorAll: sel => [...body.walk()].filter(e => sel.split(',').some(s => e.classList.contains(s.trim().slice(1)))) };
const state = { activeTab: 'filemap' };
"""


@needs_node
def test_theme_change_repaints_file_maps_from_loaded_data():
    """The structure plane of the FileMap tab, the hex minimap and the PE/ELF
    inline map paint their background from the theme: after a switch they are
    painted again, from the data they show, without loading the file again."""
    r = _run_node(["themeColor", "onThemeChange", "escapeHtml", "jsArg", "jsInt", "formatSize"], r"""
        for (const f of ['renderGraph', 'renderRtraceTimeline', 'renderDashboard']) globalThis[f] = () => {};
        let vars = { '--c-navy-900': '#10182b' };
        globalThis.getComputedStyle = () => ({ getPropertyValue: n => vars[n] || '' });
        let requests = 0;
        const bytes = s => Buffer.from(s, 'latin1').toString('base64');
        globalThis.fetch = async () => { requests++; return { json: async () => ({
            path: 'C:\\x.exe', filename: 'x.exe', format: 'PE', rows: 4, cols: 4, entropy_cols: 2, file_size: 64,
            bytes_per_cell: 4, byteplot: bytes('\x00\x01\x02\x03'.repeat(4)), entropy: bytes('\x10\x80'.repeat(4)),
            regions: [{ offset: 0, size: 32, color: '#123456', name: 'headers' }],
            legend: { byteplot: [], entropy: [], structure: [] } }) }; };
        (async () => {
            const vis = await FileMapView.load('C:\\x.exe', { cols: 256, rows: 512 });
            const map = body.appendChild(new FakeEl('div'));
            const minimap = body.appendChild(new FakeEl('div'));
            FileMapView.renderVertical(map, vis, { height: 100 });
            FileMapView.renderStrip(minimap, vis, { viewport: true, trackHeight: 14 });
            FileMapView.updateViewport(minimap, 16, 16, 64);
            const marker = m => [m.style.left, m.style.width, m.classList.contains('visible')];
            const before = painted.splice(0).filter(c => c !== '#123456');
            const markerBefore = marker(minimap._viewportMarker);
            vars = { '--c-navy-900': '#140d24' };              // <html data-theme> switched
            onThemeChange();
            console.log(JSON.stringify({ before, after: painted.filter(c => c !== '#123456'), requests,
                                         markerBefore, markerAfter: marker(minimap._viewportMarker) }));
        })();
    """, THEME_PRELUDE + FILEMAP_DOM + _module_source("FileMapView"))
    assert r["before"] == ["#10182b", "#10182b"], "structure plane and strip track"
    assert r["after"] == ["#140d24", "#140d24"], "not repainted with the new theme"
    assert r["requests"] == 1, "the file was loaded again"
    assert r["markerAfter"] == r["markerBefore"] == ["25%", "25%", True], "the minimap lost its viewport mark"


def test_theme_change_listener_is_registered_once_at_load():
    js = _strip_js_comments(_read(APP_JS))
    found = re.findall(r"^(.*)addEventListener\(\s*'tdc:themechange'\s*,\s*onThemeChange\s*\)", js, re.M)
    assert found == ["document."], found     # top level: once, not per render


GRAPH_FUNCTIONS = ["themeColor", "isoProject", "_isoNodeStyle", "_isoHexPath", "_isoCube", "_isoArrow",
                   "_isoActivityIcons", "renderIsometricGraph", "renderGraph"]

# Both graph layouts on a canvas that records every colour it is given, with
# nodes and edges for each branch: kinds, severities, detonated, focus root,
# ancestor, hover, selection, scan verdicts, fold toggle, activity icons.
GRAPH_HARNESS = r"""
const _themeColorCache = new Map();
const ISO = { COS: Math.cos(Math.PI / 6), SIN: Math.sin(Math.PI / 6), STEP_U: 118, STEP_V: 76, LIFT: 64, R: 13 };
const graphState = { nodes: [], edges: [], camera: { x: 0, y: 0, zoom: 1 }, hoveredNode: null,
                     selectedNode: null, isLoading: false, emptyMessage: '', focusPid: null, layoutMode: 'tree' };
const painted = [];
const ctx = new Proxy({}, {
    get: (t, k) => k === 'measureText' ? () => ({ width: 10 }) : (k in t ? t[k] : () => {}),
    set: (t, k, v) => { if (k === 'fillStyle' || k === 'strokeStyle') painted.push(v); t[k] = v; return true; },
});
globalThis.document = { documentElement: {}, getElementById: () => ({ width: 800, height: 600, getContext: () => ctx }) };

const node = (id, extra = {}) => Object.assign({ id, key: id, pid: id, type: 'process', label: id, x: 0, y: 0,
    radius: 13, threats: 0, severity: 'unknown', isoU: 0, isoV: 0, isoKids: [], isoAct: {}, scans: [] }, extra);
const nodes = [
    ...['process', 'network', 'dns', 'file', 'registry', 'pipe', 'module'].map(type => node('kind-' + type, { type })),
    node('pipe-c2', { type: 'pipe', family: 'cobaltstrike' }),
    ...['critical', 'high', 'medium', 'low'].map(severity => node('sev-' + severity, { threats: 3, severity })),
    node('detonated', { detonated: true, threats: 2, severity: 'critical' }),
    node('root', { isRoot: true, isoHasKids: true, isoCollapsed: true, isoHiddenCount: 4 }),
    node('ancestor', { isAncestor: true, exited: true, isoHasKids: true }),
    node('hovered'), node('selected'),
    ...['malicious', 'detected', 'clean', 'analyzed', 'unknown', 'other']
        .map(v => node('scan-' + v, { scans: [{}], scanVerdict: v })),
    node('busy', { isoAct: { network: 1, dns: 2, file: 3, registry: 4, pipe: 5 } }),
];
const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
byId.ancestor.isoKids = [byId.root];
byId.root.isoKids = [byId['kind-process']];
const edges = ['spawn', 'network', 'dns', 'inject', 'file', 'registry', 'pipe-create', 'pipe-connect', 'pipe-link', 'other']
    .map(type => ({ source: 'root', target: 'kind-process', type }));

function paint(lookup) {
    _themeColorCache.clear();
    globalThis.getComputedStyle = () => ({ getPropertyValue: lookup });
    painted.length = 0;
    Object.assign(graphState, { nodes: [], edges: [], layoutMode: 'tree', hoveredNode: null, selectedNode: null });
    renderGraph();
    Object.assign(graphState, { nodes, edges, hoveredNode: byId.hovered, selectedNode: byId.selected });
    renderGraph();
    graphState.layoutMode = 'iso';
    renderGraph();
    return [...painted];
}
"""


@needs_node
def test_graph_colours_come_from_the_theme():
    r = _run_node(GRAPH_FUNCTIONS, r"""
        const painter = vars => {
            const missing = new Set();
            const colours = paint(n => n in vars ? vars[n] : (missing.add(n), ''));
            return { missing: [...missing].sort(), colours };
        };
        const classic = painter(CLASSIC_VARIABLES), cyberpunk = painter(CYBERPUNK_VARIABLES);
        const marked = paint(n => n.endsWith('-rgb') ? '1, 2, 3' : '#010203');
        console.log(JSON.stringify({ classic, cyberpunk, marked }));
    """.replace("CLASSIC_VARIABLES", json.dumps(_root_values()))
       .replace("CYBERPUNK_VARIABLES", json.dumps(_cyberpunk_palette())), GRAPH_HARNESS)
    assert r["classic"]["missing"] == [], "read by the graph but not defined in :root (an alpha needs NAME-rgb)"
    assert r["cyberpunk"]["missing"] == []
    foreign = sorted({c for c in r["marked"] if not re.fullmatch(r"#010203|rgba\(1, 2, 3, [\d.]+\)", c)})
    assert not foreign, f"graph colours that bypass the theme: {foreign}"
    assert len(r["marked"]) == len(r["classic"]["colours"]) == len(r["cyberpunk"]["colours"]) > 100
    neutral = {_root_values()[n].lower() for n in NEUTRAL_COLOURS if not n.endswith("-rgb")} | {"#fff", "#000"}
    classic_only = sorted(set(r["classic"]["colours"]) & set(r["cyberpunk"]["colours"]) - neutral)
    assert not classic_only, f"Classic colours in the Cyberpunk graph: {classic_only}"


GRAPH_KINDS = ["--graph-process", "--graph-network", "--graph-dns", "--graph-file", "--graph-registry",
               "--graph-pipe", "--graph-detonated"]


def test_graph_node_kinds_are_distinguishable():
    """Each kind of node and event keeps a colour of its own, and stands out
    from the canvas background, in each theme."""
    def distance(a, b):
        return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5
    problems = []
    for theme, values in (("Classic", _root_values()), ("Cyberpunk", _cyberpunk_palette())):
        rgb = {kind: _hex_rgb(values[kind]) for kind in GRAPH_KINDS}
        background = _hex_rgb(values["--bg-primary"])
        problems += [f"{theme}: {a} and {b} look alike" for i, a in enumerate(GRAPH_KINDS)
                     for b in GRAPH_KINDS[i + 1:] if distance(rgb[a], rgb[b]) < 48]
        problems += [f"{theme}: {kind} is too close to the background" for kind in GRAPH_KINDS
                     if distance(rgb[kind], background) < 150]
    assert not problems, "\n".join(problems)


# --- Theme switch ------------------------------------------------------------

def _const_source(name):
    """A top-level `const NAME = ...;` of app.js, for a Node prelude: one line,
    or up to the first line that ends with `;`."""
    m = re.search(r"^const %s = .*?;$" % re.escape(name), _read(APP_JS), re.M | re.S)
    assert m, f"const {name} not found in app.js"
    return m.group(0)


@needs_node
def test_normalize_and_next_theme():
    r = _run_node(["normalizeTheme", "nextTheme"], r"""
        const themes = ['cyberpunk', 'classic', 'garbage', null, undefined, '', 'Cyberpunk'];
        console.log(JSON.stringify({
            normalized: themes.map(v => normalizeTheme(v)),
            next: ['classic', 'cyberpunk', 'garbage'].map(v => nextTheme(v)),
        }));""", _const_source("THEMES"))
    # Cyberpunk is the default: anything but an exact theme name means Cyberpunk.
    assert r["normalized"] == ["cyberpunk", "classic", "cyberpunk", "cyberpunk", "cyberpunk", "cyberpunk", "cyberpunk"]
    assert r["next"] == ["cyberpunk", "classic", "classic"]


BOOT_SCRIPT = re.compile(r"<script>((?:(?!</script>).)*tdc-theme(?:(?!</script>).)*)</script>", re.S)


def test_theme_boot_script_runs_before_styles():
    html = _read(INDEX_HTML)
    boot = BOOT_SCRIPT.search(html)
    assert boot, "no inline <script> that applies the stored theme"
    assert "try" in boot.group(1)
    assert boot.start() < html.index('<link rel="stylesheet"'), "theme applied after the styles: Classic flashes"
    assert re.search(r'<link rel="stylesheet" href="/static/css/theme-cyberpunk\.css\?v=\d+">', html)


@needs_node
def test_theme_boot_script_defaults_to_cyberpunk():
    r = _run_node([], r"""
        function boot() { BOOT_SCRIPT }
        function run(storage) {
            Object.defineProperty(globalThis, 'localStorage', { configurable: true, get: storage });
            globalThis.document = { documentElement: { dataset: {} } };
            try { boot(); } catch (e) { return 'threw: ' + e.message; }
            return document.documentElement.dataset.theme;
        }
        const stored = value => () => ({ getItem: key => (key === 'tdc-theme' ? value : null) });
        console.log(JSON.stringify([
            run(stored('cyberpunk')), run(stored('classic')), run(stored('xyz')), run(stored(null)),
            run(() => ({ getItem() { throw new Error('SecurityError'); } })),
            run(() => { throw new Error('SecurityError'); }),       // storage disabled in the browser
        ]));
    """.replace("BOOT_SCRIPT", BOOT_SCRIPT.search(_read(INDEX_HTML)).group(1)))
    # Only a stored "classic" keeps Classic; no, unknown or unreadable storage gives the default.
    assert r == ["cyberpunk", "classic", "cyberpunk", "cyberpunk", "cyberpunk", "cyberpunk"]


def test_theme_toggles_and_topbar_exist():
    html = _read(INDEX_HTML)
    for toggle in ("theme-toggle", "theme-toggle-top"):
        tag = re.search(r'<button\b[^>]*\bid="%s"[^>]*>' % toggle, html)
        assert tag and re.search(r'\baria-label="Switch to \w+ theme"', tag.group(0)), toggle
    for part in ("topbar", "drawer-toggle", "drawer-count", "topbar-nav", "topbar-more-wrap", "topbar-more-toggle",
                 "topbar-more", "topbar-services", "topbar-services-panel", "topbar-time", "drawer-scrim"):
        assert f'id="{part}"' in html, part
    css = _strip_comments(_read(STYLE_CSS))
    assert re.search(r"^#topbar\s*\{\s*display:\s*none;\s*\}", css, re.M), "the top bar shows in Classic"
    assert re.search(r"^#drawer-scrim\s*\{\s*display:\s*none;\s*\}", css, re.M), "the drawer scrim shows in Classic"


THEME_SWITCH_FUNCTIONS = ["normalizeTheme", "nextTheme", "currentTheme", "applyThemeLayout", "setTheme",
                          "toggleTheme"]
# The Cyberpunk drawer, drop-downs and tab overflow, which a switch resets
TOPBAR_FUNCTIONS = ["isDrawerOpen", "setDrawerOpen", "openDrawer", "closeDrawer", "toggleDrawer", "isTopbarMenuOpen",
                    "setTopbarMenu", "toggleTopbarMenu", "closeTopbarMenus", "computeVisibleTabs", "updateTabOverflow"]
THEME_SWITCH_FUNCTIONS += TOPBAR_FUNCTIONS


def test_set_theme_never_reloads():
    for name in ("setTheme", "toggleTheme", "applyThemeLayout"):
        body = _strip_js_comments(_function_source(name))
        assert not re.search(r"\blocation\b", body), f"{name} reloads or leaves the page"
        assert not re.search(r"\b(initTabs|initGraphControls|refreshAll)\s*\(", body), f"{name} sets the UI up again"


VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class _Elements(HTMLParser):
    """The elements of a template as {tag, attrs, children, text}; an
    element's text is the text directly inside it."""

    def __init__(self, html):
        super().__init__()
        self.root = {"tag": "#root", "attrs": {}, "children": []}
        self._open = [self.root]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": {k: v or "" for k, v in attrs}, "children": []}
        self._open[-1]["children"].append(node)
        if tag not in VOID_TAGS:
            self._open.append(node)

    def handle_data(self, data):
        self._open[-1]["text"] = self._open[-1].get("text", "") + data

    def handle_endtag(self, tag):
        for i in range(len(self._open) - 1, 0, -1):
            if self._open[i]["tag"] == tag:
                del self._open[i:]
                return

    def by_id(self, element_id, node=None):
        node = node or self.root
        if node["attrs"].get("id") == element_id:
            return node
        return next(filter(None, (self.by_id(element_id, c) for c in node["children"])), None)


# Just enough DOM for the theme switch and the top bar, built from the real
# #topbar, #drawer-scrim and #sidebar markup. As in a browser, appending or
# inserting a node that is already in the tree moves it. Layout: an element is
# as wide as the test sets it (el.width), and takes no room while it or an
# ancestor is hidden or has .tab-overflow (theme-cyberpunk.css hides those
# tabs); getComputedStyle() returns what the test puts in el.computed.
MINI_DOM = r"""
class El {
    constructor(n) {
        Object.assign(this, { tagName: n.tag.toUpperCase(), attrs: { ...n.attrs }, dataset: {}, parentElement: null,
                              children: [], text: n.text || '', listeners: {}, width: 0 });
        for (const [k, v] of Object.entries(this.attrs))
            if (k.startsWith('data-')) this.dataset[k.slice(5).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = v;
        (n.children || []).forEach(c => this.appendChild(new El(c)));
    }
    get id() { return this.attrs.id || ''; }
    get title() { return this.attrs.title || ''; }
    set title(v) { this.attrs.title = String(v); }
    get className() { return this.attrs.class || ''; }
    set className(v) { this.attrs.class = String(v); }
    get classList() {
        const el = this, names = () => el.className.split(/\s+/).filter(Boolean);
        return {
            contains: c => names().includes(c),
            add: (...cs) => { el.className = [...new Set([...names(), ...cs])].join(' '); },
            remove: (...cs) => { el.className = names().filter(c => !cs.includes(c)).join(' '); },
            toggle(c, on = !names().includes(c)) { if (on) this.add(c); else this.remove(c); return on; },
        };
    }
    get hidden() { return 'hidden' in this.attrs; }
    set hidden(v) { if (v) this.attrs.hidden = ''; else delete this.attrs.hidden; }
    get textContent() { return this.text + this.children.map(c => c.textContent).join(''); }
    set textContent(v) { this.replaceChildren(); this.text = String(v); }
    set innerHTML(v) { this.replaceChildren(); this.text = ''; this.html = String(v); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    get nextElementSibling() { const s = this.parentElement.children; return s[s.indexOf(this) + 1] || null; }
    get lastElementChild() { return this.children[this.children.length - 1] || null; }
    remove() {
        if (this.parentElement) this.parentElement.children.splice(this.parentElement.children.indexOf(this), 1);
        this.parentElement = null;
    }
    appendChild(c) { c.remove(); c.parentElement = this; this.children.push(c); return c; }
    prepend(n) { n.remove(); n.parentElement = this; this.children.unshift(n); }
    replaceChildren(...nodes) {                 // the element's own text is a child node as well
        [...this.children].forEach(c => c.remove());
        this.text = '';
        nodes.forEach(n => this.appendChild(typeof n === 'string' ? new El({ tag: '#text', attrs: {}, text: n }) : n));
    }
    after(n) {
        n.remove();
        n.parentElement = this.parentElement;
        this.parentElement.children.splice(this.parentElement.children.indexOf(this) + 1, 0, n);
    }
    contains(n) { for (let e = n; e; e = e.parentElement) if (e === this) return true; return false; }
    matches(sel) {                              // compound selectors only: tag, .class, #id, [attr="value"]
        const m = /^(\w*)((?:[.#][\w-]+|\[[\w-]+="[^"]*"\])*)$/.exec(sel);
        if (!m) throw new Error('selector not supported by the test DOM: ' + sel);
        return (!m[1] || m[1].toUpperCase() === this.tagName) && (m[2].match(/[.#][\w-]+|\[[^\]]*\]/g) || []).every(p =>
            p[0] === '#' ? this.id === p.slice(1)
            : p[0] === '.' ? this.classList.contains(p.slice(1))
            : this.getAttribute(p.slice(1, p.indexOf('='))) === p.slice(p.indexOf('"') + 1, -2));
    }
    querySelectorAll(sel) { return [...this.walk()].filter(e => e !== this && matchesSelector(e, sel)); }
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
    getBoundingClientRect() {
        for (let e = this; e; e = e.parentElement)
            if (e.hidden || e.classList.contains('tab-overflow')) return { width: 0 };
        return { width: this.width };
    }
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
    focus() { document.activeElement = this; }
    *walk() { yield this; for (const c of this.children) yield* c.walk(); }
}
function matchesSelector(el, sel) {             // compound selectors joined by descendant combinators
    const parts = sel.trim().split(/\s+/);
    if (!el.matches(parts.pop())) return false;
    for (let e = el.parentElement; e && parts.length; e = e.parentElement)
        if (e.matches(parts[parts.length - 1])) parts.pop();
    return parts.length === 0;
}
// A click as a browser delivers it: first the top bar's capture listener on the
// document, then the inline onclick handlers of the template and the listeners,
// from the element up through its ancestors.
function click(el) {
    if (typeof onTopbarOutsideClick === 'function') onTopbarOutsideClick({ target: el });
    for (let e = el; e; e = e.parentElement) {
        if (e.attrs.onclick) (0, eval)(e.attrs.onclick);
        (e.listeners.click || []).forEach(f => f({ target: el, currentTarget: e }));
    }
}
const page = new El(MARKUP);
globalThis.document = Object.assign(new EventTarget(), {
    documentElement: new El({ tag: 'html', attrs: {}, children: [] }),
    activeElement: null,
    getElementById: id => [...page.walk()].find(e => e.id === id) || null,
    querySelector: sel => [...page.walk()].find(e => matchesSelector(e, sel)) || null,
    querySelectorAll: sel => [...page.walk()].filter(e => matchesSelector(e, sel)),
    createElement: tag => new El({ tag, attrs: {}, children: [] }),
});
globalThis.getComputedStyle = el => el.computed || {};
const calls = [];
for (const f of ['initTabs', 'initGraphControls', 'refreshAll']) globalThis[f] = () => calls.push(f);
globalThis.location = { reload: () => calls.push('location.reload') };
"""


def _layout_parts():
    """#app with the parts of the page that the theme switch and the top bar
    rearrange: #topbar, #drawer-scrim and #sidebar from index.html."""
    elements = _Elements(_read(INDEX_HTML))
    parts = [elements.by_id(part) for part in ("topbar", "drawer-scrim", "sidebar")]
    assert all(parts), "#topbar, #drawer-scrim or #sidebar missing in index.html"
    return {"tag": "div", "attrs": {"id": "app"}, "children": parts}


def _dom_prelude(app):
    """The test DOM with `app`, the help modal and the dashboard clock, and the
    constants the functions under test read."""
    outside = [{"tag": "div", "attrs": {"id": "help-modal", "class": "help-modal hidden"}, "children": []},
               {"tag": "span", "attrs": {"id": "dashboard-time", "class": "header-meta"}, "children": []}]
    markup = {"tag": "div", "attrs": {}, "children": [app] + outside}
    consts = (_const_source(c) for c in ("THEMES", "THEME_LABELS", "TOPBAR_MENUS", "STATUS_SERVICES"))
    return "\n".join(consts) + MINI_DOM.replace("MARKUP", json.dumps(markup))


def _switch_prelude():
    return _dom_prelude(_layout_parts())


@needs_node
def test_set_theme_moves_tabs_and_status_and_back():
    r = _run_node(THEME_SWITCH_FUNCTIONS, r"""
        const stored = {};
        Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: {
            getItem: k => (k in stored ? stored[k] : null), setItem: (k, v) => { stored[k] = String(v); } } });
        const events = [];
        document.addEventListener('tdc:themechange', e => events.push(e.detail));
        const shape = e => [e.tagName, e.id, e.attrs.class || '', e.children.map(shape)];
        const markup = JSON.stringify(shape(page));
        const nav = document.querySelector('nav.sidebar-tabs');
        const tabs = [...nav.children];
        const status = document.getElementById('service-status');
        const view = () => ({
            theme: document.documentElement.dataset.theme,
            stored: stored['tdc-theme'],
            nav: nav.parentElement.id || nav.parentElement.attrs.class,
            status: status.parentElement.id,
            labels: ['theme-toggle', 'theme-toggle-top'].map(id => {
                const button = document.getElementById(id);
                return [button.title, button.getAttribute('aria-label')];
            }),
        });
        setTheme('cyberpunk');
        const cyberpunk = view();
        const order = document.getElementById('topbar-nav').children.map(e => e.tagName + '#' + e.id);
        toggleTheme();
        const classic = view();
        console.log(JSON.stringify({ cyberpunk, classic, events, calls, order,
            restored: JSON.stringify(shape(page)) === markup,
            sameNodes: document.querySelector('nav.sidebar-tabs') === nav
                && tabs.every((tab, i) => nav.children[i] === tab) }));
    """, _switch_prelude())
    to_classic, to_cyberpunk = ["Switch to Classic theme"] * 2, ["Switch to Cyberpunk theme"] * 2
    assert r["cyberpunk"] == {"theme": "cyberpunk", "stored": "cyberpunk", "nav": "topbar-nav",
                              "status": "topbar-services-panel", "labels": [to_classic, to_classic]}
    assert r["classic"] == {"theme": "classic", "stored": "classic", "nav": "sidebar-header",
                            "status": "sidebar", "labels": [to_cyberpunk, to_cyberpunk]}
    assert r["order"] == ["NAV#", "DIV#topbar-more-wrap"], "the tab bar is not in front of the … menu"
    assert r["restored"], "after switching back the sidebar is not in the order of the markup"
    assert r["sameNodes"], "the tab bar was re-created: its click handlers are gone"
    assert r["events"] == [{"theme": "cyberpunk"}, {"theme": "classic"}]
    assert r["calls"] == [], "the switch reloaded the page or set the UI up again"


@needs_node
def test_set_theme_survives_blocked_storage():
    r = _run_node(THEME_SWITCH_FUNCTIONS, r"""
        const blocked = [
            { get() { throw new Error('SecurityError'); } },                    // storage disabled
            { value: { setItem() { throw new Error('QuotaExceededError'); } } },
        ];
        console.log(JSON.stringify(blocked.map(storage => {
            Object.defineProperty(globalThis, 'localStorage', { configurable: true, ...storage });
            let events = 0;
            const count = () => { events++; };
            document.addEventListener('tdc:themechange', count);
            try {
                setTheme('cyberpunk');
                return [document.documentElement.dataset.theme, events,
                        document.querySelector('nav.sidebar-tabs').parentElement.id];
            } catch (e) {
                return 'threw: ' + e.message;
            } finally {
                document.removeEventListener('tdc:themechange', count);
                setTheme('classic');
            }
        })));
    """, _switch_prelude())
    assert r == [["cyberpunk", 1, "topbar-nav"], ["cyberpunk", 1, "topbar-nav"]]


def test_page_load_lays_out_the_stored_theme():
    """A page loaded in Cyberpunk moves the tab bar and the status at start-up."""
    js = _strip_js_comments(_read(APP_JS))
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    init = js[start:js.index("\n});", start)]
    assert re.search(r"applyThemeLayout\(currentTheme\(\)\);\s*initTabs\(\);", init)


@needs_node
def test_switching_with_the_keyboard_keeps_the_focus_on_a_visible_toggle():
    """Each theme hides the other theme's ✶: the focus moves along with the switch."""
    r = _run_node(THEME_SWITCH_FUNCTIONS, r"""
        const $ = id => document.getElementById(id);
        setTheme('classic');                // start from Classic (Cyberpunk is the default)
        $('theme-toggle').focus();
        toggleTheme();
        const toCyberpunk = document.activeElement.id;
        toggleTheme();
        const toClassic = document.activeElement.id;
        $('drawer-toggle').focus();
        setTheme('cyberpunk');
        console.log(JSON.stringify([toCyberpunk, toClassic, document.activeElement.id]));
    """, _switch_prelude())
    assert r == ["theme-toggle-top", "theme-toggle", "drawer-toggle"]


@needs_node
def test_theme_switch_turns_transitions_off_for_one_frame():
    """Both layouts swap at once. With transitions on, the drawer slid out of
    view on the way to Cyberpunk and the tabs faded on the way back."""
    r = _run_node(THEME_SWITCH_FUNCTIONS, r"""
        Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { setItem() {}, getItem: () => null } });
        const frames = [];
        globalThis.requestAnimationFrame = callback => frames.push(callback);
        const switching = () => document.documentElement.classList.contains('theme-switching');
        const duringEvent = [];
        document.addEventListener('tdc:themechange', () => duringEvent.push(switching()));
        const steps = [];
        for (const theme of ['cyberpunk', 'classic']) {
            setTheme(theme);
            steps.push([switching(), frames.length]);
            frames.splice(0).forEach(callback => callback());
            steps.push([switching(), frames.length]);
        }
        console.log(JSON.stringify({ steps, duringEvent }));
    """, _switch_prelude())
    assert r["steps"] == [[True, 1], [False, 0], [True, 1], [False, 0]], "on during the switch, off a frame later"
    assert r["duringEvent"] == [True, True]
    rules = [(set(_selectors(prelude)), body) for prelude, body in _css_blocks(_strip_comments(_read(STYLE_CSS))) if body]
    assert any({".theme-switching *", ".theme-switching *::before", ".theme-switching *::after"} <= selectors
               and re.search(r"transition:\s*none\s*!important", body) for selectors, body in rules), \
        "style.css has no rule that turns every transition off during a switch (in both themes)"


@needs_node
def test_failed_theme_switch_turns_transitions_back_on():
    """A switch that throws half-way must not leave every transition off."""
    r = _run_node(THEME_SWITCH_FUNCTIONS, r"""
        Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { setItem() {}, getItem: () => null } });
        const frames = [];
        globalThis.requestAnimationFrame = callback => frames.push(callback);
        applyThemeLayout = () => { throw new Error('layout failed'); };
        let thrown = null;
        try { setTheme('cyberpunk'); } catch (e) { thrown = e.message; }
        frames.splice(0).forEach(callback => callback());
        console.log(JSON.stringify({ thrown, switching: document.documentElement.classList.contains('theme-switching') }));
    """, _switch_prelude())
    assert r == {"thrown": "layout failed", "switching": False}


def test_closed_drawer_scrim_lets_clicks_through():
    """The scrim fades out for 0.22 s after the drawer closed; until then it
    caught the clicks meant for the content under it."""
    bodies = {}
    for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS))):
        for selector in _selectors(prelude):
            bodies[selector] = bodies.get(selector, "") + (body or "")
    assert re.search(r"pointer-events:\s*none", bodies.get('[data-theme="cyberpunk"] #drawer-scrim', ""))
    assert re.search(r"pointer-events:\s*auto", bodies.get('[data-theme="cyberpunk"] #app.drawer-open #drawer-scrim', ""))


def test_cyberpunk_never_hides_the_keyboard_focus():
    hidden = [selector for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS)))
              if body and re.search(r"\boutline:\s*(none|0)\b", body)
              for selector in _selectors(prelude) if ":focus-visible" in selector]
    assert not hidden, hidden


# Generated text that only decorates: a screen reader read the kicker before
# every tab title, and the caret as part of the services button's name
DECORATIVE_CONTENT = {
    '[data-theme="cyberpunk"] .content-header::before': "TDC // DETONATION CHAMBER",
    '[data-theme="cyberpunk"] #topbar-services::after': "\\25BE",
}


def test_cyberpunk_decorative_text_is_not_read_aloud():
    """Its content has an empty alternative text ("..." / ""), after the plain
    declaration that browsers without that syntax keep."""
    rules = _rules(THEME_CSS)
    for selector, text in DECORATIVE_CONTENT.items():
        contents = [c.strip() for c in re.findall(r"(?:^|;)\s*content:\s*([^;]+)", rules.get(selector, ""))]
        assert contents, f"{selector} has no content"
        assert re.fullmatch(r'"%s"\s*/\s*""' % re.escape(text), contents[-1]), f"{selector} is read aloud: {contents[-1]}"
        assert contents[:-1] == [f'"{text}"'], f"{selector}: no fallback for browsers without alternative texts"


BUTTON_COMPOUND = re.compile(r"[.#][\w-]*btn[\w-]*|#drawer-toggle|#topbar-services|#topbar-more-toggle")


def test_cyberpunk_hover_skips_disabled_buttons():
    """A disabled button stays dim under the pointer: a theme rule for
    :hover outranks Classic's .btn-primary:disabled { opacity: .4 }, so each
    one for a button has to exclude :disabled (Detonate lit up full magenta
    before a file was chosen)."""
    lit = [selector for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS))) if body
           for selector in _selectors(prelude)
           for compound in selector.split()
           if ":hover" in compound and BUTTON_COMPOUND.search(compound) and ":not(:disabled)" not in compound]
    assert not lit, "hover rules that also light up disabled buttons:\n" + "\n".join(lit)


def test_cyberpunk_hex_card_keeps_its_rows_beside_an_analysis_panel():
    """The PE/ELF panel takes up to 65 % of the window; below the top bar
    and the taller head area it squeezed the hex card until even its status
    row (offset, selection) was cut off. The card keeps a minimum height and
    the panel, which scrolls, gives way. The ELF panel does not scroll in
    Classic (overflow: hidden): without a scrolling rule of its own the
    squeezed panel cut off its lower half (770 px of content, 480 px shown)."""
    blocks = _css_blocks(_strip_comments(_read(THEME_CSS)))

    def bodies(selector):
        return "".join(body for prelude, body in blocks if body and selector in _selectors(prelude))

    m = re.search(r"min-height:\s*(\d+)px", bodies('[data-theme="cyberpunk"] .hex-editor-container'))
    assert m and int(m.group(1)) >= 232, "Classic keeps 232 px for the card at 1920 x 960"
    elf = bodies('[data-theme="cyberpunk"] .elf-panel')
    assert re.search(r"max-height:\s*65vh", elf) and re.search(r"overflow-y:\s*auto", elf), \
        "the ELF panel must scroll like the PE panel"


# --- Cyberpunk layout: top bar, drawer, tab overflow --------------------------

@needs_node
def test_compute_visible_tabs():
    r = _run_node(["computeVisibleTabs"], r"""
        const four = [100, 100, 100, 100];
        console.log(JSON.stringify([
            computeVisibleTabs(four, 450, 40, 0),
            computeVisibleTabs(four, 400, 40, 0),
            computeVisibleTabs(four, 330, 40, 0),
            computeVisibleTabs(four, 330, 40, 3),
            computeVisibleTabs(four, 0, 40, 2),
            computeVisibleTabs(four, 330, 40, -1),
            computeVisibleTabs([50, 200, 50, 80], 250, 30, 3),
            computeVisibleTabs([], 100, 40, 0),
        ]));""")
    assert r[0] == [0, 1, 2, 3] and r[1] == [0, 1, 2, 3], "all tabs fit: no … needed"
    assert r[2] == [0, 1], "… needs its 40 px: 290 px are left for tabs"
    assert r[3] == [0, 3] and r[4] == [2], "the active tab is always shown"
    assert r[5] == [0, 1], "no active tab"
    # The bar shows the first tabs and the active one; the menu holds the rest in
    # order, so a narrow tab after a wide one is not pulled forward.
    assert r[6] == [0, 3]
    assert r[7] == []


@needs_node
def test_tabs_that_do_not_fit_move_into_the_more_menu():
    r = _run_node(THEME_SWITCH_FUNCTIONS + ["switchTab", "onTopbarOutsideClick", "initTopbar"], r"""
        globalThis.state = { activeTab: 'alpha' };
        const observed = [], onResize = [];
        globalThis.ResizeObserver = class {
            constructor(callback) { onResize.push(callback); }
            observe(el) { observed.push(el.id); }
        };
        const nav = document.querySelector('nav.sidebar-tabs');
        nav.replaceChildren(...['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Zeta'].map((label, i) => {
            const name = label.toLowerCase();
            page.appendChild(new El({ tag: 'div', attrs: { id: 'tab-' + name, class: 'tab-content' } }));
            return new El({ tag: 'button', attrs: { class: i ? 'tab' : 'tab active', 'data-tab': name }, text: label });
        }));
        // Tabs of 100 px in a bar with 2 px gaps, 2 px padding and a 1 px border, and
        // 6 px between the bar and the 40 px "…" button: all six tabs need 616 px.
        nav.querySelectorAll('.tab').forEach(tab => { tab.width = 100; });
        nav.computed = { columnGap: '2px', paddingLeft: '2px', paddingRight: '2px',
                         borderLeftWidth: '1px', borderRightWidth: '1px' };
        const area = document.getElementById('topbar-nav');
        area.computed = { columnGap: '6px' };
        const wrap = document.getElementById('topbar-more-wrap');
        wrap.width = 40;
        const more = document.getElementById('topbar-more-toggle');
        const items = () => document.getElementById('topbar-more').children;
        const bar = () => ({
            shown: nav.children.filter(t => !t.classList.contains('tab-overflow')).map(t => t.textContent),
            menu: items().map(i => i.textContent),
            more: !wrap.hidden,
        });
        // The browser reports a new size of the tab area: the observer refits the tabs.
        const at = width => { area.width = width; onResize.forEach(callback => callback([])); return bar(); };
        area.width = 330;
        setTheme('cyberpunk');
        initTopbar();
        const narrow = bar();
        click(more);
        const opened = more.getAttribute('aria-expanded');
        const viaHtml = items().some(i => i.html !== undefined);
        click(items().find(i => i.textContent === 'Epsilon'));
        const picked = { ...bar(), active: nav.children.filter(t => t.classList.contains('active')).map(t => t.textContent),
                         activeTab: state.activeTab, opened: more.getAttribute('aria-expanded') };
        const wide = at(616), mid = at(540), midAgain = at(540), justTooNarrow = at(615);
        setTheme('classic');
        console.log(JSON.stringify({ narrow, opened, viaHtml, picked, wide, mid, midAgain, justTooNarrow, observed,
                                     classic: bar() }));
    """, _switch_prelude())
    six = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta"]
    assert r["observed"] == ["topbar-nav"]
    # 330 px: Alpha, Beta and … take 254 px; a third tab would need 356.
    assert r["narrow"] == {"shown": ["Alpha", "Beta"], "menu": ["Gamma", "Delta", "Epsilon", "Zeta"], "more": True}
    assert r["opened"] == "true" and not r["viaHtml"]
    assert r["picked"] == {"shown": ["Alpha", "Epsilon"], "menu": ["Beta", "Gamma", "Delta", "Zeta"], "more": True,
                           "active": ["Epsilon"], "activeTab": "epsilon", "opened": "false"}
    assert r["wide"] == {"shown": six, "menu": [], "more": False}
    # 540 px right after … was hidden: four tabs and … take 458 px, five 560.
    assert r["mid"] == r["midAgain"] == {"shown": ["Alpha", "Beta", "Gamma", "Epsilon"], "menu": ["Delta", "Zeta"],
                                         "more": True}
    assert r["justTooNarrow"] == {"shown": six[:5], "menu": ["Zeta"], "more": True}
    assert r["classic"] == {"shown": six, "menu": [], "more": False}, "Classic lost tabs to the … menu"


@needs_node
def test_top_bar_menus_keep_the_keyboard_focus():
    """A tab picked in the "…" menu takes the focus (its menu item is gone
    after the refit), and Esc gives it back to the button of the drop-down."""
    r = _run_node(THEME_SWITCH_FUNCTIONS + ["switchTab", "onTopbarOutsideClick", "handleGlobalKeydown", "closeHelp"], r"""
        globalThis.state = { activeTab: 'alpha', detailOpen: false };
        const nav = document.querySelector('nav.sidebar-tabs');
        nav.replaceChildren(...['Alpha', 'Beta', 'Gamma', 'Delta'].map((label, i) => {
            const name = label.toLowerCase();
            page.appendChild(new El({ tag: 'div', attrs: { id: 'tab-' + name, class: 'tab-content' } }));
            const tab = new El({ tag: 'button', attrs: { class: i ? 'tab' : 'tab active', 'data-tab': name }, text: label });
            tab.width = 100;
            return tab;
        }));
        const $ = id => document.getElementById(id);
        $('topbar-nav').width = 250;                  // Alpha, Beta and "…" fit
        $('topbar-more-wrap').width = 40;
        setTheme('cyberpunk');
        const focused = () => document.activeElement && (document.activeElement.id || document.activeElement.textContent);
        const esc = () => handleGlobalKeydown({ key: 'Escape', preventDefault() {} });
        const items = () => $('topbar-more').children;
        const r = {};
        $('topbar-more-toggle').focus();
        click($('topbar-more-toggle'));
        r.menu = items().map(i => i.textContent);
        items()[1].focus();
        click(items()[1]);
        r.picked = [focused(), document.activeElement.classList.contains('tab'),
                    document.activeElement.classList.contains('tab-overflow')];
        click($('topbar-more-toggle'));
        items()[0].focus();
        esc();
        r.escMore = [focused(), $('topbar-more-toggle').getAttribute('aria-expanded')];
        click($('topbar-services'));
        esc();
        r.escServices = [focused(), $('topbar-services').getAttribute('aria-expanded')];
        console.log(JSON.stringify(r));
    """, _switch_prelude())
    assert r["menu"] == ["Gamma", "Delta"]
    assert r["picked"] == ["Delta", True, False], "the focus stayed on the removed menu item"
    assert r["escMore"] == ["topbar-more-toggle", "false"]
    assert r["escServices"] == ["topbar-services", "false"]


def test_cyberpunk_hides_the_tabs_in_the_more_menu():
    """The test DOM counts a tab with .tab-overflow as hidden: the theme has to hide it."""
    hiding = [selector for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS)))
              if body and re.search(r"\bdisplay:\s*none\b", body) for selector in _selectors(prelude)]
    assert any(s.endswith(".tab-overflow") for s in hiding), hiding


@needs_node
def test_drawer_and_drop_downs_open_and_close():
    r = _run_node(THEME_SWITCH_FUNCTIONS + ["onTopbarOutsideClick", "handleGlobalKeydown", "closeHelp",
                                            "openProcessDetail", "escapeHtml"], r"""
        globalThis.state = { detailOpen: false, processes: {}, detailHistory: [] };
        for (const f of ['renderProcessList', 'pushDetailHistory', 'setDetailHeader', 'setDetailBody', 'showDetail',
                         'goDetailBack']) globalThis[f] = () => {};
        globalThis.closeDetail = () => { state.detailOpen = false; };
        const $ = id => document.getElementById(id);
        const esc = () => handleGlobalKeydown({ key: 'Escape', preventDefault() {} });
        const drawer = () => [$('app').classList.contains('drawer-open'), $('drawer-toggle').getAttribute('aria-expanded')];
        const services = () => $('topbar-services').getAttribute('aria-expanded');
        const r = {};
        setTheme('cyberpunk');
        const tab = document.querySelector('#topbar-nav .tab');
        click($('drawer-toggle')); r.opened = drawer();
        click($('drawer-toggle')); r.toggled = drawer();
        click($('drawer-toggle')); esc(); r.esc = drawer();
        click($('drawer-toggle')); click($('process-list')); r.inside = drawer();
        click($('drawer-scrim')); r.scrim = drawer();
        click($('drawer-toggle')); click(tab); r.topBar = drawer();
        click($('drawer-toggle')); openProcessDetail('4242'); r.process = drawer();
        click($('topbar-services')); r.services = [services()];
        click($('status-sysmon')); r.services.push(services());
        click(tab); r.services.push(services());
        click($('topbar-services')); esc(); r.services.push(services());
        // Esc closes one layer per press, the top-most first
        $('help-modal').classList.remove('hidden');
        toggleTopbarMenu('topbar-services');
        openDrawer();
        state.detailOpen = true;
        const layers = () => [!$('help-modal').classList.contains('hidden'), services() === 'true', drawer()[0],
                              state.detailOpen];
        r.layers = [layers()];
        for (let i = 0; i < 4; i++) { esc(); r.layers.push(layers()); }
        // Neither the drawer nor a drop-down is kept across a theme switch
        openDrawer(); toggleTopbarMenu('topbar-services');
        setTheme('classic'); r.classic = [drawer(), services()];
        openDrawer(); r.classicOpen = drawer();
        toggleDrawer(); r.classicToggle = drawer();
        setTheme('cyberpunk'); r.back = [drawer(), services()];
        console.log(JSON.stringify(r));
    """, _switch_prelude())
    closed, opened = [False, "false"], [True, "true"]
    assert r["opened"] == opened and r["toggled"] == closed
    assert r["esc"] == closed, "Esc leaves the drawer open"
    assert r["inside"] == opened, "a click in the drawer closes it"
    assert r["scrim"] == closed and r["topBar"] == closed, "a click beside the drawer leaves it open"
    assert r["process"] == closed, "the drawer stays over the detail view of the picked process"
    assert r["services"] == ["true", "true", "false", "false"], "open, click inside, click outside, Esc"
    assert r["layers"] == [[True, True, True, True], [False, True, True, True], [False, False, True, True],
                           [False, False, False, True], [False, False, False, False]]
    assert r["classic"] == [closed, "false"] and r["back"] == [closed, "false"]
    assert r["classicOpen"] == r["classicToggle"] == closed, "Classic has no drawer"


# /api/status as the VM answers it; "detonator" is not one of the five services.
LIVE_STATUS = {"detonator": {"online": False}, "detonator_agent": {"data": {"in_use": False}, "online": True},
               "fibratus": {"online": True}, "litterbox": {"online": False},
               "rustinel": {"alerts_count": 9620, "online": True}, "sysmon": {"online": True}}


@needs_node
def test_topbar_counts_the_services_like_the_sidebar():
    all_online = {key: {"online": True} for key in ("rustinel", "sysmon", "detonator_agent", "litterbox", "fibratus",
                                                    "detonator")}
    r = _run_node(["updateServiceStatus", "setStatus", "updateTopbarServices"], r"""
        globalThis.state = {};
        globalThis.showToast = () => {};
        const $ = id => document.getElementById(id);
        console.log(JSON.stringify([LIVE_STATUS_JSON, ALL_ONLINE_JSON, {}].map(status => {
            updateServiceStatus(status);
            const button = $('topbar-services');
            return { sidebar: $('service-status').children.filter(item => item.classList.contains('online')).length,
                     summary: button.textContent.trim(), dot: button.children[0].className.split(' ') };
        })));
    """.replace("LIVE_STATUS_JSON", json.dumps(LIVE_STATUS)).replace("ALL_ONLINE_JSON", json.dumps(all_online)),
                  _switch_prelude())
    assert [(x["sidebar"], x["summary"]) for x in r] == [(4, "4/5 ONLINE"), (5, "5/5 ONLINE"), (0, "0/5 ONLINE")]
    assert ["partial" in r[0]["dot"], "ok" in r[1]["dot"], "down" in r[2]["dot"]] == [True] * 3


@needs_node
def test_drawer_button_counts_the_processes():
    r = _run_node(["renderProcessList", "escapeHtml", "jsArg", "procKey"], r"""
        const $ = id => document.getElementById(id);
        const counts = processes => {
            globalThis.state = { processes, selectedProcess: null };
            renderProcessList();
            return [$('process-count').textContent, $('drawer-count').textContent];
        };
        const proc = pid => ({ pid, name: 'proc' + pid, activity: {} });
        console.log(JSON.stringify([counts({ 1: proc(1), 2: proc(2), 3: proc(3) }), counts({})]));
    """, _switch_prelude())
    assert r == [["3", "3"], ["0", "0"]]


@needs_node
def test_topbar_clock_runs_with_the_dashboard_clock():
    r = _run_node(["refreshDashboard"], r"""
        globalThis.state = {};
        globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
        for (const f of ['updateServiceStatus', 'renderDashboard', 'showToast']) globalThis[f] = () => {};
        refreshDashboard().then(() => console.log(JSON.stringify(
            ['dashboard-time', 'topbar-time'].map(id => document.getElementById(id).textContent))));
    """, _switch_prelude())
    dashboard, topbar = r
    assert re.fullmatch(r"\d\d:\d\d:\d\d", topbar), topbar
    assert dashboard == "Updated " + topbar


def _without(node, drop):
    """A copy of an element tree without the elements for which drop(element) holds."""
    return {**node, "children": [_without(c, drop) for c in node["children"] if not drop(c)]}


def _has_id(*ids):
    return lambda e: e["attrs"].get("id") in ids


MISSING_PARTS = {
    "top bar": _has_id("topbar"),
    "logo row": lambda e: "logo-container" in e["attrs"].get("class", "").split(),
    "tab bar": lambda e: e["tag"] == "nav",
    "service status": _has_id("service-status"),
    "sidebar": _has_id("sidebar"),
    "theme toggles": _has_id("theme-toggle", "theme-toggle-top"),
    "drawer and drop-down parts": _has_id("drawer-toggle", "drawer-scrim", "topbar-more-wrap", "topbar-services",
                                          "topbar-services-panel"),
}


@needs_node
def test_a_missing_part_does_not_stop_the_start_up():
    """The layout runs first in DOMContentLoaded: a template without one of its
    parts must not throw there and leave the page without its other handlers."""
    failed = {}
    for name, drop in MISSING_PARTS.items():
        failed[name] = _run_node(THEME_SWITCH_FUNCTIONS + ["initTopbar", "onTopbarOutsideClick", "handleGlobalKeydown",
                                                           "closeHelp", "updateTopbarServices"], r"""
            globalThis.ResizeObserver = class {                     // as in a browser: only elements
                observe(el) { if (!(el instanceof El)) throw new TypeError('parameter 1 is not of type Element'); }
            };
            globalThis.state = { detailOpen: false };
            const steps = {
                'start-up': () => {
                    document.documentElement.dataset.theme = 'cyberpunk';
                    applyThemeLayout(currentTheme());
                    initTopbar();
                },
                'drawer': () => { toggleDrawer(); onTopbarOutsideClick({ target: document.documentElement }); },
                'drop-downs': () => { toggleTopbarMenu('topbar-services'); updateTabOverflow(); updateTopbarServices({}); },
                'Esc': () => handleGlobalKeydown({ key: 'Escape' }),
                'switch': () => { setTheme('classic'); setTheme('cyberpunk'); },
            };
            const failed = [];
            for (const [step, run] of Object.entries(steps)) {
                try { run(); } catch (e) { failed.push(`${step}: ${e.message}`); }
            }
            console.log(JSON.stringify(failed));
        """, _dom_prelude(_without(_layout_parts(), drop)))
    assert failed == {name: [] for name in MISSING_PARTS}


# --- theme-cyberpunk.css can never change Classic -----------------------------

SCOPED_SELECTOR = re.compile(r"""(?::root)?\[data-theme=(["'])cyberpunk\1\]""")
KEYFRAMES = re.compile(r"@(?:-\w+-)?keyframes\s+([\w-]+)")


def _css_blocks(css):
    """Top-level (prelude, body) pairs of a style sheet without comments; the
    body is None for a statement such as @import."""
    blocks, depth, start, i = [], 0, 0, 0
    while i < len(css):
        ch = css[i]
        if ch in "\"'":                         # strings may hold braces: content: "}"
            i += 1
            while i < len(css) and css[i] != ch:
                i += 2 if css[i] == "\\" else 1
        elif ch == "{":
            if depth == 0:
                prelude, body_start = css[start:i].strip(), i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            assert depth >= 0, "unbalanced } in the style sheet"
            if depth == 0:
                blocks.append((prelude, css[body_start:i]))
                start = i + 1
        elif ch == ";" and depth == 0:
            blocks.append((css[start:i].strip(), None))
            start = i + 1
        i += 1
    assert depth == 0, "unbalanced { in the style sheet"
    if css[start:].strip():
        blocks.append((css[start:].strip(), None))
    return blocks


def _selectors(prelude):
    """The selectors of a list, split at the commas outside (...) and [...]."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(prelude):
        depth += (ch in "([") - (ch in ")]")
        if ch == "," and depth == 0:
            parts.append(prelude[start:i].strip())
            start = i + 1
    return parts + [prelude[start:].strip()]


def _unscoped_rules(css):
    """Rules that can apply without [data-theme="cyberpunk"]: unscoped
    selectors, and every at-rule except @media/@supports (checked inside) and
    @keyframes (its contents are not selectors)."""
    found = []
    for prelude, body in _css_blocks(_strip_comments(css)):
        at_rule = re.match(r"@(?:-\w+-)?([\w-]+)", prelude)
        if not at_rule:
            found += [s for s in _selectors(prelude) if not SCOPED_SELECTOR.match(s)]
        elif at_rule.group(1).lower() in ("media", "supports") and body is not None:
            found += _unscoped_rules(body)
        elif at_rule.group(1).lower() != "keyframes" or body is None:
            found.append(prelude)
    return found


def test_cyberpunk_css_is_scoped():
    theme = _read(THEME_CSS)
    unscoped = _unscoped_rules(theme)
    assert not unscoped, "rules in theme-cyberpunk.css that also apply in Classic:\n" + "\n".join(unscoped)
    names = [set(KEYFRAMES.findall(_strip_comments(_read(p)))) for p in (THEME_CSS, STYLE_CSS)]
    assert not names[0] & names[1], f"@keyframes that replace Classic's animations: {sorted(names[0] & names[1])}"


def test_scope_check_finds_rules_that_reach_classic():
    cases = {
        ".tab { color: red; }": [".tab"],
        '[data-theme="cyberpunk"] .a, .b {}': [".b"],
        '[data-theme="classic"] .c {}': ['[data-theme="classic"] .c'],
        '@media (max-width: 1280px) { [data-theme="cyberpunk"] .d {} .e {} }': [".e"],
        "@font-face { font-family: x; }": ["@font-face"],
        '@import url("x.css");': ['@import url("x.css")'],
        'html .f, [data-theme="cyberpunk"] :is(.g, .h) {}': ["html .f"],
        '/* .x {} */ :root[data-theme="cyberpunk"] { --a: 1; } '
        "[data-theme='cyberpunk'] .i::after { content: \"}\"; } "
        "@keyframes tdc-glow { from { opacity: 0; } to { opacity: 1; } }": [],
    }
    assert {css: _unscoped_rules(css) for css in cases} == cases


# --- The internal reference site stays out of the repo --------------------------

# (length, SHA-256) of its address and of its organisation written as one
# word, in lower case. Neither may occur inside a word (letters, digits, dots)
# of any file in any case, so a form glued to other characters is found too.
# Only lengths and digests: this file must not publish them either.
REFERENCE_SITE_WORDS = {
    (11, "180715e760afec3164c55ed5f9d47eca5720ed377068efbc6b34ed5ff406d78f"),
    (7, "03780aa12d3fce990db98a13310ef8912faf00733a7d4547a60db2df771a88b8"),
}
# Its organisation as two words joined by one space: they may not follow each
# other, whatever stands between them (spaces, a line break, "-", "_", ".",
# markup) and whatever is glued to them.
REFERENCE_SITE_PHRASES = {
    (8, "c747e34b1f739812be58c4eb405183eb10989e9306a108dbe9650e67f5077b2f"),
}
# Its name, in capitals. In lower or mixed case the name is an ordinary word
# (and a first name), so only its capitals count, case-sensitive: as a word
# and inside an identifier ("MY…THEME", "…_X").
REFERENCE_SITE_CAPS = {
    (5, "723ce87fb5560c8d2e0cffad1b198cb0526fcef0a27b509c8e23be14d3e0b506"),
}
DOTTED_WORD = re.compile(rb"[a-z0-9.]+")
PLAIN_WORD = re.compile(rb"[a-z0-9]+")
CAPITALS = re.compile(rb"[A-Z]+")


def _windows(text, length):
    """Every substring of `text` that is `length` characters long."""
    return map(text.__getitem__, map(slice, range(len(text) - length + 1), range(length, len(text) + 1)))


def _stored_in(texts, stored):
    """The (length, digest) pairs of `stored` that are a substring of one of `texts`."""
    found = set()
    for length in {n for n, _ in stored}:
        windows = set()
        for text in texts:
            windows.update(_windows(text, length))
        found |= {(length, hashlib.sha256(w).hexdigest()) for w in windows} & stored
    return found


def _reference_hits(data, words=REFERENCE_SITE_WORDS, phrases=REFERENCE_SITE_PHRASES, caps=REFERENCE_SITE_CAPS):
    """The stored forms that occur in the bytes `data`: words and phrases in
    any case, glued to other characters, with defanged dots ("[.]"); the
    capitals as written, inside any run of capital letters."""
    hits = _stored_in(set(CAPITALS.findall(data)), caps)
    data = data.lower().replace(b"[.]", b".")
    hits |= _stored_in(set(DOTTED_WORD.findall(data)), words)
    if phrases:
        # A phrase lies in the end of one word, one space and the start of the next one
        span = max(n for n, _ in phrases) - 2
        tokens = PLAIN_WORD.findall(data)
        hits |= _stored_in({a[-span:] + b" " + b[:span] for a, b in zip(tokens, tokens[1:])}, phrases)
    return hits


def _repo_texts():
    """Path and content of every text file git tracks or would add (untracked,
    not ignored)."""
    listed = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            cwd=ROOT, capture_output=True, check=True).stdout
    for path in sorted({os.fsdecode(p) for p in listed.split(b"\0") if p}):
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full):            # deleted, not staged yet
            continue
        data = open(full, "rb").read()
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):      # UTF-16 text (PowerShell, .reg)
            data = data.decode("utf-16", "replace").encode()
        elif b"\0" in data:                     # images and other binary files
            continue
        yield path, data


def test_no_reference_site_names():
    if not os.path.exists(os.path.join(ROOT, ".git")):
        pytest.skip("not a git checkout: the files to scan come from git ls-files")
    hits = []
    for path, data in _repo_texts():
        if not _reference_hits(data):
            continue
        # Where, but not what: the message must not publish the strings (CI logs)
        lines = [str(n) for n, line in enumerate(data.splitlines(), 1) if _reference_hits(line)]
        hits.append(f"{path}: line {', '.join(lines)}" if lines else f"{path}: across a line break")
    assert not hits, "name or address of the internal reference site in the repo:\n" + "\n".join(hits)


def test_reference_site_check_finds_glued_and_separated_forms():
    """The check with made-up strings: an address and an organisation (as one
    word and as two words) in any case, and a name that is also an ordinary
    word, so only its capitals count."""
    def stored(*forms):
        return {(len(f), hashlib.sha256(f.encode()).hexdigest()) for f in forms}

    words, phrases, caps = stored("relay.example.test", "acmecorp"), stored("acme corp"), stored("ZORBO")

    def found(text):
        return bool(_reference_hits(text.encode(), words, phrases, caps))

    for text in ["see relay.example.test.", "HTTPS://RELAY.EXAMPLE.TEST/x", "xrelay.example.testy",
                 "relay[.]example[.]test", "mail.relay.example.test", "ACME CORP", "acme-corp", "acme_corp",
                 "acme\n   corp", "**Acme** Corp", "acme.corp", "AcmeCorp", "theacme corps",
                 "ZORBO", "see ZORBO.", "MYZORBOTHEME", "ZORBO_X", "(ZORBO)", "ZORBO's", "applyZORBOTheme",
                 "ZORBO2"]:
        assert found(text), text
    for text in ["zorbo", "Zorbo", "zOrBo", "(zorbo)", "myzorbotheme", "applyZorboTheme", "Zorbo's", "ZORB",
                 "ORBO", "ZOR-BO", "ZOR BO", "zor bot", "relay-example-test", "relay.example.tes", "corp acme",
                 "acme x corp", "acme", "corp", ""]:
        assert not found(text), text


# --- Alerts tab ----------------------------------------------------------------

ALERT_FUNCTIONS = ["alertSeverity", "alertRuleName", "alertProcessName", "alertCategory", "filterAlerts",
                   "_alertsTimeBound", "_alertsNameKey", "_alertNameIs"]
ALERT_ROW_FUNCTIONS = ALERT_FUNCTIONS + ["alertRowsHtml", "alertInstanceIndex", "_alertInstanceId", "formatAlertTime",
                                         "escapeHtml", "jsArg", "cssToken", "procKey", "sortTimeValue",
                                         "severitySortValue"]
# The building blocks of the charts (block CHARTS of app.js) and their constants
CHART_CONSTS = ["SEVERITY_ORDER", "SEVERITY_COLORS", "CHART_PALETTE", "CHART_MONTHS", "CHART_MAX_BINS"]
CHART_FUNCTIONS = ["alertCategory", "countBy", "binByTime", "stackedBarsSvg", "donutSvg", "pieSvg", "chartLegendHtml",
                   "sparklineSvg", "scatterSvg", "verdictBarsSvg", "chartEmptyHtml", "_chartSentence", "_chartColor",
                   "_chartNumber", "_chartShare", "_chartCoord", "_chartSegments", "_chartPeriodStart", "_chartPeriodNext",
                   "_chartDate", "_chartClock", "_chartPeriodLabel", "_chartTicks", "_chartFineStep",
                   "topWithOther", "alertFlow", "_chartFlow", "layoutSankey", "sankeySvg", "_sankeyFit", "_chartEllipsis"]
# The charts of the Alerts tab above its filter bar, the parts the dashboard and the Sysmon tab share with them, and
# the CHART / TABLE switch of their cards
ALERTS_CHART_FUNCTIONS = ["renderAlertsCharts", "alertsSeverityItems", "_alertsSeverityColor", "alertsEngineItems",
                          "_drawAlertsPie", "_drawShareChart", "_alertsShareTableHtml", "chartTimeBins",
                          "alertSeverityBins", "_alertsTimeNote", "_alertsTimeBarsSvg", "_drawAlertsTime",
                          "_timeBinsTableHtml", "_alertsTimeTableHtml", "_drawAlertsFlow", "_flowTableHtml",
                          "_alertsFlowTableHtml", "_alertsFlowColors", "_alertsFlowFilter", "_flowInert",
                          "_flowClickFilter", "_alertsChartWidths",
                          "_alertsChartInert", "onAlertsChartClick", "_applyAlertsChartFilter", "toggleAlertsFlowScale",
                          "_pressFlowScale", "redrawAlertsChartsOnResize", "isTableView", "viewToggleHtml",
                          "cardViewAttrs", "toggleCardView"]
# The tab with the chips of the chart filters, which name a time range as the charts do (block CHARTS), and its charts
ALERTS_TAB_FUNCTIONS = list(dict.fromkeys(ALERT_ROW_FUNCTIONS + [
    "alertEngines", "setAlertsEngineOptions", "alertsFilterFromControls", "renderAlertsTab", "toggleAlertsSeverity",
    "selectAlertsSeverity", "openAlertsTab", "setAlertsFilters", "removeAlertsFilter", "renderAlertsActiveFilters",
    "filterChipHtml", "_alertsExtraOf", "_alertsListTop", "_tabListTop", "chartRangeLabel"] + CHART_FUNCTIONS
    + ALERTS_CHART_FUNCTIONS))
# The state of the Alerts tab and its charts (app.js top level) for the functions under test
ALERTS_TAB_CONSTS = ["ALERT_SEVERITIES", "ALERT_TIME_MIN", "alertsExtraFilter", "cardViewState",
                     "alertsFlowView"] + CHART_CONSTS
ALERTS_TAB_LETS = "\nlet _alertsTabShown = null;\nlet _alertsChartsDrawn = null;"
# The charts of the dashboard between its tiles and its service cards, and their state
DASHBOARD_CHART_FUNCTIONS = ["renderDashboardCharts", "setDashboardRange", "_dashboardCount",
                             "_dashboardFollowTheClock", "_dashboardSparkCounts", "dashboardCategoryItems",
                             "releaseDashboardCounts", "_drawDashboardSparks", "_drawDashboardBars",
                             "_drawDashboardDonuts", "_drawDashboardRange", "_dashboardBarsSize",
                             "onDashboardChartClick", "_dashboardBinPeriod", "initDashboardCharts", "onDashboardBrushStart",
                             "onDashboardBrushMove", "onDashboardBrushEnd", "onDashboardBrushCancel", "_dashboardBrushStop",
                             "_dashboardBrushMark", "_dashboardBinAt", "redrawDashboardChartsOnResize"]
DASHBOARD_CHART_CONSTS = ["DASHBOARD_RANGES", "DASHBOARD_SPARK_DAYS", "dashboardRange", "dashboardBarsRange",
                          "_dashboardMemo", "_dashboardDrawn"]
DASHBOARD_CHART_LETS = "\nlet _dashboardBrush = null;\nlet _dashboardReleased = null;"

# Four alerts as the engines write them: severity and engine in either case,
# the process by name, by image only or by PID only, time zones mixed (as a
# string "12:30:00+01:00" sorts after "12:00:00Z", as a time it is earlier).
ALERT_FIXTURE = r"""
    const alerts = [
        { id: 'a1', timestamp: '2026-11-09T10:00:00Z', severity: 'Critical', engine: 'Sigma',
          rule_name: 'Credential dump', process_name: 'lsass.exe', pid: 700, rule_description: 'LSASS memory read' },
        { id: 'a2', timestamp: '2026-11-09T12:30:00+01:00', severity: 'high', engine: 'Yara',
          rule_name: 'CobaltStrike beacon', process_name: '', process_image: 'C:\\Users\\a\\beacon.exe', pid: 4242,
          rule_description: 'In-memory implant' },
        { id: 'a3', timestamp: '2026-11-09T09:00:00.1234567Z', severity: 'low', engine: 'fibratus',
          rule_name: 'DPAPI access', process_name: '', process_image: '', pid: 2132, rule_description: 'Master keys read' },
        { id: 'a4', timestamp: '2026-11-09T12:00:00Z', severity: 'Medium', engine: 'sigma',
          rule_name: 'Mimikatz', process_name: 'm.exe', pid: 1337, rule_description: 'Known tool' },
    ];
"""


def _alerts_prelude():
    return "\n".join(_const_source(c) for c in ["ALERTS_TAB_LIMIT"] + ALERTS_TAB_CONSTS) + ALERTS_TAB_LETS


@needs_node
def test_filter_alerts():
    r = _run_node(ALERT_FUNCTIONS, ALERT_FIXTURE + r"""
        const order = alerts.map(a => a.id).join();
        filterAlerts(alerts, {});
        const unchanged = alerts.map(a => a.id).join() === order;
        const ids = filter => filterAlerts(alerts, filter).map(a => a.id);
        const extra = [...alerts, { id: 'a5', timestamp: 'not a time', engine: 'Sigma', rule_name: 'No severity' }];
        // The server writes "unknown" for engines that have no severity
        const unknown = [...extra, { id: 'a6', timestamp: '2026-11-09T08:00:00Z', severity: 'Unknown', engine: 'Yara',
                                     rule_name: 'Engine without severity' }];
        console.log(JSON.stringify({
            brief: [ids({ severities: ['critical', 'high'] }), ids({ engine: 'sigma' }), ids({ text: 'mimi' }), ids({})],
            empty: ids({ severities: [], engine: '', text: '' }), blank: ids({ text: '   ' }), none: ids(undefined),
            upper: [ids({ severities: ['CRITICAL'] }), ids({ engine: 'YARA' }), ids({ text: 'MIMI' })],
            fields: [ids({ text: 'beacon.exe' }), ids({ text: 'master keys' }), ids({ text: '2132' }), ids({ text: 'lsass.exe' })],
            combined: ids({ severities: ['medium', 'critical'], engine: 'Sigma', text: 'dump' }),
            info: filterAlerts(extra, { severities: ['info'] }).map(a => a.id),
            unknownIsInfo: [filterAlerts(unknown, { severities: ['info'] }).map(a => a.id),
                            filterAlerts(unknown, { severities: ['low'] }).map(a => a.id), alertSeverity(unknown[5])],
            invalidTimeLast: filterAlerts(extra, {}).map(a => a.id),
            unchanged,
        }));
    """)
    # The brief: two of critical/high, two Sigma (either case), one Mimikatz; all four newest first
    assert r["brief"] == [["a2", "a1"], ["a4", "a1"], ["a4"], ["a4", "a2", "a1", "a3"]]
    assert r["empty"] == r["blank"] == r["none"] == ["a4", "a2", "a1", "a3"], "an empty filter hides alerts"
    assert r["upper"] == [["a1"], ["a2"], ["a4"]], "filter values are compared case-sensitively"
    # The text is searched in the process (image name, PID) and the description as well
    assert r["fields"] == [["a2"], ["a3"], ["a3"], ["a1"]]
    assert r["combined"] == ["a1"]
    assert r["info"] == ["a5"], "an alert without severity does not count as info"
    assert r["unknownIsInfo"] == [["a6", "a5"], ["a3"], "info"], "severity unknown (server default) does not count as info"
    assert r["invalidTimeLast"] == ["a4", "a2", "a1", "a3", "a5"]
    assert r["unchanged"], "filterAlerts sorted state.alerts in place"


@needs_node
def test_alert_rows_escape_hostile_values():
    """Every value of an alert comes from a sample or a rule: none may reach
    the markup as markup or leave its attribute or handler."""
    r = _run_node(ALERT_ROW_FUNCTIONS, r"""
        const name = '"><svg onload=alert(2)>' + 'x'.repeat(277);
        const hostile = { id: 'x");alert(3)//', timestamp: '2026-11-09T10:00:00Z<b>', severity: 'high" onmouseover="x',
                          engine: '<b>sigma</b>', rule_name: '<img src=x onerror=alert(1)>', pid: '4242',
                          rule_description: '<script>alert(4)</script>', process_name: name, process_image: 'C:\\' + name };
        globalThis.state = { processes: { '4242': { pid: '4242', key: '4242',
            alerts: [{ timestamp: hostile.timestamp, rule_name: hostile.rule_name }] } } };
        const html = alertRowsHtml([hostile]);
        // Run every inline handler as the browser would (attribute value unescaped)
        const calls = [];
        globalThis.openAlertDetailById = id => calls.push(['alert', id]);
        globalThis.openProcessDetail = key => calls.push(['process', key]);
        globalThis.alert = x => calls.push(['injected', x]);
        const unescape = s => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<')
                               .replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        for (const m of html.matchAll(/\son\w+="([^"]*)"/g))
            new Function('event', unescape(m[1]))({ stopPropagation: () => calls.push(['stop']) });
        console.log(JSON.stringify({ html, calls, length: name.length, name: escapeHtml(name),
                                     classes: [...html.matchAll(/class="([^"]*)"/g)].map(m => m[1]),
                                     titles: [...html.matchAll(/title="([^"]*)"/g)].map(m => m[1]) }));
    """, _alerts_prelude())
    html = r["html"]
    assert r["length"] == 300
    for raw in ("<img", "<svg", "<script", "<b>", "onmouseover="):
        assert raw not in html, f"{raw} reached the markup"
    assert r["calls"] == [["alert", 'x");alert(3)//'], ["stop"], ["process", "4242"]], \
        "a handler ran injected code, or the process link also opens the alert"
    assert all(re.fullmatch(r"[a-z0-9_ -]*", c) for c in r["classes"]), r["classes"]
    assert html.count(r["name"]) == 2, "the process name is not escaped (text and title)"
    # Long texts are cut by CSS; the title keeps the full text, escaped
    assert "&lt;img src=x onerror=alert(1)&gt;" in r["titles"]
    assert "&lt;script&gt;alert(4)&lt;/script&gt;" in r["titles"]


def test_alerts_table_cuts_long_values_with_an_ellipsis():
    """A 300-character rule or process name must not widen the table: the
    layout is fixed and every cell stays on one line, cut with an ellipsis."""
    rules = {}
    for prelude, body in _css_blocks(_strip_comments(_read(STYLE_CSS))):
        for selector in (_selectors(prelude) if body else []):
            rules[selector] = rules.get(selector, "") + body
    assert re.search(r"table-layout:\s*fixed", rules.get(".alerts-table", "")), "the table grows with its content"
    cell = rules.get(".alerts-table td", "")
    for declaration in (r"white-space:\s*nowrap", r"overflow:\s*hidden", r"text-overflow:\s*ellipsis"):
        assert re.search(declaration, cell), f".alerts-table td lacks {declaration}"


def test_alerts_tab_is_wired():
    html = _read(INDEX_HTML)
    nav = re.search(r'<nav class="sidebar-tabs">(.*?)</nav>', html, re.S).group(1)
    tabs = re.findall(r'data-tab="([^"]+)"', nav)
    assert tabs.index("alerts") == tabs.index("dashboard") + 1, tabs
    assert 'id="tab-alerts"' in html and 'id="alerts-table"' in html
    tab = _Elements(html).by_id("tab-alerts")

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    header = find(tab, lambda e: "content-header" in e["attrs"].get("class", "").split())
    assert header and find(header[0], lambda e: e["tag"] == "h2") and \
        find(header[0], lambda e: "content-subtitle" in e["attrs"].get("class", "").split())
    table = find(tab, lambda e: e["attrs"].get("id") == "alerts-table")
    assert table and table[0]["tag"] == "table"
    assert "data-sortable" in table[0]["attrs"] and table[0]["attrs"].get("data-sort-id") == "alerts"
    chips = find(tab, lambda e: "alerts-sev-chip" in e["attrs"].get("class", "").split())
    assert [c["attrs"].get("data-severity") for c in chips] == ["critical", "high", "medium", "low", "info"]
    assert all(c["tag"] == "button" and c["attrs"].get("aria-pressed") == "false" for c in chips)
    for part in ("alerts-filter-engine", "alerts-filter-text", "alerts-count", "alerts-rows", "alerts-table-wrap"):
        assert find(tab, lambda e, part=part: e["attrs"].get("id") == part), part
    # The chips of the chart filters: in the filter bar, which stands at the top, hidden while there are none
    bar = find(tab, lambda e: "alerts-filters" in e["attrs"].get("class", "").split())
    chips = find(bar[0], lambda e: e["attrs"].get("id") == "alerts-active-filters") if bar else []
    assert chips and "hidden" in chips[0]["attrs"] and chips[0]["attrs"].get("role") == "group" \
        and chips[0]["attrs"].get("aria-label"), "the chips of the chart filters are not in the filter bar"
    engine = find(tab, lambda e: e["attrs"].get("id") == "alerts-filter-engine")[0]
    assert engine["tag"] == "select" and engine["attrs"].get("onchange") == "renderAlertsTab()", \
        "choosing an engine does not filter"
    search = find(tab, lambda e: e["attrs"].get("id") == "alerts-filter-text")[0]
    assert search["attrs"].get("oninput") == "scheduleAlertsRender()", "every keystroke lays out 2000 rows"
    assert re.search(r"tabName === 'alerts'\)\s*\{\s*renderAlertsTab\(\)", _function_source("switchTab"))


@needs_node
def test_the_alerts_search_renders_once_typing_pauses():
    """A full table takes about 0.1 s to lay out: a render per keystroke
    makes the typing lag."""
    r = _run_node(["scheduleAlertsRender"], r"""
        let renders = 0;
        globalThis.renderAlertsTab = () => renders++;
        scheduleAlertsRender(); scheduleAlertsRender(); scheduleAlertsRender();
        const typing = renders;
        setTimeout(() => console.log(JSON.stringify([typing, renders])), 500);
    """, "let _alertsRenderTimer = null;")
    assert r == [0, 1]


@needs_node
def test_alert_rows_show_at_most_the_newest_2000():
    r = _run_node(ALERT_ROW_FUNCTIONS, r"""
        globalThis.state = { processes: {} };
        const list = n => Array.from({ length: n }, (_, i) => ({ id: 'a' + i, severity: 'high', engine: 'Sigma',
            timestamp: new Date(Date.UTC(2026, 10, 9) - i * 1000).toISOString(), rule_name: 'r' + i, pid: i + 1 }));
        const ids = html => [...html.matchAll(/<tr class="alerts-row" onclick="openAlertDetailById\(&quot;(a\d+)&quot;\)/g)]
            .map(m => m[1]);
        const capped = alertRowsHtml(list(2001)), full = alertRowsHtml(list(2000));
        console.log(JSON.stringify({ capped: ids(capped).length, first: ids(capped)[0], last: ids(capped).pop(),
            full: ids(full).length, note: /Showing newest 2000 of 2001/.test(capped), fullNote: /Showing newest/.test(full) }));
    """, _alerts_prelude())
    assert r == {"capped": 2000, "first": "a0", "last": "a1999", "full": 2000, "note": True, "fullNote": False}


@needs_node
def test_alert_rows_link_each_alert_to_its_process_instance():
    """Windows reuses PIDs. An alert links the process instance it belongs to
    (the process list names the alerts of each instance), not the newest
    process with its PID; a process that is not in the list is no link."""
    r = _run_node(ALERT_ROW_FUNCTIONS, r"""
        const older = { timestamp: '2026-07-14T12:27:35Z', rule_name: 'Old rule' };
        const newer = { timestamp: '2026-11-09T07:43:18.1735023+01:00', rule_name: 'New rule' };
        globalThis.state = { processes: {
            '2132@1784032055': { pid: '2132', key: '2132@1784032055', name: 'svchost.exe', alerts: [older] },
            '2132': { pid: '2132', key: '2132', name: 'cmd.exe', alerts: [newer] },
        } };
        const row = alert => alertRowsHtml([{ id: 'x', severity: 'high', engine: 'Sigma', pid: 2132, ...alert }]);
        const links = html => [...html.matchAll(/openProcessDetail\(([^)]*)\)/g)].map(m => JSON.parse(m[1].replace(/&quot;/g, '"')));
        const shown = html => html.match(/<td class="alerts-proc"[^>]*>(.*?)<\/td>/)[1].replace(/<[^>]+>/g, '');
        const title = html => html.match(/<td class="alerts-proc"[^>]*><[^>]*\stitle="([^"]*)"/)[1];
        console.log(JSON.stringify({
            older: links(row({ ...older, process_name: 'svchost.exe' })),
            newer: links(row({ ...newer, process_name: 'cmd.exe' })),
            notListed: links(row({ timestamp: '2026-08-01T00:00:00Z', rule_name: 'Elsewhere', process_name: 'x.exe' })),
            ownKey: links(row({ key: '2132@1784032055', timestamp: '2026-08-01T00:00:00Z', rule_name: 'Elsewhere' })),
            names: [row({ ...older, process_name: 'svchost.exe' }),
                    row({ ...older, process_name: '', process_image: 'C:\\Windows\\System32\\svchost.exe' }),
                    row({ ...older, process_name: '', process_image: '' }),
                    row({ ...older, process_name: '', process_image: '', pid: '' })].map(shown),
            titles: [row({ ...older, process_name: 'svchost.exe', process_image: 'C:\\Windows\\svchost.exe' }),
                     row({ ...newer, process_name: 'cmd.exe' }),
                     row({ timestamp: '2026-08-01T00:00:00Z', rule_name: 'Elsewhere', process_name: 'x.exe' }),
                     row({ timestamp: '2026-08-01T00:00:00Z', rule_name: 'Elsewhere', process_name: '', pid: '' }),
                    ].map(html => /<td class="alerts-proc"><span class="muted">/.test(html) ? null : title(html)),
        }));
    """, _alerts_prelude())
    assert r["older"] == ["2132@1784032055"], "the alert links the newest process with its PID"
    assert r["newer"] == ["2132"]
    assert r["notListed"] == [], "a process that is not in the process list is a link"
    assert r["ownKey"] == ["2132@1784032055"]
    assert r["names"] == ["svchost.exe 2132", "svchost.exe 2132", "PID 2132", "&mdash;"]
    # The title names the PID as well: the instance of a link, or that the process is not listed
    assert r["titles"] == ["C:\\Windows\\svchost.exe · PID 2132 · instance 2132@1784032055", "cmd.exe · PID 2132",
                           "x.exe · PID 2132 (not in the process list)", None]


@needs_node
def test_alert_engines_are_offered_once_in_their_first_spelling():
    r = _run_node(["alertEngines"], r"""
        console.log(JSON.stringify(alertEngines([{ engine: 'Sigma' }, { engine: 'sigma' }, { engine: 'Yara' },
            { engine: 'fibratus' }, { engine: '' }, {}, null, { engine: 'SIGMA' }, { engine: 'yara' }])));
    """)
    assert r == ["fibratus", "Sigma", "Yara"]


def _alerts_tab_prelude():
    tab = _Elements(_read(INDEX_HTML)).by_id("tab-alerts")
    assert tab, "#tab-alerts missing in index.html"
    return _alerts_prelude() + _dom_prelude({"tag": "div", "attrs": {"id": "app"}, "children": [tab]})


@needs_node
def test_open_alerts_tab_sets_its_filters_and_a_refresh_keeps_them():
    """The tab scrolls as a whole. A refresh with the same filters keeps the
    place in the list; other filters start at the top of the list: its first
    row right under the filter bar standing at the top of the tab, so the bar
    does not move away under the pointer (above that, nothing moves)."""
    r = _run_node(ALERTS_TAB_FUNCTIONS, ALERT_FIXTURE + r"""
        globalThis.state = { alerts, processes: {}, activeTab: 'dashboard' };
        globalThis.switchTab = name => { state.activeTab = name; if (name === 'alerts') renderAlertsTab(); };
        const $ = id => document.getElementById(id);
        // The layout: the tab 56 px below the top of the window, its head 50 px
        // high, then the filter bar (40 px; it stands at the top of the tab once
        // the head has scrolled away), then the table
        const tab = $('tab-alerts'), bar = document.querySelector('#tab-alerts .alerts-filters');
        tab.scrollTop = 0;
        tab.getBoundingClientRect = () => ({ top: 56, width: 0 });
        bar.getBoundingClientRect = () => ({ top: 56 + Math.max(0, 50 - tab.scrollTop), height: 40, width: 0 });
        $('alerts-table-wrap').getBoundingClientRect = () => ({ top: 56 + 90 - tab.scrollTop, width: 0 });
        let builds = 0;
        const rows = $('alerts-rows');
        const html = Object.getOwnPropertyDescriptor(El.prototype, 'innerHTML');
        Object.defineProperty(rows, 'innerHTML', { set(v) { builds++; html.set.call(this, v); } });
        const view = () => ({
            pressed: document.querySelectorAll('#tab-alerts .alerts-sev-chip')
                .filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.dataset.severity),
            engine: $('alerts-filter-engine').value, engines: $('alerts-filter-engine').children.map(o => o.value),
            text: $('alerts-filter-text').value || '',
            ids: [...rows.html.matchAll(/openAlertDetailById\(&quot;(\w+)&quot;\)/g)].map(m => m[1]),
            count: $('alerts-count').textContent, tab: state.activeTab, scroll: tab.scrollTop,
            // Where the list begins, from the top of the tab
            list: $('alerts-table-wrap').getBoundingClientRect().top - tab.getBoundingClientRect().top,
        });
        const r = {};
        openAlertsTab({ severities: ['critical', 'High'], engine: 'yara', text: '' }); r.preset = view();
        openAlertsTab({}); r.all = view();
        builds = 0; renderAlertsTab(); renderAlertsTab(); r.unchangedBuilds = builds;
        tab.scrollTop = 480;
        state.alerts = [{ id: 'a5', timestamp: '2026-11-09T13:00:00Z', severity: 'High', engine: 'IOC', rule_name: 'New' },
                        ...alerts];
        renderAlertsTab(); r.refreshed = view();
        click(document.querySelector('.alerts-sev-chip[data-severity="medium"]')); r.medium = view();
        tab.scrollTop = 30;
        $('alerts-filter-text').value = 'mimi'; renderAlertsTab(); r.text = view();
        click(document.querySelector('.alerts-sev-chip[data-severity="medium"]')); r.unpressed = view();
        // A chart filter is another filter as well
        tab.scrollTop = 480; setAlertsFilters({ rule: 'mimikatz' }); r.chart = view();
        openAlertsTab({ engine: 'etw' }); r.unknownEngine = { ...view(), empty: /No alerts match/.test(rows.html) };
        state.alerts = []; renderAlertsTab(); r.noAlerts = { ...view(), empty: /No alerts yet/.test(rows.html) };
        console.log(JSON.stringify(r));
    """, _alerts_tab_prelude())
    assert r["preset"] == {"pressed": ["critical", "high"], "engine": "Yara", "engines": ["", "fibratus", "Sigma", "Yara"],
                           "text": "", "ids": ["a2"], "count": "1 of 4", "tab": "alerts", "scroll": 0, "list": 90}
    assert r["all"] == {**r["preset"], "pressed": [], "engine": "", "ids": ["a4", "a2", "a1", "a3"], "count": "4 of 4"}
    assert r["unchangedBuilds"] == 0, "the list is rebuilt although nothing changed"
    # New data with the same filters: the place in the list stays, the new engine is offered
    assert r["refreshed"]["ids"] == ["a5", "a4", "a2", "a1", "a3"] and r["refreshed"]["count"] == "5 of 5"
    assert r["refreshed"]["scroll"] == 480 and r["refreshed"]["engines"] == ["", "fibratus", "IOC", "Sigma", "Yara"]
    # Other filters start at the top of the list: the head scrolled away, the first row right under the bar
    assert (r["medium"]["pressed"], r["medium"]["ids"], r["medium"]["count"]) == (["medium"], ["a4"], "1 of 5")
    assert (r["medium"]["scroll"], r["medium"]["list"]) == (50, 40), "other filters do not start at the top of the list"
    # ... and where the list starts below the bar anyway, nothing moves
    assert (r["text"]["ids"], r["text"]["text"], r["text"]["scroll"]) == (["a4"], "mimi", 30)
    assert (r["unpressed"]["pressed"], r["unpressed"]["ids"]) == ([], ["a4"])
    assert (r["chart"]["ids"], r["chart"]["scroll"]) == (["a4"], 50), "a chart's filter does not start the list at the top"
    # An engine without alerts stays chosen (a tile may ask for it before alerts arrive)
    assert r["unknownEngine"]["engine"] == "etw" and "etw" in r["unknownEngine"]["engines"]
    assert (r["unknownEngine"]["ids"], r["unknownEngine"]["count"], r["unknownEngine"]["empty"]) == ([], "0 of 5", True)
    assert r["unknownEngine"]["text"] == "" and r["unknownEngine"]["pressed"] == []
    assert (r["noAlerts"]["count"], r["noAlerts"]["empty"]) == ("0 of 0", True)


@needs_node
def test_a_refresh_re_renders_the_alerts_tab_only_while_it_is_open():
    """After new alerts (not a 304) and after the process list that resolves
    their process instances; never while another tab is open. A refresh while
    the tab is closed lets go of the lists the table was built from (tens of
    MB) and keeps only its filters. The dashboard, while it is open, renders
    the new alerts (its tiles and charts) as well; while it is hidden, it
    lets go of the lists it counted, as the table does."""
    r = _run_node(["_refreshAlertsOnce"], r"""
        const log = [];
        for (const f of ['showToast', 'indexAlerts', 'renderTimeline', 'renderRtraceConsole']) globalThis[f] = () => {};
        globalThis.refreshProcesses = async () => { log.push('processes'); };
        globalThis.renderAlertsTab = () => log.push('render');
        globalThis.renderDashboard = () => log.push('dashboard');
        globalThis.releaseDashboardCounts = () => log.push('release');
        const reply = status => async () => ({ status, ok: status === 200, headers: { get: () => '"v2"' },
                                               json: async () => [{ id: 'a', timestamp: '2026-11-09T10:00:00Z' }] });
        (async () => {
            const r = [], shown = [];
            for (const [tab, status] of [['alerts', 200], ['alerts', 304], ['dashboard', 200], ['alerts', 500],
                                         ['dashboard', 304]]) {
                globalThis.state = { alerts: [], activeTab: tab, alertsEtag: '"v1"' };
                _alertsTabShown = { alerts: state.alerts, processes: {}, filterKey: '[["high"],"",""]' };
                globalThis.fetch = reply(status);
                log.length = 0;
                await _refreshAlertsOnce();
                r.push(log.join(' '));
                shown.push([...Object.keys(_alertsTabShown).sort(), _alertsTabShown.filterKey]);
            }
            console.log(JSON.stringify({ r, shown }));
        })();
    """, "let _alertsTabShown = null;")
    assert r["r"] == ["processes render release", "", "processes dashboard", "", ""], \
        "the hidden dashboard keeps the old lists, or the open one does not render the new alerts"
    kept, filters = ["alerts", "filterKey", "processes", '[["high"],"",""]'], ["filterKey", '[["high"],"",""]']
    assert r["shown"] == [kept, kept, filters, kept, kept], "a refresh with the tab closed keeps the old alert list alive"


# --- (i) explanations and sortable tables ---------------------------------------

SORT_FUNCTIONS = ["sortKey", "compareSortKeys", "compareSortValues", "sortCellAt", "sortCellValue", "isSortPinnedRow",
                  "sortRows"]
TABLE_FUNCTIONS = SORT_FUNCTIONS + ["sortHeaderRow", "isSortHeader", "sortColumnOf", "applyTableSort",
                                    "reapplyTableSorts", "sortTableBy", "sortHeaderFrom", "onSortHeaderClick",
                                    "onSortHeaderKey"]
INFO_FUNCTIONS = ["initInfoButtons", "infoPopoverPosition", "isInfoPopoverOpen", "openInfoPopover", "closeInfoPopover",
                  "onInfoClick", "onInfoAnchorScroll"]
CONTROL_FUNCTIONS = TABLE_FUNCTIONS + INFO_FUNCTIONS + ["onCardControlsMutated", "initCardControls"]

# Just enough DOM for the tables and the (i) buttons: element trees parsed from
# the markup the render functions write (innerHTML) or from index.html, text
# nodes in their order, the table API (tHead, tBodies, rows, cells, rowSpan,
# colSpan), and a MutationObserver that reports childList changes in a
# microtask, as the browser does (a change made in its callback and taken off
# with takeRecords() is not reported again). click() delivers an event as the
# browser does: the document's capture listeners, then the inline handlers
# and listeners from the target up, then the document's other listeners.
SORT_DOM = r"""
process.env.TZ = 'UTC';
const VOID_TAGS = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source',
                           'track', 'wbr']);
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', mdash: '\u2014', ndash: '\u2013',
                   rarr: '\u2192', larr: '\u2190', middot: '\u00b7', times: '\u00d7', minus: '\u2212',
                   hellip: '\u2026' };
const decodeEntities = s => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => e[0] !== '#' ? (ENTITIES[e] ?? m)
    : String.fromCodePoint(/^#x/i.test(e) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)));
const observers = [];
function queueRecord(target, addedNodes, removedNodes) {
    if (!addedNodes.length && !removedNodes.length) return;
    for (const o of observers) {
        if (!o.root || !o.root.contains(target)) continue;
        o.queue.push({ type: 'childList', target, addedNodes, removedNodes });
        if (!o.pending) { o.pending = true; queueMicrotask(() => o.deliver()); }
    }
}
class FakeMutationObserver {
    constructor(callback) { Object.assign(this, { callback, queue: [], root: null, pending: false, deliveries: 0 }); }
    observe(root, options) { this.root = root; this.options = options; observers.push(this); }
    takeRecords() { return this.queue.splice(0); }
    deliver() {
        this.pending = false;
        const records = this.queue.splice(0);
        if (records.length) { this.deliveries++; this.callback(records, this); }
    }
}
class Node {
    constructor(nodeType) { this.nodeType = nodeType; this.parentNode = null; this.childNodes = []; }
    get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
    get children() { return this.childNodes.filter(n => n.nodeType === 1); }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get nextElementSibling() {
        const siblings = this.parentNode ? this.parentNode.childNodes : [];
        return siblings.slice(siblings.indexOf(this) + 1).find(n => n.nodeType === 1) || null;
    }
    get textContent() { return this.childNodes.map(n => n.textContent).join(''); }
    set textContent(v) { this.replaceChildren(...(String(v) ? [new Text(String(v))] : [])); }
    contains(n) { for (let e = n; e; e = e.parentNode) if (e === this) return true; return false; }
    get isConnected() { return document.documentElement.contains(this); }
    insertBefore(node, ref) {
        const nodes = node.nodeType === 11 ? node.childNodes.splice(0) : [node];
        nodes.forEach(n => { if (n.parentNode && n.parentNode !== node) n.parentNode.removeChild(n); });
        const at = ref ? this.childNodes.indexOf(ref) : this.childNodes.length;
        this.childNodes.splice(at, 0, ...nodes);
        nodes.forEach(n => { n.parentNode = this; });
        queueRecord(this, nodes, []);
        return node;
    }
    appendChild(node) { return this.insertBefore(node, null); }
    append(...nodes) { nodes.forEach(n => this.appendChild(typeof n === 'string' ? new Text(n) : n)); }
    removeChild(node) {
        const i = this.childNodes.indexOf(node);
        if (i >= 0) { this.childNodes.splice(i, 1); node.parentNode = null; queueRecord(this, [], [node]); }
        return node;
    }
    remove() { if (this.parentNode) this.parentNode.removeChild(this); }
    replaceChildren(...nodes) {
        nodes = nodes.map(n => typeof n === 'string' ? new Text(n) : n);
        nodes.forEach(n => { if (n.parentNode) n.parentNode.removeChild(n); });
        const removed = this.childNodes.splice(0);
        removed.forEach(n => { n.parentNode = null; });
        this.childNodes = nodes;
        nodes.forEach(n => { n.parentNode = this; });
        queueRecord(this, nodes, removed);
    }
    *walk() { for (const c of this.children) { yield c; yield* c.walk(); } }
    querySelectorAll(selector) { return [...this.walk()].filter(e => e.matches(selector)); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
class Text extends Node {
    constructor(data) { super(3); this.data = data; }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
}
class Fragment extends Node { constructor() { super(11); } }
function matchesCompound(el, compound) {
    const m = /^(\*|[a-z][\w-]*)?((?:[.#][\w-]+|\[[\w-]+(?:="[^"]*")?\])*)$/i.exec(compound);
    if (!m) throw new Error('selector not supported by the test DOM: ' + compound);
    if (m[1] && m[1] !== '*' && m[1].toUpperCase() !== el.tagName) return false;
    return (m[2].match(/[.#][\w-]+|\[[^\]]+\]/g) || []).every(p => {
        if (p[0] === '.') return el.classList.contains(p.slice(1));
        if (p[0] === '#') return el.id === p.slice(1);
        const [, name, value] = /^\[([\w-]+)(?:="([^"]*)")?\]$/.exec(p);
        return value === undefined ? el.hasAttribute(name) : el.getAttribute(name) === value;
    });
}
function matchesSelector(el, selector) {             // compounds joined by descendant combinators
    const parts = selector.trim().split(/\s+/);
    if (!matchesCompound(el, parts.pop())) return false;
    for (let e = el.parentElement; e && parts.length; e = e.parentElement)
        if (matchesCompound(e, parts[parts.length - 1])) parts.pop();
    return !parts.length;
}
class Element extends Node {
    constructor(tag, attrs = {}) {
        super(1);
        Object.assign(this, { tagName: tag.toUpperCase(), attrs: { ...attrs }, style: {}, listeners: [] });
    }
    get id() { return this.attrs.id || ''; }
    get className() { return this.attrs.class || ''; }
    set className(v) { this.attrs.class = String(v); }
    get classList() {
        const el = this, names = () => el.className.split(/\s+/).filter(Boolean);
        return {
            contains: c => names().includes(c),
            add: (...cs) => { el.className = [...new Set([...names(), ...cs])].join(' '); },
            remove: (...cs) => { el.className = names().filter(c => !cs.includes(c)).join(' '); },
            toggle(c, on = !names().includes(c)) { if (on) this.add(c); else this.remove(c); return on; },
        };
    }
    get dataset() {
        const el = this, attr = k => 'data-' + String(k).replace(/[A-Z]/g, c => '-' + c.toLowerCase());
        return new Proxy({}, { get: (_, k) => el.getAttribute(attr(k)) ?? undefined,
                               set: (_, k, v) => { el.setAttribute(attr(k), v); return true; } });
    }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    removeAttribute(k) { delete this.attrs[k]; }
    hasAttribute(k) { return k in this.attrs; }
    get hidden() { return 'hidden' in this.attrs; }
    set hidden(v) { if (v) this.attrs.hidden = ''; else delete this.attrs.hidden; }
    get type() { return this.attrs.type || ''; }
    set type(v) { this.attrs.type = String(v); }
    get title() { return this.attrs.title || ''; }
    set title(v) { this.attrs.title = String(v); }
    get value() {
        if (this._value !== undefined) return this._value;
        if (this.tagName === 'SELECT') {
            const option = this.querySelector('option[selected]') || this.querySelector('option');
            return option ? option.value : '';
        }
        return this.tagName === 'OPTION' ? (this.attrs.value ?? this.textContent) : (this.attrs.value ?? '');
    }
    set value(v) { this._value = String(v); }
    set innerHTML(html) { this.replaceChildren(...parseHTML(String(html))); }
    get rowSpan() { return parseInt(this.attrs.rowspan, 10) || 1; }
    get colSpan() { return parseInt(this.attrs.colspan, 10) || 1; }
    get cells() { return this.children.filter(c => c.tagName === 'TD' || c.tagName === 'TH'); }
    get tHead() { return this.children.find(c => c.tagName === 'THEAD') || null; }
    get tBodies() { return this.children.filter(c => c.tagName === 'TBODY'); }
    get rows() {
        if (this.tagName !== 'TABLE') return this.children.filter(c => c.tagName === 'TR');
        return this.children.flatMap(c => c.tagName === 'TR' ? [c]
            : ['THEAD', 'TBODY', 'TFOOT'].includes(c.tagName) ? c.rows : []);
    }
    matches(selector) { return selector.split(',').some(s => matchesSelector(this, s)); }
    closest(selector) {
        for (let e = this; e && e.nodeType === 1; e = e.parentNode) if (e.matches(selector)) return e;
        return null;
    }
    addEventListener(type, fn, capture) { this.listeners.push({ type, fn, capture: !!capture }); }
    getBoundingClientRect() { return this.rect || { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
    focus() { document.activeElement = this; }
}
function parseHTML(html) {
    const root = new Fragment();
    const stack = [root];
    const add = node => { const top = stack[stack.length - 1]; top.childNodes.push(node); node.parentNode = top; };
    const token = /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/([a-z][\w-]*)\s*>|<([a-z][\w-]*)((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+))?)*)\s*\/?>|[^<]+|</gi;
    for (const [text, close, open, attrText] of html.matchAll(token)) {
        if (text.startsWith('<!')) continue;
        if (close) {
            const at = stack.map(n => n.tagName).lastIndexOf(close.toUpperCase());
            if (at > 0) stack.length = at;
        } else if (open) {
            const attrs = {};
            for (const a of attrText.matchAll(/([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g))
                attrs[a[1].toLowerCase()] = decodeEntities(a[2] ?? a[3] ?? a[4] ?? '');
            const el = new Element(open, attrs);
            if (el.tagName === 'TR' && stack[stack.length - 1].tagName === 'TABLE') {   // as the browser does
                const body = new Element('tbody');
                add(body);
                stack.push(body);
            }
            add(el);
            if (!VOID_TAGS.has(open.toLowerCase())) stack.push(el);
        } else {
            add(new Text(decodeEntities(text)));
        }
    }
    root.childNodes.forEach(n => { n.parentNode = null; });
    return root.childNodes;
}
const documentElement = new Element('html');
documentElement.appendChild(new Element('body'));
globalThis.document = {
    nodeType: 9, documentElement, body: documentElement.firstElementChild, activeElement: null, listeners: [],
    createElement: tag => new Element(tag),
    createDocumentFragment: () => new Fragment(),
    getElementById: id => [...documentElement.walk()].find(e => e.id === id) || null,
    querySelector: s => documentElement.querySelector(s),
    querySelectorAll: s => documentElement.querySelectorAll(s),
    addEventListener(type, fn, capture) { this.listeners.push({ type, fn, capture: !!capture }); },
};
globalThis.window = globalThis;
Object.assign(globalThis, { innerWidth: 1280, innerHeight: 800, windowListeners: [],
                            MutationObserver: FakeMutationObserver });
globalThis.addEventListener = (type, fn) => windowListeners.push({ type, fn });
function dispatch(type, el, extra = {}) {
    const ev = { type, target: el, defaultPrevented: false, stopped: false, ...extra,
                 preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; } };
    const listeners = capture => document.listeners.filter(l => l.type === type && l.capture === capture);
    for (const l of listeners(true)) l.fn(ev);
    for (let e = el; e && e.nodeType === 1 && !ev.stopped; e = e.parentNode) {
        const inline = e.getAttribute('on' + type);
        if (inline) new Function('event', inline).call(e, ev);
        e.listeners.filter(l => l.type === type).forEach(l => l.fn.call(e, ev));
    }
    if (!ev.stopped) for (const l of listeners(false)) l.fn(ev);
    return ev;
}
const click = el => dispatch('click', el);
const settle = () => new Promise(resolve => setTimeout(resolve, 0));     // the observer has run
"""


def _controls_prelude():
    """The state of the controls (app.js top level) for the functions under test."""
    return "\n".join([_const_source("SORT_COLLATOR"), _const_source("tableSortState"),
                      "let _cardControlsObserver = null;", "let _infoPopoverAnchor = null;"])


def _element_markup(html, start):
    """The markup of the element whose start tag begins at start, up to its end tag."""
    tag = re.match(r"<([a-zA-Z][\w-]*)", html[start:]).group(1)
    depth = 0
    for m in re.compile(r"<(/?)%s\b[^>]*>" % re.escape(tag)).finditer(html, start):
        depth += -1 if m.group(1) else 1
        if depth == 0:
            return html[start:m.end()]
    raise AssertionError(f"<{tag}> at {start} is not closed")


def _tab_markup(name):
    """The markup of #tab-<name> in index.html."""
    html = _read(INDEX_HTML)
    m = re.search(r'<div class="tab-content[^"]*" id="tab-%s">' % re.escape(name), html)
    assert m, f"#tab-{name} missing in index.html"
    return _element_markup(html, m.start())


def _body_markup():
    """What index.html puts into <body>, without its scripts."""
    html = _read(INDEX_HTML)
    body = html[html.index("<body>") + len("<body>"):html.index("</body>")]
    return re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.S)


@needs_node
def test_compare_sort_values():
    r = _run_node(SORT_FUNCTIONS, r"""
        const sorted = values => [...values].sort(compareSortValues);
        // Rows of one column with their position in a second one: the order sortRows gives
        const body = document.createElement('tbody');
        const order = (values, dir) => {
            body.innerHTML = values.map((v, i) => `<tr><td>${v}</td><td>${i}</td></tr>`).join('');
            return sortRows([...body.rows], 0, dir).map(row => Number(row.cells[1].textContent));
        };
        console.log(JSON.stringify({
            numbers: sorted(['10', '9', '100']),
            clock: [sorted(['10:00:05', '09:59:00']), sorted(['10:00:05.5', '10:00:05.25', '9:59'])],
            text: sorted(['beta', 'Alpha']),
            emptyLast: [sorted(['', '3', '1']), order(['', '3', '1'], 'asc'), order(['', '3', '1'], 'desc')],
            stable: [order(['b', 'a', 'b', 'a'], 'asc'), order(['b', 'a', 'b', 'a'], 'desc'), order(['x', 'X', 'x'], 'desc')],
            iso: sorted(['2026-11-09T12:00:00Z', '2026-11-09T12:30:00+01:00', '2026-11-09T09:00:00.1234567Z']),
            hex: sorted(['0x1F', '0x100', '0x2']),
            signed: sorted(['+0.25', '-1.5', '0.1']),
            placeholders: [order(['\u2014', '5', '-', '2', 'n/a'], 'asc'), order(['\u2014', '5', '?', '2'], 'desc')],
            natural: sorted(['chunk_10.bin', 'chunk_9.bin']),
            mixed: sorted(['10', 'abc', '9']),
        }));
    """, SORT_DOM + _controls_prelude())
    assert r["numbers"] == ["9", "10", "100"], "numbers sorted as text"
    assert r["clock"] == [["09:59:00", "10:00:05"], ["9:59", "10:00:05.25", "10:00:05.5"]], "clock times sorted as text"
    assert r["text"] == ["Alpha", "beta"], "text sorted case-sensitively"
    assert r["emptyLast"] == [["1", "3", ""], [2, 1, 0], [1, 2, 0]], "an empty cell does not stay last in both directions"
    assert r["stable"] == [[1, 3, 0, 2], [0, 2, 1, 3], [0, 1, 2]], "equal values change their order"
    # 12:30+01:00 is 11:30Z: by time, not by text
    assert r["iso"] == ["2026-11-09T09:00:00.1234567Z", "2026-11-09T12:30:00+01:00", "2026-11-09T12:00:00Z"]
    assert r["hex"] == ["0x2", "0x1F", "0x100"] and r["signed"] == ["-1.5", "0.1", "+0.25"]
    assert r["placeholders"] == [[3, 1, 0, 2, 4], [1, 3, 0, 2]], "a placeholder (—, -, n/a, ?) is not empty"
    assert r["natural"] == ["chunk_9.bin", "chunk_10.bin"]
    assert r["mixed"] == ["9", "10", "abc"]


@needs_node
def test_sorting_keeps_notes_detail_rows_and_row_groups_together():
    """A note (data-sort-skip, or one cell across the table) keeps its place;
    a detail row (data-sort-detail, the PE section rows) and the rows a
    rowspan covers (Named Pipes of a detonation) move with their row."""
    r = _run_node(SORT_FUNCTIONS, r"""
        const body = document.createElement('tbody');
        const order = (rows, col, dir) => {
            body.innerHTML = rows.join('');
            return sortRows([...body.rows], col, dir).map(row => row.cells.map(c => c.textContent.trim()).join(' '));
        };
        const details = [
            '<tr class="alerts-limit-row" data-sort-skip><td colspan="3">note</td></tr>',
            '<tr><td>b</td><td>2</td><td>x</td></tr>', '<tr data-sort-detail><td colspan="3">detail b</td></tr>',
            '<tr><td>c</td><td>3</td><td>y</td></tr>', '<tr data-sort-detail><td colspan="3">detail c</td></tr>',
            '<tr data-sort-skip><td>marked</td><td>0</td><td>note</td></tr>',
            '<tr><td>a</td><td>1</td><td>z</td></tr>', '<tr data-sort-detail><td colspan="3">detail a</td></tr>',
            '<tr><td colspan="3" class="muted">... and 6 more</td></tr>',
        ];
        const groups = [
            '<tr><td rowspan="2" data-sort-value="2">10:00</td><td>p1</td><td rowspan="2">\\b</td></tr>', '<tr><td>p2</td></tr>',
            '<tr><td data-sort-value="1">09:00</td><td>p3</td><td>\\a</td></tr>',
            '<tr><td rowspan="3" data-sort-value="3">11:00</td><td>p4</td><td rowspan="3">\\c</td></tr>',
            '<tr><td>p5</td></tr>', '<tr><td>p6</td></tr>',
        ];
        console.log(JSON.stringify({
            asc: order(details, 0, 'asc'), desc: order(details, 1, 'desc'),
            groupsByPipe: order(groups, 2, 'asc'), groupsByTime: order(groups, 0, 'desc'),
        }));
    """, SORT_DOM + _controls_prelude())
    assert r["asc"] == ["note", "a 1 z", "detail a", "b 2 x", "detail b", "marked 0 note", "c 3 y", "detail c",
                        "... and 6 more"]
    assert r["desc"] == ["note", "c 3 y", "detail c", "b 2 x", "detail b", "marked 0 note", "a 1 z", "detail a",
                         "... and 6 more"]
    assert r["groupsByPipe"] == ["09:00 p3 \\a", "10:00 p1 \\b", "p2", "11:00 p4 \\c", "p5", "p6"]
    assert r["groupsByTime"] == ["11:00 p4 \\c", "p5", "p6", "10:00 p1 \\b", "p2", "09:00 p3 \\a"]


# Tables that are no data tables, and why. (The hex view and the key-value
# fields of the detail view are no <table>s.)
SORT_EXEMPT = {
    ("index.html", "help-api-table"): "the Help modal's API and service reference: documentation in a fixed order",
}
TABLE_TAG = re.compile(r"<table\b[^>]*>")


def _table_tags():
    """(file, line, tag) of every <table ...> of index.html and app.js, comments left out."""
    found = []
    for path, strip in ((INDEX_HTML, lambda t: re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), t, flags=re.S)),
                        (APP_JS, _strip_js_comments)):
        text = strip(_read(path))
        found += [(os.path.basename(path), text.count("\n", 0, m.start()) + 1, m.group(0))
                  for m in TABLE_TAG.finditer(text)]
    return found


def test_every_data_table_is_sortable():
    tags = _table_tags()
    assert len(tags) >= 27, "the table pattern is out of date"
    problems, used, ids = [], set(), {}
    for where, line, tag in tags:
        classes = (re.search(r'\sclass="([^"]*)"', tag) or re.search("()", "")).group(1).split()
        exempt = [key for key in SORT_EXEMPT if key[0] == where and key[1] in classes]
        if exempt:
            used.update(exempt)
            continue
        sort_id = re.search(r'\sdata-sort-id="([a-z0-9-]+)"', tag)
        if not re.search(r"\sdata-sortable(?=[\s>])", tag) or not sort_id:
            problems.append(f"{where}:{line}: {tag} is no sortable table (data-sortable data-sort-id) "
                            f"and not in SORT_EXEMPT")
            continue
        ids.setdefault(sort_id.group(1), []).append(f"{where}:{line}")
    problems += [f"data-sort-id {sort_id} is used by {', '.join(places)}" for sort_id, places in ids.items()
                 if len(places) > 1]
    problems += [f"SORT_EXEMPT {key} matches no table" for key in SORT_EXEMPT if key not in used]
    assert not re.search(r"createElement\(\s*['\"]table", _read(APP_JS)), "a table built with createElement escapes this test"
    assert not problems, "\n".join(problems)


def test_rows_that_hold_no_data_are_marked():
    """A row of one cell across the table is a note (it keeps its place,
    data-sort-skip) or the detail of the row above (data-sort-detail)."""
    js = _read(APP_JS)
    rows = re.findall(r"<tr\b[^>]*>\s*<td\b[^>]*\bcolspan=", js)
    assert len(rows) >= 5, "the row pattern is out of date"
    unmarked = [row for row in rows if not re.search(r"\sdata-sort-(?:skip|detail)(?=[\s>])", row)]
    assert not unmarked, "\n".join(unmarked)


# A cell showing a time or a size as text ("23:59:58", "1.2 KB") sorts by its value
FORMATTED_CELL = re.compile(r"\$\{[^}]*\b(?:formatSize|formatTime|formatSysmonTime|formatAlertTime|toLocale\w*String)\("
                            r"|\$\{\s*(?:ts|time|size)\s*\}")


def test_formatted_times_and_sizes_sort_by_their_value():
    js = _read(APP_JS)
    cells = re.findall(r"<td\b([^>]*)>((?:(?!</td>).)*)</td>", js, re.S)
    formatted = [(attrs, content) for attrs, content in cells if FORMATTED_CELL.search(content)]
    assert len(formatted) >= 15, "the cell pattern is out of date"
    missing = [f"<td{attrs}>{content.strip()[:80]}" for attrs, content in formatted if "data-sort-value=" not in attrs]
    assert not missing, "formatted cells without data-sort-value:\n" + "\n".join(missing)


SYSMON_FUNCTIONS = ["renderSysmonTable", "getSysmonDetails", "getSysmonTypeClass", "formatSysmonTime", "truncate",
                    "getCorrelatedWindowsEvents", "escapeHtml", "sortTimeValue"]
# The Sysmon tab with its charts above its filter bar, the chips of the filters the charts set, and the parts it
# shares with the Alerts tab and the building blocks of the charts
SYSMON_TAB_FUNCTIONS = list(dict.fromkeys(SYSMON_FUNCTIONS + [
    "refreshSysmon", "renderSysmonStats", "filterSysmonLocal", "_sysmonTableHtml", "sysmonFilterFromControls",
    "filterSysmonEvents",
    "sysmonImageName", "sysmonEventType", "renderSysmonCharts", "sysmonFlow", "sysmonTypeColor", "sysmonTypeItems",
    "_sysmonTypeNames", "_sysmonEmptyText", "_drawSysmonTime", "_drawSysmonFlow", "_sysmonFlowColors",
    "_sysmonChartWidths", "onSysmonChartClick", "_sysmonFlowFilter", "setSysmonFilters", "removeSysmonFilter",
    "renderSysmonActiveFilters", "_sysmonWindowLabel", "_sysmonKeepWindow", "toggleSysmonFlowScale",
    "redrawSysmonChartsOnResize", "initSysmonTab",
    "chartTimeBins", "_timeBinsTableHtml", "_flowTableHtml", "filterChipHtml", "_alertsTimeNote",
    "_alertsChartInert", "_flowInert", "_flowClickFilter",
    "_alertsNameKey", "_alertNameIs", "_alertsTimeBound", "_pressFlowScale", "formatAlertTime", "jsArg", "_tabListTop",
    "_followBarHeight", "isTableView", "viewToggleHtml", "cardViewAttrs", "toggleCardView"] + CHART_FUNCTIONS))
# Their state (app.js top level)
SYSMON_TAB_CONSTS = ["SYSMON_WINDOWS_CORRELATION", "sysmonTimeWindow", "sysmonFlowFilter", "sysmonFlowView",
                     "SYSMON_TYPE_COLORS", "SYSMON_OTHER_COLORS", "ALERT_TIME_MIN", "cardViewState"] + CHART_CONSTS
SYSMON_TAB_LETS = ("\nlet sysmonEvents = [];\nlet sysmonStats = null;\nlet sysmonLoadError = '';"
                   "\nlet _sysmonChartsDrawn = null;\nlet _sysmonTableShown = null;\n")


def _sysmon_prelude():
    return "\n".join(_const_source(c) for c in SYSMON_TAB_CONSTS) + SYSMON_TAB_LETS


PIPE_EVENT_FUNCTIONS = ["refreshPipeEvents", "pipesIsGone", "pipesCanonical", "formatTime", "jsArg", "jsInt",
                        "renderNamedPipesBlock", "pipeProcLabel", "cssToken"]


@needs_node
def test_a_sorted_table_stays_sorted_when_polling_renders_it_again():
    """Review focus 4: the Sysmon table, the pipe events and the Alerts tab
    are built again by their render functions (polling, filters); the order
    the user chose is applied again before the next paint, without the
    observer triggering itself. Numbers sort numerically, times by time."""
    script = r"""
        (async () => {
            document.body.innerHTML = MARKUP;
            initCardControls();
            const observer = _cardControlsObserver;
            const r = {};
            const head = (table, name) => [...table.tHead.rows[0].cells].find(c => c.textContent.trim() === name);
            const column = (table, i) => [...table.tBodies[0].rows].map(row =>
                row.classList.contains('alerts-limit-row') ? 'NOTE' : row.cells[i].textContent.trim());
            const aria = table => [...table.tHead.rows[0].cells].map(c => c.getAttribute('aria-sort'));

            // Sysmon: the time column shows a clock time, so only its value orders the days
            const ev = (id, timestamp, pid) => ({ event_id: 1, type: 'ProcessCreate', timestamp, pid,
                                                  image: 'C:\\x\\p.exe', commandline: id });
            sysmonEvents = [ev('noon', '2026-11-09T12:00:00Z', 1000), ev('late', '2026-11-09T23:59:58Z', 300),
                            ev('next day', '2026-11-10T00:00:02Z', 20)];
            renderSysmonTable(); await settle();
            const sysmon = () => document.querySelector('#sysmon-table table');
            r.sysmonClock = column(sysmon(), 0);
            click(head(sysmon(), 'Time')); await settle();
            r.sysmonAsc = column(sysmon(), 4);
            click(head(sysmon(), 'Time')); await settle();
            r.sysmonDesc = column(sysmon(), 4);
            const before = observer.deliveries;
            sysmonEvents = [ev('earlier', '2026-11-09T06:00:00Z', 7), ...sysmonEvents, ev('latest', '2026-11-10T01:00:00Z', 5)];
            renderSysmonTable(); await settle();
            r.sysmonPolled = column(sysmon(), 4);
            r.sysmonDeliveries = observer.deliveries - before;
            r.sysmonAria = aria(sysmon());
            click(head(sysmon(), 'PID')); await settle();
            r.sysmonPid = [column(sysmon(), 2), aria(sysmon())];
            r.sysmonFocusable = [...sysmon().tHead.rows[0].cells].map(c => c.getAttribute('tabindex'));

            // Pipe events: a refresh (button, filter, tab switch) builds the table again
            let reply = [];
            globalThis.fetch = async () => ({ ok: true, json: async () => ({ events: reply }) });
            const pe = (timestamp, pid, pipe, family) => ({ timestamp, pid, pipe, family, type: 'PipeCreated',
                                                            image: 'C:\\x\\p' + pid + '.exe' });
            reply = [pe('2026-11-09T10:00:00Z', 4242, '\\b', ''), pe('2026-11-09T10:00:05Z', 77, '\\a', 'cobaltstrike'),
                     pe('2026-11-09T09:00:00Z', 900, '\\c', '')];
            await refreshPipeEvents(); await settle();
            const pipes = () => document.querySelector('#pipes-events table');
            click(head(pipes(), 'PID')); await settle();
            r.pipesPid = column(pipes(), 2);
            reply = [pe('2026-11-09T10:01:00Z', 5, '\\d', ''), ...reply];
            await refreshPipeEvents(); await settle();
            r.pipesPolled = column(pipes(), 2);
            click(head(pipes(), 'Family')); await settle();
            click(head(pipes(), 'Family')); await settle();
            r.pipesFamilyDesc = column(pipes(), 5);
            const actions = head(pipes(), '');
            click(actions); await settle();
            r.pipesActions = [actions.getAttribute('tabindex'), actions.getAttribute('aria-sort'), column(pipes(), 5)];

            // Alerts tab: the note above the newest rows stays on top
            globalThis.state = { alerts: ALERTS, processes: {}, activeTab: 'alerts' };
            renderAlertsTab(); await settle();
            const alertsTable = document.getElementById('alerts-table');
            r.alertsNewest = column(alertsTable, 3);
            click(head(alertsTable, 'Rule')); await settle();
            r.alertsRule = column(alertsTable, 3);
            state.alerts = [{ id: 'a5', timestamp: '2026-11-09T13:00:00Z', severity: 'High', engine: 'IOC',
                              rule_name: 'Beacon check-in' }, ...ALERTS];
            renderAlertsTab(); await settle();
            r.alertsPolled = column(alertsTable, 3);
            click(head(alertsTable, 'Severity')); await settle();
            click(head(alertsTable, 'Severity')); await settle();
            r.alertsSeverity = column(alertsTable, 1);

            // Named pipes of a detonation: a pipe's rows move as one
            const named = document.getElementById('submit-result');
            const np = { available: true, pipes: [
                { pipe: '\\msagent_1', first_seen: '2026-11-09T10:00:00Z', created_by: ['10'], connected_by: ['11', '12'] },
                { pipe: '\\a_pipe', first_seen: '2026-11-09T11:00:00Z', created_by: ['20'], connected_by: [] }] };
            named.innerHTML = renderNamedPipesBlock(np); await settle();
            const result = () => named.querySelector('table');
            click(head(result(), 'Pipe')); await settle();
            r.namedPipes = [...result().tBodies[0].rows].map(row => row.cells.map(c => c.textContent.trim()).join(' '));
            console.log(JSON.stringify(r));
        })();
    """
    markup = _tab_markup("sysmon") + _tab_markup("pipes") + _tab_markup("alerts") + '<div id="submit-result"></div>'
    consts = list(dict.fromkeys(SYSMON_TAB_CONSTS + ["pipesState", "PIPE_FLAG_LABELS"] + ALERTS_TAB_CONSTS))
    prelude = (SORT_DOM + _controls_prelude() + SYSMON_TAB_LETS
               + "\n".join(_const_source(c) for c in consts)
               + "\nconst ALERTS_TAB_LIMIT = 3;\n" + ALERTS_TAB_LETS + "\n"
               + ALERT_FIXTURE.replace("const alerts", "const ALERTS"))
    functions = sorted(set(CONTROL_FUNCTIONS + SYSMON_TAB_FUNCTIONS + PIPE_EVENT_FUNCTIONS + ALERTS_TAB_FUNCTIONS))
    r = _run_node(functions, script.replace("MARKUP", json.dumps(markup)), prelude)
    # The time column shows clock times: as text the next day would come first
    assert r["sysmonClock"] == ["12:00:00.000", "23:59:58.000", "00:00:02.000"]
    assert r["sysmonAsc"] == ["noon", "late", "next day"] and r["sysmonDesc"] == ["next day", "late", "noon"]
    assert r["sysmonPolled"] == ["latest", "next day", "late", "noon", "earlier"], "a new render dropped the order"
    assert r["sysmonDeliveries"] == 1, "the observer triggered itself"
    assert r["sysmonAria"] == ["descending", None, None, None, None, None]
    assert r["sysmonPid"] == [["5", "7", "20", "300", "1000"], [None, None, "ascending", None, None, None]]
    assert r["sysmonFocusable"] == ["0"] * 6, "a column head cannot be reached with the keyboard"
    assert r["pipesPid"] == ["77", "900", "4242"] and r["pipesPolled"] == ["5", "77", "900", "4242"]
    assert r["pipesFamilyDesc"] == ["cobaltstrike", "\u2014", "\u2014", "\u2014"], "an empty family is not last"
    assert r["pipesActions"] == [None, None, r["pipesFamilyDesc"]], "the head of the button column sorts"
    assert r["alertsNewest"] == ["NOTE", "Mimikatz", "CobaltStrike beacon", "Credential dump"]
    assert r["alertsRule"] == ["NOTE", "CobaltStrike beacon", "Credential dump", "Mimikatz"]
    assert r["alertsPolled"] == ["NOTE", "Beacon check-in", "CobaltStrike beacon", "Mimikatz"]
    assert r["alertsSeverity"] == ["NOTE", "high", "high", "medium"]
    dash = "\u2014"
    assert r["namedPipes"] == [f"11:00:00 PID 20 created \\a_pipe {dash} {dash} Intercept",
                               f"10:00:00 PID 10 created \\msagent_1 {dash} {dash} Intercept",
                               "PID 11 connected", "PID 12 connected"], "a pipe's rows were torn apart"


def _specificity(selector):
    """(ids, classes / attributes / pseudo-classes, types / pseudo-elements) of
    a selector; :not() counts as its argument (enough for these rules)."""
    s = re.sub(r":not\(([^()]*)\)", r"\1", selector)
    s = re.sub(r'"[^"]*"', '""', s)
    ids = len(re.findall(r"#[\w-]+", s))
    classes = len(re.findall(r"\.[\w-]+|\[[^\]]*\]|(?<!:):(?!:)[\w-]+", s))
    types = len(re.findall(r"(?:^|[\s>+~(])([a-zA-Z][\w-]*)", s)) + len(re.findall(r"::[\w-]+", s))
    return ids, classes, types


def test_sort_heads_show_their_state():
    """↕ on a head that sorts, ▲ / ▼ on the sorted one (aria-sort), in the
    colours of the theme; a head without text (buttons) does not sort. The
    rule of the sorted state outranks the one of the others (it showed ↕)."""
    rules = {}
    for prelude, body in _css_blocks(_strip_comments(_read(STYLE_CSS))):
        for selector in (_selectors(prelude) if body else []):
            rules[selector] = rules.get(selector, "") + body
    head = "table[data-sortable] > thead > tr > th:not([data-no-sort]):not(:empty)"
    assert re.search(r"cursor:\s*pointer", rules.get(head, ""))
    idle = head + "::after"
    assert '"\\2195"' in rules.get(idle, "")
    states = {}
    for state, arrow in (("ascending", r"\25B2"), ("descending", r"\25BC")):
        selector = next((s for s in rules if f'[aria-sort="{state}"]' in s and s.endswith("::after")), None)
        assert selector and '"%s"' % arrow in rules[selector], (state, arrow)
        assert _specificity(selector) > _specificity(idle), f"{selector} loses to {idle}: the sorted head shows ↕"
        states[state] = selector
    theme = {selector for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS))) if body
             for selector in _selectors(prelude) if selector.endswith("[aria-sort]::after")}
    assert theme, "no Cyberpunk colour for the sorted head"
    assert all(_specificity(t) > _specificity(states[s]) for t in theme for s in states), \
        "the Cyberpunk arrow colour loses to Classic's"


INFO_ATTR = re.compile(r'\sdata-info="([^"]*)"')


def test_info_texts_cover_every_tab():
    html = _read(INDEX_HTML)
    elements = _Elements(html)

    def find(node, test):
        return [n for c in node["children"] for n in ([c] if test(c) else []) + find(c, test)]

    def has_info(node):
        return "data-info" in node["attrs"] or any(has_info(c) for c in node["children"])

    def with_class(name):
        return lambda e: name in e["attrs"].get("class", "").split()

    headers = find(elements.root, with_class("content-header"))
    assert len(headers) == 10, "a tab head is missing or the pattern is out of date"
    rows = find(elements.root, with_class("rtrace-header")) + find(elements.root, with_class("graph-toolbar"))
    assert len(rows) == 2, "the head rows of Tracing and Graph"
    assert [h["children"][0]["text"] if h["children"] else "" for h in headers if not has_info(h)] == []
    assert all(has_info(row) for row in rows), "Tracing or Graph without (i)"
    tabs = find(elements.root, with_class("tab-content"))
    assert len(tabs) == 12 and all(has_info(tab) for tab in tabs)
    texts = INFO_ATTR.findall(html) + INFO_ATTR.findall(_read(APP_JS))
    assert len(texts) >= 30
    for text in texts:
        assert text.strip() and len(text) <= 300, text
        assert "<" not in text and "${" not in text and "&" not in text, f"markup, data or an entity: {text}"
        sentences = len(re.findall(r"[.!?](?:\s|$)", text))
        assert 1 <= sentences <= 2 and text.rstrip()[-1] in ".!?", f"one or two sentences: {text}"


INFO_TEST_FUNCTIONS = CONTROL_FUNCTIONS + ["handleGlobalKeydown", "closeHelp", "isTopbarMenuOpen", "setTopbarMenu",
                                           "closeTopbarMenus", "isDrawerOpen", "setDrawerOpen", "closeDrawer"]


@needs_node
def test_info_buttons_explain_headings_in_a_popover():
    r = _run_node(INFO_TEST_FUNCTIONS, r"""
        (async () => {
            document.body.innerHTML = BODY;
            globalThis.state = { detailOpen: false };
            globalThis.cardClicks = 0;
            initCardControls();
            const r = {};
            const holders = document.querySelectorAll('[data-info]');
            const buttons = el => el.children.filter(c => c.classList.contains('info-btn'));
            r.holders = holders.length;
            r.shape = [...new Set(holders.map(el => { const b = el.lastElementChild;
                return [b.tagName, b.className, b.getAttribute('type'), b.getAttribute('aria-label'), b.textContent,
                        buttons(el).length].join('|'); }))];
            initInfoButtons(document);
            r.once = holders.every(el => buttons(el).length === 1);
            // A card rendered by JavaScript gets its (i) before the next paint
            const host = document.getElementById('submit-result');
            host.innerHTML = '<div class="card" onclick="cardClicks++"><h3 data-info="&lt;img src=x onerror=alert(1)&gt; stays text.">Card</h3></div>';
            r.rendered = [buttons(host.querySelector('h3')).length];
            await settle();
            r.rendered.push(buttons(host.querySelector('h3')).length);
            const popover = document.getElementById('info-popover');
            const button = host.querySelector('.info-btn');
            button.rect = { left: 1200, right: 1214, top: 760, bottom: 774, width: 14, height: 14 };
            popover.rect = { left: 0, top: 0, right: 300, bottom: 80, width: 300, height: 80 };
            const view = () => ({ hidden: popover.hidden, text: popover.textContent, elements: popover.children.length,
                                  expanded: button.getAttribute('aria-expanded'), at: [popover.style.left, popover.style.top] });
            click(button);
            r.opened = { ...view(), cardClicks };
            click(popover); r.clickInside = popover.hidden;
            click(button); r.toggled = [popover.hidden, button.getAttribute('aria-expanded')];
            click(button); click(document.querySelector('#tab-dashboard h2')); r.clickBeside = popover.hidden;
            // Esc closes the popover first and gives the focus back to its button
            click(button); document.activeElement = null;
            let closedDetail = 0;
            globalThis.closeDetail = () => { closedDetail++; state.detailOpen = false; };
            state.detailOpen = true;
            handleGlobalKeydown({ key: 'Escape', preventDefault() {} });
            r.esc = [popover.hidden, document.activeElement === button, closedDetail];
            handleGlobalKeydown({ key: 'Escape', preventDefault() {} });
            r.escAgain = closedDetail;
            // Another (i) takes the popover over; scrolling its container, a resize or a
            // render that removes the button closes it
            const other = document.querySelector('#tab-alerts h2 .info-btn');
            click(button); click(other);
            r.other = [popover.hidden, popover.textContent === other.parentElement.getAttribute('data-info'),
                       button.getAttribute('aria-expanded'), other.getAttribute('aria-expanded')];
            onInfoAnchorScroll({ target: document.getElementById('alerts-table-wrap') }); r.unrelatedScroll = popover.hidden;
            onInfoAnchorScroll({ target: document.getElementById('tab-alerts') }); r.scroll = popover.hidden;
            click(other); windowListeners.filter(l => l.type === 'resize').forEach(l => l.fn({})); r.resize = popover.hidden;
            click(button); host.innerHTML = ''; await settle(); r.removed = popover.hidden;
            console.log(JSON.stringify(r));
        })();
    """.replace("BODY", json.dumps(_body_markup())), SORT_DOM + _controls_prelude() + _const_source("TOPBAR_MENUS"))
    assert r["holders"] >= 25
    assert r["shape"] == ["BUTTON|info-btn|button|Explain|i|1"], "each heading gets one (i) after its text"
    assert r["once"], "a second call adds a second (i)"
    assert r["rendered"] == [0, 1], "a heading rendered by JavaScript has no (i)"
    assert r["opened"] == {"hidden": False, "text": "<img src=x onerror=alert(1)> stays text.", "elements": 0,
                           "expanded": "true", "at": ["972px", "674px"], "cardClicks": 0}
    assert r["clickInside"] is False and r["toggled"] == [True, "false"] and r["clickBeside"] is True
    assert r["esc"] == [True, True, 0] and r["escAgain"] == 1, "Esc closed another layer first"
    assert r["other"] == [False, True, "false", "true"]
    assert [r["unrelatedScroll"], r["scroll"], r["resize"], r["removed"]] == [False, True, True, True]


# The Cyberpunk drawer on the whole page, with the (i) of its titles and the
# click listener of the top bar, registered at load before the card controls
DRAWER_INFO_FUNCTIONS = INFO_TEST_FUNCTIONS + ["onTopbarOutsideClick", "openDrawer", "toggleDrawer", "currentTheme",
                                               "normalizeTheme"]
DRAWER_INFO_SETUP = r"""
    document.body.innerHTML = BODY;
    globalThis.state = { detailOpen: false };
    document.addEventListener('click', onTopbarOutsideClick, true);
    initCardControls();
    document.documentElement.setAttribute('data-theme', 'cyberpunk');
    const $ = id => document.getElementById(id);
    const popover = $('info-popover');
    const drawer = () => $('app').classList.contains('drawer-open');
    const esc = () => handleGlobalKeydown({ key: 'Escape', preventDefault() {} });
    const info = section => $(section).querySelector('.section-title .info-btn');
"""


def _drawer_info_prelude():
    return SORT_DOM + _controls_prelude() + _const_source("TOPBAR_MENUS") + "\n" + _const_source("THEMES")


def _drawer_info_script(script):
    return (DRAWER_INFO_SETUP + script).replace("BODY", json.dumps(_body_markup()))


@needs_node
def test_a_click_in_the_explanation_of_a_drawer_title_keeps_the_drawer_open():
    """The popover of an (i) in the drawer (PROCESSES, TIMELINE) lies over the
    page, outside the drawer: a click in it (to select its text) leaves the
    drawer open, as it leaves the popover open; a click beside both closes
    both."""
    r = _run_node(DRAWER_INFO_FUNCTIONS, _drawer_info_script(r"""
        const r = {};
        click($('drawer-toggle'));
        for (const section of ['process-list-section', 'timeline-section']) {
            click(info(section));
            r[section] = [[drawer(), popover.hidden, popover.textContent === info(section).parentElement.getAttribute('data-info')]];
            click(popover);
            r[section].push([drawer(), popover.hidden]);
            click(info(section));
            r[section].push([drawer(), popover.hidden]);
        }
        click(info('timeline-section'));
        click($('drawer-scrim'));
        r.beside = [drawer(), popover.hidden];
        console.log(JSON.stringify(r));
    """), _drawer_info_prelude())
    for section in ("process-list-section", "timeline-section"):
        opened, clicked_inside, closed_again = r[section]
        assert opened == [True, False, True], section
        assert clicked_inside == [True, False], f"a click in the explanation of {section} closed the drawer"
        assert closed_again == [True, True], section
    assert r["beside"] == [False, True], "a click beside the drawer left it or the explanation open"


@needs_node
def test_esc_on_the_drawer_gives_the_focus_to_its_button():
    """Esc closes the popover first (the focus goes back to its (i), in the
    drawer), then the drawer: the focus that was in it goes to ☰ PROCESSES,
    as a drop-down gives it to its button, rather than to nothing. A focus
    outside the drawer stays where it is."""
    r = _run_node(DRAWER_INFO_FUNCTIONS, _drawer_info_script(r"""
        const r = {};
        const focused = () => document.activeElement ? document.activeElement.id || document.activeElement.className : null;
        openDrawer();
        info('timeline-section').focus();
        click(info('timeline-section'));
        esc(); r.popover = [popover.hidden, drawer(), focused()];
        esc(); r.drawer = [drawer(), focused()];
        openDrawer();
        $('timeline-view-toggle').innerHTML = '<button type="button" class="view-toggle">TABLE</button>';
        $('timeline-view-toggle').firstElementChild.focus();
        esc(); r.toggle = [drawer(), focused()];
        $('theme-toggle-top').focus();
        openDrawer();
        esc(); r.outside = [drawer(), focused()];
        console.log(JSON.stringify(r));
    """), _drawer_info_prelude())
    assert r["popover"] == [True, True, "info-btn"], "Esc closed the drawer before the explanation"
    assert r["drawer"] == [False, "drawer-toggle"], "Esc on the drawer dropped the keyboard focus"
    assert r["toggle"] == [False, "drawer-toggle"]
    assert r["outside"] == [False, "theme-toggle-top"], "Esc took a focus from outside the drawer"


@needs_node
def test_info_popover_stays_in_the_window():
    cases = [(100, 50, 300, 80, 1280, 800), (1200, 50, 300, 80, 1280, 800), (100, 760, 300, 80, 1280, 800),
             (-20, 30, 300, 80, 1280, 800), (100, 100, 300, 900, 1280, 800), (600, 20, 320, 120, 400, 160)]
    r = _run_node(["infoPopoverPosition"], r"""
        console.log(JSON.stringify(CASES.map(([left, top, w, h, vw, vh]) =>
            infoPopoverPosition({ left, top, right: left + 14, bottom: top + 14 }, { width: w, height: h }, { width: vw, height: vh }))));
    """.replace("CASES", json.dumps(cases)))
    assert r[0] == {"left": 100, "top": 70}, "below the button, left edges aligned"
    assert r[1] == {"left": 972, "top": 70}, "moved left to stay inside the window"
    assert r[2] == {"left": 100, "top": 674}, "above the button when there is no room below"
    assert r[3]["left"] == 8 and r[4]["top"] == 8, "a button off the left edge, a text taller than the window"
    for (left, top, w, h, vw, vh), at in zip(cases, r):
        assert at["left"] >= 8 and at["top"] >= 8, (left, top, at)
        assert at["left"] + w <= vw - 8, f"leaves the window on the right: {at}"
        assert h > vh - 16 or at["top"] + h <= vh - 8, f"leaves the window at the bottom: {at}"


def test_card_controls_are_set_up_once():
    js = _strip_js_comments(_read(APP_JS))
    start = js.index("document.addEventListener('DOMContentLoaded', () => {")
    init = js[start:js.index("\n});", start)]
    assert re.search(r"^\s*initCardControls\(\);", init, re.M), "not set up at start-up"
    assert len(re.findall(r"(?<!function )\binitCardControls\(", js)) == 1, "set up more than once"
    assert js.count("new MutationObserver(") == 1 and "new MutationObserver(" in _function_source("initCardControls")
    popover = _Elements(_read(INDEX_HTML)).by_id("info-popover")
    assert popover and "hidden" in popover["attrs"] and "info-popover" in popover["attrs"].get("class", "")
    rules = {}
    for prelude, body in _css_blocks(_strip_comments(_read(STYLE_CSS))):
        for selector in (_selectors(prelude) if body else []):
            rules[selector] = rules.get(selector, "") + body
    assert re.search(r"display:\s*none", rules.get(".info-popover[hidden]", "")), "the closed popover shows"
    assert re.search(r"position:\s*fixed", rules.get(".info-popover", ""))
    layer = re.search(r"z-index:\s*(\d+)", rules.get(".info-popover", ""))
    assert layer and int(layer.group(1)) > 300, "the popover is under the detail view or the drawer"
    # Inside a Cyberpunk title (transparent text, upper case) the (i) keeps its own look
    assert all(re.search(p, rules.get(".info-btn", "")) for p in (r"\bcolor:", r"text-transform:\s*none", r"letter-spacing:"))
    theme = {selector for prelude, body in _css_blocks(_strip_comments(_read(THEME_CSS))) if body
             for selector in _selectors(prelude)}
    assert {'[data-theme="cyberpunk"] .info-btn', '[data-theme="cyberpunk"] .info-popover'} <= theme


# --- CHART / TABLE, dashboard tiles and the Tracing event grid -------------------

CARD_VIEW_FUNCTIONS = ["isTableView", "viewToggleHtml", "cardViewAttrs", "toggleCardView", "escapeHtml", "jsArg"]
CHART_CARDS = ["renderTimeline", "renderRtraceTimeline", "updateRtraceSeverityBar", "renderDetectionOverview",
               "renderPeAnalysis", "renderAlertsCharts", "renderDashboardCharts", "renderSysmonCharts",
               "renderScoreHistory", "renderSubmissionVerdicts", "graphActivityMixHtml", "verdictFlowHtml"]


def _rules(path):
    """selector -> its declarations (all rules of the sheet for it)."""
    rules = {}
    for prelude, body in _css_blocks(_strip_comments(_read(path))):
        for selector in (_selectors(prelude) if body else []):
            rules[selector] = rules.get(selector, "") + body
    return rules


def _view_prelude():
    return (SORT_DOM + _controls_prelude() + "\n" + _const_source("cardViewState") + "\n"
            + _const_source("ALERT_SEVERITIES"))


@needs_node
def test_card_view_toggle():
    """The brief's check; and a switch shows the other view of its card in
    place (both views are in the page), keeps its button and leaves the
    other cards as they are."""
    r = _run_node(CARD_VIEW_FUNCTIONS, r"""
        const r = { start: isTableView('timeline'), chartButton: viewToggleHtml('timeline') };
        const card = id => `<div id="${id}">${viewToggleHtml(id)}<div class="chart"${cardViewAttrs(id, 'chart')}></div>`
            + `<div class="table"${cardViewAttrs(id, 'table')}></div></div>`;
        document.body.innerHTML = card('timeline') + card('rtrace-timeline');
        const view = id => { const el = document.getElementById(id);
            return [el.querySelector('.chart').hidden, el.querySelector('.table').hidden, el.querySelector('.view-toggle').textContent]; };
        r.before = [view('timeline'), view('rtrace-timeline')];
        const button = document.querySelector('#timeline .view-toggle');
        click(button);
        r.toggled = [isTableView('timeline'), viewToggleHtml('timeline'), view('timeline'), view('rtrace-timeline'),
                     isTableView('rtrace-timeline'), document.querySelector('#timeline .view-toggle') === button];
        r.attrs = [cardViewAttrs('timeline', 'chart'), cardViewAttrs('timeline', 'table')];
        toggleCardView('timeline');
        r.back = [isTableView('timeline'), view('timeline'), cardViewAttrs('timeline', 'chart')];
        console.log(JSON.stringify(r));
    """, SORT_DOM + _const_source("cardViewState"))
    assert r["start"] is False
    assert 'class="view-toggle"' in r["chartButton"] and ">TABLE</button>" in r["chartButton"]
    assert r["before"] == [[False, True, "TABLE"], [False, True, "TABLE"]]
    assert r["toggled"][0] is True and ">CHART</button>" in r["toggled"][1]
    assert r["toggled"][2:] == [[True, False, "CHART"], [False, True, "TABLE"], False, True], \
        "the switch did not show the table, changed another card or replaced its button"
    assert r["attrs"] == [' data-view-of="timeline" data-view="chart" hidden', ' data-view-of="timeline" data-view="table"']
    assert r["back"] == [False, [False, True, "TABLE"], ' data-view-of="timeline" data-view="chart"']


def test_chart_cards_have_view_toggle():
    for name in CHART_CARDS:
        assert "viewToggleHtml(" in _function_source(name), f"{name} renders no CHART / TABLE switch"
    # In the PE analysis the switch belongs to the file map strip; the SECTIONS
    # card is a sortable table already (every number printed beside its bar)
    pe = _function_source("renderPeAnalysis")
    assert re.search(r"fileMapInlineBlock\(pe\.path, 'pe', '([\w-]+)', viewToggleHtml\('\1'\)\)", pe), \
        "the PE analysis's switch is not the file map's"
    assert pe.count("viewToggleHtml(") == 1 and "cardViewAttrs(" not in pe, "the SECTIONS card has a switch"


def test_dashboard_tiles_open_their_views():
    source = _function_source("renderDashboard")
    for needle in ("openAlertsTab(", "revealProcessList(", "switchTab('threatscan')", "openHelp(", 'role="button"'):
        assert needle in source, needle


@needs_node
def test_dashboard_tiles_count_and_open_their_lists():
    """A click or Enter / Space on a tile opens its view; a severity count of
    TOTAL ALERTS opens the Alerts tab filtered, and not the whole list as
    well. The counts take the severity in any case and count what the
    Alerts tab counts as low or info ("unknown", none) as low."""
    r = _run_node(["renderDashboard", "escapeHtml", "onTileKey"] + NEWEST_ALERTS_FUNCTIONS, r"""
        document.body.innerHTML = MARKUP;
        Element.prototype.click = function () { return click(this); };
        const calls = [];
        globalThis.renderDashboardCharts = () => {};          // the charts have tests of their own
        globalThis.openAlertsTab = filter => calls.push(['alerts', filter]);
        globalThis.revealProcessList = () => calls.push(['processes']);
        globalThis.revealSection = id => calls.push(['reveal', id]);
        globalThis.openHelp = (...args) => calls.push(['help', ...args]);
        globalThis.switchTab = name => calls.push(['tab', name]);
        const severities = ['High', 'critical', 'CRITICAL', 'Medium', 'medium', 'low', 'Low', 'info', 'unknown', undefined, '',
                            'bogus'];
        globalThis.state = { serviceStatus: {}, rustinelInfo: { rules: { sigma: 13, yara: 2 } }, processes: { 1: {}, 2: {} },
            alerts: severities.map((severity, i) => ({ id: 'a' + i, severity, rule_name: 'r', timestamp: '2026-11-09T10:00:00Z' })) };
        renderDashboard();
        const tile = name => document.querySelector('#dashboard-stats .stat-card.stat-' + name);
        const names = ['alerts', 'processes', 'services', 'rules', 'tools'];
        const r = {
            tags: [...tile('alerts').querySelectorAll('.stat-tag')].map(t => t.textContent.trim()),
            focusable: names.map(n => [tile(n).getAttribute('role'), tile(n).getAttribute('tabindex')]),
            clicks: {}, tagClicks: {}, keys: [],
        };
        for (const n of names) { click(tile(n)); r.clicks[n] = calls.splice(0); }
        for (const tag of tile('alerts').querySelectorAll('.stat-tag')) { click(tag); r.tagClicks[tag.textContent.trim()] = calls.splice(0); }
        for (const key of ['Enter', ' ', 'a', 'Tab']) {
            const ev = dispatch('keydown', tile('tools'), { key });
            r.keys.push([key, calls.splice(0), ev.defaultPrevented]);
        }
        // The keyboard focus stays on its tile when a refresh renders the tiles again
        tile('rules').focus();
        renderDashboard();
        r.focus = [document.activeElement === tile('rules'), document.activeElement.isConnected];
        console.log(JSON.stringify(r));
    """.replace("MARKUP", json.dumps(_tab_markup("dashboard"))), SORT_DOM)
    assert r["tags"] == ["3 high", "2 med", "6 low"], "the counts miss a case or the alerts the Alerts tab counts as info"
    assert r["focusable"] == [["button", "0"]] * 5
    assert r["clicks"] == {"alerts": [["alerts", {}]], "processes": [["processes"]], "services": [["reveal", "dashboard-grid"]],
                           "rules": [["help", "services", "help-detection-rules"]], "tools": [["tab", "threatscan"]]}
    assert r["tagClicks"] == {"3 high": [["alerts", {"severities": ["critical", "high"]}]],
                              "2 med": [["alerts", {"severities": ["medium"]}]],
                              "6 low": [["alerts", {"severities": ["low", "info"]}]]}, "a count also clicked its tile"
    assert r["keys"] == [["Enter", [["tab", "threatscan"]], True], [" ", [["tab", "threatscan"]], True],
                         ["a", [], False], ["Tab", [], False]]
    assert r["focus"] == [True, True], "a refresh takes the keyboard focus from the tile"


@needs_node
def test_processes_tile_reveals_the_process_list():
    """Classic: the process list of the sidebar scrolls into view and is
    marked for about a second; Cyberpunk: the drawer with the list opens."""
    r = _run_node(["revealProcessList", "revealSection", "revealElement", "currentTheme", "normalizeTheme", "openDrawer",
                   "setDrawerOpen", "isDrawerOpen"], r"""
        const timers = [];
        globalThis.setTimeout = (fn, ms) => { timers.push([fn, ms]); return timers.length; };
        globalThis.clearTimeout = () => {};
        const scrolled = [];
        El.prototype.scrollIntoView = function () { scrolled.push(this.id); };
        const section = document.getElementById('process-list-section');
        const marked = () => section.classList.contains('reveal-flash');
        const r = {};
        document.documentElement.dataset.theme = 'classic';
        revealProcessList();
        r.classic = [scrolled.splice(0), marked(), isDrawerOpen(), timers.map(t => t[1])];
        timers.splice(0).forEach(([fn]) => fn());
        r.classicLater = marked();
        document.documentElement.dataset.theme = 'cyberpunk';
        revealProcessList();
        r.cyberpunk = [scrolled.splice(0), marked(), isDrawerOpen()];
        console.log(JSON.stringify(r));
    """, _switch_prelude())
    assert r["classic"] == [["process-list-section"], True, False, [1000]]
    assert r["classicLater"] is False, "the mark stays"
    assert r["cyberpunk"] == [[], False, True]


@needs_node
def test_detection_rules_tile_opens_the_help_at_the_rules():
    r = _run_node(["openHelp", "showHelpSection", "closeHelp"], r"""
        document.body.innerHTML = BODY;
        const scrolled = [];
        Element.prototype.scrollIntoView = function () { scrolled.push(this.id); };
        const modal = document.getElementById('help-modal');
        const active = () => [[...document.querySelectorAll('.help-tab')].filter(t => t.classList.contains('active')).map(t => t.dataset.help),
                              [...document.querySelectorAll('.help-section')].filter(s => s.classList.contains('active')).map(s => s.id)];
        const r = { start: active() };
        openHelp('services', 'help-detection-rules');
        r.rules = [modal.classList.contains('hidden'), active(), scrolled.splice(0)];
        closeHelp();
        openHelp();
        r.plain = [modal.classList.contains('hidden'), active(), scrolled.splice(0)];
        showHelpSection('usage');
        r.usage = active();
        showHelpSection('nonsense');
        r.unknown = active();
        console.log(JSON.stringify(r));
    """.replace("BODY", json.dumps(_body_markup())), SORT_DOM)
    assert r["start"] == [["overview"], ["help-overview"]]
    assert r["rules"] == [False, [["services"], ["help-services"]], ["help-detection-rules"]]
    assert r["plain"] == [False, [["services"], ["help-services"]], []], "the help without a section does not stay where it was"
    assert r["usage"] == [["usage"], ["help-usage"]]
    assert r["unknown"] == r["usage"], "an unknown section hid every section"
    elements = _Elements(_read(INDEX_HTML))
    rules = elements.by_id("help-detection-rules", elements.by_id("help-services"))
    assert rules and rules["text"].strip() == "Detection Rules"


TIMELINE_TABLE_FUNCTIONS = CARD_VIEW_FUNCTIONS + CONTROL_FUNCTIONS + NEWEST_ALERTS_FUNCTIONS + [
    "renderTimeline", "timelineTableHtml", "cssToken", "formatTime", "sortTimeValue", "severitySortValue"]


@needs_node
def test_sidebar_timeline_shows_its_alerts_as_a_table():
    """TABLE lists the alerts of the bars (the 60 newest, newest first; the
    list of /api/alerts starts with the oldest) with time, severity and rule;
    a refresh renders the table again in the view and the order chosen,
    without replacing the switch."""
    r = _run_node(sorted(set(TIMELINE_TABLE_FUNCTIONS)), r"""
        (async () => {
            document.body.innerHTML = BODY;
            initCardControls();
            const alert = (i, severity, rule) => ({ id: 'a' + i, severity, rule_name: rule,
                timestamp: new Date(Date.UTC(2026, 10, 9, 23, 59, 0) - i * 1000).toISOString() });
            const alerts = [alert(0, 'High', '<img src=x onerror=alert(1)>'), alert(1, 'unknown', 'beta'), alert(2, 'low', 'Alpha')];
            for (let i = 3; i < 70; i++) alerts.push(alert(i, 'medium', 'filler ' + i));
            alerts.reverse();               // oldest first, as /api/alerts lists them: alert(0) is the newest
            globalThis.state = { alerts };
            renderTimeline(); await settle();
            const $ = id => document.getElementById(id);
            const table = () => $('timeline-table').querySelector('table');
            const rows = () => [...table().tBodies[0].rows].map(row => row.cells.map(c => c.textContent.trim()));
            const r = {};
            r.chart = [$('timeline').children.length, $('timeline').hidden, $('timeline-table').hidden];
            r.button = $('timeline-view-toggle').textContent;
            r.rows = [rows().length, rows().slice(0, 3)];
            r.rules = rows().map(row => row[2]);
            r.bars = $('timeline').children.map(bar => bar.getAttribute('title'));
            r.hostile = [table().querySelectorAll('img').length, table().tBodies[0].rows[0].cells[2].getAttribute('title')];
            r.table = [table().getAttribute('data-sort-id'), table().hasAttribute('data-sortable'),
                       [...table().tHead.rows[0].cells].map(c => c.textContent.trim())];
            const button = $('timeline-view-toggle').querySelector('.view-toggle');
            click(button);
            r.toggled = [$('timeline').hidden, $('timeline-table').hidden, button.textContent];
            click([...table().tHead.rows[0].cells].find(c => c.textContent.trim() === 'Rule')); await settle();
            r.byRule = rows().map(row => row[2]);
            state.alerts = [...alerts, alert(-1, 'Critical', 'Aardvark')];      // a new alert comes last
            renderTimeline(); await settle();
            r.refreshed = [$('timeline').hidden, $('timeline-table').hidden, $('timeline-view-toggle').querySelector('.view-toggle') === button,
                           button.textContent, rows().length];
            r.refreshedByRule = rows().map(row => row[2]);
            state.alerts = [];
            renderTimeline(); await settle();
            r.empty = [rows(), $('timeline').children.length];
            console.log(JSON.stringify(r));
        })();
    """.replace("BODY", json.dumps(_body_markup())), _view_prelude())
    assert r["chart"] == [60, False, True] and r["button"] == "TABLE"
    assert r["rows"] == [60, [["23:59:00", "high", "<img src=x onerror=alert(1)>"], ["23:58:59", "info", "beta"],
                              ["23:58:58", "low", "Alpha"]]], "the table does not start with the newest alerts"
    assert not [rule for rule in r["rules"] if rule in {f"filler {i}" for i in range(60, 70)}], \
        "the table shows the oldest alerts"
    assert r["bars"] == r["rules"], "the table shows other alerts than the bars, or in another order"
    assert r["hostile"] == [0, "<img src=x onerror=alert(1)>"], "a rule name reached the markup"
    assert r["table"] == ["timeline-alerts", True, ["Time", "Severity", "Rule"]]
    assert r["toggled"] == [True, False, "CHART"]
    rules = r["byRule"]
    assert rules.index("Alpha") < rules.index("beta") < rules.index("filler 9") < rules.index("filler 10")
    assert r["refreshed"] == [True, False, True, "CHART", 60], "a refresh dropped the view or replaced the switch"
    rules = r["refreshedByRule"]
    assert "Aardvark" in rules and "filler 59" not in rules, "a refresh did not take the newest alert in"
    assert rules.index("Aardvark") < rules.index("Alpha") < rules.index("beta"), \
        "a refresh dropped the order"
    assert r["empty"] == [[["No alerts yet."]], 0]


RTRACE_TABLE_FUNCTIONS = CARD_VIEW_FUNCTIONS + CONTROL_FUNCTIONS + [
    "renderRtraceTimeline", "rtraceTimelineTableHtml", "updateRtraceSeverityBar", "rtraceSeverityTableHtml",
    "severitySortValue", "cssToken"]


@needs_node
def test_tracing_timeline_and_severity_bar_show_their_counts_as_tables():
    """The Tracing timeline as alerts per event type (its lanes), the severity
    bar as alerts per severity; sortable, and the order survives the next
    render (every alerts poll while Tracing is open)."""
    r = _run_node(sorted(set(RTRACE_TABLE_FUNCTIONS)), r"""
        (async () => {
            document.body.innerHTML = MARKUP;
            initCardControls();
            const a = (severity, category, s) => ({ severity, category, timestamp: `2026-11-09T10:00:0${s}Z`, rule_name: 'r' + s,
                                                    engine: 'sigma' });
            const alerts = [a('High', 'process', 1), a('critical', 'network', 2), a('low', 'process', 3), a('medium', 'network', 4),
                            a('low', ['registry'], 5), a('Low', 'dns', 6), a('medium', '', 7),
                            { severity: 'low', category: 'file', timestamp: 'not a time' }];
            globalThis.state = { alerts };
            const $ = id => document.getElementById(id);
            const rows = id => [...$(id).querySelector('table').tBodies[0].rows].map(row => row.cells.map(c => c.textContent.trim()));
            const legend = document.querySelector('.rtrace-timeline-legend');
            renderRtraceTimeline(); await settle();
            const r = {};
            r.lanes = rows('rtrace-timeline-table');
            r.lanesView = [$('rtrace-timeline-bar').hidden, legend.hidden, $('rtrace-timeline-table').hidden,
                           $('rtrace-timeline-view-toggle').textContent, $('rtrace-timeline-table').querySelector('table').getAttribute('data-sort-id')];
            click($('rtrace-timeline-view-toggle').querySelector('.view-toggle'));
            r.lanesToggled = [$('rtrace-timeline-bar').hidden, legend.hidden, $('rtrace-timeline-table').hidden,
                              $('rtrace-timeline-view-toggle').textContent];
            const count = () => [...$('rtrace-timeline-table').querySelector('table').tHead.rows[0].cells].find(c => c.textContent.trim() === 'Count');
            click(count()); await settle();
            click(count()); await settle();
            r.byCount = rows('rtrace-timeline-table');
            state.alerts = [...alerts, a('low', 'file', 8), a('low', 'file', 9)];
            renderRtraceTimeline(); await settle();
            r.polled = rows('rtrace-timeline-table');
            r.polledView = [$('rtrace-timeline-bar').hidden, $('rtrace-timeline-table').hidden];

            updateRtraceSeverityBar({ alerts });
            await settle();
            r.severities = rows('rtrace-sev-table');
            r.severityView = [$('rtrace-sev-counts').hidden, $('rtrace-sev-table').hidden, $('rtrace-sev-view-toggle').textContent,
                              $('rtrace-sev-table').querySelector('table').getAttribute('data-sort-id')];
            click($('rtrace-sev-view-toggle').querySelector('.view-toggle'));
            r.severityToggled = [$('rtrace-sev-counts').hidden, $('rtrace-sev-table').hidden, $('rtrace-sev-view-toggle').textContent,
                                 $('rtrace-timeline-table').hidden];
            state.alerts = [];
            renderRtraceTimeline(); await settle();
            r.noAlerts = rows('rtrace-timeline-table');
            console.log(JSON.stringify(r));
        })();
    """.replace("MARKUP", json.dumps(_tab_markup("tracing"))), _view_prelude())
    assert r["lanes"] == [["Critical/High", "2"], ["Process", "2"], ["Network", "1"], ["DNS", "1"], ["File", "0"],
                          ["Registry", "1"]], "the table counts other alerts than the lanes"
    assert r["lanesView"] == [False, False, True, "TABLE", "rtrace-timeline-types"]
    assert r["lanesToggled"] == [True, True, False, "CHART"]
    assert r["byCount"] == [["Critical/High", "2"], ["Process", "2"], ["Network", "1"], ["DNS", "1"], ["Registry", "1"],
                            ["File", "0"]]
    assert r["polled"] == [["Critical/High", "2"], ["Process", "2"], ["File", "2"], ["Network", "1"], ["DNS", "1"],
                           ["Registry", "1"]], "the next render dropped the order"
    assert r["polledView"] == [True, False]
    assert r["severities"] == [["critical", "1"], ["high", "1"], ["medium", "2"], ["low", "4"]]
    assert r["severityView"] == [False, True, "TABLE", "rtrace-severity-counts"]
    assert r["severityToggled"] == [True, False, "CHART", False], "a switch changed another card"
    assert r["noAlerts"] == [["No alerts yet."]]


BINARY_TABLE_FUNCTIONS = CARD_VIEW_FUNCTIONS + [
    "renderDetectionOverview", "dieSectionKind", "dieSectionsTableHtml", "renderPeAnalysis", "fileMapInlineBlock",
    "fileMapInlineMount", "fileMapRegionsTableHtml", "formatSize", "sortNumberValue", "cssToken"]
# FileMapView without its canvases: the loaded map of the fixture, the tree and
# the offsets as the module writes them
FILEMAP_STUB = r"""
globalThis.renderInlineFileMap = () => {};
globalThis.FileMapView = { load: async () => (VIS), treeHtml: () => '<div class="fmap-trees"></div>',
                           hexOff: n => '0x' + (n >>> 0).toString(16).padStart(8, '0').toUpperCase() };
"""
HOSTILE = "<img src=x onerror=alert(1)>"
# Section headers need not be in file order: .data comes first here
DIE_FIXTURE = r"""
const hostile = '<img src=x onerror=alert(1)>';
const detection = { assessment: 'packed', detections: [], entropy_map: [1, 7.9], file_size: 4096,
    section_layout: [
        { name: '.data', offset: 3624, size: 60, pct_start: 88.5, pct_size: 0.2, entropy: 2.04, entropy_status: 'normal',
          executable: false, writable: true, packer: '' },
        { name: '.text', offset: 1024, size: 2048, pct_start: 25, pct_size: 50, entropy: 6.36, entropy_status: 'normal',
          executable: true, writable: false, packer: '' },
        { name: hostile, offset: 3072, size: 512, pct_start: 75, pct_size: 12.5, entropy: 7.95, entropy_status: 'high',
          executable: false, writable: false, packer: 'UPX' },
        { name: '.idata', offset: 3584, size: 40, pct_start: 87.5, pct_size: 0.1, entropy: 6.9, entropy_status: 'warn',
          executable: false, writable: false, packer: '' },
        { name: '.rdata', offset: 3684, size: 12, pct_start: 89.9, pct_size: 0.2, entropy: 1, entropy_status: 'normal',
          executable: false, writable: false, packer: '' },
    ], overlay: { offset: 3696, size: 400 } };
"""


@needs_node
def test_binary_analysis_and_pe_file_map_show_their_numbers_as_tables():
    """BINARY ANALYSIS: TABLE swaps the file structure for its sections in
    file order with their offsets (also those too small to draw, and the
    overlay); the entropy map stays. PE analysis: the switch is the file map
    strip's, whose regions become a table of name, offset, raw size,
    permissions and entropy; the SECTIONS card has none. Names from the file
    stay text; each card keeps its own choice, also over a new render."""
    vis = {"regions": [
        {"name": ".text", "kind": "section", "offset": 1024, "size": 2048, "color": "#6b7280", "priority": 0,
         "detail": {"virtual_address": "0x1000", "virtual_size": 2000, "raw_size": 2048, "permissions": "R-X", "entropy": 6.36}},
        {"name": "MSDOS Header", "kind": "msdos", "offset": 0, "size": 64, "color": "#1d4ed8", "priority": 0, "detail": {}},
        {"name": "Imports", "kind": "imports", "offset": 1024, "size": 200, "color": "#16a34a", "priority": 2,
         "detail": {"rva": "0x1000", "size": 200}},
        {"name": HOSTILE, "kind": "section", "offset": 3072, "size": 512, "color": "red;background:url(x)", "priority": 0,
         "detail": {"permissions": "RWX", "entropy": 7.951}},
        {"name": "Overlay", "kind": "overlay", "offset": 3696, "size": 400, "color": "#f97316", "priority": 1,
         "detail": {"size": 400, "entropy": 7.2}},
    ]}
    r = _run_node(sorted(set(BINARY_TABLE_FUNCTIONS)), DIE_FIXTURE + r"""
        (async () => {
            const pe = { path: 'C:\\x.exe', detection, flags: [], total_entropy: 6.1,
                file_header: { machine: 'AMD64', machine_raw: '0x8664', timestamp_utc: '2026-11-09', num_sections: 2, is_dll: false,
                               is_exe: true, characteristics: '0x22' },
                optional_header: { is_pe32_plus: true, entry_point: '0x1000', image_base: '0x140000000', linker_version: '14.38',
                                   subsystem_name: 'GUI', checksum: '0x0', checksum_valid: false, aslr: true, dep_nx: true,
                                   no_seh: false, cfg: true },
                sections: [
                    { name: '.text', virtual_address: '0x1000', virtual_size: 2000, raw_size: 2048, readable: true, writable: false,
                      executable: true, entropy: 6.36, entropy_status: 'normal', raw_offset_dec: 1024 },
                    { name: hostile, virtual_address: '0x2000', virtual_size: 600, raw_size: 512, readable: true, writable: true,
                      executable: true, rwx_warning: true, entropy: 7.95, entropy_status: 'high', packer_indicator: 'UPX',
                      raw_offset_dec: 3072 },
                ],
                imports: [], dll_count: 0, import_count: 0, exports: [], tls_callbacks: [] };
            const host = document.createElement('div');
            document.body.appendChild(host);
            const rows = table => [...table.tBodies[0].rows].map(row => row.cells.map(c => c.textContent.trim()));
            const heads = table => [...table.tHead.rows[0].cells].map(c => c.textContent.trim());
            const view = () => {
                const die = host.querySelector('.die-overview'), map = host.querySelector('.fmap-inline');
                const entropy = die.querySelector('.die-entropy-section');
                return {
                    die: [die.querySelector('.die-header .view-toggle').textContent, entropy.hidden, entropy.hasAttribute('data-view'),
                          die.querySelector('.die-layout-section').hidden, die.querySelector('.die-table-section').hidden],
                    map: [map.querySelector('.fmap-inline-head .view-toggle').textContent, document.getElementById('fmap-inline-map-pe').hidden,
                          document.getElementById('fmap-inline-table-pe').hidden],
                };
            };
            renderPeAnalysis(pe, host);
            await settle();
            const dieTable = host.querySelector('.die-table-section table');
            const mapTable = document.getElementById('fmap-inline-table-pe').querySelector('table');
            const sections = host.querySelector('.pe-section-table');
            const r = {
                start: view(),
                die: [heads(dieTable), rows(dieTable), dieTable.getAttribute('data-sort-id')],
                map: [heads(mapTable), rows(mapTable), mapTable.getAttribute('data-sort-id'), mapTable.hasAttribute('data-sortable'),
                      mapTable.querySelectorAll('.view-table-dot').length],
                sections: [sections.querySelectorAll('.view-toggle').length, sections.querySelectorAll('[data-view]').length,
                           sections.querySelectorAll('table').length],
                images: host.querySelectorAll('img').length,
            };
            click(host.querySelector('.die-header .view-toggle'));
            r.dieToggled = view();
            click(host.querySelector('.fmap-inline-head .view-toggle'));
            r.mapToggled = view();
            renderPeAnalysis(pe, host);
            r.rendered = view();
            await settle();
            r.renderedTable = document.getElementById('fmap-inline-table-pe').querySelectorAll('tbody tr').length;
            // The ELF panel: a binary analysis card of its own, and a file map without a switch
            const elf = document.createElement('div');
            document.body.appendChild(elf);
            elf.innerHTML = renderDetectionOverview(detection, 'elf') + fileMapInlineBlock('/x.elf', 'elf');
            r.elf = [elf.querySelector('.die-header .view-toggle').textContent, elf.querySelector('.die-table-section').hidden,
                     elf.querySelectorAll('.fmap-inline-head .view-toggle').length, !!document.getElementById('fmap-inline-table-elf'),
                     document.getElementById('fmap-inline-map-elf').hasAttribute('data-view')];
            console.log(JSON.stringify(r));
        })();
    """, SORT_DOM + _const_source("cardViewState") + FILEMAP_STUB.replace("VIS", json.dumps(vis)))
    dash = "\u2014"
    assert r["start"] == {"die": ["TABLE", False, False, False, True], "map": ["TABLE", False, True]}
    assert r["die"] == [["Section", "Offset", "Size", "Entropy", "Assessment"],
                        [[".text", "0x00000400", "2.0 KB", "6.36", "Code"], [HOSTILE, "0x00000C00", "512 B", "7.95", "Packer (UPX)"],
                         [".idata", "0x00000E00", "40 B", "6.90", "Suspicious Entropy"], [".data", "0x00000E28", "60 B", "2.04", "Data"],
                         [".rdata", "0x00000E64", "12 B", "1.00", "Read-only"], ["overlay", "0x00000E70", "400 B", dash, "Overlay"]],
                        "die-sections"], "not in file order, or a section, an offset or the overlay missing"
    assert r["map"] == [["Name", "Offset", "Raw Size", "Permissions", "Entropy"],
                        [["MSDOS Header", "0x00000000", "64 B", dash, dash], [".text", "0x00000400", "2.0 KB", "R-X", "6.36"],
                         ["Imports", "0x00000400", "200 B", dash, dash], [HOSTILE, "0x00000C00", "512 B", "RWX", "7.95"],
                         ["Overlay", "0x00000E70", "400 B", dash, "7.20"]],
                        "file-map-regions", True, 4], "the regions in another order or with other values"
    assert r["sections"] == [0, 0, 1], "the SECTIONS card has a switch or a second table"
    assert r["images"] == 0, "a section or region name, or a colour, reached the markup"
    assert r["dieToggled"] == {"die": ["CHART", False, False, True, False], "map": r["start"]["map"]}, \
        "TABLE hid the entropy map or switched the file map too"
    assert r["mapToggled"] == {"die": r["dieToggled"]["die"], "map": ["CHART", True, False]}
    assert r["rendered"] == r["mapToggled"] and r["renderedTable"] == 5, "a new render dropped the choice or the table"
    assert r["elf"] == ["TABLE", True, 0, False, False], "the ELF panel took the PE choices or a file map switch"


@needs_node
def test_binary_analysis_without_sections_keeps_its_entropy_map():
    """A packed or stripped ELF has no section headers (e_shnum = 0) and so no
    file structure, but its 64-block entropy map: there is nothing to switch,
    and the entropy map shows, also when TABLE was chosen for the card."""
    r = _run_node(sorted(set(BINARY_TABLE_FUNCTIONS)), r"""
        const host = document.createElement('div');
        document.body.appendChild(host);
        const entropyMap = Array.from({ length: 64 }, (_, i) => i < 8 ? 0.5 : 7.9);
        const look = detection => {
            host.innerHTML = renderDetectionOverview(detection, 'elf');
            const entropy = host.querySelector('.die-entropy-section');
            return [host.querySelectorAll('.view-toggle').length, host.querySelectorAll('[data-view]').length,
                    !!entropy && !entropy.hidden, host.querySelectorAll('.die-entropy-block').length,
                    host.querySelectorAll('.die-table-section, .die-layout-section').length, /No sections/.test(host.textContent)];
        };
        const packed = { assessment: 'packed', detections: [], entropy_map: entropyMap, section_layout: [], file_size: 16384 };
        const r = { packed: look(packed) };
        cardViewState['elf-die'] = 'table';
        r.tableChosen = look(packed);
        r.nothing = look({ assessment: 'clean', detections: [], entropy_map: [], section_layout: [] });
        console.log(JSON.stringify(r));
    """, SORT_DOM + _const_source("cardViewState") + FILEMAP_STUB.replace("VIS", "{}"))
    assert r["packed"] == [0, 0, True, 64, 0, False], "a switch, an empty table or a hidden entropy map without sections"
    assert r["tableChosen"] == r["packed"], "TABLE hid the entropy map of a file without sections"
    assert r["nothing"] == [0, 0, False, 0, 0, False]


# FileMapView with loads the test settles itself, in any order; like the
# module, one load per file for the strip, the table and the tree
FILEMAP_DEFERRED_STUB = r"""
Object.defineProperty(Node.prototype, 'firstChild', { get() { return this.childNodes[0] || null; } });
const loads = {};
const vis = file => ({ file, regions: [{ name: file + ' .text', kind: 'section', offset: 1024, size: 512, color: '#6b7280',
                                         priority: 0, detail: { permissions: 'R-X', entropy: 6.1 } }] });
globalThis.FileMapView = {
    load: file => (loads[file] = loads[file] || (() => {
        let resolve, reject;
        const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
        return { promise, resolve: () => resolve(vis(file)), reject: message => reject(new Error(message)) };
    })()).promise,
    renderStrip: (el, v) => { el.textContent = 'strip of ' + v.file; },
    legendHtml: () => '<div class="fmap-legend"></div>',
    treeHtml: v => '<div class="fmap-trees">tree of ' + v.file + '</div>',
    hexOff: n => '0x' + (n >>> 0).toString(16).padStart(8, '0').toUpperCase(),
};
"""


@needs_node
def test_inline_file_map_ignores_a_stale_load():
    """PE analysis of A, then of B before A's file map has loaded: whichever
    load finishes last, the strip, the table and the import / export tree
    all show B, and a failed load of A does not end up in B's table. The ELF
    panel's tree likewise."""
    r = _run_node(sorted(set(BINARY_TABLE_FUNCTIONS + ["renderInlineFileMap"])), r"""
        (async () => {
            const pe = path => ({ path, flags: [], total_entropy: 6.1,
                file_header: { machine: 'AMD64', machine_raw: '0x8664', timestamp_utc: '2026-11-09', num_sections: 0, is_dll: false,
                               is_exe: true, characteristics: '0x22' },
                optional_header: { is_pe32_plus: true, entry_point: '0x1000', image_base: '0x140000000', linker_version: '14.38',
                                   subsystem_name: 'GUI', checksum: '0x0', checksum_valid: true, aslr: true, dep_nx: true,
                                   no_seh: false, cfg: true },
                sections: [], imports: [], dll_count: 0, import_count: 0, exports: [], tls_callbacks: [] });
            const host = document.createElement('div');
            document.body.appendChild(host);
            const $ = id => document.getElementById(id);
            const shown = scope => {
                const table = $('fmap-inline-table-' + scope)?.querySelector('table');
                return [$('fmap-inline-map-' + scope).textContent.trim(),
                        table ? [...table.tBodies[0].rows].map(row => row.cells[0].textContent.trim())
                              : ($('fmap-inline-table-' + scope)?.textContent.trim() ?? null),
                        $('fmap-inline-trees-' + scope).textContent.trim()];
            };
            const r = {};
            renderPeAnalysis(pe('A.exe'), host);
            renderPeAnalysis(pe('B.exe'), host);
            loads['B.exe'].resolve(); await settle();
            r.b = shown('pe');
            loads['A.exe'].resolve(); await settle();
            r.aLate = shown('pe');
            // A load that fails after the next file's panel is up
            renderPeAnalysis(pe('C.exe'), host);
            renderPeAnalysis(pe('D.exe'), host);
            loads['C.exe'].reject('C.exe is gone'); await settle();
            r.cFailed = shown('pe');
            loads['D.exe'].resolve(); await settle();
            r.d = shown('pe');
            // The ELF panel (renderElfAnalysis): a file map without a table
            const elf = document.createElement('div');
            document.body.appendChild(elf);
            const elfPanel = path => { elf.innerHTML = fileMapInlineBlock(path, 'elf'); fileMapInlineMount(path, 'elf'); };
            elfPanel('E.so');
            elfPanel('F.so');
            loads['F.so'].resolve(); await settle();
            loads['E.so'].resolve(); await settle();
            r.elf = shown('elf');
            console.log(JSON.stringify(r));
        })();
    """, SORT_DOM + _const_source("cardViewState") + FILEMAP_DEFERRED_STUB)
    b = ["strip of B.exe", ["B.exe .text"], "tree of B.exe"]
    assert r["b"] == b
    assert r["aLate"] == b, "A's late file map replaced B's table or tree"
    assert r["cFailed"] == ["building planes\u2026", "building the table\u2026", ""], "C's failed load reached D's panel"
    assert r["d"] == ["strip of D.exe", ["D.exe .text"], "tree of D.exe"]
    assert r["elf"] == ["strip of F.so", None, "tree of F.so"], "E's late file map replaced F's tree"


RTRACE_EVENT_FUNCTIONS = ["renderRtraceEventTable", "initRtraceEventSort", "sortRtraceEvents", "updateRtraceEventSortHeads",
                          "rtraceEventAction", "rtraceEventSortValue", "sortItemsBy", "sortKey", "compareSortKeys",
                          "getActionBadgeClass", "getEventDetails", "formatRelativeTime", "formatTime", "escapeHtml", "jsArg",
                          "cssToken", "severitySortValue", "sortTimeValue", "alertSeverity"]


@needs_node
def test_tracing_event_grid_sorts_by_its_column_heads():
    """The event grid of Tracing (a grid of <div>s) sorts like a table: a click
    or Enter on a head, ascending then descending, numbers numerically, times
    by time, text in any case, empty values last; the order survives the
    alerts poll that renders the grid again."""
    r = _run_node(RTRACE_EVENT_FUNCTIONS, r"""
        document.body.innerHTML = MARKUP;
        initRtraceEventSort();
        const ev = (id, timestamp, pid, rule, severity, path) => ({ id, timestamp, pid, rule_name: rule, severity, engine: 'sigma',
                                                                     process_name: 'p' + pid, raw: { file: { path } } });
        const events = [ev('e1', '2026-11-09T23:59:58Z', 1000, 'beta', 'high', 'C:\\b'),
                        ev('e2', '2026-11-10T00:00:02Z', 20, 'Alpha', 'low', 'C:\\a'),
                        ev('e3', '2026-11-09T12:00:00Z', 300, 'gamma', 'Critical', 'C:\\c'),
                        ev('e4', '2026-11-09T18:00:00Z', null, 'delta', 'medium', 'C:\\d')];
        globalThis.state = { processes: { '100': { pid: 100, alerts: events, children: [] } }, rtraceSelectedPid: '100',
                             rtraceActiveDetailTab: 'live', sessionStart: Date.parse('2026-11-09T12:00:00Z') };
        const ids = () => [...document.getElementById('rtrace-event-table-body').children]
            .map(row => (/openAlertDetailById\("(\w+)"\)/.exec(row.getAttribute('onclick')) || [])[1]);
        const heads = () => [...document.querySelectorAll('.rtrace-event-table-header .rtrace-col')];
        const head = name => heads().find(h => h.textContent.trim() === name);
        const aria = () => heads().map(h => h.getAttribute('aria-sort'));
        renderRtraceEventTable();
        const r = { initial: ids(), heads: heads().map(h => [h.getAttribute('role'), h.getAttribute('tabindex')]) };
        click(head('PID')); r.pidAsc = [ids(), aria()];
        click(head('PID')); r.pidDesc = [ids(), aria()];
        events.push(ev('e5', '2026-11-09T13:00:00Z', 500, 'epsilon', 'low', 'C:\\e'));
        renderRtraceEventTable();
        r.polled = ids();
        click(head('Rule / Engine')); r.rule = ids();
        click(head('Time')); r.time = ids();
        click(head('Time')); r.timeDesc = ids();
        const key = dispatch('keydown', head('Sev'), { key: 'Enter' });
        r.sev = [ids(), aria(), key.defaultPrevented];
        dispatch('keydown', head('Details'), { key: 'a' });
        r.otherKey = aria();
        // Values from the events stay text (a PID or a time that is no number or no time)
        events.push({ id: 'e6', timestamp: '<b>bold</b>', pid: '<img src=x onerror=alert(1)>', rule_name: 'x',
                      severity: 'low', engine: 'sigma', raw: {} });
        renderRtraceEventTable();
        const body = document.getElementById('rtrace-event-table-body');
        r.hostile = [body.querySelectorAll('img').length + body.querySelectorAll('b').length,
                     body.querySelectorAll('.ev-pid').map(c => c.textContent).filter(t => t.includes('<')).length,
                     body.querySelectorAll('.ev-time').map(c => c.textContent).filter(t => t === '<b>bold</b>').length];
        console.log(JSON.stringify(r));
    """.replace("MARKUP", json.dumps(_tab_markup("tracing"))),
        SORT_DOM + _controls_prelude() + "\n" + "\n".join(_const_source(c) for c in ("ALERT_SEVERITIES", "RTRACE_EVENT_SORT_ID")))
    none = [None] * 7
    assert r["initial"] == ["e3", "e4", "e1", "e2"]
    assert r["heads"] == [["columnheader", "0"]] * 7, "a head cannot be reached with the keyboard"
    assert r["pidAsc"] == [["e2", "e3", "e1", "e4"], none[:4] + ["ascending"] + none[5:]], "PIDs sorted as text"
    assert r["pidDesc"] == [["e1", "e3", "e2", "e4"], none[:4] + ["descending"] + none[5:]], "an empty PID is not last"
    assert r["polled"] == ["e1", "e5", "e3", "e2", "e4"], "the next render dropped the order"
    assert r["rule"] == ["e2", "e1", "e4", "e5", "e3"], "rules sorted case-sensitively"
    assert r["time"] == ["e3", "e5", "e4", "e1", "e2"] and r["timeDesc"] == ["e2", "e1", "e4", "e5", "e3"]
    assert r["sev"] == [["e5", "e2", "e4", "e1", "e3"], ["ascending"] + none[1:], True]
    assert r["otherKey"] == ["ascending"] + none[1:]
    assert r["hostile"] == [0, 1, 1], "an event's PID or time reached the markup"
    # The heads are wired once at start-up (initRtraceTabs runs in DOMContentLoaded)
    assert re.search(r"^\s*initRtraceEventSort\(\);", _function_source("initRtraceTabs"), re.M)


def test_card_controls_of_task_8_are_styled_in_both_themes():
    """The view not chosen is hidden whatever display its class sets; the
    switch keeps its own look inside upper-case or monospace headings; tiles
    and the Tracing grid heads show that they take a click and the keyboard
    focus, in both themes; the sorted head's arrow outranks the idle one."""
    rules, theme = _rules(STYLE_CSS), _rules(THEME_CSS)
    assert re.search(r"display:\s*none\s*!important", rules.get("[data-view-of][hidden]", "")), "the view not chosen shows"
    assert all(re.search(p, rules.get(".view-toggle", "")) for p in
               (r"\bcolor:", r"font-family:", r"text-transform:\s*none", r"letter-spacing:")), "the switch takes a heading's look"
    for selector in (".view-toggle:hover", ".view-toggle:focus-visible", ".view-table th", ".view-table td",
                     '.stat-card[role="button"]', '.stat-card[role="button"]:hover', '.stat-card[role="button"]:focus-visible',
                     ".stat-tag-link:hover", ".reveal-flash"):
        assert selector in rules, selector
    assert re.search(r"animation:\s*tdc-reveal\b", rules[".reveal-flash"]) and "@keyframes tdc-reveal" in _read(STYLE_CSS)
    # A 300-character rule or section name ends in an ellipsis instead of widening the card
    for selector in (".view-table .view-table-text", ".view-table .view-table-clip"):
        assert all(re.search(p, rules.get(selector, "")) for p in (r"max-width:", r"overflow:\s*hidden", r"text-overflow:\s*ellipsis")), selector
    assert re.search(r"white-space:\s*nowrap", rules.get(".view-table td", ""))
    prefix = '[data-theme="cyberpunk"] '
    for selector in (".view-toggle", ".view-toggle:hover:not(:disabled)", ".view-toggle:focus-visible", ".view-table th",
                     '.stat-card[role="button"]:hover', '.stat-card[role="button"]:focus-visible'):
        assert prefix + selector in theme, prefix + selector
    head = ".rtrace-event-table-header > .rtrace-col"
    assert re.search(r"cursor:\s*pointer", rules.get(head, "")) and head + ":focus-visible" in rules
    idle = head + "::after"
    assert '"\\2195"' in rules.get(idle, "")
    for state, arrow in (("ascending", r"\25B2"), ("descending", r"\25BC")):
        selector = f'{head}[aria-sort="{state}"]::after'
        assert '"%s"' % arrow in rules.get(selector, ""), selector
        assert _specificity(selector) > _specificity(idle), f"{selector} loses to {idle}"
        assert re.search(r"\bcolor:", theme.get(prefix + selector, "")), f"no Cyberpunk colour for {selector}"
        assert _specificity(prefix + selector) > _specificity(selector)
