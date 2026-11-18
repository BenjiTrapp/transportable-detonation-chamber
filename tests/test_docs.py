"""Documentation stays in sync with the code.

Regressions covered: the README documented a /api/fibratus proxy that did not
exist, missed 17 routes and had no MCP section; the in-app help described
layouts and tabs that were gone; screenshots showed an old UI.
"""

import ast
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
README = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
APP = open(os.path.join(ROOT, "webui", "app.py"), encoding="utf-8").read()
HELP = open(os.path.join(ROOT, "webui", "templates", "index.html"), encoding="utf-8").read()


def _doc(name):
    """One page of the guide under docs/."""
    return open(os.path.join(DOCS, name), encoding="utf-8").read()


def _norm(path):
    return re.sub(r"<[^>]+>|&lt;[^&]+&gt;", "*", path).rstrip("/")


ROUTES = {_norm(p) for p in re.findall(r'@app\.route\("(/api/[^"]+)"', APP)}


def test_api_page_documents_every_route_and_nothing_else():
    """The API reference moved from the README to docs/api.md; the promise is
    the same one, against the new source: every /api/ route of webui/app.py has
    exactly one row there, and no row names a route that does not exist."""
    api = _doc("api.md")
    rows = [(m.strip(), _norm(p)) for m, p in
            re.findall(r"\|\s*([A-Z /]+?)\s*\|\s*`(/api/[^`]+)`", api)]
    documented = {p for _, p in rows}
    assert ROUTES - documented == set(), "routes missing from the docs/api.md reference"
    assert documented - ROUTES == set(), "docs/api.md documents routes that do not exist"
    # one row per method and route - a route with two methods has two rows
    twice = sorted(r for r in set(rows) if rows.count(r) > 1)
    assert twice == [], "docs/api.md has more than one row for %s" % twice


def test_help_modal_only_mentions_existing_routes():
    mentioned = {_norm(p) for p in re.findall(r"<code>(/api/[^<]+)</code>", HELP)}
    assert mentioned and mentioned <= ROUTES, mentioned - ROUTES


def test_api_page_lists_every_mcp_tool():
    """The MCP section moved to docs/api.md and took the tool count with it:
    "(N tools" is the one copy of that number, beside the server it belongs to."""
    tree = ast.parse(open(os.path.join(ROOT, "mcp", "server.py"), encoding="utf-8").read())
    tools = {f.name for f in tree.body if isinstance(f, ast.FunctionDef)
             and any(isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "tool" for d in f.decorator_list)}
    api = _doc("api.md")
    start = api.index("## MCP Server")
    end = api.find("\n## ", start + 1)
    section = api[start:end if end != -1 else len(api)]
    listed = set(re.findall(r"`(tdc_\w+)`", section))
    assert tools == listed
    assert f"({len(tools)} tools" in api


def test_images_exist_and_none_are_orphaned():
    """Every screenshot in static/ is used by the README (the showcase) or by a
    page of the guide, and every image a page names is on disk. The README
    carries its own with <img src="static/...">, a docs page as a markdown
    image ![alt](../static/...) - the wiki generator reads markdown, so a page
    that wrote HTML would show its picture as text, and a page sits one folder
    down, so without the ../ the link is broken from the page even though the
    file check (which resolves from the repository root) would be happy."""
    here = r'(?:src="|\]\()(static/[^")\s]+\.png)'
    referenced = set(re.findall(here, README))
    for page in _docs_pages():
        body = _doc(page)
        referenced |= set(re.findall(r'(?:src="|\]\()\.\./(static/[^")\s]+\.png)', body))
        stray = re.findall(here, body)
        assert stray == [], "docs/%s links %s without the ../" % (page, stray)
    for path in sorted(referenced):
        assert os.path.isfile(os.path.join(ROOT, path)), path
    on_disk = {f"static/{f}" for f in os.listdir(os.path.join(ROOT, "static")) if f.endswith(".png")}
    assert on_disk - referenced == set(), "screenshots used neither in the README nor in docs/"


def test_readme_tabs_match_the_ui():
    ui_tabs = re.findall(r'data-tab="[^"]+">([^<]+)</button>', HELP)
    start = README.index("### Web UI Tabs")
    # Bounded by the next "## " section, not the next "### ": the table is the
    # last subsection of Architecture, so a "### " bound runs past Quick Start
    # into Security Notes, and any later table row with a bold first cell
    # ("| **Wiki** | ... |" in the documentation map) joins the list of tabs.
    section = README[start:README.index("\n## ", start)]
    readme_tabs = re.findall(r"^\| \*\*([^*]+)\*\* \|", section, re.M)
    assert ui_tabs == readme_tabs


def test_help_tab_guide_covers_every_tab():
    ui_tabs = re.findall(r'data-tab="[^"]+">([^<]+)</button>', HELP)
    guide = HELP[HELP.index('id="help-usage"'):HELP.index('id="help-api"')]
    assert re.findall(r"<h4>([^<]+)</h4>", guide) == ui_tabs


WEB_UI_ASSETS = ["static/js/app.js", "static/css/style.css", "static/css/theme-layout.css",
                 "static/css/theme-cyberpunk.css"]


def test_every_deploy_path_uploads_the_web_ui_modules():
    """deploy-utm.py, the Makefile (Vagrant) and make.ps1 (Hyper-V) must ship
    the same files: a missing module is an ImportError on the VM, a missing
    script or style sheet a page without its behaviour or its theme."""
    utm = open(os.path.join(ROOT, "scripts", "deploy-utm.py"), encoding="utf-8").read()
    modules = set(re.findall(r'"webui/([\w.]+\.(?:py|json|ps1))"', utm))
    assert {"app.py", "pipe_proxy.py", "pipe_backends.py", "pipe_signatures.json"} <= modules
    # Every module app.py imports from webui/ (the FIREWALL tab brought five), and the script firewall_rules.py runs
    local = {f[:-3] for f in os.listdir(os.path.join(ROOT, "webui")) if f.endswith(".py")}
    imported = set(re.findall(r"^import (\w+)", APP, re.M)) & local
    assert {"firewall", "firewall_fetch", "firewall_rules", "firewall_store", "geoip"} <= imported
    assert {f"{m}.py" for m in imported} | {"firewall_rules.ps1"} <= modules
    make = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
    ps1 = open(os.path.join(ROOT, "make.ps1"), encoding="utf-8").read()
    vagrant = make[make.index("\ndeploy:"):make.index("\n.PHONY: deploy-app")]
    hyperv = ps1[ps1.index("'deploy' {"):ps1.index("'deploy-app' {")]
    for name in sorted(modules) + WEB_UI_ASSETS:
        win = name.replace("/", "\\")
        assert f'"webui/{name}": r"C:\\DetonationChamberUI\\{win}"' in utm, name
        assert f"webui/{name} C:\\\\DetonationChamberUI\\\\" + win.replace("\\", "\\\\") in vagrant, name
        assert f"'webui\\{win}' -Destination 'C:\\DetonationChamberUI\\{win}'" in hyperv, name


def test_every_deploy_path_ships_the_data_directories_and_the_way_out_of_isolated():
    """The FIREWALL tab reads webui/data (the offline geo index) and webui/static/data (the world map). The deploy
    paths copied named files only, so both directories are shipped whole, each file of them. tdc-unisolate.ps1 is
    the way out of ISOLATED without the web UI: a VM that only gets a deploy needs it in C:\\tdc\\scripts too."""
    utm = open(os.path.join(ROOT, "scripts", "deploy-utm.py"), encoding="utf-8").read()
    make = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
    ps1 = open(os.path.join(ROOT, "make.ps1"), encoding="utf-8").read()
    vagrant = make[make.index("\ndeploy:"):make.index("\n.PHONY: deploy-app")]
    hyperv = ps1[ps1.index("'deploy' {"):ps1.index("'deploy-app' {")]
    for local in ("data", "static/data"):
        assert os.listdir(os.path.join(ROOT, "webui", *local.split("/")))
        win = local.replace("/", "\\")
        assert f'"webui/{local}": r"C:\\DetonationChamberUI\\{win}"' in utm, local
        assert f"webui/{local}/*" in vagrant, local
        assert f"'{win}'" in hyperv and "Get-ChildItem \"webui\\$dataDir\" -File" in hyperv, local
    assert "DATA_FILES" in utm[utm.index("def do_deploy"):]
    assert 'os.path.join(REPO, "scripts", "tdc-unisolate.ps1")' in utm
    assert "scripts/tdc-unisolate.ps1" in vagrant and "'scripts\\tdc-unisolate.ps1'" in hyperv
    # deploy-app ships app.py and its modules; without the data and the hatch it would leave a tab with no geo
    # data and no way out of ISOLATED (review m-4)
    vagrant_app = make[make.index("\ndeploy-app:"):make.index("\n.PHONY: restart")]
    hyperv_app = ps1[ps1.index("'deploy-app' {"):ps1.index("'restart' {")]
    for local in ("data", "static/data"):
        assert f"webui/{local}/*" in vagrant_app and f"'{local.replace('/', chr(92))}'" in hyperv_app, local
    assert "scripts/tdc-unisolate.ps1" in vagrant_app and "'scripts\\tdc-unisolate.ps1'" in hyperv_app
    # The geo index is not held open by the web UI any more (geoip maps a copy), so no path stops it to deploy
    for path in (utm, vagrant, hyperv):
        assert "Stop-Process" not in path.replace(utm[utm.index("RESTART_PS"):utm.index("LOGS_PS")], "")


# The offline wiki is built on the host by `make docs` and git-ignored, so it is
# the one file of the Web UI that a deploy may not find. The VM has no network
# at all - no GitHub, no documentation site - so when it is there it has to go
# up with the rest.
WIKI = "webui/static/wiki.html"
# What each path says when it did not find the wiki. Round 1, Important 2: this
# used to be a search for a line holding "docs" and "wiki", which the comments
# above the uploads satisfy - the hints could be deleted from the code and the
# test stayed green. The message itself is pinned now, each in its own path's
# wording, because that is what the person running the deploy reads.
WIKI_HINTS = {
    "scripts/deploy-utm.py": '" - build the wiki with: make docs"',
    "Makefile": 'echo "[deploy] no webui/static/wiki.html - build the wiki with: make docs"',
    "make.ps1": '"[deploy] no webui\\static\\wiki.html - build the wiki with: .\\make.ps1 docs"',
}


def test_every_deploy_path_uploads_the_wiki():
    """All three deploy paths carry webui/static/wiki.html to the VM when it
    exists, and none of them fails when it does not.

    The file is generated and git-ignored: a fresh clone has none until someone
    runs `make docs`, and a deploy that stopped there would leave the VM without
    its app.py over a missing documentation file. Each path therefore guards the
    upload with an existence check and says, in so many words, how to build what
    it did not find.
    """
    utm = open(os.path.join(ROOT, "scripts", "deploy-utm.py"), encoding="utf-8").read()
    make = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
    ps1 = open(os.path.join(ROOT, "make.ps1"), encoding="utf-8").read()

    # 1. deploy-utm.py: one more entry in FILES, which the loop skips when the
    # file is not on disk (that guard is what makes the entry safe)
    assert f'WIKI_FILE = "{WIKI}"' in utm and \
        'WIKI_FILE: r"C:\\DetonationChamberUI\\static\\wiki.html"' in utm, \
        "deploy-utm.py does not carry the wiki"
    assert "if not os.path.isfile(os.path.join(REPO, local)):" in utm, \
        "deploy-utm.py no longer skips a file that is not there"
    # The remote copy keeps the date of the file it is a copy of, so the help on
    # the VM dates the wiki and not the deploy (round 1, Important 1)
    assert "LastWriteTimeUtc" in utm and "FromUnixTimeSeconds" in utm, \
        "the UTM deploy lets the download stamp the file with the deploy's clock"
    assert "os.path.getmtime(os.path.join(REPO, local))" in utm, \
        "the preserved date does not come from the host's file"

    # 2. the Makefile (Vagrant): the upload stands behind a test for the file,
    # and the else branch says how to build it, so the recipe runs on either way
    vagrant = make[make.index("\ndeploy:"):make.index("\n.PHONY: deploy-app")]
    assert f"[ -f {WIKI} ]" in vagrant, \
        "the Makefile's deploy does not look for the wiki before uploading it"
    assert f"vagrant upload {WIKI} " in vagrant, "the Makefile's deploy does not carry the wiki"
    assert vagrant.index(f"[ -f {WIKI} ]") < vagrant.index(f"vagrant upload {WIKI} "), \
        "the Makefile uploads the wiki before it has looked for it"
    upload = vagrant[vagrant.index(f"vagrant upload {WIKI} "):]
    line = upload[:upload.index("\n")]
    assert "C:\\\\DetonationChamberUI\\\\static\\\\wiki.html" in line, line
    # 15 MB over the network can fail; the install scripts after it and the
    # "Done." line must not be lost with it (round 1, Minor 3 - icon.png one
    # line above has carried its `|| true` since it was added)
    assert "||" in line, \
        "a failed wiki upload aborts the rest of the deploy: %s" % line.strip()

    # 3. make.ps1 (Hyper-V)
    hyperv = ps1[ps1.index("'deploy' {"):ps1.index("'deploy-app' {")]
    assert "Test-Path 'webui\\static\\wiki.html'" in hyperv, \
        "make.ps1 uploads the wiki unguarded"
    assert ("Copy-Item 'webui\\static\\wiki.html' -Destination "
            "'C:\\DetonationChamberUI\\static\\wiki.html'") in hyperv, \
        "make.ps1 does not carry the wiki"

    # Each path says how to build what it did not find - the message, not a
    # comment that happens to hold the same words
    for where, hint in WIKI_HINTS.items():
        text = {"scripts/deploy-utm.py": utm, "Makefile": vagrant, "make.ps1": hyperv}[where]
        assert hint in text, "%s does not tell anybody how to build the wiki: %s" % (where, hint)


def test_rizin_page_rows_say_what_the_server_answers():
    """Follow-up findings 1 and 2: the flags row claimed that over the 32 MB cap "Tab completes the
    function names"; the server answers names: [], common: "" and truncated: true then, and the UI's Tab
    lists the names of its function list without completing one (tests/test_rizin_ui.py). The function
    list itself has no such cap any anymore: it reads rizin's afl, whose rows are about 63 B each.

    Review, Minors 3 and 4: the other views are not without a limit (they carry their own, and a view
    over it answers 500), and FUNCTIONS does have the row cap - only no 32 MB one.

    The rows now live in docs/api.md, which is where every route has to have its
    one row (test_api_page_documents_every_route_and_nothing_else); the limits
    the tab itself carries live in docs/rizin.md, the page about the tab."""
    api = _doc("api.md")
    rizin = _doc("rizin.md")
    rows = {path: line for line in api.splitlines()
            for path in re.findall(r"`(/api/rizin/[^`]+)`", line)}
    flags = rows["/api/rizin/<sid>/flags"]
    assert "completes the function names" not in flags, flags
    assert "without completing" in flags and "truncated" in flags, flags
    functions = rows["/api/rizin/<sid>/functions"]
    assert "`afl`" in functions and "200 000" in functions, functions
    # The error list names the lists that the cap refuses, and the limit the other views carry
    errors = next(line for line in api.splitlines() if line.startswith("One rizin session per opened file"))
    assert "too many strings to list here" in errors
    assert "the other views have no such limit" not in errors, errors
    assert "is larger than" in errors, errors
    # The Limitations bullet does not read as if the function list had no cap at all
    limits = next(line for line in rizin.splitlines() if "FUNCTIONS has no" in line)
    assert "no 32 MB limit" in limits, limits


def test_help_lists_every_pipe_interception_route():
    routes = set()
    for m in re.finditer(r'@app\.route\("(/api/pipes/intercept[^"]*)"(?:, methods=\[([^\]]*)\])?', APP):
        for method in re.findall(r'"(\w+)"', m.group(2) or '"GET"'):
            routes.add((method, _norm(m.group(1))))
    assert len(routes) == 8
    rows = {(m, _norm(p.replace("&lt;", "<").replace("&gt;", ">"))) for m, p in re.findall(
        r'<td class="api-\w+">(\w+)</td><td><code>(/api/pipes/intercept[^<]*)</code>', HELP)}
    assert routes <= rows, routes - rows
    assert '<td class="api-delete">DELETE</td>' in HELP


def test_help_lists_every_firewall_route():
    routes = set()
    for m in re.finditer(r'@app\.route\("(/api/firewall/[^"]*)"(?:, methods=\[([^\]]*)\])?', APP):
        for method in re.findall(r'"(\w+)"', m.group(2) or '"GET"'):
            routes.add((method, _norm(m.group(1))))
    assert len(routes) == 15
    rows = {(m, _norm(p.replace("&lt;", "<").replace("&gt;", ">"))) for m, p in re.findall(
        r'<td class="api-\w+">(\w+)</td><td><code>(/api/firewall/[^<]*)</code>', HELP)}
    assert rows == routes


# A reader lands on a page either from the index or from the "Next:" of the page
# before it, so a page nobody links to is a page nobody reads. Shape: an H1, one
# sentence saying what the page answers, and a single "Next:" at the end.
NEXT = re.compile(r"^\*\*Next:\*\* \[[^\]]+\]\(([A-Za-z0-9_.-]+\.md)\)$", re.M)


def _docs_pages():
    """Every page of the guide. docs/superpowers/ holds designs and plans, not
    the guide, so only the files directly under docs/ count."""
    return sorted(f for f in os.listdir(DOCS)
                  if f.endswith(".md") and os.path.isfile(os.path.join(DOCS, f)))


def _page_links(text):
    """Links to another page of the guide: a bare file name, so `../README.md`
    (the repository README) and web links are left out."""
    return re.findall(r"\]\(([A-Za-z0-9_-]+\.md)\)", text)


def _docs_section(text, title):
    start = text.index(title)
    end = text.find("\n#", start)
    return text[start:end if end != -1 else len(text)]


def test_every_docs_page_is_reachable_and_shaped():
    pages = _docs_pages()
    assert "README.md" in pages, "docs/ needs an index page"
    index = open(os.path.join(DOCS, "README.md"), encoding="utf-8").read()
    linked = _page_links(index)
    for page in pages:
        if page != "README.md":
            assert page in linked, "docs/%s is not linked from docs/README.md" % page
    for target in set(linked):
        assert target in pages, \
            "docs/README.md links to docs/%s, which does not exist" % target
    assert not NEXT.search(index), "the index starts the paths, it needs no Next"
    for page in pages:
        body = open(os.path.join(DOCS, page), encoding="utf-8").read()
        lines = body.splitlines()
        assert lines[0].startswith("# "), "docs/%s needs its title as the first line" % page
        intro = ""
        for line in lines[1:]:
            if line.strip():
                intro = (intro + " " + line.strip()).strip()
            elif intro:
                break
        assert intro.endswith(".") and not intro.startswith(("#", "-", "|", ">", "*", "`")), \
            "docs/%s needs a sentence under its title: %r" % (page, intro)
        if page == "README.md":
            continue
        targets = NEXT.findall(body)
        assert len(targets) == 1, \
            "docs/%s needs exactly one **Next:** line, found %d" % (page, len(targets))
        assert targets[0] in pages, \
            "docs/%s points on to docs/%s, which does not exist" % (page, targets[0])
        last = [l for l in lines if l.strip()][-1]
        assert NEXT.match(last), "the **Next:** of docs/%s is not its last line: %r" % (page, last)


def test_the_index_names_both_reading_paths():
    index = open(os.path.join(DOCS, "README.md"), encoding="utf-8").read()
    assert index.index("Set it up") < index.index("Work with it"), \
        "setting it up comes before working with it"
    assert _page_links(_docs_section(index, "Set it up")) == \
        ["setup.md", "installation.md", "configuration.md"]
    work = _page_links(_docs_section(index, "Work with it"))
    assert work == ["workflow.md", "memory.md", "pipes.md", "rizin.md", "logs.md",
                    "firewall.md", "updates.md", "web-ui.md", "api.md"], work


# Every "##"/"###"/"####" title the README carried before the guide was split
# out of it (commit 2d5aa41, 2367 lines), in its own order. Three are not in the
# list, each because the design renames or drops the title itself, not what
# stood under it: "Table of Contents", which was navigation and is the index's
# job now; "Usage", which is the page docs/workflow.md; and "Features", which is
# the showcase's "What it does" - the eight to ten features are held by
# test_readme_is_a_showcase instead, which counts them and their pictures.
OLD_README_SECTIONS = [
    "Quick Start",
    "Option A: Local UI Only (no VM)",
    "Option B: Full VM (recommended for analysis)",
    "Detection Engines",
    "Web UI Tabs",
    "Themes",
    "Charts",
    "Own dashboards",
    "ETW Browser",
    "Binary Analysis (PE / ELF)",
    "Reverse Engineering Tools",
    "Tests",
    "Developer Experience",
    "Architecture",
    "Data Flow",
    "Services",
    "Platform Support",
    "ARM64 Compatibility",
    "Prerequisites",
    "Windows Host",
    "macOS Host (Apple Silicon)",
    "Recommended Setup (UTM + automated provisioning)",
    "Alternative: Vagrant/QEMU (headless, experimental)",
    "Local Development Only",
    "Installation",
    "Using make / make.ps1",
    "Manual Installation",
    "Detonation Workflow",
    "CLI Submission",
    "Scanner Workflow",
    "PE Analysis",
    "ELF Analysis",
    "Hunt-Sleeping-Beacons",
    "Live Memory Analysis",
    "What runs after a detonation",
    "How findings become a verdict",
    "Before the first detonation (clean box)",
    "ARM64 hosts",
    "Limitations",
    "Named Pipes",
    "A: Observation (passive, from Sysmon)",
    "B: Interception (active, pipe-intercept style)",
    "Rizin",
    "Opening a file",
    "One place in every view",
    "Console without a shell",
    "Sessions",
    "Projects",
    "Tool Updates",
    "What is checked",
    "Pinned tools",
    "Maintenance mode",
    "Scripts and logs",
    "Logs",
    "Demo",
    "Service Dashboard (Telemetry theme)",
    "Cyberpunk Theme (default)",
    "Alerts",
    "Dashboard & Alerts Charts",
    "Own Dashboard Tiles",
    "Detonation Results",
    "Tracing Console & Alert Detail",
    "Process Graph",
    "PE Analysis, Hex Editor & File Map",
    "Rizin (Reverse Engineering)",
    "Live Process Memory",
    "Sysmon & ETW",
    "API Reference",
    "Core",
    "Submission & Detonation",
    "Named Pipe Interception",
    "Hex Editor & Binary Analysis",
    "Sysmon",
    "Scanner",
    "Live Memory",
    "Proxy Endpoints",
    "Dashboards",
    "MCP Server",
    "Configuration",
    "Environment Variables (Web UI)",
    "Custom Detection Rules",
    "Sysmon Pipe Events",
    "Defender Exclusions",
    "Detection Rules",
    "File Structure",
    "VM File Layout",
    "Troubleshooting",
    "Check service status",
    "Services not starting",
    "Port forwarding not working (Hyper-V)",
    "Web UI not loading",
    'Web UI answers 403 "Host not allowed" or "Cross-site request rejected"',
    "Rustinel not detecting events",
    "macOS: QEMU won't start",
    "Local install fails",
    "Security Notes",
    "Web UI hardening",
    "Credits",
]

HEADING = re.compile(r"^#{1,4} (.+?)\s*$")


def _heading_titles(text):
    """The headings of a markdown file, as written. Lines inside a fenced block
    are not headings: the README's code samples are full of "# macOS / Linux"."""
    out, fence = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fence = not fence
        elif not fence:
            m = HEADING.match(line)
            if m:
                out.append(m.group(1))
    return out


def _headings(text):
    """The same, lower-cased, for the "nothing was lost" comparison."""
    return {t.lower() for t in _heading_titles(text)}


def _slug(title):
    """GitHub's anchor for a heading: lower case, everything but word
    characters, spaces and hyphens dropped, then spaces as hyphens. "Sysmon &
    ETW" is #sysmon--etw, because the & leaves its space behind."""
    return re.sub(r"[^\w\s-]", "", title.strip().lower()).replace(" ", "-")


ANCHOR_LINK = re.compile(r"\]\(([A-Za-z0-9_./-]*)#([A-Za-z0-9_-]+)\)")


def test_every_anchor_link_points_at_a_heading():
    """A pointer at a section has to land on that section. The guide's pages
    point across files now - a screenshot named in rizin.md or logs.md lives in
    web-ui.md, the routes behind the dashboards in api.md - and an anchor that
    names no heading silently drops the reader at the top of the page instead.
    On web-ui.md, 557 lines long, that is hundreds of lines from what was
    meant, with nothing to say that it went wrong.

    The file is checked too, not only the anchor: _page_links (the bare-link
    regex the reachability test uses) does not match a link that carries an
    anchor, so until this test resolved the path, a typo in the file name of an
    anchored link - ](web-io.md#charts) - was held by no test at all."""
    files = {"README.md": README}
    for page in _docs_pages():
        files["docs/" + page] = _doc(page)
    slugs = {name: {_slug(t) for t in _heading_titles(text)} for name, text in files.items()}
    checked, bad = 0, []
    for name, text in files.items():
        for target, anchor in ANCHOR_LINK.findall(text):
            if target.startswith(("http:", "https:", "mailto:")):
                continue
            path = name if not target else \
                os.path.normpath(os.path.join(os.path.dirname(name), target))
            if path in slugs:
                checked += 1
                if anchor not in slugs[path]:
                    bad.append("%s -> %s#%s: no heading of that name in %s"
                               % (name, target or "this page", anchor, path))
            elif path.startswith("..") or not os.path.isfile(os.path.join(ROOT, path)):
                bad.append("%s -> %s#%s: there is no file %s"
                           % (name, target, anchor, path))
            # else: a file of the repository that is not a page of the guide,
            # so there are no headings to match the anchor against
    assert bad == [], bad
    # Same-page anchors are cheap; the guide's pointers that can rot are the
    # ones across files (22 of the 27 today), so both are counted. A floor
    # under the total alone passed while every cross-file pointer lost its
    # anchor, because one page's own table of contents made up the number.
    cross = sum(1 for name, text in files.items()
                for target, _ in ANCHOR_LINK.findall(text)
                if target and not target.startswith(("http:", "https:", "mailto:"))
                and (os.path.normpath(os.path.join(os.path.dirname(name), target)) in slugs))
    assert checked >= 24 and cross >= 18, \
        "only %d anchor links checked, %d of them into another file - " \
        "did they lose their anchors?" % (checked, cross)


# "see below", "described above": the README said this of sections that are in
# docs/ now, so the words point at nothing. Any case, and the passive wording
# too - the finding of round 1 was one prose "(see below)" that the sweep for
# ](#anchor) links could not see.
STALE_POINTER = re.compile(r"\b(?:see|described|shown|listed|explained)\s+(?:above|below)\b", re.I)


def test_the_readme_points_at_the_guide_for_what_left_it():
    """Ten cross-references of the tab table named a section of the README that
    the split moved into docs/. Nine of them were anchors, which an anchor
    sweep finds; the ETW row said "(see below)" in prose, so it kept pointing
    at a section that is not in the file any more.

    A link that names a section needs that section's anchor: its text says
    "Charts" or "ETW Browser", and landing at the top of web-ui.md instead is
    the defect, not the fix. A link whose text is the target page's own title
    ("Logs" -> docs/logs.md) is already where it says it goes."""
    start = README.index("### Web UI Tabs")
    table = README[start:README.index("\n## ", start)]
    stale = STALE_POINTER.search(table)
    assert not stale, \
        "the tab table says %r of a README section that moved into docs/" % (
            stale.group(0) if stale else "")
    rows = {m.group(1): m.group(0) for m in re.finditer(r"^\| \*\*([^*]+)\*\* \|.*$", table, re.M)}
    titles = {"docs/" + p: _heading_titles(_doc(p))[0].lower() for p in _docs_pages()}
    for tab in ("Dashboard", "Alerts", "LOGS", "ETW", "Rizin"):
        links = re.findall(r"\[([^\]]+)\]\((docs/[a-z0-9-]+\.md)(#[a-z0-9-]*)?\)", rows[tab])
        assert links, "the %s row has no link into the guide: %s" % (tab, rows[tab])
        for text, page, anchor in links:
            assert page in titles, "the %s row links %s, which is not a page" % (tab, page)
            if text.lower() == titles[page]:
                continue      # it names the whole page, which is where it lands
            assert anchor not in ("", "#"), \
                "the %s row points at %r of %s, a section, without its anchor" % (tab, text, page)


# The help modal, as a reader sees it: without the tags, so a pointer split
# over an element ("see <a ...>below</a>") is found like any other.
HELP_TEXT = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", HELP))
# The API page of the offline wiki, which is on the VM when the wiki is.
WIKI_API_PAGE = "/static/wiki.html#api"


def test_the_help_points_where_a_reader_on_the_vm_can_follow():
    """The help modal and the built wiki are the only two documents a reader on
    the VM has: that machine has no network, no GitHub and no checkout, and no
    deploy path carries the README to it. A pointer in the help therefore has
    to name something on that machine.

    Round 4, Important 1: the API section said "the full reference with all
    endpoints is in the README", and this branch moved the endpoint table into
    docs/api.md (commit 225d09c) - so the sentence named a file the reader
    cannot open for a table that is not in it either. The same gate the
    README's tab table has (STALE_POINTER) runs over the help as well now, so
    the next prose pointer at something that moved fails here.
    """
    assert "README" not in HELP, \
        "the help points at the README, which is on no VM: %r" % (
            HELP_TEXT[max(0, HELP_TEXT.index("README") - 120):
                      HELP_TEXT.index("README") + 60] if "README" in HELP_TEXT else "")
    stale = STALE_POINTER.search(HELP_TEXT)
    assert not stale, \
        "the help says %r of a section that may not be there any more" % (
            stale.group(0) if stale else "")
    api = HELP[HELP.index('id="help-api"'):HELP.index('id="help-architecture"')]
    assert WIKI_API_PAGE in api, \
        "the API section does not lead to the wiki's API page, the one reference a VM has"
    assert "docs/api.md" in api, \
        "the API section does not name the page in the repository, for a reader on the host"


def test_the_help_and_the_guide_name_the_fibratus_path_the_installer_uses():
    """Round 4, Important 1: the help's File Layout named C:\\tools\\fibratus\\,
    a path that exists nowhere. scripts/install-fibratus.ps1 installs into
    $env:ProgramFiles\\Fibratus, and webui/app.py and webui/tool_updates.py look
    for the binary under C:\\Program Files\\Fibratus\\Bin. The same claim was
    corrected in docs/troubleshooting.md and left standing in the help, which
    is the document a reader on the VM has - so both are held here, against
    the installer rather than against each other."""
    install = open(os.path.join(ROOT, "scripts", "install-fibratus.ps1"),
                   encoding="utf-8").read()
    assert '$fibratusInstallDir = "$env:ProgramFiles\\Fibratus"' in install, \
        "install-fibratus.ps1 installs somewhere else now; the documents follow it"
    assert r"C:\Program Files\Fibratus\Bin\fibratus.exe" in APP, \
        "webui/app.py no longer looks for Fibratus under Program Files"
    for where, text in (("webui/templates/index.html", HELP),
                        ("docs/troubleshooting.md", _doc("troubleshooting.md")),
                        ("README.md", README)):
        assert "tools\\fibratus" not in text.lower(), \
            "%s names C:\\tools\\fibratus\\, where Fibratus is not installed" % where
    for where, text in (("webui/templates/index.html", HELP),
                        ("docs/troubleshooting.md", _doc("troubleshooting.md"))):
        assert r"C:\Program Files\Fibratus" in text, \
            "%s does not say where Fibratus is" % where


# Every TDC_ setting the Web UI reads has a row in docs/configuration.md.
# TDC_NO_BACKGROUND is the exception: it is a test hook (the suite sets it so
# no loader thread starts), not something anybody deploys with. Only reads
# count - webui/dev_server.py *sets* TDC_MOCK_SERVICES for its --mock flag,
# which is not a setting a reader of the page would ever put in an environment.
ENV_TEST_HOOKS = {"TDC_NO_BACKGROUND"}
ENV_READ = re.compile(r'environ\.get\(\s*["\'](TDC_\w+)["\']'
                      r'|environ\[\s*["\'](TDC_\w+)["\']\s*\](?!\s*=)')


def test_the_configuration_page_documents_every_setting_the_code_reads():
    """Round 4, Important 5: `TDC_VM_IP` is read in webui/app.py and stood in
    no table, while `TDC_ALLOWED_HOSTS`, `TDC_VM_WEBUI` and
    `TDC_VM_USER`/`TDC_VM_PASS` are documented - so the host-side set read as
    complete and was not. Whoever set only `TDC_VM_WEBUI` got an instance whose
    WinRM calls went to the hard-coded fallback.

    Both directions: a setting the code reads needs its row, and a row needs a
    setting that is read (the round-3 defect was a documented `VM_WEBUI_URL`
    that nothing ever looked up)."""
    read = set()
    for name in sorted(os.listdir(os.path.join(ROOT, "webui"))):
        if name.endswith(".py"):
            source = open(os.path.join(ROOT, "webui", name), encoding="utf-8").read()
            read |= {name for group in ENV_READ.findall(source) for name in group if name}
    assert "TDC_VM_IP" in read, "webui/ no longer reads TDC_VM_IP; drop it from the page"
    page = _doc("configuration.md")
    rows = set()
    for line in page.splitlines():
        if line.startswith("| `"):
            rows |= set(re.findall(r"`(TDC_\w+)`", line.split("|")[1]))
    missing = sorted(read - rows - ENV_TEST_HOOKS)
    assert missing == [], \
        "docs/configuration.md has no row for %s, which webui/ reads" % missing
    stale = sorted(rows - read)
    assert stale == [], \
        "docs/configuration.md documents %s, which nothing reads" % stale
    # The fallback is the part that confuses people: an unset TDC_VM_IP does
    # not mean "no VM", it means this address (webui/app.py's _detect_vm_ip)
    fallback = re.search(r'VM_IP = "([\d.]+)"\s+# Fallback', APP)
    assert fallback, "webui/app.py no longer falls back to a fixed VM address"
    row = next(l for l in page.splitlines() if l.startswith("| `TDC_VM_IP`"))
    assert fallback.group(1) in row, \
        "the TDC_VM_IP row does not name the fallback %s: %s" % (fallback.group(1), row)


def test_the_security_notes_are_reachable_from_the_vm():
    """Round 4, Important 3: "treat it as compromised", "snapshot before each
    detonation" and "the Web UI has no login - keep it on an isolated network"
    stood in the README alone. The README is not a page of the guide and not a
    page of the wiki, and no deploy path carries it - so the most operational
    text in the repository was unreachable from the machine it is about.

    The full text is a section of docs/configuration.md now, the page about how
    the thing is run, and that section is the authority; the README keeps its
    title, the one sentence that has to be read before anything else, and a
    pointer at the page."""
    page = _doc("configuration.md")
    notes = _section_of(page, "Security Notes")
    for promise in ("treat it as compromised", "snapshot", "isolated network",
                    "no login", "Cross-site requests", "DNS rebinding",
                    "TDC_ALLOWED_HOSTS", "WEBUI_HOST=127.0.0.1",
                    "Rustinel active response"):
        assert promise in notes, \
            "the Security Notes of docs/configuration.md do not carry %r" % promise
    assert "### Web UI hardening" in notes, \
        "the hardening list is not a part of that section"
    # The README keeps the title and the warning, and points at the page
    section = _section_of(README, "Security Notes")
    assert "treat it as compromised" in section, \
        "the showcase drops the one sentence a reader has to see first"
    assert re.search(r"\]\(docs/configuration\.md#security-notes\)", section), \
        "the README's Security Notes do not point at the page that carries them"
    assert "### " not in section, \
        "the README keeps the short form; the hardening list lives on the page"
    assert len([l for l in section.splitlines() if l.strip()]) <= 14, \
        "the README's Security Notes are the short form, not the text again"


def test_the_file_tree_names_every_web_ui_module():
    """Round 4, Minor 4: the tree of docs/troubleshooting.md omitted
    webui/dashboards.py, which all three deploy paths ship. Both directions,
    which is cheap here: every webui/*.py on disk has a line in the tree, and
    every .py the tree names is a file of this repository - so a module added
    to the Web UI (and to the deploy paths, which
    test_every_deploy_path_uploads_the_web_ui_modules holds) cannot be missing
    from the one listing that claims to be the file structure."""
    tree = _docs_section(_doc("troubleshooting.md"), "## File Structure")
    modules = sorted(f for f in os.listdir(os.path.join(ROOT, "webui"))
                     if f.endswith(".py"))
    missing = [m for m in modules if m not in tree]
    assert missing == [], \
        "the file tree of docs/troubleshooting.md does not name webui/%s" % missing
    on_disk = set()
    for where, _, files in os.walk(ROOT):
        if any(part.startswith((".", "node_modules")) for part in
               os.path.relpath(where, ROOT).split(os.sep)):
            continue
        on_disk |= {f for f in files if f.endswith(".py")}
    named = set(re.findall(r"([\w.-]+\.py)", tree))
    assert named <= on_disk, \
        "the file tree names %s, which is not a file of the repository" % sorted(named - on_disk)


def test_the_make_table_names_targets_that_exist():
    """Round 4, Minor 6: the table of docs/installation.md did not list `docs`,
    the target that builds the one documentation a reader on the VM has. Every
    target it names has to exist in the Makefile and in make.ps1's ValidateSet,
    or the reader runs a command that answers with a usage message."""
    page = _doc("installation.md")
    table = _docs_section(page, "## Using make / make.ps1")
    named = re.findall(r"^\| `([a-z][a-z-]*)", table, re.M)
    assert "docs" in named, \
        "the make table does not list `docs`, which builds the offline wiki"
    make = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
    targets = set(re.findall(r"^\.PHONY:\s*([\w-]+)", make, re.M))
    ps1 = open(os.path.join(ROOT, "make.ps1"), encoding="utf-8").read()
    start = ps1.index("[ValidateSet(")
    allowed = set(re.findall(r"'([\w-]+)'", ps1[start:ps1.index(")]", start)]))
    for target in named:
        assert target in targets, \
            "docs/installation.md names `make %s`, which the Makefile has not" % target
        assert target in allowed, \
            "docs/installation.md names `%s`, which make.ps1 refuses" % target


def test_the_utm_deploy_keeps_the_date_of_every_file_it_copies():
    """Round 4, Minor 7: the date preservation was written for the wiki and
    applied to every deployed file. Keeping it is right - a copy that carries
    the date of its original tells the truth about what is on the VM, for app.py
    as much as for wiki.html - but then it is not a wiki-only rule, and the
    help may not say that a deploy renews the date (it does on the Vagrant and
    Hyper-V paths, not on this one). Held here so the next edit cannot narrow
    it back to the wiki unnoticed: the mtime is read and written in the loop
    over all files, not inside a branch for one of them."""
    source = open(os.path.join(ROOT, "scripts", "deploy-utm.py"), encoding="utf-8").read()
    tree = ast.parse(source)
    deploy = next(n for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name == "do_deploy")
    loop = next(n for n in ast.walk(deploy) if isinstance(n, ast.For)
                and "FILES" in ast.dump(n.iter))
    assigned = {}
    for statement in loop.body:          # the loop's own body, no branch of it
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = ast.dump(statement.value)
    assert "mtime" in assigned and "getmtime" in assigned["mtime"], \
        "the UTM deploy reads the host file's date somewhere else than once per file"
    assert "ps" in assigned and "LastWriteTimeUtc" in assigned["ps"], \
        "the remote command that stamps the copy is not built for every file"


# --- The numbers the guide quotes -------------------------------------------
# A page that writes a number out by hand goes stale silently when the constant
# behind it moves, and on the VM there is no second source to check it against:
# the exit-capture window alone stands in three places (docs/workflow.md,
# docs/memory.md and a node of the detonation diagram). Pinned here is the
# phrase, not only the number, so a page that drops the sentence fails as
# loudly as one that keeps a stale number. Diagram nodes count: the phrase of
# docs/workflow.md is inside its mermaid block.
QUOTED_NUMBERS = [
    ("webui/app.py", "EXIT_CAPTURE_WINDOW", lambda v: "%d" % v,
     [("docs/workflow.md", "for a window of %s s"),
      ("docs/memory.md", "Armed per image name for %s s")]),
    ("webui/memory_evidence.py", "VERDICT_SUSPICIOUS", lambda v: "%.1f" % v,
     [("docs/memory.md", "%s suspicious"),            # the verdict diagram
      ("docs/memory.md", "score \u2265 %s SUSPICIOUS")]),
    ("webui/memory_evidence.py", "VERDICT_MALICIOUS", lambda v: "%.1f" % v,
     [("docs/memory.md", "%s malicious"),
      ("docs/memory.md", "\u2265 %s MALICIOUS")]),
    ("webui/rizin_sessions.py", "BIG_FILE", lambda v: "%d MB" % (v // (1024 * 1024)),
     [("docs/rizin.md", "up to %s"),                  # prose and the state diagram
      ("README.md", "up to %s")]),
    ("webui/pipe_proxy.py", "MAX_LIVE_SESSIONS", lambda v: "%d" % v,
     [("docs/pipes.md", "at most %s live sessions"),
      ("docs/api.md", "429 with %s live sessions")]),
    ("webui/dashboards.py", "MAX_DASHBOARDS", lambda v: "%d" % v,
     [("docs/logs.md", "**%s** dashboards"),
      ("docs/api.md", "at most %s dashboards")]),
    ("webui/dashboards.py", "MAX_PANELS", lambda v: "%d" % v,
     [("docs/logs.md", "**%s** tiles per dashboard"),
      ("docs/api.md", "%s tiles each")]),
]


def _constant(relative, name):
    """The value of a module-level ``NAME = <number>`` of one source file."""
    source = open(os.path.join(ROOT, *relative.split("/")), encoding="utf-8").read()
    m = re.search(r"^%s = ([^#\n]+)" % re.escape(name), source, re.M)
    assert m, "%s has no %s" % (relative, name)
    value = eval(m.group(1).strip(), {"__builtins__": {}})   # 120, 2.0, 20 * 1024 * 1024
    assert isinstance(value, (int, float)), "%s is not a number: %r" % (name, value)
    return value


def test_the_numbers_the_guide_quotes_come_from_the_code():
    for relative, name, render, places in QUOTED_NUMBERS:
        value = render(_constant(relative, name))
        for page, phrase in places:
            text = README if page == "README.md" else _doc(page[len("docs/"):])
            assert (phrase % value) in text, \
                "%s does not say %r - %s of %s says %s" % (
                    page, phrase % value, name, relative, value)


def test_no_readme_section_was_lost():
    """The split moved text out of the README; it did not drop any. Every
    section the old README had is a heading of the README or of a page of the
    guide today - at any level, because a "## " section of the README became
    the "# " title of a page, and in any case, because a page may title it the
    way the index names it ("Option A: local UI only")."""
    found = _headings(README)
    for page in _docs_pages():
        found |= _headings(_doc(page))
    missing = [t for t in OLD_README_SECTIONS if t.lower() not in found]
    assert missing == [], "sections of the old README that no page carries: %s" % missing


# --- The four diagrams -------------------------------------------------------
# The design replaces the README's ASCII box drawing and three prose walkthroughs
# (Data Flow, the verdict chain, the life of a rizin session) with four mermaid
# blocks. A diagram nobody can read is worse than the list it replaced, so each
# one is checked for syntax a renderer accepts, for sitting on the page that
# needs it, and for the prose that says the same thing in words.

MERMAID_BLOCK = re.compile(r"^```mermaid[ \t]*\n(.*?)^```[ \t]*$", re.M | re.S)
# Mermaid 10 (the vendored copy of the wiki) and GitHub both render these.
MERMAID_TYPES = re.compile(
    r"^(?:flowchart|graph)\s+(?:TB|TD|BT|RL|LR)$|^stateDiagram-v2$|^sequenceDiagram$")
QUOTED = re.compile(r'"[^"]*"')
ARROW = re.compile(r"-\.->|-->|---|==>|===|--[xo]")
EDGE_LABEL = re.compile(r"^\|[^|]*\|")
SENTENCE_END = re.compile(r"[.!?](?:\s|$)")
BOX_DRAWING = re.compile(r"[\u2500-\u257F]")
# A line that starts something other than a paragraph. Bold at the start of a
# line ("**Full analysis** goes on ...") is prose, a bullet needs its space.
NOT_PROSE = re.compile(r"^(?:#{1,6}\s|[-*+]\s|\d+\.\s|\||>|```|---\s*$|\*\*\*)")


def _pages():
    """The README and every page of the guide, by the name a message can use."""
    pages = {"README.md": README}
    for page in _docs_pages():
        pages["docs/" + page] = _doc(page)
    return pages


def _mermaid(text):
    """The mermaid blocks of a page: (body, the text that follows the block)."""
    return [(m.group(1), text[m.end():]) for m in MERMAID_BLOCK.finditer(text)]


def _prose_under(rest):
    """The first paragraph after a block, if it is prose: not a heading, list,
    table, blockquote or another fence."""
    para = []
    for line in rest.splitlines():
        if not line.strip():
            if para:
                break
            continue
        if NOT_PROSE.match(line.lstrip()):
            break
        para.append(line.strip())
    return " ".join(para)


def _section_of(text, title):
    """The lines of one "## " section, by its title."""
    start = text.index("\n## " + title + "\n")
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else len(text)]


def _table_rows(text, title):
    """The rows of the first markdown table under a heading, as they stand.

    The README writes the services as a "### " subsection and docs/README.md as
    a "## " section, so the level is not part of the search.
    """
    m = re.search(r"^#{2,4} %s\s*$" % re.escape(title), text, re.M)
    assert m, "no %s section" % title
    rows = []
    for line in text[m.end():].splitlines():
        if line.startswith("|"):
            rows.append(line.rstrip())
        elif rows:
            break
    assert rows, "the %s section has no table" % title
    return rows


def test_every_mermaid_block_is_well_formed():
    """No renderer ships with the repository yet (the wiki vendors Mermaid 10 in
    a later step), so the blocks are checked here instead: every block starts
    with a diagram type both Mermaid 10 and GitHub know, its brackets nest and
    close, and no arrow has an empty end - a node id lost to a typo renders as
    an edge into nowhere, or as the error box Mermaid draws instead of the
    diagram."""
    blocks = 0
    for name, text in _pages().items():
        for body, _ in _mermaid(text):
            blocks += 1
            lines = [l for l in body.splitlines() if l.strip()]
            assert lines, "%s has an empty mermaid block" % name
            head = lines[0].strip()
            assert MERMAID_TYPES.match(head), \
                "%s: %r is not a diagram type Mermaid 10 and GitHub both render" % (name, head)
            plain = QUOTED.sub('""', body)
            for raw in body.splitlines():
                assert raw.count('"') % 2 == 0, \
                    "%s: a label of the %s block has an unclosed quote: %r" % (name, head, raw.strip())
            stack, pairs = [], {")": "(", "]": "[", "}": "{"}
            for ch in plain:
                if ch in "([{":
                    stack.append(ch)
                elif ch in pairs:
                    assert stack and stack.pop() == pairs[ch], \
                        "%s: the brackets of the %s block do not pair up" % (name, head)
            assert not stack, "%s: the %s block leaves %s open" % (name, head, stack)
            for raw in plain.splitlines():
                line = raw.strip()
                if not line or line.startswith("%%") or not ARROW.search(line):
                    continue
                for i, part in enumerate(ARROW.split(line)):
                    end = part.strip()
                    if i:
                        end = EDGE_LABEL.sub("", end).strip()
                    assert end, "%s: an arrow of the %s block ends in nothing: %r" % (
                        name, head, raw.strip())
    # The design sanctions four to six diagrams, and the architecture one is in
    # both the README and the index, so the number of blocks is one more than
    # the number of diagrams. A range, not a pin: a fifth diagram is allowed
    # and must not fail three tests with a message that reads like an error
    # (round 4, Minor 2).
    assert 5 <= blocks <= 7, \
        "the design wants four to six diagrams, the architecture one counted twice " \
        "(README and docs/README.md): found %d blocks" % blocks


def test_the_four_diagrams_are_where_they_belong():
    """Each diagram belongs to the page whose text it replaces: the architecture
    in the README (the showcase) and in docs/README.md (the index), where the
    box drawing used to be, the detonation chain in the Data Flow section the
    README gave up, the verdict model where memory.md explains it, and the rizin
    session where rizin.md describes its sessions. Each one keeps two to three
    sentences of prose under it, because a reader without a rendered diagram -
    a plain-text view, a terminal, a screen reader - still has to be told what
    it says."""
    pages = _pages()
    found = {}
    for name, text in pages.items():
        for body, rest in _mermaid(text):
            found.setdefault(name, []).append((body, rest))
            prose = _prose_under(rest)
            assert len(SENTENCE_END.findall(prose)) >= 2, \
                "%s: the %s block needs two sentences of prose under it, found %r" % (
                    name, body.splitlines()[0].strip(), prose)

    # 1. Architecture: the same drawing in both, so the two cannot drift apart
    for name in ("README.md", "docs/README.md"):
        assert len(found.get(name, [])) == 1, "%s needs the architecture diagram" % name
        body = found[name][0][0]
        assert body.splitlines()[0].strip().startswith("flowchart"), body.splitlines()[0]
        for part in (":9000", "DetonatorAgent", "LitterBox", "Rustinel", "Aether"):
            assert part in body, "%s: the architecture diagram does not name %s" % (name, part)
    assert found["README.md"][0][0] == found["docs/README.md"][0][0], \
        "the README and docs/README.md carry two different architecture diagrams"
    # Round 4, Minor 1: the prose under the diagram and the services table are
    # byte-identical in both files as well, and only the diagram was pinned -
    # so one of the two copies could be corrected alone and the other stay
    # wrong. The prose is what a reader without a rendered diagram gets, and
    # the services table carries the ports.
    assert _prose_under(found["README.md"][0][1]) == _prose_under(found["docs/README.md"][0][1]), \
        "the README and docs/README.md say two different things under the same diagram"
    assert _table_rows(README, "Services") == _table_rows(_doc("README.md"), "Services"), \
        "the services table of the README and of docs/README.md have drifted apart"

    # 2. The detonation chain, left to right, in the section the README lost
    body, _ = found["docs/workflow.md"][0]
    assert body.splitlines()[0].strip() == "flowchart LR", \
        "the detonation chain runs left to right: %r" % body.splitlines()[0].strip()
    assert "```mermaid" in _section_of(_doc("workflow.md"), "Data Flow"), \
        "the detonation chain belongs in the Data Flow section of docs/workflow.md"
    for part in ("/api/submit", "PID", "Exit", "verdict"):
        assert part in body, "the detonation chain does not name %s" % part
    assert "Data Flow" not in README, "the Data Flow section leaves the README"

    # 3. How a memory finding becomes the shared verdict
    body, _ = found["docs/memory.md"][0]
    assert body.splitlines()[0].strip().startswith("flowchart"), body.splitlines()[0]
    assert "```mermaid" in _section_of(_doc("memory.md"), "How findings become a verdict")
    for part in ("baseline", "Persistence", "Corroboration", "verdict"):
        assert part in body, "the verdict diagram does not name %s" % part

    # 4. The life of a rizin session
    body, _ = found["docs/rizin.md"][0]
    assert body.splitlines()[0].strip() == "stateDiagram-v2", \
        "the rizin session is a state diagram: %r" % body.splitlines()[0].strip()
    assert "```mermaid" in _section_of(_doc("rizin.md"), "Sessions")
    for part in ("aaa", "aa", "pagehide", "30 minutes", "another"):
        assert part in body, "the rizin session diagram does not name %s" % part

    assert sorted(found) == ["README.md", "docs/README.md", "docs/memory.md",
                             "docs/rizin.md", "docs/workflow.md"], \
        "these blocks are the design's four diagrams, each checked above; a new " \
        "diagram is allowed (four to six) and needs its own check here: %s" % sorted(found)


def test_no_ascii_box_drawing_is_left():
    """The box drawing is gone, and no page draws a new one. The exemptions are
    by location, never by character: the file tree of docs/troubleshooting.md,
    which the design keeps as indented text, and the one line of prose that
    names a control of the Web UI by the glyph on it - the \u2550 of the rizin
    dock's grip, which webui/templates/index.html carries as that element's
    text, allowed once per line and never inside a fence. The VM path list needs
    no exemption of its own: it draws with no box-drawing character at all.
    Everywhere else one character of U+2500..U+257F is one too many - the first
    round allowed one per line on every page, which let a drawing in as long as
    it was pasted one character per line. An exemption that covers nothing fails
    as well, so none can go stale while a listing is rewritten."""
    exempt = {("docs/troubleshooting.md", "File Structure"): None,     # a listing: any of them
              ("docs/rizin.md", "One place in every view"): "\u2550"}  # a glyph: that one, once
    bad, used = [], set()
    for name, text in _pages().items():
        section, fence = "", False
        for number, line in enumerate(text.splitlines(), 1):
            if line.startswith("```"):
                fence = not fence
                continue
            if not fence:
                m = HEADING.match(line)
                if m:
                    section = m.group(1)
            hits = BOX_DRAWING.findall(line)
            if not hits:
                continue
            key = (name, section)
            if key not in exempt:
                bad.append("%s:%d: a box drawing outside the listings that keep one" % (name, number))
                continue
            used.add(key)
            glyph = exempt[key]
            if glyph is not None and (fence or hits != [glyph]):
                bad.append("%s:%d: %r is not the one %s this line may name"
                           % (name, number, "".join(hits), glyph))
    assert bad == [], bad
    assert used == set(exempt), \
        "an exemption that covers nothing: %s" % sorted(set(exempt) - used)


# The architecture diagram's one timing claim, against the loop that makes it.
ARCH_NODE = re.compile(r'(\w+)\["([^"]*)"\]')
ARCH_EDGE = re.compile(r'^\s*(\w+)\s*(?:-->|-\.->)\s*(?:\|"([^"]*)"\|)?\s*(\w+)\b', re.M)


def test_the_architecture_diagram_polls_only_what_the_loader_polls():
    """Round 1, Important: the diagram ran all three detection engines into one
    node and read that node "every 5 s". Only two of them are on that clock.
    alert_loader_thread reloads Rustinel, Fibratus and LitterBox every five
    seconds; Sysmon's Operational log is queried per request instead
    (_read_sysmon_events through wevtutil, for the event list, the process tree,
    the pipes and the counts), so a view can be minutes old or seconds old. The
    engines that feed the node behind the "every 5 s" edge therefore have to be
    exactly the ones the loader polls, and the prose must not promise the
    cadence for Sysmon either."""
    loader = APP[APP.index("def alert_loader_thread"):APP.index("# --- Routes: Pages ---")]
    code = re.sub(r"#[^\n]*", "", loader)      # a comment of the loop names Sysmon; its code does not
    polled = set(re.findall(r"load_(\w+?)_(?:alerts|results)\(\)", code))
    assert polled == {"rustinel", "fibratus", "litterbox"}, \
        "the 5 s loader changed what it reloads: %s" % sorted(polled)
    assert "sysmon" not in code.lower(), "the 5 s loader reads Sysmon now; the diagram may say so"

    for name in ("README.md", "docs/README.md"):
        body, rest = _mermaid(_pages()[name])[0]
        labels = dict(ARCH_NODE.findall(body))
        edges = [(src, label or "", dst) for src, label, dst in ARCH_EDGE.findall(body)]
        timed = [e for e in edges if "every 5 s" in e[1]]
        assert len(timed) == 1, "%s: expected one timed edge, found %s" % (name, timed)
        source = timed[0][0]
        assert "sysmon" not in labels[source].lower(), \
            "%s: %r is read every 5 s and names Sysmon" % (name, labels[source])
        feeding = {labels[src].split(":")[0].split(",")[0].strip().lower()
                   for src, _, dst in edges if dst == source}
        assert feeding == {"rustinel", "fibratus"}, \
            "%s: the node read every 5 s is fed by %s" % (name, sorted(feeding))
        prose = _prose_under(rest)
        if "five seconds" in prose:
            assert re.search(r"Sysmon[^.]*\b(asks|request)", prose), \
                "%s: the prose gives the five seconds without saying when Sysmon's log is read" % name


# --- The README as a showcase ------------------------------------------------
# The manual is in docs/ now, so what is left of the README has one job: say
# what the tool is, show it, and point into the guide. The design fixes nine
# sections in one order and about 400 lines (it was 2367); what it keeps is what
# sells - the two theme images, the demo video and eight to ten features, each
# with one sentence and one picture of itself. The video is linked, not
# embedded: static/demo.gif is 10 MB, and embedded it loads before anybody has
# decided to watch it.

SHOWCASE_SECTIONS = ["What it does", "Architecture", "Web UI Tabs", "Quick Start",
                     "Platform support", "Documentation", "Security Notes",
                     "Credits", "License"]
# A feature of the showcase: "**Named pipes** - one sentence." as a paragraph.
FEATURE = re.compile(r"^\*\*([^*]+)\*\* \u2014 (.+?)\n[ \t]*\n", re.M | re.S)
README_IMAGE = re.compile(r'<img src="(static/[^"]+)"')


def test_readme_is_a_showcase():
    lines = README.splitlines()
    assert len(lines) < 500, \
        "the README is %d lines; the showcase stays under 500" % len(lines)
    titles = _heading_titles(README)
    assert [t for t in titles if t in SHOWCASE_SECTIONS] == SHOWCASE_SECTIONS, \
        "the showcase needs its nine sections in the design's order, found %s" % titles

    assert "static/demo.gif" in README, "the README lost the way to the demo video"
    assert '<img src="static/demo.gif"' not in README, \
        "the demo video is linked, not embedded - it is 10 MB"
    for shot in ("static/theme_cyberpunk.png", "static/theme_telemetry.png"):
        assert shot in README, "the showcase keeps both theme images, %s is gone" % shot

    section = _section_of(README, "What it does")
    features = FEATURE.findall(section)
    assert 8 <= len(features) <= 10, \
        "the showcase names %d features, not the eight to ten of the design: %s" % (
            len(features), [n for n, _ in features])
    for name, sentence in features:
        one = " ".join(sentence.split())
        assert one.endswith(".") and len(SENTENCE_END.findall(one)) == 1, \
            "the %s feature is one sentence, not %r" % (name, one)
    # What follows a feature, up to the next one, is its one picture
    parts = FEATURE.split(section)[1:]
    for name, rest in zip(parts[0::3], parts[2::3]):
        shots = README_IMAGE.findall(rest)
        assert len(shots) == 1, \
            "the %s feature shows %s, and a feature shows exactly one picture" % (name, shots)
        assert os.path.isfile(os.path.join(ROOT, shots[0])), shots[0]


def test_the_documentation_map_links_every_page():
    """The map is the way from the showcase into the guide: every page of docs/
    (superpowers/ holds designs and plans, not the guide) is named there, with
    the sentence that says what it answers, and every link resolves to a file
    that is on disk. A page missing from the map is a page nobody finds."""
    section = _section_of(README, "Documentation")
    linked = set(re.findall(r"\]\((docs/[A-Za-z0-9_.-]+\.md)[^)]*\)", section))
    for page in _docs_pages():
        assert "docs/" + page in linked, \
            "the documentation map does not link docs/%s" % page
    for target in sorted(linked):
        assert os.path.isfile(os.path.join(ROOT, target)), \
            "the map links %s, which is not a file" % target
    rows = {m.group(1): m.group(0) for m in
            re.finditer(r"^\| \[[^\]]+\]\((docs/[^)#]+)[^)]*\).*$", section, re.M)}
    for page in _docs_pages():
        if page == "README.md":
            continue      # the index: the sentence above the table takes it
        row = rows.get("docs/" + page)
        assert row, "docs/%s has no line of its own in the map" % page
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert len(cells) == 2 and cells[1].endswith(("?", ".")), \
            "the line of docs/%s needs the sentence it answers: %r" % (page, row)


def test_the_documentation_map_shows_the_offline_wiki():
    """The map is the way from the showcase into the guide, so it is where the
    one offline file belongs: what builds it, where it lands, that the Web UI's
    help links it - and a picture of it, like every other thing the README
    shows. The VM has no network, so on that machine this file is the whole
    documentation; a reader who never hears of it builds it never."""
    section = _section_of(README, "Documentation")
    assert "make docs" in section and ".\\make.ps1 docs" in section, \
        "the map does not say what builds the wiki, on either host"
    assert "webui/static/wiki.html" in section, "the map does not say where the wiki lands"
    assert re.search(r"\bhelp\b", section), "the map does not say that the help links it"
    shots = README_IMAGE.findall(section)
    assert shots == ["static/wiki.png"], \
        "the map shows %s; the wiki is the one picture of this section" % shots
    assert os.path.isfile(os.path.join(ROOT, shots[0])), shots[0]
