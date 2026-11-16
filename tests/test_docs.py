"""Documentation stays in sync with the code.

Regressions covered: the README documented a /api/fibratus proxy that did not
exist, missed 17 routes and had no MCP section; the in-app help described
layouts and tabs that were gone; screenshots showed an old UI.
"""

import ast
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
APP = open(os.path.join(ROOT, "webui", "app.py"), encoding="utf-8").read()
HELP = open(os.path.join(ROOT, "webui", "templates", "index.html"), encoding="utf-8").read()


def _norm(path):
    return re.sub(r"<[^>]+>|&lt;[^&]+&gt;", "*", path).rstrip("/")


ROUTES = {_norm(p) for p in re.findall(r'@app\.route\("(/api/[^"]+)"', APP)}


def test_readme_documents_every_api_route_and_nothing_else():
    documented = {_norm(p) for p in re.findall(r"\|\s*[A-Z /]+\s*\|\s*`(/api/[^`]+)`", README)}
    assert ROUTES - documented == set(), "routes missing from the README API reference"
    assert documented - ROUTES == set(), "README documents routes that do not exist"


def test_help_modal_only_mentions_existing_routes():
    mentioned = {_norm(p) for p in re.findall(r"<code>(/api/[^<]+)</code>", HELP)}
    assert mentioned and mentioned <= ROUTES, mentioned - ROUTES


def test_readme_lists_every_mcp_tool():
    tree = ast.parse(open(os.path.join(ROOT, "mcp", "server.py"), encoding="utf-8").read())
    tools = {f.name for f in tree.body if isinstance(f, ast.FunctionDef)
             and any(isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "tool" for d in f.decorator_list)}
    section = README[README.index("## MCP Server"):README.index("## Configuration")]
    listed = set(re.findall(r"`(tdc_\w+)`", section))
    assert tools == listed
    assert f"({len(tools)} tools" in README


def test_readme_images_exist_and_none_are_orphaned():
    referenced = set(re.findall(r'src="(static/[^"]+\.png)"', README))
    for path in referenced:
        assert os.path.isfile(os.path.join(ROOT, path)), path
    on_disk = {f"static/{f}" for f in os.listdir(os.path.join(ROOT, "static")) if f.endswith(".png")}
    assert on_disk - referenced == set(), "screenshots not used in the README"


def test_readme_tabs_match_the_ui():
    ui_tabs = re.findall(r'data-tab="[^"]+">([^<]+)</button>', HELP)
    start = README.index("### Web UI Tabs")
    section = README[start:README.index("\n### ", start)]
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


def test_readme_rizin_rows_say_what_the_server_answers():
    """Follow-up findings 1 and 2: the flags row claimed that over the 32 MB cap "Tab completes the
    function names"; the server answers names: [], common: "" and truncated: true then, and the UI's Tab
    lists the names of its function list without completing one (tests/test_rizin_ui.py). The function
    list itself has no such cap any anymore: it reads rizin's afl, whose rows are about 63 B each.

    Review, Minors 3 and 4: the other views are not without a limit (they carry their own, and a view
    over it answers 500), and FUNCTIONS does have the row cap - only no 32 MB one."""
    rows = {path: line for line in README.splitlines()
            for path in re.findall(r"`(/api/rizin/[^`]+)`", line)}
    flags = rows["/api/rizin/<sid>/flags"]
    assert "completes the function names" not in flags, flags
    assert "without completing" in flags and "truncated" in flags, flags
    functions = rows["/api/rizin/<sid>/functions"]
    assert "`afl`" in functions and "200 000" in functions, functions
    # The error list names the lists that the cap refuses, and the limit the other views carry
    errors = next(line for line in README.splitlines() if line.startswith("One rizin session per opened file"))
    assert "too many strings to list here" in errors
    assert "the other views have no such limit" not in errors, errors
    assert "is larger than" in errors, errors
    # The Limitations bullet does not read as if the function list had no cap at all
    limits = next(line for line in README.splitlines() if "FUNCTIONS has no" in line)
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
