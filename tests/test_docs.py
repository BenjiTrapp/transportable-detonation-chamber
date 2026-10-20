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
    section = README[README.index("### Web UI Tabs"):README.index("### ETW Browser")]
    readme_tabs = re.findall(r"^\| \*\*([^*]+)\*\* \|", section, re.M)
    assert ui_tabs == readme_tabs


def test_help_tab_guide_covers_every_tab():
    ui_tabs = re.findall(r'data-tab="[^"]+">([^<]+)</button>', HELP)
    guide = HELP[HELP.index('id="help-usage"'):HELP.index('id="help-api"')]
    assert re.findall(r"<h4>([^<]+)</h4>", guide) == ui_tabs
