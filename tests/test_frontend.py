"""Frontend (static/js/app.js): escaping, inline handlers, instance keys.

Regressions covered:
  * values from samples/events inserted into HTML unescaped (XSS)
  * onclick="fn(${proc.pid})" - unquoted values executed as code
  * class="sev-${severity}" - a value could leave the attribute
  * graph layouts linked children by PID, so reused PIDs mixed processes

The JavaScript checks run in Node; they are skipped where Node is missing.
"""

import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "webui", "static", "js", "app.js")
SOURCE = open(APP_JS, encoding="utf-8").read()

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


def _function_source(name):
    """Source of a top-level `function name(...) {...}` (brace-matched)."""
    m = re.search(r"^(async )?function %s\(" % re.escape(name), SOURCE, re.M)
    assert m, f"{name} not found in app.js"
    i = SOURCE.index("{", m.end())
    depth = 0
    for j in range(i, len(SOURCE)):
        if SOURCE[j] == "{":
            depth += 1
        elif SOURCE[j] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[m.start():j + 1]
    raise AssertionError(f"unbalanced braces in {name}")


def _run_node(functions, script, prelude=""):
    code = prelude + "\n" + "\n".join(_function_source(f) for f in functions) + "\n" + script
    out = subprocess.run([NODE, "-e", code], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@needs_node
def test_escaping_helpers():
    r = _run_node(["escapeHtml", "jsArg", "jsInt", "cssToken"], r"""
        console.log(JSON.stringify({
          esc: escapeHtml(`<img src=x onerror="a('b')">&`),
          escNum: escapeHtml(0), escNull: escapeHtml(null),
          arg: jsArg(`a");alert(1)//`),
          intBad: jsInt("1);alert(1"), intWord: jsInt("x"), intOk: jsInt(4242),
          css: cssToken(`high" onmouseover="alert(1)`), cssCase: cssToken("Critical"),
        }));""")
    assert r["esc"] == "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;"
    assert r["escNum"] == "0" and r["escNull"] == ""
    assert "<" not in r["arg"] and '"' not in r["arg"]          # safe inside onclick="..."
    assert r["intBad"] == "1" and r["intWord"] == "null" and r["intOk"] == "4242"
    assert re.fullmatch(r"[a-z0-9_-]*", r["css"]) and r["cssCase"] == "critical"


# Values that may appear raw inside on*="..." handlers: loop indexes and
# numbers computed in the frontend, or strings already built with jsArg().
SAFE_HANDLER_EXPR = re.compile(
    r"^(jsArg|jsInt)\(|^(globalIdx|i|idx|secOffsetDec|elfSecOffsetDec|sec\.index|sec\.display_size|"
    r"sec\.raw_offset_dec|sysmonEvents\.indexOf\(ev\)|args|fullArgs|safe|esc)$|\.map\(jsArg\)")


def test_inline_handlers_only_interpolate_safe_values():
    offenders = []
    for m in re.finditer(r'\bon[a-z]+="([^"]*)"', SOURCE):
        for expr in re.findall(r"\$\{([^}]*)\}", m.group(1)):
            if not SAFE_HANDLER_EXPR.search(expr.strip()):
                line = SOURCE.count("\n", 0, m.start()) + 1
                offenders.append(f"app.js:{line}: ${{{expr}}}")
    assert not offenders, "unsafe values in inline handlers:\n" + "\n".join(offenders)


def test_event_derived_values_in_class_attributes_use_csstoken():
    risky = re.compile(r'class="[^"]*\$\{(sev|severity|maxSev|alert\.severity|f\.severity|risk\.risk_level)\}')
    hits = [SOURCE.count("\n", 0, m.start()) + 1 for m in risky.finditer(SOURCE)]
    assert not hits, f"severity values in class attributes without cssToken() at lines {hits}"


def test_no_dynamic_code_execution():
    assert not re.search(r"\beval\(|new Function\(|setTimeout\(\s*['\"`]|setInterval\(\s*['\"`]", SOURCE)


@needs_node
def test_isometric_layout_links_children_by_instance_key():
    prelude = """
        const graphState = { isoCollapsed: new Set() };
        const ISO = { COS: Math.cos(Math.PI / 6), SIN: Math.sin(Math.PI / 6), STEP_U: 118, STEP_V: 76, LIFT: 64, R: 13 };
    """
    r = _run_node(["isoProject", "applyIsometricLayout"], r"""
        // Two processes share PID 1112 (reused); each has its own child.
        const n = (key, pid, parent, children, seen) => ({ id: 'proc_' + key, key, pid, type: 'process',
            parentPid: parent, children, firstSeen: seen, threats: 0, depth: 0 });
        const nodes = [
            n('1112@100', '1112', null, ['836'], '2026-09-14'),
            n('836', '836', '1112@100', [], '2026-09-14'),
            n('1112', '1112', null, ['9000'], '2026-10-20'),
            n('9000', '9000', '1112', [], '2026-10-20'),
        ];
        const nodeMap = Object.fromEntries(nodes.map(x => [x.key, x]));
        applyIsometricLayout(nodes, [], nodeMap);
        console.log(JSON.stringify(Object.fromEntries(nodes.map(x => [x.key, (x.isoKids || []).map(k => k.key)]))));
    """, prelude)
    assert r == {"1112@100": ["836"], "836": [], "1112": ["9000"], "9000": []}


def test_asset_versions_are_bumped_with_the_frontend():
    """index.html must reference app.js/style.css with a version query, so a
    deploy is not hidden behind the browser cache."""
    html = open(os.path.join(ROOT, "webui", "templates", "index.html"), encoding="utf-8").read()
    assert re.search(r'/static/js/app\.js\?v=\d+', html)
    assert re.search(r'/static/css/style\.css\?v=\d+', html)


# Fields that come from samples, events, alerts or scanner output. Inside an
# HTML template they must go through escapeHtml()/cssToken()/jsArg()/jsInt().
EVENT_FIELD = re.compile(
    r"\$\{\s*(alert|ev|proc|node|sym|e|target|child|risk|m|p|a|sub|f|d|exec)\."
    r"(pid|os_pid|timestamp|severity|ip|port|protocol|_type|bind|type|value|firstSeen|parent_pid|"
    r"parent_name|name|label|image|command_line|cmdline|commandline|rule_name|category|engine|"
    r"filename|sha256|md5|status|target|reason|query|result|dst_ip|dst_port|details|user)\b")


def _is_html_line(line):
    """A source line that builds markup (not a key, a title string or textContent)."""
    stripped = line.strip()
    if stripped.startswith("//") or "textContent" in line or "headerText" in line:
        return False
    return bool(re.search(r"</?[a-zA-Z]", line))


def test_event_fields_are_escaped_in_html():
    offenders = []
    for no, line in enumerate(SOURCE.splitlines(), 1):
        if not _is_html_line(line):
            continue
        for m in EVENT_FIELD.finditer(line):
            # ${x.field ? `...${escapeHtml(x.field)}...` : ''} only tests the value.
            if re.match(r"\s*\?", line[m.end():]) or line[m.end():].lstrip().startswith(("!=", "==", ">", "<", "&&", "||")):
                continue
            offenders.append(f"app.js:{no}: {line.strip()[:120]}")
    assert not offenders, "event-derived values inserted into HTML unescaped:\n" + "\n".join(offenders)
