"""Catalog and update checks for the tool updates (webui/tool_updates.py).

FakeEnv is the injected Env: commands are matched by argument prefix (the
longest prefix wins), URLs by (method, url), and every call is recorded.
Test files that need the same stand-in import it:
``from test_tool_updates import FakeEnv`` (tests/ is on sys.path).
"""

import os
import re

import pytest

import tool_updates as tu
from tool_updates import HttpResult, RunResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "docs", "superpowers", "specs", "2026-11-13-tool-updates-design.md")

GIT_PREFIX = ["git", "-c", "safe.directory=*", "-C"]


def ok(stdout="", stderr=""):
    return RunResult(0, stdout, stderr)


def fail(stderr="boom", code=1):
    return RunResult(code, "", stderr)


def js(payload, status=200, headers=None):
    return HttpResult(status, dict(headers or {}), payload, "")


class FakeEnv:
    """Env stand-in: canned command results, URL results and files."""

    def __init__(self, files=None, paths=(), commands=None, urls=None, internet=True):
        self.files = dict(files or {})
        self.paths = set(paths)
        self.commands = [(tuple(k), v) for k, v in (commands or {}).items()]
        self.urls = dict(urls or {})
        self.run_calls = []
        self.http_calls = []
        if internet:
            self.urls.setdefault(("GET", "https://api.github.com"), js({}))
        else:
            self.urls[("GET", "https://api.github.com")] = HttpResult(0, {}, None, "offline")

    def on(self, prefix, result):
        self.commands.append((tuple(prefix), result))

    def run(self, args, timeout):
        args = list(args)
        self.run_calls.append(args)
        best = None
        for prefix, result in self.commands:
            if tuple(args[:len(prefix)]) == prefix and (best is None or len(prefix) >= len(best[0])):
                best = (prefix, result)
        if best is None:
            return RunResult(127, "", "not found: %s" % args[0])
        result = best[1]
        if isinstance(result, Exception):
            raise result
        return result(args) if callable(result) else result

    def http_get(self, url, timeout, method="GET"):
        self.http_calls.append((method, url))
        result = self.urls.get((method, url))
        if result is None:
            return HttpResult(404, {}, None, "")
        return result

    def exists(self, path):
        return path in self.paths or path in self.files

    def read_text(self, path):
        return self.files.get(path)

    def commands_matching(self, *needle):
        return [c for c in self.run_calls if all(n in c for n in needle)]


def spec_of(tool_id):
    return next(t for t in tu.CATALOG if t.id == tool_id)


def by_id(entries):
    return {e["id"]: e for e in entries}


def git_env(path, behind="0", fetch=None):
    env = FakeEnv(paths=[path + "\\.git", path])
    base = GIT_PREFIX + [path]
    env.on(base + ["fetch"], fetch or ok())
    env.on(base + ["rev-parse", "--short", "HEAD"], ok("abc1234\n"))
    env.on(base + ["rev-parse", "--short", "@{u}"], ok("def5678\n"))
    env.on(base + ["rev-list", "--count", "HEAD..@{u}"], ok(behind + "\n"))
    return env


def test_compare_versions():
    assert tu.compare_versions("v1.1.1", "1.2.0") == -1
    assert tu.compare_versions("3.0.0", "3.0.0") == 0
    assert tu.compare_versions("9.10.0", "9.4.0") == 1
    assert tu.compare_versions("2.5.0", "v2.5.0") == 0
    assert tu.compare_versions("1.0", "1.0.0") == 0
    assert tu.normalize_version(" V2.0.1 ") == "2.0.1"


def test_parse_choco_outdated():
    text = "Chocolatey v2.2.2\ngit|2.40.0|2.41.0|false\nphp|8.2.1|8.3.0|true\n"
    rows = tu.parse_choco_outdated(text)
    assert rows == [
        {"package": "git", "current": "2.40.0", "available": "2.41.0", "pinned": False},
        {"package": "php", "current": "8.2.1", "available": "8.3.0", "pinned": True},
    ]


def test_check_choco_entries_and_missing_choco():
    env = FakeEnv(commands={("choco", "outdated"): ok("git|2.40.0|2.41.0|false\nphp|8.2.1|8.3.0|true\n")})
    entries = by_id(tu.check_choco(env))
    assert entries["choco:git"]["status"] == "update_available"
    assert entries["choco:git"]["kind"] == "choco"
    assert entries["choco:git"]["installed"] == "2.40.0"
    assert entries["choco:git"]["available"] == "2.41.0"
    assert entries["choco:php"]["status"] == "pinned_update"
    assert entries["choco:php"]["pinned"] == "8.2.1"
    assert env.run_calls[0] == ["choco", "outdated", "-r", "--ignore-unfound", "--limit-output"]

    entries = tu.check_choco(FakeEnv())
    assert [(e["id"], e["status"]) for e in entries] == [("choco", "not_installed")]


def test_check_choco_failures_are_errors_not_an_empty_list():
    env = FakeEnv(commands={("choco", "outdated"): RunResult(124, "", "timed out after 180s")})
    entries = tu.check_choco(env)
    assert [(e["id"], e["status"]) for e in entries] == [("choco", "error")]
    assert entries[0]["detail"] == "choco outdated timed out"
    env = FakeEnv(commands={("choco", "outdated"): fail("Access denied\nmore", code=1)})
    entries = tu.check_choco(env)
    assert [(e["id"], e["status"], e["detail"]) for e in entries] == [("choco", "error", "Access denied")]
    # exit code 2 with a list is choco's "outdated packages found"
    env = FakeEnv(commands={("choco", "outdated"): RunResult(2, "git|2.40.0|2.41.0|false\n", "")})
    assert [e["id"] for e in tu.check_choco(env)] == ["choco:git"]
    assert tu.check_choco(FakeEnv(commands={("choco", "outdated"): ok("")})) == []


def test_git_behind_reports_commits():
    path = "C:\\LitterBox"
    env = git_env(path, behind="3")
    entry = tu.check_tool(spec_of("litterbox"), env)
    assert entry["status"] == "update_available"
    assert entry["detail"] == "3 new commits"
    assert entry["installed"] == "abc1234"
    assert entry["available"] == "def5678"
    assert env.run_calls
    for call in env.run_calls:
        assert call[:5] == GIT_PREFIX + [path]


def test_git_up_to_date_and_fetch_failure():
    entry = tu.check_tool(spec_of("litterbox"), git_env("C:\\LitterBox", behind="0"))
    assert entry["status"] == "up_to_date"
    entry = tu.check_tool(spec_of("litterbox"), git_env(
        "C:\\LitterBox", fetch=fail("fatal: unable to access\nsecond line")))
    assert entry["status"] == "error"
    assert entry["detail"] == "fatal: unable to access"


def test_aether_without_source_folder_is_unknown():
    entry = tu.check_tool(spec_of("aether"), FakeEnv())
    assert entry["status"] == "unknown"


def test_release_pinned_newer():
    spec = spec_of("rustinel")
    env = FakeEnv(
        paths=[spec.path],
        commands={(spec.version_cmd[0], "--version"): ok("rustinel 1.1.1\n")},
        urls={("GET", "https://api.github.com/repos/Karib0u/rustinel/releases/latest"): js({"tag_name": "v1.2.0"})},
    )
    entry = tu.check_tool(spec, env)
    assert entry["status"] == "pinned_update"
    assert entry["installed"] == "1.1.1"
    assert entry["available"] == "1.2.0"
    assert entry["pinned"] == "1.1.1"


def test_release_same_version_is_up_to_date_via_marker():
    spec = spec_of("process_dump")
    env = FakeEnv(
        files={spec.marker: "v2.1\n"}, paths=[spec.path],
        urls={("GET", "https://api.github.com/repos/glmcdona/Process-Dump/releases/latest"): js({"tag_name": "v2.1"})},
    )
    entry = tu.check_tool(spec, env)
    assert entry["status"] == "up_to_date"
    assert entry["installed"] == "2.1"


def test_release_without_marker_is_unknown_and_updatable():
    spec = spec_of("beaconeye")
    env = FakeEnv(
        paths=[spec.path],
        urls={("GET", "https://api.github.com/repos/CCob/BeaconEye/releases/latest"): js({"tag_name": "v1.0.0"})},
    )
    entry = tu.check_tool(spec, env)
    assert entry["installed"] == "unknown"
    assert entry["status"] == "update_available"


def test_release_api_errors_are_one_line_errors():
    spec = spec_of("beaconeye")
    url = "https://api.github.com/repos/CCob/BeaconEye/releases/latest"
    limited = HttpResult(403, {"x-ratelimit-remaining": "0"}, {"message": "rate limit"}, "")
    entry = tu.check_tool(spec, FakeEnv(paths=[spec.path], urls={("GET", url): limited}))
    assert entry["status"] == "error"
    assert "TDC_GITHUB_TOKEN" in entry["detail"]
    entry = tu.check_tool(spec, FakeEnv(paths=[spec.path], urls={("GET", url): js({}, status=500)}))
    assert entry["status"] == "error"
    assert "\n" not in entry["detail"]


def test_rizin_reads_cutter_version_from_package_marker():
    spec = spec_of("rizin")
    env = FakeEnv(
        files={spec.marker: "Cutter-v2.5.0-Windows-x86_64.zip sha256:" + "ab" * 32 + "\n"},
        paths=[spec.path],
        urls={("GET", "https://api.github.com/repos/rizinorg/cutter/releases/latest"): js({"tag_name": "v2.6.0"})},
    )
    entry = tu.check_tool(spec, env)
    assert entry["installed"] == "2.5.0"
    assert entry["available"] == "2.6.0"
    assert entry["status"] == "pinned_update"
    assert entry["pinned"] == "2.5.0"


def test_sysinternals_etag_compare_and_missing_marker():
    spec = spec_of("sysmon")
    url = "https://download.sysinternals.com/files/Sysmon.zip"
    head = {("HEAD", url): HttpResult(200, {"etag": '"abc"'}, None, "")}
    env = FakeEnv(paths=[spec.path], files={spec.marker: '{"binary_etag": "\\"old\\"", "config_etag": "x"}'}, urls=head)
    entry = tu.check_tool(spec, env)
    assert entry["status"] == "update_available"
    env = FakeEnv(paths=[spec.path], files={spec.marker: '{"binary_etag": "\\"abc\\""}'}, urls=head)
    assert tu.check_tool(spec, env)["status"] == "up_to_date"
    env = FakeEnv(paths=[spec.path], urls=head)
    entry = tu.check_tool(spec, env)
    assert entry["status"] == "unknown"
    assert entry["detail"] == "Not checked yet; an update records the current version"


def test_sysmon_config_uses_its_own_etag():
    spec = spec_of("sysmon_config")
    url = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    env = FakeEnv(
        paths=[spec.path], files={spec.marker: '{"binary_etag": "b", "config_etag": "c1"}'},
        urls={("HEAD", url): HttpResult(200, {"etag": "c2"}, None, "")},
    )
    assert tu.check_tool(spec, env)["status"] == "update_available"


def test_winget_missing_and_update_available():
    spec = spec_of("windbg")
    entry = tu.check_tool(spec, FakeEnv())
    assert entry["status"] == "unknown"
    assert entry["detail"] == "winget is not available for SYSTEM"
    env = FakeEnv(commands={("winget", "list"): ok(
        "Name     Id                 Version  Available Source\n"
        "WinDbg   Microsoft.WinDbg   1.2.0.0  1.3.0.0   winget\n")})
    entry = tu.check_tool(spec, env)
    assert entry["status"] == "update_available"
    assert entry["installed"] == "1.2.0.0"
    assert entry["available"] == "1.3.0.0"


def test_winget_failures_are_errors_and_no_match_is_not_installed():
    spec = spec_of("windbg")
    entry = tu.check_tool(spec, FakeEnv(commands={("winget", "list"): fail("Failed when opening source\nx", 1)}))
    assert (entry["status"], entry["detail"]) == ("error", "Failed when opening source")
    for code in (-1978335212, 2316632084):
        env = FakeEnv(commands={("winget", "list"): RunResult(code, "No installed package found matching input criteria.", "")})
        assert tu.check_tool(spec, env)["status"] == "not_installed"
    # upgrade list says nothing, the plain list shows the package: up to date
    def listing(args):
        if "--upgrade-available" in args:
            return RunResult(-1978335212, "No installed package found matching input criteria.", "")
        return ok("WinDbg  Microsoft.WinDbg  1.3.0.0  winget\n")
    entry = tu.check_tool(spec, FakeEnv(commands={("winget", "list"): listing}))
    assert entry["status"] == "up_to_date"
    # the second call failing is an error too
    def failing_second(args):
        if "--upgrade-available" in args:
            return ok("")
        return fail("access denied", 5)
    entry = tu.check_tool(spec, FakeEnv(commands={("winget", "list"): failing_second}))
    assert (entry["status"], entry["detail"]) == ("error", "access denied")


def test_missing_tool_is_not_installed():
    for tool_id in ("capa", "litterbox", "sysmon", "rizin"):
        entry = tu.check_tool(spec_of(tool_id), FakeEnv())
        assert entry["status"] == "not_installed", tool_id
        assert entry["log"] == [] and entry["updated_at"] is None
    env = FakeEnv(paths=["C:\\LitterBox"])
    assert tu.check_tool(spec_of("litterbox"), env)["status"] == "not_installed"
    assert not env.run_calls


def test_entry_has_the_spec_fields():
    entry = tu.check_tool(spec_of("capa"), FakeEnv())
    assert set(entry) == {"id", "name", "kind", "installed", "available", "status",
                          "pinned", "detail", "log", "updated_at"}


def test_offline_marks_network_tools():
    paths = [t.path for t in tu.CATALOG if t.path] + ["C:\\LitterBox\\.git"]
    env = FakeEnv(paths=paths, internet=False)
    entries = by_id(tu.check_all(env))
    assert entries["litterbox"]["status"] == "offline"
    assert entries["litterbox"]["detail"] == "No internet access from the VM"
    assert entries["capa"]["status"] == "offline"
    assert entries["rizin"]["status"] == "offline"
    assert not env.commands_matching("fetch")
    assert not env.commands_matching("choco")
    assert env.http_calls == [("GET", "https://api.github.com")]


def test_offline_keeps_not_installed():
    env = FakeEnv(paths=[spec_of("capa").path], internet=False)
    entries = by_id(tu.check_all(env))
    assert entries["capa"]["status"] == "offline"
    assert entries["beaconeye"]["status"] == "not_installed"


def test_check_all_covers_choco_and_catalog_in_order():
    env = FakeEnv(commands={("choco", "outdated"): ok("git|2.40.0|2.41.0|false\n")})
    entries = tu.check_all(env)
    assert [e["id"] for e in entries] == ["choco:git"] + [t.id for t in tu.CATALOG]


def test_one_failing_tool_does_not_break_the_check():
    capa = spec_of("capa")
    litterbox = "C:\\LitterBox"
    env = git_env(litterbox, behind="2")
    env.paths.add(capa.path)
    env.on(capa.version_cmd, RuntimeError("version\nexploded"))
    entries = by_id(tu.check_all(env))
    assert entries["capa"]["status"] == "error"
    assert "\n" not in entries["capa"]["detail"]
    assert "version" in entries["capa"]["detail"]
    assert entries["litterbox"]["status"] == "update_available"
    assert entries["beaconeye"]["status"] == "not_installed"


def spec_catalog_ids():
    text = open(SPEC, encoding="utf-8").read()
    section = text[text.index("## Werkzeugkatalog"):text.index("- **Git-Prüfung:**")]
    ids = re.findall(r"^\| `([^`|]+)` \|", section, re.M)
    return [i for i in ids if not i.startswith("choco:")]


def test_catalog_ids_are_unique_and_match_spec():
    ids = [t.id for t in tu.CATALOG]
    assert len(ids) == len(set(ids))
    assert ids == spec_catalog_ids()
    assert spec_of("rizin").consumers == ["rizin_sessions"]
    assert spec_of("fibratus").consumers == ["service:fibratus"]
    assert spec_of("rustinel").consumers == ["task:Rustinel", "service:Rustinel"]
    assert tu.CHOCO_CONSUMERS == {
        "python312": ["task:LitterBox", "task:DetonatorAPI", "task:DetonatorUI"],
        "dotnet-8.0-sdk": ["task:DetonatorAgent"],
        "php": ["task:theZoo-WebUI"],
    }


def test_catalog_values():
    assert spec_of("capa").script_args == ["-Force"]
    assert spec_of("threatcheck").script_args == ["-Force", "-Only", "ThreatCheck"]
    assert spec_of("defendercheck").script_args == ["-Force", "-Only", "DefenderCheck"]
    assert spec_of("aether").script_args == ["-NoPrebuilt", "-Force"]
    assert spec_of("rizin").script_args == []
    assert spec_of("sysmon").script_args == ["-Force"]
    assert spec_of("sysmon_config").script_args == []
    assert (spec_of("rustinel").pinned, spec_of("fibratus").pinned, spec_of("rizin").pinned) == (
        "1.1.1", "3.0.0", "2.5.0")
    assert spec_of("litterbox").script == "install-litterbox.ps1"
    assert spec_of("detonator_agent").consumers == ["task:DetonatorAgent"]
    assert spec_of("detonator").consumers == ["task:DetonatorAPI", "task:DetonatorUI"]
    assert spec_of("thezoo").consumers == ["task:theZoo-WebUI"]
    for t in tu.CATALOG:
        assert t.kind in ("winget", "git", "release", "sysinternals")
        assert all(c.split(":")[0] in ("task", "service", "rizin_sessions") or c == "rizin_sessions"
                   for c in t.consumers)


class TestEnv:
    def test_run_maps_missing_exe_and_timeout(self):
        env = tu.Env()
        res = env.run(["tdc-definitely-not-an-exe-xyz"], 5)
        assert res.returncode == 127
        assert res.stderr == "not found: tdc-definitely-not-an-exe-xyz"
        import sys
        res = env.run([sys.executable, "-c", "import time; time.sleep(5)"], 0.3)
        assert res.returncode == 124
        res = env.run([sys.executable, "-c", "print('hi')"], 10)
        assert (res.returncode, res.stdout.strip()) == (0, "hi")

    def test_timeout_kills_the_child_and_returns_quickly(self):
        import sys
        import time
        start = time.monotonic()
        res = tu.Env().run([sys.executable, "-c", "print('partial', flush=True); import time; time.sleep(5)"], 0.5)
        assert res.returncode == 124
        assert time.monotonic() - start < 4
        assert "timed out" in res.stderr

    def test_timeout_kills_grandchildren_holding_the_pipes(self):
        import sys
        import time
        code = ("import subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); time.sleep(20)")
        start = time.monotonic()
        res = tu.Env().run([sys.executable, "-c", code], 0.5)
        assert res.returncode == 124
        assert time.monotonic() - start < 8

    def test_child_gets_git_terminal_prompt_disabled(self):
        import sys
        res = tu.Env().run([sys.executable, "-c", "import os; print(os.environ.get('GIT_TERMINAL_PROMPT'))"], 10)
        assert res.stdout.strip() == "0"

    def test_read_text_and_exists(self, tmp_path):
        f = tmp_path / "m.txt"
        f.write_text("v1.2.3\n", encoding="utf-8")
        env = tu.Env()
        assert env.exists(str(f)) and not env.exists(str(tmp_path / "nope"))
        assert env.read_text(str(f)) == "v1.2.3\n"
        assert env.read_text(str(tmp_path / "nope")) is None

    def test_http_get_headers_and_network_errors(self, monkeypatch):
        seen = {}

        class Resp:
            status_code = 200
            headers = {"ETag": '"x"'}
            text = '{"a": 1}'

            def json(self):
                return {"a": 1}

        def fake_request(method, url, headers=None, timeout=None, allow_redirects=True):
            seen.update(method=method, url=url, headers=headers or {})
            return Resp()

        monkeypatch.setattr(tu.requests, "request", fake_request)
        monkeypatch.setenv("TDC_GITHUB_TOKEN", "tok")
        res = tu.Env().http_get("https://api.github.com/repos/x/y/releases/latest", 5)
        assert res.status == 200 and res.json == {"a": 1} and res.headers == {"etag": '"x"'}
        assert seen["headers"]["Accept"] == "application/vnd.github+json"
        assert seen["headers"]["Authorization"] == "Bearer tok"
        tu.Env().http_get("https://download.sysinternals.com/files/Sysmon.zip", 5, method="HEAD")
        assert "Authorization" not in seen["headers"] and seen["method"] == "HEAD"

        def boom(*a, **k):
            raise tu.requests.ConnectionError("no route")

        monkeypatch.setattr(tu.requests, "request", boom)
        assert tu.Env().http_get("https://api.github.com", 5).status == 0


# ---------------------------------------------------------------------------
# UpdateManager
# ---------------------------------------------------------------------------

import json  # noqa: E402

PS = ["powershell", "-NoProfile", "-Command"]
SCRIPT_PREFIX = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]


def tool_entry(tool_id, status="update_available", installed="1.0.0", available="1.1.0", pinned=None, name=None):
    spec = next((t for t in tu.CATALOG if t.id == tool_id), None)
    return {"id": tool_id, "name": name or (spec.name if spec else tool_id.split(":")[-1]),
            "kind": spec.kind if spec else "choco", "installed": installed, "available": available,
            "status": status, "pinned": pinned, "detail": "", "log": [], "updated_at": None}


class World:
    """A FakeEnv with a script dir, plus a manager seeded with a state file."""

    def __init__(self, tmp_path, entries, **manager_kwargs):
        self.tmp = tmp_path
        self.scripts = str(tmp_path / "scripts")
        self.state_path = str(tmp_path / "state.json")
        self.log_path = str(tmp_path / "logs" / "tool-updates.log")
        self.env = FakeEnv()
        self.running = set()
        self.events = []
        self.installed_done = set()
        if entries is not None:
            with open(self.state_path, "w") as handle:
                json.dump({"mode": "idle", "checked_at": "2026-01-01T00:00:00Z", "tools": entries}, handle)
        self.env.on(PS, self._powershell)
        self.manager = None
        self.kwargs = manager_kwargs

    def build(self):
        self.manager = tu.UpdateManager(
            self.env, self.state_path, self.log_path, self.scripts, spawn=lambda f: f(), **self.kwargs)
        return self.manager

    def _powershell(self, args):
        script = args[-1]
        name = re.search(r"(?:-TaskName|-Name|\$n=) ?'([^']+)'", script)
        name = name.group(1) if name else "?"
        if "Stop-ScheduledTask" in script or "Stop-Service" in script:
            self.events.append(("stop", name))
        elif "Start-ScheduledTask" in script or "Start-Service" in script:
            self.events.append(("start", name))
        else:
            key = ("task:" if "ScheduledTask" in script else "service:") + name
            return ok("True\n" if key in self.running else "False\n")
        return ok()

    def script(self, name, result=None, effect=None):
        path = os.path.join(self.scripts, name)
        self.env.paths.add(path)

        def handler(args):
            self.events.append(("script", name, args[len(SCRIPT_PREFIX) + 1:]))
            if effect:
                effect(args)
            return result if result is not None else ok("done\n")
        self.env.on(SCRIPT_PREFIX + [path], handler)

    def git_tool(self, path, behind_before="2"):
        base = GIT_PREFIX + [path]
        self.env.paths.update([path + "\\.git", path])
        self.env.on(base + ["fetch"], ok())
        self.env.on(base + ["rev-parse", "--short", "HEAD"], ok("abc1234\n"))
        self.env.on(base + ["rev-parse", "--short", "@{u}"], ok("def5678\n"))
        self.env.on(base + ["rev-list", "--count", "HEAD..@{u}"],
                    lambda a: ok("0\n" if self.installed_done else behind_before + "\n"))
        self.env.on(base + ["pull"], lambda a: (self.events.append(("pull", path, a[len(base):])) or ok("Updating\n")))

    def kinds(self):
        return [e[0] for e in self.events]


def snap_tool(manager, tool_id):
    return next(t for t in manager.snapshot()["tools"] if t["id"] == tool_id)


def test_apply_all_skips_pinned(tmp_path):
    w = World(tmp_path, [
        tool_entry("capa"), tool_entry("beaconeye"),
        tool_entry("rustinel", "pinned_update", "1.1.1", "1.2.0", pinned="1.1.1"),
        tool_entry("process_dump", "up_to_date"),
    ])
    w.script("install-capa.ps1", effect=lambda a: w.installed_done.add("capa"))
    w.script("install-beaconeye.ps1")
    m = w.build()
    code, body = m.start_apply("all")
    assert (code, body) == (202, {"started": True, "tools": ["capa", "beaconeye"]})
    assert snap_tool(m, "rustinel")["status"] == "pinned_update"
    assert not [e for e in w.events if e[0] == "script" and "rustinel" in e[1]]
    assert m.snapshot()["last_run"]["results"].keys() == {"capa", "beaconeye"}


def release_world(tmp_path, tool_id, script, version_after, entries, available="1.2.0", installed="1.1.1"):
    """A release tool whose version command reports the old version until the script ran."""
    spec = spec_of(tool_id)
    w = World(tmp_path, entries)
    w.env.paths.add(spec.path)
    w.env.on(spec.version_cmd, lambda a: ok(
        "x %s\n" % (version_after if w.installed_done else installed)))
    w.env.urls[("GET", "https://api.github.com/repos/%s/releases/latest" % spec.repo)] = js(
        {"tag_name": "v" + available})
    w.script(script, effect=lambda a: w.installed_done.add(tool_id))
    return w


def test_apply_pinned_needs_include_pinned(tmp_path):
    entries = [tool_entry("rustinel", "pinned_update", "1.1.1", "1.2.0", pinned="1.1.1")]
    w = release_world(tmp_path, "rustinel", "install-rustinel.ps1", "1.2.0", entries)
    m = w.build()
    code, body = m.start_apply(["rustinel"])
    assert code == 409
    assert body == {"error": "Rustinel is pinned to 1.1.1. Pass include_pinned to install 1.2.0."}
    assert m.snapshot()["mode"] == "idle"
    code, body = m.start_apply(["rustinel"], include_pinned=True)
    assert code == 202
    script = [e for e in w.events if e[0] == "script"]
    assert script[0][2] == ["-Force", "-Version", "1.2.0"]
    assert snap_tool(m, "rustinel")["status"] == "updated"
    assert snap_tool(m, "rustinel")["installed"] == "1.2.0"


def test_running_consumer_restarted_after_failure(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox", installed="abc1234", available="def5678")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1", result=fail("kaboom", 1))
    w.running.add("task:LitterBox")
    m = w.build()
    assert m.start_apply(["litterbox"])[0] == 202
    kinds = w.kinds()
    assert kinds.index("stop") < kinds.index("script") < kinds.index("start")
    assert ("stop", "LitterBox") in w.events and ("start", "LitterBox") in w.events
    assert snap_tool(m, "litterbox")["status"] == "failed"
    assert "Exit code 1" in snap_tool(m, "litterbox")["detail"]


def test_consumer_not_running_is_not_started(tmp_path):
    w = World(tmp_path, [tool_entry("detonator"), ])
    w.git_tool("C:\\detonator")
    w.script("install-detonator.ps1", effect=lambda a: w.installed_done.add("d"))
    w.running.add("task:DetonatorAPI")
    m = w.build()
    m.start_apply(["detonator"])
    assert ("stop", "DetonatorAPI") in w.events and ("start", "DetonatorAPI") in w.events
    assert ("stop", "DetonatorUI") not in w.events and ("start", "DetonatorUI") not in w.events


def test_consumers_restarted_even_when_the_script_raises(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1", effect=lambda a: (_ for _ in ()).throw(RuntimeError("crash")))
    w.running.add("task:LitterBox")
    m = w.build()
    m.start_apply(["litterbox"])
    assert ("start", "LitterBox") in w.events
    assert snap_tool(m, "litterbox")["status"] == "failed"
    assert m.snapshot()["mode"] == "idle"


def test_reboot_required_exit_code(tmp_path):
    w = World(tmp_path, [tool_entry("choco:git", installed="2.40.0", available="2.41.0")])
    w.env.on(["choco", "upgrade", "git"], RunResult(3010, "reboot", ""))
    w.env.on(["choco", "outdated"], ok("git|2.40.0|2.41.0|false\n"))
    m = w.build()
    assert m.start_apply(["choco:git"])[0] == 202
    assert snap_tool(m, "choco:git")["status"] == "reboot_required"
    assert w.env.commands_matching("choco", "upgrade", "git", "-y", "--no-progress")


def test_choco_success_rechecks_with_choco_outdated(tmp_path):
    w = World(tmp_path, [tool_entry("choco:git", installed="2.40.0", available="2.41.0")])
    w.env.on(["choco", "upgrade"], ok("upgraded"))
    w.env.on(["choco", "outdated"], ok(""))
    m = w.build()
    m.start_apply("all")
    assert snap_tool(m, "choco:git")["status"] == "updated"
    assert snap_tool(m, "choco:git")["installed"] == "2.41.0"


def test_preconditions_block(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.script("install-capa.ps1")
    m = w.build()
    m.preconditions = lambda: "A detonation is running."
    assert m.start_apply("all") == (409, {"error": "A detonation is running."})
    assert w.env.run_calls == []
    assert m.snapshot()["mode"] == "idle"
    assert snap_tool(m, "capa")["status"] == "update_available"


def test_busy_returns_409(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.kwargs["spawn"] = None
    m = tu.UpdateManager(w.env, w.state_path, w.log_path, w.scripts, spawn=lambda f: None)
    assert m.start_check() == (202, {"started": True})
    assert m.snapshot()["mode"] == "checking"
    busy = (409, {"error": "An update check or install is already running."})
    assert m.start_check() == busy
    assert m.start_apply("all") == busy
    assert not m.maintenance


def test_unknown_tool_400(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    m = w.build()
    assert m.start_apply(["nope", "capa", "other"]) == (400, {"error": "Unknown tools: nope, other"})
    assert m.snapshot()["mode"] == "idle"


def test_nothing_to_install_409(tmp_path):
    w = World(tmp_path, [tool_entry("capa", "up_to_date")])
    m = w.build()
    assert m.start_apply("all") == (409, {"error": "No updates to install."})
    assert m.start_apply([]) == (409, {"error": "No updates to install."})


def test_maintenance_flag_during_run(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    seen = []
    m = w.build()
    w.script("install-capa.ps1", effect=lambda a: seen.append((m.maintenance, m.snapshot()["mode"],
                                                              m.snapshot()["progress"]["current"],
                                                              snap_tool(m, "capa")["status"])))
    assert not m.maintenance
    m.start_apply("all")
    assert seen == [(True, "updating", "capa", "updating")]
    assert not m.maintenance


def test_interrupted_state_recovered(tmp_path):
    w = World(tmp_path, None)
    with open(w.state_path, "w") as handle:
        json.dump({"mode": "updating", "checked_at": "2026-01-01T00:00:00Z",
                   "queued_prev": {"beaconeye": "update_available"},
                   "tools": [tool_entry("capa", "updating"), tool_entry("beaconeye", "queued"),
                             tool_entry("process_dump", "queued")]}, handle)
    m = w.build()
    snap = m.snapshot()
    assert snap["mode"] == "idle" and not m.maintenance
    assert snap_tool(m, "capa")["status"] == "failed"
    assert snap_tool(m, "capa")["detail"] == "Interrupted: the web UI restarted during the update."
    assert snap_tool(m, "beaconeye")["status"] == "update_available"
    assert snap_tool(m, "process_dump")["status"] == "unknown"
    with open(w.state_path) as handle:
        assert json.load(handle)["mode"] == "idle"
    assert tu.UpdateManager(w.env, w.state_path, w.log_path, w.scripts).snapshot()["mode"] == "idle"


def test_checking_state_becomes_idle_and_garbage_state_is_ignored(tmp_path):
    w = World(tmp_path, None)
    with open(w.state_path, "w") as handle:
        json.dump({"mode": "checking", "tools": []}, handle)
    assert w.build().snapshot()["mode"] == "idle"
    with open(w.state_path, "w") as handle:
        handle.write("{broken")
    assert w.build().snapshot()["tools"] == []


def test_git_update_pulls_with_autostash_then_runs_script(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox", installed="abc1234", available="def5678")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1", effect=lambda a: w.installed_done.add("x"))
    m = w.build()
    m.start_apply(["litterbox"])
    assert w.kinds() == ["pull", "script"]
    assert w.events[0][2] == ["pull", "--ff-only", "--autostash"]
    assert snap_tool(m, "litterbox")["status"] == "updated"


def test_failed_pull_skips_the_script(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1")
    w.env.on(GIT_PREFIX + ["C:\\LitterBox", "pull"], fail("not fast-forward", 1))
    m = w.build()
    m.start_apply(["litterbox"])
    assert "script" not in w.kinds()
    assert snap_tool(m, "litterbox")["status"] == "failed"


def rizin_entry():
    return tool_entry("rizin", "pinned_update", "2.5.0", "2.6.0", pinned="2.5.0")


def test_rizin_without_digest_fails_and_closes_sessions(tmp_path):
    closed = []
    w = World(tmp_path, [rizin_entry()], close_rizin=lambda: closed.append(1))
    w.script("install-rizin.ps1")
    w.env.urls[("GET", "https://api.github.com/repos/rizinorg/cutter/releases/latest")] = js(
        {"tag_name": "v2.6.0", "assets": [{"name": "Cutter-v2.6.0-Windows-x86_64.zip"}]})
    m = w.build()
    assert m.start_apply(["rizin"], include_pinned=True)[0] == 202
    assert closed == [1]
    assert snap_tool(m, "rizin")["status"] == "failed"
    assert snap_tool(m, "rizin")["detail"] == "GitHub publishes no SHA-256 for this package; not installed."
    assert "script" not in w.kinds()


def test_rizin_passes_version_and_digest(tmp_path):
    w = World(tmp_path, [rizin_entry()])
    w.script("install-rizin.ps1", effect=lambda a: w.installed_done.add("r"))
    spec = spec_of("rizin")
    w.env.paths.add(spec.path)
    w.env.on(["C:\\tools\\cutter\\never"], ok())
    w.env.files[spec.marker] = "Cutter-v2.5.0-Windows-x86_64.zip sha256:" + "ab" * 32

    def new_marker(a):
        w.env.files[spec.marker] = "Cutter-v2.6.0-Windows-x86_64.zip sha256:" + "cd" * 32
        w.installed_done.add("r")
    w.script("install-rizin.ps1", effect=new_marker)
    w.env.urls[("GET", "https://api.github.com/repos/rizinorg/cutter/releases/latest")] = js(
        {"tag_name": "v2.6.0", "assets": [
            {"name": "Cutter-v2.6.0-Windows-x86_64.zip", "digest": "sha256:" + "CD" * 32}]})
    m = w.build()
    m.start_apply(["rizin"], include_pinned=True)
    script = [e for e in w.events if e[0] == "script"][0]
    assert script[2] == ["-Version", "2.6.0", "-PackageSha256", "cd" * 32]
    assert snap_tool(m, "rizin")["status"] == "updated"


def test_exit_zero_without_effect_is_failed(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox", installed="abc1234", available="def5678")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1")  # exits 0, installs nothing
    m = w.build()
    m.start_apply(["litterbox"])
    tool = snap_tool(m, "litterbox")
    assert tool["status"] == "failed"
    assert tool["detail"] == "Install finished but the tool still reports abc1234; see the log."


def test_installed_tool_missing_after_the_run_is_failed(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.script("install-capa.ps1")
    m = w.build()
    m.start_apply("all")
    assert snap_tool(m, "capa")["status"] == "failed"
    assert snap_tool(m, "capa")["detail"] == "Install finished but the tool is not found; see the log."


def test_missing_script_fails_cleanly(tmp_path):
    w = World(tmp_path, [tool_entry("capa"), tool_entry("beaconeye")])
    w.script("install-beaconeye.ps1", effect=lambda a: w.installed_done.add("b"))
    w.running.add("task:LitterBox")
    m = w.build()
    m.start_apply("all")
    path = os.path.join(w.scripts, "install-capa.ps1")
    assert snap_tool(m, "capa")["status"] == "failed"
    assert snap_tool(m, "capa")["detail"] == "Install script missing: %s (run make deploy)" % path
    assert m.snapshot()["last_run"]["results"]["capa"] == "failed"
    assert "beaconeye" in m.snapshot()["last_run"]["results"]
    assert m.snapshot()["mode"] == "idle"


def test_python312_runs_last(tmp_path):
    w = World(tmp_path, [
        tool_entry("choco:python312", installed="3.12.1", available="3.12.2"),
        tool_entry("choco:git", installed="2.40.0", available="2.41.0"),
        tool_entry("capa"),
    ])
    w.script("install-capa.ps1")
    w.env.on(["choco", "upgrade"], ok())
    w.env.on(["choco", "outdated"], ok(""))
    w.running.update(["task:LitterBox", "task:DetonatorAPI"])
    m = w.build()
    code, body = m.start_apply("all")
    assert body["tools"] == ["capa", "choco:git", "choco:python312"]
    order = [c for c in w.env.run_calls if c[:2] == ["choco", "upgrade"] or c[:5] == SCRIPT_PREFIX]
    assert [c[2] if c[0] == "choco" else "capa" for c in order] == ["capa", "git", "python312"]
    stops = [e[1] for e in w.events if e[0] == "stop"]
    assert stops == ["LitterBox", "DetonatorAPI"]
    assert [e[1] for e in w.events if e[0] == "start"] == ["LitterBox", "DetonatorAPI"]


def test_log_is_capped_and_written_to_file(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.script("install-capa.ps1", result=ok("\n".join("line %d" % i for i in range(500))))
    m = w.build()
    m.start_apply("all")
    log = snap_tool(m, "capa")["log"]
    assert len(log) == 200
    assert log[-1].endswith("[capa] line 499")
    assert re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \[capa\] ", log[0])
    with open(w.log_path) as handle:
        assert handle.read().splitlines() == log
    assert snap_tool(m, "capa")["updated_at"]


def test_state_written_atomically(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.script("install-capa.ps1")
    w.env.paths.add(spec_of("capa").path)
    m = w.build()
    m.start_apply("all")
    assert not os.path.exists(w.state_path + ".tmp")
    with open(w.state_path) as handle:
        data = json.load(handle)
    assert data["mode"] == "idle"
    assert data["last_run"]["results"] == {"capa": "updated"}
    assert data["tools"][0]["detail"].startswith("Installed; could not re-check")


def test_check_keeps_log_and_updated_at_and_sets_checked_at(tmp_path):
    spec = spec_of("litterbox")
    previous = tool_entry("litterbox", "failed")
    previous.update(log=["a line"], updated_at="2026-01-02T00:00:00Z")
    w = World(tmp_path, [previous])
    w.git_tool(spec.path, behind_before="1")
    m = w.build()
    assert m.start_check() == (202, {"started": True})
    snap = m.snapshot()
    assert snap["mode"] == "idle"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", snap["checked_at"])
    tool = snap_tool(m, "litterbox")
    assert tool["status"] == "update_available"
    assert tool["log"] == ["a line"] and tool["updated_at"] == "2026-01-02T00:00:00Z"


def test_snapshot_is_a_deep_copy(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    m = w.build()
    snap = m.snapshot()
    snap["tools"][0]["status"] = "hacked"
    assert snap_tool(m, "capa")["status"] == "update_available"
    assert set(snap) == {"mode", "checked_at", "tools", "progress", "last_run"}


def test_consumer_helpers_quote_names_and_use_powershell():
    env = FakeEnv()
    seen = []
    env.on(PS, lambda a: (seen.append(a[-1]) or ok("True\n")))
    assert tu.consumer_running("task:Lit'ter", env) is True
    assert "'Lit''ter'" in seen[-1] and "Get-ScheduledTask" in seen[-1]
    assert tu.consumer_running("service:fibratus", env) is True
    assert "Get-Service" in seen[-1]
    tu.stop_consumer("service:fibratus", env)
    assert "Stop-Service -Name 'fibratus' -Force" in seen[-1]
    tu.stop_consumer("task:LitterBox", env)
    assert "Stop-ScheduledTask" in seen[-1] and "Stop-Process" in seen[-1]
    tu.start_consumer("task:LitterBox", env)
    assert "Start-ScheduledTask -TaskName 'LitterBox'" in seen[-1]
    env.on(PS, fail("access denied"))
    with pytest.raises(RuntimeError):
        tu.stop_consumer("service:fibratus", env)
    assert tu.consumer_running("service:fibratus", env) is False
