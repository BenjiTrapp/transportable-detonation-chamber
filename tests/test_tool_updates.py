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
            if tuple(args[:len(prefix)]) == prefix and (best is None or len(prefix) > len(best[0])):
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
