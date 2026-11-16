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

GIT_HARDENING = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=NUL", "-c", "core.sshCommand=",
                 "-c", "credential.helper="]


def git_base(path):
    """The start of every git call: hardened for SYSTEM, safe.directory for this repo only."""
    return ["git"] + GIT_HARDENING + ["-c", "safe.directory=" + path.replace("\\", "/"), "-C", path]


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
    base = git_base(path)
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


def test_python312_is_held_back_by_tdc_not_by_choco():
    env = FakeEnv(commands={("choco", "outdated"): ok(
        "python312|3.12.1|3.12.2|false\ngit|2.40.0|2.41.0|false\nphp|8.2.1|8.3.0|true\n")})
    entries = by_id(tu.check_choco(env))
    py = entries["choco:python312"]
    assert py["status"] == "pinned_update" and py["pinned"] == "3.12.1"
    assert py["detail"] == "The web UI runs on this Python; updating it restarts services and may need a reboot."
    assert py["choco_pinned"] is False
    assert entries["choco:git"]["status"] == "update_available" and entries["choco:git"]["choco_pinned"] is False
    assert entries["choco:php"]["choco_pinned"] is True and entries["choco:php"]["pinned"] == "8.2.1"


def test_check_choco_drops_install_duplicates_of_listed_metapackages():
    text = ("git|2.40.0|2.41.0|false\ngit.install|2.40.0|2.41.0|false\n"
            "7zip|23.1|24.0|false\n7zip.install|23.1|24.0|false\n"
            "dotnet-8.0-sdk|8.0.100|8.0.200|false\ndotnet-8.0-sdk-4xx|8.0.400|8.0.500|false\n"
            "vlc.install|3.0|3.1|false\n")
    env = FakeEnv(commands={("choco", "outdated"): ok(text)})
    ids = [e["id"] for e in tu.check_choco(env)]
    assert ids == ["choco:git", "choco:7zip", "choco:dotnet-8.0-sdk", "choco:dotnet-8.0-sdk-4xx",
                   "choco:vlc.install"]


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
        assert call[:len(git_base(path))] == git_base(path)
        assert "safe.directory=*" not in call


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
    entry = tu.check_tool(spec, FakeEnv(paths=[spec.path], urls={("GET", url): js({}, status=429)}))
    assert entry["status"] == "error"
    assert entry["detail"] == "GitHub API answered HTTP 429 for CCob/BeaconEye"


def test_release_repo_without_releases_is_unknown():
    for tool_id, repo in (("beaconeye", "CCob/BeaconEye"), ("threatcheck", "rasta-mouse/ThreatCheck"),
                          ("defendercheck", "matterpreter/DefenderCheck")):
        spec = spec_of(tool_id)
        url = "https://api.github.com/repos/%s/releases/latest" % repo
        env = FakeEnv(paths=[spec.path], urls={("GET", url): js({"message": "Not Found"}, status=404)})
        entry = tu.check_tool(spec, env)
        assert entry["status"] == "unknown"
        assert entry["detail"] == "Upstream publishes no GitHub releases."
        assert entry["installed"] == "unknown"
        assert entry["available"] is None
    env = FakeEnv(paths=[spec.path], files={spec.marker: "v1.2\n"},
                  urls={("GET", url): js({"message": "Not Found"}, status=404)})
    assert tu.check_tool(spec, env)["installed"] == "1.2"


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
    assert entry["status"] == "update_available"
    assert entry["installed"] is None
    assert entry["available"] == "abc"
    assert entry["detail"] == "Installed version unknown; an update records it"
    # a marker without the key behaves the same
    env = FakeEnv(paths=[spec.path], files={spec.marker: '{"config_etag": "x"}'}, urls=head)
    assert tu.check_tool(spec, env)["status"] == "update_available"
    # without a known remote ETag nothing can be said
    env = FakeEnv(paths=[spec.path], urls={("HEAD", url): HttpResult(200, {}, None, "")})
    entry = tu.check_tool(spec, env)
    assert entry["status"] == "unknown"
    assert entry["detail"] == "The server sent no ETag"


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
    # both rows run install-detonator.ps1, so both stop the tasks of both
    both = ["task:DetonatorAgent", "task:DetonatorAPI", "task:DetonatorUI"]
    assert spec_of("detonator_agent").consumers == both
    assert spec_of("detonator").consumers == both
    assert spec_of("detonator_agent").script == spec_of("detonator").script
    assert spec_of("thezoo").consumers == ["task:theZoo-WebUI"]
    for t in tu.CATALOG:
        assert t.kind in ("winget", "git", "release", "sysinternals")
        assert all(c.split(":")[0] in ("task", "service", "rizin_sessions") or c == "rizin_sessions"
                   for c in t.consumers)


class TestEnv:
    def test_run_decodes_utf16_lines_inside_a_utf8_stream(self):
        import sys
        code = ("import sys; w = sys.stdout.buffer.write; "
                "w(b'[*] Uninstalling Sysmon...\\r\\n'); "
                "w('Sysmon64a removed.\\r\\nSysmonDrv removed.\\r\\n'.encode('utf-16-le')); "
                "w(b'[+] done caf\\xc3\\xa9\\r\\n'); "
                "sys.stderr.buffer.write('Error: driver'.encode('utf-16-le'))")
        res = tu.Env().run([sys.executable, "-c", code], 10)
        assert res.stdout == "[*] Uninstalling Sysmon...\nSysmon64a removed.\nSysmonDrv removed.\n[+] done caf\u00e9\n"
        assert res.stderr == "Error: driver"

    def test_run_strips_stray_nuls_and_keeps_plain_utf8(self):
        import sys
        res = tu.Env().run([sys.executable, "-c", "print('caf\\u00e9 is fine, plain output with one stray NUL\\x00')"], 10)
        assert res.stdout.strip() == "caf\u00e9 is fine, plain output with one stray NUL"

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
        self.task_dirs = ""
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
        if ".Actions" in script and "Stop-ScheduledTask" not in script:
            return ok(self.task_dirs)
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
        base = git_base(path)
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
    w.env.on(git_base("C:\\LitterBox") + ["pull"], fail("not fast-forward", 1))
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
    assert "Stop-ScheduledTask -TaskName $n" in seen[-1] and "'LitterBox'" in seen[-1]
    tu.start_consumer("task:LitterBox", env)
    assert "Start-ScheduledTask -TaskName 'LitterBox'" in seen[-1]
    env.on(PS, fail("access denied"))
    with pytest.raises(RuntimeError):
        tu.stop_consumer("service:fibratus", env)
    assert tu.consumer_running("service:fibratus", env) is False


# ---------------------------------------------------------------------------
# Review fixes: retry of failed, kill scope, preconditions outside the lock
# ---------------------------------------------------------------------------

import threading  # noqa: E402


def test_retry_of_failed_tool(tmp_path):
    failed = tool_entry("capa", "failed", installed="1.0.0", available="1.1.0")
    failed["detail"] = "Exit code 1; see the log."
    w = World(tmp_path, [failed, tool_entry("beaconeye", "failed")])
    w.script("install-capa.ps1")
    m = w.build()
    code, body = m.start_apply(["capa"])
    assert (code, body) == (202, {"started": True, "tools": ["capa"]})
    assert w.kinds() == ["script"]
    assert snap_tool(m, "beaconeye")["status"] == "failed"  # not selected


def test_all_ignores_failed_tools(tmp_path):
    w = World(tmp_path, [tool_entry("capa", "failed"), tool_entry("beaconeye", "update_available")])
    w.script("install-beaconeye.ps1")
    m = w.build()
    code, body = m.start_apply("all")
    assert body["tools"] == ["beaconeye"]
    assert m.snapshot()["last_run"]["results"].keys() == {"beaconeye"}
    assert snap_tool(m, "capa")["status"] == "failed"


def test_retry_of_failed_pinned_tool_needs_include_pinned(tmp_path):
    entries = [tool_entry("rustinel", "failed", "1.1.1", "1.2.0", pinned="1.1.1")]
    w = release_world(tmp_path, "rustinel", "install-rustinel.ps1", "1.2.0", entries)
    m = w.build()
    code, body = m.start_apply(["rustinel"])
    assert code == 409
    assert body == {"error": "Rustinel is pinned to 1.1.1. Pass include_pinned to install 1.2.0."}
    assert snap_tool(m, "rustinel")["status"] == "failed"
    assert m.snapshot()["mode"] == "idle"
    code, body = m.start_apply(["rustinel"], include_pinned=True)
    assert code == 202
    assert [e for e in w.events if e[0] == "script"][0][2] == ["-Force", "-Version", "1.2.0"]
    assert snap_tool(m, "rustinel")["status"] == "updated"


def test_failed_pinned_tool_at_its_pin_needs_no_include_pinned(tmp_path):
    entries = [tool_entry("rustinel", "failed", "1.0.0", "1.1.1", pinned="1.1.1")]
    w = release_world(tmp_path, "rustinel", "install-rustinel.ps1", "1.1.1", entries, available="1.1.1")
    assert w.build().start_apply(["rustinel"])[0] == 202


def test_pinned_tool_without_target_version_fails_cleanly(tmp_path):
    for i, available in enumerate((None, "", "unknown")):
        sub = tmp_path / ("case%d" % i)
        sub.mkdir()
        entries = [tool_entry("rustinel", "failed", "1.1.1", available, pinned="1.1.1")]
        w = release_world(sub, "rustinel", "install-rustinel.ps1", "1.2.0", entries)
        m = w.build()
        assert m.start_apply(["rustinel"], include_pinned=True)[0] == 202
        assert "script" not in w.kinds()
        assert snap_tool(m, "rustinel")["status"] == "failed"
        assert snap_tool(m, "rustinel")["detail"] == (
            "No target version known for Rustinel; run Check for updates first.")


@pytest.mark.parametrize("path", [
    "C:\\", "C:", "C:\\Windows", "C:\\Windows\\System32", "c:\\windows\\system32\\wbem",
    "C:\\Program Files", "C:\\Program Files\\Fibratus\\Bin", "C:\\Program Files (x86)\\X",
    "C:\\Python312", "C:\\Python312\\Scripts", "C:\\python311", "C:\\Python3",
    "", "relative\\dir", "\\\\server\\share\\dir", "LitterBox", "C:\\LitterBox\\..\\Windows",
    "C:\\Users", "C:\\Users\\bob\\tools", "c:\\users\\Public", "C:\\ProgramData", "C:\\ProgramData\\Tool\\bin",
])
def test_safe_kill_dirs_refuses(path):
    assert tu._safe_kill_dirs([path]) == []


def test_safe_kill_dirs_accepts_install_folders():
    dirs = ['"C:\\LitterBox"', "C:\\LitterBox\\", "C:\\tools\\theZoo-WebUI", "D:\\detonator", "C:\\Windows",
            "C:\\Python312x\\"]
    assert tu._safe_kill_dirs(dirs) == ["C:\\LitterBox", "C:\\tools\\theZoo-WebUI", "D:\\detonator"]
    # custom Windows / Program Files folders
    assert tu._safe_kill_dirs(["E:\\Win\\x", "E:\\Apps\\y"], windows_dir="E:\\Win", program_files=["E:\\Apps"]) == []


def test_stop_task_kills_only_approved_dirs():
    env = FakeEnv()
    seen = []

    def answer(args):
        seen.append(args[-1])
        if ".Actions" in args[-1] and "Stop-ScheduledTask" not in args[-1]:
            return ok("C:\\Python312\nC:\\LitterBox\nC:\\\n")
        return ok()
    env.on(PS, answer)
    tu.stop_consumer("task:LitterBox", env)
    stop = seen[-1]
    assert "Stop-ScheduledTask" in stop and "Stop-Process" in stop
    assert "'C:\\LitterBox'" in stop
    assert "Python312" not in stop and "'C:\\'" not in stop
    assert str(os.getpid()) in stop and "ParentProcessId" in stop


def test_stop_task_without_approved_dirs_kills_no_processes():
    env = FakeEnv()
    seen = []
    env.on(PS, lambda a: (seen.append(a[-1]) or ok("C:\\Python312\n")))
    tu.stop_consumer("task:LitterBox", env)
    assert "Stop-ScheduledTask" in seen[-1] and "Stop-Process" not in seen[-1]


def test_stop_task_query_failure_raises():
    env = FakeEnv()
    env.on(PS, fail("no such task"))
    with pytest.raises(RuntimeError):
        tu.stop_consumer("task:Nope", env)


def test_preconditions_callback_does_not_hold_the_lock(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.script("install-capa.ps1")
    m = w.build()
    seen = {}

    def reason():
        # another thread must get the lock while the callback is running
        worker = threading.Thread(target=lambda: seen.setdefault("snap", m.snapshot()))
        worker.start()
        worker.join(2)
        seen["finished"] = not worker.is_alive()
        return None
    m.preconditions = reason
    assert m.start_apply("all")[0] == 202
    assert seen["finished"] and seen["snap"]["mode"] == "idle"


def test_mode_change_during_preconditions_gives_busy(tmp_path):
    w = World(tmp_path, [tool_entry("capa")])
    w.script("install-capa.ps1")
    m = tu.UpdateManager(w.env, w.state_path, w.log_path, w.scripts, spawn=lambda f: None)

    def reason():
        assert m.start_check()[0] == 202  # someone else got in first
        return None
    m.preconditions = reason
    assert m.start_apply("all") == (409, {"error": "An update check or install is already running."})
    assert snap_tool(m, "capa")["status"] == "update_available"
    assert m.snapshot()["mode"] == "checking"


# ---------------------------------------------------------------------------
# Flask routes, maintenance gate, preconditions, daily check (webui/app.py)
# ---------------------------------------------------------------------------

MAINTENANCE_TEXT = "Maintenance: tool updates are running. Detonations, scans and uploads are paused."
DETONATION_TEXT = "A detonation is running. Wait until it finishes."


class _Reply:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


@pytest.fixture
def update_manager(tdc, monkeypatch, tmp_path):
    """A manager on a FakeEnv wired into the web UI; no thread, no real process."""
    manager = tu.UpdateManager(FakeEnv(), str(tmp_path / "state.json"), str(tmp_path / "updates.log"),
                               str(tmp_path / "scripts"), preconditions=tdc._update_preconditions,
                               spawn=lambda work: None)
    monkeypatch.setattr(tdc, "_update_manager", manager)
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: None)
    monkeypatch.setattr(tdc, "_sweep_state", {"running": False})
    monkeypatch.setattr(tdc, "_pd_db_state", {"running": False})
    return manager


def test_updates_get_shape(client, update_manager):
    resp = client.get("/api/updates")
    assert resp.status_code == 200
    body = resp.get_json()
    assert {"mode", "checked_at", "tools", "progress", "last_run"} <= set(body)
    assert body["mode"] == "idle"


def test_maintenance_blocks_unsafe_requests(client, update_manager):
    update_manager._state["mode"] = "updating"
    assert update_manager.maintenance
    for method, path in (("post", "/api/submit"), ("post", "/api/service/launch"),
                         ("put", "/api/anything"), ("delete", "/api/anything")):
        resp = getattr(client, method)(path)
        assert resp.status_code == 503, path
        assert resp.get_json() == {"error": MAINTENANCE_TEXT, "maintenance": True}
    assert client.get("/api/status").status_code != 503
    assert client.get("/api/updates").status_code == 200
    assert client.post("/api/updates/check").status_code == 409  # busy, but not blocked
    assert client.post("/api/updates/apply", json={"tools": "all"}).status_code == 409


def test_no_gate_when_idle(client, update_manager):
    assert client.post("/api/service/launch").status_code != 503


def test_gate_does_not_create_the_manager(client, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_update_manager", None)
    client.post("/api/service/launch")
    assert tdc._update_manager is None


def test_apply_refused_during_detonation(client, tdc, update_manager, monkeypatch):
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: _Reply({"in_use": True}))
    resp = client.post("/api/updates/apply", json={"tools": "all"})
    assert resp.status_code == 409
    assert resp.get_json() == {"error": DETONATION_TEXT}
    assert update_manager.snapshot()["mode"] == "idle"


def test_preconditions_reasons(tdc, update_manager, monkeypatch):
    assert tdc._update_preconditions() is None  # agent unreachable is not a detonation
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: _Reply({"locked": True}))
    assert tdc._update_preconditions() == DETONATION_TEXT
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: _Reply({"in_use": False}))
    assert tdc._update_preconditions() is None
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: _Reply("not json at all", 500))
    assert tdc._update_preconditions() is None
    monkeypatch.setattr(tdc, "_sweep_state", {"running": True})
    assert tdc._update_preconditions() == "A memory sweep is running."
    monkeypatch.setattr(tdc, "_sweep_state", {"running": False})
    monkeypatch.setattr(tdc, "_pd_db_state", {"running": True})
    assert tdc._update_preconditions() == "A process dump is running."


def test_agent_probe_uses_the_lock_status_url(tdc, update_manager, monkeypatch):
    urls = []
    monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: urls.append(url))
    tdc._update_preconditions()
    assert urls == [tdc.DETONATOR_AGENT_API + "/api/lock/status"]


@pytest.mark.parametrize("body", [None, {}, {"tools": 5}, {"tools": None}, {"tools": ["a", 3]},
                                  {"tools": {"a": 1}}, ["all"], {"tools": "all", "include_pinned": "yes"}])
def test_apply_bad_body_400(client, update_manager, body):
    resp = client.post("/api/updates/apply", json=body) if body is not None else \
        client.post("/api/updates/apply", data="not json", content_type="text/plain")
    assert resp.status_code == 400
    assert resp.get_json()["error"]


def test_apply_bad_body_message(client, update_manager):
    resp = client.post("/api/updates/apply", json={"tools": 5})
    assert resp.get_json() == {"error": 'tools must be "all" or a list of tool ids'}


def test_apply_passes_the_request_to_the_manager(client, update_manager, monkeypatch):
    calls = []
    monkeypatch.setattr(update_manager, "start_apply",
                        lambda tools, include_pinned=False: calls.append((tools, include_pinned)) or (202, {"started": True}))
    assert client.post("/api/updates/apply", json={"tools": ["capa"], "include_pinned": True}).status_code == 202
    assert client.post("/api/updates/apply", json={"tools": "all"}).get_json() == {"started": True}
    assert calls == [(["capa"], True), ("all", False)]


def test_check_route_starts_a_check(client, update_manager):
    resp = client.post("/api/updates/check")
    assert resp.status_code == 202 and resp.get_json() == {"started": True}
    assert update_manager.snapshot()["mode"] == "checking"
    assert client.post("/api/updates/check").status_code == 409


def test_cross_site_post_still_403(client, update_manager):
    update_manager._state["mode"] = "updating"
    resp = client.post("/api/updates/apply", json={"tools": "all"}, headers={"Origin": "http://evil.example"})
    assert resp.status_code == 403
    resp = client.post("/api/submit", headers={"Origin": "http://evil.example"})
    assert resp.status_code == 403  # the cross-site check runs before the gate


def test_manager_is_created_lazily_from_the_environment(tdc, monkeypatch, tmp_path):
    monkeypatch.setattr(tdc, "_update_manager", None)
    monkeypatch.setenv("TDC_UPDATE_LOG", str(tmp_path / "u.log"))
    monkeypatch.setenv("TDC_SCRIPTS_DIR", str(tmp_path / "scripts"))
    manager = tdc._get_update_manager()
    assert manager is tdc._get_update_manager()
    assert manager.log_path == str(tmp_path / "u.log")
    assert manager.scripts_dir == str(tmp_path / "scripts")
    assert manager.state_path == os.path.join(tdc.APP_DIR, "tool_updates_state.json")
    assert manager.preconditions == tdc._update_preconditions


def test_close_rizin_shuts_the_sessions_down(tdc, monkeypatch):
    class Sessions:
        closed = 0

        def shutdown(self):
            Sessions.closed += 1
    monkeypatch.setattr(tdc, "_rizin_manager", None)
    tdc._close_all_rizin()  # no manager yet: nothing to do
    monkeypatch.setattr(tdc, "_rizin_manager", Sessions())
    tdc._close_all_rizin()
    assert Sessions.closed == 1


def test_daily_check_waits_then_checks_only_when_idle(tdc, update_manager, monkeypatch):
    sleeps, starts = [], []
    monkeypatch.setattr(update_manager, "start_check", lambda: starts.append(1) or (202, {"started": True}))

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            update_manager._state["mode"] = "updating"  # busy during the second round
        if len(sleeps) == 3:
            update_manager._state["mode"] = "idle"
    tdc._update_check_loop(12, sleep=sleep, rounds=3)
    assert sleeps == [300, 12 * 3600, 12 * 3600, 12 * 3600]
    assert len(starts) == 2  # idle, busy, idle; the check in the busy round was skipped


def test_daily_check_thread_off_for_zero_hours(tdc, monkeypatch):
    monkeypatch.setenv("TDC_UPDATE_CHECK_HOURS", "0")
    assert tdc._start_update_check_thread() is None


def test_daily_check_default_is_24_hours(tdc, monkeypatch):
    monkeypatch.delenv("TDC_UPDATE_CHECK_HOURS", raising=False)
    assert tdc._update_check_hours() == 24
    monkeypatch.setenv("TDC_UPDATE_CHECK_HOURS", "junk")
    assert tdc._update_check_hours() == 24
    monkeypatch.setenv("TDC_UPDATE_CHECK_HOURS", "6")
    assert tdc._update_check_hours() == 6


# ---------------------------------------------------------------------------
# Final review fixes
# ---------------------------------------------------------------------------

def test_safe_kill_dirs_does_not_refuse_lookalikes():
    assert tu._safe_kill_dirs(["C:\\UsersTools", "C:\\ProgramDataX\\a"]) == ["C:\\UsersTools", "C:\\ProgramDataX\\a"]


def test_git_calls_are_hardened_for_system():
    path = "C:\\LitterBox"
    cmd = tu.git_command(path, "fetch", "--quiet")
    assert cmd == ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=NUL", "-c", "core.sshCommand=",
                   "-c", "credential.helper=", "-c", "safe.directory=C:/LitterBox", "-C", path, "fetch", "--quiet"]
    assert not any(a == "safe.directory=*" for a in cmd)


def test_the_update_pull_uses_the_hardened_git(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox", installed="abc1234", available="def5678")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1", effect=lambda a: w.installed_done.add("x"))
    m = w.build()
    m.start_apply(["litterbox"])
    pulls = w.env.commands_matching("pull")
    assert pulls == [git_base("C:\\LitterBox") + ["pull", "--ff-only", "--autostash"]]


# -- python312 is pinned by TDC; Chocolatey pins cannot be upgraded ----------

def python_world(tmp_path):
    w = World(tmp_path, [
        tool_entry("choco:python312", "pinned_update", installed="3.12.1", available="3.12.2", pinned="3.12.1"),
        tool_entry("choco:git", installed="2.40.0", available="2.41.0"),
    ])
    w.env.on(["choco", "upgrade"], ok())
    w.env.on(["choco", "outdated"], ok(""))
    return w


def test_apply_all_skips_python312(tmp_path):
    m = python_world(tmp_path).build()
    code, body = m.start_apply("all")
    assert (code, body["tools"]) == (202, ["choco:git"])
    assert snap_tool(m, "choco:python312")["status"] == "pinned_update"


def test_python312_needs_include_pinned_and_then_runs_last(tmp_path):
    w = python_world(tmp_path)
    m = w.build()
    code, body = m.start_apply(["choco:python312"])
    assert code == 409 and "include_pinned" in body["error"]
    assert not w.env.commands_matching("choco", "upgrade")
    code, body = m.start_apply("all", include_pinned=True)
    assert (code, body["tools"]) == (202, ["choco:git", "choco:python312"])
    assert snap_tool(m, "choco:python312")["status"] == "updated"


def choco_pinned_world(tmp_path, status="pinned_update"):
    entry = tool_entry("choco:php", status, installed="8.2.1", available="8.3.0", pinned="8.2.1", name="php")
    entry["choco_pinned"] = True
    w = World(tmp_path, [entry, tool_entry("choco:git", installed="2.40.0", available="2.41.0")])
    w.env.on(["choco", "upgrade"], ok())
    w.env.on(["choco", "outdated"], ok(""))
    return w


def test_choco_pinned_package_is_refused_even_with_include_pinned(tmp_path):
    w = choco_pinned_world(tmp_path)
    m = w.build()
    for include in (False, True):
        code, body = m.start_apply(["choco:php"], include_pinned=include)
        assert code == 409
        assert body == {"error": "php is pinned in Chocolatey. Unpin it with choco pin remove -n php first."}
    assert not w.env.commands_matching("choco", "upgrade")
    assert m.snapshot()["mode"] == "idle"


def test_all_with_include_pinned_leaves_choco_pinned_packages_out(tmp_path):
    w = choco_pinned_world(tmp_path)
    m = w.build()
    code, body = m.start_apply("all", include_pinned=True)
    assert (code, body["tools"]) == (202, ["choco:git"])


def test_all_with_a_choco_pinned_package_alone_has_nothing_to_install(tmp_path):
    w = World(tmp_path, [dict(tool_entry("choco:php", "pinned_update", pinned="8.2.1"), choco_pinned=True)])
    assert w.build().start_apply("all", include_pinned=True) == (409, {"error": "No updates to install."})


# -- "all" must stand alone ---------------------------------------------------

@pytest.mark.parametrize("tools", [["all", "capa"], ["capa", "all"], ["all"]])
def test_all_in_a_list_is_rejected(tmp_path, tools):
    w = World(tmp_path, [tool_entry("capa"), tool_entry("beaconeye")])
    w.script("install-capa.ps1")
    w.script("install-beaconeye.ps1")
    m = w.build()
    assert m.start_apply(tools) == (400, {"error": 'Use "all" alone or a list of tool ids'})
    assert m.snapshot()["mode"] == "idle"
    assert snap_tool(m, "capa")["status"] == "update_available"
    assert m.start_apply("all")[0] == 202


# -- interrupted run: what was stopped is started again -------------------------

def test_stopped_consumers_are_saved_before_they_are_stopped_and_cleared_after(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1", effect=lambda a: w.installed_done.add("x"))
    w.running.add("task:LitterBox")
    seen = []

    def saved():
        with open(w.state_path) as handle:
            return json.load(handle).get("stopped")
    base = w._powershell

    def spy(args):
        if "Stop-ScheduledTask" in args[-1]:
            seen.append(("stop", saved()))
        elif "Start-ScheduledTask" in args[-1]:
            seen.append(("start", saved()))
        return base(args)
    w.env.commands = [(k, v) for k, v in w.env.commands if k != tuple(PS)]
    w.env.on(PS, spy)
    m = w.build()
    m.start_apply(["litterbox"])
    wanted = {"tool": "litterbox", "consumers": ["task:LitterBox"]}
    assert seen == [("stop", wanted), ("start", wanted)]
    assert saved() is None
    assert m.snapshot()["mode"] == "idle"


def test_nothing_saved_when_no_consumer_runs(tmp_path):
    w = World(tmp_path, [tool_entry("litterbox")])
    w.git_tool("C:\\LitterBox")
    w.script("install-litterbox.ps1", effect=lambda a: w.installed_done.add("x"))
    m = w.build()
    m.start_apply(["litterbox"])
    with open(w.state_path) as handle:
        assert json.load(handle).get("stopped") is None


def interrupted_world(tmp_path, consumers, spawn=None):
    w = World(tmp_path, None)
    with open(w.state_path, "w") as handle:
        json.dump({"mode": "updating", "checked_at": "2026-01-01T00:00:00Z",
                   "stopped": {"tool": "litterbox", "consumers": consumers},
                   "tools": [tool_entry("litterbox", "updating")]}, handle)
    if spawn is not None:
        w.kwargs["spawn"] = spawn
    return w


def build_with(w):
    kwargs = dict(w.kwargs)
    return tu.UpdateManager(w.env, w.state_path, w.log_path, w.scripts, **kwargs)


def test_interrupted_run_restarts_what_it_had_stopped(tmp_path):
    jobs = []
    w = interrupted_world(tmp_path, ["task:LitterBox", "service:Rustinel"], spawn=jobs.append)
    m = build_with(w)
    # the load itself only marks the tool; the restart runs through spawn
    assert w.events == [] and len(jobs) == 1
    assert snap_tool(m, "litterbox")["detail"] == tu.INTERRUPTED_DETAIL
    jobs[0]()
    assert w.events == [("start", "LitterBox"), ("start", "Rustinel")]
    detail = snap_tool(m, "litterbox")["detail"]
    assert detail == "Interrupted: the web UI restarted during the update. Restarted: LitterBox, Rustinel."
    assert detail.startswith("Interrupted: the web UI restarted during the update.")
    assert snap_tool(m, "litterbox")["status"] == "failed"
    with open(w.state_path) as handle:
        assert json.load(handle).get("stopped") is None
    # a second start has nothing left to restart
    again = []
    tu.UpdateManager(w.env, w.state_path, w.log_path, w.scripts, spawn=again.append)
    assert again == []


def test_interrupted_restart_failure_is_logged_not_fatal(tmp_path):
    w = interrupted_world(tmp_path, ["task:Gone", "task:LitterBox"], spawn=lambda f: f())
    base = w._powershell
    w.env.commands = [(k, v) for k, v in w.env.commands if k != tuple(PS)]
    w.env.on(PS, lambda a: fail("no such task") if "'Gone'" in a[-1] else base(a))
    m = build_with(w)
    assert ("start", "LitterBox") in w.events
    assert snap_tool(m, "litterbox")["detail"] == tu.INTERRUPTED_DETAIL + " Restarted: LitterBox."
    assert m.snapshot()["mode"] == "idle"


def test_interrupted_restart_nothing_restarted_keeps_the_plain_sentence(tmp_path):
    w = interrupted_world(tmp_path, ["task:Gone"], spawn=lambda f: f())
    w.env.commands = [(k, v) for k, v in w.env.commands if k != tuple(PS)]
    w.env.on(PS, fail("no such task"))
    m = build_with(w)
    assert snap_tool(m, "litterbox")["detail"] == tu.INTERRUPTED_DETAIL


def test_interrupted_state_without_saved_consumers_starts_nothing(tmp_path):
    jobs = []
    w = World(tmp_path, None)
    with open(w.state_path, "w") as handle:
        json.dump({"mode": "updating", "tools": [tool_entry("capa", "updating")]}, handle)
    tu.UpdateManager(w.env, w.state_path, w.log_path, w.scripts, spawn=jobs.append)
    assert jobs == []


# -- scans in flight (webui/app.py) ----------------------------------------------

def test_a_running_scan_blocks_updates(tdc, update_manager):
    assert tdc._update_preconditions() is None
    tdc._scan_started()
    try:
        assert tdc._update_preconditions() == "A scan is running. Wait until it finishes."
        tdc._scan_started()
        tdc._scan_finished()
        assert tdc._update_preconditions() == "A scan is running. Wait until it finishes."
    finally:
        tdc._scan_finished()
    assert tdc._update_preconditions() is None


def test_scan_reason_comes_after_the_other_reasons(tdc, update_manager, monkeypatch):
    tdc._scan_started()
    try:
        monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: _Reply({"in_use": True}))
        assert tdc._update_preconditions() == DETONATION_TEXT
        monkeypatch.setattr(tdc, "_probe_http", lambda url, timeout=2: None)
        monkeypatch.setattr(tdc, "_sweep_state", {"running": True})
        assert tdc._update_preconditions() == "A memory sweep is running."
        monkeypatch.setattr(tdc, "_sweep_state", {"running": False})
        monkeypatch.setattr(tdc, "_pd_db_state", {"running": True})
        assert tdc._update_preconditions() == "A process dump is running."
    finally:
        tdc._scan_finished()


def test_apply_refused_while_a_scan_runs(client, tdc, update_manager):
    tdc._scan_started()
    try:
        resp = client.post("/api/updates/apply", json={"tools": "all"})
    finally:
        tdc._scan_finished()
    assert resp.status_code == 409
    assert resp.get_json() == {"error": "A scan is running. Wait until it finishes."}


def test_the_scan_counter_never_goes_below_zero(tdc):
    tdc._scan_finished()
    assert tdc._scans_running() == 0


def test_sync_scan_endpoint_counts_while_it_runs(client, tdc, update_manager, monkeypatch):
    seen = []
    monkeypatch.setattr(tdc, "PROCESSDUMP_EXE", __file__)  # any existing file
    monkeypatch.setattr(tdc, "_image_name_for_pid", lambda pid: "x.exe")

    def run(**kwargs):
        seen.append(tdc._update_preconditions())
        return {"tool": "Process Dump"}, None
    monkeypatch.setattr(tdc, "_run_process_dump", run)
    resp = client.post("/api/scan/processdump", json={"pid": 4})
    assert resp.status_code == 200
    assert seen == ["A scan is running. Wait until it finishes."]
    assert tdc._scans_running() == 0 and tdc._update_preconditions() is None


def test_sync_scan_endpoint_uncounts_after_an_error(client, tdc, update_manager, monkeypatch):
    monkeypatch.setattr(tdc, "THREATCHECK_EXE", __file__)

    def boom(*a, **k):
        raise RuntimeError("tool crashed")
    monkeypatch.setattr(tdc, "_run_cmd", boom)
    resp = client.post("/api/scan/threatcheck", data={"path": __file__})
    assert resp.status_code == 500
    assert tdc._scans_running() == 0


def test_a_scan_rejected_by_the_maintenance_gate_is_not_counted(client, tdc, update_manager):
    update_manager._state["mode"] = "updating"
    assert client.post("/api/scan/processdump", json={"pid": 4}).status_code == 503
    assert client.post("/api/scan/processdump", json={"pid": 4}, headers={"Origin": "http://evil.example"}
                       ).status_code == 403
    assert tdc._scans_running() == 0


def test_reading_scan_endpoints_is_not_counted(client, tdc, update_manager):
    client.get("/api/scan/status")
    client.get("/api/scan/history")
    assert tdc._scans_running() == 0


def test_memory_scans_after_a_detonation_count_until_they_end(tdc, update_manager, monkeypatch):
    import threading as th
    release, entered, seen = th.Event(), th.Event(), []
    monkeypatch.setattr(tdc.time, "sleep", lambda s: None)

    def hsb(pid):
        seen.append(tdc._update_preconditions())
        entered.set()
        release.wait(5)
        return {"tool": "hsb"}, None
    monkeypatch.setattr(tdc, "_run_hsb", hsb)
    monkeypatch.setattr(tdc, "_run_beaconeye", lambda pid: (None, "not installed"))
    monkeypatch.setattr(tdc, "AETHER_EXE", "/nonexistent/aether")
    monkeypatch.setattr(tdc, "PROCESSDUMP_EXE", "/nonexistent/pd")
    monkeypatch.setattr(tdc, "_image_name_for_pid", lambda pid: "x.exe")
    tdc._run_memory_scans_async(4, "abc")
    # counted from the call on, before the worker thread has even started
    assert tdc._update_preconditions() == "A scan is running. Wait until it finishes."
    assert entered.wait(5)
    release.set()
    for _ in range(100):
        if tdc._scans_running() == 0:
            break
        th.Event().wait(0.05)
    assert tdc._scans_running() == 0
    assert seen == ["A scan is running. Wait until it finishes."]


def test_memory_scan_counter_ends_when_a_tool_raises(tdc, update_manager, monkeypatch):
    import threading as th
    monkeypatch.setattr(tdc.time, "sleep", lambda s: None)
    crashes = []
    monkeypatch.setattr(th, "excepthook", lambda args: crashes.append(args.exc_type))

    def hsb(pid):
        raise RuntimeError("scanner crashed")
    monkeypatch.setattr(tdc, "_run_hsb", hsb)
    tdc._run_memory_scans_async(4, "abc")
    for _ in range(100):
        if tdc._scans_running() == 0:
            break
        th.Event().wait(0.05)
    assert tdc._scans_running() == 0
    th.Event().wait(0.1)
    assert crashes == [RuntimeError]


# -- TDC_UPDATE_CHECK_HOURS ---------------------------------------------------------

@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "-inf", "Infinity", "junk", ""])
def test_check_hours_not_finite_falls_back_to_24(tdc, monkeypatch, value):
    monkeypatch.setenv("TDC_UPDATE_CHECK_HOURS", value)
    assert tdc._update_check_hours() == 24


def test_check_loop_survives_a_sleep_that_raises(tdc, update_manager, monkeypatch):
    monkeypatch.setattr(update_manager, "start_check", lambda: (202, {"started": True}))
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if seconds != 24 * 3600 and seconds != 300:
            raise OverflowError("timestamp too large")
    tdc._update_check_loop(1e300, sleep=sleep, rounds=2)
    assert sleeps.count(24 * 3600) >= 2  # the loop kept going on the default

    sleeps.clear()
    tdc._update_check_loop(float("nan"), sleep=sleep, rounds=1)
    assert sleeps == [300, 24 * 3600]
