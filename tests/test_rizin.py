"""Rizin for the RIZIN tab."""

import base64
import collections
import functools
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_RIZIN = os.path.join(ROOT, "scripts", "install-rizin.ps1")
PACKAGE = "Cutter-v2.5.0-Windows-x86_64.zip"
# The "digest" GitHub publishes for the release asset
# (https://api.github.com/repos/rizinorg/cutter/releases/tags/v2.5.0).
PACKAGE_SHA256 = "a04154a03a392dbf5886a629938582f7d23a93636fa0611c3e1c34905b197e69"


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _assigned_var(script, value_pattern):
    m = re.search(r'^\s*(?:\[\w+\])?\$(\w+)\s*=\s*"' + value_pattern + '"', script, re.M)
    assert m, value_pattern
    return m.group(1)


def test_install_rizin_is_pinned_and_wired():
    script = _read("scripts", "install-rizin.ps1")

    assert PACKAGE in script
    assert re.findall(r"\b[0-9a-fA-F]{64}\b", script) == [PACKAGE_SHA256]
    pin = _assigned_var(script, PACKAGE_SHA256)
    hashed = re.search(r"\$(\w+)\s*=\s*\(Get-FileHash\b[^\n]*-Algorithm SHA256[^\n]*\)\.Hash", script)
    assert hashed
    # -ne, not -cne: Get-FileHash answers in upper case, the pin is lower case.
    assert re.search(rf"if\s*\(\s*\${hashed.group(1)}\s+-ne\s+\${pin}\s*\)", script)
    assert not re.search(r"-c(?:eq|ne)\b", script)

    redist = _assigned_var(script, r"[^\"]*\\vc_redist\.x64\.exe")
    assert re.search(rf"\${redist}\b[^\n]*/install /quiet /norestart", script)
    assert "C:\\tools\\cutter" in script

    # Self-test: the version, then the ghidra core plugin in the Lc listing.
    rizin = _assigned_var(script, r"[^\"]*\\rizin\.exe")
    assert re.search(rf"&\s*\${rizin}\s+-v\b", script)
    assert re.search(rf'&\s*\${rizin}\b[^\n]*"Lc"', script)
    assert re.search(r"-match\s+\"[^\"]*ghidra", script)
    # rz-ghidra only finds its sleigh specs through SLEIGHHOME: the path compiled into
    # core_ghidra.dll is the package's build folder on Cutter's CI machine.
    sleigh = _assigned_var(script, r"\$\w+\\lib\\rizin\\plugins\\rz_ghidra_sleigh")
    assert re.search(rf'\[Environment\]::SetEnvironmentVariable\("SLEIGHHOME", \${sleigh}, "Machine"\)', script)
    assert re.search(rf"\$env:SLEIGHHOME = \${sleigh}\b", script)
    assert re.search(rf'&\s*\${rizin}\b[^\n]*"af; pdg"', script)

    # A failed install never stops provisioning: every exit is "exit 0" on a line of its own.
    assert re.findall(r"(?m)^\s*exit\b(.*)$", script) and \
        set(re.findall(r"(?m)^\s*exit\b(.*)$", script)) == {" 0"}
    assert not re.search(r"[{;]\s*exit\b", script)
    # Unpacked without Expand-Archive, whose progress bar crawls on PowerShell 5.1.
    assert "[System.IO.Compression.ZipFile]::ExtractToDirectory(" in script
    assert "Expand-Archive" not in script
    # The web UI (SYSTEM) keeps uploads in C:\Windows\Temp\rizin_uploads; Defender must leave them.
    uploads = _assigned_var(script, re.escape("C:\\Windows\\Temp\\rizin_uploads"))
    assert re.search(rf"New-Item -ItemType Directory -Path \${uploads}\b", script)
    assert re.search(rf"Add-MpPreference -ExclusionPath \${uploads}\b", script)

    for name in ("Vagrantfile", "Vagrantfile.utm"):
        order = re.findall(r'path:\s*"scripts/([\w.-]+\.ps1)"', _read(name))
        assert order.count("install-rizin.ps1") == 1, name
        assert order[order.index("install-re-tools.ps1") + 1] == "install-rizin.ps1", name
    setup = _read("scripts", "setup-macos-utm.sh")
    block = re.search(r"^SCRIPTS=\((.*?)^\)", setup, re.S | re.M).group(1)
    order = re.findall(r'"([\w.-]+\.ps1)"', block)
    assert order.count("install-rizin.ps1") == 1
    assert order[order.index("install-re-tools.ps1") + 1] == "install-rizin.ps1"


class _PackageServer:
    """Serves a folder on 127.0.0.1 and records the paths asked for."""

    def __init__(self, root):
        self.root = root
        self.requests = []
        server = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args, **kwargs):
                pass

            def do_GET(self):
                server.requests.append(self.path)
                super().do_GET()

        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(Handler, directory=str(root)))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, name):
        return f"http://127.0.0.1:{self.httpd.server_port}/{name}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


needs_pwsh = pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell (pwsh) not installed")

FAKE_RIZIN_EXE = """#!/bin/sh
case "$*" in
  -v) echo "rizin {version} @ windows-x86-64" ;;
  *pdg*) case "$SLEIGHHOME" in
           *rz_ghidra_sleigh) printf 'uint64_t entry0(void)\\n{{\\n    return 0;\\n}}\\n' ;;
           *) echo "Ghidra Decompiler Error: No sleigh specification for x86:LE:64:default" >&2 ;;
         esac ;;
  *) echo "{plugins}" ;;
esac
"""
GHIDRA_LC = "ghidra: Ghidra integration (Made by thestr4ng3r, v0.9.1, LGPL3)"


@pytest.fixture
def package_server(tmp_path):
    root = tmp_path / "served"
    root.mkdir()
    server = _PackageServer(root)
    yield server
    server.close()


def _fake_package(path, version="0.9.1", plugins=GHIDRA_LC):
    """A tiny stand-in for the Cutter zip (shell scripts as .exe); returns its SHA-256."""
    import zipfile

    def add(z, name, data, mode):
        info = zipfile.ZipInfo(f"Cutter-v2.5.0-Windows-x86_64/{name}")
        info.create_system = 3
        info.external_attr = (0o100000 | mode) << 16
        z.writestr(info, data)

    with zipfile.ZipFile(path, "w") as z:
        add(z, "rizin.exe", FAKE_RIZIN_EXE.format(version=version, plugins=plugins), 0o755)
        add(z, "lib/rizin/plugins/core_ghidra.dll", "not a dll", 0o644)
        add(z, "share/flag/tags.rz", "", 0o644)
        add(z, "vc_redist.x64.exe", '#!/bin/sh\necho "$@" >> "$FAKE_REDIST_LOG"\n', 0o755)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _patched_install_script(tmp_path, sha256):
    """install-rizin.ps1 pinned to a fake package, installing below tmp_path."""
    script = _read("scripts", "install-rizin.ps1")
    for old, new in ((PACKAGE_SHA256, sha256),
                     ('"C:\\tools\\cutter"', f'"{tmp_path / "tools" / "cutter"}"'),
                     ('"C:\\Windows\\Temp\\rizin_uploads"', f'"{tmp_path / "rizin_uploads"}"')):
        assert script.count(old) == 1, old
        script = script.replace(old, new)
    path = tmp_path / "install-rizin-test.ps1"
    path.write_text(script, encoding="utf-8")
    return path


def _run_install(script, url, tmp_path):
    temp = tmp_path / "temp"
    work = tmp_path / "work"
    temp.mkdir(exist_ok=True)
    work.mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(temp), TEMP=str(temp), TMP=str(temp),
               FAKE_REDIST_LOG=str(tmp_path / "redist.log"))
    run = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), "-PackageUrl", url],
        capture_output=True, text=True, timeout=120, env=env, cwd=str(work))
    return run.returncode, run.stdout + run.stderr


@needs_pwsh
def test_install_rizin_deletes_a_package_that_fails_the_pin(tmp_path, package_server):
    (package_server.root / PACKAGE).write_bytes(b"PK\x03\x04 not the release")

    code, out = _run_install(INSTALL_RIZIN, package_server.url(PACKAGE), tmp_path)

    # Warns and goes on: provisioning of the web UI must not stop here.
    assert code == 0, out
    assert "SHA-256 mismatch" in out and "Rizin is not installed" in out
    assert package_server.requests == [f"/{PACKAGE}"]
    assert not (tmp_path / "temp" / PACKAGE).exists(), "the download was not deleted"
    assert list((tmp_path / "work").iterdir()) == [], "something was unpacked"


@needs_pwsh
def test_install_rizin_survives_a_failed_download(tmp_path, package_server):
    code, out = _run_install(INSTALL_RIZIN, package_server.url("missing.zip"), tmp_path)

    assert code == 0, out
    assert "Download failed" in out and "Rizin is not installed" in out
    assert not (tmp_path / "temp" / PACKAGE).exists()
    assert list((tmp_path / "work").iterdir()) == []


@needs_pwsh
def test_install_rizin_installs_once_and_replaces_a_mismatch(tmp_path, package_server):
    sha256 = _fake_package(package_server.root / PACKAGE)
    script = _patched_install_script(tmp_path, sha256)
    url = package_server.url(PACKAGE)
    cutter = tmp_path / "tools" / "cutter"

    code, out = _run_install(script, url, tmp_path)
    assert code == 0, out
    assert "SHA-256 verified" in out and "Rizin installation complete" in out, out
    assert "pdg decompiles" in out, out
    assert (cutter / "rizin.exe").is_file()
    assert (cutter / "lib" / "rizin" / "plugins" / "core_ghidra.dll").is_file()
    assert (cutter / "share" / "flag" / "tags.rz").is_file()
    assert sorted(p.name for p in (tmp_path / "tools").iterdir()) == ["cutter"]
    assert not (tmp_path / "temp" / PACKAGE).exists()
    assert (tmp_path / "redist.log").read_text().split() == ["/install", "/quiet", "/norestart"]
    assert (tmp_path / "rizin_uploads").is_dir()
    assert len(package_server.requests) == 1

    # Again: nothing to do.
    code, out = _run_install(script, url, tmp_path)
    assert code == 0 and "already installed" in out, out
    assert "Rizin installation complete" in out
    assert len(package_server.requests) == 1

    # Another rizin in the folder (a version bump of the pin): replaced.
    (cutter / "rizin.exe").write_text(FAKE_RIZIN_EXE.format(version="0.9.0", plugins=GHIDRA_LC))
    code, out = _run_install(script, url, tmp_path)
    assert code == 0 and "Rizin installation complete" in out, out
    assert len(package_server.requests) == 2
    assert "rizin 0.9.1" in (cutter / "rizin.exe").read_text()
    assert sorted(p.name for p in (tmp_path / "tools").iterdir()) == ["cutter"]

    # An install from another package (here: no package marker at all): replaced as well.
    markers = list(cutter.glob("tdc-package*"))
    assert markers, "no package marker"
    for marker in markers:
        marker.unlink()
    code, out = _run_install(script, url, tmp_path)
    assert code == 0 and "Rizin installation complete" in out, out
    assert len(package_server.requests) == 3
    assert list(cutter.glob("tdc-package*"))


@needs_pwsh
def test_install_rizin_warns_when_the_self_test_fails(tmp_path, package_server):
    sha256 = _fake_package(package_server.root / PACKAGE,
                           plugins="dex: Suite of dex commands (Made by deroad, v1.0, LGPL-3.0-only)")
    script = _patched_install_script(tmp_path, sha256)

    code, out = _run_install(script, package_server.url(PACKAGE), tmp_path)

    assert code == 0, out
    assert "rz-ghidra missing" in out and "self-test failed" in out, out
    assert "Rizin installation complete" not in out


# --- Sessions, pipe and console filter (webui/rizin_sessions.py) -------------

FAKE_RIZIN = os.path.join(ROOT, "tests", "fake_rizin.py")
REAL_RIZIN = shutil.which("rizin") or ("/opt/homebrew/bin/rizin" if os.path.exists("/opt/homebrew/bin/rizin") else None)
MINGW = shutil.which("x86_64-w64-mingw32-gcc")


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def wait_for(cond, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _log(path):
    """The fake's command log as [(pid, command)]."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [tuple(line.rstrip("\n").split("\t", 1)) for line in fh]


@pytest.fixture
def fake(tmp_path, monkeypatch):
    """An executable that runs tests/fake_rizin.py, and its command log."""
    exe = tmp_path / "rizin"
    exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_RIZIN}" "$@"\n')
    exe.chmod(0o755)
    log = tmp_path / "fake.log"
    monkeypatch.setenv("FAKE_RIZIN_LOG", str(log))
    monkeypatch.delenv("FAKE_RIZIN_SLOW", raising=False)

    class Fake:
        path = str(exe)
        log_path = str(log)

        @staticmethod
        def commands():
            return [cmd for _, cmd in _log(str(log))]

        @staticmethod
        def by_process():
            runs = collections.OrderedDict()
            for pid, cmd in _log(str(log)):
                runs.setdefault(pid, []).append(cmd)
            return list(runs.values())

    return Fake


@pytest.fixture
def sample(tmp_path):
    def make(name="sample.exe", content=b"MZ\x90\x00 fake sample", size=None):
        path = tmp_path / "files" / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
        if size:
            with open(path, "r+b") as fh:
                fh.truncate(size)
        return str(path)
    return make


@pytest.fixture
def sessions(fake, tmp_path):
    import rizin_sessions
    made = []

    def make(**kw):
        kw.setdefault("exe", fake.path)
        kw.setdefault("projects_dir", str(tmp_path / "projects"))
        # Full analysis holds off STEP_GAP (2 s) between two steps; short here, so the tests that run it
        # stay fast (test_full_analysis_serves_requests_between_steps sets its own)
        kw.setdefault("step_gap", 0.05)
        kw.setdefault("step_gap_limit", 0.5)
        s = rizin_sessions.RizinSessions(**kw)
        made.append(s)
        return s

    yield make
    for s in made:
        s.shutdown()


ATTACKS = [
    # From the brief.
    "!calc", "pd 1;!calc", "pd 1 | findstr x", "pd 1 > C:\\x", "pd 1 >> x",
    "?e `!calc`", "?e $(id)", ".!calc", "#!python", "(m;!calc)", ".(m)",
    "o C:\\Windows\\win.ini", "wtf C:\\x 10", "dc", "doo", "L", "Ps C:\\x",
    "e scr.pager=cmd.exe", "e cfg.editor=x", "to C:\\x.h", "agw dot x", '"!calc"',
    "pd 1\n!calc", "x" * 2001,
    # Refused families (rizin 0.9.1 `?`).
    "oo+", "R x", "T", "H", "yy", "k foo=bar", "q", ". script", "(m) foo", "=!", "# x", "& aaa", "% 1+1",
    "V", "v", "g", "r 0", "m", "c 90", "B", "F", "Fa", "_", ":", "*0x1000=0x90", "$a=o x", "$a",
    "10pd 1", "'o' x", '"o" x', "O x", "E asm.bytes",
    "\u3000o x", "\to x", "pd 1\x1b", "pd 1\0",
    # Inside the allowed families: from `?*` and the help of each family.
    "agf interactive", "agf v", "agc interactive @ sym.main", "agf inter'active'",
    "aep", "aepcj", "aepc.", "aeli C:\\x.dll", "aeli lib.dll", "aelir 3", "aek foo=bar", "aek-", "afco C:\\x.sdb",
    "afco x.sdb",
    # R74: the three ESIL run commands that ignore esil.timeout (measured: all three past 15 s on a `jmp $`
    # with esil.timeout=2, while aesu, aecu, aecue, aesue, aess, aeso, aesou and aecb all stop at it). In the
    # console the limit is CONSOLE_TIMEOUT, after which the pipe kills rizin and the session goes with it.
    "aecc", "aecs", "aesuo", "aesuo call", "aesuo call jmp", "aecc @ 0x140001440", "aec;aecc", "aecc~?",
    'a"ec"c', "ae'cc'", "aes;aesuo call", 'Cf 4 "x;aecc" @ 0x140005000',
    "arpo profile.txt", "arpg gdb.txt", "afs!", "ascii",
    "pfo C:\\x.fdf", "pfo x", "pfw x 41", "pm C:\\x", "pm", "pmj x", "pkill rizin", "pwd", "p==v", "p==ev",
    "idp C:\\x.pdb", "idpi x.pdb", "idpd", "idpx x.pdb out", "ik foo=bar", "iO d/s 10", "inittime",
    "flush", "fortune", "CCe", "Cve var", "sleep 100", "sort C:\\x", "sort x", "shell", "shell cat x",
    "/F C:\\x", "/Fj x", "/m C:\\magic", "/mj x", "?**", "?**e", "?***", "?i", "?ie name",
    "toe int", "tos x.sdb", "time o x", "time pd 1",
    "bm 0x7fffffff",
    "e-", "ee asm.bytes", "er asm.bytes", "eco theme", "eco.", "ecn", "ecp", "ecoo", "ec", "ecr", "ecs", "ecd",
    "ecH- ", "e! asm.bytes",
    "env PATH=x", "env", "exit", "echo hi",
    "e asm.bytes=true scr.pager=x", "e cmd.hit=x", "e cmd.fcnrename=x", "e io.cache.auto=true", "e io.pcache=true",
    "e asm.cpu=../../x", "e asm.cpu=a/b", "e asm.cpu=C:x", "e \"scr.pager=x\"", "e 'scr.pager'=x", "e scr\\.pager=x",
    "e bin.demangle.libs=true", "e scr.color=3", "e log.file=x", "e http.root=x",
    # The write and debug families are open for the cache and the breakpoint list only: the rest is refused.
    "wv 1", "wb 90", "wm ff", "wxf x", "wff x", "wf 0x10 4", "wfx 0x10 4", "wcp", "wcpi", "wci", "wao nop",
    "waf x", "wA nop", "wD 8", "w6d aGk=", "wen 4", "wr 4", "ww hi", "ws hi", "w0 4", "wB 1",
    "dbic 0 pdf", "dbix 0 rax", "dbH", "dbm lib 0x10", "dbf", "dbtd", "dbW x", "dbw r 4", "dr", "dx 90",
    "dcu 0x10", "dsu 0x10", "de r reg rip", "dt", "di", "dl 1", "dg x", "do", "dw", "dkl", "ddl",
    # Quoted pieces that rizin joins into a refused name (wci, wff, dc).
    'w"c"i', "w'f'f x", 'd"c"',
    # Reads the source files that the sample's DWARF names.
    "agl", "agl json", "e asm.debuginfo.file=true",
    # Modifiers (`@?`, `@@?`).
    "pd 1 @e:scr.pager=x", "pd 1 @f:C:\\x", "pd 1 @f:x", "pd 1 @k:foo", "pd 1 @o:3",
    "pd 1 @@c:o x", "pd 1 @@@c:afl", "pd 1 @@. x", "pd 1 @@/x 90", "pd 1 @@/F x", "pd 1 @@dbt", "pd 1 @@dbta",
    "pd 1 @@dbtb", "pd 1 @@dbts", "pd 1 @@t", "pd 1 @@r", "pd 1 @@om", "pd 1 @@dm", "pd 1 @x", "pd 1 @0x10",
    "pd 1 @", "afn a@@c:ood",
    # Grep (`~?`): less and hud.
    "afl~..", "afl~...", "ij~{:..", "ij~{:...", "ij~{}..", "ij~{}...", "afl~&..", "afl~mov~..",
    # Escapes and SDB queries.
    "a\\gw dot x", "p\\fo x", "s $k{foo=bar}", "?v $k{x}", "pd 1;o x", "pd 1 ; o x", "afl;;o x",
    # External assemblers (x86.nasm runs nasm, x86.as/arm.as/ppc.as run as) and what selects them.
    "pa nop @a:x86.nasm:64", "e asm.arch=x86.nasm", "e asm.arch=x86 asm.bits=64 asm.assembler=x86.nasm;pa nop",
    "/a nop @a:x86.nasm:64", "pa nop @a:ppc.as:32", "pa nop", "pae nop", "/a nop", "/aj nop", "/aq nop",
    "e asm.assembler=x86.nz", "e asm.assembler=", "e asm.arch=x86.as", "e asm.arch=arm.as", "e asm.arch=ppc.as",
    "e analysis.arch=x86.nasm", "e asm.arch=x86.nz", "e asm.arch=nope", "pd 1 @a:x86", "pd 1 @b:64",
    "aha x86.nasm", "aha ppc.as @ 0x1000",
    "pa", "paj nop", "pa\u3000nop", "/a* nop", "/ajq nop", "/a nop @ 0x1000", "e asm.syntax=att;pa nop",
    "e anal.arch=x86.nasm", "e analysis.arch=", "e asm.arch=x86.nasm;pd 1", "aha 'x86'", 'aha "x86.nasm"',
    "ahax x86.nasm", "e asm.arch=ppc.as asm.bits=32",
    # rz_silhouette (shipped with Cutter) talks to a server.
    "sil", "sil test", "sil share",
    # Commands that run a stored or typed format as a command line (pxa: the Cf formats; tpv/tpx: a type's
    # format, which can come from the sample's debug info), and quoted pieces that rizin joins into a
    # refused name inside such a format (Cf stores x;agw ..., pxa would run it).
    "pxa", "pxa 64 @ 0x140005000", "tpv foo 0x10", "tpx foo 4142",
    'Cf 4 "x;a"gw" dot g.png" @ 0x140005000', "Cf 4 'x;a'gw' dot g.png'", 'a"gw" dot x', "p'fo' x",
    'a"el"i lib.dll', 'i"dp"d', 'C"Ce"', 'e"c"o theme', "'a'a", 'a"a"a', 'Cf 4 "x;?e $"k"{x}"', 'Cf 4 "x;afl~".."',
]
# The bounded neighbours of R74's three: every one of these stops at esil.timeout (measured), so the refusal
# must not reach them. `aec` itself is what CONT sends and `aesu` what TO CALL is built from.
BOUNDED_EMULATION = [
    "aec", "aecb", "aecu 0x140001440", "aecue rax,0x999,==", "aes", "aes 4", "aesp 0 10", "aesb",
    "aess", "aessu", "aeso", "aesou 0x140001440", "aesu 0x140001440", "aesue rax,0x999,==", "aeip",
]
# Whole-program analysis (every aa... command) runs from the Full analysis button, not the console.
WHOLE_PROGRAM = [
    "aa", "aaa", "aaaa", "aac", "aaci", "aaC", "aad", "aae", "aae 64", "aaef", "aaf", "aafe", "aafr 64", "aaft",
    "aai", "aaij", "aaj", "aalg", "aalor", "aalos", "aan", "aanr", "aap", "aar", "aar 100", "aas", "aaS", "aat",
    "aaT", "aau", "aav", "afl;aaa", "pdf @ main;aac", "aaa @ sym.main", "aa~?",
]
ALLOWED = [
    # From the brief.
    "afl", "pdf @ sym.main", "pdg", "iz~pipe", "axt @ sym.imp.KERNEL32.dll_CreateNamedPipeA",
    "s 0x1400014b7", "?v $$+4", "/x 4d5a", "afn my_main", "e asm.bytes=true", "e asm.bytes",
    # More of what the console is for; per-function analysis stays.
    "af", "afr", "af @ 0x1400014b7", "afr @ sym.main", "aF", "afb", "afva", "afvl", "afvn x var_8h", "aa?",
    "afl~main", "pdf~:0..5", "pd 10 @ entry0", "pdfj @ sym.main~{ops}", "ij~{bin.arch}", "pd 1 @@F",
    "pd 1 @@i", "px 16 @x:4d5a", "pd 1 @@=0x10 0x20", "e asm.arch=arm", "e asm.arch=ghidra",
    "e analysis.arch=x86", "e asm.syntax=att", "e asm.assembler", "pad 90", "pade 90", "/at call", "/aa nop",
    "aha arm", "pa?",
    "/a?", "/ad mov", "/ai 0x10", "/am nop", "/a1 1", "/aI", "/ac nop", "/ao nop", "/af priv", "/as", "/atj call",
    "/al", "/ae rax", "aha 0", "aha x86 @ 0x1000", "aha-", "ahS att", "e asm.arch=ppc", "e asm.arch=riscv",
    "e asm.arch=??", "tp foo", "tp foo 0x1000", "pxA", 'CC "quoted text"', "/z 'two words'",
    'Cf 4 "x"', "aes", "aeip",
    "e asm.arch=x86", "e analysis.depth=64", "e bin.demangle=false", "e asm.arch=?", "el asm.", "e", "es",
    "?", "?*afl", "pd?", "e?", "agw?", "afvl", "CC hello", "CCu base64:aGk=", "agf", "agf json", "agf dot",
    "axt", "iz", "ii", "x 64", "b 256", "t", "tf", "s sym.main", "s++", "pdg @ sym.main", "pdgj", "afl;pdf",
    "iS;afl", "afi", "ax", "/z hello", "f my_flag @ 0x1000", "C", "Cd 4 @ 0x1000", "pxj 16",
    *BOUNDED_EMULATION,
]


def test_console_filter_refuses_shell_and_file_access():
    from rizin_sessions import check_console_command

    for text in ATTACKS:
        reason = check_console_command(text)
        assert isinstance(reason, str) and reason, f"not refused: {text!r}"
        assert "\n" not in reason and len(reason) < 120, (text, reason)
        assert re.fullmatch(r"[\x20-\x7e]+", reason), (text, reason)
    for text in WHOLE_PROGRAM:
        assert check_console_command(text) == "whole-program analysis runs from the Full analysis button", text
    for text in ALLOWED:
        assert check_console_command(text) is None, (text, check_console_command(text))


def test_console_allows_emulation_and_cache_writes():
    import rizin_sessions

    for cmd in ("wx 9090", "wx 90 @ 0x401000", "wo x 41", "wz hi", "w text", "wc", "wcj", "wc- 0x401000",
                "wc-*", "db", "db @ 0x401000", "db- @ 0x401000", "db-*", "dbl", "dblj", "dbd", "dbe",
                "dbs", "dbn name", "aepc 0x401000", "e esil.timeout=5", "e io.cache=true",
                "e esil.breakoninvalid=true"):
        assert rizin_sessions.check_console_command(cmd) is None, cmd


def test_console_still_refuses_what_writes_executes_or_hangs():
    import rizin_sessions

    cases = {
        "wci": "the file", "wc+ 0x0 0x10": "the file", "wa nop": "assembl",
        "wu /tmp/p": "file", "wff /tmp/x": "file", "wfs host 1": "file",
        "dbc pdf": "run", "dbC pdf": "run", "dbx rax": "run", "dbw w 1": "hang",
        "aep 0x10": "not allowed", "aepn": "not allowed",
        # R74: unbounded by esil.timeout, so the console's own 60 s would kill rizin and the session
        "aecc": "esil.timeout", "aecs": "esil.timeout", "aesuo call": "esil.timeout",
        "aesuo": "TO CALL does this",
        "ood": "not allowed", "dc": "not allowed", "ds": "not allowed", "dm": "not allowed",
        "dp": "not allowed", "dbt": "not allowed", "dk 9": "not allowed",
        "aa": "Full analysis", "aaa": "Full analysis", "aav": "Full analysis",
        "e esil.mdev.range=0x0": "cannot be set",
    }
    for cmd, fragment in cases.items():
        reason = rizin_sessions.check_console_command(cmd)
        assert reason and fragment in reason, (cmd, reason)


def test_pipe_answers_and_times_out(fake, sample, monkeypatch):
    from rizin_sessions import RizinPipe, RizinTimeout

    path = sample()
    pipe = RizinPipe(fake.path, path)
    try:
        assert json.loads(_log(fake.log_path)[0][1][len("START "):]) == [
            "-q0", "-N", "-e", "scr.interactive=false", "-e", "scr.pager=", "-e", "scr.color=0", path]
        assert pipe.cmd("echo hello") == "hello\n"
        info = pipe.cmdj("ij")
        assert info["core"]["format"] == "pe64" and info["bin"]["arch"] == "x86"
        assert [f["name"] for f in pipe.cmdj("aflj")] == ["entry0", "sym.watchdog", "sym.main"]
        assert pipe.cmdj("aa") is None
        assert pipe.alive
    finally:
        pipe.close()
    assert not pipe.alive

    monkeypatch.setenv("FAKE_RIZIN_SLOW", "pdfj:30")
    pipe = RizinPipe(fake.path, path)
    try:
        started = time.monotonic()
        with pytest.raises(RizinTimeout):
            pipe.cmdj("pdfj @ sym.main", timeout=1.0)
        # It waited for its limit, not for the answer (which takes 30 s); the upper bound is wide, so a
        # stall on a loaded runner does not fail it (follow-up finding 3)
        assert 1.0 <= time.monotonic() - started <= 10.0
        assert not pipe.alive
        assert pipe._proc.poll() is not None
    finally:
        pipe.close()


def test_rizin_gets_the_sleigh_folder_next_to_it(fake, sample, tdc, tmp_path, monkeypatch):
    """A session and the status probe hand rz-ghidra SLEIGHHOME: the one set, else <rizin's folder>/lib/..."""
    from rizin_sessions import RizinPipe

    env_log = tmp_path / "env.log"
    monkeypatch.setenv("FAKE_RIZIN_ENV_LOG", str(env_log))
    path = sample()
    sleigh = tmp_path / "lib" / "rizin" / "plugins" / "rz_ghidra_sleigh"  # the fake runs from tmp_path

    def seen():
        """SLEIGHHOME as a session, then rizin -v and rizin -qc Lc of the probe get it."""
        RizinPipe(fake.path, path).close()
        tdc._rizin_probe(fake.path)
        runs = [line.split("\t")[1:] for line in env_log.read_text(encoding="utf-8").splitlines()]
        env_log.unlink()
        return [(mode, json.loads(value)) for mode, value in runs]

    sleigh.mkdir(parents=True)
    monkeypatch.setenv("SLEIGHHOME", "/elsewhere/sleigh")
    assert seen() == [("START", "/elsewhere/sleigh"), ("VERSION", "/elsewhere/sleigh"), ("QC", "/elsewhere/sleigh")]

    monkeypatch.delenv("SLEIGHHOME")
    assert seen() == [("START", str(sleigh)), ("VERSION", str(sleigh)), ("QC", str(sleigh))]
    monkeypatch.setenv("SLEIGHHOME", "")  # empty: rz-ghidra ignores it, so it counts as none
    assert seen() == [("START", str(sleigh)), ("VERSION", str(sleigh)), ("QC", str(sleigh))]

    monkeypatch.delenv("SLEIGHHOME")
    sleigh.rmdir()
    assert seen() == [("START", None), ("VERSION", None), ("QC", None)]


def test_sessions_limit_idle_and_takeover(sessions, sample):
    from rizin_sessions import SessionEnded, SessionMoved

    clock = Clock()
    mgr = sessions(clock=clock)
    files = [sample(f"f{i}.exe", b"MZ file %d" % i) for i in range(5)]
    opened = []
    for i in range(3):
        opened.append(mgr.open(files[i], f"tab{i}"))
        clock.advance(10)
    assert {o["file"]["format"] for o in opened} == {"pe64"}
    assert opened[0]["file"]["sha256"] == hashlib.sha256(b"MZ file 0").hexdigest()
    assert opened[0]["file"]["size"] == len(b"MZ file 0")
    assert opened[0]["file"]["arch"] == "x86" and opened[0]["file"]["bits"] == 64
    assert opened[0]["analysis"]["level"] == "aaa"

    # tab0 was used last; tab1 is the longest unused one.
    mgr.get(opened[0]["session"])
    clock.advance(10)
    fourth = mgr.open(files[3], "tab3")
    with pytest.raises(SessionEnded):
        mgr.get(opened[1]["session"])
    for o in (opened[0], opened[2], fourth):
        assert mgr.get(o["session"]).id == o["session"]

    # The same file in another tab: the session moves, the old ID says so.
    moved = mgr.open(files[3], "tab9")
    assert moved["session"] != fourth["session"]
    with pytest.raises(SessionMoved):
        mgr.get(fourth["session"])
    session = mgr.get(moved["session"])
    assert session.tab == "tab9"
    mgr.close(fourth["session"])  # the old tab's close must not end the moved session
    assert mgr.get(moved["session"]) is session
    back = mgr.open(files[3], "tab3")
    with pytest.raises(SessionMoved):
        mgr.get(moved["session"])
    assert mgr.get(back["session"]) is session

    # A new file in the same tab closes the old session.
    replaced = mgr.open(files[4], "tab3")
    with pytest.raises(SessionEnded):
        mgr.get(back["session"])
    assert session.closed and not session._pipe.alive
    assert mgr.get(replaced["session"]).path == files[4]
    with pytest.raises(SessionEnded):
        mgr.get("no-such-session")

    # 1800 s without use ends a session.
    last = mgr.get(replaced["session"])
    clock.advance(1799)
    mgr.reap()
    assert not last.closed
    clock.advance(1)
    with pytest.raises(SessionEnded):
        mgr.get(replaced["session"])
    assert last.closed and not last._pipe.alive


def _wait_state(session, *states, timeout=20.0):
    assert wait_for(lambda: session.analysis["state"] in states, timeout), session.analysis
    return session.analysis


FULL = ["aa", "aac", "aar", "aaft", "Fa", "aanr", "aaC", "avrr"]
BIG = 20 * 1024 * 1024 + 1


class Timers:
    """Stands in for threading.Timer; fire() runs the timers that are due."""

    def __init__(self):
        self.made = []

    def __call__(self, delay, fn):
        timer = _Timer(delay, fn)
        self.made.append(timer)
        return timer

    @property
    def pending(self):
        return [t for t in self.made if t.started and not t.cancelled and not t.ran]

    def fire(self):
        for timer in self.pending:
            timer.ran = True
            timer.fn()


class _Timer:
    def __init__(self, delay, fn):
        self.delay, self.fn = delay, fn
        self.started = self.cancelled = self.ran = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


def _steps_in(commands):
    return [c for c in commands if c in FULL or c == "aaa"]


def test_analysis_runs_in_steps_and_stays_usable(sessions, sample, fake, monkeypatch):
    from rizin_sessions import RizinBusy

    # Up to 20 MB: aaa, as one step, so the result is exactly rizin's. The fake steps take seconds, so
    # that a stall on a loaded runner cannot end them while the test looks at them (follow-up finding 3).
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aaa:4")
    mgr = sessions()
    small = mgr.open(sample(), "tab1")
    assert small["analysis"]["level"] == "aaa"
    session = mgr.get(small["session"])
    assert wait_for(lambda: session.analysis["step"] == "aaa")
    started = time.monotonic()
    with pytest.raises(RizinBusy) as busy:
        session.json("aflj", wait=0.3)
    # It gave up during the step instead of waiting for it: it waited its turn (and not much longer: the
    # ceiling is wide for a stall, far below the step), and the step it named is the one still running.
    took = time.monotonic() - started
    assert busy.value.step == "aaa" and 0.3 <= took < 2.0, took
    assert session.analysis["step"] == "aaa" and session.analysis["state"] == "running"
    state = _wait_state(session, "done")
    assert state["done_steps"] == ["aaa"] and state["level"] == "aaa" and state["note"] is None
    assert state["elapsed"] >= 4.0
    assert _steps_in(fake.by_process()[0]) == ["aaa"]

    # Over 20 MB: aa.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aac:4")
    big = mgr.open(sample("big.bin", b"MZ", size=BIG), "tab2")
    assert big["analysis"]["level"] == "aa"
    session = mgr.get(big["session"])
    state = _wait_state(session, "done")
    assert state["done_steps"] == ["aa"] and state["note"] is None

    # Full analysis: aaa's steps one by one; busy within a step, a waiting request gets the pipe between two.
    session.analyze_full()
    assert session.analysis["level"] == "aaa" and "variables" in session.analysis["note"]
    assert wait_for(lambda: session.analysis["step"] == "aac")
    with pytest.raises(RizinBusy) as busy:
        session.json("aflj", wait=0.3)
    assert busy.value.step == "aac" and session.analysis["step"] == "aac"
    assert len(session.json("aflj", wait=10.0)) == 3
    state = _wait_state(session, "done")
    assert state["done_steps"] == FULL and state["level"] == "aaa"
    assert "variables are analysed less than with aaa" in state["note"]
    log = fake.by_process()[1]
    assert _steps_in(log) == FULL
    assert log.index("aac") < log.index("aflj") < log.index("aar")
    assert log[log.index("aac") - 1] == "e analysis.calls=true"
    assert session.analyze_full()["done_steps"] == FULL  # nothing left to run
    assert mgr.get(small["session"]).analyze_full()["done_steps"] == ["aaa"]  # aaa covers the steps


def test_full_analysis_serves_requests_between_steps(sessions, sample, fake, monkeypatch):
    """The controller's ruling: between two steps of Full analysis the session holds off for step_gap
    seconds, so a view asked for just after a step is answered before the next step starts (not busy),
    and the status shows no running step then. aaa and aa, one step each, have no gap.

    The gap is seconds long here, so that a stall between the step's end and the request does not use it
    up (follow-up finding 3); what is pinned is the state (no step runs) and the order in rizin's log."""
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aac:0.4,aar:0.4")
    mgr = sessions(big_file=1, step_gap=1.5, step_gap_limit=4.0)
    session = mgr.get(mgr.open(sample("gap.exe", b"MZ gap"), "tab")["session"])
    _wait_state(session, "done")
    session.analyze_full()
    assert wait_for(lambda: session.analysis["step"] == "aac")
    assert wait_for(lambda: "aac" in session.analysis["done_steps"])
    gap = session.analysis
    assert gap["state"] == "running" and gap["step"] is None, gap
    assert len(session.json("aflj", wait=0.1)) == 3          # at once: the next step waits
    state = _wait_state(session, "done")
    assert state["done_steps"] == FULL
    log = fake.by_process()[0]
    assert log.index("aac") < log.index("aflj") < log.index("aar")

    # One step: no gap before it or after it, whatever step_gap says
    mgr = sessions(step_gap=5.0, step_gap_limit=20.0)
    small = mgr.get(mgr.open(sample("one.exe", b"MZ one"), "tab")["session"])
    assert _wait_state(small, "done", timeout=2.0)["done_steps"] == ["aaa"]


def test_the_gap_between_steps_is_bounded_when_requests_keep_coming(sessions, sample, fake, monkeypatch):
    """Requests that use or wait for the pipe hold the next step off, step_gap_limit seconds after the
    step at most; then the step goes first, and the requests that wait come after it.

    That the step comes at all while requests keep coming is what this pins; the upper bound on when it
    comes is wide, so a stall on a loaded runner does not fail it (follow-up finding 3)."""
    from rizin_sessions import RizinBusy

    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aac:0.3,aflj:0.1")
    mgr = sessions(big_file=1, step_gap=0.3, step_gap_limit=1.2)
    session = mgr.get(mgr.open(sample("bound.exe", b"MZ bound"), "tab")["session"])
    _wait_state(session, "done")
    session.analyze_full()
    assert wait_for(lambda: session.analysis["step"] == "aac")
    stop, served = threading.Event(), []

    def keep_asking():
        while not stop.is_set():
            try:
                session.json("aflj", wait=5.0)
                served.append(time.monotonic())
            except RizinBusy:
                pass

    askers = [threading.Thread(target=keep_asking, daemon=True) for _ in range(3)]
    for asker in askers:
        asker.start()
    try:
        assert wait_for(lambda: "aac" in session.analysis["done_steps"], timeout=5.0)
        ended = time.monotonic()
        assert wait_for(lambda: session.analysis["step"] == "aar" or "aar" in session.analysis["done_steps"],
                        timeout=10.0), "the next step never started while requests kept coming"
        started = time.monotonic()
    finally:
        stop.set()
        for asker in askers:
            asker.join(timeout=10)
    # Bounded by step_gap_limit, with room for a stall but still near enough to pin the limit's value
    assert started - ended < 1.2 + 1.5, started - ended
    assert any(ended <= t <= started for t in served), "no request was served between the two steps"
    assert _wait_state(session, "done")["done_steps"] == FULL


def test_analysis_stops_at_the_limit_and_restarts_hanging_steps(sessions, sample, fake, monkeypatch):
    # Full analysis: at analysis_limit it stops at the end of the running step.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aac:1.5")
    mgr = sessions(analysis_limit=1, big_file=1)
    session = mgr.get(mgr.open(sample("limit.exe", b"MZ limit"), "tab")["session"])
    _wait_state(session, "done")
    session.analyze_full()
    state = _wait_state(session, "stopped")
    assert state["done_steps"] == ["aa", "aac"]
    assert "after 1 s" in state["note"] and "aar" in state["note"] and "variables" in state["note"]
    # The reason comes first: the toolbar shows the start of the note
    assert state["note"].startswith("The analysis stopped after 1 s"), state["note"]

    # aaa runs past analysis_limit + grace: rizin is killed and the session restarts with aa.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aaa:60")
    mgr.shutdown()
    open(fake.log_path, "w").close()
    mgr = sessions(analysis_limit=1.0, step_grace=0.5)
    session = mgr.get(mgr.open(sample("hang.exe", b"MZ hang"), "tab")["session"])
    state = _wait_state(session, "stopped")
    assert state["done_steps"] == ["aa"] and state["level"] == "aa"
    assert "aaa" in state["note"] and "1.5 s" in state["note"] and "restarted" in state["note"]
    first, second = fake.by_process()
    assert _steps_in(first) == ["aaa"]
    assert second[0].startswith("START ") and _steps_in(second) == ["aa"]
    assert session.json("aflj")  # the restarted session answers

    # A step of the full analysis that hangs: restart, then the finished steps are replayed.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr.shutdown()
    open(fake.log_path, "w").close()
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1)
    session = mgr.get(mgr.open(sample("hang2.exe", b"MZ hang 2"), "tab")["session"])
    _wait_state(session, "done")
    session.analyze_full()
    state = _wait_state(session, "stopped")
    assert state["done_steps"] == ["aa", "aac"]
    assert "aar" in state["note"] and "restarted" in state["note"] and "variables" in state["note"]
    assert state["note"].startswith("Step aar did not finish"), state["note"]
    first, second = fake.by_process()
    assert _steps_in(first) == ["aa", "aac", "aar"]
    assert _steps_in(second) == ["aa", "aac"]


def test_a_restarted_rizin_gets_the_patches_back_and_does_not_erase_them(sessions, sample, fake, tmp_path,
                                                                        monkeypatch):
    """A step that hangs restarts rizin, whose write cache starts empty. The patches have to go back in
    -- otherwise the mirror empties itself at the next read and the next save writes ``patches=`` over
    the ones the project holds, so a hung step would *erase* the analyst's patches."""
    import rizin_sessions

    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    path = sample("hang3.exe", b"MZ hang 3")
    opened = mgr.open(path, "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.patch(0x140001440, "9090")
    session.breakpoint_set(0x1400014B7)
    timers.fire()
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    assert "\npatches=140001440:9090\n" in project.read_text()

    session.analyze_full()  # its aar hangs, so rizin is killed and restarted
    _wait_state(session, "stopped")
    assert len(fake.by_process()) == 2
    # back in the restarted rizin: the list and the bytes
    assert [(r["addr"], r["after"], r["mine"]) for r in session.patches()["patches"]] == [(0x140001440, "9090", True)]
    assert session.json("pxj 2 @ 0x140001440") == [0x90, 0x90]
    assert any(c.startswith("wx 9090 @ 0x140001440") for c in fake.by_process()[1])
    # and the save that follows keeps them, instead of writing an empty line over them
    session.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert "\npatches=140001440:9090\n" in project.read_text()

    # one that cannot go back (it was made into memory only the emulation had mapped) stays in the
    # project all the same: a cache that died must not erase it
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr2 = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    second = mgr2.open(sample("hang4.exe", b"MZ hang 4"), "tab")
    stacked = mgr2.get(second["session"])
    _wait_state(stacked, "done")
    stacked.emulation_start(0x140001440)
    stacked.patch(rizin_sessions.ESIL_STACK_ADDR + 0x80, "41")
    timers.fire()
    saved = tmp_path / "projects" / (second["file"]["sha256"] + ".rzdb")
    assert "\npatches=100080:41\n" in saved.read_text()
    stacked.analyze_full()
    _wait_state(stacked, "stopped")
    answer = stacked.patches()  # the emulation's memory is gone with its rizin
    assert (answer["patches"], answer["waiting"]) == ([], [])
    assert answer["restore"]["actions"] == 0 and "restarted" in answer["restore"]["reason"]
    assert "could not be applied" in stacked.analysis["note"]
    stacked.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert "\npatches=100080:41\n" in saved.read_text(), "a lost cache must not erase the project"


def test_a_patch_made_while_a_step_runs_is_announced_and_then_saved(sessions, sample, fake, tmp_path,
                                                                   monkeypatch):
    """A patch is not refused while the analysis runs -- a step changes no bytes -- but its project
    cannot be written before the step lets go of rizin, and the project is the only place a patch
    outlives the session. The session says so for as long as that is true, and a close waits for the
    pipe, so the patch is written after all."""
    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aac:0.5,aaft:5")
    mgr = sessions(big_file=1, timer=timers)
    opened = mgr.open(sample("steps3.exe", b"MZ steps 3"), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")  # aa, because the file counts as big
    session.analyze_full()
    assert wait_for(lambda: session.analysis["step"] == "aac")
    session.patch(0x140001440, "90", wait=10.0)  # waits for the step; a rename would be refused
    assert wait_for(lambda: session.analysis["step"] == "aaft")
    note = session.analysis["note"]
    assert "waiting to be saved" in note, note
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    assert not project.exists(), "nothing could be written while the step holds rizin"

    # closing waits for the pipe, so the patch is still written; the note goes with the session
    mgr.close(opened["session"])
    assert session.wait_closed(30)
    assert "\npatches=140001440:90\n" in project.read_text()


def test_no_renames_or_comments_while_the_analysis_runs(sessions, sample, fake, monkeypatch):
    from rizin_sessions import RizinBusy

    # Steps of seconds: the refusals are measured against one wait for the pipe (2 s), not against a
    # step that may already be over (follow-up finding 3).
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aaa:4,aac:4")
    mgr = sessions()
    session = mgr.get(mgr.open(sample(), "tab")["session"])
    assert wait_for(lambda: session.analysis["step"] == "aaa")
    started = time.monotonic()
    for annotate in (lambda: session.rename(0x1400014B7, "early"), lambda: session.comment(0x1400014B7, "early"),
                     lambda: session.console("afn early @ 0x1400014b7"), lambda: session.console("CC early")):
        with pytest.raises(RizinBusy) as busy:
            annotate()
        assert busy.value.step == "aaa"
    # Refused at once: four of them took less than one wait for the pipe, and the step still runs
    assert time.monotonic() - started < 2.0
    assert session.analysis["step"] == "aaa"
    assert not [c for c in fake.commands() if "early" in c]
    _wait_state(session, "done")
    assert session.rename(0x1400014B7, "late")["name"] == "late"

    # Also during the full analysis, which leaves the pipe free between its steps: refused because it
    # runs, not because the pipe is held (wait=5 would let it wait for the pipe).
    mgr = sessions(big_file=1)
    session = mgr.get(mgr.open(sample("steps.exe", b"MZ steps"), "tab2")["session"])
    _wait_state(session, "done")
    session.analyze_full()
    assert wait_for(lambda: session.analysis["step"] == "aac")
    started = time.monotonic()
    with pytest.raises(RizinBusy) as busy:
        session.comment(0x1400014B7, "between", wait=5.0)
    assert busy.value.step == "aac" and time.monotonic() - started < 2.0
    assert session.analysis["step"] == "aac"
    _wait_state(session, "done")


def test_project_saves_are_debounced_and_flushed(sessions, sample, fake, tmp_path):
    clock = Clock()
    timers = Timers()
    mgr = sessions(clock=clock, timer=timers, max_sessions=2)

    def saves():
        return [c for c in fake.commands() if c.startswith("Ps ")]

    opened = mgr.open(sample(), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")

    # Two quick renames: one save, 3 s after the second.
    session.rename(0x1400014B7, "first")
    session.rename(0x1400014B7, "second")
    assert saves() == [] and not project.exists()  # rename returns without waiting for the save
    assert [t.delay for t in timers.made] == [3.0, 3.0]
    assert timers.made[0].cancelled and timers.pending == [timers.made[1]]
    timers.fire()
    assert len(saves()) == 1 and '"name":"second"' in project.read_text()
    assert timers.pending == []

    # close() writes a save that is still pending.
    session.comment(0x1400014B7, "pending at close")
    assert len(timers.pending) == 1
    mgr.close(opened["session"])
    assert len(saves()) == 2 and "pending at close" in project.read_text()
    assert timers.pending == []  # nothing left for the timer

    # Eviction and reaping write it too.
    first = mgr.open(sample("e1.exe", b"MZ e1"), "tab1")
    _wait_state(mgr.get(first["session"]), "done")
    mgr.get(first["session"]).comment(0x1400014B7, "pending at eviction")
    clock.advance(10)
    second = mgr.open(sample("e2.exe", b"MZ e2"), "tab2")
    clock.advance(10)
    mgr.open(sample("e3.exe", b"MZ e3"), "tab3")  # evicts first
    evicted = tmp_path / "projects" / (first["file"]["sha256"] + ".rzdb")
    assert len(saves()) == 3 and "pending at eviction" in evicted.read_text()
    reaped = mgr.get(second["session"])
    _wait_state(reaped, "done")
    reaped.comment(0x1400014B7, "pending at reap")
    clock.advance(1800)
    mgr.reap()
    assert reaped.closed and len(saves()) == 4
    assert "pending at reap" in (tmp_path / "projects" / (second["file"]["sha256"] + ".rzdb")).read_text()


def test_rename_and_comment_cannot_form_commands(sessions, sample, fake, tmp_path):
    from rizin_sessions import RizinRefused

    timers = Timers()
    mgr = sessions(timer=timers)
    opened = mgr.open(sample(), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    assert "asm.debuginfo.file=false" in json.loads(_log(fake.log_path)[0][1][len("START "):])
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    assert not project.exists()  # the analysis alone writes no project

    text = "x; !calc @ 0 | y"
    session.comment(0x1400014B7, text)
    log = fake.commands()
    assert not [c for c in log if "!" in c]
    assert f"CCu base64:{base64.b64encode(text.encode()).decode()} @ 0x1400014b7" in log
    assert session.text("CC. @ 0x1400014b7") == text + "\n"
    timers.fire()
    assert project.exists()

    with pytest.raises(RizinRefused):
        session.rename(0x1400014B7, "a;!calc")
    for bad in ("", "1abc", "a b", "a'b", 'a"b', "a`b", "a|b", "x" * 129, "abc\n", "abc\r"):
        with pytest.raises(RizinRefused):
            session.rename(0x1400014B7, bad)
    assert not [c for c in fake.commands() if c.startswith("afn")]
    assert session.rename(0x1400014B7, "my_main") == {"offset": 0x1400014B7, "name": "my_main"}
    assert "afn 'my_main' @ 0x1400014b7" in fake.commands()
    # An address inside the function (a line of the disassembly, a block): rizin 0.9.1's afn renames only
    # at the function's start, so the session names the function's entry
    assert session.rename(0x1400015B9, "inner_main") == {"offset": 0x1400014B7, "name": "inner_main"}
    assert "afn 'inner_main' @ 0x1400014b7" in fake.commands()
    for bad in ("two\nlines", "cr\r", "nul\0", "x" * 501):
        with pytest.raises(RizinRefused):
            session.comment(0x1400014B7, bad)

    # A project written by rizin is made loadable: no DWARF variable origins, no eval_pending.
    timers.fire()
    saved = project.read_text()
    assert '"DWARF"' not in saved and "eval_pending" not in saved and '"hDllHandle"' in saved
    assert saved.rstrip().endswith("mode=one\ndone=aaa\npatches=")  # no patch: the line is there, empty

    # The console renames and comments too, and then saves the project; its answer says so (changed).
    project.unlink()
    out = session.console("afn console_name @ 0x1400014b7")
    assert out["function"] == "console_name" and out["changed"] is True
    timers.fire()
    assert project.exists()
    with pytest.raises(RizinRefused):
        session.console("pd 1;!calc")


def test_console_runs_in_colour_and_follows_seeks(sessions, sample, fake):
    from rizin_sessions import RizinRefused

    mgr = sessions()
    session = mgr.get(mgr.open(sample(), "tab")["session"])
    _wait_state(session, "done")
    out = session.console("pd 1 @ sym.main")
    assert out == {"output": "fake disassembly at 0x1400014b7\n", "seek": 0x1400014B7, "function": "sym.main",
                   "truncated": False, "changed": False}
    log = fake.commands()
    i = log.index("pd 1 @ sym.main")
    assert log[i - 1] == "e scr.color=3" and "e scr.color=0" in log[i + 1:i + 4]
    # Output with NUL bytes does not shift later answers; stderr shows up as well.
    assert session.console("pr 8")["output"] == "MZ\ufffd\x03rest\n"
    assert session.console("xyzzy")["output"] == "ERROR: Command 'xyzzy' does not exist.\n"
    assert session.json("aflj")[0]["name"] == "entry0"
    big = session.console("x 2000000")
    assert big["truncated"] and len(big["output"]) == 1024 * 1024
    assert session.seek(0x140001490) == {"seek": 0x140001490, "function": "sym.watchdog"}
    assert session.status()["seek"] == 0x140001490
    with pytest.raises(RizinRefused):
        session.console("o C:\\x")


def _plant_breakpoint_command(project, addr, data, cond):
    """Arm a saved project's breakpoint with the command and the condition rizin runs when it hits
    (``dbc``/``dbC``), as a project from somewhere else can carry them."""
    text = project.read_text(encoding="utf-8", errors="surrogateescape")
    namespace, line = None, None
    for candidate in text.split("\n"):
        if candidate.startswith("/"):
            namespace = candidate
        # the functions namespace has rows under the same keys, so the namespace has to match
        elif namespace == "/core/debug/breakpoints" and candidate.startswith(f"{addr:#x}="):
            line = candidate
    assert line, f"no breakpoint at {addr:#x} in {project}"
    key, value = line.split("=", 1)
    saved = json.loads(value)
    saved["data"], saved["cond"] = data, cond
    project.write_text(text.replace(line, key + "=" + json.dumps(saved, separators=(",", ":"))),
                       encoding="utf-8", errors="surrogateescape")


def test_a_loaded_project_brings_back_no_assembler_hooks_or_hints(sessions, sample, fake, tmp_path):
    timers = Timers()
    mgr = sessions(timer=timers)
    path = sample()
    opened = mgr.open(path, "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.rename(0x1400014B7, "named")
    timers.fire()
    mgr.close(opened["session"])
    assert wait_for(lambda: session.closed)
    # Poo brings back what a project holds; here an older or altered one names x86.nasm, a hook, a
    # pager, an arch hint and an ESIL hint that runs a command ("#!").
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    with open(project, "a", encoding="utf-8") as fh:
        fh.write("\n/core/config\nasm.arch=x86.nasm\nanalysis.arch=x86.nasm\nasm.assembler=x86.nasm\n"
                 "cmd.fcn.rename=CC hooked\ncmd.hit=CC hooked\nscr.pager=less\ncfg.editor=vi\n"
                 "\n/core/analysis/hints\n"
                 '0x1400014b7={"arch":"x86.nasm","esil":"#!CC hooked"}\n0x140001490={"arch":"arm"}\n'
                 '0x140001440={"esil":"1,rax,="}\n')
    open(fake.log_path, "w").close()
    session = mgr.get(mgr.open(path, "tab")["session"])
    assert session.analysis["note"] == "Restored from the saved project."
    log = fake.commands()
    after = log[log.index(next(c for c in log if c.startswith("Poo "))):]
    reset = next(c for c in after if c.startswith("e ") and "asm.assembler=" in c).split()
    for setting in ("asm.assembler=", "cfg.editor=", "scr.pager=", "cmd.fcn.rename=", "cmd.hit=", "cmd.esil.intr="):
        assert setting in reset
    # rizin 0.9.1 stays on x86.nasm when asked for x86 (the same arch), so the session goes through null.
    assert after.index("e asm.arch=null") < after.index("e asm.arch=x86")
    for key in ("asm.arch", "analysis.arch"):
        assert session.text("e " + key) == "x86\n"
    assert session.text("e asm.assembler") == "\n" and session.text("e cmd.fcn.rename") == "\n"
    hints = session.text("ahl")
    assert "x86.nasm" not in hints and "#!" not in hints
    assert "arch='arm'" in hints and "esil='1,rax,='" in hints  # the safe hints stay
    assert session.json("aflj")[2]["name"] == "named"  # and so does the project


def test_a_loaded_project_brings_back_no_breakpoint_command(sessions, sample, fake, tmp_path, monkeypatch):
    """R24: a breakpoint carries a command (``dbc``) and a condition (``dbC``) that rizin runs when it
    hits, and the project stores both verbatim (measured on 0.9.1). The console cannot set one, so a
    project that came from somewhere else is the way in -- and ``GET /breakpoints`` answers ``addr`` and
    ``enabled`` only, so nothing would show it. The boot takes both off, like the cmd.* hooks and the
    "#!" ESIL hints."""
    timers = Timers()
    mgr = sessions(timer=timers)
    path = sample()
    opened = mgr.open(path, "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.breakpoint_set(0x1400014B7)
    timers.fire()
    mgr.close(opened["session"])
    assert wait_for(lambda: session.closed)
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    _plant_breakpoint_command(project, 0x1400014B7, "CC pwned", "e asm.arch=x86.nasm")
    open(fake.log_path, "w").close()

    session = mgr.get(mgr.open(path, "tab")["session"])
    assert session.analysis["note"] == "Restored from the saved project."
    # the breakpoint is kept -- and what it would have run is gone, in rizin's own list, not just in
    # the answer the API gives
    assert session.breakpoints() == [{"addr": 0x1400014B7, "enabled": True}]
    assert [(b["data"], b["cond"]) for b in json.loads(session.text("dblj"))] == [("", "")]
    log = fake.commands()
    assert 'dbc "" @ 0x1400014b7' in log and 'dbC "" @ 0x1400014b7' in log
    assert session.text("e asm.arch") == "x86\n"  # the condition never ran

    # a rizin that does not let the command go: the project is not used at all, like one whose arch
    # cannot be made safe
    mgr.close(session.id)
    assert wait_for(lambda: session.closed)
    monkeypatch.setenv("FAKE_RIZIN_BP_ARMED", "1")
    session = mgr.get(mgr.open(path, "tab")["session"])
    _wait_state(session, "done")
    assert "could not be loaded" in session.analysis["note"]
    assert (tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb.broken")).exists()
    assert session.breakpoints() == []


def test_a_failed_final_save_leaves_the_analysis_done(sessions, sample, fake, tmp_path, monkeypatch):
    import rizin_sessions
    from rizin_sessions import SessionEnded

    # The end of an analysis saves an existing project. If that fails, the analysis is still done.
    mgr = sessions(big_file=1)
    opened = mgr.open(sample("disk.exe", b"MZ disk"), "tab1")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / (opened["file"]["sha256"] + ".rzdb")).write_text("an older project\n")

    def disk_full(pipe):
        raise OSError("disk full")

    session._project_snapshot = disk_full
    session.analyze_full()
    state = _wait_state(session, "done", "failed", "stopped")
    assert state["state"] == "done" and state["done_steps"] == FULL
    assert not session.closed and session.json("aflj")

    # A Ps that runs over its time limit gets rizin killed: the analysis stays done, the session ends.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "Ps:5")
    monkeypatch.setattr(rizin_sessions, "PROJECT_TIMEOUT", 0.5)
    opened = mgr.open(sample("slow.exe", b"MZ slow save"), "tab2")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    project = projects / (opened["file"]["sha256"] + ".rzdb")
    project.write_text("an older project\n")
    session.analyze_full()
    state = _wait_state(session, "done", "failed", "stopped")
    assert state["state"] == "done" and state["done_steps"] == FULL
    assert wait_for(lambda: session.closed)
    with pytest.raises(SessionEnded):
        mgr.get(opened["session"])
    assert project.read_text() == "an older project\n"
    assert not list(projects.glob("*.tmp"))


def test_close_does_not_wait_for_a_save_that_waits_for_the_pipe(sessions, sample, fake, tmp_path, monkeypatch):
    # A view holds the pipe for 10 s, and the timer's save waits for it (holding the save lock) when the
    # tab closes: close() returns after about 2 s (_CLOSE_WAIT), the save is written once the pipe is
    # free, and then the session ends. The view is long, so that the upper bound on close() lies far
    # below the time a close that waited for the save would take (follow-up finding 3).
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "pdfj:10")
    timers = Timers()
    mgr = sessions(timer=timers)
    opened = mgr.open(sample(), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.comment(0x1400014B7, "pending at close")
    view = threading.Thread(target=session.json, args=("pdfj @ sym.main",), kwargs={"wait": 5.0})
    view.start()
    assert wait_for(lambda: session._gate.holder == "view")
    saver = threading.Thread(target=timers.fire)
    saver.start()
    assert wait_for(lambda: session._save_lock.locked())
    started = time.monotonic()
    mgr.close(opened["session"])
    assert time.monotonic() - started < 6.0
    assert not session.closed
    assert wait_for(lambda: session.closed, 25)
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    assert "pending at close" in project.read_text()
    view.join(15)
    saver.join(15)
    assert len([c for c in fake.commands() if c.startswith("Ps ")]) == 1


def test_reap_ends_sessions_whose_rizin_died(sessions, sample, fake):
    from rizin_sessions import SessionEnded

    mgr = sessions()
    sid = mgr.open(sample(), "tab")["session"]
    session = mgr.get(sid)
    _wait_state(session, "done")
    # While the pipe is held (a step, or a restart after a hang), rizin may be dead: the holder replaces it.
    session._gate.enter("restart", 1.0)
    session._pipe._proc.kill()
    session._pipe._proc.wait(5)
    mgr.reap()
    assert mgr.get(sid) is session and not session.closed
    # Nobody holds it: the session is reaped.
    session._gate.leave()
    with pytest.raises(SessionEnded):
        mgr.get(sid)
    assert session.closed


def _running(pid):
    """Whether the process pid (a fake rizin's, from its log) still runs."""
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    return True


def _rizin_pids(fake):
    return [pid for pid, cmd in _log(fake.log_path) if cmd.startswith("START ")]


def test_a_reopened_file_leaves_an_unfinished_full_analysis_to_the_button(sessions, sample, fake, monkeypatch):
    """Final review, S1: a project saved while a Full analysis had not finished (here a step hung, so the
    session started again with the steps it had done) does not go on by itself when the file is opened
    again, the hung step with it: the session is stopped and says why, renames and comments work, and
    Full analysis goes on with the steps left."""
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    timers = Timers()
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    path = sample("resume.exe", b"MZ resume")
    opened = mgr.open(path, "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.analyze_full()
    assert _wait_state(session, "stopped")["done_steps"] == ["aa", "aac"]
    session.rename(MAIN, "kept_name")
    mgr.close(opened["session"])  # writes the project: Full analysis, aa and aac done
    assert wait_for(lambda: session.closed)

    monkeypatch.delenv("FAKE_RIZIN_SLOW")
    open(fake.log_path, "w").close()
    mgr = sessions(big_file=1, timer=timers)
    again = mgr.get(mgr.open(path, "tab")["session"])
    state = again.analysis
    assert state["state"] == "stopped" and state["step"] is None and state["level"] == "aaa", state
    assert state["done_steps"] == ["aa", "aac"]
    assert state["note"].startswith("Full analysis did not finish; not run: aar, aaft, Fa, aanr, aaC, avrr."), state
    assert again.comment(MAIN, "while stopped") == {"offset": MAIN, "comment": "while stopped"}
    assert again.json("aflj")[2]["name"] == "kept_name"
    time.sleep(0.3)
    assert _steps_in(fake.commands()) == [], "an analysis step ran by itself"
    again.analyze_full()
    state = _wait_state(again, "done")
    assert state["done_steps"] == FULL and "did not finish" not in state["note"]
    assert _steps_in(fake.commands()) == ["aar", "aaft", "Fa", "aanr", "aaC", "avrr"]


def test_an_older_open_that_ends_later_leaves_the_newer_session_of_its_tab(sessions, sample, fake, monkeypatch):
    """Final review, S2: the tab opens file A and, before A's answer comes, file B. A's rizin starts slowly
    and B's answer comes first. When A's start ends, A's own session is closed and its OPEN says that a
    newer one came first; B's session stays, and A holds no slot."""
    import rizin_sessions

    mgr = sessions()
    a, b = sample("a.exe", b"MZ file a"), sample("b.exe", b"MZ file b")
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "ij:1.5")
    outcome = {}

    def open_a():
        try:
            outcome["a"] = mgr.open(a, "tab")
        except Exception as exc:
            outcome["a"] = exc

    older = threading.Thread(target=open_a)
    older.start()
    assert wait_for(lambda: "ij" in fake.commands()), "A's rizin did not start"
    monkeypatch.delenv("FAKE_RIZIN_SLOW")
    newer = mgr.open(b, "tab")
    older.join(15)
    session = mgr.get(newer["session"])  # A's end must not close it
    assert not session.closed and len(session.json("aflj")) == 3
    assert type(outcome["a"]).__name__ == "SessionSuperseded", outcome
    assert isinstance(outcome["a"], rizin_sessions.SessionEnded)
    assert [s.path for s in mgr._sessions.values()] == [b] and mgr._starting == {}
    first = _rizin_pids(fake)[0]
    assert wait_for(lambda: not _running(first)), "A's rizin kept running"


def test_reopening_waits_for_the_save_of_the_closing_session(sessions, sample, fake, tmp_path, monkeypatch):
    """Final review, S3: the file is opened again while the session that closes still writes its project
    (Ps takes 3 s, longer than close() waits). The new session loads the project once that save is
    written: the rename is there, and the new session's own next save keeps it."""
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "Ps:3")
    timers = Timers()
    mgr = sessions(timer=timers)
    path = sample()
    opened = mgr.open(path, "tab")
    first = mgr.get(opened["session"])
    _wait_state(first, "done")
    first.rename(MAIN, "first_name")
    mgr.close(opened["session"])
    assert not first.closed, "the save did not outlast close()"
    again = mgr.get(mgr.open(path, "tab")["session"])
    assert again.json("aflj")[2]["name"] == "first_name", "the reopened file lost the rename"
    assert first.closed
    again.comment(MAIN, "second change")
    timers.fire()
    project = (tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")).read_text()
    assert '"name":"first_name"' in project and "second change" in project


def test_a_save_that_fails_unexpectedly_still_ends_rizin(sessions, sample, fake, tmp_path, monkeypatch):
    """Final review, S4: a save that fails with an error nobody planned for (here the copy of the project)
    keeps the change to be saved again, from the timer too, and close() still ends rizin."""
    import rizin_sessions

    timers = Timers()
    mgr = sessions(timer=timers)
    opened = mgr.open(sample(), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    real = rizin_sessions._sanitize_project

    def broken(*args):
        raise TypeError("an unexpected shape")

    monkeypatch.setattr(rizin_sessions, "_sanitize_project", broken)
    session.rename(MAIN, "kept_name")
    timers.fire()  # the timer's save fails; nothing leaves the timer
    assert not project.exists() and not session.closed
    monkeypatch.setattr(rizin_sessions, "_sanitize_project", real)
    assert session.flush() is True, "the change of the failed save was dropped"
    assert '"name":"kept_name"' in project.read_text()

    monkeypatch.setattr(rizin_sessions, "_sanitize_project", broken)
    session.comment(MAIN, "lost at close")
    mgr.close(opened["session"])
    assert wait_for(lambda: session.closed)
    assert wait_for(lambda: session._pipe._proc.poll() is not None), "rizin kept running"
    assert not _running(_rizin_pids(fake)[0])


def test_rizin_ends_with_the_web_ui_on_windows(fake, sample, monkeypatch, capsys):
    """Final review, S5: a killed web UI (deploy-utm.py and install-webui.ps1 force-kill python, so atexit does
    not run) leaves no rizin behind. On Windows every rizin goes into a job object that ends its
    processes once the web UI's handle to it closes; the handle is kept as long as rizin runs. Off
    Windows nothing is done, and a job that cannot be made is logged, never fatal."""
    import ctypes
    import types

    import rizin_sessions

    proc = types.SimpleNamespace(_handle=0x1234, pid=42)
    assert rizin_sessions._job_for(proc) is None  # off Windows
    with monkeypatch.context() as patch:
        patch.setattr(rizin_sessions.os, "name", "nt")
        no_job = rizin_sessions._job_for(proc)  # no kernel32 here: logged, not raised
    assert no_job is None and "[rizin]" in capsys.readouterr().out

    # The wiring: a rizin goes into its job right after it starts, the job goes once rizin has ended
    made, released = [], []

    class Job:
        def close(self):
            released.append(pipe._proc.poll())

    monkeypatch.setattr(rizin_sessions, "_job_for", lambda p: made.append(p) or Job())
    pipe = rizin_sessions.RizinPipe(fake.path, sample())
    try:
        assert made == [pipe._proc] and isinstance(pipe._job, Job) and released == []
        assert pipe.cmd("echo hi") == "hi\n"
    finally:
        pipe.close()
    pipe.close()
    assert len(released) == 1 and released[0] is not None, "the job went before rizin ended, or twice"

    # The calls to kernel32 (a stand-in): the job ends its processes when its last handle closes
    class Kernel32:
        def __init__(self, fail=None):
            self.calls, self.fail = [], fail

        def CreateJobObjectW(self, attributes, name):
            self.calls.append(("create", attributes, name))
            return 0x88

        def SetInformationJobObject(self, job, kind, info, size):
            self.calls.append(("limits", job.value, kind, info._obj.BasicLimitInformation.LimitFlags, size))
            return 1

        def AssignProcessToJobObject(self, job, process):
            self.calls.append(("assign", job.value, process.value))
            return 0 if self.fail == "assign" else 1

        def CloseHandle(self, handle):
            self.calls.append(("close", handle.value))
            return 1

    kernel32 = Kernel32()
    job = rizin_sessions._Job(proc, kernel32)
    assert kernel32.calls == [("create", None, None),
                              ("limits", 0x88, 9, 0x2000, ctypes.sizeof(rizin_sessions._JobLimits)),
                              ("assign", 0x88, 0x1234)]
    job.close()
    job.close()
    assert [c for c in kernel32.calls if c[0] == "close"] == [("close", 0x88)]
    failing = Kernel32(fail="assign")
    with pytest.raises(OSError):
        rizin_sessions._Job(proc, failing)
    assert failing.calls[-1] == ("close", 0x88), "a job that failed was left open"


def test_view_answers_are_capped_and_the_pipe_stays_in_sync(fake, sample, monkeypatch):
    """Final review, S6: an answer of a view command over the cap is not kept (the reader goes on to its
    end without keeping it, so the next answer is the next command's), and the view says it is too large.
    Follow-up finding 1: without a limit of its own a command keeps ANSWER_MAX, the backstop."""
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_STRINGS", "2000")
    pipe = rizin_sessions.RizinPipe(fake.path, sample())
    kept = []
    real_answer = pipe._answer

    def spy(deadline, limit=None):
        data, cut = real_answer(deadline, limit)
        kept.append(len(data))
        return data, cut

    pipe._answer = spy
    try:
        with pytest.raises(rizin_sessions.RizinTooLarge):
            pipe.cmdj("izj", limit=4096)
        assert max(kept) <= 4096
        assert pipe.cmd("echo next") == "next\n", "the pipe is out of step after a capped answer"
        assert len(pipe.cmdj("izj")) == 2006
        assert pipe.alive
        # No limit asked for: the backstop, which no legitimate answer reaches
        monkeypatch.setattr(rizin_sessions, "ANSWER_MAX", 4096)
        with pytest.raises(rizin_sessions.RizinTooLarge) as too_large:
            pipe.cmdj("izj")
        assert "4096 bytes" in str(too_large.value)
        assert pipe.cmd("echo after") == "after\n"
    finally:
        pipe.close()


def _build_pipesim(tmp_path):
    out = tmp_path / "build" / "pipesim.exe"
    out.parent.mkdir()
    subprocess.run([MINGW, "-O1", "-o", str(out), os.path.join(ROOT, "tests", "samples", "pipesim.c")],
                   check=True, capture_output=True, timeout=120)
    return out


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_project_survives_another_path(tmp_path):
    import rizin_sessions

    exe = _build_pipesim(tmp_path)
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        first = mgr.open(str(exe), "tab1")
        session = mgr.get(first["session"])
        state = _wait_state(session, "done", timeout=120)
        assert state["done_steps"] == ["aaa"] and state["note"] is None
        # aaa integrates DWARF variables, whose project rizin 0.9.1 cannot load as it is.
        assert any("@ ..." in session.text(f"afvl @ {f['offset']:#x}") for f in session.json("aflj"))
        main = next(f["offset"] for f in session.json("aflj") if f["name"] == "sym.main")
        nasty = "x; !calc @ 0 | y \"q\" 'r' `id` $(id) #c ~.. end \u00fc"
        assert session.rename(main, "tdc_main")["name"] == "tdc_main"
        session.comment(main, nasty)
        assert session.text(f"CC. @ {main:#x}") == nasty + "\n"
        mgr.close(first["session"])  # writes the save that is still pending

        copy = tmp_path / "elsewhere" / "renamed copy.exe"
        copy.parent.mkdir()
        shutil.copy(exe, copy)
        os.remove(exe)
        second = mgr.open(str(copy), "tab2")
        assert second["file"]["sha256"] == first["file"]["sha256"]
        session = mgr.get(second["session"])
        assert session.analysis["state"] == "done"
        assert session.json("ij")["core"]["file"] == str(copy)
        names = {f["offset"]: f["name"] for f in session.json("aflj")}  # rizin 0.9.1 crashed here
        assert names[main] == "tdc_main"
        assert session.text(f"CC. @ {main:#x}") == nasty + "\n"
        assert session.json(f"pdfj @ {main:#x}")["name"] == "tdc_main"
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_full_analysis_runs_the_steps(tmp_path):
    import rizin_sessions

    exe = _build_pipesim(tmp_path)
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"), big_file=1,
                                       step_gap=0.05, step_gap_limit=0.5)
    try:
        opened = mgr.open(str(exe), "tab")
        assert opened["analysis"]["level"] == "aa"
        session = mgr.get(opened["session"])
        assert _wait_state(session, "done", timeout=120)["done_steps"] == ["aa"]
        session.analyze_full()
        state = _wait_state(session, "done", timeout=120)
        assert state["done_steps"] == FULL and state["level"] == "aaa" and "variables" in state["note"]
        assert any(f["name"] == "sym.main" for f in session.json("aflj"))
        with pytest.raises(rizin_sessions.RizinRefused) as refused:
            session.console("aaa")
        assert refused.value.reason == "whole-program analysis runs from the Full analysis button"
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_does_not_read_files_the_sample_names(tmp_path):
    import rizin_sessions

    # Debug info names pipesim.c, which sits next to the binary.
    src = tmp_path / "src"
    src.mkdir()
    shutil.copy(os.path.join(ROOT, "tests", "samples", "pipesim.c"), src)
    subprocess.run([MINGW, "-g", "-O1", "-o", "pipesim.exe", "pipesim.c"], cwd=str(src), check=True,
                   capture_output=True, timeout=120)
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(src / "pipesim.exe"), "tab")["session"])
        _wait_state(session, "done", timeout=120)
        disasm = session.text("pdf @ sym.main") + json.dumps(session.json("pdfj @ sym.main"))
        assert "pipesim.c:118" in disasm
        # Source lines (the signature itself comes from the DWARF types).
        assert "char self[MAX_PATH]" not in disasm and "GetModuleFileNameA(NULL" not in disasm
        with pytest.raises(rizin_sessions.RizinRefused):
            session.console("agl json @ sym.main")
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_console_and_comment_stay_text(tmp_path):
    import rizin_sessions

    exe = _build_pipesim(tmp_path)
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(exe), "tab")["session"])
        _wait_state(session, "done", timeout=120)
        out = session.console("pdf @ sym.main~:0..3")
        assert "sym.main" in out["output"] and len(out["output"].splitlines()) == 3
        assert out["function"] == "sym.main" and out["seek"] == session.status()["seek"]
        assert "\x1b[" in session.console("pd 3")["output"]  # rizin drops colours when grepping
        assert "\x1b[" not in session.text("pd 3")
        assert "does not exist" in session.console("xyzzy")["output"]
        wrong = session.console("afn")["output"]  # an error with help text, all on stderr
        assert "Wrong number of arguments" in wrong and "Rename function" in wrong
        for shown in (wrong, session.console("pd 2")["output"]):
            assert "tdc" not in shown and "Ztdc" not in shown
        raw = session.console("pr 64 @ 0x140000000")["output"]
        assert raw.startswith("MZ")
        assert session.json("ij")["bin"]["arch"] == "x86"  # still in sync after NUL output
        marker = tmp_path / "pwned"
        main = out["seek"]
        for text in (f"x; !touch {marker} @ 0 | y", f"'; o {marker}; '", "$(id) `id`"):
            session.comment(main, text)
            assert session.text(f"CC. @ {main:#x}") == text + "\n"
        assert not marker.exists()
    finally:
        mgr.shutdown()


def _plant(project, config, hints):
    """Put settings and hints into a saved project, as an older or altered one could hold them."""
    keys = {"/core/config": set(config), "/core/analysis/hints": {f"{addr:#x}" for addr in hints}}
    out, ns = [], None
    for line in project.read_text(encoding="utf-8", errors="surrogateescape").split("\n"):
        if line.startswith("/"):
            ns = line
            out.append(line)
            if ns == "/core/config":
                out += [f"{key}={value}" for key, value in config.items()]
            elif ns == "/core/analysis/hints":
                out += [f"{addr:#x}={json.dumps(hint)}" for addr, hint in hints.items()]
        elif line.split("=", 1)[0] not in keys.get(ns, ()):
            out.append(line)
    project.write_text("\n".join(out), encoding="utf-8", errors="surrogateescape")


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_never_starts_an_external_assembler(tmp_path, monkeypatch):
    import rizin_sessions
    from rizin_sessions import RizinRefused

    # Stand-ins for nasm and as, first on PATH, each leaving a marker when it runs. The *.as plugins
    # run as only where these name it (or on a host of their arch).
    bindir, marks = tmp_path / "bin", tmp_path / "marks"
    bindir.mkdir()
    marks.mkdir()
    for tool in ("nasm", "as"):
        (bindir / tool).write_text(f'#!/bin/sh\necho "$@" >> "{marks / tool}"\nexit 1\n')
        (bindir / tool).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    for name in ("RZ_X86_AS", "RZ_ARM32_AS", "RZ_ARM64_AS", "RZ_PPC_AS"):
        monkeypatch.setenv(name, "as")

    def ran():
        found = sorted(p.name for p in marks.iterdir())
        for p in marks.iterdir():
            p.unlink()
        return found

    exe = _build_pipesim(tmp_path)
    # The trap works: asked directly instead of through the console, rizin runs both stand-ins.
    pipe = rizin_sessions.RizinPipe(REAL_RIZIN, str(exe))
    try:
        pipe.cmd("pa nop @a:x86.nasm:64")
        pipe.cmd("pa nop @a:ppc.as:32")
    finally:
        pipe.close()
    assert ran() == ["as", "nasm"]

    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        opened = mgr.open(str(exe), "tab")
        session = mgr.get(opened["session"])
        _wait_state(session, "done", timeout=120)
        offsets = sorted(f["offset"] for f in session.json("aflj"))
        main = next(f["offset"] for f in session.json("aflj") if f["name"] == "sym.main")
        other = offsets[0]
        assert other < main
        # The console: pa and /a with @a:, the same through e, an arch hint; and each of these alone.
        for text in ("pa nop @a:x86.nasm:64", "/a nop @a:x86.nasm:64", "pa nop @a:ppc.as:32", "pa nop @a:x86.as:64",
                     "/aj nop @a:arm.as:64", "e asm.arch=x86.nasm", "e asm.arch=x86 asm.bits=64 asm.assembler=x86.nasm;pa nop",
                     "e analysis.arch=ppc.as;/a nop", "e asm.syntax=att;pa nop", f"aha x86.nasm @ {main:#x}",
                     "e asm.assembler=x86.nasm", "pd 1 @a:x86.nasm:64", "pa nop", "/a nop"):
            with pytest.raises(RizinRefused):
                session.console(text)
        # What the console may set (AT&T syntax, another disassembler) starts nothing: nothing in it assembles.
        for text in ("e asm.syntax=att", f"pd 3 @ {main:#x}", "/ad nop", "e asm.syntax=intel", "e asm.arch=ppc",
                     "pd 2", "e asm.arch=x86"):
            session.console(text)
        assert ran() == []

        # A project whose stored settings name x86.nasm, with a hook and hints that would run commands.
        session.rename(main, "tdc_main")
        mgr.close(opened["session"])  # writes the project
        assert wait_for(lambda: session.closed)
        project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
        _plant(project, {"asm.arch": "x86.nasm", "analysis.arch": "x86.nasm", "asm.assembler": "x86.nasm",
                         "cmd.fcn.rename": "CC hooked @ 0x140001000"},
               {main: {"arch": "x86.nasm"}, other: {"esil": "#!CC esil_ran @ 0x140001004"}})
        session = mgr.get(mgr.open(str(exe), "tab")["session"])
        assert session.analysis["note"] == "Restored from the saved project."
        for key in ("asm.arch", "analysis.arch"):
            assert session.text("e " + key) == "x86\n"
        assert session.text("e asm.assembler") == "\n" and session.text("e cmd.fcn.rename") == "\n"
        session.text(f"pd 3 @ {main:#x}")  # an arch hint left there would switch asm.arch
        assert session.text("e asm.arch") == "x86\n"
        session.text("pa nop")  # the web UI's own call, past the console filter: assembles with x86.nz
        assert session.rename(main, "tdc_again")["name"] == "tdc_again"  # cmd.fcn.rename would run here
        for cmd in (f"aes @ {other:#x}", f"s {other:#x}", "aeip", "aes"):  # and the ESIL hint here
            session.text(cmd)
        assert "hooked" not in session.text("CC. @ 0x140001000")
        assert "esil_ran" not in session.text("CC. @ 0x140001004")
        assert ran() == []
    finally:
        mgr.shutdown()


# --- API: /api/rizin/... (webui/app.py) ----------------------------------------

ENTRY, WATCHDOG, MAIN = 0x140001440, 0x140001490, 0x1400014B7
MAIN_BLOCKS = [0x1400014B7, 0x1400014CA, 0x140001600, 0x140001620, 0x140001630, 0x140001640]
PIPE_IMPORT = 0x1400093B0  # sym.imp.KERNEL32.dll_CreateNamedPipeA
SAMPLE = b"MZ\x90\x00 fake sample"


class _Api:
    """The web UI's test client with the folders the RIZIN tab may read."""

    def __init__(self, tdc, fake, mgr, tmp):
        self.tdc, self.fake, self.mgr, self.tmp = tdc, fake, mgr, tmp
        self.allowed, self.dumps, self.uploads = tmp / "allowed", tmp / "dumps", tmp / "uploads"
        self.client = tdc.app.test_client()

    def get(self, url):
        return self.client.get(url)

    def post(self, url, body=None, **kwargs):
        return self.client.post(url, json=body, **kwargs)

    def delete(self, url, body=None, **kwargs):
        return self.client.delete(url, json=body, **kwargs)

    @staticmethod
    def ok(response):
        assert response.status_code == 200, (response.status_code, response.get_json())
        return response.get_json()

    def read(self, url):
        return self.ok(self.get(url))

    def send(self, url, body=None):
        return self.ok(self.post(url, body))

    def remove(self, url, body=None):
        return self.ok(self.delete(url, body))

    def close(self, sid):
        """End the session; a project save that is still waiting is written as it closes."""
        return self.send(f"/api/rizin/{sid}/close", {})

    def project(self, data=SAMPLE):
        """Where the project of a sample with these bytes is written."""
        return self.tmp / "projects" / (hashlib.sha256(data).hexdigest() + ".rzdb")

    def write(self, name, data=SAMPLE):
        path = self.allowed / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)

    def open(self, path, tab="tab1"):
        return self.send("/api/rizin/open", {"path": path, "tab": tab})

    def status(self, sid):
        return self.get(f"/api/rizin/{sid}/status").get_json()

    def wait_done(self, sid, timeout=20.0):
        assert wait_for(lambda: self.status(sid)["analysis"]["state"] == "done", timeout), self.status(sid)

    def rizin_runs(self):
        """The commands of each rizin session process (not the status probe's runs)."""
        return [cmds for cmds in self.fake.by_process() if cmds[0].startswith("START ")]

    def commands(self):
        return self.fake.commands()

    def session(self, name="pipesim.exe"):
        """A sample opened and analysed: its session ID. The fake's FAKE_RIZIN_* variables set before apply."""
        sid = self.open(self.write(name))["session"]
        self.wait_done(sid)
        return sid


@pytest.fixture
def rz(tdc, sessions, fake, tmp_path, monkeypatch):
    """The web UI with the fake rizin; the readable folders, dumps and uploads are under tmp_path."""
    import rizin_sessions

    mgr = sessions()
    api = _Api(tdc, fake, mgr, tmp_path)
    api.allowed.mkdir()
    api.dumps.mkdir()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", fake.path)
    monkeypatch.setattr(tdc, "PROCESSDUMP_DIR", str(api.dumps))
    monkeypatch.setattr(tdc, "RIZIN_UPLOAD_DIR", str(api.uploads))
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(api.allowed), str(api.dumps), str(api.uploads)])
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    return api


def test_rizin_routes_open_and_read(rz):
    path = rz.write("pipesim.exe")
    opened = rz.open(path)
    sid = opened["session"]
    assert opened["file"]["path"] == path and opened["file"]["format"] == "pe64"
    assert opened["file"]["sha256"] == hashlib.sha256(SAMPLE).hexdigest() and opened["file"]["size"] == len(SAMPLE)
    rz.wait_done(sid)
    status = rz.status(sid)
    assert set(status) == {"analysis", "seek", "function"}
    assert status["seek"] == ENTRY and status["function"] == "entry0"
    assert rz.send(f"/api/rizin/{sid}/analyze")["analysis"]["done_steps"] == ["aaa"]  # aaa covers it

    assert rz.read(f"/api/rizin/{sid}/functions") == [
        {"name": "entry0", "offset": ENTRY, "size": 29, "nbbs": 1},
        {"name": "sym.watchdog", "offset": WATCHDOG, "size": 38, "nbbs": 1},
        {"name": "sym.main", "offset": MAIN, "size": 1382, "nbbs": 30}]

    # Disassembly: the function around addr, from its start, page by page.
    first = rz.read(f"/api/rizin/{sid}/disasm?addr=0x1400014c0&count=100")
    assert first["function"] == "sym.main" and first["more"] is True and len(first["ops"]) == 100
    assert first["ops"][0] == {"offset": MAIN, "size": 2, "text": "push r15", "type": "rpush", "jump": None,
                               "comment": None}
    assert first["ops"][2] == {"offset": 0x1400014C0, "size": 5, "text": "call dbg.__main", "type": "call",
                               "jump": 0x140001AF0, "comment": None}
    ops = list(first["ops"])
    while True:
        page = rz.read(f"/api/rizin/{sid}/disasm?addr={MAIN}&count=100&after={ops[-1]['offset']:#x}")
        ops += page["ops"]
        if not page["more"]:
            break
    offsets = [op["offset"] for op in ops]
    assert len(ops) == 258 and offsets == sorted(set(offsets)) and offsets[-1] == 0x14000164B
    # Far into a long function, the first page reaches addr, with ops after it; near the start it is count.
    deep = rz.read(f"/api/rizin/{sid}/disasm?addr=0x140001500&count=100")
    deep_offsets = [op["offset"] for op in deep["ops"]]
    assert deep_offsets[0] == MAIN and deep["more"] is True and len(deep_offsets) == 100
    deep = rz.read(f"/api/rizin/{sid}/disasm?addr=0x14000155b&count=100")
    deep_offsets = [op["offset"] for op in deep["ops"]]
    assert deep_offsets[0] == MAIN and len(deep_offsets) > 100 and deep["more"] is True
    assert len(deep_offsets) - 1 - deep_offsets.index(0x14000155B) == 25  # a quarter of count after addr
    assert len(rz.read(f"/api/rizin/{sid}/disasm?addr={MAIN}&count=20")["ops"]) == 20
    # Outside a function: linear disassembly, and its next page.
    linear = rz.read(f"/api/rizin/{sid}/disasm?addr=0x140003098&count=3")
    assert linear["function"] is None and linear["more"] is True
    assert [op["text"] for op in linear["ops"]] == ["jmp qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]", "int3",
                                                    "invalid"]
    after = rz.read(f"/api/rizin/{sid}/disasm?addr=0x140003098&count=3&after=0x140003098")
    assert [op["offset"] for op in after["ops"]] == [0x14000309E, 0x14000309F, 0x1400030A0]

    # A comment comes back decoded in the disassembly; a rename shows in every view.
    note = 'pipe <b>"x"</b> \u00fc'
    assert rz.send(f"/api/rizin/{sid}/comment", {"addr": "0x1400015b9", "text": note}) == {
        "offset": 0x1400015B9, "comment": note}
    page = rz.read(f"/api/rizin/{sid}/disasm?addr=0x1400015b9&count=300")
    assert next(op for op in page["ops"] if op["offset"] == 0x1400015B9)["comment"] == note
    assert rz.send(f"/api/rizin/{sid}/rename", {"addr": MAIN, "name": "tdc_main"}) == {
        "offset": MAIN, "name": "tdc_main"}

    # Graph: the blocks with their lines; edges only between blocks of the function.
    graph = rz.read(f"/api/rizin/{sid}/graph?addr={0x140001625}")
    assert graph["function"] == "tdc_main" and graph["offset"] == MAIN
    assert [n["offset"] for n in graph["nodes"]] == MAIN_BLOCKS
    nodes = {n["offset"]: n for n in graph["nodes"]}
    assert nodes[MAIN] == {"offset": MAIN, "size": 19, "jump": 0x140001600, "fail": 0x1400014CA, "cases": [],
                           "lines": ["push r15", "sub rsp, 0x558", "call dbg.__main", "cmp ebx, 0x02",
                                     "jle 0x140001600"]}
    assert len(nodes[0x1400014CA]["lines"]) == 242 and nodes[0x1400014CA]["jump"] == 0x140001600
    assert nodes[0x140001600]["cases"] == [0x140001620, 0x140001630]
    assert nodes[0x140001600]["jump"] is None and nodes[0x140001600]["fail"] is None
    assert nodes[0x140001630]["jump"] == 0x140001640
    assert nodes[0x140001640]["jump"] is None  # the tail call to sym.watchdog leaves the function

    # Strings and imports: filtered on the server, in pages (truncated: rizin listed more than RIZIN_ROWS_MAX).
    pipe = "\\\\.\\pipe\\msagent_%04x%02x"
    assert rz.read(f"/api/rizin/{sid}/strings?q=PIPE&limit=1") == {"total": 2, "truncated": False, "items": [
        {"offset": 0x140005041, "string": pipe, "length": len(pipe), "section": ".rdata", "type": "ascii"}]}
    assert rz.read(f"/api/rizin/{sid}/strings?q=PIPE&limit=1&offset=1")["items"][0]["string"] == "Pipe closed"
    assert rz.read(f"/api/rizin/{sid}/strings?q=pipe&offset=2") == {"total": 2, "items": [], "truncated": False}
    everything = rz.read(f"/api/rizin/{sid}/strings")
    assert everything["total"] == 6 and everything["items"][4]["string"] == '<b>bold</b> & "quoted"'  # as rizin has it
    assert rz.read(f"/api/rizin/{sid}/imports?q=kernel32")["total"] == 4
    assert rz.read(f"/api/rizin/{sid}/imports?q=NamedPipe") == {"total": 1, "truncated": False, "items": [
        {"offset": PIPE_IMPORT, "name": "CreateNamedPipeA", "library": "KERNEL32.dll", "type": "FUNC",
         "ordinal": 4}]}

    # Cross references to an import; to and from a function (at its entry the whole function's); and from
    # one instruction.
    xrefs = rz.read(f"/api/rizin/{sid}/xrefs?addr={PIPE_IMPORT:#x}")
    assert xrefs == {"scope": "address", "function": None, "truncated": False, "from": [], "to": [
        {"from": 0x1400015B9, "to": PIPE_IMPORT, "type": "CALL",
         "text": "call qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]", "function": "tdc_main"},
        {"from": 0x140003098, "to": PIPE_IMPORT, "type": "CODE",
         "text": "jmp qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]", "function": None}]}
    xrefs = rz.read(f"/api/rizin/{sid}/xrefs?addr={MAIN}")
    assert xrefs["scope"] == "function" and xrefs["function"] == "tdc_main"
    assert xrefs["to"] == [{"from": 0x140001444, "to": MAIN, "type": "CALL", "text": "call sym.main",
                            "function": "entry0"}]
    assert [(x["from"], x["to"], x["type"]) for x in xrefs["from"]] == [
        (0x1400014C0, 0x140001AF0, "CALL"), (0x1400015B9, PIPE_IMPORT, "CALL"), (0x140001603, 0x140005100, "DATA"),
        (0x140001625, 0x1400093A8, "CALL"), (0x140001630, WATCHDOG, "CALL"), (0x14000164B, WATCHDOG, "CODE")]
    assert {x["function"] for x in xrefs["from"]} == {"tdc_main"}
    assert xrefs["from"][4]["text"] == "call sym.watchdog"
    inside = rz.read(f"/api/rizin/{sid}/xrefs?addr=0x140001630")
    assert inside["scope"] == "address" and inside["function"] == "tdc_main" and inside["to"] == []
    assert [x["to"] for x in inside["from"]] == [WATCHDOG]

    # Hex: the bytes at addr, 512 unless len says otherwise, and where they are in the file (paddr)
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140000000&len=4") == {"offset": 0x140000000,
                                                                       "bytes": [0x4D, 0x5A, 0x90, 0x00], "paddr": 0}
    assert len(rz.read(f"/api/rizin/{sid}/hex?addr={0x140000000}")["bytes"]) == 512

    # Seek to an address or a name; a console command moves the views too.
    assert rz.send(f"/api/rizin/{sid}/seek", {"addr": "0x140001499"}) == {"seek": 0x140001499,
                                                                          "function": "sym.watchdog"}
    assert rz.send(f"/api/rizin/{sid}/seek", {"addr": 0x1400014C0}) == {"seek": 0x1400014C0, "function": "tdc_main"}
    assert rz.send(f"/api/rizin/{sid}/seek", {"addr": "entry0"}) == {"seek": ENTRY, "function": "entry0"}
    unknown = rz.post(f"/api/rizin/{sid}/seek", {"addr": "sym.nosuch"})
    assert unknown.status_code == 400 and "sym.nosuch" in unknown.get_json()["refused"]
    assert rz.status(sid)["seek"] == ENTRY
    assert rz.send(f"/api/rizin/{sid}/console", {"cmd": "pd 1 @ sym.watchdog"}) == {
        "output": "fake disassembly at 0x140001490\n", "seek": WATCHDOG, "function": "sym.watchdog",
        "truncated": False, "changed": False}
    assert rz.status(sid)["seek"] == WATCHDOG
    # A command that comments or renames says so, for the views to be drawn again
    assert rz.send(f"/api/rizin/{sid}/console", {"cmd": "CC seen here @ 0x140001490"})["changed"] is True

    # Close ends the session; closing again is fine.
    assert rz.send(f"/api/rizin/{sid}/close") == {"closed": True}
    gone = rz.get(f"/api/rizin/{sid}/functions")
    assert gone.status_code == 404 and gone.get_json() == {"error": "session ended"}
    assert rz.send(f"/api/rizin/{sid}/close") == {"closed": True}


def test_rizin_decompile_lines_follow_rizins_offsets(rz, monkeypatch):
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    out = rz.read(f"/api/rizin/{sid}/decompile?addr=0x1400015b9")
    assert out["available"] is True and out["reason"] is None and out["function"] == "sym.main"
    # A line's offset is its first offset annotation (rizin's pdgo); offsets are all of them. Positions count
    # bytes: the 40 two-byte characters in line 3 must not move the lines after it.
    assert out["lines"] == [
        {"text": "int sym.main(int argc, char **argv)", "offset": None, "offsets": []},
        {"text": "{", "offset": None, "offsets": []},
        {"text": "    if (argc < 3) {", "offset": 0x1400014C5, "offsets": [0x1400014C5, 0x1400014C8]},
        {"text": '        s = "' + "\u00fc" * 40 + '"; Sleep(1000);', "offset": 0x140001625, "offsets": [0x140001625]},
        {"text": "    }", "offset": None, "offsets": []},
        {"text": "    hPipe = CreateNamedPipeA(lpName);", "offset": 0x1400015BF,
         "offsets": [0x1400015B9, 0x1400015BF]},
        {"text": "    return 0;", "offset": 0x140001640, "offsets": [0x140001640]},
        {"text": "}", "offset": None, "offsets": []}]
    assert rz.read(f"/api/rizin/{sid}/decompile?addr=0x140003098") == {
        "available": True, "reason": "No function at 0x140003098", "function": None, "lines": []}
    nothing = rz.read(f"/api/rizin/{sid}/decompile?addr={WATCHDOG}")
    assert nothing["available"] is True and nothing["function"] == "sym.watchdog" and nothing["lines"] == []
    assert "sym.watchdog" in nothing["reason"]

    monkeypatch.setenv("FAKE_RIZIN_NO_GHIDRA", "1")
    other = rz.open(rz.write("other.exe", b"MZ other"), "tab2")["session"]
    rz.wait_done(other)
    assert rz.read(f"/api/rizin/{other}/decompile?addr={MAIN}") == {
        "available": False, "reason": "Decompiler not available (rz-ghidra missing)", "function": None, "lines": []}
    assert not [c for c in rz.rizin_runs()[1] if c.startswith("pdgj")]


def test_rizin_open_refuses_paths_outside_and_odd_files(rz, monkeypatch):
    elsewhere = rz.tmp / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "x.exe").write_bytes(b"MZ outside")
    (rz.allowed / "link").symlink_to(elsewhere, target_is_directory=True)
    real_realpath = os.path.realpath
    resolved = []
    with monkeypatch.context() as patch:
        patch.setattr(rz.tdc.os.path, "realpath",
                      lambda p, *a, **k: resolved.append(p) or real_realpath(p, *a, **k))
        for path in (str(rz.allowed / ".." / "elsewhere" / "x.exe"), r"\\host\share\x", "//host/share/x",
                     r"\\?\C:\Windows\win.ini", str(elsewhere / "x.exe"), str(rz.allowed / "link" / "x.exe"),
                     "x.exe"):
            r = rz.post("/api/rizin/open", {"path": path, "tab": "tab1"})
            assert r.status_code == 403, path
            assert r.get_json()["error"], path
    # UNC and device paths are refused before anything resolves them (that would connect to the host).
    assert resolved and not [p for p in resolved if str(p).replace("/", "\\").startswith("\\\\")]

    for body in ({"tab": "tab1"}, {"path": 5, "tab": "tab1"}, {"path": "", "tab": "tab1"},
                 {"path": rz.write("ok.exe") + "\0", "tab": "tab1"}, {"path": rz.write("ok.exe")},
                 {"path": rz.write("ok.exe"), "tab": "a b"}, {"path": rz.write("ok.exe"), "tab": "x" * 65}, [1]):
        r = rz.post("/api/rizin/open", body)
        assert r.status_code == 400 and r.get_json()["refused"], body
    assert rz.client.post("/api/rizin/open", data="path=x").status_code == 400

    # Odd files get a clear message, and no rizin is started for them.
    for path, reason in ((rz.write("empty.bin", b""), "the file is empty"),
                         (str(rz.allowed / "missing.exe"), "the file does not exist"),
                         (str(rz.allowed), "the path is a folder, not a file")):
        r = rz.post("/api/rizin/open", {"path": path, "tab": "tab1"})
        assert r.status_code == 400 and r.get_json() == {"refused": reason}, path
    assert rz.fake.commands() == []

    # Deleted after opening: the open session still answers (rizin has the file open), opening it again
    # says that it is gone.
    gone = rz.write("gone.exe", b"MZ gone")
    sid = rz.open(gone)["session"]
    rz.wait_done(sid)
    os.remove(gone)
    assert len(rz.read(f"/api/rizin/{sid}/functions")) == 3
    r = rz.post("/api/rizin/open", {"path": gone, "tab": "tab2"})
    assert r.status_code == 400 and r.get_json() == {"refused": "the file does not exist"}

    # A file without code: empty views, no errors.
    monkeypatch.setenv("FAKE_RIZIN_NO_CODE", "1")
    monkeypatch.setenv("FAKE_RIZIN_FORMAT", "any")
    sid = rz.open(rz.write("notes.txt", b"just some text\n"), "tab3")["session"]
    rz.wait_done(sid)
    assert rz.read(f"/api/rizin/{sid}/functions") == []
    assert rz.read(f"/api/rizin/{sid}/graph?addr=0x140000000") == {"function": None, "offset": None, "nodes": []}
    disasm = rz.read(f"/api/rizin/{sid}/disasm?addr=0x140000000&count=4")
    assert disasm["function"] is None and len(disasm["ops"]) == 4
    assert rz.read(f"/api/rizin/{sid}/decompile?addr=0x140000000")["reason"] == "No function at 0x140000000"
    xrefs = rz.read(f"/api/rizin/{sid}/xrefs?addr=0x140000000")
    assert xrefs["to"] == [] and xrefs["from"] == [] and xrefs["function"] is None


def test_rizin_busy_session_does_not_block_other_routes(rz, monkeypatch):
    """The step takes long enough that an answer which waited for it could not be mistaken for a quick
    one, so the bounds here are wide (follow-up finding 3)."""
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aaa:20")
    sid = rz.open(rz.write("slow.exe", b"MZ slow"))["session"]
    assert wait_for(lambda: rz.status(sid)["analysis"]["step"] == "aaa")
    answers = {}

    def view(name, method, url, body=None):
        client = rz.tdc.app.test_client()
        started = time.monotonic()
        r = client.get(url) if method == "GET" else client.post(url, json=body)
        answers[name] = (r.status_code, r.get_json(), time.monotonic() - started)

    threads = [threading.Thread(target=view, args=("functions", "GET", f"/api/rizin/{sid}/functions")),
               threading.Thread(target=view, args=("console", "POST", f"/api/rizin/{sid}/console", {"cmd": "afl"}))]
    rz.read("/api/rizin/status")  # asks rizin for its version once, before the clock runs
    for thread in threads:
        thread.start()
    time.sleep(0.3)  # both wait for the pipe now
    for url in ("/api/health", f"/api/rizin/{sid}/status", "/api/rizin/status"):
        started = time.monotonic()
        assert rz.get(url).status_code == 200, url
        assert time.monotonic() - started < 5.0, url  # they do not wait for the step (20 s)
    for thread in threads:
        thread.join(15)
    for name in ("functions", "console"):
        status, body, took = answers[name]
        assert status == 409 and body == {"busy": True, "step": "aaa"}, name
        assert took < 10.0, name  # busy after about 2 s of waiting, not after the step


def test_rizin_console_refusal_and_cross_site(rz):
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    r = rz.post(f"/api/rizin/{sid}/console", {"cmd": "!calc"})
    assert r.status_code == 400 and r.get_json() == {"refused": "'!' is not allowed: no shell commands"}
    for cmd in ("pd 1;!calc", "o C:\\x", "afl\nlo", 5, None, ["afl"]):
        r = rz.post(f"/api/rizin/{sid}/console", {"cmd": cmd})
        assert r.status_code == 400 and r.get_json()["refused"], cmd
    assert not [c for c in rz.fake.commands() if "calc" in c or c.startswith("o ") or c.startswith("lo")]

    # Requests from another site, or for another host name, never reach a session.
    before = len(rz.fake.commands())
    path = rz.write("other.exe", b"MZ other")
    for url, body in ((f"/api/rizin/{sid}/console", {"cmd": "afl"}), ("/api/rizin/open", {"path": path, "tab": "t"}),
                      (f"/api/rizin/{sid}/rename", {"addr": MAIN, "name": "x"}), (f"/api/rizin/{sid}/close", None),
                      (f"/api/rizin/{sid}/seek", {"addr": MAIN}), ("/api/rizin/upload", None)):
        for headers in ({"Origin": "http://evil.example"}, {"Referer": "http://evil.example/x"}, {"Origin": "null"},
                        {"Host": "evil.example:9000"}):
            assert rz.post(url, body, headers=headers).status_code == 403, (url, headers)
    assert len(rz.fake.commands()) == before
    assert rz.status(sid)["analysis"]["state"] == "done"

    # The page's own close beacon (same origin, a text body) ends the session.
    r = rz.client.post(f"/api/rizin/{sid}/close", data="", content_type="text/plain;charset=UTF-8",
                       headers={"Origin": "http://localhost"})
    assert r.status_code == 200 and r.get_json() == {"closed": True}
    assert rz.get(f"/api/rizin/{sid}/status").status_code == 404


def test_rizin_not_installed(rz, monkeypatch):
    import rizin_sessions

    missing = str(rz.tmp / "nowhere" / "rizin.exe")
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", missing)
    assert rz.read("/api/rizin/status") == {"installed": False, "path": missing, "version": None, "ghidra": False}
    r = rz.post("/api/rizin/open", {"path": rz.write("x.exe"), "tab": "tab1"})
    assert r.status_code == 503 and r.get_json() == {"error": "rizin not installed", "path": missing}
    assert rz.fake.commands() == []


def test_rizin_status_reports_version_and_decompiler(rz, monkeypatch):
    import rizin_sessions

    assert rz.read("/api/rizin/status") == {"installed": True, "path": rz.fake.path, "version": "0.9.1",
                                            "ghidra": True}
    probes = len(rz.fake.commands())
    assert probes == 2  # rizin -v, rizin -qc Lc
    rz.read("/api/rizin/status")
    assert len(rz.fake.commands()) == probes  # asked once per rizin
    other = rz.tmp / "rizin-without-ghidra"
    other.write_text(f'#!/bin/sh\nFAKE_RIZIN_NO_GHIDRA=1 exec "{sys.executable}" "{FAKE_RIZIN}" "$@"\n')
    other.chmod(0o755)
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", str(other))
    assert rz.read("/api/rizin/status") == {"installed": True, "path": str(other), "version": "0.9.1",
                                            "ghidra": False}


def test_rizin_files_and_upload(rz, monkeypatch):
    sample = rz.write("pipesim.exe")
    outside = rz.tmp / "outside.exe"
    outside.write_bytes(b"MZ outside")
    monkeypatch.setattr(rz.tdc, "_load_submissions", lambda: [
        {"filename": "pipesim.exe", "file_path": sample, "sha256": "ab" * 32, "timestamp": "2026-11-12T10:00:00"},
        {"filename": "pipesim.exe", "file_path": sample, "sha256": "ab" * 32, "timestamp": "2026-11-11T09:00:00"},
        {"filename": "gone.exe", "file_path": str(rz.allowed / "gone.exe"), "sha256": "cd" * 32, "timestamp": "x"},
        {"filename": "outside.exe", "file_path": str(outside), "sha256": "ef" * 32, "timestamp": "x"},
        {"filename": "empty.exe", "file_path": rz.write("empty.exe", b""), "sha256": "00" * 32, "timestamp": "x"},
        {"filename": "unknown.exe", "file_path": None, "sha256": "11" * 32, "timestamp": "x"},
        "not a submission"])
    run = rz.dumps / "20261112-101010_pid42"
    run.mkdir()
    (run / "pipesim.exe_0x140000000.exe").write_bytes(b"MZ" * 50)
    (run / "empty.dll").write_bytes(b"")
    os.utime(run / "pipesim.exe_0x140000000.exe", (1_000_000, 1_000_000))
    capture = rz.dumps / "exit" / "pipesim.exe-(PID-42)"
    capture.mkdir(parents=True)
    (capture / "pipesim.exe-(PID-42)-1234.dmp").write_bytes(b"MDMP" * 10)

    def upload(data, name):
        return rz.client.post("/api/rizin/upload", data={"file": (io.BytesIO(data), name)},
                              content_type="multipart/form-data")

    path = rz.ok(upload(b"MZ uploaded", "my sample.exe"))["path"]
    assert os.path.dirname(path) == str(rz.uploads)
    assert os.path.basename(path) == hashlib.sha256(b"MZ uploaded").hexdigest()[:16] + "_my_sample.exe"
    with open(path, "rb") as fh:
        assert fh.read() == b"MZ uploaded"
    os.utime(path, (1_000_000, 1_000_000))
    assert rz.ok(upload(b"MZ uploaded", "my sample.exe")) == {"path": path}  # the same file again
    assert os.path.getmtime(path) > 1_000_000  # and newest again, so it is not pruned first
    for data, name, reason in ((b"", "empty.exe", "the file is empty"),):
        r = upload(data, name)
        assert r.status_code == 400 and r.get_json() == {"refused": reason}
    r = rz.client.post("/api/rizin/upload", data={}, content_type="multipart/form-data")
    assert r.status_code == 400 and r.get_json()["refused"]
    assert sorted(os.listdir(rz.uploads)) == [os.path.basename(path)]  # no leftovers

    assert rz.read("/api/rizin/files") == {
        "submissions": [{"filename": "pipesim.exe", "path": sample, "sha256": "ab" * 32, "time": "2026-11-12T10:00:00"}],
        "dumps": [{"name": os.path.join("exit", "pipesim.exe-(PID-42)", "pipesim.exe-(PID-42)-1234.dmp"),
                   "path": str(capture / "pipesim.exe-(PID-42)-1234.dmp"), "size": 40},
                  {"name": os.path.join("20261112-101010_pid42", "pipesim.exe_0x140000000.exe"),
                   "path": str(run / "pipesim.exe_0x140000000.exe"), "size": 100}],
        "uploads": [{"name": os.path.basename(path), "path": path, "size": len(b"MZ uploaded")}]}
    assert rz.open(path)["file"]["path"] == path  # an upload opens

    # A dump folder with more files than are looked at: the newest run folders come first.
    os.utime(run, (1_000_000, 1_000_000))
    monkeypatch.setattr(rz.tdc, "RIZIN_SCAN_MAX", 1)
    assert [d["name"] for d in rz.read("/api/rizin/files")["dumps"]] == [
        os.path.join("exit", "pipesim.exe-(PID-42)", "pipesim.exe-(PID-42)-1234.dmp")]


def test_readable_roots_are_shared_by_download_and_rizin(tdc, client, monkeypatch, tmp_path):
    assert tdc._readable_roots() == [os.path.normpath(tdc.RUSTINEL_ALERTS_DIR), r"C:\Users", r"C:\Windows\Temp",
                                     r"C:\Temp", tdc.PROCESSDUMP_DIR, tdc.RIZIN_UPLOAD_DIR,
                                     tdc.CAPTURE_DIR]
    assert tdc.RIZIN_UPLOAD_DIR == os.path.join(tempfile.gettempdir(), "rizin_uploads")
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.bin").write_bytes(b"a")
    (tmp_path / "b.bin").write_bytes(b"b")
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(root)])

    def download(path):
        return client.get("/api/file/download", query_string={"path": path}).status_code

    assert download(str(root / "a.bin")) == 200
    assert download(str(tmp_path / "b.bin")) == 403
    assert download(str(root / ".." / "b.bin")) == 403
    assert download(r"\\host\share\a.bin") == 403


def test_rizin_session_states_map_to_status_codes(rz, monkeypatch):
    path = rz.write("pipesim.exe")
    first = rz.open(path, "tab1")
    rz.wait_done(first["session"])
    # The same file in another tab: the session moves there; the first tab hears so and can take it back.
    second = rz.open(path, "tab2")
    assert second["session"] != first["session"]
    r = rz.get(f"/api/rizin/{first['session']}/functions")
    assert r.status_code == 409 and r.get_json() == {"moved": True}
    back = rz.open(path, "tab1")
    assert len(rz.read(f"/api/rizin/{back['session']}/functions")) == 3
    assert rz.status(second["session"]) == {"moved": True}
    assert len(rz.rizin_runs()) == 1  # one rizin all along
    r = rz.get("/api/rizin/0123456789abcdef01234567/status")
    assert r.status_code == 404 and r.get_json() == {"error": "session ended"}

    # Renames and comments wait for the analysis.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aaa:2")
    sid = rz.open(rz.write("slow.exe", b"MZ slow"), "tab3")["session"]
    assert wait_for(lambda: rz.status(sid)["analysis"]["step"] == "aaa")
    for route, body in (("rename", {"addr": MAIN, "name": "early"}), ("comment", {"addr": MAIN, "text": "early"})):
        r = rz.post(f"/api/rizin/{sid}/{route}", body)
        assert r.status_code == 409 and r.get_json() == {"busy": True, "step": "aaa"}, route
    monkeypatch.delenv("FAKE_RIZIN_SLOW")

    # rizin stops during a view: that answer and the next say that the session ended.
    monkeypatch.setenv("FAKE_RIZIN_CRASH", "pdfj")
    sid = rz.open(rz.write("crash.exe", b"MZ crash"), "tab4")["session"]
    rz.wait_done(sid)
    r = rz.get(f"/api/rizin/{sid}/disasm?addr={MAIN}")
    assert r.status_code == 404 and r.get_json()["error"] == "session ended" and r.get_json()["reason"]
    assert rz.status(sid) == {"error": "session ended"}


def test_rizin_routes_refuse_bad_input(rz):
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    before = len(rz.fake.commands())
    for query in ("disasm?addr=main", "disasm?addr=0x", "disasm?addr=-1", "disasm?addr=0x1ffffffffffffffff",
                  f"disasm?addr={2 ** 64}", "disasm?addr=1;afl", "disasm?addr=0x10%3B%21calc", "disasm?addr=0x10%20@%200x20",
                  f"disasm?addr={MAIN}&count=0", f"disasm?addr={MAIN}&count=2001", f"disasm?addr={MAIN}&count=x",
                  f"disasm?addr={MAIN}&after=sym.main", "graph?addr=0x10%0Apdf", "hex?addr=0x10&len=4097",
                  "hex?addr=0x10&len=0", "hex?addr=0x10&len=-1", "strings?offset=-1", "strings?limit=0",
                  "strings?limit=1001", "strings?q=" + "x" * 201, "strings?q=a%0Ab", "imports?limit=x",
                  "imports?offset=1e3", "xrefs?addr=sym.main", "decompile?addr=0x10;pdg", "flags?limit=0",
                  "flags?limit=201", "flags?limit=x", "flags?q=" + "x" * 201, "flags?q=a%0Ab", "comment?addr=sym.main",
                  "comment?addr=0x10%0Apdf", "comment?addr=0x10;CC-"):
        r = rz.get(f"/api/rizin/{sid}/{query}")
        assert r.status_code == 400 and r.get_json()["refused"], query
    for route, body in (("seek", {"addr": "0x10;!calc"}), ("seek", {"addr": "sym.main;afl"}), ("seek", {"addr": "a b"}),
                        ("seek", {"addr": "sym.main@0x10"}), ("seek", {"addr": "$$"}), ("seek", {"addr": True}),
                        ("seek", {"addr": -1}), ("seek", {"addr": 2 ** 64}), ("seek", {"addr": None}), ("seek", {}),
                        ("seek", None), ("seek", [MAIN]), ("rename", {"addr": MAIN, "name": "a;b"}),
                        ("rename", {"addr": "main", "name": "ok"}), ("comment", {"addr": MAIN, "text": "two\nlines"}),
                        ("comment", {"addr": MAIN}), ("console", {})):
        r = rz.post(f"/api/rizin/{sid}/{route}", body)
        assert r.status_code == 400 and r.get_json()["refused"], (route, body)
    assert len(rz.fake.commands()) == before  # none of it reached rizin


def test_rizin_flags_complete_names(rz, sessions, monkeypatch):
    """Tab in the console completes flag names: /flags gives the names that start with q, in any case,
    sorted, at most 200, and the start that all of them share (common, also of those past the limit).
    rizin is asked (flj) once, and again after a console command, a rename or a comment and when an
    analysis step is done, which change the flags; strings and imports stay."""
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)

    def asked(command):
        return rz.fake.commands().count(command)

    pipe = ["sym.imp.KERNEL32.dll_CreateNamedPipeA", "sym.imp.KERNEL32.dll_Sleep"]
    # truncated: rizin listed more flags than the server keeps (RIZIN_ROWS_MAX), see test_rizin_big_lists_stay_bounded
    assert rz.read(f"/api/rizin/{sid}/flags?q=sym.imp.kernel32") == {"total": 2, "names": pipe,
                                                                     "common": "sym.imp.KERNEL32.dll_", "truncated": False}
    assert rz.read(f"/api/rizin/{sid}/flags?q=SYM.W") == {"total": 1, "names": ["sym.watchdog"], "common": "sym.watchdog",
                                                          "truncated": False}
    every = rz.read(f"/api/rizin/{sid}/flags")
    assert every == {"total": 6, "names": ["entry0", "str.child", *pipe, "sym.main", "sym.watchdog"], "common": "",
                     "truncated": False}
    assert rz.read(f"/api/rizin/{sid}/flags?q=sym.&limit=2") == {"total": 4, "names": pipe, "common": "sym.",
                                                                 "truncated": False}, \
        "common went as far as the names sent agree, not as far as all that match"
    assert rz.read(f"/api/rizin/{sid}/flags?q=nothing") == {"total": 0, "names": [], "common": "", "truncated": False}
    assert asked("flj") == 1, "rizin was asked again for flags it had given"

    rz.read(f"/api/rizin/{sid}/strings")
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "afl"})
    rz.read(f"/api/rizin/{sid}/flags?q=x")
    assert asked("flj") == 2
    rz.read(f"/api/rizin/{sid}/strings")  # asked for again after the console command
    strings = asked("izj")
    rz.send(f"/api/rizin/{sid}/rename", {"addr": MAIN, "name": "tdc_main"})
    assert rz.read(f"/api/rizin/{sid}/flags?q=TDC") == {"total": 1, "names": ["tdc_main"], "common": "tdc_main",
                                                        "truncated": False}
    assert asked("flj") == 3
    rz.send(f"/api/rizin/{sid}/comment", {"addr": MAIN, "text": "a note"})
    rz.read(f"/api/rizin/{sid}/flags")
    rz.read(f"/api/rizin/{sid}/flags?q=sym")
    rz.read(f"/api/rizin/{sid}/strings")
    assert asked("flj") == 4 and asked("izj") == strings, "a rename or a comment dropped the strings too"

    # Many flags: at most 200 names, the total says how many match, common is that of all of them
    monkeypatch.setenv("FAKE_RIZIN_FLAGS", "250")
    many = rz.open(rz.write("many.exe", b"MZ many flags"), "tab2")["session"]
    rz.wait_done(many)
    names = rz.read(f"/api/rizin/{many}/flags?q=str.")
    assert names["total"] == 251 and len(names["names"]) == 200 and names["common"] == "str."
    assert names["names"][:3] == ["str.child", "str.extra_0000", "str.extra_0001"]
    names = rz.read(f"/api/rizin/{many}/flags?q=STR.EXTRA_&limit=10")
    assert names["names"][-1] == "str.extra_0009" and names["common"] == "str.extra_0", \
        "common went as far as the 10 names sent (str.extra_000), not as far as all 250 agree"
    monkeypatch.delenv("FAKE_RIZIN_FLAGS")

    # An analysis step gives new flags: they are asked for again once it is done
    monkeypatch.setattr(rz.tdc, "_rizin_manager", sessions(big_file=4))
    big = rz.open(rz.write("big.exe", b"MZ bigger than four bytes"), "tab3")["session"]
    rz.wait_done(big)
    before = asked("flj")
    rz.read(f"/api/rizin/{big}/flags")
    rz.read(f"/api/rizin/{big}/flags")
    assert asked("flj") == before + 1
    assert rz.send(f"/api/rizin/{big}/analyze")["analysis"]["state"] == "running"
    rz.wait_done(big)
    rz.read(f"/api/rizin/{big}/flags")
    assert asked("flj") == before + 2, "the flags of a finished analysis step were not asked for"


def test_rizin_flags_load_once_for_requests_at_once(rz, monkeypatch):
    """Review, Minor 6: Tab again and again right after a console command, which drops the copy: the
    requests that come while flj runs wait for that load, so rizin lists the flags once; a request waits
    for it no longer than RIZIN_LOAD_WAIT (as for rizin's pipe) and is busy then, as a view would be."""
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "flj:0.6")
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "afl"})
    before = rz.fake.commands().count("flj")
    answers, took = {}, {}

    def tab(name, session, q):
        started = time.monotonic()
        r = rz.tdc.app.test_client().get(f"/api/rizin/{session}/flags?q={q}")
        answers[name], took[name] = (r.status_code, r.get_json()), time.monotonic() - started

    threads = [threading.Thread(target=tab, args=(name, sid, q))
               for name, q in (("a", "sym.w"), ("b", "sym.w"), ("c", "SYM.MA"), ("d", "entry"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert answers == {"a": (200, {"total": 1, "names": ["sym.watchdog"], "common": "sym.watchdog", "truncated": False}),
                       "b": (200, {"total": 1, "names": ["sym.watchdog"], "common": "sym.watchdog", "truncated": False}),
                       "c": (200, {"total": 1, "names": ["sym.main"], "common": "sym.main", "truncated": False}),
                       "d": (200, {"total": 1, "names": ["entry0"], "common": "entry0", "truncated": False})}
    assert rz.fake.commands().count("flj") == before + 1, "rizin listed the flags once for each request"

    # A load that takes longer than a request waits for it: that request is busy, the load goes on
    monkeypatch.setattr(rz.tdc, "RIZIN_LOAD_WAIT", 0.3)
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "flj:4")
    slow = rz.open(rz.write("slow.exe", b"MZ slow flags"), "tab2")["session"]
    rz.wait_done(slow)
    first = threading.Thread(target=tab, args=("first", slow, "sym"))
    first.start()
    assert wait_for(lambda: "flj" in rz.rizin_runs()[-1], 5)
    tab("second", slow, "sym")
    first.join(15)
    # It gave up after RIZIN_LOAD_WAIT; the load it did not wait for takes 4 s (follow-up finding 3)
    assert answers["second"] == (409, {"busy": True, "step": "view"}) and took["second"] < 2.0, took
    assert answers["first"][0] == 200 and answers["first"][1]["total"] == 4
    assert rz.read(f"/api/rizin/{slow}/flags?q=sym")["total"] == 4
    assert rz.rizin_runs()[-1].count("flj") == 1


def test_rizin_comment_is_read_at_its_address(rz):
    """Review, Minor 1: the right-click menu's Comment… field shows the comment there also when the
    disassembly has not loaded it: GET comment gives the comment at addr as the disassembly shows it
    ('' when there is none)."""
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    assert rz.read(f"/api/rizin/{sid}/comment?addr={MAIN:#x}") == {"offset": MAIN, "comment": ""}
    note = 'a <b>note</b> & "more"'
    rz.send(f"/api/rizin/{sid}/comment", {"addr": MAIN, "text": note})
    assert rz.read(f"/api/rizin/{sid}/comment?addr={MAIN}") == {"offset": MAIN, "comment": note}
    assert "pdj 1 @ 0x1400014b7" in rz.fake.commands()
    assert rz.read(f"/api/rizin/{sid}/comment?addr={WATCHDOG:#x}") == {"offset": WATCHDOG, "comment": ""}
    assert rz.read(f"/api/rizin/{sid}/comment?addr=0x10") == {"offset": 0x10, "comment": ""}, "an unmapped address"


def test_rizin_hex_gives_the_file_offset(rz):
    """HEX's Open in Hex tab needs the file offset of an address: paddr, from the map rizin has there
    (oml.j) when it is a map of the file rizin has open (ol.j); None where no byte of the file is (a
    zero-filled map, no map, past the end of the file). Both commands are fixed, built from the number."""
    sid = rz.open(rz.write("pipesim.exe", bytes(range(256)) * 48))["session"]  # 12 KB
    rz.wait_done(sid)

    def hexed(addr, n=4):
        return rz.read(f"/api/rizin/{sid}/hex?addr={addr:#x}&len={n}")

    assert hexed(0x140000010)["paddr"] == 0x10
    assert hexed(MAIN)["paddr"] == 0x400 + 0x4B7
    assert hexed(0x140005010)["paddr"] == 0x2410
    assert hexed(0x140003010)["paddr"] is None, "a zero-filled map has no byte of the file"
    assert hexed(0x150000000) == {"offset": 0x150000000, "bytes": [0xFF] * 4, "paddr": None}, "no map there"
    assert [c for c in rz.fake.commands() if c.startswith(("ol", "oml"))][:2] == ["ol.j", "oml.j @ 0x140000010"]
    small = rz.open(rz.write("small.exe"), "tab2")["session"]
    rz.wait_done(small)
    assert rz.read(f"/api/rizin/{small}/hex?addr=0x140000002&len=1")["paddr"] == 2
    assert rz.read(f"/api/rizin/{small}/hex?addr=0x140005010&len=1")["paddr"] is None, "past the end of the file"


def test_rizin_linear_disasm_ends_at_a_page_of_invalid_ops(rz):
    """Review, Critical 1: outside functions every full page said more, so the tab could page on forever
    through bytes rizin cannot decode (data, or memory without bytes, which rizin reads as 0xff). A page of
    nothing but invalid instructions is no code: no page follows it."""
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    data = rz.read(f"/api/rizin/{sid}/disasm?addr=0x1400030a0&count=3")
    assert data["function"] is None and [op["type"] for op in data["ops"]] == ["invalid"] * 3
    assert data["more"] is False, "a page of invalid instructions said more"
    after = rz.read(f"/api/rizin/{sid}/disasm?addr=0x140003098&count=3&after=0x14000309f")
    assert [op["offset"] for op in after["ops"]] == [0x1400030A0, 0x1400030A1, 0x1400030A2] and after["more"] is False
    # A page with code in it goes on as before
    assert rz.read(f"/api/rizin/{sid}/disasm?addr=0x140003098&count=3")["more"] is True
    # Each page sets rizin's block for its instructions (16 bytes each at most), else rizin 0.9.1 decodes only
    # its block of 256 bytes: a page of 300 lines (jmp, int3, then bytes that start no instruction) comes whole
    linear = [c for c in rz.fake.commands() if c.startswith("pdj ") and not c.startswith("pdj 1 ")]
    assert linear[:3] == ["pdj 3 @! 48 @ 0x1400030a0", "pdj 4 @! 64 @ 0x14000309f", "pdj 3 @! 48 @ 0x140003098"], linear
    long = rz.read(f"/api/rizin/{sid}/disasm?addr=0x140003098&count=300")
    assert len(long["ops"]) == 300 and long["more"] is True, (len(long["ops"]), long["more"])


def test_rizin_decompile_time_limit_ends_the_session(rz, monkeypatch):
    """The ruling: rz-ghidra may take long under x64 emulation, so pdgj has a limit of its own
    (DECOMPILE_TIMEOUT, 120 s, above a console command's); over it rizin is stopped, the session ends, and
    the answer says why for DECOMPILER to show it. A save waiting for the pipe at close waits longer."""
    import rizin_sessions

    assert rizin_sessions.DECOMPILE_TIMEOUT == 120 and rizin_sessions.DECOMPILE_TIMEOUT > rizin_sessions.CONSOLE_TIMEOUT
    assert rizin_sessions._FLUSH_WAIT > rizin_sessions.DECOMPILE_TIMEOUT
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "pdgj:20")
    monkeypatch.setattr(rizin_sessions, "DECOMPILE_TIMEOUT", 0.5)
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    started = time.monotonic()
    out = rz.get(f"/api/rizin/{sid}/decompile?addr={MAIN:#x}")
    # Stopped at its limit, far below the 20 s the answer would take (follow-up finding 3)
    assert time.monotonic() - started < 10.0, "pdgj did not stop at the decompile limit"
    assert out.status_code == 404 and out.get_json() == {"error": "session ended",
                                                         "reason": "Decompiling took too long, the session ended."}
    assert rz.get(f"/api/rizin/{sid}/status").status_code == 404


def test_scan_history_says_whether_its_file_is_still_there(rz, tdc, monkeypatch):
    """The ThreatScan history offers an entry's file (result.filepath) to the RIZIN tab only while it is
    there: exists, by the rule of the rizin routes (inside the readable folders, a non-empty file). A UNC
    path is refused without resolving it; the entries are otherwise as stored."""
    there = rz.write("there.exe")
    empty = rz.write("empty.exe", b"")
    outside = rz.tmp / "outside.exe"
    outside.write_bytes(SAMPLE)
    entries = [
        {"id": "1", "tool": "capa", "filename": "there.exe", "result": {"filepath": there}},
        {"id": "2", "tool": "EMBER2024", "filename": "gone.exe", "result": {"filepath": str(rz.allowed / "gone.exe")}},
        {"id": "3", "tool": "ThreatCheck", "filename": "outside.exe", "result": {"filepath": str(outside)}},
        {"id": "4", "tool": "DefenderCheck", "filename": "empty.exe", "result": {"filepath": empty}},
        {"id": "5", "tool": "Process Dump", "filename": "PID 4", "result": {}},
        {"id": "6", "tool": "capa", "filename": "unc.exe", "result": {"filepath": "\\\\host\\share\\unc.exe"}},
        {"id": "7", "tool": "capa", "filename": "odd", "result": "not a dict"},
        {"id": "8", "tool": "capa", "filename": "number", "result": {"filepath": 42}},
    ]
    monkeypatch.setattr(tdc, "_load_scan_history", lambda: [dict(e) for e in entries])
    resolved = []
    real = os.path.realpath
    monkeypatch.setattr(os.path, "realpath", lambda p, *a, **k: resolved.append(str(p)) or real(p, *a, **k))
    out = rz.read("/api/scan/history")
    assert out["count"] == 8
    assert [e["exists"] for e in out["history"]] == [True, False, False, False, False, False, False, False]
    assert [{k: v for k, v in e.items() if k != "exists"} for e in out["history"]] == entries
    assert not [p for p in resolved if "host" in p], "a UNC path was resolved"
    assert rz.read("/api/scan/history?limit=1")["history"] == [dict(entries[0], exists=True)]


def test_rizin_big_lists_stay_bounded(rz, monkeypatch):
    """Final review, S6: strings, imports and flags are not copied whole into the web UI. An answer over
    the cap is not read in (a clear error says to filter in the console, and rizin is not asked again for
    it until a console command; the next view answers), and at most RIZIN_ROWS_MAX rows are kept, with
    truncated in the answer. Flags over the cap leave Tab with the function names."""
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_STRINGS", "2000")
    monkeypatch.setenv("FAKE_RIZIN_FLAGS", "2000")
    sid = rz.open(rz.write("big.exe"))["session"]
    rz.wait_done(sid)
    monkeypatch.setattr(rizin_sessions, "VIEW_ANSWER_MAX", 8192)
    for url, word in ((f"/api/rizin/{sid}/strings", "strings"), (f"/api/rizin/{sid}/strings?q=text", "strings")):
        r = rz.get(url)
        assert r.status_code == 500 and r.is_json, url
        assert f"too many {word}" in r.get_json()["error"] and "console" in r.get_json()["error"], r.get_json()
    assert rz.fake.commands().count("izj") == 1, "rizin was asked again for a list that is too large"
    assert len(rz.read(f"/api/rizin/{sid}/functions")) == 3, "the pipe is out of step after a capped answer"
    assert rz.read(f"/api/rizin/{sid}/flags?q=sym") == {"total": 0, "names": [], "common": "", "truncated": True}
    rz.read(f"/api/rizin/{sid}/flags?q=str")
    assert rz.fake.commands().count("flj") == 1

    monkeypatch.setattr(rizin_sessions, "VIEW_ANSWER_MAX", 32 * 1024 * 1024)
    monkeypatch.setattr(rz.tdc, "RIZIN_ROWS_MAX", 1000)
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "afl"})  # the copies go
    page = rz.read(f"/api/rizin/{sid}/strings?limit=5")
    assert page["total"] == 1000 and page["truncated"] is True and len(page["items"]) == 5
    assert page["items"][0] == {"offset": 0x140005000, "string": "watchdog: giving up", "length": 19,
                                "section": ".rdata", "type": "ascii"}
    assert rz.read(f"/api/rizin/{sid}/imports")["truncated"] is False
    flags = rz.read(f"/api/rizin/{sid}/flags?q=str.extra_&limit=3")
    assert flags["truncated"] is True and len(flags["names"]) == 3 and flags["total"] < 2000
    rows = rz.tdc._rizin_cache[rz.mgr.get(sid)]["strings"][1][0]
    assert len(rows) == 1000 and all(isinstance(row, tuple) for row in rows), "the copy keeps whole rows"


def test_rizin_function_list_does_not_depend_on_the_answer_cap(rz, monkeypatch):
    """Follow-up finding 1: the answer cap was made for the lists whose JSON runs to hundreds of MB
    (izj, iij, flj), but it also covered aflj, which carries about 2.7 KB per function (44 MB for a
    16 000-function dump): from about 12 000 functions /functions answered 500 and the tab had no
    function list, and XREFS then named no function. The list comes from afl's text instead (about
    63 B per function), so a small cap does not reach it; the lists it was made for still refuse."""
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_FUNCTIONS", "20000")
    monkeypatch.setenv("FAKE_RIZIN_STRINGS", "2000")
    sid = rz.open(rz.write("dump.bin"))["session"]
    rz.wait_done(sid)
    monkeypatch.setattr(rizin_sessions, "VIEW_ANSWER_MAX", 8192)

    functions = rz.read(f"/api/rizin/{sid}/functions")
    assert len(functions) == 20003, "the function list was cut (or refused) for its size"
    assert functions[:3] == [{"name": "entry0", "offset": ENTRY, "size": 29, "nbbs": 1},
                             {"name": "sym.watchdog", "offset": WATCHDOG, "size": 38, "nbbs": 1},
                             {"name": "sym.main", "offset": MAIN, "size": 1382, "nbbs": 30}]
    assert functions[3] == {"name": "fcn.00000", "offset": 0x140010000, "size": 16, "nbbs": 1}
    assert [f["offset"] for f in functions] == sorted(f["offset"] for f in functions)
    # The names of the functions that references lie in come from the same list
    assert rz.read(f"/api/rizin/{sid}/xrefs?addr={MAIN:#x}")["to"][0]["function"] == "entry0"
    # rizin's own JSON of this list is not asked for at all
    assert "afl" in rz.fake.commands() and not [c for c in rz.fake.commands() if c.startswith("aflj")]
    # The lists the cap was made for still say to filter in the console
    assert rz.get(f"/api/rizin/{sid}/strings").status_code == 500


def test_rizin_function_list_reads_afls_text(rz, monkeypatch):
    """Follow-up finding 1: afl's rows are read defensively (a line that is no row is left out) and at
    most RIZIN_ROWS_MAX of them are kept, as for the other lists; the answer keeps its shape, so the
    rows of a function with gaps (``-> realsz``) and a name with spaces come through as rizin has them."""
    monkeypatch.setenv("FAKE_RIZIN_AFL_NOISE", "1")
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    assert rz.read(f"/api/rizin/{sid}/functions") == [
        {"name": "entry0", "offset": ENTRY, "size": 29, "nbbs": 1},
        {"name": "sym.watchdog", "offset": WATCHDOG, "size": 38, "nbbs": 1},
        {"name": "sym.main", "offset": MAIN, "size": 1382, "nbbs": 30}]

    # rizin 0.9.1's own rows (afl of a sample built with mingw), odd lines and a row cap
    class Pipe:
        def __init__(self, text):
            self.text = lambda cmd, **kw: text

    rows = ("0x140001000    1 1            sym.__mingw_invalidParameterHandler\n"
            "0x140001020   49 1024 -> 980  sym.__tmainCRTStartup\n"
            "0x140001a70    8 114  -> 111  sym.__do_global_ctors\n"
            "0x140001440    1 29           entry0\n"
            "0x140002000    2 32           sym.a name with spaces\n")
    odd = "\nWARN: no row\n0x140003000 x 4 name\nxx 1 4 name\n0x140004000 1\n0x1 1 4\n"
    functions = rz.tdc._rizin_functions(Pipe(rows + odd))
    assert functions == [
        {"name": "sym.__mingw_invalidParameterHandler", "offset": 0x140001000, "size": 1, "nbbs": 1},
        {"name": "sym.__tmainCRTStartup", "offset": 0x140001020, "size": 1024, "nbbs": 49},
        {"name": "entry0", "offset": 0x140001440, "size": 29, "nbbs": 1},
        {"name": "sym.__do_global_ctors", "offset": 0x140001A70, "size": 114, "nbbs": 8},
        {"name": "sym.a name with spaces", "offset": 0x140002000, "size": 32, "nbbs": 2}]
    monkeypatch.setattr(rz.tdc, "RIZIN_ROWS_MAX", 2)
    assert [f["name"] for f in rz.tdc._rizin_functions(Pipe(rows))] == [
        "sym.__mingw_invalidParameterHandler", "sym.__tmainCRTStartup"]


# The separators that str.splitlines() breaks a line at, besides rizin's own "\n" (and "\r\n"); those
# that are no ASCII control character can be set through the console's afn, the others can come from a
# symbol name in the file.
ODD_SEPARATORS = "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
ODD_IN_A_NAME = "\x85\u2028\u2029"


def test_rizin_function_names_keep_rizins_own_line_separator(rz):
    """Review, Important 2: a function name may hold a character that str.splitlines() breaks a line at
    (\\x0b, \\x0c, \\x1c-\\x1e, \\x85, U+2028, U+2029). The console's name check refuses only the ASCII
    control characters, so afn can set such a name (and a symbol in the file can carry any of them), and
    rizin keeps the raw UTF-8 and prints it in afl. Split at those, the row was listed with its name cut
    there and the rest dropped as unparsable, while the tab takes the current function's name from afij,
    whole: the mark in FUNCTIONS, the rename follow-up and the right-click menu then missed that
    function. Only "\\n" ends a row, and a separator at the start of a name belongs to the name.
    """
    import rizin_sessions

    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    for odd in ("sym.a" + ODD_IN_A_NAME + "b", "\x85foo", "\u2028lead"):
        assert rz.send(f"/api/rizin/{sid}/console", {"cmd": f"afn {odd} @ {MAIN:#x}"})["changed"] is True
        assert [f["name"] for f in rz.read(f"/api/rizin/{sid}/functions")] == ["entry0", "sym.watchdog", odd]
        # The name the tab marks the row by (afij, through the disassembly) is the same text
        assert rz.read(f"/api/rizin/{sid}/disasm?addr={MAIN:#x}&count=1")["function"] == odd
        # Review round 3, item 4: and so is the session's own function (afl.), which /status, /seek and
        # /console answer with and the tab's SEEK box, its mark and the rename shortcut go by. Review
        # round 4: a separator at the start of the name belongs to the name too, as the row has it.
        assert rz.status(sid)["function"] == odd
        assert rz.send(f"/api/rizin/{sid}/seek", {"addr": f"{MAIN:#x}"})["function"] == odd
        assert rz.send(f"/api/rizin/{sid}/console", {"cmd": f"pd 1 @ {MAIN:#x}"})["function"] == odd

    # A name starting with a carriage return: rizin lists it, so the session has to name it the same way
    # (the console cannot set one - a command is a single line - but a symbol in the file can carry it)
    class Afl:
        @staticmethod
        def cmd(text, **kwargs):
            return "0x140001440\n" if text == "s" else "0x140001440 \rcr\n"

    session = rz.mgr.get(sid)
    session._where(Afl)
    assert session.function == "\rcr"
    assert session.status()["function"] == "\rcr"

    # A line of afl. that holds no address: refused as "no function", never an IndexError
    class NoAddress:
        @staticmethod
        def cmd(text, **kwargs):
            return "0x140001440\n" if text == "s" else "\x85\n"

    real_pipe = session._pipe
    session._pipe = NoAddress
    try:
        with pytest.raises(rizin_sessions.RizinRefused) as refused:
            session.rename(MAIN, "clean")
    finally:
        session._pipe = real_pipe
    assert "no function" in refused.value.reason

    # A row still ends at "\n" alone, and a "\r\n" line ending leaves no carriage return in the name
    class Pipe:
        def __init__(self, text):
            self.text = lambda cmd, **kw: text

    rows = f"0x140001000    1 1            sym.a{ODD_SEPARATORS}b\r\n0x140001020    1 2            second\n"
    assert rz.tdc._rizin_functions(Pipe(rows)) == [
        {"name": f"sym.a{ODD_SEPARATORS}b", "offset": 0x140001000, "size": 1, "nbbs": 1},
        {"name": "second", "offset": 0x140001020, "size": 2, "nbbs": 1}]
    # Review round 3, item 5: a name whose first character is a carriage return is a name too, while a
    # row whose name is nothing but one (a "\r\n" ending with no name) is no row
    odd_first = f"0x140001040    1 3            \rthird\r\n0x140001060    1 4            \r\n"
    assert rz.tdc._rizin_functions(Pipe(odd_first)) == [
        {"name": "\rthird", "offset": 0x140001040, "size": 3, "nbbs": 1}]


def test_rizin_function_list_stops_reading_at_the_row_cap(rz, monkeypatch):
    """Review, Minor 6: the row cap has to bound the memory the list takes, not only the work after it:
    the rows are read one by one (no list of every line of the answer), so a dump far above the cap
    costs the rows kept, not the whole answer again."""
    import tracemalloc

    class Pipe:
        def __init__(self, text):
            self.text = lambda cmd, **kw: text

    rows = "".join(f"{0x140000000 + i * 16:#011x}    1 16           sym.fcn_{i:06d}\n"
                   for i in range(400000))
    assert len(rows) > 16 * 1024 * 1024
    pipe = Pipe(rows)
    monkeypatch.setattr(rz.tdc, "RIZIN_ROWS_MAX", 1000)
    tracemalloc.start()
    try:
        functions = rz.tdc._rizin_functions(pipe)
        taken = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(functions) == 1000 and functions[0]["name"] == "sym.fcn_000000"
    assert taken < 2 * 1024 * 1024, f"{taken} bytes for 1000 rows of a {len(rows)}-byte answer"


def test_rizin_the_answer_cap_belongs_to_the_lists_it_was_made_for(rz, monkeypatch):
    """Follow-up finding 1: VIEW_ANSWER_MAX is passed by the three list views only (izj, iij, flj).

    Review, Important 1: the commands that answer for one whole function (pdfj, pdgj) carry
    FUNCTION_ANSWER_MAX, not the backstop: their answer is decoded and parsed, which takes several
    times its size, so the backstop's band would let one request take gigabytes. Everything else keeps
    ANSWER_MAX, so a function list, a linear page, a graph or a hexdump is never refused for its size.
    """
    import rizin_sessions

    assert rizin_sessions.ANSWER_MAX >= 8 * rizin_sessions.VIEW_ANSWER_MAX
    assert rizin_sessions.VIEW_ANSWER_MAX < rizin_sessions.FUNCTION_ANSWER_MAX < rizin_sessions.ANSWER_MAX
    seen = []
    real = rizin_sessions.RizinPipe.cmd

    def spy(self, text, timeout=rizin_sessions.VIEW_TIMEOUT, limit=None):
        seen.append((text.split("~")[0].split(" ")[0],
                     rizin_sessions.ANSWER_MAX if limit is None else limit))
        return real(self, text, timeout, limit)

    monkeypatch.setattr(rizin_sessions.RizinPipe, "cmd", spy)
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)
    del seen[:]
    for url in (f"/api/rizin/{sid}/functions", f"/api/rizin/{sid}/disasm?addr={MAIN:#x}",
                f"/api/rizin/{sid}/disasm?addr=0x140003098", f"/api/rizin/{sid}/graph?addr={MAIN:#x}",
                f"/api/rizin/{sid}/decompile?addr={MAIN:#x}", f"/api/rizin/{sid}/hex?addr={MAIN:#x}",
                f"/api/rizin/{sid}/xrefs?addr={MAIN:#x}", f"/api/rizin/{sid}/xrefs?addr=0x140001630",
                f"/api/rizin/{sid}/comment?addr={MAIN:#x}",
                f"/api/rizin/{sid}/strings", f"/api/rizin/{sid}/imports", f"/api/rizin/{sid}/flags?q=sym"):
        rz.read(url)
    rz.send(f"/api/rizin/{sid}/seek", {"addr": "entry0"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "afl"})
    by_limit = {}
    for cmd, limit in seen:
        by_limit.setdefault(limit, set()).add(cmd)
    assert by_limit[rizin_sessions.VIEW_ANSWER_MAX] == {"izj", "iij", "flj"}
    assert by_limit[rizin_sessions.FUNCTION_ANSWER_MAX] == {"pdfj", "pdgj"}
    assert {"afl", "afij", "pdj", "afbj", "pxj", "axtj", "axfj", "afxj", "Lc"} \
        <= by_limit[rizin_sessions.ANSWER_MAX]
    assert set(by_limit) == {rizin_sessions.VIEW_ANSWER_MAX, rizin_sessions.FUNCTION_ANSWER_MAX,
                             rizin_sessions.ANSWER_MAX}
    # A function of that size is refused, with the command and the limit in the error
    monkeypatch.setattr(rizin_sessions, "FUNCTION_ANSWER_MAX", 512)
    for url, command in ((f"/api/rizin/{sid}/disasm?addr={MAIN:#x}", "pdfj"),
                         (f"/api/rizin/{sid}/graph?addr={MAIN:#x}", "pdfj"),
                         (f"/api/rizin/{sid}/decompile?addr={MAIN:#x}", "pdgj")):
        r = rz.get(url)
        assert r.status_code == 500 and r.get_json()["error"] == \
            f"rizin's answer to {command} is larger than 512 bytes", (url, r.get_json())
    assert len(rz.read(f"/api/rizin/{sid}/functions")) == 3, "the pipe is out of step after a capped answer"


def test_rizin_open_and_download_use_the_path_that_was_checked(rz):
    """Final review, S7: the path checked against the readable folders is the resolved one, and that one
    goes to rizin and to the download, so a link swapped in between cannot point them elsewhere."""
    real = rz.write("real.exe")
    link = rz.allowed / "link.exe"
    link.symlink_to(real)
    opened = rz.open(str(link))
    assert opened["file"]["path"] == real
    assert json.loads(rz.rizin_runs()[0][0][len("START "):])[-1] == real
    r = rz.client.get("/api/file/download", query_string={"path": str(link)})
    assert r.status_code == 200 and "real.exe" in r.headers["Content-Disposition"], r.headers


def test_rizin_routes_answer_json_when_a_file_cannot_be_written(rz, sessions, monkeypatch):
    """Final review, S8: an OSError (a full disk) in /analyze, whose pending save comes first, and in /upload
    answers JSON, not Flask's HTML error page."""
    import rizin_sessions

    monkeypatch.setattr(rz.tdc, "_rizin_manager", sessions(big_file=1))
    sid = rz.open(rz.write("pipesim.exe"))["session"]
    rz.wait_done(sid)

    def full(self, wait=None):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(rizin_sessions.RizinSession, "flush", full)
    r = rz.post(f"/api/rizin/{sid}/analyze")
    assert r.status_code == 500 and r.is_json and "No space left on device" in r.get_json()["error"], r.data[:200]
    taken = rz.tmp / "taken"
    taken.write_text("a file where the upload folder goes")
    monkeypatch.setattr(rz.tdc, "RIZIN_UPLOAD_DIR", str(taken))
    r = rz.client.post("/api/rizin/upload", data={"file": (io.BytesIO(b"MZ upload"), "x.exe")},
                       content_type="multipart/form-data")
    assert r.status_code == 500 and r.is_json and r.get_json()["error"].startswith("the upload could not be stored"), \
        r.data[:200]


def _emulation_settings(rz):
    """The settings of the last emulation start: its one ``e key=value ...`` command."""
    line = [c for c in rz.commands() if c.startswith("e ") and "io.cache=" in c][-1]
    return dict(token.split("=", 1) for token in line.split()[1:])


def test_emulation_start_sets_the_guards_and_reports_the_pc(rz):
    import rizin_sessions

    sid = rz.session()
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert state["running"] is True and state["pc"] == "0x140001440"
    assert {r["name"] for r in state["registers"]} >= {"rax", "rip", "rsp"}
    settings = _emulation_settings(rz)
    assert settings["io.cache"] == "true" and float(settings["esil.timeout"]) > 0
    for key in ("esil.breakoninvalid", "esil.exectrap", "esil.iotrap", "esil.nonull"):
        assert settings[key] == "true"
    assert settings["esil.romem"] == "false"
    # The run is bounded by rizin itself, well inside the console's time limit
    assert 0 < float(settings["esil.timeout"]) == rizin_sessions.ESIL_TIMEOUT < rizin_sessions.CONSOLE_TIMEOUT / 4
    # R12: the stack size is the server's, whatever the console set before
    assert int(settings["esil.stack.size"], 0) == rizin_sessions.ESIL_STACK_SIZE <= 16 * 1024 * 1024
    assert set(state) == {"running", "pc", "registers", "changed", "stack", "stopped", "arch", "bits"}
    assert state["arch"] == "x86" and state["bits"] == 64 and state["stopped"] is None and state["changed"] == []
    commands = rz.commands()
    start = max(i for i, c in enumerate(commands) if "io.cache=" in c)
    # "omlj" is the sweep of the ESIL memory a run before may have left mapped (nothing here, so no o-)
    assert commands[start + 1:start + 6] == ["e io.cache", "omlj", "aei", "aeim", "aepc 0x140001440"]


def test_emulation_start_defaults_to_the_current_seek(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/seek", {"addr": "0x1400014b7"})
    assert rz.send(f"/api/rizin/{sid}/emulation/start", {})["pc"] == hex(0x1400014B7)


def test_emulation_state_reads_the_stack_with_hints(rz, monkeypatch):
    import rizin_sessions

    # sym.watchdog; past the end of the image, 0xd50 after the last flag (fd: "...CreateNamedPipeA + 3408");
    # inside entry0 (a return address); the stack pointer's own value, where aei put the flags rsp and rbp;
    # 0x41, past which fd names the register flag at the PC ("rip + ..."); a flag; a byte past it in .rdata;
    # entry0's start, which is also the PC (the flag rip).
    words = [WATCHDOG, 0x14000A100, ENTRY + 9, 0x178000, 0x41, 0x140005014, 0x140005015, ENTRY]
    monkeypatch.setenv("FAKE_RIZIN_STACK", ",".join(hex(w) for w in words))
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    state = rz.read(f"/api/rizin/{sid}/emulation")
    stack = state["stack"]
    assert len(stack) == rizin_sessions.RIZIN_STACK_ROWS
    assert _word(stack[0]["value"]) == 0x140001490 and stack[0]["hint"] == "sym.watchdog"
    assert stack[1]["hint"] is None
    sp = _word(next(r["value"] for r in state["registers"] if r["name"] == "rsp"))
    assert sp == 0x178000
    assert [_word(row["addr"]) for row in stack] == [sp + 8 * i for i in range(rizin_sessions.RIZIN_STACK_ROWS)]
    assert [(_word(row["value"]), row["hint"]) for row in stack[:len(words)]] == [
        (WATCHDOG, "sym.watchdog"), (0x14000A100, None), (ENTRY + 9, "entry0 + 9"), (0x178000, None),
        (0x41, None), (0x140005014, "str.child"), (0x140005015, None), (ENTRY, "entry0")]
    # The fake's fd answers what rizin's does there: the closest flag, however far, a register's too
    assert re.fullmatch(r"r\w+ \+ [0-9]+", rz.send(f"/api/rizin/{sid}/console", {"cmd": "fd @ 0x41"})["output"].strip())
    assert rz.send(f"/api/rizin/{sid}/console", {"cmd": "fd @ 0x178000"})["output"].strip() in ("rsp", "rbp")
    # A word outside every map is not even looked up
    assert not any("0x14000a100" in c or c.endswith("@ 0x41") for c in rz.commands() if c.startswith(("afij", "fd.j")))


def test_emulation_asks_once_for_a_value_that_comes_twice_and_not_for_the_stack_itself(rz, monkeypatch):
    # The state is read after every step: a saved frame pointer (a word inside the stack) is no function
    # or flag, and a return address that fills several rows is one question
    words = [ENTRY + 9, 0x177FF0, ENTRY + 9, 0x178100, ENTRY + 9, WATCHDOG]
    monkeypatch.setenv("FAKE_RIZIN_STACK", ",".join(hex(w) for w in words))
    sid = rz.session()
    mark = len(rz.commands())
    stack = rz.send(f"/api/rizin/{sid}/emulation/start", {})["stack"]
    assert [row["hint"] for row in stack[:6]] == ["entry0 + 9", None, "entry0 + 9", None, "entry0 + 9", "sym.watchdog"]
    asked = [c for c in _commands_since(rz, mark) if c.startswith(("afij @", "fd.j @"))]
    assert asked.count(f"afij @ {ENTRY + 9:#x}") == 1 and not any("0x177ff0" in c or "0x178100" in c for c in asked)


def test_emulation_shows_no_stack_where_the_stack_pointer_is_not_in_it(rz):
    import rizin_sessions

    sid = rz.session()
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert len(state["stack"]) == rizin_sessions.RIZIN_STACK_ROWS
    end = 0x100000 + rizin_sessions.ESIL_STACK_SIZE
    # Near the stack's end: only the words that are in it
    state = rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rsp", "value": hex(end - 16)})
    assert [_word(row["addr"]) for row in state["stack"]] == [end - 16, end - 8]
    # Outside it (rizin would read 0xff there): no stack at all
    state = rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rsp", "value": "0x41"})
    assert state["running"] is True and state["stack"] == []
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rsp", "value": hex(end - 16)})
    # The console unmapped the stack: no stack either, though rsp points where it was
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "aeim-"})
    state = rz.read(f"/api/rizin/{sid}/emulation")
    assert state["running"] is True and state["stack"] == []
    assert not any(c.startswith("pxj") for c in rz.commands()[-6:])


def test_emulation_reads_a_32_bit_stack_in_4_byte_words(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    monkeypatch.setenv("FAKE_RIZIN_STACK", "0x41424344,0x41")
    sid = rz.session()
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x401000"})
    assert state["bits"] == 32 and state["pc"] == "0x401000"
    assert {r["name"] for r in state["registers"]} >= {"eax", "eip", "esp"}
    sp = _word(next(r["value"] for r in state["registers"] if r["name"] == "esp"))
    assert [(_word(row["addr"]), _word(row["value"])) for row in state["stack"][:3]] == [(sp, 0x41424344), (sp + 4, 0x41),
                                                                           (sp + 8, 0)]


def test_emulation_refuses_when_io_cache_did_not_take(rz, monkeypatch):
    # Review Focus 5: without io.cache nothing the run writes is kept, and a decryption
    # would silently do nothing. The start must fail loudly instead.
    monkeypatch.setenv("FAKE_RIZIN_NO_IO_CACHE", "1")
    sid = rz.session()
    r = rz.post(f"/api/rizin/{sid}/emulation/start", {})
    assert r.status_code == 400 and "io.cache" in r.get_json()["refused"]
    assert "aei" not in rz.commands()
    r = rz.get(f"/api/rizin/{sid}/emulation")
    assert r.status_code == 400 and "not started" in r.get_json()["refused"]


def test_emulation_state_is_refused_before_start(rz):
    sid = rz.session()
    r = rz.get(f"/api/rizin/{sid}/emulation")
    assert r.status_code == 400 and "not started" in r.get_json()["refused"]
    r = rz.post(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x1"})
    assert r.status_code == 400 and "not started" in r.get_json()["refused"]


def test_emulation_stop_leaves_the_emulation(rz):
    """R37(a): the ESIL memory is given back by closing the file descriptors of its maps (`o- <fd>`),
    not with rizin's own `aeim-`, which drops the map it made last and can never name the stack again
    once the assistant has mapped a buffer (measured on 0.9.1)."""
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    mark = len(rz.commands())
    assert rz.send(f"/api/rizin/{sid}/emulation/stop") == {"running": False}
    since = _commands_since(rz, mark)
    assert since[0] == "omlj" and [c for c in since if c.startswith("o- ")], since
    assert not any(m["name"].startswith("mem.") for m in rz.mgr.get(sid).json("omlj")), "still mapped"
    r = rz.get(f"/api/rizin/{sid}/emulation")
    assert r.status_code == 400 and "not started" in r.get_json()["refused"]
    assert rz.send(f"/api/rizin/{sid}/emulation/stop") == {"running": False}  # stopping twice is no error
    # A new start begins afresh: nothing counts as changed against the run before
    assert rz.send(f"/api/rizin/{sid}/emulation/start", {})["changed"] == []


def test_a_register_can_be_set_and_only_a_known_one(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    state = rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x41"})
    assert _word(next(r["value"] for r in state["registers"] if r["name"] == "rax")) == 0x41
    assert any(c.startswith("ar rax=0x41") for c in rz.commands())
    assert state["changed"] == ["rax"]
    for name in ("rax; wci", "nope", "rax rbx", "", None, 7):
        r = rz.post(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": "0x1"})
        assert r.status_code == 400 and "register" in r.get_json()["refused"], name
    assert not any(c.startswith(("ar rax;", "ar nope", "ar rax rbx", "ar =")) for c in rz.commands())
    r = rz.post(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "-1"})
    assert r.status_code == 400 and "value" in r.get_json()["refused"]


def test_a_machine_word_crosses_the_wire_as_a_hex_string(rz, monkeypatch):
    """R52: the browser reads a JSON number as a double, which cannot hold a 64-bit register (measured:
    0x7ff7a1b2c3d4e5f6 arrived as 0x7ff7a1b2c3d4e400, and a register is editable there). In the emulation's
    state every word -- the PC, the registers, the stack's addresses and values -- is an exact "0x…" string;
    stack_fix is a count of bytes and stays a number, and a breakpoint's address stays a number too."""
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = rz.session()
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {})
    big, odd = "0x7ff7a1b2c3d4e5f6", "0x20000000000001"        # above 2^53: a double cannot hold either
    for name, value in (("rax", big), ("rbx", odd)):
        state = rz.send(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": value})
    values = {r["name"]: r["value"] for r in state["registers"]}
    assert values["rax"] == big and values["rbx"] == odd, "a word lost digits on the way"
    assert isinstance(state["pc"], str) and re.fullmatch(r"0x[0-9a-f]+", state["pc"]), state["pc"]
    assert all(isinstance(r["value"], str) and re.fullmatch(r"0x[0-9a-f]+", r["value"]) for r in state["registers"])
    assert state["stack"], "the stack words are part of the answer"
    for row in state["stack"]:
        assert re.fullmatch(r"0x[0-9a-f]+", row["addr"]) and re.fullmatch(r"0x[0-9a-f]+", row["value"]), row
    assert all(isinstance(name, str) for name in state["changed"])
    # The assistant's offered value is a word as well, its stack correction is a count
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": "0x8000"})
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": hex(ASSIST_AT)})
    assist = _assist(rz, sid, ASSIST_AT)
    assert re.fullmatch(r"0x[0-9a-f]+", assist["value"]) and isinstance(assist["stack_fix"], int), assist
    # The breakpoints keep their numbers: they are bounded by the file's own layout
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    assert [b["addr"] for b in rz.read(f"/api/rizin/{sid}/breakpoints")] == [0x140001450]
    # The words go in as the strings they came out as, so that an edit writes what was read
    again = rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": big})
    assert {r["name"]: r["value"] for r in again["registers"]}["rax"] == big


def _run(rz, sid, kind, **body):
    """POST emulation/run: the state it answers."""
    return rz.send(f"/api/rizin/{sid}/emulation/run", dict(body, kind=kind))


def _commands_since(rz, mark):
    return rz.commands()[mark:]


def _started(rz, addr=None):
    """A session with the emulation started (at addr, default the entry point): its ID."""
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {} if addr is None else {"addr": addr})
    return sid


def test_each_run_kind_sends_its_command(rz):
    sid = _started(rz)
    for kind, command in (("step", "aes"), ("over", "aeso"), ("skip", "aess")):
        mark = len(rz.commands())
        rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": kind})
        assert command in _commands_since(rz, mark), kind
    mark = len(rz.commands())
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "until", "addr": "0x140001450"})
    assert "aesu 0x140001450" in _commands_since(rz, mark)
    mark = len(rz.commands())
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "cont"})
    assert "aec" in _commands_since(rz, mark)
    # to_call: one step, then aesu to the call (rizin's aecc runs past a call through the import table)
    sid = _started(rz, "0x140001490")
    mark = len(rz.commands())
    rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "to_call"})
    since = _commands_since(rz, mark)
    assert "aes" in since and any(c.startswith("aesu 0x") for c in since) and "aecc" not in since


def test_a_run_moves_the_pc_through_the_code_and_says_why_it_stopped(rz):
    sid = _started(rz)
    state = _run(rz, sid, "step")
    assert state["pc"] == hex(0x140001444) and state["stopped"] == "step"
    assert "rip" in state["changed"] and set(state) >= {"running", "pc", "registers", "stack", "stopped"}
    # at the call to sym.main: skip passes it
    state = _run(rz, sid, "skip")
    assert state["pc"] == hex(0x140001449) and state["stopped"] == "step"
    # a state read afterwards does not claim a stop
    assert rz.read(f"/api/rizin/{sid}/emulation")["stopped"] is None


def test_until_runs_to_the_address_and_is_refused_without_one(rz):
    sid = _started(rz)
    state = _run(rz, sid, "until", addr="0x140001444")
    assert state["pc"] == hex(0x140001444) and state["stopped"] == "step"
    assert "aesu 0x140001444" in rz.commands()
    mark = len(rz.commands())
    for body in ({"kind": "until"}, {"kind": "until", "addr": "-1"}, {"kind": "until", "addr": "main; wci"}):
        r = rz.post(f"/api/rizin/{sid}/emulation/run", body)
        assert r.status_code == 400 and "addr" in r.get_json()["refused"], body
    assert not any(c.startswith("aesu") for c in _commands_since(rz, mark))


def test_cont_on_a_breakpoint_runs_on_to_the_next_one(rz):
    # rizin 0.9.1's aec runs the instruction at the PC before it looks at breakpoints, so it does not hit the
    # one it stands on again (checked with real rizin, test_real_rizin_runs_an_emulation): no step off it
    # is needed. Breakpoints are set through the console: db takes its address after "@".
    sid = _started(rz, "0x140001440")
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "db @ 0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "db @ 0x1400014b7"})
    mark = len(rz.commands())
    state = _run(rz, sid, "cont")
    assert state["pc"] == hex(0x1400014B7) and state["stopped"] == "breakpoint"
    assert "aes" not in _commands_since(rz, mark) and "aec" in _commands_since(rz, mark)
    # and on from there, past the one it stands on, into code that ends where nothing can execute
    state = _run(rz, sid, "cont")
    assert state["pc"] != 0x1400014B7 and state["stopped"] == "trap"


def test_cont_that_runs_away_stops_with_timeout_and_keeps_the_session(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    sid = _started(rz)
    state = _run(rz, sid, "cont")
    assert state["stopped"] == "timeout" and state["pc"] == "0x140001440"
    assert rz.status(sid)["analysis"]["state"] in ("done", "stopped")
    assert rz.send(f"/api/rizin/{sid}/emulation/stop") == {"running": False}


def test_run_refuses_an_unknown_kind(rz):
    sid = _started(rz)
    mark = len(rz.commands())
    # "back": rizin 0.9.1's aesb restores no memory and the step after it runs without moving the PC
    for kind in ("ood", "", None, 7, "aes; wci", "STEP", "aecc", "back"):
        r = rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": kind})
        assert r.status_code == 400 and "kind" in r.get_json()["refused"], kind
    assert not any(c.split(" ")[0] in ("aes", "aec", "aesu", "aesb", "aets+", "wci") for c in _commands_since(rz, mark))


def test_run_is_refused_before_the_emulation_starts(rz):
    sid = rz.session()
    r = rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    assert r.status_code == 400 and "not started" in r.get_json()["refused"]
    assert not any(c.split(" ")[0] == "aes" for c in rz.commands())


def test_a_step_into_nothing_is_named_not_shown_as_a_result(rz):
    # A step INTO a call through the import table leaves the PC where nothing is mapped. rizin 0.9.1 says
    # nothing about that step, and says "Trap" only at the next one.
    sid = _started(rz, "0x140001499")
    state = _run(rz, sid, "step")
    assert state["pc"] == hex(0) and state["stopped"] == "trap"
    state = _run(rz, sid, "step")
    assert state["pc"] == hex(0) and state["stopped"] == "trap"


def test_skip_passes_a_call_through_the_import_table_too(rz):
    # rizin 0.9.1's aess skips a direct call but runs call qword [import] (type ircall): the PC would be in
    # nothing. The server sets the PC after the call itself.
    sid = _started(rz, "0x140001499")
    mark = len(rz.commands())
    state = _run(rz, sid, "skip")
    assert state["pc"] == hex(0x14000149F) and state["stopped"] == "step"
    since = _commands_since(rz, mark)
    assert "aepc 0x14000149f" in since and "aess" not in since
    # the stack was not touched: nothing was called
    assert _word(next(r["value"] for r in state["registers"] if r["name"] == "rsp")) == 0x178000


def test_over_runs_a_call_through_the_import_table_to_its_return_address(rz):
    # rizin 0.9.1's aeso steps over a direct call only; for the others the server runs to the next address
    sid = _started(rz, "0x140001499")
    mark = len(rz.commands())
    state = _run(rz, sid, "over")
    since = _commands_since(rz, mark)
    assert "aesu 0x14000149f" in since and "aeso" not in since
    # the fake's callee is nothing: the call ends where nothing can execute, and says so
    assert state["pc"] == hex(0) and state["stopped"] == "trap"


def test_to_call_stops_before_the_next_call_of_any_kind(rz):
    sid = _started(rz, "0x140001490")  # sub rsp; mov ecx; call qword [Sleep]
    mark = len(rz.commands())
    state = _run(rz, sid, "to_call")
    assert state["pc"] == hex(0x140001499) and state["stopped"] == "step"
    since = _commands_since(rz, mark)
    assert "aesu 0x140001499" in since and "aecc" not in since
    # standing before a call, it runs that call, as rizin's aecc does: the next one is the one after it
    state = _run(rz, sid, "to_call")
    assert state["pc"] == hex(0) and state["stopped"] == "trap"


def test_to_call_stands_still_when_one_step_reaches_a_call(rz):
    sid = _started(rz, "0x140001440")  # sub rsp; call sym.main
    mark = len(rz.commands())
    state = _run(rz, sid, "to_call")
    assert state["pc"] == hex(0x140001444) and state["stopped"] == "step"
    assert not any(c.startswith("aesu") for c in _commands_since(rz, mark))


def test_to_call_takes_the_jumps_on_the_way(rz):
    # cmp; jle (falls through in the fake); then a block of nops and the call qword [CreateNamedPipeA]
    sid = _started(rz, "0x1400014c5")
    state = _run(rz, sid, "to_call")
    assert state["pc"] == hex(0x1400015B9) and state["stopped"] == "step"
    assert rz.commands().count("aes") >= 2  # the first step and the jle


def test_to_call_stops_at_a_breakpoint_on_the_way(rz):
    sid = _started(rz, "0x140001490")
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "db @ 0x140001499"})
    state = _run(rz, sid, "to_call")
    assert state["pc"] == hex(0x140001499) and state["stopped"] == "breakpoint"


def test_to_call_that_runs_into_the_timeout_says_so(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    sid = _started(rz, "0x140001490")
    state = _run(rz, sid, "to_call")
    assert state["stopped"] == "timeout" and state["pc"] == "0x140001494"


def test_a_run_sets_the_guards_again_and_checks_what_the_console_may_have_changed(rz):
    import rizin_sessions

    sid = _started(rz)
    # esil.timeout=0 would turn the bounded run into an endless one
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "e esil.timeout=0"})
    mark = len(rz.commands())
    _run(rz, sid, "step")
    since = _commands_since(rz, mark)
    settings = next(c for c in since if c.startswith("e ") and "io.cache=" in c)
    assert f"esil.timeout={rizin_sessions.ESIL_TIMEOUT:g}" in settings.split()
    assert since.index(settings) < since.index("aes")
    # set after aei, esil.exectrap takes effect (rizin 0.9.1 ignores it at the start), and esil.verbose
    # makes an invalid read or write say so
    assert "esil.exectrap=true" in settings.split() and "esil.verbose=1" in settings.split()
    # io.cache switched off in the console is switched on again by that
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "e io.cache=false"})
    assert _run(rz, sid, "step")["stopped"] == "step"


def test_a_run_is_refused_when_io_cache_does_not_hold(rz, monkeypatch):
    # The start switched io.cache on; the console switches it off, and rizin does not take it on again
    monkeypatch.setenv("FAKE_RIZIN_IO_CACHE_ONCE", "1")
    sid = _started(rz)
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "e io.cache=false"})
    mark = len(rz.commands())
    r = rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    assert r.status_code == 400 and "io.cache" in r.get_json()["refused"]
    assert not any(c.split(" ")[0] in ("aes", "aec") for c in _commands_since(rz, mark))


def test_a_run_is_refused_when_the_console_unmapped_the_stack(rz):
    sid = _started(rz)
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "aeim-"})
    mark = len(rz.commands())
    r = rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
    assert r.status_code == 400 and "stack" in r.get_json()["refused"]
    assert not any(c.split(" ")[0] in ("aes", "aec") for c in _commands_since(rz, mark))


def test_every_run_command_is_given_more_time_than_esil_timeout_but_less_than_the_console(rz, monkeypatch):
    import rizin_sessions

    seen = []
    real = rizin_sessions.RizinPipe.console

    def console(self, text, timeout=rizin_sessions.CONSOLE_TIMEOUT, limit=rizin_sessions.CONSOLE_LIMIT, tail=False):
        seen.append((text, timeout))
        return real(self, text, timeout, limit, tail)

    monkeypatch.setattr(rizin_sessions.RizinPipe, "console", console)
    sid = _started(rz, "0x140001490")
    for kind in ("to_call", "step", "over", "cont"):
        _run(rz, sid, kind)
    commands = {text.split(" ")[0] for text, _ in seen if text.startswith("ae")}
    assert {"aes", "aesu", "aec"} <= commands
    for text, timeout in seen:
        if text.startswith("ae"):
            assert rizin_sessions.ESIL_TIMEOUT < timeout < rizin_sessions.CONSOLE_TIMEOUT, text


def test_a_run_drops_the_cached_lists(rz):
    sid = rz.session()
    rz.read(f"/api/rizin/{sid}/strings")
    before = rz.commands().count("izj")
    rz.read(f"/api/rizin/{sid}/strings")
    assert rz.commands().count("izj") == before, "the strings should have been cached"
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    _run(rz, sid, "step")
    rz.read(f"/api/rizin/{sid}/strings")
    assert rz.commands().count("izj") == before + 1, "a run changes bytes, so the strings are read again"


def test_a_flood_on_stderr_does_not_bury_the_reason(rz, monkeypatch):
    # esil.verbose=1 makes every int3 print a line (148 000 in a second from a loop around one), and the
    # timeout line comes last: the reason is read from the end of stderr
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    monkeypatch.setenv("FAKE_RIZIN_ESIL_FLOOD", "20000")  # 440 KB: past the 64 KB cut and the pipe's 256 KB buffer
    sid = _started(rz)
    assert _run(rz, sid, "cont")["stopped"] == "timeout"
    assert _run(rz, sid, "until", addr="0x140001444")["stopped"] == "timeout"
    sid = _started(rz, "0x140001490")
    assert _run(rz, sid, "to_call")["stopped"] == "timeout"


def test_console_keeps_the_head_of_stderr_and_its_last_whole_lines_on_demand(fake, sample, monkeypatch):
    """The reason a run stopped is the last line of a flood of warnings, so a run reads stderr from its end;
    every other command keeps the head, where its own error is. A tail is cut back to whole lines: the slice
    starts anywhere, and the pipe's buffer (256 KB) has dropped the start of the flood on top of that, so
    without the trim the kept text begins in the middle of a warning, which matches nothing."""
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    monkeypatch.setenv("FAKE_RIZIN_ESIL_FLOOD", "20000")  # 440 KB, past the 64 KB cut and the 256 KB buffer
    pipe = rizin_sessions.RizinPipe(fake.path, sample())
    try:
        pipe.cmd("aei")
        _, head, _ = pipe.console("aec")
        assert len(head) == 64 * 1024 and "timeout exceeded" not in head
        _, tail, _ = pipe.console("aec", tail=True)
        assert 63 * 1024 < len(tail) <= 64 * 1024
        assert tail.rstrip().endswith("WARNING: core: esil: timeout exceeded.")
        assert set(tail.splitlines()) == {"WARNING: $ returned 0",
                                          "WARNING: core: esil: timeout exceeded."}
        assert pipe.console("echo quiet")[1] == "", "a command that writes nothing keeps nothing"
    finally:
        pipe.close()


def test_a_missing_stack_pointer_is_refused_not_a_server_error(rz, monkeypatch):
    # `ar SP` answers nothing: stack_map used to compare None with the map and raise TypeError (500)
    monkeypatch.setenv("FAKE_RIZIN_NO_SP", "1")
    sid = rz.session()
    r = rz.post(f"/api/rizin/{sid}/emulation/start", {})
    assert r.status_code == 400 and "stack" in r.get_json()["refused"]


def test_breakpoints_are_set_listed_and_cleared(rz):
    sid = rz.session()
    # POST and DELETE answer the list under "breakpoints"; GET answers it bare
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"}) == {
        "breakpoints": [{"addr": 0x140001450, "enabled": True}]}
    # the lower address second: rizin lists them in the order they were set (measured), the server sorts
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": 0x140001440}) == {
        "breakpoints": [{"addr": 0x140001440, "enabled": True}, {"addr": 0x140001450, "enabled": True}]}
    assert [b["addr"] for b in json.loads(
        rz.send(f"/api/rizin/{sid}/console", {"cmd": "dblj"})["output"])] == [0x140001450, 0x140001440]
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [
        {"addr": 0x140001440, "enabled": True}, {"addr": 0x140001450, "enabled": True}]
    assert any(c.startswith("db @ 0x140001440") for c in rz.commands())
    assert rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"}) == {
        "breakpoints": [{"addr": 0x140001450, "enabled": True}]}
    assert [b["addr"] for b in rz.read(f"/api/rizin/{sid}/breakpoints")] == [0x140001450]
    assert "db- @ 0x140001440" in rz.commands()
    rz.remove(f"/api/rizin/{sid}/breakpoints", {})
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == []
    assert "db-*" in rz.commands()


def test_breakpoints_work_before_emulation_starts(rz):
    # They are rizin's own, so they can be placed and then run into: no start is needed to set one.
    sid = rz.session()
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})["breakpoints"]
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x140001440, "enabled": True}]
    assert "aei" not in rz.commands()


def test_a_breakpoint_set_before_the_start_stops_the_run(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x1400014B7, "enabled": True}]
    state = _run(rz, sid, "cont")
    assert state["pc"] == hex(0x1400014B7) and state["stopped"] == "breakpoint"


def test_setting_a_breakpoint_twice_leaves_the_one(rz):
    # rizin says "Breakpoint already set at this address." and keeps the one it has: the end state is
    # what was asked for, so the request is not refused.
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"}) == {
        "breakpoints": [{"addr": 0x140001440, "enabled": True}]}
    # and clearing one that is not there is no error either
    assert rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"}) == {
        "breakpoints": [{"addr": 0x140001440, "enabled": True}]}


def test_a_breakpoint_rizin_did_not_set_is_refused_not_reported_as_set(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_BP_IGNORED", "1")
    sid = rz.session()
    r = rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    assert r.status_code == 400 and "0x140001440" in r.get_json()["refused"]
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == []


def test_the_api_offers_no_disabled_breakpoint(rz):
    # rizin 0.9.1 stops a run at a breakpoint whose enabled is false all the same (dbd changes nothing
    # that matters), so asking for one is refused rather than answered with an enabled breakpoint.
    sid = rz.session()
    mark = len(rz.commands())
    for body in ({"addr": "0x140001440", "on": False}, {"addr": "0x140001440", "on": True}):
        r = rz.post(f"/api/rizin/{sid}/breakpoints", body)
        assert r.status_code == 400 and "on" in r.get_json()["refused"], body
    assert not any(c.startswith(("db ", "dbd", "dbe")) for c in _commands_since(rz, mark))
    # what the console disabled is still reported as rizin reports it
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "dbd @ 0x140001440"})
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x140001440, "enabled": False}]
    # and so is a POST on that address: rizin keeps the breakpoint it has, so the answer says disabled
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"}) == {
        "breakpoints": [{"addr": 0x140001440, "enabled": False}]}
    assert [c for c in rz.commands() if c.startswith(("dbd", "dbe"))] == ["dbd @ 0x140001440"]


def test_a_breakpoint_address_that_is_no_address_is_refused(rz):
    sid = rz.session()
    mark = len(rz.commands())
    bad = ("-1", "0x140001440; wci", "main", True, 2 ** 64, 1.5)
    for addr in bad + (None,):  # POST without an addr is a POST without an address
        r = rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": addr})
        assert r.status_code == 400 and "addr" in r.get_json()["refused"], addr
    for addr in bad:  # a DELETE without an addr means all of them, so None is left out here
        r = rz.delete(f"/api/rizin/{sid}/breakpoints", {"addr": addr})
        assert (r.status_code, "addr" in r.get_json()["refused"]) == (400, True), addr
    for body in (None, [], "db"):
        assert rz.post(f"/api/rizin/{sid}/breakpoints", body).status_code == 400, body
    for body in ([], "db"):  # a DELETE of a null body is one without a body: that means all of them
        assert rz.delete(f"/api/rizin/{sid}/breakpoints", body).status_code == 400, body
    assert not any(c.startswith(("db ", "db-")) for c in _commands_since(rz, mark))
    # A DELETE without a body at all clears them all, as one with an empty object does.
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"})
    assert rz.ok(rz.client.delete(f"/api/rizin/{sid}/breakpoints")) == {"breakpoints": []}


def test_breakpoints_say_the_session_ended_rather_than_fail(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/close", {})
    for response in (rz.get(f"/api/rizin/{sid}/breakpoints"),
                     rz.post(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001440"}),
                     rz.delete(f"/api/rizin/{sid}/breakpoints", {})):
        assert response.status_code == 404 and response.get_json()["error"] == "session ended"


# --- Patching (webui/rizin_sessions.py's patch, patch_op, patches, unpatch) --

# The fake's check outside every function, with the x86 encodings the four buttons work on:
# cmp eax, 1 / jz (short) / jnz (near) / call sym.watchdog.
CHECK_CMP, CHECK_JZ, CHECK_JNZ, CHECK_CALL = 0x140003080, 0x140003083, 0x140003085, 0x14000308B


def _patch(rz, sid, **body):
    return rz.send(f"/api/rizin/{sid}/patch", body)


def _patches(rz, sid):
    return rz.read(f"/api/rizin/{sid}/patches")["patches"]


def _waiting(rz, sid):
    return rz.read(f"/api/rizin/{sid}/patches")["waiting"]


def test_patch_writes_through_the_cache_and_lists_before_and_after(rz):
    sid = rz.session()
    before = rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=2")["bytes"]
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "9090"})
    assert any(c.startswith("wx 9090 @ 0x140001440") for c in rz.commands())
    rows = _patches(rz, sid)
    # one row per write operation, not per byte (measured: wx 9090 gives {"size": 2, "after": "9090"})
    assert rows == [{"addr": 0x140001440, "size": 2, "before": bytes(before).hex(),
                     "after": "9090", "mine": True, "over_run": False}]
    assert all(r["mine"] is True for r in rows)
    # and the bytes rizin shows are the patched ones: HEX and DISASSEMBLY read through the cache
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=2")["bytes"] == [0x90, 0x90]


def test_a_run_s_bytes_are_in_the_list_but_not_mine(rz):
    sid = rz.session()
    # at 0x140001444 stands `call sym.main`: the step pushes its return address, which rizin's one
    # write cache holds just like a patch (measured: one row of size 8 at rsp-8)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    _run(rz, sid, "step")
    rows = {r["addr"]: r["mine"] for r in _patches(rz, sid)}
    assert rows[0x140001440] is True
    assert any(mine is False for mine in rows.values())
    assert len(rows) == 2


def test_unpatch_takes_one_back_and_all_back(rz):
    sid = rz.session()
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001450", "bytes": "90"})
    rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001440"})
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001450]
    # the range, not the address: rizin's `wc- <addr>` drops a whole block of the cache (measured)
    assert "wc- 0x140001440 0x140001441" in rz.commands()
    rz.delete(f"/api/rizin/{sid}/patch", {})
    assert _patches(rz, sid) == []
    assert "wc-*" in rz.commands()
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=1")["bytes"] != [0x90]


def test_unpatch_names_the_run_rows_it_took_with_the_patch(rz):
    """R72. `wc- <addr> <addr+1>` removes every write that overlaps the address, so a ✕ on a patch set
    over bytes a run wrote drops the run's whole row -- up to a copied stage. The answer has to name
    them: "Took the patch at X back" alone would be the pane claiming less than happened."""
    sid = rz.session()
    # the "run" writes four bytes (a console wx is the same row to rizin), then a patch over the second.
    # The start is what switches io.cache on, without which rizin loses a write and says so on stderr only.
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41424344 @ 0x140001440"})
    _patch(rz, sid, addr="0x140001441", bytes="90")
    rows = _patches(rz, sid)
    assert [(r["addr"], r["mine"], r["over_run"]) for r in rows] == [
        (0x140001440, False, False), (0x140001441, True, True)]

    answer = rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001441"}).get_json()
    assert answer == {"patches": [], "run_removed": [{"addr": 0x140001440, "size": 4}]}
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=4")["bytes"] != [0x41, 0x42, 0x43, 0x44], \
        "the run's bytes really went: that is what the answer names"

    # a patch with nothing of the run's under it names nothing
    _patch(rz, sid, addr="0x140001450", bytes="90")
    assert rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001450"}).get_json() == {
        "patches": [], "run_removed": []}

    # wc-* names them too, but it is the button that asks first, and they come lowest address first
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 4142 @ 0x140001460"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 43 @ 0x140001455"})
    _patch(rz, sid, addr="0x140001470", bytes="90")
    assert rz.delete(f"/api/rizin/{sid}/patch", {}).get_json() == {
        "patches": [], "run_removed": [{"addr": 0x140001455, "size": 1}, {"addr": 0x140001460, "size": 2}]}


def test_patch_refuses_what_is_not_bytes(rz):
    sid = rz.session()
    mark = len(rz.commands())
    for body in ({"addr": "0x140001440", "bytes": "9"}, {"addr": "0x140001440", "bytes": "zz"},
                 {"addr": "0x140001440", "bytes": "90" * 4097}, {"addr": "0x140001440"},
                 {"addr": "0x140001440", "bytes": "9090", "kind": "nop"},
                 {"addr": "0x140001440", "bytes": 144}, {"bytes": "90"},
                 {"addr": "main", "bytes": "90"}, {"addr": -1, "bytes": "90"}):
        response = rz.post(f"/api/rizin/{sid}/patch", body)
        answer = response.get_json()
        assert response.status_code == 400 and "refused" in answer, body
    for body in (None, [], "wx 90"):
        assert rz.post(f"/api/rizin/{sid}/patch", body).status_code == 400, body
    for body in ([], "wx 90"):  # a DELETE of a null body is one without a body: that means all of them
        assert rz.delete(f"/api/rizin/{sid}/patch", body).status_code == 400, body
    assert not any(c.startswith(("wx", "wc-")) for c in _commands_since(rz, mark))
    assert _patches(rz, sid) == []


def test_patching_works_without_a_running_emulation(rz):
    """An analyst neutralises a check before ever stepping: the patch switches io.cache on itself,
    because without it rizin loses the write ("Could not write hexpair" on stderr, which cmd never reads)."""
    sid = rz.session()
    mark = len(rz.commands())
    _patch(rz, sid, addr=CHECK_CALL, bytes="90" * 5)
    sent = _commands_since(rz, mark)
    cache = [i for i, c in enumerate(sent) if "io.cache=true" in c]
    write = [i for i, c in enumerate(sent) if c.startswith("wx ")]
    assert cache and write and cache[0] < write[0], sent
    assert not any(c.startswith(("aei", "aeim", "aepc")) for c in sent), "no emulation was started"
    assert [r["after"] for r in _patches(rz, sid)] == ["9090909090"]


def test_a_patch_is_refused_when_io_cache_did_not_take(rz, monkeypatch):
    # Without io.cache the write is lost and px keeps showing the original: refused, not answered as done.
    monkeypatch.setenv("FAKE_RIZIN_NO_IO_CACHE", "1")
    sid = rz.session()
    mark = len(rz.commands())
    response = rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    assert response.status_code == 400 and "io.cache" in response.get_json()["refused"]
    assert not any(c.startswith("wx") for c in _commands_since(rz, mark))
    assert rz.get(f"/api/rizin/{sid}/patches").get_json() == {"patches": [], "waiting": [], "restore": {"actions": 0, "reason": None, "digests": 0, "refused": _NO_RECORD}}


def test_the_patch_buttons_write_the_bytes_of_the_instruction(rz):
    """The four kinds over the instruction pdj reports there; every encoding checked with rz-asm."""
    sid = rz.session()
    for addr, kind, written in ((CHECK_CMP, "nop", "909090"),
                                (CHECK_JZ, "flip", "750b"),
                                (CHECK_JZ, "always", "eb0b"),
                                (CHECK_JNZ, "flip", "0f840c000000"),
                                # e9 is a byte shorter, so the displacement goes up by one and a nop fills
                                (CHECK_JNZ, "always", "e90d00000090"),
                                (CHECK_CALL, "nocall", "9090909090")):
        mark = len(rz.commands())
        answer = _patch(rz, sid, addr=f"{addr:#x}", kind=kind)
        sent = _commands_since(rz, mark)
        assert f"pdj 1 @ {addr:#x}" in sent, (kind, sent)
        assert f"wx {written} @ {addr:#x}" in sent, (kind, sent)
        assert answer["patches"][-1]["after"] == written
        rz.delete(f"/api/rizin/{sid}/patch", {})
    assert not any(c.startswith(("wa", "wci", "wc+")) for c in rz.commands()), "no assembling, no commit"


def test_a_patch_kind_that_does_not_apply_is_refused(rz):
    sid = rz.session()
    mark = len(rz.commands())
    for addr, kind in ((CHECK_CALL, "flip"), (CHECK_CALL, "always"), (CHECK_CMP, "nocall"),
                       (CHECK_JZ, "zap"), (0x140003091, "nop")):  # 0x140003091: no instruction there
        response = rz.post(f"/api/rizin/{sid}/patch", {"addr": f"{addr:#x}", "kind": kind})
        assert response.status_code == 400 and "refused" in response.get_json(), (addr, kind)
    assert not any(c.startswith("wx") for c in _commands_since(rz, mark))


def test_what_this_session_wrote_stays_its_own(rz):
    """`mine` decides what is kept, re-analysed and exported, so it survives a neighbour being taken
    back and a second write to the same address, claims no foreign write inside a patch of its own, and
    leaves this session claiming nothing after `wc-*`."""
    sid = rz.session()
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    _patch(rz, sid, addr="0x140001450", bytes="41")
    rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001450"})
    assert [(r["addr"], r["mine"]) for r in _patches(rz, sid)] == [(0x140001440, True)]

    # a write by somebody else *inside* the patched range is its own row, and not this session's
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41 @ 0x140001441"})
    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid)] == [
        (0x140001440, "9090", True), (0x140001441, "41", False)]

    # one of the same length at an address this session then patches as well: the row made before it
    # stays foreign, the session's own is the one claimed
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41 @ 0x140001460"})
    _patch(rz, sid, addr="0x140001460", bytes="90")
    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid)][-2:] == [
        (0x140001460, "41", False), (0x140001460, "90", True)]
    rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001460"})

    # and the address that was taken back is not claimed any more: what writes there next is not ours
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 42 @ 0x140001450"})
    assert [(r["addr"], r["mine"]) for r in _patches(rz, sid)] == [
        (0x140001440, True), (0x140001441, False), (0x140001450, False)]

    # taking back one byte of a write takes the whole write: rizin drops every row that overlaps the
    # range, so the two-byte patch goes with the foreign byte inside it
    rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001441"})
    assert [(r["addr"], r["mine"]) for r in _patches(rz, sid)] == [(0x140001450, False)]
    rz.delete(f"/api/rizin/{sid}/patch", {})

    # a second write at the same address: rizin stacks the operations and both are this session's
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    _patch(rz, sid, addr="0x140001440", bytes="cccc")
    rows = _patches(rz, sid)
    assert [(r["addr"], r["before"], r["after"], r["mine"]) for r in rows] == [
        (0x140001440, rows[0]["before"], "9090", True), (0x140001440, "9090", "cccc", True)]

    # a foreign write of *the same bytes* at an address this session has taken back: the mirror keeps
    # only what the cache still holds, so the entry that was dropped cannot claim this row
    _patch(rz, sid, addr="0x140001470", bytes="41")
    rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140001470"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41 @ 0x140001470"})
    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid)][-1:] == [
        (0x140001470, "41", False)]

    # after wc-* nothing is claimed any more: what a run writes then is the run's
    rz.delete(f"/api/rizin/{sid}/patch", {})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    _run(rz, sid, "step")
    assert [r["mine"] for r in _patches(rz, sid)] == [False]


def test_a_patch_drops_the_views_rizin_built_from_the_bytes(rz):
    sid = rz.session()

    def asked(cmd):
        return rz.commands().count(cmd)

    rz.read(f"/api/rizin/{sid}/flags?q=sym")
    rz.read(f"/api/rizin/{sid}/strings")
    flags, strings = asked("flj"), asked("izj")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    rz.read(f"/api/rizin/{sid}/flags?q=sym")
    rz.read(f"/api/rizin/{sid}/strings")
    assert (asked("flj"), asked("izj")) == (flags + 1, strings + 1)
    rz.delete(f"/api/rizin/{sid}/patch", {})
    rz.read(f"/api/rizin/{sid}/flags?q=sym")
    assert asked("flj") == flags + 2


def test_a_patch_rizin_did_not_write_is_refused_not_reported_as_written(rz):
    # The highest address of all is the one write rizin refuses (measured: rz_core_write_at asserts
    # addr != UT64_MAX and says "Could not write hexpair" on stderr, which cmd does not read), so the
    # answer comes from reading the cache back, not from the command having been sent.
    sid = rz.session()
    response = rz.post(f"/api/rizin/{sid}/patch", {"addr": "0xffffffffffffffff", "bytes": "9090"})
    assert response.status_code == 400 and "0xffffffffffffffff" in response.get_json()["refused"]
    assert _patches(rz, sid) == []


def test_patches_say_the_session_ended_rather_than_fail(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/close", {})
    for response in (rz.get(f"/api/rizin/{sid}/patches"),
                     rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"}),
                     rz.delete(f"/api/rizin/{sid}/patch", {})):
        assert response.status_code == 404 and response.get_json()["error"] == "session ended"


# --- Re-analysing the range a run decrypted ---------------------------------
# The fake's decryption stub outside every function: eight unrolled `xor byte [DECRYPTED + i], 0x41`
# stores and a ret. The bytes there are zero, so a run `until` the ret leaves eight 0x41 ('A') -- a
# function's worth of bytes and a string where neither was before.
DECRYPT_AT, DECRYPT_END, DECRYPTED = 0x140002800, 0x140002838, 0x140002000
DECRYPTED_END = DECRYPTED + 7


def _reanalyze(rz, sid, **body):
    return rz.send(f"/api/rizin/{sid}/reanalyze", body)


def _decrypted(rz):
    """A session that has run the fake's decryption stub: its ID. The cache then holds the eight bytes
    the run wrote at DECRYPTED, as a real decryption loop leaves its range in rizin's write cache."""
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    return sid


def test_reanalyze_runs_af_and_a_string_search_over_the_range(rz):
    sid = _decrypted(rz)
    mark = len(rz.commands())
    found = _reanalyze(rz, sid)
    assert found["functions"] >= 0 and found["strings"] >= 0
    sent = _commands_since(rz, mark)
    assert any(c.startswith("af @ ") for c in sent)
    assert any(c.startswith("/zj") for c in sent)
    # a request without a body at all is one without a range, as for DELETE /patch and /breakpoints
    assert rz.ok(rz.client.post(f"/api/rizin/{sid}/reanalyze"))["start"] == DECRYPTED
    # the range is the run's own, and the search found the string the run wrote where there was none
    assert found == {"start": DECRYPTED, "end": DECRYPTED_END, "functions": 0, "strings": 1}
    import rizin_sessions

    assert f"af @ {DECRYPTED:#x} @e:analysis.limits=true,analysis.from={DECRYPTED:#x}," \
        f"analysis.to={DECRYPTED_END + 1 + rizin_sessions.REANALYZE_SLACK:#x}" in sent, sent
    assert f"/zj [[:print:]]{{4,}} r ascii @e:search.in=range,search.from={DECRYPTED:#x}," \
        f"search.to={DECRYPTED_END + 1:#x}" in sent, sent
    # a whole-program analysis is not what this does, and the sample is never written
    assert not any(c.split(" ", 1)[0].startswith("aa") for c in sent), sent
    assert not any(c.startswith(("wx", "wa", "wci", "wc+", "af-*")) for c in sent), sent


def test_reanalyze_refuses_when_the_run_wrote_nothing(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    mark = len(rz.commands())
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    answer = response.get_json()
    assert response.status_code == 400 and "nothing" in answer["refused"]
    assert not any(c.startswith(("af ", "af-", "/zj")) for c in _commands_since(rz, mark))


def test_reanalyze_lets_the_lists_see_the_new_names(rz, monkeypatch):
    # A function rizin only knows once something has analysed the bytes there, which is what a
    # decryption leaves behind. The server drops its copies, so FUNCTIONS loads again.
    monkeypatch.setenv("FAKE_RIZIN_EXTRA_FUNCTION", f"{DECRYPTED:#x}:fcn.decrypted")
    sid = rz.session()
    before = rz.read(f"/api/rizin/{sid}/functions")
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    # read after the run, so that what the list shows afterwards can only come of the re-analysis
    assert rz.read(f"/api/rizin/{sid}/flags?q=hit")["names"] == []
    found = _reanalyze(rz, sid)
    after = rz.read(f"/api/rizin/{sid}/functions")
    assert len(after) == len(before) + 1
    assert found["functions"] == 1
    assert [f["name"] for f in after if f["offset"] == DECRYPTED] == ["fcn.decrypted"]
    # and the string the run wrote is a flag of its own, so FLAGS and the console's Tab show it -- the
    # list was read before the re-analysis, so this only holds because the copy of it was dropped
    names = rz.read(f"/api/rizin/{sid}/flags?q=hit")["names"]
    assert names == ["hit.string.ascii.0"], names


FAR_FUNCTION = 0x140003500   # past the range and past REANALYZE_SLACK


def test_reanalyze_stays_inside_the_range(rz, monkeypatch):
    """rizin's af follows the calls out of the range -- measured on 0.9.1, with analysis.calls false as
    well: it made a function at the target of a call in freshly decrypted bytes, and 32 of them down a
    chain. analysis.limits is what holds it to the range, and the answer counts only what begins in the
    range, never what af made in the slack past it."""
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_EXTRA_FUNCTION",
                       f"{DECRYPTED:#x}:fcn.decrypted,{FAR_FUNCTION:#x}:fcn.far")
    sid = _decrypted(rz)
    assert FAR_FUNCTION > DECRYPTED_END + rizin_sessions.REANALYZE_SLACK
    assert _reanalyze(rz, sid)["functions"] == 1
    assert [f["offset"] for f in rz.read(f"/api/rizin/{sid}/functions")
            if f["offset"] >= DECRYPTED] == [DECRYPTED]
    # and it is the limits that held the other one back, not the analysis missing it
    assert _reanalyze(rz, sid, start=f"{DECRYPTED:#x}", end=f"{FAR_FUNCTION:#x}")["functions"] == 2
    assert [f["offset"] for f in rz.read(f"/api/rizin/{sid}/functions")
            if f["offset"] >= DECRYPTED] == [DECRYPTED, FAR_FUNCTION]


def test_the_range_is_the_runs_own_writes_not_the_stack_or_a_patch(rz):
    """What the run decrypted, told apart from the words it pushed, from a patch of this session's and
    from a write far away: neither may stretch the range (an enormous span would be analysed and
    searched byte for byte)."""
    sid = rz.session()
    # a step on `call sym.main` pushes its return address: the emulation's stack is in the same cache
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    _run(rz, sid, "step")
    _patch(rz, sid, addr="0x140002100", bytes="90" * 16)          # more bytes than the run wrote
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41 @ 0x140005000"})   # and one far away
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    assert len([r for r in _patches(rz, sid) if not r["mine"]]) == 10, "a stack row, a far one, eight stores"
    found = _reanalyze(rz, sid)
    assert (found["start"], found["end"]) == (DECRYPTED, DECRYPTED_END)


def test_reanalyze_builds_the_function_the_overwritten_bytes_left_behind(rz, monkeypatch):
    """rizin's af leaves a function that is already there alone -- measured on 0.9.1: a 1-byte function
    at an address with 7 decrypted bytes under it stayed 1 byte, and became 7 only after an af- there.
    So the functions of the range go first and are then built from the bytes again."""
    monkeypatch.setenv("FAKE_RIZIN_EXTRA_FUNCTION", f"{DECRYPTED:#x}:fcn.decrypted")
    sid = _decrypted(rz)
    assert _reanalyze(rz, sid)["functions"] == 1, "the bytes the run wrote now carry a function"

    # again, over the very bytes the run overwrote: the function that is there goes first, and the
    # answer is still one -- without the af- a second re-analysis would find nothing at all
    mark = len(rz.commands())
    assert _reanalyze(rz, sid)["functions"] == 1
    sent = _commands_since(rz, mark)
    assert f"af- @ {DECRYPTED:#x}" in sent, sent
    assert sent.index(f"af- @ {DECRYPTED:#x}") < next(i for i, c in enumerate(sent)
                                                      if c.startswith("af @ ")), sent
    assert [f["name"] for f in rz.read(f"/api/rizin/{sid}/functions") if f["offset"] == DECRYPTED] == \
        ["fcn.decrypted"]

    # and a function of the file, in a range given by hand, goes the same way
    assert _reanalyze(rz, sid, start=f"{WATCHDOG:#x}", end=f"{WATCHDOG + 37:#x}")["functions"] == 1
    assert f"af- @ {WATCHDOG:#x}" in rz.commands()
    assert [f["name"] for f in rz.read(f"/api/rizin/{sid}/functions") if f["offset"] == WATCHDOG] == \
        ["sym.watchdog"]


def test_reanalyze_is_refused_when_io_cache_does_not_hold(rz, monkeypatch):
    """Without io.cache rizin reads the file again while wcj still lists the run's rows (measured), so
    the range would be right and the bytes analysed would not be the ones the run wrote."""
    monkeypatch.setenv("FAKE_RIZIN_IO_CACHE_ONCE", "1")
    sid = _decrypted(rz)
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "e io.cache=false"})
    mark = len(rz.commands())
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert response.status_code == 400 and "io.cache" in response.get_json()["refused"]
    assert not any(c.startswith(("af ", "af-", "/zj")) for c in _commands_since(rz, mark))


def test_what_the_reanalysis_found_does_not_go_into_the_project(rz, monkeypatch):
    """rizin's own Ps keeps the function and the flags a range re-analysis made (measured), and the next
    session would list a function over bytes that are not in the file. The save drops what rests on
    bytes only the run wrote -- and keeps what rests on bytes a patch of this session brings back."""
    monkeypatch.setenv("FAKE_RIZIN_EXTRA_FUNCTION", f"{DECRYPTED:#x}:fcn.decrypted")
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    assert _reanalyze(rz, sid) == {"start": DECRYPTED, "end": DECRYPTED_END,
                                   "functions": 1, "strings": 1}
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": f"{MAIN:#x}"})  # what makes a project be written
    rz.close(sid)
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    functions = _project_namespace(saved, "/core/analysis/functions")
    assert hex(DECRYPTED) not in functions, sorted(functions)
    assert hex(MAIN).lower() in functions, "the file's own functions stay"
    assert "hit.string.ascii.0" not in _project_namespace(saved, "/core/flags/flags")
    assert "sym.main" in _project_namespace(saved, "/core/flags/flags"), "the file's own flags stay"

    # the same again with a patch of this session over the function's first byte: those bytes come
    # back when the file is opened again, so what rests on them may stay
    sid = rz.open(path, tab="tab2")["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    _reanalyze(rz, sid)
    _patch(rz, sid, addr=f"{DECRYPTED:#x}", bytes="41")
    rz.close(sid)
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    assert hex(DECRYPTED) in _project_namespace(saved, "/core/analysis/functions")
    assert f"patches={DECRYPTED:x}:41" in saved


def test_reanalyze_refuses_a_range_that_is_no_range(rz, monkeypatch):
    import rizin_sessions

    sid = _decrypted(rz)
    mark = len(rz.commands())
    too_wide = rizin_sessions.MAX_REANALYZE_BYTES + 1
    for body in ({"start": f"{DECRYPTED:#x}"}, {"end": f"{DECRYPTED:#x}"},
                 {"start": "0x20", "end": "0x10"}, {"start": "main", "end": "0x10"},
                 {"start": -1, "end": 0x10}, {"start": 0, "end": 2 ** 64 - 1},
                 {"start": DECRYPTED, "end": DECRYPTED + too_wide - 1}):
        response = rz.post(f"/api/rizin/{sid}/reanalyze", body)
        assert response.status_code == 400 and "refused" in response.get_json(), body
    for body in ([], "af", 7):
        assert rz.post(f"/api/rizin/{sid}/reanalyze", body).status_code == 400, body
    assert not any(c.startswith(("af ", "af-", "/zj")) for c in _commands_since(rz, mark))
    # the widest range it does take is analysed
    assert _reanalyze(rz, sid, start=f"{DECRYPTED:#x}",
                      end=f"{DECRYPTED + too_wide - 2:#x}")["start"] == DECRYPTED
    # and the cap holds for the range the run wrote as well, which the request does not choose
    monkeypatch.setattr(rizin_sessions, "MAX_REANALYZE_BYTES", 4)
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert response.status_code == 400 and "4 bytes" in response.get_json()["refused"]


def test_reanalyze_refuses_a_range_of_more_functions_than_it_rebuilds(rz, monkeypatch):
    """Every function of the range costs an af- and an af, so a range that holds a dump's thousands is
    refused rather than run as thousands of commands under the pipe's lock."""
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_FUNCTIONS", str(rizin_sessions.MAX_REANALYZE_FUNCTIONS + 1))
    sid = rz.session()
    many = 0x140010000 + rizin_sessions.MAX_REANALYZE_FUNCTIONS * 0x20
    mark = len(rz.commands())
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {"start": "0x140010000", "end": f"{many:#x}"})
    assert response.status_code == 400 and "functions" in response.get_json()["refused"]
    assert not any(c.startswith(("af ", "af-", "/zj")) for c in _commands_since(rz, mark))
    # one function fewer is analysed
    assert _reanalyze(rz, sid, start="0x140010000", end=f"{many - 0x20:#x}")["start"] == 0x140010000


def test_the_range_the_run_wrote_is_still_known_after_a_stop(rz):
    """Finding 1 of fix round 1: a stop gives the emulation's memory back while the write cache keeps
    its rows, so the live map list alone cannot tell afterwards that a pushed word was no code -- and
    `af`/`/zj` would then run over the stack. Both sources are needed: the live maps and the record."""
    sid = rz.session()
    # a step on `call sym.main` pushes the return address: that write is a row of the cache
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    _run(rz, sid, "step")
    pushed = [r for r in _patches(rz, sid) if not r["mine"]]
    assert pushed and all(r["addr"] >= 0x100000 for r in pushed), pushed
    assert rz.mgr.get(sid).run_range() is None, "while it is mapped"
    assert rz.send(f"/api/rizin/{sid}/emulation/stop") == {"running": False}
    assert not [m for m in rz.mgr.get(sid).json("omlj") if m["name"].startswith("mem.")]
    assert [r for r in _patches(rz, sid) if not r["mine"]] == pushed, "the rows outlive the maps"
    assert rz.mgr.get(sid).run_range() is None, "and the pushed word is still no code"
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert response.status_code == 400 and "nothing" in response.get_json()["refused"], \
        response.get_json()
    # the same for a buffer the assistant mapped: it is recorded when it is mapped, and a stop and
    # even a new start cannot make its bytes look like the file's
    assert rz.mgr.get(sid).run_range() is None
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    assert rz.mgr.get(sid).run_range() == (DECRYPTED, DECRYPTED_END), "what the run really decrypted"


def test_a_console_mapped_region_stays_out_of_the_range_after_a_stop(rz):
    """Fix round 3: the console may map memory of its own (`aeim <addr> <size> <name>` passes the
    filter), and the sweep closes it like the rest -- so the sweep records what it is about to close,
    or a write into that region would become "the range the run wrote" once the map is gone."""
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "aeim 0x60000000 0x1000 mine"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 4142434445464748 @ 0x60000000"})
    assert [(r["addr"], r["mine"]) for r in _patches(rz, sid)] == [(0x60000000, False)]
    assert rz.mgr.get(sid).run_range() is None, "while the console's region is mapped"
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    assert rz.mgr.get(sid).run_range() is None, "and after the stop closed it"
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert response.status_code == 400 and "nothing" in response.get_json()["refused"]


def test_reanalyze_says_the_session_ended_rather_than_fail(rz):
    sid = _decrypted(rz)
    rz.send(f"/api/rizin/{sid}/close", {})
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert response.status_code == 404 and response.get_json()["error"] == "session ended"


# --- The API-call assistant (webui/rizin_sessions.py) ------------------------

# The fake's calls into imports. SLEEP_CALL and PIPE_CALL are in the model itself, the five of
# ASSIST_AT behind FAKE_RIZIN_ASSIST, and the five of ASSIST32_AT in its 32-bit mode (fake_rizin.py).
SLEEP_CALL = 0x140001499        # call qword [sym.imp.KERNEL32.dll_Sleep]: in the table, returns nothing
PIPE_CALL = 0x1400015B9         # call qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]: not in the table
# VirtualAlloc, memcpy, GetTickCount, IsDebuggerPresent, GetProcAddress, QueryPerformanceCounter,
# GetComputerNameW -- one call per answer the table can give, six bytes apart
ASSIST_AT = 0x140002900
# Sleep, VirtualAlloc, CreateNamedPipeA, LoadLibraryA, VirtualProtect, GetVolumeInformationA
ASSIST32_AT = 0x401000
COPY_FROM, COPY_TO = 0x140000020, 0x140002200


def _word(text):
    """A machine word of the emulation routes as a number: they send "0x…" strings, because a JSON number
    cannot hold a 64-bit register in the browser (R52)."""
    assert isinstance(text, str) and re.fullmatch(r"0x[0-9a-f]+", text), text
    return int(text, 16)


def _assist(rz, sid, addr):
    """GET the assistant's answer for the call at addr."""
    return rz.read(f"/api/rizin/{sid}/call?addr={addr:#x}")


def _skip(rz, sid, addr, **body):
    """POST the skip: the state it answers."""
    return rz.send(f"/api/rizin/{sid}/call", dict(body, addr=f"{addr:#x}"))


def _register(rz, sid, name):
    return _word(next(r["value"] for r in rz.read(f"/api/rizin/{sid}/emulation")["registers"]
                      if r["name"] == name))


def test_the_assistant_names_the_api_behind_a_call(rz):
    sid = _started(rz, f"{SLEEP_CALL:#x}")
    assist = _assist(rz, sid, SLEEP_CALL)
    assert set(assist) == {"supported", "reason", "api", "ret_reg", "value", "stack_fix", "summary"}
    assert assist["supported"] is True and assist["reason"] is None
    assert assist["api"] == "Sleep" and assist["ret_reg"] == "rax"
    # Sleep returns nothing, and under win64 the caller clears the stack: nothing is applied but the PC
    assert assist["value"] is None and assist["stack_fix"] == 0
    assert "Sleep" in assist["summary"], assist["summary"]
    # and the skip passes the call through the import table, as a SKIP run does
    state = _skip(rz, sid, SLEEP_CALL)
    assert state["pc"] == hex(SLEEP_CALL + 6) and state["stopped"] == "step"
    assert f"aepc {SLEEP_CALL + 6:#x}" in rz.commands(), "the PC is set, because aess runs an ircall"
    assert _register(rz, sid, "rsp") == 0x178000, "nothing was called, so nothing was pushed"


def test_an_unknown_import_is_named_but_offers_no_value(rz):
    sid = rz.session()
    assist = _assist(rz, sid, PIPE_CALL)   # a call to an import not in the table
    assert assist["supported"] is True and assist["api"] and assist["value"] is None
    assert assist["api"] == "sym.imp.KERNEL32.dll_CreateNamedPipeA"
    assert assist["ret_reg"] == "rax" and assist["stack_fix"] == 0
    assert "does not know" in assist["summary"], assist["summary"]


def test_an_unknown_import_at_32_bits_says_the_stack_is_not_corrected(rz, monkeypatch):
    """R31: the table does not know the import, so its argument count is unknown and nothing is
    corrected -- said in words, because at 32-bit stdcall a missing correction leaves the stack too
    deep. The field is there to be filled in by hand."""
    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = _started(rz, f"{ASSIST32_AT + 12:#x}")        # call dword [sym.imp...CreateNamedPipeA]
    assist = _assist(rz, sid, ASSIST32_AT + 12)
    assert assist["supported"] is True and assist["api"].endswith("CreateNamedPipeA")
    assert assist["value"] is None and assist["stack_fix"] == 0 and assist["ret_reg"] == "eax"
    assert "argument count" in assist["summary"] and "not corrected" in assist["summary"], assist["summary"]


def test_skip_a_32bit_stdcall_call_corrects_the_stack(rz, monkeypatch):
    """Review Focus 1: a stdcall callee clears its arguments, a skipped call clears nothing, so SKIP
    adds them to the stack pointer itself -- else every later step computes on a stack that is too
    deep while the surface shows one that looks fine."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = _started(rz, f"{ASSIST32_AT:#x}")             # call dword [sym.imp.KERNEL32.dll_Sleep]
    before = _register(rz, sid, "esp")
    assist = _assist(rz, sid, ASSIST32_AT)
    assert assist["supported"] and assist["ret_reg"] == "eax" and assist["stack_fix"] > 0
    assert assist["api"] == "Sleep" and assist["stack_fix"] == 4, "Sleep takes one argument"
    state = _skip(rz, sid, ASSIST32_AT, value="0x1", stack_fix=assist["stack_fix"])
    assert state["pc"] == hex(ASSIST32_AT + 6) and state["stopped"] == "step"
    assert _register(rz, sid, "esp") == before + assist["stack_fix"]
    assert _register(rz, sid, "eax") == 1
    assert f"ar SP={before + assist['stack_fix']:#x}" in rz.commands()
    # a cdecl import is the other way round: there the caller clears, so nothing may be added
    assert rizin_emulation.stack_fix(
        rizin_emulation.convention("x86", 32, rizin_emulation.lookup_api("memcpy")), 3) == 0


def test_skip_at_32_bits_reads_the_arguments_from_the_stack(rz, monkeypatch):
    """R35: the PC stands **on** the call, so the return address is not pushed yet and argument i is at
    [esp + 4*i], not [esp + 4*(i+1)] -- measured with rizin 0.9.1. One word off and the buffer size
    comes from the wrong slot while the answer looks confident."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    # VirtualAlloc(lpAddress, dwSize, ...): the size is the second argument
    monkeypatch.setenv("FAKE_RIZIN_STACK", "0,0x3000,0x1000,0x40")
    sid = _started(rz, f"{ASSIST32_AT + 6:#x}")
    assist = _assist(rz, sid, ASSIST32_AT + 6)
    assert assist["api"] == "VirtualAlloc" and assist["stack_fix"] == 16
    assert _word(assist["value"]) == rizin_emulation.ASSIST_ADDR
    assert "12288 bytes" in assist["summary"], assist["summary"]
    state = _skip(rz, sid, ASSIST32_AT + 6, value=assist["value"], stack_fix=assist["stack_fix"])
    assert f"aeim {_word(assist['value']):#x} 0x3000 assist" in rz.commands()
    assert hex(_register(rz, sid, "eax")) == assist["value"]
    assert state["stack"], "the stack pointer is still in the emulation's stack"


def test_the_assistant_switches_itself_off_on_another_arch(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ARCH", "arm")
    sid = _started(rz, f"{SLEEP_CALL:#x}")
    assist = _assist(rz, sid, SLEEP_CALL)
    assert assist["supported"] is False and "arm" in assist["reason"]
    assert assist["value"] is None and assist["stack_fix"] == 0
    assert assist["api"] is None and assist["ret_reg"] is None
    # emulation, breakpoints and patching go on working there
    assert _run(rz, sid, "step")["running"] is True
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": f"{MAIN:#x}"})["breakpoints"]
    assert _patch(rz, sid, addr=f"{MAIN:#x}", bytes="90")["patches"]
    # and a skip there is refused rather than guessing a register
    response = rz.post(f"/api/rizin/{sid}/call", {"addr": f"{SLEEP_CALL:#x}"})
    assert response.status_code == 400 and "arm" in response.get_json()["refused"]


def test_the_assistant_refuses_where_there_is_no_call(rz):
    sid = _started(rz)
    mark = len(rz.commands())
    for addr in (0x140001441, ENTRY, 0x140009000):   # inside an instruction, a sub, not an instruction
        response = rz.get(f"/api/rizin/{sid}/call?addr={addr:#x}")
        answer = response.get_json()
        assert response.status_code == 400 and "call" in answer["refused"], (addr, answer)
        response = rz.post(f"/api/rizin/{sid}/call", {"addr": f"{addr:#x}"})
        assert response.status_code == 400 and "call" in response.get_json()["refused"], addr
    assert not any(c.startswith(("aess", "aepc", "ar rax=", "aeim ")) for c in _commands_since(rz, mark))


def test_the_assistant_answers_before_the_emulation_starts(rz, monkeypatch):
    """R34: the call can be read without a run -- pdj and the flag are enough to name the API. What only
    the VM has (a buffer size, the tick counter, memcpy's arguments) is None, and the summary says why."""
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = rz.session()
    assist = _assist(rz, sid, ASSIST_AT)
    assert assist["supported"] is True and assist["api"] == "VirtualAlloc"
    assert assist["value"] is None and "not started" in assist["summary"], assist["summary"]
    # a value that needs no VM is offered all the same
    assert _assist(rz, sid, ASSIST_AT + 18)["value"] == "0x0", "IsDebuggerPresent: not observed"
    # the skip does need one
    response = rz.post(f"/api/rizin/{sid}/call", {"addr": f"{ASSIST_AT:#x}"})
    assert response.status_code == 400 and "not started" in response.get_json()["refused"]


def test_the_assistant_offers_a_buffer_and_skip_maps_it(rz, monkeypatch):
    """The core of the unpacking goal: VirtualAlloc answers with memory that is really there, so the
    code after it can write into it."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT:#x}")
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": "0x8000"})  # dwSize
    assist = _assist(rz, sid, ASSIST_AT)
    assert assist["api"] == "VirtualAlloc" and assist["ret_reg"] == "rax"
    assert _word(assist["value"]) == rizin_emulation.ASSIST_ADDR and assist["stack_fix"] == 0
    assert "32768 bytes" in assist["summary"], assist["summary"]
    state = _skip(rz, sid, ASSIST_AT, value=assist["value"])
    assert state["pc"] == hex(ASSIST_AT + 6) and state["stopped"] == "step"
    assert next(r["value"] for r in state["registers"] if r["name"] == "rax") == assist["value"]
    assert f"aeim {_word(assist['value']):#x} 0x8000 assist" in rz.commands()
    # R73: aeim makes an rw- map, and esil.exectrap (set after aei, as every run does) then traps at the
    # first instruction inside it -- so the server makes the map executable, by its address, because
    # `omf <flags>` without a map id takes the map at the current offset (all measured)
    assert f"omf rwx @ {_word(assist['value']):#x}" in rz.commands()
    assert rz.commands().index(f"aeim {_word(assist['value']):#x} 0x8000 assist") \
        < rz.commands().index(f"omf rwx @ {_word(assist['value']):#x}"), "the omf must follow the aeim"
    buffer = next(m for m in rz.mgr.get(sid).json("omlj") if m["from"] == _word(assist["value"]))
    assert buffer["perm"] == "rwx", buffer
    assert "buffer" in state["summary"], state["summary"]
    # rizin's aeim moves the PC and the stack and base pointer into the map it just made (measured),
    # so the three are put back: the stack is still the stack and the PC is after the call
    assert state["stack"] and _word(next(r["value"] for r in state["registers"] if r["name"] == "rsp")) == 0x178000
    maps = [m["name"] for m in rz.mgr.get(sid).json("omlj")]
    assert "mem.assist" in maps and "mem.0x100000_0xf0000" in maps, maps
    # the buffer is memory the run can write and read, which is what an unpacker does with it
    _patch(rz, sid, addr=assist["value"], bytes="4142")
    assert rz.read(f"/api/rizin/{sid}/hex?addr={assist['value']}&len=2")["bytes"] == [0x41, 0x42]
    # a second allocation in the same run is not handed the same memory: the PC goes back to the call
    # (no restart -- a start gives the ESIL memory back, the buffer included)
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": hex(ASSIST_AT)})
    second = _assist(rz, sid, ASSIST_AT)
    assert _word(second["value"]) == rizin_emulation.ASSIST_ADDR + rizin_emulation.ASSIST_STEP
    assert _skip(rz, sid, ASSIST_AT, value=second["value"])["pc"] == hex(ASSIST_AT + 6)
    maps = [m["name"] for m in rz.mgr.get(sid).json("omlj")]
    assert maps.count("mem.assist") == 2, maps
    # and the code in such a buffer really runs: the PC into it, one step, no trap (R73). The control is a
    # region only `aeim` made, which is rw-: there the same step traps and the PC does not move.
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": second["value"]})
    ran = _run(rz, sid, "step")
    assert ran["stopped"] == "step" and _word(ran["pc"]) == _word(second["value"]) + 1, ran["stopped"]
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "aeim 0x70000000 0x1000 control"})
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": "0x70000000"})
    trapped = _run(rz, sid, "step")
    assert trapped["stopped"] == "trap" and _word(trapped["pc"]) == 0x70000000, trapped["stopped"]


def test_a_buffer_is_not_offered_where_the_size_cannot_be_read(rz, monkeypatch):
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT:#x}")
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": "0x0"})
    assist = _assist(rz, sid, ASSIST_AT)
    assert assist["value"] is None and "size" in assist["summary"], assist["summary"]
    # and a size above the maximum is refused rather than mapped: gigabytes on the VM's 8 GB
    rz.send(f"/api/rizin/{sid}/emulation/register",
            {"name": "rdx", "value": hex(rizin_emulation.ASSIST_BUFFER_MAX + 1)})
    assert _assist(rz, sid, ASSIST_AT)["value"] is None
    # nothing is mapped when the skip comes without a value either
    mark = len(rz.commands())
    _skip(rz, sid, ASSIST_AT)
    assert not any(c.startswith("aeim ") for c in _commands_since(rz, mark))


def test_skip_really_copies_what_memcpy_would_copy(rz, monkeypatch):
    """Spec §4: a copying API copies in the ESIL memory map for real, so that unpacked data comes of
    it -- a memcpy-driven unpacker is the second shape after an xor loop. The bytes it writes are the
    run's, not a patch of this session's."""
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 6:#x}")
    for name, value in (("rcx", hex(COPY_TO)), ("rdx", hex(COPY_FROM)), ("r8", "0x8")):
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": value})
    assist = _assist(rz, sid, ASSIST_AT + 6)
    assert assist["api"] == "memcpy" and assist["value"] == hex(COPY_TO), "memcpy returns its destination"
    assert "8 bytes" in assist["summary"], assist["summary"]
    source = rz.read(f"/api/rizin/{sid}/hex?addr={COPY_FROM:#x}&len=8")["bytes"]
    assert rz.read(f"/api/rizin/{sid}/hex?addr={COPY_TO:#x}&len=8")["bytes"] != source
    state = _skip(rz, sid, ASSIST_AT + 6, value=hex(COPY_TO))
    assert rz.read(f"/api/rizin/{sid}/hex?addr={COPY_TO:#x}&len=8")["bytes"] == source
    assert "copied" in state["summary"], state["summary"]
    # it belongs to the run, not to the file: it must not go into the project
    assert [r["mine"] for r in _patches(rz, sid) if r["addr"] == COPY_TO] == [False]


def test_a_copy_that_is_too_large_or_unmapped_copies_nothing(rz, monkeypatch):
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 6:#x}")
    for name, value in (("rcx", hex(COPY_TO)), ("rdx", hex(COPY_FROM)),
                        ("r8", hex(rizin_emulation.ASSIST_COPY_MAX + 1))):
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": value})
    assert "not copied" in _assist(rz, sid, ASSIST_AT + 6)["summary"]
    mark = len(rz.commands())
    assert "not copied" in _skip(rz, sid, ASSIST_AT + 6, value=hex(COPY_TO))["summary"]
    assert not any(c.startswith("wx ") for c in _commands_since(rz, mark))
    # and where the source is in no map there is nothing to read: rizin answers 0xff, which is no data
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST_AT + 6:#x}"})
    for name, value in (("rdx", "0x41"), ("r8", "0x8")):
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": value})
    mark = len(rz.commands())
    assert "not copied" in _skip(rz, sid, ASSIST_AT + 6, value=hex(COPY_TO))["summary"]
    assert not any(c.startswith("wx ") for c in _commands_since(rz, mark))


def test_the_clock_rises_with_every_applied_skip_and_not_with_a_look(rz, monkeypatch):
    """The table answers like a clean, unobserved machine -- that is the anti-VM bypass, and it needs
    no patch. R38: asking what the clock would answer must not move it, because the run line asks on
    every step; applying a skip must, or a timing check sees no time pass."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 12:#x}")
    first = _assist(rz, sid, ASSIST_AT + 12)
    assert first["api"] == "GetTickCount" and _word(first["value"]) > rizin_emulation.TICK_START
    assert _assist(rz, sid, ASSIST_AT + 12)["value"] == first["value"], "a look does not move the clock"
    assert "rises with every skip" in first["summary"], first["summary"]
    assert _skip(rz, sid, ASSIST_AT + 12, value=first["value"])["pc"] == hex(ASSIST_AT + 18)
    assert hex(_register(rz, sid, "rax")) == first["value"]
    # and now it has moved on, by the one step of a scheduler tick
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": hex(ASSIST_AT + 12)})
    assert _assist(rz, sid, ASSIST_AT + 12)["value"] == hex(_word(first["value"]) + rizin_emulation.TICK_STEP)
    # IsDebuggerPresent: not observed
    assert _assist(rz, sid, ASSIST_AT + 18)["value"] == "0x0"


def test_get_proc_address_answers_what_the_file_imports(rz, monkeypatch):
    """Spec §4: the address of the import where the file knows the name, a recognisable pseudo address
    otherwise. The name is read from the argument and only ever compared with the file's own imports."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 24:#x}")
    name_at = 0x140005100
    _patch(rz, sid, addr=hex(name_at), bytes=b"Sleep\0".hex())
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": hex(name_at)})
    assist = _assist(rz, sid, ASSIST_AT + 24)
    assert assist["api"] == "GetProcAddress" and assist["value"] == "0x1400093a8"
    assert "Sleep" in assist["summary"], assist["summary"]
    # a name the file does not import: a pseudo address, and the summary says so
    _patch(rz, sid, addr=hex(name_at), bytes=b"NtNope\0".hex())
    other = _assist(rz, sid, ASSIST_AT + 24)
    assert _word(other["value"]) == rizin_emulation.ASSIST_PSEUDO and "pseudo" in other["summary"]
    assert "NtNope" in other["summary"], other["summary"]
    # R38: two looks give the same address, and only an applied skip moves the series on
    assert _assist(rz, sid, ASSIST_AT + 24)["value"] == other["value"]
    _skip(rz, sid, ASSIST_AT + 24, value=other["value"])
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": hex(ASSIST_AT + 24)})
    assert _word(_assist(rz, sid, ASSIST_AT + 24)["value"]) == \
        rizin_emulation.ASSIST_PSEUDO + rizin_emulation.ASSIST_SPACING
    # a name that cannot be read at all is a pseudo address too, and says which name it stands for
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": "0x41"})
    assert "the name" in _assist(rz, sid, ASSIST_AT + 24)["summary"]


def test_a_handle_and_a_success_are_recognisable_values(rz, monkeypatch):
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = _started(rz, f"{ASSIST32_AT + 18:#x}")      # call dword [sym.imp...LoadLibraryA]
    handle = _assist(rz, sid, ASSIST32_AT + 18)
    assert handle["api"] == "LoadLibrary" and _word(handle["value"]) == rizin_emulation.ASSIST_HANDLE
    assert handle["stack_fix"] == 4 and "handle" in handle["summary"]
    # a handle is offered again until one is applied (R38), and then the next one differs
    assert _assist(rz, sid, ASSIST32_AT + 18)["value"] == handle["value"]
    _skip(rz, sid, ASSIST32_AT + 18, value=handle["value"], stack_fix=handle["stack_fix"])
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "eip", "value": hex(ASSIST32_AT + 18)})
    assert _word(_assist(rz, sid, ASSIST32_AT + 18)["value"]) == \
        rizin_emulation.ASSIST_HANDLE + rizin_emulation.ASSIST_SPACING
    # VirtualProtect reports success: the memory the emulation holds is writable anyway
    done = _assist(rz, sid, ASSIST32_AT + 24)
    assert done["api"] == "VirtualProtect" and done["value"] == "0x1" and done["stack_fix"] == 16
    assert "reports success" in done["summary"], done["summary"]


def test_skip_only_applies_to_the_call_the_pc_is_on(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT:#x}")
    mark = len(rz.commands())
    response = rz.post(f"/api/rizin/{sid}/call", {"addr": f"{ASSIST_AT + 6:#x}"})
    assert response.status_code == 400 and "PC" in response.get_json()["refused"]
    assert not any(c.startswith(("aess", "aepc", "aeim ")) for c in _commands_since(rz, mark))


def test_skip_refuses_a_stack_correction_that_is_no_correction(rz, monkeypatch):
    """R32: the correction comes from the request, so it is bounded -- a value that moves the stack
    pointer out of the stack aeim mapped would leave the next state showing words that are no stack."""
    import rizin_emulation
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = _started(rz, f"{ASSIST32_AT:#x}")
    most = rizin_emulation.ASSIST_MAX_ARGS * 4
    for fix, says in ((6, "multiple"), (most + 4, "at most"), (-4, "0 or more"), ("x", "stack_fix"),
                      (True, "stack_fix"), (1.5, "stack_fix")):
        response = rz.post(f"/api/rizin/{sid}/call", {"addr": f"{ASSIST32_AT:#x}", "stack_fix": fix})
        assert response.status_code == 400 and says in response.get_json()["refused"], (fix, says)
    # the most it does take is applied
    assert _skip(rz, sid, ASSIST32_AT, stack_fix=most)["running"] is True
    # and at the end of the stack even a correction inside the bounds is refused
    end = 0x100000 + rizin_sessions.ESIL_STACK_SIZE
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST32_AT:#x}"})
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "esp", "value": hex(end - 8)})
    response = rz.post(f"/api/rizin/{sid}/call", {"addr": f"{ASSIST32_AT:#x}", "stack_fix": 16})
    assert response.status_code == 400 and "stack" in response.get_json()["refused"]


def test_the_assistant_refuses_what_is_no_address(rz):
    sid = _started(rz)
    for query in ("?addr=-1", "?addr=main;wci", "?addr=0x10000000000000000"):
        response = rz.get(f"/api/rizin/{sid}/call{query}")
        assert response.status_code == 400 and "addr" in response.get_json()["refused"], query
    # without an addr the session's own address is read, and there (the entry point) is no call
    response = rz.get(f"/api/rizin/{sid}/call")
    assert response.status_code == 400 and "not a call" in response.get_json()["refused"]
    for body in ({}, {"addr": "-1"}, {"addr": f"{SLEEP_CALL:#x}", "value": "-1"}, [], "x", 7):
        assert rz.post(f"/api/rizin/{sid}/call", body).status_code == 400, body


def test_the_assistant_says_the_session_ended_rather_than_fail(rz):
    sid = _started(rz, f"{SLEEP_CALL:#x}")
    rz.send(f"/api/rizin/{sid}/close", {})
    for response in (rz.get(f"/api/rizin/{sid}/call?addr={SLEEP_CALL:#x}"),
                     rz.post(f"/api/rizin/{sid}/call", {"addr": f"{SLEEP_CALL:#x}"})):
        assert response.status_code == 404 and response.get_json()["error"] == "session ended"


def test_a_skip_writes_the_out_parameters_of_the_time_and_environment_calls(rz, monkeypatch):
    """Important 3 / spec §4: the answer of those two groups is the **value**, not just a return code.
    A QueryPerformanceCounter whose counter is never written lets a timing check see no time pass, and
    a GetComputerName that writes nothing answers no name at all."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 30:#x}")       # call qword [sym.imp...QueryPerformanceCounter]
    into = 0x177000                                   # inside the stack the start mapped
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rcx", "value": hex(into)})
    assist = _assist(rz, sid, ASSIST_AT + 30)
    assert assist["api"] == "QueryPerformanceCounter" and assist["value"] == "0x1"
    assert "performance counter" in assist["summary"] and hex(into) in assist["summary"], assist["summary"]
    state = _skip(rz, sid, ASSIST_AT + 30, value="0x1")
    assert "performance counter" in state["summary"], state["summary"]
    written = bytes(rz.read(f"/api/rizin/{sid}/hex?addr={into:#x}&len=8")["bytes"])
    counter = int.from_bytes(written, "little")
    # the clock the tick answers come from, one step on: 10 MHz, so 10 000 counts per millisecond
    assert counter == (rizin_emulation.TICK_START + rizin_emulation.TICK_STEP) * 10000
    # the counter rises with the next applied skip, so a delta check sees time pass
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": hex(ASSIST_AT + 30)})
    _skip(rz, sid, ASSIST_AT + 30, value="0x1")
    later = int.from_bytes(bytes(rz.read(f"/api/rizin/{sid}/hex?addr={into:#x}&len=8")["bytes"]), "little")
    assert later > counter, (counter, later)

    # GetComputerNameW: the name in UTF-16 at the first argument, its length at the second -- and only
    # as much as the caller said it had room for, which it passes a pointer to
    sid = _started(rz, f"{ASSIST_AT + 36:#x}")
    name_at, size_at = 0x177100, 0x177200
    for register, value in (("rcx", hex(name_at)), ("rdx", hex(size_at))):
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": register, "value": value})
    room = len(rizin_emulation.ASSIST_COMPUTER) + 1
    _patch(rz, sid, addr=hex(size_at), bytes=room.to_bytes(4, "little").hex())
    assist = _assist(rz, sid, ASSIST_AT + 36)
    assert assist["api"] == "GetComputerName" and assist["value"] == "0x1"
    assert rizin_emulation.ASSIST_COMPUTER in assist["summary"], assist["summary"]
    state = _skip(rz, sid, ASSIST_AT + 36, value="0x1")
    expected = rizin_emulation.ASSIST_COMPUTER.encode("utf-16-le") + b"\0\0"
    assert bytes(rz.read(f"/api/rizin/{sid}/hex?addr={name_at:#x}&len={len(expected)}")["bytes"]) == expected
    assert int.from_bytes(bytes(rz.read(f"/api/rizin/{sid}/hex?addr={size_at:#x}&len=4")["bytes"]),
                          "little") == len(rizin_emulation.ASSIST_COMPUTER)
    assert "characters" in state["summary"], state["summary"]


def test_a_name_is_not_written_past_the_buffer_the_caller_asked_for(rz, monkeypatch):
    """Windows writes no more than the caller said it had room for, and a buffer inside a mapped page
    still belongs to the sample: where the room is too small, or the call does not say, nothing is
    written and the summary says so."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 36:#x}")        # GetComputerNameW(lpBuffer, nSize)
    name_at, size_at = 0x177100, 0x177200
    for register, value in (("rcx", hex(name_at)), ("rdx", hex(size_at))):
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": register, "value": value})
    # the caller says it has room for four characters, and the name needs more
    _patch(rz, sid, addr=hex(size_at), bytes=(4).to_bytes(4, "little").hex())
    assist = _assist(rz, sid, ASSIST_AT + 36)
    assert "is not written" in assist["summary"] and "4 characters" in assist["summary"], assist["summary"]
    mark = len(rz.commands())
    state = _skip(rz, sid, ASSIST_AT + 36, value="0x1")
    assert "is not written" in state["summary"] and "not written either" in state["summary"]
    assert not any(c.startswith("wx ") for c in _commands_since(rz, mark)), "nothing was written"
    assert bytes(rz.read(f"/api/rizin/{sid}/hex?addr={name_at:#x}&len=2")["bytes"]) == b"\0\0"
    # and where the size pointer is in no map, the call does not say how much room it has
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": "0x41"})
    assert "does not say how much room" in _assist(rz, sid, ASSIST_AT + 36)["summary"]
    # the room the call does have is honoured: exactly the name and its terminator
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": hex(size_at)})
    _patch(rz, sid, addr=hex(size_at),
           bytes=(len(rizin_emulation.ASSIST_COMPUTER) + 1).to_bytes(4, "little").hex())
    assert rizin_emulation.ASSIST_COMPUTER in _assist(rz, sid, ASSIST_AT + 36)["summary"]


def test_an_out_parameter_that_is_in_no_map_is_not_written(rz, monkeypatch):
    """The same discipline as the buffer and the copy: where the pointer is in no map, nothing is
    written and the summary says so, rather than a value being claimed that is nowhere."""
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 30:#x}")
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rcx", "value": "0x41"})
    assert "is not written" in _assist(rz, sid, ASSIST_AT + 30)["summary"]
    mark = len(rz.commands())
    state = _skip(rz, sid, ASSIST_AT + 30, value="0x1")
    assert "is not written" in state["summary"], state["summary"]
    assert not any(c.startswith("wx ") for c in _commands_since(rz, mark))
    # and before the emulation runs at all, the pointers cannot be read either (another file, because
    # opening the same one again moves this session rather than making a second one)
    other = rz.open(rz.write("other.exe", b"MZ\x90\x00 another sample"), "tab2")["session"]
    rz.wait_done(other)
    assert "not started" in _assist(rz, other, ASSIST_AT + 30)["summary"]


def test_a_32_bit_out_parameter_comes_from_the_stack(rz, monkeypatch):
    """GetVolumeInformationA writes its volume label and serial through two of its eight arguments,
    which at 32 bits are on the stack -- the same [esp + 4*i] reading as a buffer's size (R35)."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    label_at, serial_at = 0x177100, 0x177200
    # lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, ...
    monkeypatch.setenv("FAKE_RIZIN_STACK", f"0,{label_at:#x},0x100,{serial_at:#x}")
    sid = _started(rz, f"{ASSIST32_AT + 30:#x}")
    assist = _assist(rz, sid, ASSIST32_AT + 30)
    assert assist["api"] == "GetVolumeInformation" and assist["value"] == "0x1"
    assert assist["stack_fix"] == 32, "eight stdcall arguments"
    assert rizin_emulation.ASSIST_VOLUME in assist["summary"], assist["summary"]
    _skip(rz, sid, ASSIST32_AT + 30, value="0x1", stack_fix=assist["stack_fix"])
    label = rizin_emulation.ASSIST_VOLUME.encode("ascii") + b"\0"
    assert bytes(rz.read(f"/api/rizin/{sid}/hex?addr={label_at:#x}&len={len(label)}")["bytes"]) == label
    assert int.from_bytes(bytes(rz.read(f"/api/rizin/{sid}/hex?addr={serial_at:#x}&len=4")["bytes"]),
                          "little") == rizin_emulation.ASSIST_SERIAL


def test_a_pseudo_value_is_never_offered_where_something_is_mapped(rz, monkeypatch):
    """Important 4: these values are offered because nothing is mapped at them. A dump -- which the
    spec names as a case -- can have maps anywhere, so the offer checks and moves on."""
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = _started(rz, f"{ASSIST32_AT + 18:#x}")        # LoadLibraryA: a pseudo handle
    assert _word(_assist(rz, sid, ASSIST32_AT + 18)["value"]) == rizin_emulation.ASSIST_HANDLE
    # the console maps memory over the first two values of the series (as a dump's own maps would)
    rz.send(f"/api/rizin/{sid}/console",
            {"cmd": f"aeim {rizin_emulation.ASSIST_HANDLE:#x} {2 * rizin_emulation.ASSIST_SPACING:#x} dump"})
    assert _word(_assist(rz, sid, ASSIST32_AT + 18)["value"]) == \
        rizin_emulation.ASSIST_HANDLE + 2 * rizin_emulation.ASSIST_SPACING


def test_a_start_gives_the_memory_of_the_run_before_back(rz, monkeypatch):
    """R37(a): without the sweep rizin keeps the old stack mapped and maps a second one somewhere else
    (measured), so the emulation would run on a stack the server does not know about."""
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT:#x}")
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rdx", "value": "0x8000"})
    assist = _assist(rz, sid, ASSIST_AT)
    _skip(rz, sid, ASSIST_AT, value=assist["value"])
    assert [m["name"] for m in rz.mgr.get(sid).json("omlj")].count("mem.assist") == 1
    mark = len(rz.commands())
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST_AT:#x}"})
    since = _commands_since(rz, mark)
    assert [c for c in since if c.startswith("o- ")], since
    assert since.index("aei") > max(i for i, c in enumerate(since) if c.startswith("o- ")), since
    # one stack, where the server put it, and no buffer of the run before
    maps = [m["name"] for m in rz.mgr.get(sid).json("omlj") if m["name"].startswith("mem.")]
    assert maps == ["mem.0x100000_0xf0000"], maps
    assert state["stack"] and _register(rz, sid, "rsp") == 0x178000


def test_the_reanalysis_range_leaves_out_every_map_of_the_emulation(rz, monkeypatch):
    """R37(b): the words a run pushed are no code, and neither are the bytes in a buffer the assistant
    mapped -- and the check cannot rest on the stack the *start* recorded, because rizin can map the
    stack somewhere else (measured). Reachable as: skip with a buffer, stop, start, run, reanalyze."""
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 6:#x}")            # memcpy: it writes into the buffer
    buffer_at = 0x50000000
    rz.send(f"/api/rizin/{sid}/console", {"cmd": f"aeim {buffer_at:#x} 0x1000 assist"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST_AT + 6:#x}"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": f"aeim {buffer_at:#x} 0x1000 assist"})
    for name, value in (("rcx", hex(buffer_at)), ("rdx", hex(COPY_FROM)), ("r8", "0x20")):
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": value})
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rip", "value": hex(ASSIST_AT + 6)})
    state = _skip(rz, sid, ASSIST_AT + 6, value=hex(buffer_at))
    assert "copied" in state["summary"], state["summary"]
    assert [r["addr"] for r in _patches(rz, sid) if r["addr"] == buffer_at] == [buffer_at]
    # the copy went into the emulation's own memory, so it is not "the range the run wrote"
    response = rz.post(f"/api/rizin/{sid}/reanalyze", {})
    assert response.status_code == 400 and "nothing" in response.get_json()["refused"], response.get_json()


def test_a_skip_drops_the_cached_lists(rz, monkeypatch):
    # a skip can map memory and copy bytes, so the strings, imports, flags and functions are stale
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT:#x}")
    rz.read(f"/api/rizin/{sid}/flags?q=sym")
    mark = len(rz.commands())
    _skip(rz, sid, ASSIST_AT)
    rz.read(f"/api/rizin/{sid}/flags?q=sym")
    assert "flj" in _commands_since(rz, mark)


# --- What stays: the /tdc namespace of the project (webui/rizin_sessions.py) -

def _project_namespace(text, name):
    """The ``key=value`` lines of one namespace of a project, as {key: value}."""
    found, inside = {}, False
    for line in text.split("\n"):
        if line.startswith("/"):
            inside = line == name
        elif inside and "=" in line:
            key, _, value = line.partition("=")
            found[key] = value
    return found


def _plant_patches(project, patches):
    """Put a patch list into a saved project, as an older session or another build could leave it: each patch is
    (addr, hex), which is an entry without a provenance mark, or (addr, hex, True) for one set over a run's bytes."""

    line = "patches=" + ",".join(f"{addr:x}:{after}" + (":r" if any(mark) else "")
                                 for addr, after, *mark in patches)
    text = project.read_text(encoding="utf-8", errors="surrogateescape")
    planted = re.sub(r"(?m)^patches=.*$", line, text)
    assert planted != text, "the project has no patches line to replace"
    project.write_text(planted, encoding="utf-8", errors="surrogateescape")


def test_a_patch_is_not_refused_while_the_analysis_runs(rz, monkeypatch):
    # Unlike a rename or a comment: an analysis step changes no bytes, so a patch waits for the pipe
    # (2 s) and goes through, and the project is written for it like any other.
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aaa:1")
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    assert rz.status(sid)["analysis"]["state"] == "running"
    assert [r["addr"] for r in rz.send(f"/api/rizin/{sid}/patch",
                                       {"addr": "0x140001440", "bytes": "90"})["patches"]] == [0x140001440]
    assert rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})["breakpoints"]
    rz.wait_done(sid)
    rz.close(sid)
    assert "\npatches=140001440:90\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")


def test_a_replay_that_rizin_does_not_survive_does_not_lock_the_file_out(rz, monkeypatch):
    """The project decides how many commands the replay sends, so it must not be able to cost the
    session: a rizin that stops over a saved patch leaves the file open, with a note, and the project
    is kept (nothing is renamed .broken), so the next open works again."""
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.close(sid)

    monkeypatch.setenv("FAKE_RIZIN_CRASH", "wx")
    described = rz.open(path)  # the open answers rather than failing
    assert "could not be applied" in (described["analysis"]["note"] or "")
    assert rz.project().exists() and not rz.project().with_suffix(".rzdb.broken").exists()
    rz.mgr.close(described["session"])

    monkeypatch.delenv("FAKE_RIZIN_CRASH")
    sid = rz.open(path)["session"]
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001440]


def test_a_patch_and_a_breakpoint_come_back_when_the_file_is_opened_again(rz):
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    original = rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=2")["bytes"]
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "9090"})
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.close(sid)

    mark = len(rz.commands())
    sid = rz.open(path)["session"]
    # R2: one row per write operation, so a two-byte wx is one patch of size 2, not two patches
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001440]
    assert _patches(rz, sid) == [
        {"addr": 0x140001440, "size": 2, "before": bytes(original).hex(), "after": "9090", "mine": True,
         "over_run": False}]
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x1400014B7, "enabled": True}]
    # back in effect, not only in the list: the patch was written before the open answered, so the first
    # disassembly and the first hexdump already show it
    assert any(c.startswith("wx 9090 @ 0x140001440") for c in _commands_since(rz, mark))
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=2")["bytes"] == [0x90, 0x90]
    # and the breakpoint stops a run, as one set by hand does
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    state = _run(rz, sid, "cont")
    assert (state["pc"], state["stopped"]) == ("0x1400014b7", "breakpoint")


def test_what_a_run_wrote_does_not_come_back(rz):
    """A run's bytes never stood in the file; baking them in would lose track of where bytes come from
    (design section 6), and the cache of an XOR run over a section would blow past the 64 KB that
    _read_project_meta reads."""
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    _run(rz, sid, "step")
    ran = _patches(rz, sid)
    assert [r["mine"] for r in ran] == [False]
    rz.close(sid)
    # a run alone asks for a save since the timeline is kept (R-T4a): a project, with the way to the bytes (a hash of
    # them) and not the bytes -- no patch, and nothing of the run's row
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    assert "\npatches=\n" in saved and "\nrestore=1;" in saved
    assert ran[0]["after"] not in saved, "its bytes are not in the project, only their hash"
    assert f"patches={ran[0]['addr']:x}" not in saved
    rz.project().unlink()

    # and with a patch of its own beside it, the project holds the patch and nothing of the run
    sid = rz.open(path)["session"]
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    _run(rz, sid, "step")
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    run = [r for r in _patches(rz, sid) if not r["mine"]]
    assert run
    rz.close(sid)
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    assert "\npatches=140001440:90\n" in saved
    for row in run:
        assert f"{row['addr']:x}:" not in saved and row["after"] not in saved.split("\n/tdc\n")[-1]

    sid = rz.open(path)["session"]
    assert [(r["addr"], r["mine"]) for r in _patches(rz, sid)] == [(0x140001440, True)]


def test_only_the_patches_this_session_still_holds_go_into_the_project(rz):
    """What the mirror and the cache disagree about at save time: the save reads the cache back, so a
    patch the console took away is not written and a write that is not this session's never is."""
    sid = rz.session()
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    _patch(rz, sid, addr="0x140001460", bytes="41")
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 42 @ 0x140001480"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wc- 0x140001460 0x140001461"})
    rz.close(sid)
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    assert "\npatches=140001440:9090\n" in saved


def test_a_stale_patch_outside_the_file_is_skipped_with_a_note(rz):
    # Review Focus 4: the saved list must not be applied blindly nor break the boot.
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.close(sid)
    _plant_patches(rz.project(), [(0xDEADBEEF0000, "90"), (0x140001440, "90")])
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "could not be applied" in note and "0xdeadbeef0000" in note
    sid = described["session"]
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001440]
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=1")["bytes"] == [0x90]
    # the note stays while the session lives, and the session is usable
    assert "could not be applied" in rz.status(sid)["analysis"]["note"]


def _patched_over_a_run(rz, name="pipesim.exe"):
    """A file opened, a "run" that wrote four bytes at 0x140001440 (a console wx is the same row to rizin and
    the start is what switches io.cache on), and a patch of the session's own over the second of them:
    what the tab invites -- the anti-VM check inside freshly decrypted code. Returns the path and the
    session ID; the session is still open."""
    path = rz.write(name)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41424344 @ 0x140001440"})
    _patch(rz, sid, addr="0x140001441", bytes="90")
    assert [(r["addr"], r["mine"], r["over_run"]) for r in _patches(rz, sid)] == [
        (0x140001440, False, False), (0x140001441, True, True)]
    return path, sid


def test_a_patch_over_a_runs_bytes_is_held_back_when_the_file_is_opened_again(rz):
    # The damage: _replay_patches runs before any run, so the patch landed in the still encrypted
    # bytes, and the next decryption XORed over it. It is not applied, it waits -- and says why.
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    assert "\npatches=140001441:90:r\n" in saved, "the project says where the patch was set"

    mark = len(rz.commands())
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    assert not any(c.startswith("wx 90") for c in _commands_since(rz, mark)), "it was not even sent"
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert set(answer) == {"patches", "waiting", "restore"}
    assert answer["patches"] == [], "not in the cache, so it is not exported either"
    assert [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x140001441, "90")]
    assert set(answer["waiting"][0]) == {"addr", "after", "reason", "apply_now"}
    assert isinstance(answer["waiting"][0]["addr"], int) and answer["waiting"][0]["reason"]
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001441&len=1")["bytes"] != [0x90]
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "no patches" in response.get_json()["refused"]

    # it stays in the project through a save that has nothing to do with it, and still waits
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.close(sid)
    assert "\npatches=140001441:90:r\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    sid = rz.open(path)["session"]
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    assert _patches(rz, sid) == []


def test_a_patch_without_a_provenance_mark_is_applied_as_before(rz):
    # Review Focus 1: a project written before the mark has entries without one. Holding them back
    # would silently devalue every project that exists, so they are applied, as they were.
    path, sid = _patched_over_a_run(rz)  # the very patch that is held back, as a build of before saved it
    rz.close(sid)
    _plant_patches(rz.project(), [(0x140001441, "90")])
    assert "\npatches=140001441:90\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")

    mark = len(rz.commands())
    described = rz.open(path)
    sid = described["session"]
    assert any(c.startswith("wx 90 @ 0x140001441") for c in _commands_since(rz, mark))
    assert [(r["addr"], r["mine"], r["over_run"]) for r in _patches(rz, sid)] == [(0x140001441, True, False)]
    assert _waiting(rz, sid) == []
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001441&len=1")["bytes"] == [0x90]
    assert "Held back" not in (described["analysis"]["note"] or "")
    # and saved again it keeps no mark it never had
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.close(sid)
    assert "\npatches=140001441:90\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")


def test_the_note_names_the_held_back_patches_once_when_the_file_is_opened(rz):
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    # a second one over a run, and one that has no place in the file at all, beside one made before the mark
    _plant_patches(rz.project(), [(0x140001441, "90", True), (0x140001450, "9090", True),
                                  (0xDEADBEEF0000, "90"), (0x140001460, "41")])
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "Held back, not applied: 2 saved patches" in note, note
    assert "0x140001441" in note and "0x140001450" in note and "0x140001460" not in note, note
    assert "could not be applied" in note and "0xdeadbeef0000" in note, "the older note is still said"
    sid = described["session"]
    rz.wait_done(sid)  # the start went on
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001460]
    assert [w["addr"] for w in _waiting(rz, sid)] == [0x140001441, 0x140001450]
    # once: not again by a status, by an analysis that plans again, or by a save
    rz.send(f"/api/rizin/{sid}/analyze")
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.mgr.get(sid).flush()
    assert (rz.status(sid)["analysis"]["note"] or "").count("Held back") == 1


def test_a_marked_patch_too_long_to_write_is_named_and_one_entry_waits_once(rz):
    # Too long for one command line, it cannot be restored by anything, so it is named as one that could
    # not be applied rather than listed as waiting. And an entry the project holds twice waits once.
    import rizin_emulation

    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    over = rizin_emulation.MAX_PATCH_BYTES + 1
    _plant_patches(rz.project(), [(0x140002000, "90" * over, True), (0x140001441, "90", True),
                                  (0x140001441, "90", True)])
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "could not be applied" in note and "0x140002000" in note and "Held back" in note, note
    assert "1 saved patch over bytes" in note, "the duplicate is one patch"
    sid = described["session"]
    assert [w["addr"] for w in _waiting(rz, sid)] == [0x140001441]
    assert not any(c.startswith("wx " + "90" * over) for c in rz.commands())


def test_the_same_patch_made_again_over_a_run_is_saved_once(rz):
    # the patch waits; the user decrypts again and patches the same bytes over the run's: that patch is
    # in the cache now, and the project must not hold it twice (once as itself, once as the one that waited)
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    assert [w["addr"] for w in _waiting(rz, sid)] == [0x140001441]
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41424344 @ 0x140001440"})
    _patch(rz, sid, addr="0x140001441", bytes="90")
    rz.close(sid)
    assert "\npatches=140001441:90:r\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")


def _reopened_with_a_waiting_patch(rz):
    """_patched_over_a_run, saved and opened again: the patch 0x140001441:90 waits. Returns path and session ID."""
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    return path, sid


def _project_patches(rz):
    return rz.project().read_text(encoding="utf-8", errors="surrogateescape").split("\npatches=")[1].split("\n")[0]


def test_a_waiting_entry_says_whether_apply_now_would_be_taken(rz):
    # The pane draws "Apply now" from this flag and decides nothing itself: it is rizin_emulation.run_covers over the
    # rows of the very read the answer is made from (no second wcj), so it is true exactly where a press would be
    # accepted -- a row of the cache that is not the user's own overlaps a byte of the patch -- and a press of the
    # route says the same. The edges count, and the user's own row is no run's.
    path, sid = _reopened_with_a_waiting_patch(rz)
    session = rz.mgr.get(sid)
    session._waiting.append((0x50000000, "90", True))  # in no map, no run anywhere near

    def flags():
        return {w["addr"]: w["apply_now"] for w in _waiting(rz, sid)}

    assert flags() == {0x140001441: False, 0x50000000: False}, "nothing has run in this session"
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _console(rz, sid, "wx 41 @ 0x140001440")
    assert flags()[0x140001441] is False, "a run's row that ends where the patch starts covers nothing"
    _console(rz, sid, "wx 90 @ 0x140001448")
    assert flags()[0x140001441] is False, "one that lies elsewhere neither"
    # the length of the patch counts, in bytes: the row at ...48 is under the second byte of a two-byte patch at ...47, and
    # one byte past the end of the one at ...46
    session._waiting += [(0x140001447, "9090", True), (0x140001446, "9090", True)]
    assert flags()[0x140001447] is True and flags()[0x140001446] is False
    _console(rz, sid, "wx 4142 @ 0x140001440")
    assert flags() == {0x140001441: True, 0x50000000: False, 0x140001447: True, 0x140001446: False}
    assert all(type(w["apply_now"]) is bool for w in _waiting(rz, sid))

    mark = len(rz.commands())
    assert flags()[0x140001441] is True
    assert rz.commands()[mark:].count("wcj") == 1, "the flag is made from the read of the answer, not a second one"
    # the press agrees with the flag, in both directions
    refused = rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x50000000", "waiting": True})
    assert refused.status_code == 400 and "no run's bytes" in refused.get_json()["refused"]
    answer = rz.ok(rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001441", "waiting": True}))
    assert {w["addr"]: w["apply_now"] for w in answer["waiting"]} == {0x50000000: False, 0x140001447: True, 0x140001446: False}
    assert [r["addr"] for r in answer["patches"] if r["mine"]] == [0x140001441]


def test_a_patch_made_again_over_the_run_is_not_in_both_lists_of_one_answer(rz):
    # It waited; the user decrypts again and sets the same patch: it is a row of the cache now, and
    # "a waiting patch is not in the cache" would be false of the entry the answer still listed.
    path, sid = _reopened_with_a_waiting_patch(rz)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41424344 @ 0x140001440"})
    _patch(rz, sid, addr="0x140001441", bytes="90")
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert [(r["addr"], r["after"], r["mine"], r["over_run"]) for r in answer["patches"]] == [
        (0x140001440, "41424344", False, False), (0x140001441, "90", True, True)]
    assert answer["waiting"] == []
    rz.mgr.get(sid).flush()
    assert _project_patches(rz) == "140001441:90:r", "and the project says what the answer does"


def test_a_patch_made_again_without_a_run_under_it_does_not_wait_either(rz):
    # The same address and bytes, set live and not over a run: the cache holds it and applied it, so the
    # waiting entry says nothing more -- the answer and the project each hold it once
    path, sid = _reopened_with_a_waiting_patch(rz)
    _patch(rz, sid, addr="0x140001441", bytes="90")
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert [(r["addr"], r["mine"], r["over_run"]) for r in answer["patches"]] == [(0x140001441, True, False)]
    assert answer["waiting"] == []
    rz.mgr.get(sid).flush()
    assert _project_patches(rz) == "140001441:90"


def test_a_patch_made_again_with_other_bytes_leaves_the_waiting_one_waiting(rz):
    # Same address, different bytes: the saved entry's bytes are still not applied, so it still waits,
    # and the project holds both -- the answer and the project agree
    path, sid = _reopened_with_a_waiting_patch(rz)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wx 41424344 @ 0x140001440"})
    _patch(rz, sid, addr="0x140001441", bytes="91")
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert [(r["addr"], r["after"]) for r in answer["patches"] if r["mine"]] == [(0x140001441, "91")]
    assert [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x140001441, "90")]
    rz.mgr.get(sid).flush()
    assert _project_patches(rz) == "140001441:91:r,140001441:90:r"


def test_the_hold_back_bound_is_the_bound_of_one_patch(rz):
    # An entry of exactly MAX_PATCH_BYTES can be written, so it is held; one byte more can not, so it is
    # named with the others that cannot be applied and is not listed as waiting for something that cannot come
    import rizin_emulation

    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    top = rizin_emulation.MAX_PATCH_BYTES
    _plant_patches(rz.project(), [(0x140001441, "90" * top, True), (0x140002000, "90" * (top + 1), True)])
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "1 saved patch could not be applied to this file: 0x140002000" in note, note
    assert "Held back, not applied: 1 saved patch over bytes an emulation run wrote (0x140001441)" in note, note
    sid = described["session"]
    assert [(w["addr"], len(w["after"])) for w in _waiting(rz, sid)] == [(0x140001441, 2 * top)]
    assert not any(c.startswith("wx " + "90" * top) for c in rz.commands()), "neither was written"


def test_the_held_note_counts_what_this_replay_held_back(sessions, sample):
    # A restart replays the session's own patches into a session that may hold one back already. The note
    # states what **this** replay held back (the addresses it names are that many), not how much the list
    # of waiting patches grew by: an entry that waited already is held back again, and said so.
    mgr = sessions()
    session = mgr.get(mgr.open(sample("count.exe", b"MZ count"), "tab")["session"])
    _wait_state(session, "done")
    first = session._replay_patches([(0x140001441, "90", True)])
    assert first.startswith("Held back, not applied: 1 saved patch over bytes an emulation run wrote (0x140001441).")
    second = session._replay_patches([(0x140001441, "90", True), (0x140001450, "41", True)])
    assert second.startswith("Held back, not applied: 2 saved patches over bytes an emulation run wrote "
                             "(0x140001441, 0x140001450)."), second
    assert len(session._waiting) == 2, "the waiting list grew by one, and the note says two: it names both"
    again = session._replay_patches([(0x140001441, "90", True)])
    assert again.startswith("Held back, not applied: 1 saved patch over bytes an emulation run wrote (0x140001441).")
    assert len(session._waiting) == 2


def test_a_waiting_patch_says_whether_a_map_holds_its_address(rz):
    """The omlj at the start lists the file's maps; the ESIL stack's mem.* map arrives with the emulation
    (measured, see the real-rizin test below). A marked patch at an address no map holds is **held**, not
    dropped -- but its reason may only say what is true: that nothing is mapped there *now*."""
    import rizin_sessions

    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})  # what makes a project be written
    rz.close(sid)
    stack = rizin_sessions.ESIL_STACK_ADDR + 0x80
    edge = rizin_sessions.ESIL_STACK_ADDR + rizin_sessions.ESIL_STACK_SIZE - 1  # the stack's last byte
    _plant_patches(rz.project(), [(stack, "41", True), (0xDEADBEEF0000, "90", True), (0x140001441, "90", True),
                                  (edge, "42", True), (edge, "4243", True)])
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    reasons = {(w["addr"], w["after"]): w["reason"] for w in _waiting(rz, sid)}
    assert sorted(reasons) == [(stack, "41"), (edge, "42"), (edge, "4243"), (0x140001441, "90"),
                               (0xDEADBEEF0000, "90")], "all are held, none dropped"
    mapped = reasons[(0x140001441, "90")]
    for key in ((stack, "41"), (edge, "42"), (0xDEADBEEF0000, "90")):
        assert reasons[key].startswith(mapped) and reasons[key] != mapped, reasons[key]
        assert "No map holds this address now" in reasons[key] and "when it starts" in reasons[key]
    assert "No map" not in mapped
    assert "never" not in reasons[(stack, "41")] and "cannot be applied" not in reasons[(stack, "41")]
    # the emulation maps its stack: the address is held by a map now, and the reason says no more than the others'
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    reasons = {(w["addr"], w["after"]): w["reason"] for w in _waiting(rz, sid)}
    assert reasons[(stack, "41")] == mapped, "the stack is mapped now"
    assert reasons[(edge, "42")] == mapped, "its last byte is held by the map"
    assert reasons[(edge, "4243")] != mapped, "two bytes there run past the map: one map has to hold them all"
    assert "No map holds this address now" in reasons[(0xDEADBEEF0000, "90")]


def test_taking_the_whole_cache_back_leaves_a_waiting_patch_and_the_project_keeps_it(rz):
    # A waiting patch is no write of the cache, so `wc-*` cannot take it; it leaves by its own exit
    path, sid = _reopened_with_a_waiting_patch(rz)
    answer = rz.remove(f"/api/rizin/{sid}/patch", {})
    assert answer["patches"] == []
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": 0x140001441})
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    rz.close(sid)
    assert _project_patches(rz) == "140001441:90:r", "the project holds it after the take-back, as it did before"
    sid = rz.open(path)["session"]
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]


def test_a_patch_that_a_restart_lost_and_one_that_waits_are_one_entry_of_the_project(sessions, sample, fake,
                                                                                     tmp_path, monkeypatch):
    """The same address and bytes as one that waits, through ``self._lost`` (a patch a restarted rizin could not
    take back): the project line held both (``100080:41:r,100080:41``), and a reopened file then named one patch
    twice, as one that could not be applied and as one held back."""
    import rizin_sessions

    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    path = sample("hang6.exe", b"MZ hang 6")
    stack = rizin_sessions.ESIL_STACK_ADDR + 0x80
    first = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    opened = first.open(path, "tab")
    session = first.get(opened["session"])
    _wait_state(session, "done")
    session.patch(0x140001441, "90")
    timers.fire()
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    _plant_patches(project, [(stack, "41", True)])  # a patch that waits, in the emulation's stack
    first.close(opened["session"])
    assert session.wait_closed(30)

    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    session = mgr.get(mgr.open(path, "tab2")["session"])
    _wait_state(session, "done")
    assert session._waiting == [(stack, "41", True)]
    session.emulation_start(0x140001440)
    session.patch(stack, "41")  # made again, live: the cache holds it and it waits no more
    timers.fire()
    assert _project_patches_of(project) == f"{stack:x}:41"

    session.analyze_full()  # its aar hangs, so rizin is restarted, and the stack is not mapped in the new one
    _wait_state(session, "stopped")
    assert session._lost == [(stack, "41", False)] and session._waiting == [(stack, "41", True)]
    assert session.patches()["patches"] == [] and [w["addr"] for w in session.patches()["waiting"]] == [stack]
    session.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert _project_patches_of(project) == f"{stack:x}:41:r", "one entry, the one the answer shows"


def test_a_patch_a_restart_lost_at_the_address_of_one_that_waits_but_with_other_bytes_is_kept(
        sessions, sample, fake, tmp_path, monkeypatch):
    """The key of the project line is the address **and** the bytes: a lost patch beside a waiting one at the same
    address but with other bytes is another patch, and keyed by the address alone it would leave the project
    without a word."""
    import rizin_sessions

    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    path = sample("hang7.exe", b"MZ hang 7")
    stack = rizin_sessions.ESIL_STACK_ADDR + 0x80
    first = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    opened = first.open(path, "tab")
    session = first.get(opened["session"])
    _wait_state(session, "done")
    session.patch(0x140001441, "90")
    timers.fire()
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    _plant_patches(project, [(stack, "41", True)])  # waits
    first.close(opened["session"])
    assert session.wait_closed(30)

    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    session = mgr.get(mgr.open(path, "tab2")["session"])
    _wait_state(session, "done")
    session.emulation_start(0x140001440)
    session.patch(stack, "42")  # the same address, other bytes: live, and the waiting one is still not applied
    session.analyze_full()  # rizin restarts and the stack is not mapped in the new one: the live patch is lost
    _wait_state(session, "stopped")
    assert session._lost == [(stack, "42", False)] and session._waiting == [(stack, "41", True)]
    session.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert _project_patches_of(project) == f"{stack:x}:41:r,{stack:x}:42", "both: they are two patches"


def _project_patches_of(project):
    return project.read_text(encoding="utf-8", errors="surrogateescape").split("\npatches=")[1].split("\n")[0]


def test_a_patch_hidden_by_a_live_one_waits_again_when_the_console_takes_the_live_one(rz):
    # The cache is read **before** what waits is worked out: a `wc-` of the console has taken the live patch out
    # of the cache, and the mirror only learns that when the cache is read. Worked out first, the patch would be
    # in neither list while the project still holds it.
    path, sid = _reopened_with_a_waiting_patch(rz)
    _patch(rz, sid, addr="0x140001441", bytes="90")
    assert rz.read(f"/api/rizin/{sid}/patches")["waiting"] == []
    rz.send(f"/api/rizin/{sid}/console", {"cmd": "wc- 0x140001441 0x140001442"})
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert answer["patches"] == []
    assert [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x140001441, "90")]
    rz.mgr.get(sid).flush()
    assert _project_patches(rz) == "140001441:90:r"


def test_a_reason_does_not_claim_an_unmapped_address_where_the_maps_could_not_be_read(rz, monkeypatch):
    # omlj answers what is no JSON: what is mapped is not known, so the reason says nothing about it -- for an
    # address the file's map holds as much as for one it does not
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    _plant_patches(rz.project(), [(0x140001441, "90", True), (0xDEADBEEF0000, "90", True)])
    monkeypatch.setenv("FAKE_RIZIN_BAD_OMLJ", "1")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert [w["addr"] for w in answer["waiting"]] == [0x140001441, 0xDEADBEEF0000]
    assert {w["reason"] for w in answer["waiting"]} == {rizin_sessions_reason()}


def rizin_sessions_reason():
    import rizin_sessions

    return rizin_sessions._PATCH_WAITING_REASON


def test_a_rizin_that_times_out_over_the_maps_costs_no_answer_and_ends_the_session(rz, monkeypatch):
    """The other half of the death test above: a read that times out kills rizin first (RizinPipe._answer), then
    raises RizinTimeout -- the same answer, the same ended session."""
    import rizin_sessions

    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    session = rz.mgr.get(sid)
    real = rizin_sessions.RizinPipe.cmdj

    def slow_maps(pipe, text, *args, **kwargs):
        if text == "omlj":
            pipe._kill()  # what a timed-out read does before it raises
            raise rizin_sessions.RizinTimeout("rizin did not answer in time")
        return real(pipe, text, *args, **kwargs)

    monkeypatch.setattr(rizin_sessions.RizinPipe, "cmdj", slow_maps)
    response = rz.get(f"/api/rizin/{sid}/patches")
    assert response.status_code == 200, response.get_json()
    answer = response.get_json()
    assert answer["patches"] == [] and [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x140001441, "90")]
    assert answer["waiting"][0]["reason"] == rizin_sessions_reason()
    assert session.closed is True
    assert rz.get(f"/api/rizin/{sid}/patches").status_code == 404


def test_a_replay_that_fails_over_the_maps_still_keeps_what_it_held_back(rz, monkeypatch):
    # omlj is no JSON when the other patches are replayed, so they are named as not applied and the session goes
    # on -- and the patch held back, which needed no command, is still waiting and still in the answer
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    _plant_patches(rz.project(), [(0x140001441, "90", True), (0x140001460, "41")])
    monkeypatch.setenv("FAKE_RIZIN_BAD_OMLJ", "1")
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "1 saved patch could not be applied to this file." in note and "Held back" in note, note
    sid = described["session"]
    rz.wait_done(sid)
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})  # a save
    rz.close(sid)
    assert _project_patches(rz) == "140001441:90:r"


def test_nothing_asks_for_the_maps_where_nothing_waits(rz):
    sid = rz.session()
    _patch(rz, sid, addr="0x140001440", bytes="90")
    mark = len(rz.commands())
    assert rz.read(f"/api/rizin/{sid}/patches")["waiting"] == []
    assert "omlj" not in _commands_since(rz, mark), "the read is for the reason of a waiting patch only"


def test_a_rizin_that_dies_over_the_maps_costs_no_answer_and_ends_the_session(rz, monkeypatch):
    """The read of omlj is for one sentence of prose and must not cost the answer, but the pipe it died on is
    dead: the session is ended as _call ends one -- the answer is what was read before, the next request says
    "session ended", and the session is not reported as live in between."""
    path, sid = _patched_over_a_run(rz)
    rz.close(sid)
    monkeypatch.setenv("FAKE_RIZIN_CRASH", "omlj")
    sid = rz.open(path)["session"]  # a project that only holds a patch back sends no omlj
    rz.wait_done(sid)
    session = rz.mgr.get(sid)
    response = rz.get(f"/api/rizin/{sid}/patches")
    assert response.status_code == 200, response.get_json()
    answer = response.get_json()
    assert answer["patches"] == [] and [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x140001441, "90")]
    assert answer["waiting"][0]["reason"] == rizin_sessions_reason(), "the sentence is not guessed at"
    assert session.closed is True, "a dead pipe is not a live session"
    again = rz.get(f"/api/rizin/{sid}/patches")
    assert again.status_code == 404 and again.get_json()["error"] == "session ended"


def test_a_patch_held_back_twice_waits_once(sessions, sample):
    # _recover replays the mirror into a session that may already hold the same patch back (made again, by
    # hand, over the same run's bytes); the list of what waits must not grow a second entry for it
    mgr = sessions()
    session = mgr.get(mgr.open(sample("twice.exe", b"MZ twice"), "tab")["session"])
    _wait_state(session, "done")
    note = session._replay_patches([(0x140001441, "90", True)])
    assert "Held back" in note and "1 saved patch " in note
    session._replay_patches([(0x140001441, "90", True), (0x140001450, "41", True)])
    assert session._waiting == [(0x140001441, "90", True), (0x140001450, "41", True)]


def test_a_patch_held_back_does_not_cost_the_session(rz, monkeypatch):
    # "A project must not cost a session": the held-back patch is named and the rest goes on, even
    # where the replay of the others fails
    path, sid = _patched_over_a_run(rz)
    _patch(rz, sid, addr="0x140001460", bytes="41")
    rz.close(sid)
    monkeypatch.setenv("FAKE_RIZIN_CRASH", "wx")
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "could not be applied" in note and "Held back" in note and "0x140001441" in note, note
    assert rz.project().exists() and not rz.project().with_suffix(".rzdb.broken").exists()
    rz.mgr.close(described["session"])
    assert "\npatches=140001441:90:r,140001460:41\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")

    monkeypatch.delenv("FAKE_RIZIN_CRASH")  # and the next open has both: one applied, one waiting
    sid = rz.open(path)["session"]
    assert [w["addr"] for w in _waiting(rz, sid)] == [0x140001441]
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001460]


def test_a_held_back_patch_is_still_kept_by_a_restarted_rizin(sessions, sample, fake, tmp_path, monkeypatch):
    """_recover replays the session's own mirror into a rizin whose cache is empty -- the run's bytes are
    gone with the old one, so a patch that was set over them would land in the encrypted ones, exactly as
    on open. It waits there as well, and the project keeps it."""
    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    opened = mgr.open(sample("hang5.exe", b"MZ hang 5"), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.emulation_start(0x140001440)
    session.console("wx 41424344 @ 0x140001440")
    # made in this order, which is not the order of the addresses: the mark has to stay with its patch
    session.patch(0x140001460, "41")
    session.patch(0x140001441, "90")
    assert [(r["addr"], r["over_run"]) for r in session.patches()["patches"] if r["mine"]] == [
        (0x140001441, True), (0x140001460, False)]
    timers.fire()
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    assert "\npatches=140001460:41,140001441:90:r\n" in project.read_text()

    session.analyze_full()  # its aar hangs, so rizin is killed and restarted
    _wait_state(session, "stopped")
    assert len(fake.by_process()) == 2
    answer = session.patches()
    assert [(r["addr"], r["after"]) for r in answer["patches"]] == [(0x140001460, "41")]
    assert [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x140001441, "90")]
    assert not any(c.startswith("wx 90") for c in fake.by_process()[1]), "not written into the new rizin"
    assert "Held back" in session.analysis["note"] and "0x140001441" in session.analysis["note"]
    assert session._lost == [], "held back is not lost: a later patch clears what is lost and not what waits"
    session.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert "\npatches=140001460:41,140001441:90:r\n" in project.read_text(), "kept, with its mark"
    session.patch(0x140001470, "42")  # the user patches again: what waits is not what a restart lost
    timers.fire()
    assert "\npatches=140001460:41,140001470:42,140001441:90:r\n" in project.read_text()


def test_patches_line_counts_the_provenance_mark_against_the_budget(monkeypatch):
    import rizin_sessions

    patches = [(0x1000, "90", False), (0x2000, "90", True)]
    assert rizin_sessions._patches_line(patches) == ("1000:90,2000:90:r", 0)
    # a budget that fits the two entries without the mark and not with it: the longer form is what is written
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len("1000:90,2000:90"))
    assert rizin_sessions._patches_line(patches) == ("1000:90", 1)
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len("1000:90,2000:90:r"))
    assert rizin_sessions._patches_line(patches) == ("1000:90,2000:90:r", 0)


def test_the_mark_goes_through_the_project_and_comes_back(tmp_path):
    import rizin_sessions

    src, dst = tmp_path / "in.rzdb", tmp_path / "out.rzdb"
    src.write_text("/\nversion=25\n")
    patches = [(0x140001000, "9090", False), (0x140002000, "41", True), (0x140003000, "42", False)]
    assert rizin_sessions._sanitize_project(str(src), str(dst), "aaa", "one", ["aaa"], patches) == (0, True, True)
    assert "\npatches=140001000:9090,140002000:41:r,140003000:42\n" in dst.read_text()
    assert rizin_sessions._read_project_meta(str(dst))["patches"] == patches
    # the slice that cuts the line takes the entry it cuts, with its mark: "1:90:" is no entry either
    cut = tmp_path / "cut.rzdb"
    entries = ",".join(f"{0x140001000 + i:x}:{'90' * 1000}:r" for i in range(20))
    cut.write_text(f"/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches={entries}\n")
    read = rizin_sessions._read_project_meta(str(cut))["patches"]
    assert read and all(len(after) == 2000 and over for _, after, over in read), read


def test_a_saved_patch_too_long_for_one_command_line_is_named_not_dropped(rz):
    """Fix round 3: a project written before MAX_PATCH_BYTES was corrected can hold an entry of up to
    2035 bytes, which rizin did take then (a line of 4094 characters lands, measured) and cannot take
    now. It is skipped **with a note**, like a patch outside the file's maps -- Task 6's Review Focus 4
    asks for exactly that: named, not applied blindly and not dropped in silence."""
    import rizin_emulation

    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.close(sid)
    over = rizin_emulation.MAX_PATCH_BYTES + 1
    _plant_patches(rz.project(), [(0x140002000, "90" * over), (0x140001440, "90")])
    described = rz.open(path)
    note = described["analysis"]["note"] or ""
    assert "could not be applied" in note and "0x140002000" in note, note
    sid = described["session"]
    # the patch that fits is back and the one that does not was never written
    assert [r["addr"] for r in _patches(rz, sid)] == [0x140001440]
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140002000&len=1")["bytes"] != [0x90]
    assert not any(c.startswith("wx " + "90" * over) for c in rz.commands()), "it was not even sent"


def test_a_project_is_written_for_a_patch_alone(rz):
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    assert not rz.project().exists()  # the analysis alone writes none
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.close(sid)
    assert rz.project().exists()


def test_a_project_is_written_for_a_breakpoint_alone(rz):
    # rizin keeps breakpoints in its own project (/core/debug/breakpoints, measured), so all the server
    # has to do for them is write a project at all
    other = SAMPLE + b" two"
    path = rz.write("second.exe", other)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    assert not rz.project(other).exists()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    rz.close(sid)
    assert rz.project(other).exists()
    sid = rz.open(path)["session"]
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [{"addr": 0x140001450, "enabled": True}]


def test_taking_a_patch_back_is_saved_too(rz):
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "90"})
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140001440"})
    rz.close(sid)
    assert "\npatches=\n" in rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    sid = rz.open(path)["session"]
    assert _patches(rz, sid) == []
    assert rz.read(f"/api/rizin/{sid}/hex?addr=0x140001440&len=1")["bytes"] != [0x90]


def test_patches_that_do_not_fit_the_project_are_named_not_dropped_in_silence(rz, monkeypatch):
    # _read_project_meta reads the last 64 KB: patches that pushed /tdc out of it would take the
    # analysis progress with them, so what does not fit is left out and the session says so
    import rizin_emulation
    import rizin_sessions

    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    # a budget for exactly three of the largest patch ("<addr>:<hex>", and a comma between two), so
    # that this test is about the naming whatever MAX_PATCH_BYTES is; the budget's own arithmetic is
    # covered by test_the_tdc_namespace_stays_inside_the_tail_that_is_read_back
    entry = len("140001000") + 1 + 2 * rizin_emulation.MAX_PATCH_BYTES
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", 3 * entry + 2)
    for i in range(5):
        _patch(rz, sid, addr=hex(0x140001000 + i * 0x2000), bytes="90" * rizin_emulation.MAX_PATCH_BYTES)
    assert rz.mgr.get(sid).flush() is True
    note = rz.status(sid)["analysis"]["note"]
    assert note.startswith("2 patches did not fit into the project"), note
    saved = rz.project().read_text(encoding="utf-8", errors="surrogateescape")
    assert len(saved.split("\n/tdc\n")[-1]) < 64 * 1024
    rz.close(sid)
    sid = rz.open(path)["session"]
    # the three that fit come back; the analysis progress comes back either way
    assert len(_patches(rz, sid)) == 3 and rz.status(sid)["analysis"]["level"] == "aaa"
    assert rz.status(sid)["analysis"]["done_steps"] == ["aaa"]


def test_the_budget_note_is_not_withdrawn_by_a_full_analysis(sessions, sample, monkeypatch):
    """The pane says the patches set by hand are "kept with the project", and this note is the only
    thing that says they are not all of them. _start_analysis drops the notes of the run before it when
    it plans again, and _dropped_noted keeps the note from being added a second time -- so one Full
    analysis used to take the only signal away while the pane went on promising the project."""
    import rizin_emulation
    import rizin_sessions

    # over big_file the file is analysed with `aa`, so Full analysis still has steps to plan: with a
    # finished `aaa` analyze_full returns at once and never reaches _start_analysis
    mgr = sessions(big_file=1)
    session = mgr.get(mgr.open(sample("big.bin", b"MZ", size=4096), "tab")["session"])
    assert _wait_state(session, "done")["level"] == "aa"
    entry = len("140001000") + 1 + 2 * rizin_emulation.MAX_PATCH_BYTES
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", entry)
    for i in range(2):
        session.patch(0x140001000 + i * 0x2000, "90" * rizin_emulation.MAX_PATCH_BYTES)
    assert session.flush() is True
    assert "did not fit into the project" in session.analysis["note"]

    session.analyze_full()
    state = _wait_state(session, "done")
    assert state["level"] == "aaa" and state["done_steps"], "the analysis really planned again"
    assert "did not fit into the project" in state["note"], \
        "the note is still true, and nothing else says the project has only some of the patches"
    # and it is still said only once, however many saves follow
    session.patch(0x140005000, "90" * rizin_emulation.MAX_PATCH_BYTES)
    assert session.flush() is True
    assert session.analysis["note"].count("did not fit into the project") == 1


def test_the_project_meta_reads_what_it_can_and_drops_the_rest(tmp_path):
    import rizin_sessions

    project = tmp_path / "x.rzdb"
    project.write_text("/\nversion=25\n\n/tdc\nlevel=aaa\nmode=one\ndone=aaa,aa\n"
                       "patches=140001440:9090,nope,1:zz,2:9,,3:90,10000000000000000:90\n")
    meta = rizin_sessions._read_project_meta(str(project))
    assert meta["patches"] == [(0x140001440, "9090", False), (3, "90", False)]
    assert (meta["level"], meta["mode"], meta["done"]) == ("aaa", "one", ["aaa", "aa"])
    # a project from before this version has no patches line at all
    project.write_text("/\nversion=25\n\n/tdc\nlevel=aa\nmode=steps\ndone=aa\n")
    assert rizin_sessions._read_project_meta(str(project))["patches"] == []


def test_the_tdc_namespace_stays_inside_the_tail_that_is_read_back(tmp_path):
    import rizin_emulation
    import rizin_sessions

    src, dst = tmp_path / "in.rzdb", tmp_path / "out.rzdb"
    src.write_text("/\nversion=25\n")
    big = [(0x140001000 + i * 0x2000, "90" * rizin_emulation.MAX_PATCH_BYTES, False) for i in range(10)]
    left_out, fitted, _ = rizin_sessions._sanitize_project(str(src), str(dst), "aaa", "one", ["aaa"], big)
    assert fitted, "there was no record to fit"
    meta = rizin_sessions._read_project_meta(str(dst))
    # an entry costs 9 + 1 + 2 * MAX_PATCH_BYTES characters, and a comma between two of them
    entry = len("140001000") + 1 + 2 * rizin_emulation.MAX_PATCH_BYTES
    fits = (rizin_sessions.PROJECT_PATCH_CHARS + 1) // (entry + 1)
    assert 0 < fits < len(big), fits
    assert meta["patches"] == big[:fits] and left_out == len(big) - fits
    # and what the tail is read for still comes back
    assert (meta["level"], meta["mode"], meta["done"]) == ("aaa", "one", ["aaa"])

    # a line longer than the budget (a project edited by hand): the entry the slice cuts is dropped,
    # not applied as the shorter patch its half still parses as
    cut = tmp_path / "cut.rzdb"
    entries = ",".join(f"{0x140001000 + i:x}:{'90' * 1000}" for i in range(20))
    cut.write_text(f"/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches={entries}\n")
    read = rizin_sessions._read_project_meta(str(cut))["patches"]
    assert len(entries) > rizin_sessions.PROJECT_PATCH_CHARS
    # the slice ends in the middle of the 17th entry, on an even number of its hex digits
    assert all(len(after) == 2000 for _, after, _ in read), [len(after) for _, after, _ in read]
    assert len(read) == 16 and read[0] == (0x140001000, "90" * 1000, False)


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_patches_through_the_cache(tdc, tmp_path, monkeypatch):
    """The three routes against rizin 0.9.1 itself, and the behaviour the fake models for them:
    wcj groups per write operation, a patch shows through px, wc- and wc-* take it back, and the file
    on disk is never written."""
    import rizin_sessions

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    before = hashlib.sha256(exe.read_bytes()).hexdigest()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed)])
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        session = mgr.get(sid)
        main = next(f for f in api.read(f"/api/rizin/{sid}/functions") if f["name"] == "sym.main")["offset"]
        ops = api.read(f"/api/rizin/{sid}/disasm?addr={main}&count=60")["ops"]
        original = api.read(f"/api/rizin/{sid}/hex?addr={main}&len=2")["bytes"]

        # one row per write operation, with the bytes that were there before it
        assert api.read(f"/api/rizin/{sid}/patches") == {"patches": [], "waiting": [], "restore": {"actions": 0, "reason": None, "digests": 0, "refused": _NO_RECORD}}
        answer = api.send(f"/api/rizin/{sid}/patch", {"addr": main, "bytes": "9090"})
        assert answer["patches"] == [{"addr": main, "size": 2, "before": bytes(original).hex(),
                                      "after": "9090", "mine": True, "over_run": False}]
        # rizin 0.9.1 prints the rows without the [] of an array, so wcj is read as text, not as JSON
        assert session.text("wcj").strip().startswith('{"idx":0,')
        # and the patch shows through px: HEX and DISASSEMBLY need no plumbing of their own
        assert api.read(f"/api/rizin/{sid}/hex?addr={main}&len=2")["bytes"] == [0x90, 0x90]

        # a kind computes the bytes from the instruction there; a call is nopped over its whole length
        call = next(op for op in ops if op["type"].endswith("call"))
        call_bytes = api.read(f"/api/rizin/{sid}/hex?addr={call['offset']}&len={call['size']}")["bytes"]
        api.send(f"/api/rizin/{sid}/patch", {"addr": call["offset"], "kind": "nocall"})
        nopped = api.read(f"/api/rizin/{sid}/hex?addr={call['offset']}&len={call['size']}")["bytes"]
        assert nopped == [0x90] * call["size"]
        patched = api.read(f"/api/rizin/{sid}/disasm?addr={call['offset']}&count=60")["ops"]
        assert next(op for op in patched if op["offset"] == call["offset"])["type"] == "nop"

        # flip and always against the binary: the two kinds that would silently invert what the analyst
        # asked for. rizin reads the bytes back as the opposite jump, and as a jump to the same address.
        jump = next(op for op in ops if op["type"] == "cjmp")
        api.send(f"/api/rizin/{sid}/patch", {"addr": jump["offset"], "kind": "flip"})
        flipped = next(op for op in api.read(
            f"/api/rizin/{sid}/disasm?addr={jump['offset']}&count=60")["ops"] if op["offset"] == jump["offset"])
        assert flipped["type"] == "cjmp" and flipped["jump"] == jump["jump"], "the same target"
        assert flipped["text"].split(" ")[0] != jump["text"].split(" ")[0], (jump["text"], flipped["text"])
        api.send(f"/api/rizin/{sid}/patch", {"addr": jump["offset"], "kind": "always"})
        always = next(op for op in api.read(
            f"/api/rizin/{sid}/disasm?addr={jump['offset']}&count=60")["ops"] if op["offset"] == jump["offset"])
        assert always["type"] == "jmp" and always["jump"] == jump["jump"], (always, jump)
        assert always["size"] <= jump["size"], "the patch is no longer than the instruction it covers"
        api.remove(f"/api/rizin/{sid}/patch", {"addr": jump["offset"]})

        # what a run writes lands in the same cache and stays the run's: a step into a call pushes the
        # return address, and that write is one row of the cache too (measured)
        watchdog = next(f for f in api.read(f"/api/rizin/{sid}/functions")
                        if f["name"] == "sym.watchdog")["offset"]
        into = next(op for op in api.read(f"/api/rizin/{sid}/disasm?addr={watchdog}&count=20")["ops"]
                    if op["type"].endswith("call"))
        api.send(f"/api/rizin/{sid}/emulation/start", {"addr": into["offset"]})
        api.send(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
        rows = api.read(f"/api/rizin/{sid}/patches")["patches"]
        assert [r["mine"] for r in rows if r["addr"] in (main, call["offset"])] == [True, True]
        run = [r for r in rows if not r["mine"]]
        assert run and all(r["addr"] >= rizin_sessions.ESIL_STACK_ADDR for r in run), rows
        assert [r["size"] for r in run] == [8], "one row for the one eight-byte write, not eight rows"

        # the one write rizin refuses: the highest address of all (rz_core_write_at asserts on UT64_MAX)
        refused = api.post(f"/api/rizin/{sid}/patch", {"addr": "0xffffffffffffffff", "bytes": "90"})
        assert refused.status_code == 400 and "0xffffffffffffffff" in refused.get_json()["refused"]

        # take one back: only that one goes, and the bytes under it are the file's again
        taken = api.remove(f"/api/rizin/{sid}/patch", {"addr": main})
        assert [r["addr"] for r in api.read(f"/api/rizin/{sid}/patches")["patches"] if r["mine"]] == [call["offset"]]
        assert api.read(f"/api/rizin/{sid}/hex?addr={main}&len=2")["bytes"] == original
        assert taken["run_removed"] == [], "nothing of the run's was at that address"
        # and all of them: the run's bytes too, because rizin has one cache, and the answer names them
        assert api.remove(f"/api/rizin/{sid}/patch", {}) == {
            "patches": [], "run_removed": [{"addr": r["addr"], "size": r["size"]} for r in run]}
        assert session.text("wcj").strip() == ""
        assert api.read(f"/api/rizin/{sid}/hex?addr={call['offset']}&len={call['size']}")["bytes"] == call_bytes
    finally:
        mgr.shutdown()
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == before, "the sample must never be written"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_runs_an_emulation(tmp_path, monkeypatch):
    """The start sequence and every run kind against rizin 0.9.1 itself: what the fake models.

    sym.watchdog is `sub rsp, 0x28; mov ecx, 90000; call qword [Sleep]; ...`: a call through the import
    table, whose callee rizin's emulation cannot run (the import table holds RVAs, nothing is mapped there).
    """
    import rizin_sessions

    exe = _build_pipesim(tmp_path)
    before = hashlib.sha256(exe.read_bytes()).hexdigest()
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        opened = mgr.open(str(exe), "tab")
        session = mgr.get(opened["session"])
        assert _wait_state(session, "done", timeout=120)["state"] == "done"
        watchdog = next(f["offset"] for f in session.json("aflj") if f["name"] == "sym.watchdog")
        ops = session.json(f"pdfj @ {watchdog:#x}")["ops"]
        call = next(op for op in ops if op["type"].endswith("call"))
        assert call["type"] == "ircall", "call qword [import]: the call that aecc, aess and aeso mishandle"
        after_call = call["offset"] + call["size"]

        def register(state, name):
            return _word(next(r["value"] for r in state["registers"] if r["name"] == name))

        # start: the PC is where it was asked, the stack is mapped around rsp, nothing has stopped yet
        state = session.emulation_start(watchdog)
        assert state["pc"] == hex(watchdog) and state["running"] is True and state["stopped"] is None
        assert len(state["stack"]) == rizin_sessions.RIZIN_STACK_ROWS
        sp = register(state, "rsp")
        assert rizin_sessions.ESIL_STACK_ADDR < sp < rizin_sessions.ESIL_STACK_ADDR + rizin_sessions.ESIL_STACK_SIZE

        # step: the PC moves as rizin moves it, and says why it stopped
        state = session.emulation_run("step")
        assert state["pc"] == hex(ops[1]["offset"]) and state["stopped"] == "step" and "rip" in state["changed"]
        assert register(state, "rsp") == sp - 0x28
        state = session.emulation_run("step")
        assert state["pc"] == hex(call["offset"]) and register(state, "rcx") == 90000
        assert "rcx" in state["changed"]
        # to_call: stops before the call through the import table (aecc runs past it); until does as well
        session.emulation_start(watchdog)
        state = session.emulation_run("to_call")
        assert state["pc"] == hex(call["offset"]) and state["stopped"] == "step"
        session.emulation_start(watchdog)
        assert session.emulation_run("until", call["offset"])["pc"] == hex(call["offset"])

        # skip passes the call, which the server has to do itself for call qword [import]
        state = session.emulation_run("skip")
        assert state["pc"] == hex(after_call) and state["stopped"] == "step"
        assert register(state, "rsp") == sp - 0x28, "nothing was called, so nothing was pushed"

        # a step into the call ends where nothing is mapped: named, not shown as a result
        session.emulation_start(watchdog)
        session.emulation_run("until", call["offset"])
        state = session.emulation_run("step")
        assert state["pc"] != hex(after_call) and _word(state["pc"]) < 0x100000 and state["stopped"] == "trap"
        state = session.emulation_run("step")  # rizin says it now, on stderr
        assert state["stopped"] == "trap"
        # over a call through the import table runs it (aeso would step into it: the same place)
        session.emulation_start(watchdog)
        session.emulation_run("until", call["offset"])
        assert session.emulation_run("over")["stopped"] == "trap"

        # cont: a breakpoint it stands on is not hit again (rizin runs the instruction first), the next is
        session.emulation_start(watchdog)
        session.console(f"db @ {watchdog:#x}")
        session.console(f"db @ {call['offset']:#x}")
        state = session.emulation_run("cont")
        assert state["pc"] == hex(call["offset"]) and state["stopped"] == "breakpoint"
        state = session.emulation_run("cont")  # on into the call: nothing can execute there
        assert state["stopped"] == "trap" and state["pc"] != hex(call["offset"])
        # dbd lists the breakpoint as disabled, and rizin 0.9.1 stops at it all the same: only db- removes
        # one. The fake models this and Tasks 4 and 11 drop their on/off because of it.
        session.emulation_start(watchdog)
        session.console(f"dbd @ {call['offset']:#x}")
        assert [b["enabled"] for b in session.json("dblj") if b["addr"] == call["offset"]] == [False]
        state = session.emulation_run("cont")
        assert state["pc"] == hex(call["offset"]) and state["stopped"] == "breakpoint"
        session.console(f"db- @ {call['offset']:#x}")
        assert [b["addr"] for b in session.json("dblj")] == [watchdog]
        session.console(f"db- @ {watchdog:#x}")

        # an endless loop (written into the cache): cont stops at esil.timeout, to_call at its own deadline;
        # the session goes on
        monkeypatch.setattr(rizin_sessions, "ESIL_TIMEOUT", 1.0)
        monkeypatch.setattr(rizin_sessions, "ESIL_SETTINGS", tuple(
            "esil.timeout=1" if c.startswith("esil.timeout=") else c for c in rizin_sessions.ESIL_SETTINGS))
        session.emulation_start(watchdog)
        session.console(f"wx ebfe @ {watchdog:#x}")
        started = time.monotonic()
        state = session.emulation_run("cont")
        assert state["stopped"] == "timeout" and state["pc"] == hex(watchdog)
        assert 0.9 < time.monotonic() - started < 10
        state = session.emulation_run("to_call")
        assert state["stopped"] == "timeout" and state["pc"] == hex(watchdog)
        assert session.emulation_state()["running"] is True
        assert session.json("ij")["core"]["file"] == str(exe)
    finally:
        mgr.shutdown()
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == before, "the sample must never be written"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_keeps_a_patch_and_a_breakpoint_in_the_project(tdc, tmp_path, monkeypatch):
    """A patch and a breakpoint made in one rizin 0.9.1 session are in effect again in the next one.

    Only the binary can show this: the project goes through rizin's own ``Ps`` and ``Poo``, and what the
    project does and does not hold is the whole reason the /tdc namespace exists. Measured on 0.9.1:
    ``Ps`` writes no cache row at all, so the patches live in /tdc, but it *does* write
    /core/debug/breakpoints, so the breakpoints come back through rizin itself.
    """
    import rizin_sessions

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    before = hashlib.sha256(exe.read_bytes()).hexdigest()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed)])
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    project = tmp_path / "projects" / (hashlib.sha256(exe.read_bytes()).hexdigest() + ".rzdb")
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        main = next(f for f in api.read(f"/api/rizin/{sid}/functions") if f["name"] == "sym.main")["offset"]
        ops = api.read(f"/api/rizin/{sid}/disasm?addr={main}&count=60")["ops"]
        size, stop = ops[0]["size"], ops[1]["offset"]
        nops = "90" * size
        original = api.read(f"/api/rizin/{sid}/hex?addr={main}&len={size}")["bytes"]
        api.send(f"/api/rizin/{sid}/patch", {"addr": main, "kind": "nop"})
        api.send(f"/api/rizin/{sid}/breakpoints", {"addr": stop})
        # a run's bytes land in the same cache, and they are the ones that must not be written: a step
        # on a call pushes the return address, which is one row of the cache (measured)
        call = next(op for op in ops if op["type"].endswith("call"))
        api.send(f"/api/rizin/{sid}/emulation/start", {"addr": call["offset"]})
        api.send(f"/api/rizin/{sid}/emulation/run", {"kind": "step"})
        run = [r for r in api.read(f"/api/rizin/{sid}/patches")["patches"] if not r["mine"]]
        assert run, "the step wrote nothing into the cache"
        api.close(sid)
        assert wait_for(lambda: project.exists()), "the patch wrote no project"

        saved = project.read_text(encoding="utf-8", errors="surrogateescape")
        tdc_namespace = saved.split("\n/tdc\n")[-1]
        assert f"\npatches={main:x}:{nops}\n" in saved
        for row in run:
            assert f"{row['addr']:x}:" not in tdc_namespace, "a run's bytes must not be saved"
        assert len(tdc_namespace) < 1024, "the /tdc namespace holds the hand patches, not a run's cache"
        # rizin keeps the breakpoints itself, which is why /tdc carries only the patches
        assert f"{stop:#x}=" in saved.split("\n/core/debug/breakpoints\n")[1].split("\n/")[0]
        assert '"before":' not in saved and '"after":' not in saved, "Ps saves no write cache"

        # R24: arm the project's breakpoint with the command and the condition rizin runs when it hits
        # (dbc/dbC, which Poo brings back and nothing in the API would show), and they must be gone
        _plant_breakpoint_command(project, stop, "CC pwned", "e asm.arch=x86.nasm")

        sid = api.open(str(exe))["session"]
        session = mgr.get(sid)
        assert [(b["data"], b["cond"]) for b in session.json("dblj")] == [("", "")]
        assert session.text("e asm.arch").strip() == "x86", "the condition never ran"
        assert session.text(f"CC. @ {stop:#x}").strip() == "", "the command never ran"
        assert api.read(f"/api/rizin/{sid}/patches")["patches"] == [
            {"addr": main, "size": size, "before": bytes(original).hex(), "after": nops, "mine": True,
             "over_run": False}]
        # in effect, not merely listed: px reads through the cache again
        assert api.read(f"/api/rizin/{sid}/hex?addr={main}&len={size}")["bytes"] == [0x90] * size
        assert api.read(f"/api/rizin/{sid}/breakpoints") == [{"addr": stop, "enabled": True}]
        # and the breakpoint stops a run: nops from main, then the breakpoint
        api.send(f"/api/rizin/{sid}/emulation/start", {"addr": main})
        state = api.send(f"/api/rizin/{sid}/emulation/run", {"kind": "cont"})
        assert (state["pc"], state["stopped"]) == (hex(stop), "breakpoint")

        # taking it back is saved too: the next session starts with the file's own bytes
        api.remove(f"/api/rizin/{sid}/patch", {"addr": main})
        api.remove(f"/api/rizin/{sid}/breakpoints", {})
        api.close(sid)
        sid = api.open(str(exe))["session"]
        assert api.read(f"/api/rizin/{sid}/patches")["patches"] == []
        assert api.read(f"/api/rizin/{sid}/breakpoints") == []
        assert api.read(f"/api/rizin/{sid}/hex?addr={main}&len={size}")["bytes"] == original
    finally:
        mgr.shutdown()
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == before, "the sample must never be written"


RZ_ASM = shutil.which("rz-asm") or ("/opt/homebrew/bin/rz-asm"
                                   if os.path.exists("/opt/homebrew/bin/rz-asm") else None)


def _assemble(text, at):
    out = subprocess.run([RZ_ASM, "-a", "x86", "-b", "64", "-o", hex(at), text],
                         capture_output=True, text=True, check=True)
    return bytes.fromhex(out.stdout.strip())


def _decryptor_blob(path):
    """A blob whose code at 0 decrypts 0x40 bytes at 0x1000 (one XOR with 0xff, byte by byte) and stops
    at 0x19.

    Decrypted, those bytes begin a function -- `stc; push rbp; mov rbp, rsp; call 0x8000; jmp 0x1040` --
    and hold the string "DecryptedSecretString". Encrypted, the first byte is 0x06, which x86-64 cannot
    decode, so rizin finds neither a function nor a string there before the run.

    Two addresses outside the range make the bound measurable: the function's **tail** (`pop rbp; ret`)
    sits at 0x1040, plaintext in the file and one byte past the range, so a re-analysis without slack
    truncates the function; the call's target is at 0x8000, far past the slack, where af must not reach.
    Every byte assembled with rz-asm.
    """
    plain = (_assemble("stc", 0x1000) + _assemble("push rbp", 0x1001)
             + _assemble("mov rbp, rsp", 0x1002) + _assemble("call 0x8000", 0x1005)
             + _assemble("jmp 0x1040", 0x100A))
    plain = plain.ljust(0x20, b"\x00") + b"DecryptedSecretString\x00"
    plain = plain.ljust(0x40, b"\x00")
    code = _assemble("mov rcx, 0x40", 0) + _assemble("mov rsi, 0x1000", 7)
    loop = _assemble("xor byte [rsi], 0xff", 0xE) + _assemble("inc rsi", 0x11)
    loop += _assemble("dec rcx", 0x14) + _assemble("jnz 0xe", 0x17)
    blob = bytearray(b"\xcc" * 0x9000)
    blob[0:len(code + loop)] = code + loop
    assert len(code + loop) == 0x19, (code + loop).hex()
    blob[0x1000:0x1040] = bytes(b ^ 0xFF for b in plain)
    blob[0x1040:0x1042] = _assemble("pop rbp", 0x1040) + _assemble("ret", 0x1041)
    blob[0x8000:0x8003] = _assemble("xor eax, eax", 0x8000) + _assemble("ret", 0x8002)
    path.write_bytes(bytes(blob))
    return 0x19


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not RZ_ASM, reason="rz-asm not installed")
def test_real_rizin_reanalyses_what_a_run_decrypted(tmp_path):
    """The whole point of the feature, against the binary: a real decryption loop runs in rizin's ESIL,
    its bytes land in the write cache, and the re-analysis then finds a function and a string that rizin
    could not find while they were still encrypted. Only the binary can show that -- the fake can replay
    no more than what it was told."""
    import rizin_sessions

    blob = tmp_path / "decryptor.bin"
    stop = _decryptor_blob(blob)
    before_sha = hashlib.sha256(blob.read_bytes()).hexdigest()
    project = tmp_path / "projects" / (before_sha + ".rzdb")
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        # rizin takes a raw blob for the host's arch (avr here), so the arch is set as the flood test
        # does, and that wrong-arch analysis is dropped -- its functions *and* its references: a
        # reference to an address with no function there makes af create one even outside
        # analysis.limits (measured; on a real PE after a full aaa the limits hold, also measured).
        # The before/after below is then rizin's reading of these bytes and nothing else.
        session.console("e asm.arch=x86")
        session.console("e asm.bits=64")
        session.console("af-*")
        session.console("ax-*")

        # before: 0x1000 holds no instruction rizin can decode, no function and no string
        # (rizin 0.9.1's pdj leaves a byte it cannot decode without a "type": only opcode "invalid")
        assert session.text("pdj 1 @ 0x1000").count('"opcode":"invalid"') == 1
        assert session.reanalyze(0x1000, 0x103F) == {"start": 0x1000, "end": 0x103F,
                                                     "functions": 0, "strings": 0}
        assert session.run_range() is None, "nothing has run yet"

        # the decryption loop, in rizin's own ESIL
        session.emulation_start(0)
        state = session.emulation_run("until", stop)
        assert (state["stopped"], state["pc"]) == ("step", hex(stop))
        rows = [r for r in session.patches()["patches"] if not r["mine"]]
        assert len(rows) == 0x40 and {r["size"] for r in rows} == {1}, "one cache row per decrypted byte"
        assert session.run_range() == (0x1000, 0x103F), "the range comes from the cache, measured"

        # and now rizin finds what the run wrote: a function, and a string
        assert session.reanalyze() == {"start": 0x1000, "end": 0x103F, "functions": 1, "strings": 1}
        assert "stc" in session.text("pd 1 @ 0x1000"), session.text("pd 1 @ 0x1000")
        # 66 bytes, not 12: the function's tail at 0x1040 is past the range, and analysis.limits
        # truncates the function it cuts (measured), which is what REANALYZE_SLACK leaves room for
        assert session.text("afl").split()[:4] == ["0x00001000", "2", "66", "->"], session.text("afl")
        # again, and it is still one: rizin's af leaves a function that is there alone (measured), so
        # without taking the range's functions out first a second re-analysis would find nothing at all
        assert session.reanalyze() == {"start": 0x1000, "end": 0x103F, "functions": 1, "strings": 1}
        assert session.text("afl").split()[:3] == ["0x00001000", "2", "66"], session.text("afl")
        # bounded: af follows the call at 0x1005, and the limits stop it at the range plus the slack,
        # well before its target at 0x8000
        assert "0x00008000" not in session.text("afl")
        assert session.reanalyze(0x1000, 0x8002)["functions"] >= 1
        assert "0x00008000" in session.text("afl"), "and with the range around it, af does make one"

        # the string is a flag of its own, which is how STRINGS, FLAGS and the console's Tab see it
        assert session.text("fd @ 0x1020").strip() == "hit.string.ascii.0"

        # R25: none of it may reach the project. rizin's Ps keeps the function and the flag (measured),
        # so the save drops what rests on bytes only the run wrote. A breakpoint is what makes a
        # project be written at all here -- exactly the later save that would carry the leak.
        assert session.reanalyze(0x8000, 0x8002) == {"start": 0x8000, "end": 0x8002,
                                                     "functions": 1, "strings": 0}
        session.breakpoint_set(0x8000)
        assert session.flush() is True
        saved = project.read_text(encoding="utf-8", errors="surrogateescape")
        functions = _project_namespace(saved, "/core/analysis/functions")
        assert "0x1000" not in functions, sorted(functions)
        assert "0x8000" in functions, "a function over bytes that are in the file is no leak"
        assert "hit.string.ascii.0" not in _project_namespace(saved, "/core/flags/flags")
        assert "patches=\n" in saved, "nothing was patched by hand"
        clean = tmp_path / "clean.rzdb"
        clean.write_bytes(project.read_bytes())  # the project as this leak-free save left it

        # and the self-correcting half: a patch of this session over the function's first byte, so
        # those bytes do come back when the file is opened again -- then the function may stay
        session.patch(0x1000, b"\xf9")
        assert session.flush() is True
        saved = project.read_text(encoding="utf-8", errors="surrogateescape")
        assert "0x1000" in _project_namespace(saved, "/core/analysis/functions")
        assert "patches=1000:f9" in saved
    finally:
        mgr.shutdown()
    assert hashlib.sha256(blob.read_bytes()).hexdigest() == before_sha, "the sample must never be written"

    # the untouched sample opened again with that project: no function over the run's bytes
    second = tmp_path / "projects2"
    second.mkdir()
    shutil.copy(str(clean), str(second / (before_sha + ".rzdb")))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(second))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        assert session.analysis["note"] == "Restored from the saved project."
        listed = session.text("afl")
        assert "0x00001000" not in listed, listed
        assert "0x00008000" in listed, "and the one over the file's own bytes is still there"
        assert session.text("fd @ 0x1020").strip() != "hit.string.ascii.0"
        assert '"opcode":"invalid"' in session.text("pdj 1 @ 0x1000"), "the bytes are encrypted again"
    finally:
        mgr.shutdown()
    assert hashlib.sha256(blob.read_bytes()).hexdigest() == before_sha, "the sample must never be written"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not RZ_ASM, reason="rz-asm not installed")
def test_real_rizin_a_patch_over_a_runs_bytes_would_be_xored_again(tmp_path):
    """Why the patch is held back, measured on the binary: a patch written into the file's own (still
    encrypted) bytes **before** the decryption runs is decrypted over -- it is neither there afterwards nor
    is the byte what the file would have decrypted to. That is what _replay_patches did when it ran at the
    start of a session; held back, the second run decrypts the file's own byte and the patch is not lost."""
    import rizin_sessions

    blob = tmp_path / "decryptor.bin"
    stop = _decryptor_blob(blob)
    sha = hashlib.sha256(blob.read_bytes()).hexdigest()
    plain, encrypted, patch = 0xF9, 0x06, 0x90  # `stc` at 0x1000, the file's byte there, and a nop

    def first_byte(session):
        return session.json("pxj 1 @ 0x1000")[0]

    def run_decryptor(session):
        session.console("e asm.arch=x86")
        session.console("e asm.bits=64")
        session.emulation_start(0)
        state = session.emulation_run("until", stop)
        assert (state["stopped"], state["pc"]) == ("step", hex(stop))

    # what the old replay did: the patch is in the cache before the run, and the run xors over it
    before_dir = tmp_path / "before"
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(before_dir))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        assert first_byte(session) == encrypted
        session.patch(0x1000, bytes([patch]))
        assert first_byte(session) == patch
        run_decryptor(session)
        assert first_byte(session) == patch ^ 0xFF, "the run xored over the patch's byte"
        assert first_byte(session) not in (patch, plain), "the patch is gone and the decrypted byte is wrong"
    finally:
        mgr.shutdown()

    # the real order, and the fix: run, then patch over what the run wrote, save, open again
    projects = tmp_path / "projects"
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(projects))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        run_decryptor(session)
        assert first_byte(session) == plain
        session.patch(0x1000, bytes([patch]))
        row = next(r for r in session.patches()["patches"] if r["mine"])
        assert (row["addr"], row["over_run"], row["before"]) == (0x1000, True, f"{plain:02x}")
        assert session.flush() is True
    finally:
        mgr.shutdown()
    saved = (projects / (sha + ".rzdb")).read_text(encoding="utf-8", errors="surrogateescape")
    assert "\npatches=1000:90:r\n" in saved

    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(projects))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        answer = session.patches()
        assert answer["patches"] == [], "not written into the file's bytes"
        assert [(w["addr"], w["after"]) for w in answer["waiting"]] == [(0x1000, "90")]
        assert "Held back" in session.analysis["note"] and "0x1000" in session.analysis["note"]
        assert first_byte(session) == encrypted, "the file's own byte is still what rizin reads"
        run_decryptor(session)
        assert first_byte(session) == plain, "the decryption is right where the analyst wanted to read"
    finally:
        mgr.shutdown()
    assert hashlib.sha256(blob.read_bytes()).hexdigest() == sha, "the sample must never be written"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not RZ_ASM, reason="rz-asm not installed")
def test_real_rizin_the_digest_covers_the_bytes_a_patch_sits_on(tmp_path):
    """The facts run_digests rests on, measured on the binary: ``run_only_ranges`` loses the bytes under a
    patch, the cache lists the writes in the order they were made in (``patches_made``; the list by
    address does not), and a patch over a run's byte leaves the run's byte in its row's ``before`` while
    the cache reads the patch. The digest must be the SHA-256 of the bytes the run decrypted -- worked out
    here from the file and the key, not from rizin -- patch or no patch."""
    import rizin_emulation
    import rizin_sessions

    blob = tmp_path / "decryptor.bin"
    stop = _decryptor_blob(blob)
    plain = bytes(b ^ 0xFF for b in blob.read_bytes()[0x1000:0x1040])
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.console("e asm.arch=x86")
        session.console("e asm.bits=64")
        session.emulation_start(0)
        assert session.emulation_run("until", stop)["stopped"] == "step"
        session.patch(0x1010, b"\x90\x90")
        assert session.json("pxj 2 @ 0x1010") == [0x90, 0x90], "the cache reads the patch"

        rows = session.patches_made()
        mine = [row for row in rows if row["mine"]]
        assert [(r["addr"], r["after"], r["before"]) for r in mine] == [(0x1010, "9090", plain[0x10:0x12].hex())]
        ranges = rizin_emulation.run_only_ranges(rows)
        assert ranges == [(0x1000, 0x100F), (0x1012, 0x103F)], "the patched bytes are not in them"
        assert rizin_emulation.run_digests(rows, ranges) == [
            {"start": 0x1000, "end": 0x103F, "sha256": hashlib.sha256(plain).hexdigest()}]

        # the order of the rows is the order of the writes, and the digest is what is left of them
        session.console("wx ee @ 0x1101")
        session.console("wx aabbccdd @ 0x1100")
        session.console("wx 11223344 @ 0x1200")
        session.console("wx 99 @ 0x1201")
        rows = session.patches_made()
        assert [r["addr"] for r in rows if not r["mine"]][-4:] == [0x1101, 0x1100, 0x1200, 0x1201]
        assert [r["addr"] for r in session.patches()["patches"] if not r["mine"]][-4:] == [
            0x1100, 0x1101, 0x1200, 0x1201], "by address, the first two have changed places"
        digests = {d["start"]: d["sha256"] for d in rizin_emulation.run_digests(
            rows, rizin_emulation.run_only_ranges(rows))}
        assert digests[0x1100] == hashlib.sha256(bytes.fromhex("aabbccdd")).hexdigest()
        assert digests[0x1200] == hashlib.sha256(bytes.fromhex("11993344")).hexdigest()
        assert session.json("pxj 4 @ 0x1100") == [0xAA, 0xBB, 0xCC, 0xDD], "and that is what rizin reads"
        assert session.json("pxj 4 @ 0x1200") == [0x11, 0x99, 0x33, 0x44]
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not RZ_ASM, reason="rz-asm not installed")
def test_real_rizin_the_emulations_stack_is_mapped_only_once_the_emulation_starts(tmp_path):
    """Why the reason of a waiting patch at an unmapped address may not say "never": ``omlj`` when the file
    is opened lists the file's maps only, and the ``mem.*`` map of ``aeim`` arrives with the emulation
    (measured on rizin 0.9.1). An address that no map holds at the open can be held by one later."""
    import rizin_emulation
    import rizin_sessions

    blob = tmp_path / "decryptor.bin"
    _decryptor_blob(blob)
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        stack = rizin_sessions.ESIL_STACK_ADDR + 0x80
        before = session.json("omlj")
        assert [m["name"] for m in before if m["name"].startswith("mem.")] == []
        assert not rizin_emulation.maps_hold(stack, 1, before)
        session.console("e asm.arch=x86")
        session.console("e asm.bits=64")
        session.emulation_start(0)
        after = session.json("omlj")
        assert [m["name"] for m in after if m["name"].startswith("mem.")] == [
            f"mem.{rizin_sessions.ESIL_STACK_ADDR:#x}_{rizin_sessions.ESIL_STACK_SIZE:#x}"]
        assert rizin_emulation.maps_hold(stack, 1, after)
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_flood_of_esil_warnings_does_not_hide_the_timeout(tmp_path, monkeypatch):
    """`int3; jmp -3`: with esil.verbose=1 rizin 0.9.1 prints "WARNING: $ returned 0" for every int3, some
    150 000 lines a second, and "esil: timeout exceeded" last. The pipe keeps the first 64 KB of stderr by
    default, which is all flood; the tail is what holds the reason."""
    import rizin_emulation
    import rizin_sessions

    blob = tmp_path / "loop.bin"
    blob.write_bytes(bytes.fromhex("cceb" "fd") + bytes(61))
    pipe = rizin_sessions.RizinPipe(REAL_RIZIN, str(blob), extra_args=("-a", "x86", "-b", "64"))
    try:
        for command in ("e io.cache=true esil.timeout=1 esil.breakoninvalid=true esil.verbose=1",
                        "aei", "aeim", "aepc 0"):
            pipe.cmd(command)
        out, err, _ = pipe.console("aec")
        assert len(err) == 64 * 1024 and "WARNING: $ returned 0" in err
        assert rizin_emulation.stop_reason(out, err) == "step", "the first 64 KB are all flood"
        pipe.cmd("aepc 0")
        out, err, _ = pipe.console("aec", tail=True)
        assert err.rstrip().endswith("WARNING: core: esil: timeout exceeded.")
        # whole lines: the slice starts anywhere, and the pipe's buffer has dropped the first lines of the
        # run altogether, so without a trim the kept text begins in the middle of a warning
        assert err.startswith("WARNING: "), repr(err[:40])
        assert set(err.splitlines()) == {"WARNING: $ returned 0",
                                         "WARNING: core: esil: timeout exceeded."}
        assert rizin_emulation.stop_reason(out, err) == "timeout"
        assert pipe.cmd("ar PC").split("=")[1].strip() in ("0x0000000000000000", "0x0000000000000001")
    finally:
        pipe.close()

    # and through the session: every run kind that reads stderr says "timeout", not "step"
    monkeypatch.setattr(rizin_sessions, "ESIL_TIMEOUT", 1.0)
    monkeypatch.setattr(rizin_sessions, "ESIL_SETTINGS", tuple(
        "esil.timeout=1" if c.startswith("esil.timeout=") else c for c in rizin_sessions.ESIL_SETTINGS))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.console("e asm.arch=x86")  # rizin takes a raw blob for arm64
        session.console("e asm.bits=64")
        session.bits = 64
        session.emulation_start(0)
        for kind, addr in (("cont", None), ("to_call", None), ("until", 0x20)):
            state = session.emulation_run(kind, addr)
            assert state["stopped"] == "timeout" and _word(state["pc"]) in (0, 1), kind
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_assists_an_api_call(tmp_path):
    """The assistant against rizin 0.9.1 itself, on a 64-bit PE: what the fake models for it.

    Measured here and relied on everywhere: `call qword [sym.imp.KERNEL32.dll_Sleep]` is type ircall and
    carries the import table's slot in ``ptr`` (pdj has no "mnemonic" in 0.9.1), the flag at that slot
    is the import's name, and under win64 nothing has to be done to the stack.
    """
    import rizin_emulation
    import rizin_sessions

    exe = _build_pipesim(tmp_path)
    before = hashlib.sha256(exe.read_bytes()).hexdigest()
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(exe), "tab")["session"])
        assert _wait_state(session, "done", timeout=120)["state"] == "done"
        watchdog = next(f["offset"] for f in session.json("aflj") if f["name"] == "sym.watchdog")
        call = next(op for op in session.json(f"pdfj @ {watchdog:#x}")["ops"]
                    if op["type"].endswith("call"))
        assert call["type"] == "ircall" and isinstance(call.get("ptr"), int), call
        assert "mnemonic" not in call, "rizin 0.9.1's pdj names none: the name comes from the flag"
        assert session.json(f"fd.j @ {call['ptr']:#x}")[0]["name"].endswith("_Sleep")

        # Sleep: named, no value (it returns none), and nothing to correct under win64
        session.emulation_start(call["offset"])
        assist = session.call_assist(call["offset"])
        assert set(assist) == {"supported", "reason", "api", "ret_reg", "value", "stack_fix", "summary"}
        assert assist["supported"] is True and assist["api"] == "Sleep"
        assert assist["ret_reg"] == "rax" and assist["value"] is None and assist["stack_fix"] == 0
        # the skip lands after the call -- aess would run into the callee (R18) -- and sets the register
        sp = _word(next(r["value"] for r in session.emulation_state()["registers"] if r["name"] == "rsp"))
        state = session.call_skip(call["offset"], 0x41, 0)
        assert state["pc"] == hex(call["offset"] + call["size"]) and state["stopped"] == "step"
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "rax")) == 0x41
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "rsp")) == sp, \
            "nothing was called, so nothing was pushed and nothing is corrected"

        # a rising clock, where the file really calls GetTickCount
        main = next(f["offset"] for f in session.json("aflj") if f["name"] == "sym.main")
        main_ops = session.json(f"pdfj @ {main:#x}")["ops"]
        tick_call = next(op for op in main_ops if "GetTickCount" in op.get("disasm", "")
                         and op["type"].endswith("call"))
        session.emulation_start(tick_call["offset"])
        first = session.call_assist(tick_call["offset"])
        assert first["api"] == "GetTickCount" and _word(first["value"]) > rizin_emulation.TICK_START
        assert session.call_assist(tick_call["offset"])["value"] == first["value"], \
            "R38: a look does not move the clock"
        applied = session.call_skip(tick_call["offset"], _word(first["value"]), 0)
        assert next(r["value"] for r in applied["registers"] if r["name"] == "rax") == first["value"]
        session.emulation_register("rip", tick_call["offset"])
        assert session.call_assist(tick_call["offset"])["value"] == hex(_word(first["value"]) + rizin_emulation.TICK_STEP)

        # an import the table does not know is named all the same, with no value
        pipe_call = next(op for op in main_ops if "CreateNamedPipe" in op.get("disasm", "")
                         and op["type"].endswith("call"))
        unknown = session.call_assist(pipe_call["offset"])
        assert unknown["supported"] is True and unknown["value"] is None
        assert unknown["api"].endswith("CreateNamedPipeA") and "does not know" in unknown["summary"]

        # where there is no call, both refuse
        with pytest.raises(rizin_sessions.RizinRefused):
            session.call_assist(watchdog)
        with pytest.raises(rizin_sessions.RizinRefused):
            session.call_skip(watchdog)
    finally:
        mgr.shutdown()
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == before, "the sample must never be written"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_assists_a_32_bit_stdcall_call(tmp_path):
    """Review Focus 1 and R35 against rizin 0.9.1 itself, on 32-bit code: this is the half of the
    assistant that nothing else proves, and x86_64-w64-mingw32-gcc cannot build a 32-bit PE (measured:
    its -m32 link fails on an incompatible libkernel32.a), so the file is a raw blob whose arch and
    bits are set after it is opened -- a blob gets one r-x map and runs (Task 3 measured that).

    Four measurements the fake models: ``call dword [<slot>]`` is type **ucall** (not ircall) and
    carries the slot in ``ptr``; with the PC **on** the call the return address is not pushed yet, so
    argument i is at [esp + 4*i]; ``aeim <addr> <size> <name>`` maps beside the stack but moves the PC
    and the stack and base pointer into the new map; and ``ar SP=<value>`` takes the role name.
    """
    import rizin_emulation
    import rizin_sessions

    # push 0x40; push 0x1000; push 0x200; push 0; call dword [0x100]  (VirtualAlloc, stdcall, 4 arguments)
    # push 8; push 0x180; push 0x1c0; call dword [0x104]              (memcpy, cdecl, 3 arguments)
    # every instruction checked with rz-asm (-d -a x86 -b 32)
    code = bytes.fromhex("6a40680010000068000200006a00" "ff1500010000"
                         "6a08688001000068c0010000" "ff1504010000" "90c3")
    alloc_call, copy_start, copy_call, after_copy = 0xE, 0x14, 0x20, 0x26
    blob = bytearray(0x200)
    blob[:len(code)] = code
    blob[0x180:0x188] = b"unpacked"
    (tmp_path / "call32.bin").write_bytes(bytes(blob))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(tmp_path / "call32.bin"), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.text("e asm.arch=x86")       # rizin takes a raw blob for the host's arch
        session.text("e asm.bits=32")
        session.arch, session.bits = "x86", 32
        session.text("f sym.imp.KERNEL32.dll_VirtualAlloc @ 0x100")
        session.text("f sym.imp.msvcrt.dll_memcpy @ 0x104")
        op = session.json(f"pdj 1 @ {alloc_call:#x}")[0]
        assert op["type"] == "ucall" and op["ptr"] == 0x100, "32 bits: ucall, with the slot in ptr"

        # the four pushes, then the PC stands on the call and the arguments are at [esp + 4*i]
        session.emulation_start(0)
        for _ in range(4):
            assert session.emulation_run("step")["stopped"] == "step"
        state = session.emulation_state()
        sp = _word(next(r["value"] for r in state["registers"] if r["name"] == "esp"))
        bp = _word(next(r["value"] for r in state["registers"] if r["name"] == "ebp"))
        assert state["pc"] == hex(alloc_call)
        assert [_word(row["value"]) for row in state["stack"][:4]] == [0, 0x200, 0x1000, 0x40], \
            "argument i sits at [esp + 4*i] while the PC is on the call"

        assist = session.call_assist(alloc_call)
        assert assist["api"] == "VirtualAlloc" and assist["ret_reg"] == "eax"
        assert assist["stack_fix"] == 16, "a stdcall callee clears its four arguments"
        assert _word(assist["value"]) == rizin_emulation.ASSIST_ADDR, "a buffer clear of the file and the stack"
        assert "4096 bytes" in assist["summary"], assist["summary"]

        state = session.call_skip(alloc_call, _word(assist["value"]), assist["stack_fix"])
        assert state["pc"] == hex(alloc_call + 6) and state["stopped"] == "step"
        assert next(r["value"] for r in state["registers"] if r["name"] == "eax") == assist["value"]
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "esp")) == sp + 16
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "ebp")) == bp, \
            "aeim put the base pointer into its new map; the skip put it back"
        # the buffer is there, the stack aeim mapped at the start is still the stack, and the PC did not
        # go to the seek -- all three of which a bare aeim would have broken
        maps = {m["name"]: (m["from"], m["to"]) for m in session.json("omlj")}
        assert maps["mem.assist"] == (_word(assist["value"]), _word(assist["value"]) + 0x1000), maps
        assert state["stack"] and any(name.startswith("mem.0x") for name in maps), maps
        session.text(f"wx 41424344 @ {_word(assist['value']):#x}")
        assert session.json(f"pxj 4 @ {_word(assist['value']):#x}") == [0x41, 0x42, 0x43, 0x44]

        # and the copy a cdecl memcpy stands for really happens, with no correction to the stack
        session.emulation_start(copy_start)
        for _ in range(3):
            session.emulation_run("step")
        copy = session.call_assist(copy_call)
        assert copy["api"] == "memcpy" and copy["value"] == "0x1c0" and copy["stack_fix"] == 0
        assert "8 bytes" in copy["summary"], copy["summary"]
        state = session.call_skip(copy_call, _word(copy["value"]), 0)
        assert state["pc"] == hex(after_copy)
        assert bytes(session.json("pxj 8 @ 0x1c0")) == b"unpacked", "the copy is really made"
        assert [row["mine"] for row in session.patches()["patches"] if row["addr"] == 0x1C0] == [False], \
            "what the copy wrote belongs to the run, not to the patches"
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_gives_the_emulations_memory_back(tmp_path):
    """R37(a) against rizin 0.9.1 itself, which is where the mechanism had to change.

    Measured here, three ways: ``aeim-`` gives the region of the most recent ``aeim`` back and can then
    name nothing at all ("cannot deinitialize mem.0x10000000_0xf0000"), so the emulation's **stack**
    stays mapped for good once the assistant has mapped a buffer -- whether the buffers went first with
    ``om-``, with ``o-`` or not at all. ``om-`` unmaps without freeing (``ol`` keeps the malloc://
    entry). Closing the descriptors (``o- <fd>``, what the server does) unmaps **and** frees, and a
    start after that maps the stack where ESIL_STACK_ADDR says, exactly like a first one.
    """
    import rizin_emulation
    import rizin_sessions

    blob = tmp_path / "sweep.bin"
    blob.write_bytes(bytes.fromhex("90" * 16 + "c3") + bytes(0x100))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.text("e asm.arch=x86")
        session.text("e asm.bits=64")
        session.arch, session.bits = "x86", 64

        # what rizin cannot do: aeim- never names the stack again once a named map has existed
        session.emulation_start(0)
        session.text(f"aeim {rizin_emulation.ASSIST_ADDR:#x} 0x1000 assist")
        mapped = [m["name"] for m in session.json("omlj") if m["name"].startswith("mem.")]
        assert len(mapped) == 2 and mapped[0].startswith("mem.0x") and mapped[1] == "mem.assist", mapped
        session.text("aeim-")          # gives the buffer back
        session.text("aeim-")          # cannot name the stack: "cannot deinitialize mem.0x..."
        session.text("aeim-")
        left = [m["name"] for m in session.json("omlj") if m["name"].startswith("mem.")]
        assert len(left) == 1 and left[0].startswith("mem.0x"), left

        # what the server does instead: a stop closes the descriptors of those maps, which unmaps the
        # memory **and** frees it
        session.text(f"aeim {rizin_emulation.ASSIST_ADDR:#x} 0x1000 assist")
        state = session.emulation_state()
        sp = _word(next(r["value"] for r in state["registers"] if r["name"] == "rsp"))
        assert session.emulation_stop() == {"running": False}
        assert [m["name"] for m in session.json("omlj") if m["name"].startswith("mem.")] == []
        assert "malloc://" not in session.text("ol"), "the memory was freed, not only unmapped"

        # and a start after that is like a first one: one stack, where ESIL_STACK_ADDR says
        again = session.emulation_start(0)
        at = _word(next(r["value"] for r in again["registers"] if r["name"] == "rsp"))
        assert rizin_sessions.ESIL_STACK_ADDR < at < rizin_sessions.ESIL_STACK_ADDR + rizin_sessions.ESIL_STACK_SIZE
        assert again["stack"], "the stack the server knows about is the one that is mapped"
        assert len([m for m in session.json("omlj") if m["name"].startswith("mem.")]) == 1
        # a start sweeps as well, so the buffers of a run before do not pile up
        session.text(f"aeim {rizin_emulation.ASSIST_ADDR:#x} 0x1000 assist")
        session.emulation_start(0)
        assert len([m for m in session.json("omlj") if m["name"].startswith("mem.")]) == 1

        # the one thing the sweep cannot reach: ``om-`` unmaps without freeing (the malloc:// entry
        # stays), and a descriptor whose map is gone is in no map list any more, so it stays open
        # until rizin ends with the session
        stack = next(m for m in session.json("omlj") if m["name"].startswith("mem.0x"))
        session.text(f"om- {stack['map']}")
        assert not [m for m in session.json("omlj") if m["name"].startswith("mem.")]
        assert f"malloc://{rizin_sessions.ESIL_STACK_SIZE}" in session.text("ol"), session.text("ol")
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_copies_more_than_one_wx_can_carry(tmp_path):
    """R36 against rizin 0.9.1 itself: a section-sized copy is the shape this is for, and it only works
    because the write is chunked.

    Measured: a ``wx`` whose command line passes about 4 KB writes **nothing at all** and says so on
    stderr only ("Cannot convert '4141…' to bin data"), which ``cmd`` never reads -- 0x500 bytes land,
    0x7ff bytes do not. So the one thing this test must show is that the bytes really arrive, over a
    length that no single ``wx`` could carry.
    """
    import rizin_emulation
    import rizin_sessions

    size = 4 * rizin_emulation.ASSIST_WRITE_CHUNK      # four chunks: no single wx could carry them
    # mov rcx, 0x50000000; mov rdx, 0x60000000; mov r8, <size>; call qword [0x2000]  (memcpy, win64);
    # every instruction checked with rz-asm (-d -a x86 -b 64)
    code = (bytes.fromhex("48b9") + (0x50000000).to_bytes(8, "little")
            + bytes.fromhex("48ba") + (0x60000000).to_bytes(8, "little")
            + bytes.fromhex("49b8") + size.to_bytes(8, "little"))
    code += bytes.fromhex("ff15") + (0x2000 - len(code) - 6).to_bytes(4, "little")
    blob = tmp_path / "copy.bin"
    blob.write_bytes(code + bytes(0x3000 - len(code)))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.text("e asm.arch=x86")
        session.text("e asm.bits=64")
        session.arch, session.bits = "x86", 64
        session.text("f sym.imp.msvcrt.dll_memcpy @ 0x2000")
        call = len(code) - 6
        state = session.emulation_start(0)
        sp = _word(next(r["value"] for r in state["registers"] if r["name"] == "rsp"))
        # two buffers of the emulation's own; each aeim moves the VM into its new map (measured), so
        # the PC and the stack pointer go back afterwards, the way call_skip does it
        session.text(f"aeim 0x50000000 {2 * size:#x} dst")
        session.text(f"aeim 0x60000000 {2 * size:#x} src")
        session.text("aepc 0")
        session.text(f"ar SP={sp:#x}")
        session.text(f"ar BP={sp:#x}")
        # the source is filled in chunks rizin does take, which is the very point being tested
        for at in range(0, size, rizin_emulation.ASSIST_WRITE_CHUNK):
            session.text(f"wx {'41424344' * (rizin_emulation.ASSIST_WRITE_CHUNK // 4)} "
                         f"@ {0x60000000 + at:#x}")
        for _ in range(3):
            session.emulation_run("step")
        assert session.emulation_state()["pc"] == hex(call)
        assert bytes(session.json(f"pxj 4 @ {0x60000000 + size - 4:#x}")) == b"ABCD", "the source is filled"
        assert bytes(session.json("pxj 4 @ 0x50000000")) != b"ABCD", "and the destination is not"

        assist = session.call_assist(call)
        assert assist["api"] == "memcpy" and assist["value"] == "0x50000000"
        assert f"{size} bytes are copied" in assist["summary"], assist["summary"]
        state = session.call_skip(call, _word(assist["value"]), 0)
        assert f"{size} bytes were copied" in state["summary"], state["summary"]
        # every chunk arrived: the first bytes, the last bytes and one in the middle
        for at in (0, size // 2, size - 4):
            assert bytes(session.json(f"pxj 4 @ {0x50000000 + at:#x}")) == b"ABCD", at
        # and one byte past the copy is untouched, so nothing ran over the end
        assert bytes(session.json(f"pxj 4 @ {0x50000000 + size:#x}")) != b"ABCD"
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_runs_code_in_a_buffer_the_assistant_mapped(tmp_path):
    """R73 against rizin 0.9.1 itself: the feature's first goal is to walk through unpacked code, and
    without this it stopped at the unpacked code's first instruction.

    Measured: ``aeim <addr> <size> assist`` makes an **rw-** map, and with ``esil.exectrap`` set *after*
    ``aei`` -- which every run does, because set before it has no effect -- a step at an address in that
    map prints "ERROR: core: esil: Trap, trying to execute on non-executable memory", leaves the PC
    where it was and runs nothing. ``omf rwx @ <addr>`` makes the same map rwx and the same instruction
    then runs. The control below is the rw- half, on the binary, so neither half is assumed.
    """
    import rizin_sessions

    # mov rdx, 0x1000 (dwSize, the second argument under win64); call qword [0x2000]
    code = bytes.fromhex("48ba") + (0x1000).to_bytes(8, "little")
    code += bytes.fromhex("ff15") + (0x2000 - len(code) - 6).to_bytes(4, "little")
    blob = tmp_path / "alloc.bin"
    blob.write_bytes(code + bytes(0x3000 - len(code)))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.text("e asm.arch=x86")
        session.text("e asm.bits=64")
        session.arch, session.bits = "x86", 64
        session.text("f sym.imp.KERNEL32.dll_VirtualAlloc @ 0x2000")
        call = len(code) - 6
        session.emulation_start(0)
        session.emulation_run("step")                       # the mov, so the size is in rdx
        assist = session.call_assist(call)
        assert assist["api"] == "VirtualAlloc" and assist["value"], assist
        buffer = _word(assist["value"])
        session.call_skip(call, buffer, 0)
        mapped = next(m for m in session.json("omlj") if m["from"] == buffer)
        assert mapped["perm"] == "rwx", f"aeim maps rw-; the server's omf has to add the x: {mapped}"

        # stage 2: the bytes of the "unpacked" code, and the PC moved into the buffer as a jmp would
        session.text(f"wx 48ffc0 @ {buffer:#x}")            # inc rax
        session.emulation_register("rax", 0)
        session.emulation_register("rip", buffer)
        state = session.emulation_run("step")
        assert state["stopped"] == "step", state["stopped"]
        assert _word(state["pc"]) == buffer + 3, "the instruction in the buffer ran"
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "rax")) == 1

        # the control: a region that only aeim made is rw-, and the same instruction traps there
        session.text("aeim 0x70000000 0x1000 control")
        assert next(m["perm"] for m in session.json("omlj") if m["from"] == 0x70000000) == "rw-"
        session.text("wx 48ffc0 @ 0x70000000")
        session.emulation_register("rax", 0)
        session.emulation_register("rip", 0x70000000)
        state = session.emulation_run("step")
        assert state["stopped"] == "trap" and _word(state["pc"]) == 0x70000000
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "rax")) == 0, \
            "rizin ran nothing there"
    finally:
        mgr.shutdown()


def _wall_address(length):
    """An address for a `wx` command line of exactly ``length`` characters: its length gives the hex an
    even number of digits, and it is high enough that a write from the same address with its last digit
    cut off (sixteen times lower) cannot reach it."""
    return 0xA000 if (length - len("wx  @ 0xA000")) % 2 == 0 else 0xA0000


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_cuts_a_command_line_at_the_wall(tmp_path):
    """R39 against rizin 0.9.1 itself: this is why a patch is bounded the way it is, and it is the one
    behaviour the fake newly models in this round.

    rizin reads its stdin a line at a time and keeps RIZIN_LINE_MAX (4094) characters of it. One
    character more and the line is cut, and what is left runs as it stands: the write lands at
    whatever address survives the cut, with nothing on stdout and nothing on stderr. So `wx` is never
    chunked (one patch is one `wcj` row, which a take-back needs) and MAX_PATCH_BYTES is what one line
    can carry instead.
    """
    import rizin_emulation
    import rizin_sessions

    blob = tmp_path / "wall.bin"
    blob.write_bytes(bytes(0x100000))
    pipe = rizin_sessions.RizinPipe(REAL_RIZIN, str(blob), extra_args=("-a", "x86", "-b", "64"))
    try:
        pipe.cmd("e io.cache=true")
        assert pipe.cmd("e io.cache").strip() == "true"
        # the largest patch the server will send: its command line is inside the wall, and it lands
        at, most = 0x2000, rizin_emulation.MAX_PATCH_BYTES
        command = f"wx {'41' * most} @ {at:#x}"
        assert len(command) <= rizin_emulation.RIZIN_LINE_MAX, len(command)
        pipe.cmd(command)
        assert pipe.cmdj(f"pxj 2 @ {at:#x}") == [0x41, 0x41]
        assert pipe.cmdj(f"pxj 2 @ {at + most - 2:#x}") == [0x41, 0x41], "all of it, not a prefix"

        # a line of exactly RIZIN_LINE_MAX characters still lands: that is what the constant claims,
        # and one character more does not (below). A line's hex must be even, so the address is picked
        # by the parity of the length under test, and far enough above its own cut (the same address
        # with its last digit gone) that a write from there cannot reach it.
        at = _wall_address(rizin_emulation.RIZIN_LINE_MAX)
        padding = rizin_emulation.RIZIN_LINE_MAX - len(f"wx  @ {at:#x}")
        assert padding % 2 == 0, padding
        exactly = f"wx {'44' * (padding // 2)} @ {at:#x}"
        assert len(exactly) == rizin_emulation.RIZIN_LINE_MAX
        pipe.cmd(exactly)
        assert pipe.cmdj(f"pxj 2 @ {at:#x}") == [0x44, 0x44], "the longest line that rizin keeps whole"
        assert pipe.cmdj(f"pxj 2 @ {at + padding // 2 - 2:#x}") == [0x44, 0x44]

        # a line of exactly one character over the wall: nothing lands where it says, and rizin says
        # nothing at all about it -- the trap this bound exists for. The address is chosen so that its
        # command overhead leaves an even number of hex digits for that length, and so that the write
        # from the **cut** address (one digit shorter, so sixteen times lower) cannot reach it.
        at = _wall_address(rizin_emulation.RIZIN_LINE_MAX + 1)
        padding = rizin_emulation.RIZIN_LINE_MAX + 1 - len(f"wx  @ {at:#x}")
        assert padding % 2 == 0, padding
        over = f"wx {'42' * (padding // 2)} @ {at:#x}"
        assert len(over) == rizin_emulation.RIZIN_LINE_MAX + 1
        out, err, _ = pipe.console(over)
        assert out.strip() == "" and err.strip() == "", (out, err)
        assert pipe.cmdj(f"pxj 2 @ {at:#x}") == [0, 0], "the bytes did not go where they were asked to"
        # they went somewhere: the row of the cut line is in the cache, at the cut address
        rows = rizin_emulation.parse_cache(pipe.cmd("wcj"))
        strays = [row for row in rows if row["after"].startswith("42")]
        assert strays and all(row["addr"] != at for row in strays), rows
        assert [row["addr"] for row in strays] == [at >> 4], "the address with its last digit cut off"
        # the pipe is still in step, and one character less lands again
        assert pipe.cmd("echo in-step").strip() == "in-step"
        inside = f"wx {'43' * ((padding - 2) // 2)} @ {at:#x}"
        assert len(inside) <= rizin_emulation.RIZIN_LINE_MAX
        pipe.cmd(inside)
        assert pipe.cmdj(f"pxj 2 @ {at:#x}") == [0x43, 0x43]
    finally:
        pipe.close()


def test_readable_takes_only_drive_paths_on_windows(tdc, monkeypatch):
    """Final review, S9: before anything resolves a path, only absolute paths go on, and on Windows only
    drive paths (X:\\...): NT paths (\\??\\UNC\\...), UNC and device paths, drive-relative and relative
    ones are refused without being resolved (resolving \\??\\UNC\\host would contact the host)."""
    import ntpath

    resolved = []
    posix_real = os.path.realpath
    with monkeypatch.context() as patch:
        patch.setattr(tdc.os.path, "realpath", lambda p, *a, **k: resolved.append(str(p)) or posix_real(p, *a, **k))
        posix = {p: tdc._readable(p) for p in ("\\??\\UNC\\host\\share\\x", "//?/UNC/host/x", "x.exe", "dir/x.exe")}
    assert posix == dict.fromkeys(posix, False) and resolved == [], (posix, resolved)

    windows_real = ntpath.realpath
    with monkeypatch.context() as patch:
        # Windows' rules on this machine: os.name and os.path as there, the folders as on the VM
        patch.setattr(tdc.os, "name", "nt")
        patch.setattr(tdc.os, "path", ntpath)
        patch.setattr(ntpath, "realpath", lambda p, *a, **k: resolved.append(str(p)) or windows_real(p, *a, **k))
        patch.setattr(tdc, "_readable_roots", lambda: ["C:\\Users"])
        paths = ("\\??\\UNC\\host\\share\\x", "/??/UNC/host/x", "//?/UNC/host/x", "\\\\host\\share\\x", "C:x",
                 "C:x\\y.exe", "\\Users\\x.exe", "x.exe", "\\??\\C:\\Users\\x.exe", "C:\\Users\\Public\\x.exe")
        windows = {p: tdc._readable(p) for p in paths}
    assert windows == dict(dict.fromkeys(paths, False), **{"C:\\Users\\Public\\x.exe": True}), windows
    assert [p for p in resolved if p != "C:\\Users"] == ["C:\\Users\\Public\\x.exe"], \
        "a path was resolved before it was refused"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_breakpoint_routes(tdc, tmp_path, monkeypatch):
    """The three routes against rizin 0.9.1 itself: what the fake models for them.

    Task 3's real-rizin test already covers that a disabled breakpoint stops a run and that only db-
    removes one; this one covers the routes (set, list, clear one, clear all) and the thing only the fake
    proves otherwise: a breakpoint set before emulation/start is honoured by the run afterwards.
    """
    import rizin_sessions

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    before = hashlib.sha256(exe.read_bytes()).hexdigest()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed)])
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        url = f"/api/rizin/{sid}/breakpoints"
        main = next(f for f in api.read(f"/api/rizin/{sid}/functions") if f["name"] == "sym.main")["offset"]
        ops = api.read(f"/api/rizin/{sid}/disasm?addr={main}&count=4")["ops"]
        first, second = ops[0]["offset"], ops[1]["offset"]

        # set and list, before any emulation was started
        assert api.read(url) == []
        assert api.send(url, {"addr": second}) == {"breakpoints": [{"addr": second, "enabled": True}]}
        assert api.send(url, {"addr": first})["breakpoints"] == [
            {"addr": first, "enabled": True}, {"addr": second, "enabled": True}]
        # the server sorts: rizin's own dblj lists them in the order they were set
        assert [b["addr"] for b in mgr.get(sid).json("dblj")] == [second, first]
        assert api.read(url) == [{"addr": first, "enabled": True}, {"addr": second, "enabled": True}]

        # and the run honours the one that was set before the start
        api.send(f"/api/rizin/{sid}/emulation/start", {"addr": first})
        state = api.send(f"/api/rizin/{sid}/emulation/run", {"kind": "cont"})
        assert state["pc"] == hex(second) and state["stopped"] == "breakpoint"
        assert api.read(url) == [{"addr": first, "enabled": True}, {"addr": second, "enabled": True}]

        # clear one, then all
        assert api.remove(url, {"addr": first}) == {"breakpoints": [{"addr": second, "enabled": True}]}
        assert api.remove(url, {}) == {"breakpoints": []}
        assert api.read(url) == [] and mgr.get(sid).json("dblj") == []

        # an address outside every map: rizin warns and sets an invalid breakpoint, which stops a run
        # all the same, so the route answers it like any other (measured: valid false, aec hits it)
        assert api.send(url, {"addr": "0x14"}) == {"breakpoints": [{"addr": 0x14, "enabled": True}]}
        assert [b["valid"] for b in mgr.get(sid).json("dblj")] == [False]
        assert api.remove(url, {}) == {"breakpoints": []}
    finally:
        mgr.shutdown()
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == before, "the sample must never be written"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_routes(tdc, tmp_path, monkeypatch):
    import rizin_sessions

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed)])
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        status = api.read("/api/rizin/status")
        assert status["installed"] and status["version"] == "0.9.1"
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        functions = api.read(f"/api/rizin/{sid}/functions")
        main = next(f for f in functions if f["name"] == "sym.main")
        assert main["nbbs"] == 30
        # The list is read from afl's text, not from aflj (2.7 KB per function there): the same functions.
        # Follow-up finding 1: aflj of a big dump is larger than the answer cap, so the tab had no list.
        session = mgr.get(sid)
        aflj = [{"name": f["name"], "offset": f["offset"], "size": f.get("size"), "nbbs": f.get("nbbs")}
                for f in session.json("aflj", timeout=rizin_sessions.CONSOLE_TIMEOUT)]
        assert len(functions) > 80
        assert functions == sorted(aflj, key=lambda f: f["offset"])
        assert len(session.text("afl", timeout=rizin_sessions.CONSOLE_TIMEOUT)) * 8 < \
            len(json.dumps(session.json("aflj", timeout=rizin_sessions.CONSOLE_TIMEOUT))), \
            "afl's text is not much smaller than aflj's JSON"

        disasm = api.read(f"/api/rizin/{sid}/disasm?addr={main['offset']}&count=2000")
        assert disasm["function"] == "sym.main" and disasm["more"] is False
        assert disasm["ops"][0]["offset"] == main["offset"] and all(op["text"] for op in disasm["ops"])
        assert any(op["type"] == "cjmp" and op["jump"] for op in disasm["ops"])
        # Outside functions: whole pages, past rizin's block of 256 bytes (rizin 0.9.1 decodes only the block and
        # then repeats a broken op, unless the command sets the block for the page: @!); it realigns at flags
        at = api.read(f"/api/rizin/{sid}/strings?limit=1")["items"][0]["offset"]
        linear = api.read(f"/api/rizin/{sid}/disasm?addr={at}&count=400")
        ops = linear["ops"]
        assert linear["function"] is None and len(ops) == 400 and linear["more"] is True, (len(ops), linear["more"])
        offsets = [op["offset"] for op in ops]
        assert offsets[0] == at and offsets == sorted(set(offsets)) and offsets[-1] - at > 256, \
            "the linear page stops at rizin's block"
        page2 = api.read(f"/api/rizin/{sid}/disasm?addr={at}&count=400&after={offsets[-1]}")["ops"]
        assert len(page2) == 400 and page2[0]["offset"] > offsets[-1]
        graph = api.read(f"/api/rizin/{sid}/graph?addr={main['offset']}")
        starts = {n["offset"] for n in graph["nodes"]}
        assert graph["offset"] == main["offset"]
        assert len(graph["nodes"]) == 30 and sum(len(n["lines"]) for n in graph["nodes"]) == len(disasm["ops"])
        assert all(t in starts for n in graph["nodes"] for t in [n["jump"], n["fail"], *n["cases"]] if t is not None)
        # rizin 0.9.1 lists flags with flj (fj is no command there)
        flags = api.read(f"/api/rizin/{sid}/flags?q=SYM.MAI")
        names = flags["names"]
        assert "sym.main" in names and "sym.mainCRTStartup" in names and all(n.startswith("sym.mai") for n in names)
        assert flags["common"] == "sym.main"
        assert api.send(f"/api/rizin/{sid}/console", {"cmd": "afl~main"})["changed"] is False

        assert any("msagent" in s["string"] for s in api.read(f"/api/rizin/{sid}/strings?q=MSAGENT")["items"])
        imports = api.read(f"/api/rizin/{sid}/imports?q=CreateNamedPipeA")
        assert imports["total"] == 1 and imports["items"][0]["library"] == "KERNEL32.dll"
        xrefs = api.read(f"/api/rizin/{sid}/xrefs?addr={imports['items'][0]['offset']}")
        call = next(x for x in xrefs["to"] if x["function"] == "sym.main")
        assert "CreateNamedPipeA" in call["text"]
        xrefs = api.read(f"/api/rizin/{sid}/xrefs?addr={main['offset']}")
        assert xrefs["scope"] == "function" and xrefs["from"] and all(x["text"] for x in xrefs["from"])
        assert api.read(f"/api/rizin/{sid}/hex?addr=0x140000000&len=2")["bytes"] == [0x4D, 0x5A]
        # paddr: where the bytes at an address are in the file (rizin's map there, oml.j, of the file it has open)
        hexed = api.read(f"/api/rizin/{sid}/hex?addr={main['offset']}&len=16")
        with open(exe, "rb") as fh:
            fh.seek(hexed["paddr"])
            assert list(fh.read(16)) == hexed["bytes"], "paddr is not where the bytes are in the file"
        assert api.read(f"/api/rizin/{sid}/hex?addr=0x150000000&len=1")["paddr"] is None

        note = 'see <b>"this"</b> \u00fc'
        api.send(f"/api/rizin/{sid}/comment", {"addr": call["from"], "text": note})
        page = api.read(f"/api/rizin/{sid}/disasm?addr={call['from']}&count=2000")
        assert next(op for op in page["ops"] if op["offset"] == call["from"])["comment"] == note
        # The menu's Comment… field reads it at the address (pdj 1, base64 like pdfj)
        assert api.read(f"/api/rizin/{sid}/comment?addr={call['from']}") == {"offset": call["from"], "comment": note}
        assert api.read(f"/api/rizin/{sid}/comment?addr={main['offset']}")["comment"] == ""
        assert api.send(f"/api/rizin/{sid}/seek", {"addr": "sym.watchdog"})["function"] == "sym.watchdog"
        assert api.post(f"/api/rizin/{sid}/seek", {"addr": "sym.nosuch"}).status_code == 400
        # A rename from a line inside the function (the right-click menu) names the function
        assert api.send(f"/api/rizin/{sid}/rename", {"addr": call["from"], "name": "tdc_main"}) == {
            "offset": main["offset"], "name": "tdc_main"}
        assert api.read(f"/api/rizin/{sid}/disasm?addr={call['from']}&count=2000")["function"] == "tdc_main"
        # Review, Important 2: rizin keeps a name with U+2028 or U+0085 as it is and prints it in afl;
        # the row is read whole, like afij's name that the tab marks the row by
        odd = "sym.odd" + ODD_IN_A_NAME + "tail"
        api.send(f"/api/rizin/{sid}/console", {"cmd": f"afn {odd} @ {main['offset']:#x}"})
        assert odd in [f["name"] for f in api.read(f"/api/rizin/{sid}/functions")]
        assert api.read(f"/api/rizin/{sid}/disasm?addr={call['from']}&count=1")["function"] == odd
        assert api.status(sid)["function"] == odd  # the session's own (afl.)
        # Review round 4: a separator at the start of the name belongs to the name, in both
        lead = "\u2028lead"
        api.send(f"/api/rizin/{sid}/console", {"cmd": f"afn {lead} @ {main['offset']:#x}"})
        assert lead in [f["name"] for f in api.read(f"/api/rizin/{sid}/functions")]
        assert api.status(sid)["function"] == lead
        api.send(f"/api/rizin/{sid}/rename", {"addr": main["offset"], "name": "tdc_main"})
        decompiled = api.read(f"/api/rizin/{sid}/decompile?addr={main['offset']}")
        if status["ghidra"]:
            assert decompiled["available"] and any(line["offset"] for line in decompiled["lines"])
        else:
            assert decompiled == {"available": False, "reason": "Decompiler not available (rz-ghidra missing)",
                                  "function": None, "lines": []}

        # A text file: the views answer in their usual shapes.
        text = allowed / "notes.txt"
        text.write_bytes(b"just some text\n")
        sid = api.open(str(text), "tab2")["session"]
        api.wait_done(sid, timeout=120)
        assert isinstance(api.read(f"/api/rizin/{sid}/functions"), list)
        assert isinstance(api.read(f"/api/rizin/{sid}/graph?addr=0x0")["nodes"], list)
        assert api.read(f"/api/rizin/{sid}/disasm?addr=0x0&count=4")["ops"]
        assert "available" in api.read(f"/api/rizin/{sid}/decompile?addr=0x0")
        assert api.read(f"/api/rizin/{sid}/hex?addr=0x0&len=4") == {"offset": 0, "bytes": list(b"just"), "paddr": 0}
    finally:
        mgr.shutdown()


# --- Export of the patched copy --------------------------------------------------------------------------------
# The fake's file maps need a file of at least 0x3000 bytes (the sample of the paddr test above is 12 KB too).
EXPORT_SAMPLE = bytes(range(256)) * 48


def _export_session(rz, name="pipesim.exe", data=EXPORT_SAMPLE, tab="tab1"):
    """A sample the fake's maps reach into, opened and analysed: (its session ID, its path)."""
    path = rz.write(name, data)
    sid = rz.open(path, tab)["session"]
    rz.wait_done(sid)
    return sid, path


def _paddr(rz, sid, addr):
    return rz.read(f"/api/rizin/{sid}/hex?addr={addr:#x}&len=1")["paddr"]


def test_export_writes_a_copy_with_the_patches_applied(rz):
    sid, path = _export_session(rz)
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert set(result) == {"path", "name", "sha256", "patched", "skipped", "note"}
    data = open(result["path"], "rb").read()
    original = open(path, "rb").read()
    paddr = _paddr(rz, sid, 0x140001440)
    assert paddr == 0x840, "the fake's .text is at file offset 0x400, so the address is not the offset"
    assert data[paddr:paddr + 2] == b"\x90\x90" and original[paddr:paddr + 2] != b"\x90\x90"
    assert data[:paddr] == original[:paddr] and data[paddr + 2:] == original[paddr + 2:]
    assert result["patched"] == 2 and result["skipped"] == []
    assert hashlib.sha256(data).hexdigest() == result["sha256"]
    digest = hashlib.sha256(original).hexdigest()[:16]
    assert result["name"] == f"{digest}_pipesim.patched.exe" and result["path"] == os.path.join(
        rz.tdc.RIZIN_UPLOAD_DIR, result["name"])
    note = open(result["path"] + ".patch.txt").read()
    assert note == result["note"]
    row = _patches(rz, sid)[0]
    assert path in note and "0x140001440" in note
    assert result["sha256"] in note and hashlib.sha256(original).hexdigest() in note
    # R72: the bytes the note calls replaced are the **file's** at the offset, not rizin's `before`
    assert f"file {paddr:#x}  {original[paddr:paddr + 2].hex()} -> 9090" in note
    assert "UTC" in note, "the time"
    # and where the two differ the row is named, because the copy carries the file's bytes around it.
    # (The fake's byte model and the sample on disk are independent by construction -- the one case
    # real rizin reaches is a patch over bytes a run changed, which the real-rizin test below pins.)
    assert row["before"] != original[paddr:paddr + 2].hex()
    assert "rizin's write cache already held a write at the address of these patches when they were made (1)" in note
    assert f"the patch replaced {row['before']}; in the file they are {original[paddr:paddr + 2].hex()}" in note


def test_export_leaves_the_original_untouched(rz):
    sid, path = _export_session(rz)
    before = open(path, "rb").read()
    stamp = os.stat(path).st_mtime_ns
    _patch(rz, sid, addr="0x140001440", bytes="90")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    # the export did write a patched byte somewhere, or the check below would hold for any code at all
    assert open(result["path"], "rb").read()[0x840] == 0x90 and before[0x840] != 0x90
    assert open(path, "rb").read() == before and os.stat(path).st_mtime_ns == stamp


def test_export_names_patches_without_a_file_offset_and_writes_the_rest(rz):
    # Review Focus 2: a patch set by hand where the file has no byte must be named, and the others written.
    sid, path = _export_session(rz)
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    _patch(rz, sid, addr="0x140001440", bytes="90")
    _patch(rz, sid, addr="0xdead0000", bytes="90")  # no map
    _patch(rz, sid, addr="0x140009000", bytes="90")  # a map of the file, but past the end of this 12 KB file
    _patch(rz, sid, addr="0x140002ffe", bytes="aabbccdd")  # starts in the file's data, ends in the zero-filled room
    _patch(rz, sid, addr="0x140005bfe", bytes="aabbccdd")  # starts in the file's data, ends past the file
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert result["skipped"] == [0xDEAD0000, 0x140002FFE, 0x140005BFE, 0x140009000] and result["patched"] == 1
    assert "could not be placed in the file" in result["note"]
    for addr in result["skipped"]:
        assert f"{addr:#x}" in result["note"]
    data, original = open(result["path"], "rb").read(), open(path, "rb").read()
    assert [i for i in range(len(data)) if data[i] != original[i]] == [0x840], \
        "a patch that is only partly in the file is skipped whole, not written in part"


def _scrambled_session(rz, monkeypatch):
    """The fake with three maps side by side in memory whose data are out of order in the file (see
    FAKE_RIZIN_SCRAMBLED): .s1 at 0x14000c000 is file offset 0x400, .s2 at 0x14000c200 is 0xa00, .s3 at
    0x14000c400 is 0x800 -- as a PE with SectionAlignment == FileAlignment and out-of-order raw pointers is
    mapped by rizin 0.9.1 (measured)."""
    monkeypatch.setenv("FAKE_RIZIN_SCRAMBLED", "1")
    return _export_session(rz)


def test_a_patch_across_maps_whose_data_are_out_of_order_is_not_written(rz, monkeypatch):
    """The first byte (file 0x400) and the last (0x9ff) of 0x600 bytes from .s1 are as far apart in the
    file as in memory, yet .s3's data are in between and .s2's are not: written from the first offset on, the
    copy would have .s3 overwritten, .s2 untouched, and the answer would say success."""
    sid, path = _scrambled_session(rz, monkeypatch)
    assert [_paddr(rz, sid, a) for a in (0xC000, 0xC1FF, 0xC200, 0xC3FF, 0xC400, 0xC5FF)] == [None] * 6
    assert [_paddr(rz, sid, 0x140000000 + a) for a in (0xC000, 0xC1FF, 0xC200, 0xC3FF, 0xC400, 0xC5FF)] == [
        0x400, 0x5FF, 0xA00, 0xBFF, 0x800, 0x9FF]
    _patch(rz, sid, addr="0x14000c000", bytes="ff" * 0x600)
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "0x14000c000" in response.get_json()["refused"]
    # a patch that is in one map is written, and nowhere else
    _patch(rz, sid, addr="0x14000c200", bytes="ee" * 0x200)
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert result["patched"] == 0x200 and result["skipped"] == [0x14000C000]
    data, original = open(result["path"], "rb").read(), open(path, "rb").read()
    assert [i for i in range(len(data)) if data[i] != original[i]] == [i for i in range(0xA00, 0xC00)
                                                                       if original[i] != 0xEE]
    assert data[0xA00:0xC00] == b"\xee" * 0x200


def test_a_patch_over_two_maps_of_the_file_is_not_written_where_rizin_does_not_show_it(rz, monkeypatch):
    """Two maps over the same addresses: rizin reads through the topmost (the fake's oml.j answers it as
    rizin's does), and omlj lists both without saying which. The first one that holds the row is the wrong
    one half of the time: the copy would have the patch where nothing shows it, and say it had it."""
    monkeypatch.setenv("FAKE_RIZIN_OVERLAP", "1")
    sid, path = _export_session(rz)
    assert _paddr(rz, sid, 0x14000E000) == 0xA00, "rizin shows the later map there"
    _patch(rz, sid, addr="0x14000e000", bytes="ab" * 16)
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "0x14000e000" in response.get_json()["refused"]
    _patch(rz, sid, addr="0x140001440", bytes="90")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert result["skipped"] == [0x14000E000] and result["patched"] == 1
    data, original = open(result["path"], "rb").read(), open(path, "rb").read()
    assert [i for i in range(len(data)) if data[i] != original[i]] == [0x840], "neither .o1's data nor .o2's"


def test_a_patch_is_never_placed_past_the_end_of_the_file(rz):
    """Real rizin always says how long the file is (ol.j); where it does not, the session's size bounds."""
    maps = [{"fd": 3, "from": 0x1000, "to": 0x3000, "delta": 0x400}]
    place = rz.tdc._rizin_patch_paddr
    assert place({"fd": 3}, maps, {"addr": 0x1000, "size": 16}, 0x500) == 0x400
    assert place({"fd": 3}, maps, {"addr": 0x1000, "size": 16}, 0x40F) is None, "ends one byte past the file"
    assert place({"fd": 3, "size": 0x40F}, maps, {"addr": 0x1000, "size": 16}, None) is None
    assert place({"fd": 3}, maps, {"addr": 0x1000, "size": 16}, None) is None, "nothing says how long it is"


def test_every_byte_of_an_exported_patch_lands_where_rizin_says_it_is(rz, monkeypatch):
    """The property, not a rule for it: for each byte of each exported patch, the file offset rizin gives
    for that byte's address holds the byte the patch wrote there."""
    sid, path = _scrambled_session(rz, monkeypatch)
    for addr, data in ((0x14000C000, "11" * 0x200), (0x14000C3F0, "22" * 0x10), (0x14000C5F0, "33" * 0x10),
                       (0x140001440, "4455"), (0x14000C1F8, "6677" * 8)):
        _patch(rz, sid, addr=f"{addr:#x}", bytes=data)
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert result["skipped"] == [0x14000C1F8]  # .s1's last 8 bytes and .s2's first 8: two maps
    copy = open(result["path"], "rb").read()
    for addr, data in ((0x14000C000, b"\x11" * 0x200), (0x14000C3F0, b"\x22" * 0x10),
                       (0x14000C5F0, b"\x33" * 0x10), (0x140001440, b"\x44\x55")):
        for i in range(0, len(data), 7):
            assert copy[_paddr(rz, sid, addr + i)] == data[i], hex(addr + i)
        assert copy[_paddr(rz, sid, addr + len(data) - 1)] == data[-1]
    expected = bytearray(open(path, "rb").read())
    for start, data in ((0x400, b"\x11" * 0x200), (0xBF0, b"\x22" * 0x10), (0x9F0, b"\x33" * 0x10), (0x840, b"\x44\x55")):
        expected[start:start + len(data)] = data
    assert copy == bytes(expected), "the copy is the original with these bytes changed and no others"


def test_export_asks_rizin_a_fixed_number_of_times_however_many_patches_there_are(rz):
    sid, _ = _export_session(rz)
    for i in range(12):
        _patch(rz, sid, addr=f"{0x140001440 + 4 * i:#x}", bytes="90")
    mark = len(rz.commands())
    assert rz.send(f"/api/rizin/{sid}/export", {})["patched"] == 12
    sent = _commands_since(rz, mark)
    assert [c for c in sent if c.startswith(("wcj", "ol", "oml"))] == ["wcj", "ol.j", "omlj"], sent


def test_export_refuses_when_no_patch_has_a_place_in_the_file(rz):
    sid, _ = _export_session(rz)
    _patch(rz, sid, addr="0xdead0000", bytes="90")
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "0xdead0000" in response.get_json()["refused"]
    assert not os.path.exists(rz.tdc.RIZIN_UPLOAD_DIR) or not os.listdir(rz.tdc.RIZIN_UPLOAD_DIR)


def test_export_does_not_write_what_a_run_wrote(rz):
    sid, _ = _export_session(rz)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001444"})
    _run(rz, sid, "step")
    assert [r["mine"] for r in _patches(rz, sid)] == [False], "the step wrote a row, and it is the run's"
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "no patches" in response.get_json()["refused"]
    assert not os.path.exists(rz.tdc.RIZIN_UPLOAD_DIR) or not os.listdir(rz.tdc.RIZIN_UPLOAD_DIR)
    # with a patch of the analyst's beside the run's row, only the patch is exported
    _patch(rz, sid, addr="0x140001440", bytes="90")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    data = open(result["path"], "rb").read()
    assert result["patched"] == 1 and result["skipped"] == [] and data[0x840] == 0x90
    file_byte = EXPORT_SAMPLE[0x840:0x841].hex()
    assert [l for l in result["note"].splitlines() if l.startswith("  0x")] == [
        f"  0x140001440  file 0x840  {file_byte} -> 90",
        f"  0x140001440  file 0x840  the patch replaced 00; in the file they are {file_byte}; "
        "no run is known to have written there"], \
        "one patch line, for the one patch and none for the run's row, and the row named once"


def test_export_applies_overlapping_patches_in_the_order_they_were_made(rz):
    """patches() lists by address, but a later write wins where two overlap: a one-byte fix before the start
    of a longer patch, made afterwards, covers its first byte -- and sorted by address it would come first."""
    sid, _ = _export_session(rz)
    _patch(rz, sid, addr="0x140001451", bytes="11223344")
    _patch(rz, sid, addr="0x140001450", bytes="aabb")
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [
        (0x140001450, "aabb"), (0x140001451, "11223344")], "listed by address, not by when they were made"
    paddr = _paddr(rz, sid, 0x140001450)
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert open(result["path"], "rb").read()[paddr:paddr + 5] == bytes.fromhex("aabb223344")
    # and the note's "before" is the **original's** bytes for both rows, not what the patch written just
    # before it put there: the bytes are read from the untouched copy, all of them, before any is written
    original = EXPORT_SAMPLE[paddr:paddr + 5]
    lines = [l for l in result["note"].splitlines() if l.startswith("  0x")]
    assert f"  0x140001451  file {paddr + 1:#x}  {original[1:5].hex()} -> 11223344" in lines, lines
    assert f"  0x140001450  file {paddr:#x}  {original[0:2].hex()} -> aabb" in lines, lines
    # and the same address twice: the second is the one that stays
    _patch(rz, sid, addr="0x140001450", bytes="cc")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert open(result["path"], "rb").read()[paddr:paddr + 5] == bytes.fromhex("ccbb223344")
    lines = [l for l in result["note"].splitlines() if l.startswith("  0x")]
    assert f"  0x140001450  file {paddr:#x}  {original[0:1].hex()} -> cc" in lines, \
        "the third patch's line shows what the first one wrote, not the file's byte: " + str(lines)


def test_a_second_export_replaces_the_copy_and_its_note_together(rz):
    sid, _ = _export_session(rz)
    _patch(rz, sid, addr="0x140001440", bytes="90")
    first = rz.send(f"/api/rizin/{sid}/export", {})
    _patch(rz, sid, addr="0x140001460", bytes="cc")
    second = rz.send(f"/api/rizin/{sid}/export", {})
    assert second["path"] == first["path"] and second["sha256"] != first["sha256"]
    copy = open(second["path"], "rb").read()
    assert hashlib.sha256(copy).hexdigest() == second["sha256"] and copy[0x860] == 0xCC
    note = open(second["path"] + ".patch.txt").read()
    assert second["sha256"] in note and first["sha256"] not in note, "the note describes the copy beside it"
    assert "0x140001440" in note and "0x140001460" in note
    assert sorted(os.listdir(rz.tdc.RIZIN_UPLOAD_DIR)) == [second["name"], second["name"] + ".patch.txt"], \
        "no temporary file is left"


def test_export_refuses_a_file_that_changed_since_it_was_opened(rz):
    sid, path = _export_session(rz)
    _patch(rz, sid, addr="0x140001440", bytes="90")
    with open(path, "ab") as fh:
        fh.write(b"x")
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "changed" in response.get_json()["refused"]
    assert os.listdir(rz.tdc.RIZIN_UPLOAD_DIR) == [], "no copy, no temporary file"


def test_export_never_writes_where_the_original_is(rz):
    """The copy's name is made from the original's digest, so it is not the original's name; where the
    path it would take already leads to the original (a link), it is refused rather than replaced."""
    sid, path = _export_session(rz)
    _patch(rz, sid, addr="0x140001440", bytes="90")
    name = f"{hashlib.sha256(EXPORT_SAMPLE).hexdigest()[:16]}_pipesim.patched.exe"
    rz.uploads.mkdir()
    os.symlink(path, rz.uploads / name)
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 400 and "original" in response.get_json()["refused"]
    assert open(path, "rb").read() == EXPORT_SAMPLE and os.listdir(rz.uploads) == [name]


def test_two_samples_of_one_name_do_not_replace_each_others_copy(rz):
    one, path_one = _export_session(rz, "dir_a/evil.exe", EXPORT_SAMPLE)
    two, path_two = _export_session(rz, "dir_b/evil.exe", EXPORT_SAMPLE[:-1] + b"!", tab="tab2")
    _patch(rz, one, addr="0x140001440", bytes="90")
    first = rz.send(f"/api/rizin/{one}/export", {})
    _patch(rz, two, addr="0x140001440", bytes="cc")
    second = rz.send(f"/api/rizin/{two}/export", {})
    assert first["path"] != second["path"] and first["name"].endswith("_evil.patched.exe")
    assert open(first["path"], "rb").read()[0x840] == 0x90 and open(second["path"], "rb").read()[0x840] == 0xCC
    assert path_one in open(first["path"] + ".patch.txt").read() and path_two in open(second["path"] + ".patch.txt").read()


def test_export_keeps_the_suffix_of_a_name_without_ascii(rz):
    """secure_filename("пример.exe") is "exe": the copy would have had no suffix to be detonated by."""
    sid, _ = _export_session(rz, "\u043f\u0440\u0438\u043c\u0435\u0440.exe")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    name = rz.send(f"/api/rizin/{sid}/export", {})["name"]
    assert name.endswith("_sample.patched.exe"), name
    sid, _ = _export_session(rz, "noextension", EXPORT_SAMPLE[:-1] + b"?")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    assert rz.send(f"/api/rizin/{sid}/export", {})["name"].endswith("_noextension.patched")


def test_export_does_not_prune_the_original_it_copied(rz, monkeypatch):
    """A sample that was uploaded is in the folder the prune empties: with 45 newer files, the original
    the session has open must not go while the copy and the note stay."""
    rz.uploads.mkdir()
    path = str(rz.uploads / "0123456789abcdef_old.exe")
    with open(path, "wb") as fh:
        fh.write(EXPORT_SAMPLE)
    os.utime(path, (1, 1))
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    for i in range(45):
        (rz.uploads / f"newer_{i:02d}.bin").write_bytes(b"x")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    left = set(os.listdir(rz.uploads))
    assert {os.path.basename(path), result["name"], result["name"] + ".patch.txt"} <= left
    assert len(left) == rz.tdc.RIZIN_UPLOADS_KEEP + 1, "the rest is pruned as for an upload, and the original is the one more"


def test_the_note_names_a_row_the_mirror_says_was_over_a_runs_bytes(tdc):
    """The note names a row where the file's bytes and rizin's ``before`` differ **or** where the cache's
    own rows say a foreign write changed them (``over_run``). The second half matters on its own: the
    mark rests on the session's mirror, and a note that fell silent when a run happened to write the
    file's own byte back would be wrong about the copy for no good reason."""
    session = types.SimpleNamespace(path="C:/samples/evil.exe")
    row = {"addr": 0x140001001, "size": 1, "before": "31", "after": "90", "mine": True, "over_run": True}
    note = tdc._rizin_export_note(session, "a" * 64, "copy.exe", "b" * 64, [(row, 0x401, "31")], [])
    assert "  0x140001001  file 0x401  31 -> 90" in note
    assert "rizin's write cache already held a write at the address of these patches when they were made (1)" in note, note
    assert "the patch replaced 31; in the file they are 31; a run wrote there first" in note, note
    # the run wrote the file's own byte back, so the bytes replaced *are* the file's: the header says nothing else
    assert "not the file's" not in note, note
    # an earlier hand patch at the same address (no mark: no run was involved) is named too, for the same reason
    second = dict(row, over_run=False, before="91")
    note_b = tdc._rizin_export_note(session, "a" * 64, "copy.exe", "b" * 64, [(second, 0x401, "31")], [])
    assert "write cache already held a write at the address of these patches when they were made (1)" in note_b, note_b
    assert "an earlier patch of yours that covers it" in note_b, note_b
    assert "the patch replaced 91; in the file they are 31; no run is known to have written there" in note_b, note_b
    assert "a run wrote there first" not in note_b, note_b
    # the same row without the mark and with the same bytes is not named
    plain = tdc._rizin_export_note(session, "a" * 64, "copy.exe", "b" * 64,
                                   [(dict(row, over_run=False), 0x401, "31")], [])
    assert "rizin's write cache already held a write at the address of these patches when they were made" not in plain and "the patch replaced" not in plain, plain
    # and rizin's upper case, which 0.9.1 never writes, is no difference either
    upper = tdc._rizin_export_note(session, "a" * 64, "copy.exe", "b" * 64,
                                   [(dict(row, over_run=False, before="AB"), 0x401, "ab")], [])
    assert "rizin's write cache already held a write at the address of these patches when they were made" not in upper and "the patch replaced" not in upper, upper


def test_the_note_shortens_a_long_patch_to_a_line_that_can_be_read(rz):
    sid, _ = _export_session(rz)
    _patch(rz, sid, addr="0x140001440", bytes="ab" * 1224)
    result = rz.send(f"/api/rizin/{sid}/export", {})
    lines = [l for l in result["note"].splitlines() if l.startswith("  0x")]
    assert len(lines) == 2, lines      # the patch's own line, and the one naming the bytes it replaced
    assert all(len(l) < 300 for l in lines) and all(l.count("(1224 bytes)") == 2 for l in lines)
    assert "ab" * 32 in lines[0] and "ab" * 33 not in lines[0]
    assert result["patched"] == 1224


def test_export_answers_500_when_the_copy_cannot_be_written(rz, monkeypatch):
    sid, path = _export_session(rz)
    _patch(rz, sid, addr="0x140001440", bytes="90")
    blocked = rz.tmp / "not_a_folder"
    blocked.write_bytes(b"")
    monkeypatch.setattr(rz.tdc, "RIZIN_UPLOAD_DIR", str(blocked / "uploads"))
    response = rz.post(f"/api/rizin/{sid}/export", {})
    assert response.status_code == 500 and "could not be read or written" in response.get_json()["error"]
    assert open(path, "rb").read() == EXPORT_SAMPLE


def test_export_prunes_like_an_upload(rz, monkeypatch):
    sid, _ = _export_session(rz, "pipesim.exe")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert result["name"].endswith(".patched.exe")
    assert os.path.dirname(result["path"]) == rz.tdc.RIZIN_UPLOAD_DIR
    # with room for one file, the copy and its note both stay and the old upload goes
    old = rz.uploads / "old_upload.bin"
    old.write_bytes(b"old")
    os.utime(old, (1, 1))
    monkeypatch.setattr(rz.tdc, "RIZIN_UPLOADS_KEEP", 1)
    result = rz.send(f"/api/rizin/{sid}/export", {})
    assert sorted(os.listdir(rz.uploads)) == [result["name"], result["name"] + ".patch.txt"]


def test_the_prune_keeps_every_file_it_is_told_to(rz, monkeypatch):
    """The copy and its note are two files and `keep` names both: with room for one file, a prune that
    knows only the copy deletes the note (a patched sample with nothing that says what was changed)."""
    rz.uploads.mkdir()
    names = ["old.bin", "copy.patched.exe", "copy.patched.exe.patch.txt"]
    for age, name in enumerate(names):
        (rz.uploads / name).write_bytes(b"x")
        os.utime(rz.uploads / name, (1000 + age, 1000 + age))  # the note is the newest
    monkeypatch.setattr(rz.tdc, "RIZIN_UPLOADS_KEEP", 1)
    rz.tdc._rizin_prune_uploads((str(rz.uploads / names[1]), str(rz.uploads / names[2])))
    assert sorted(os.listdir(rz.uploads)) == sorted(names[1:])
    # one path, as the upload route passes it: the copy stays although it is outside the one file of room
    (rz.uploads / names[0]).write_bytes(b"x")
    os.utime(rz.uploads / names[0], (2000, 2000))  # now the newest
    rz.tdc._rizin_prune_uploads(str(rz.uploads / names[1]))
    assert sorted(os.listdir(rz.uploads)) == sorted(names[:2])


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_exports_the_patch_at_the_physical_offset(tdc, tmp_path, monkeypatch):
    """The copy against a real PE, whose sections are page-aligned in memory and not in the file, so that an
    address and its file offset really differ; and against rizin's maps, which the fake only models."""
    import rizin_sessions

    allowed, uploads = tmp_path / "allowed", tmp_path / "uploads"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    original = exe.read_bytes()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed), str(uploads)])
    monkeypatch.setattr(tdc, "RIZIN_UPLOAD_DIR", str(uploads))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        session = mgr.get(sid)
        main = next(f for f in api.read(f"/api/rizin/{sid}/functions") if f["name"] == "sym.main")["offset"]
        hexed = api.read(f"/api/rizin/{sid}/hex?addr={main}&len=4")
        assert hexed["paddr"] is not None and hexed["paddr"] != main - 0x140000000, "a section is not at its address"
        assert bytes(hexed["bytes"]) == original[hexed["paddr"]:hexed["paddr"] + 4]

        # three patches: two apart, and a pair that overlaps and was made later than its neighbour
        api.send(f"/api/rizin/{sid}/patch", {"addr": main, "bytes": "9090"})
        api.send(f"/api/rizin/{sid}/patch", {"addr": main + 0x21, "bytes": "11223344"})
        api.send(f"/api/rizin/{sid}/patch", {"addr": main + 0x20, "bytes": "aabb"})
        # beyond the file: the zero-filled room after .text's data, and one that crosses into it
        text_end = next(m["from"] for m in session.json("omlj") if m["name"] == "mmap..text")
        api.send(f"/api/rizin/{sid}/patch", {"addr": text_end + 2, "bytes": "90"})
        api.send(f"/api/rizin/{sid}/patch", {"addr": text_end - 2, "bytes": "aabbccdd"})
        # across the zero-filled room between two sections whose data follow each other in the file: both ends
        # are in the file, and a copy written from the first end's offset would put the bytes in the wrong place
        maps = {m["name"]: m for m in session.json("omlj")}
        rdata_end, room = maps["fmap..rdata"]["to"], maps["mmap..rdata"]
        assert room["from"] == rdata_end and maps["fmap..pdata"]["from"] == room["to"] and \
            maps["fmap..pdata"]["delta"] == maps["fmap..rdata"]["delta"] + (rdata_end - maps["fmap..rdata"]["from"])
        crossing = rdata_end - 100
        api.send(f"/api/rizin/{sid}/patch", {"addr": crossing, "bytes": "ab" * (100 + (room["to"] - room["from"]) + 100)})
        # one in the memory an emulation maps: no byte of the file is there
        api.send(f"/api/rizin/{sid}/emulation/start", {})
        stack = rizin_sessions.ESIL_STACK_ADDR
        api.send(f"/api/rizin/{sid}/patch", {"addr": stack + 0x10, "bytes": "90"})
        api.send(f"/api/rizin/{sid}/patch", {"addr": 0xDEAD0000, "bytes": "90"})  # and one with no map at all

        result = api.send(f"/api/rizin/{sid}/export", {})
        assert result["skipped"] == sorted([text_end - 2, text_end + 2, crossing, stack + 0x10, 0xDEAD0000])
        assert result["patched"] == 2 + 4 + 2
        data = open(result["path"], "rb").read()
        assert hashlib.sha256(data).hexdigest() == result["sha256"] and len(data) == len(original)
        at = hexed["paddr"]
        assert data[at:at + 2] == b"\x90\x90"
        assert data[at + 0x20:at + 0x25] == bytes.fromhex("aabb223344"), "the later write is the one that stays"
        changed = [i for i in range(len(data)) if data[i] != original[i]]
        assert changed and all(at <= i < at + 0x25 for i in changed), "nothing else in the file was touched"
        assert hashlib.sha256(exe.read_bytes()).hexdigest() == hashlib.sha256(original).hexdigest(), \
            "the original is never written"
        assert result["sha256"] in open(result["path"] + ".patch.txt").read()
        # what rizin shows through its cache is what the copy holds there
        assert bytes.fromhex(session.text(f"p8 0x25 @ {main:#x}").strip())[:2] == data[at:at + 2]

        # the copy opens as a file of its own, with the patch in it and none of it in the cache
        other = api.open(result["path"], "tab2")["session"]
        api.wait_done(other, timeout=120)
        assert api.read(f"/api/rizin/{other}/hex?addr={main}&len=2")["bytes"] == [0x90, 0x90]
        assert api.read(f"/api/rizin/{other}/patches")["patches"] == []
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_the_note_says_what_the_file_holds_under_a_patch(tdc, tmp_path, monkeypatch):
    """R72 against rizin 0.9.1 itself: a patch set by hand over bytes a run had already changed, which is
    what patching inside freshly decrypted code is.

    Measured, and the whole reason the note is built the way it is: ``wcj`` gives as a row's ``before``
    what stood at the address **when that write was made** -- the run's byte, not the file's. On a file
    holding 73317331, a run's ``wx 41 @ 1`` and then a patch ``wx 90 @ 1`` give a second row with
    ``before: "41"`` while the file still holds ``31``, and ``p8`` shows 73907331. The old note copied
    that ``before`` and so said the file held 0x41. The bytes the run wrote are *not* in the copy, so
    the patch really does sit in the file's own (still encrypted) bytes, and nothing but the note says so.

    The bytes before the patch are written with ``wx`` rather than by a decryption routine on purpose:
    rizin has one write cache for a run and for the console, and cannot tell them apart -- which is the
    premise of the whole feature. The server counts the row as foreign either way (``mine: false``).
    """
    import rizin_sessions

    allowed, uploads = tmp_path / "allowed", tmp_path / "uploads"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    original = exe.read_bytes()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed), str(uploads)])
    monkeypatch.setattr(tdc, "RIZIN_UPLOAD_DIR", str(uploads))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        session = mgr.get(sid)
        main = next(f for f in api.read(f"/api/rizin/{sid}/functions") if f["name"] == "sym.main")["offset"]
        paddr = api.read(f"/api/rizin/{sid}/hex?addr={main}&len=4")["paddr"]
        assert paddr is not None and bytes(api.read(
            f"/api/rizin/{sid}/hex?addr={main}&len=4")["bytes"]) == original[paddr:paddr + 4]

        # four bytes "decrypted" into .text, every one different from the file's, then a patch over the
        # second of them -- the anti-VM check inside freshly decrypted code that this feature invites
        api.send(f"/api/rizin/{sid}/emulation/start", {"addr": main})
        decrypted = bytes(b ^ 0xFF for b in original[paddr:paddr + 4])
        session.text(f"wx {decrypted.hex()} @ {main:#x}")
        api.send(f"/api/rizin/{sid}/patch", {"addr": main + 1, "bytes": "90"})

        rows = api.read(f"/api/rizin/{sid}/patches")["patches"]
        run_row = next(r for r in rows if r["addr"] == main)
        patch_row = next(r for r in rows if r["addr"] == main + 1)
        assert run_row["mine"] is False and run_row["over_run"] is False
        assert patch_row["mine"] is True and patch_row["over_run"] is True, patch_row
        assert patch_row["before"] == decrypted[1:2].hex(), "rizin's before is the run's byte"
        assert patch_row["before"] != original[paddr + 1:paddr + 2].hex(), "and not the file's"

        result = api.send(f"/api/rizin/{sid}/export", {})
        note = result["note"]
        was = original[paddr + 1:paddr + 2].hex()
        assert result["patched"] == 1 and result["skipped"] == []
        # the note says what the **file** held there, not what rizin's cache did
        assert f"  {main + 1:#x}  file {paddr + 1:#x}  {was} -> 90" in note, note
        assert f"{patch_row['before']} -> 90" not in note, "the run's byte is not called the file's"
        # and it names the row, with both bytes, so the copy's state is knowable from the note alone
        assert "rizin's write cache already held a write at the address of these patches when they were made (1)" in note, note
        assert f"  {main + 1:#x}  file {paddr + 1:#x}  the patch replaced {patch_row['before']}; " \
               f"in the file they are {was}" in note, note

        # the copy itself: the file's bytes everywhere but the one patched byte -- the run's three other
        # bytes are not in it, which is why the patch sits in bytes that are still as the file has them
        copy = open(result["path"], "rb").read()
        assert [i for i in range(len(copy)) if copy[i] != original[i]] == [paddr + 1]
        assert copy[paddr + 1] == 0x90
        assert copy[paddr:paddr + 4] == original[paddr:paddr + 1] + b"\x90" + original[paddr + 2:paddr + 4]
        assert exe.read_bytes() == original, "the original is never written"
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not MINGW, reason="mingw (x86_64-w64-mingw32-gcc) not installed")
def test_real_rizin_the_note_header_is_true_in_all_three_cases_that_name_a_row(tdc, tmp_path, monkeypatch):
    """The note names a row where rizin's write cache already held a write at the address when the patch was
    made. Three ways to get there, and the header must be true of every one (rizin 0.9.1, measured):

    a. a run wrote a byte other than the file's, then the patch went over it;
    b. an **earlier hand patch** at the same address, no run involved (the pane shows no mark for it);
    c. a run wrote the file's **own** byte back, then the patch went over it -- the bytes replaced *are*
       the file's, so a header saying they are not would be false;
    d. an earlier hand patch that only **covers** the address (a 4-byte patch, then one byte inside it): rizin
       reports its byte as ``before`` (measured: ``90`` against the file's own byte), and the earlier patch is
       at another address, so "an earlier patch at the same address" would be false of it.
    """
    import rizin_sessions

    allowed, uploads = tmp_path / "allowed", tmp_path / "uploads"
    allowed.mkdir()
    exe = allowed / "pipesim.exe"
    shutil.copy(_build_pipesim(tmp_path), exe)
    original = exe.read_bytes()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed), str(uploads)])
    monkeypatch.setattr(tdc, "RIZIN_UPLOAD_DIR", str(uploads))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        session = mgr.get(sid)
        main = next(f for f in api.read(f"/api/rizin/{sid}/functions") if f["name"] == "sym.main")["offset"]
        paddr = api.read(f"/api/rizin/{sid}/hex?addr={main}&len=1")["paddr"]
        a_at, b_at, c_at, d_at = main, main + 1, main + 2, main + 6
        api.send(f"/api/rizin/{sid}/emulation/start", {"addr": main})
        session.text(f"wx {original[paddr] ^ 0xFF:02x} @ {a_at:#x}")       # a: a run's byte, not the file's
        api.send(f"/api/rizin/{sid}/patch", {"addr": a_at, "bytes": "90"})
        api.send(f"/api/rizin/{sid}/patch", {"addr": b_at, "bytes": "91"})   # b: an earlier hand patch ...
        api.send(f"/api/rizin/{sid}/patch", {"addr": b_at, "bytes": "92"})   # ... and a second thought
        session.text(f"wx {original[paddr + 2]:02x} @ {c_at:#x}")           # c: the run writes the file's own byte
        api.send(f"/api/rizin/{sid}/patch", {"addr": c_at, "bytes": "93"})
        api.send(f"/api/rizin/{sid}/patch", {"addr": main + 4, "bytes": "90909090"})   # d: a patch of four bytes ...
        api.send(f"/api/rizin/{sid}/patch", {"addr": d_at, "bytes": "94"})              # ... and one byte inside it

        rows = api.read(f"/api/rizin/{sid}/patches")["patches"]
        mine = {r["addr"]: r for r in rows if r["mine"]}
        assert mine[a_at]["over_run"] is True and mine[a_at]["before"] != original[paddr:paddr + 1].hex()
        assert mine[b_at]["over_run"] is False, "case b: no run was involved, and the pane shows no mark"
        assert mine[c_at]["over_run"] is True and mine[c_at]["before"] == original[paddr + 2:paddr + 3].hex(), \
            "case c: the run's byte *is* the file's"
        assert mine[d_at]["over_run"] is False and mine[d_at]["before"] == "90", "case d: the earlier patch's byte, no run"
        assert mine[d_at]["before"] != original[paddr + 6:paddr + 7].hex()

        note = api.send(f"/api/rizin/{sid}/export", {})["note"]
        assert "not the file's" not in note, "case c's bytes are the file's: " + note
        assert "rizin's write cache already held a write at the address of these patches when they were made (4)" in note, note
        assert "a write by an emulation run (or the console), or an earlier patch of yours that covers it" in note, \
            "the header names both writers it can be (the note's first line mentions a run too, so the whole phrase is pinned): " + note
        was = lambda at: original[paddr + at - main:paddr + at - main + 1].hex()
        for at in (a_at, b_at, c_at, d_at):
            replaced = next(r for r in mine.values() if r["addr"] == at)["before"]
            cause = "a run wrote there first" if mine[at]["over_run"] else "no run is known to have written there"
            assert f"  {at:#x}  file {paddr + at - main:#x}  the patch replaced {replaced}; " \
                   f"in the file they are {was(at)}; {cause}" in note, note
        assert mine[c_at]["before"] == was(c_at), "case c's own line says the two are the same"
    finally:
        mgr.shutdown()


def _build_scrambled_pe(path, overlap=False):
    """A minimal PE32+ with SectionAlignment == FileAlignment == 0x200 and three 0x200-byte sections whose raw
    data are out of order: .s1 -> file 0x400, .s2 -> 0xa00, .s3 -> 0x800 (virtual 0x1000, 0x1200, 0x1400).
    rizin 0.9.1 maps them side by side with no zero-filled room between them (measured). Each section's data
    is its own name repeated, so a byte says where it came from. With ``overlap`` .s2 is at virtual 0x1000 as
    well, over .s1, and .s3 at 0x1200: rizin maps both over the same addresses and reads through .s2."""
    import struct

    align, base = 0x200, 0x140000000
    sections = [(b".s1", 0x1000, 0x400), (b".s2", 0x1000 if overlap else 0x1200, 0xA00),
                (b".s3", 0x1200 if overlap else 0x1400, 0x800)]
    headers = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40)
    headers += b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 240, 0x22)
    headers += struct.pack("<HBBIIIIIQ", 0x20B, 14, 0, 0x600, 0x600, 0, 0x1000, 0x1000, base)
    headers += struct.pack("<IIHHHHHHIIIIHH", align, align, 6, 0, 0, 0, 6, 0, 0, 0x1600, 0x400, 0, 2, 0)
    headers += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(16 * 8)
    for name, va, raw in sections:
        headers += name.ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", align, va, align, raw, 0, 0, 0, 0, 0x60000020)
    blob = bytearray(headers.ljust(0x400, b"\x00") + bytes(0x800))
    for name, va, raw in sections:
        blob[raw:raw + align] = (name.strip(b".") * align)[:align]
    path.write_bytes(bytes(blob))
    return path


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_exports_only_what_one_map_of_the_file_holds(tdc, tmp_path, monkeypatch):
    """A patch across side-by-side maps whose data are out of order in the file: its first and last byte are
    as far apart in the file as in memory, and the sections between them are elsewhere. The copy has to be
    what rizin shows through its cache, for every byte, which is what the two-endpoint check missed."""
    import rizin_sessions

    allowed, uploads = tmp_path / "allowed", tmp_path / "uploads"
    allowed.mkdir()
    exe = _build_scrambled_pe(allowed / "scrambled.exe")
    original = exe.read_bytes()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed), str(uploads)])
    monkeypatch.setattr(tdc, "RIZIN_UPLOAD_DIR", str(uploads))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        session = mgr.get(sid)
        side_by_side = [(m["from"], m["to"], m["delta"]) for m in session.json("omlj") if m["fd"] == 3 and
                        m["name"].startswith("fmap..s")]
        assert sorted(side_by_side) == [(0x140001000, 0x140001200, 0x400), (0x140001200, 0x140001400, 0xA00),
                                        (0x140001400, 0x140001600, 0x800)], "the layout the test is about"

        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x140001000, "bytes": "ff" * 0x600})
        refused = api.post(f"/api/rizin/{sid}/export", {})
        assert refused.status_code == 400 and "0x140001000" in refused.get_json()["refused"], refused.get_json()
        assert not uploads.exists() or not os.listdir(uploads)

        api.remove(f"/api/rizin/{sid}/patch", {})
        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x140001200, "bytes": "ee" * 0x200})  # one map: file 0xa00
        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x1400013F0, "bytes": "dd" * 0x10})   # the end of it
        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x1400015F0, "bytes": "cc" * 0x10})   # the end of .s3: 0x9f0
        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x1400011F8, "bytes": "bb" * 0x10})   # two maps: not exported
        result = api.send(f"/api/rizin/{sid}/export", {})
        assert result["skipped"] == [0x1400011F8] and result["patched"] == 0x200 + 0x10 + 0x10
        data = open(result["path"], "rb").read()
        expected = bytearray(original)
        expected[0xA00:0xC00] = b"\xee" * 0x200
        expected[0xBF0:0xC00] = b"\xdd" * 0x10
        expected[0x9F0:0xA00] = b"\xcc" * 0x10
        assert data == bytes(expected)
        assert data[0x400:0x600] == original[0x400:0x600], ".s1 was in the skipped patch's range and is untouched"

        # what the copy shows once rizin has mapped it is what this session shows through its cache
        api.remove(f"/api/rizin/{sid}/patch", {"addr": 0x1400011F8})
        other = api.open(result["path"], "tab2")["session"]
        api.wait_done(other, timeout=120)
        assert mgr.get(other).text("p8 0x600 @ 0x140001000") == session.text("p8 0x600 @ 0x140001000")
        assert hashlib.sha256(exe.read_bytes()).hexdigest() == hashlib.sha256(original).hexdigest()
    finally:
        mgr.shutdown()


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_does_not_export_into_a_map_it_does_not_show(tdc, tmp_path, monkeypatch):
    """Sections that overlap in memory: rizin lists both maps and reads through the later one (`oml.j`,
    `px`). A patch there goes into the cache and shows, but the first map that holds it is .s1's, whose data
    rizin does not show at those addresses: written there, the copy would not have the patch at all."""
    import rizin_sessions

    allowed, uploads = tmp_path / "allowed", tmp_path / "uploads"
    allowed.mkdir()
    exe = _build_scrambled_pe(allowed / "overlap.exe", overlap=True)
    original = exe.read_bytes()
    monkeypatch.setattr(rizin_sessions, "RIZIN_EXE", REAL_RIZIN)
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(allowed), str(uploads)])
    monkeypatch.setattr(tdc, "RIZIN_UPLOAD_DIR", str(uploads))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    monkeypatch.setattr(tdc, "_rizin_manager", mgr)
    monkeypatch.setattr(tdc, "_rizin_install", {"key": None, "value": None})
    api = _Api(tdc, None, mgr, tmp_path)
    try:
        sid = api.open(str(exe))["session"]
        api.wait_done(sid, timeout=120)
        session = mgr.get(sid)
        maps = {m["name"]: m for m in session.json("omlj") if m["name"].startswith("fmap..s")}
        assert (maps["fmap..s1"]["from"], maps["fmap..s1"]["delta"]) == (0x140001000, 0x400)
        assert (maps["fmap..s2"]["from"], maps["fmap..s2"]["delta"]) == (0x140001000, 0xA00), "the layout"
        assert api.read(f"/api/rizin/{sid}/hex?addr=0x140001000&len=1")["paddr"] == 0xA00, "rizin shows .s2 there"

        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x140001000, "bytes": "ab" * 16})
        assert api.read(f"/api/rizin/{sid}/hex?addr=0x140001000&len=2")["bytes"] == [0xAB, 0xAB]
        refused = api.post(f"/api/rizin/{sid}/export", {})
        assert refused.status_code == 400 and "0x140001000" in refused.get_json()["refused"], refused.get_json()
        assert not uploads.exists() or not os.listdir(uploads)

        api.send(f"/api/rizin/{sid}/patch", {"addr": 0x140001200, "bytes": "cd" * 16})  # .s3: one map, file 0x800
        result = api.send(f"/api/rizin/{sid}/export", {})
        assert result["skipped"] == [0x140001000] and result["patched"] == 16
        expected = bytearray(original)
        expected[0x800:0x810] = b"\xcd" * 16
        assert open(result["path"], "rb").read() == bytes(expected), "the skipped patch is in no part of the file"
        assert hashlib.sha256(exe.read_bytes()).hexdigest() == hashlib.sha256(original).hexdigest()
    finally:
        mgr.shutdown()


# --- The timeline of the emulation (RizinSession._restore) ----------------------

def _state(rz, sid):
    """What the timeline holds, without asking rizin: how many actions and the record's own taint (after a
    discard, the reason it is gone)."""
    session = rz.mgr.get(sid)
    record = session._restore
    if record is None:
        return {"actions": 0, "tainted": session._restore_gone}
    return {"actions": len(record["actions"]), "tainted": record["tainted"]}


def _offer(rz, sid):
    """What the pane is told about the **timeline** (it asks rizin, so it waits for the gate): the offer without
    ``refused``, which is the other question -- see _refused."""
    offer = rz.mgr.get(sid)._restore_offer()
    offer.pop("refused")
    return offer


_NO_RECORD = "the project holds no timeline of the emulation to restore"


def _offered(session):
    """A session's offer without ``refused`` (the three fields of the timeline's own question)."""
    offer = session._restore_offer()
    offer.pop("refused")
    return offer


def _refused(rz, sid):
    """Why POST /restore would refuse now, as the offer says it (None where it would run)."""
    return rz.mgr.get(sid)._restore_offer()["refused"]


def _wrote(rz, sid, addr="0x140002200", data="41424344"):
    """What an emulation run leaves in the cache: a write that is not a patch of the session's own. It is made
    on the pipe, as the assistant's copies are, and not through the console, which would spoil the timeline."""
    rz.mgr.get(sid)._pipe.cmd(f"wx {data} @ {addr}")


def _record(rz, sid):
    return rz.mgr.get(sid)._restore


def _console(rz, sid, cmd):
    return rz.send(f"/api/rizin/{sid}/console", {"cmd": cmd})


def _another_file(rz, name, data):
    """A session of a file of its own: opening the same file again in the tab is the same session."""
    sid = rz.open(rz.write(name, data))["session"]
    rz.wait_done(sid)
    return sid


def _started_another(rz, name, addr=None):
    sid = _another_file(rz, name, SAMPLE + name.encode())
    rz.send(f"/api/rizin/{sid}/emulation/start", {} if addr is None else {"addr": addr})
    return sid


def test_the_timeline_records_what_the_emulation_routes_did(rz, monkeypatch):
    # start, a skip with the value and the correction it applied, a step, a patch, a run to an address and a
    # patch by kind -- in that order, because the replay is only the same run if it happens in the order it
    # was made in
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = rz.session()
    assert _state(rz, sid) == {"actions": 0, "tainted": None}, "nothing has started"
    assert _record(rz, sid) is None
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST32_AT:#x}"})
    _skip(rz, sid, ASSIST32_AT, value="0x1", stack_fix=4)
    _run(rz, sid, "step")
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    _run(rz, sid, "until", addr="0x401020")
    _patch(rz, sid, addr=hex(CHECK_JZ), kind="nop")

    written = next(row["after"] for row in _patches(rz, sid) if row["addr"] == CHECK_JZ)
    record = _record(rz, sid)
    assert record["actions"] == [
        {"kind": "start", "addr": ASSIST32_AT},
        {"kind": "skip", "addr": ASSIST32_AT, "value": 1, "fix": 4},
        {"kind": "run", "run": "step"},
        {"kind": "patch", "addr": 0x140001440, "data": "9090"},
        {"kind": "run", "run": "until", "addr": 0x401020},
        {"kind": "patch", "addr": CHECK_JZ, "data": written}], "a patch by kind is the bytes it wrote"
    assert record["counters"] == {"tick": rizin_emulation.TICK_START, "handle": 0, "pseudo": 0}
    assert record["breakpoints"] == [] and record["tainted"] is None
    assert _state(rz, sid) == {"actions": 6, "tainted": None}
    # every one of them is one the writer takes: the timeline is a record without its digests
    line, fitted = rizin_emulation.restore_line(dict(record, digests=[]), 4096)
    assert fitted and rizin_emulation.read_restore(line)["actions"] == record["actions"]


def test_a_refusal_or_a_read_that_fails_does_not_spoil_or_lose_an_action(rz, monkeypatch):
    sid = _started(rz)
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    # a run that is refused before it runs changed nothing: it is not on the timeline, and it spoils nothing
    assert rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"}).status_code == 400
    assert rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "until"}).status_code == 400
    assert _state(rz, sid) == {"actions": 1, "tainted": None}
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid)["actions"] == 2

    # a read after the run that fails: the run happened, so it is on the timeline -- and nothing is spoilt
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_emulation_read", lambda pipe: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        session.emulation_run("step")
    assert _state(rz, sid) == {"actions": 3, "tainted": None}
    with pytest.raises(ValueError):
        session.emulation_start(0x140001440)
    assert [a["kind"] for a in _record(rz, sid)["actions"]] == ["start", "start", "run", "start"], \
        "the start happened, so a start whose read failed is on the timeline too"


def test_a_run_that_fails_after_it_changed_something_spoils_the_timeline(rz, monkeypatch):
    sid = _started(rz)
    session = rz.mgr.get(sid)
    real = session._emulation_command

    def runs_then_fails(pipe, kind, command, addr):
        real(pipe, kind, command, addr)
        raise ValueError("boom")

    monkeypatch.setattr(session, "_emulation_command", runs_then_fails)
    with pytest.raises(ValueError):
        session.emulation_run("step")
    offer = _state(rz, sid)
    assert offer["tainted"] and "half-way" in offer["tainted"]
    assert offer["actions"] == 1, "what failed is not an action: nobody knows what it did"
    # the reason that came first stays
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x1"})
    assert "half-way" in _state(rz, sid)["tainted"]


def test_a_skip_or_a_patch_that_fails_after_it_changed_something_spoils_the_timeline(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 12:#x}")
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_assist_apply", lambda pipe, plan: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        session.call_skip(ASSIST_AT + 12, 0x7, 0)
    offer = _state(rz, sid)
    assert offer["actions"] == 1 and "half-way" in offer["tainted"]

    sid = _started_another(rz, "patchfail.exe")
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_patch_list", lambda pipe, ordered=False: (_ for _ in ()).throw(ValueError("x")))
    with pytest.raises(ValueError):
        session.patch(0x140001440, b"\x90")
    assert _state(rz, sid)["actions"] == 1 and "half-way" in _state(rz, sid)["tainted"]


def test_a_skip_whose_read_fails_is_on_the_timeline_all_the_same(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 12:#x}")
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_emulation_read", lambda pipe: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        session.call_skip(ASSIST_AT + 12, 0x7, 0)
    assert _record(rz, sid)["actions"][1:] == [{"kind": "skip", "addr": ASSIST_AT + 12, "value": 7, "fix": 0}]
    assert _state(rz, sid)["tainted"] is None


def test_a_skip_that_ended_at_the_time_limit_spoils_the_timeline(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 12:#x}")
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_emulation_command", lambda *args: "timeout")
    session.call_skip(ASSIST_AT + 12, None, 0)
    offer = _state(rz, sid)
    assert offer["actions"] == 2 and "time limit" in offer["tainted"]
    assert _record(rz, sid)["actions"][1] == {"kind": "skip", "addr": ASSIST_AT + 12, "value": None, "fix": 0}, \
        "a skip that leaves the register as it is is recorded with no value"


def test_a_register_that_is_set_and_then_not_read_back_still_taints(rz, monkeypatch):
    sid = _started(rz)
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_emulation_read", lambda pipe: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        session.emulation_register("rax", 5)
    assert "register" in _state(rz, sid)["tainted"]


def test_only_an_until_run_carries_an_address(rz):
    sid = _started(rz)
    _run(rz, sid, "step", addr="0x140001450")
    _run(rz, sid, "over", addr="0x140001450")
    _run(rz, sid, "until", addr="0x140001450")
    assert _record(rz, sid)["actions"][1:] == [{"kind": "run", "run": "step"}, {"kind": "run", "run": "over"},
                                               {"kind": "run", "run": "until", "addr": 0x140001450}]


def test_a_patch_refused_before_it_wrote_spoils_nothing(rz):
    sid = _started(rz)
    assert rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "bytes": "zz"}).status_code == 400
    assert rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140001440", "kind": "nonsense"}).status_code == 400
    assert _state(rz, sid) == {"actions": 1, "tainted": None}


@pytest.mark.parametrize("error", [RuntimeError, KeyError, OSError, AssertionError])
def test_whatever_fails_inside_an_action_spoils_the_timeline(rz, monkeypatch, error):
    sid = _started(rz)
    session = rz.mgr.get(sid)
    real = session._emulation_command

    def runs_then_fails(pipe, kind, command, addr):
        real(pipe, kind, command, addr)
        raise error("boom")

    monkeypatch.setattr(session, "_emulation_command", runs_then_fails)
    with pytest.raises(error):
        session.emulation_run("step")
    assert "half-way" in _state(rz, sid)["tainted"]


@pytest.mark.parametrize("kind", ["cont", "to_call", "until"])
def test_a_run_that_ended_in_a_timeout_taints_the_timeline(rz, monkeypatch, kind):
    # the result hangs on the wall clock, so the recording is not reproducible and is never offered
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    sid = _started(rz)
    _run(rz, sid, "step")
    assert _state(rz, sid) == {"actions": 2, "tainted": None}, "a step ended in time"
    state = _run(rz, sid, kind, **({"addr": "0x140001500"} if kind == "until" else {}))
    assert state["stopped"] == "timeout"
    offer = _state(rz, sid)
    assert offer["actions"] == 3 and offer["tainted"] and "time limit" in offer["tainted"]
    # and it stays so: later actions do not make it a timeline again
    _run(rz, sid, "step")
    assert "time limit" in _state(rz, sid)["tainted"] and _state(rz, sid)["actions"] == 4


def test_a_timeout_that_is_followed_by_a_failure_keeps_its_reason(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    sid = _started(rz)
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session, "_emulation_read", lambda pipe: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        session.emulation_run("cont")
    offer = _state(rz, sid)
    assert offer["actions"] == 2 and "time limit" in offer["tainted"], "the run is on it, and it is spoilt for that"


def test_a_run_that_stopped_for_another_reason_is_no_taint(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert _run(rz, sid, "cont")["stopped"] == "breakpoint"
    assert _run(rz, sid, "cont")["stopped"] == "trap"  # a trap is a result, not the clock
    assert _state(rz, sid) == {"actions": 3, "tainted": None}


def test_a_hand_set_register_taints_the_timeline(rz):
    sid = _started(rz)
    _run(rz, sid, "step")
    assert _state(rz, sid)["tainted"] is None
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})
    offer = _state(rz, sid)
    assert offer["tainted"] and "register" in offer["tainted"] and offer["actions"] == 2
    # a register that is refused changed nothing
    sid = _started_another(rz, "refused.exe")
    assert rz.post(f"/api/rizin/{sid}/emulation/register", {"name": "nonsense", "value": "0x5"}).status_code == 400
    assert _state(rz, sid)["tainted"] is None


SPOILING = [
    "wx 90 @ 0x140001440", "w hello @ 0x140001440", "wz hi @ 0x140001440", "wo4 @ 0x140001440", "wc-*",
    "wc- @ 0x140001440", "wc 0x140001440", "ar rax=1", "aer rax=1", "aeim 0x300000 0x100 mine", "aei", "aes", "aepc 0x140001450",
    "aecu 0x140001450", "e esil.timeout=0", "e io.cache=false", "e asm.arch=x86", "ahs 3 @ 0x140001440",
    "ah- @ 0x140001440", "px 4; wx 90 @ 0x140001440", 'a"e"im 0x1000 0x100 x',
    # any setting that is set, not a list of the ones that matter: analysis.gp is ESIL's $gp on MIPS
    "e asm.syntax=intel", "e analysis.gp=0x1000", "e anal.gp=0x1000", "e bin.demangle=true",
    "e asm.syntax=intel analysis.nopskip=false"]
BREAKPOINT_COMMANDS = ["db @ 0x140001450", "db- @ 0x140001450", "db-*", "dbd 0x140001450"]
READING = [
    "px 16", "pd 3", "ar", "ar rax", "arj", "aerj", "wcj", "wc", "e esil.timeout", "e asm.syntax", "el", "elj",
    "e asm.arch", "pdj 2 @ 0x140001440", "ae?", "w?", "dbl", "dblj", "afl", "s 0x140001440", "iz", "ahl",
    "ar=", "e io.cache", "px 4 @ 0x140001440; ar", "e asm.bits"]


@pytest.mark.parametrize("cmd", SPOILING)
def test_a_console_command_that_writes_or_sets_taints_the_timeline(rz, cmd):
    sid = _started(rz)
    assert _state(rz, sid)["tainted"] is None
    _console(rz, sid, cmd)
    offer = _state(rz, sid)
    assert offer["tainted"] and offer["actions"] == 1, cmd
    assert "breakpoint" not in offer["tainted"], (cmd, offer["tainted"])


@pytest.mark.parametrize("cmd", READING)
def test_a_console_command_that_only_reads_spoils_nothing(rz, cmd):
    sid = _started(rz)
    _console(rz, sid, cmd)
    assert _state(rz, sid) == {"actions": 1, "tainted": None}, cmd


def test_the_console_filter_agrees_with_the_lists_of_what_spoils(rz):
    import rizin_sessions

    for cmd in SPOILING:
        assert rizin_sessions.check_console_command(cmd) is None, cmd
        kind = ("_RESTORE_GONE" if cmd.startswith("wc-") else
                "_RESTORE_HAND_WRITE" if cmd.startswith(("w", "px 4; w")) else
                "_RESTORE_HAND_SETTING" if cmd.startswith(("e ", "ah")) else
                "_RESTORE_HAND_SETUP" if cmd.replace('"', "").split()[0] in ("aei", "aeim", "aepc") else "_RESTORE_HAND_EMULATION")
        assert rizin_sessions._console_spoils(cmd) == getattr(rizin_sessions, kind), cmd
    for cmd in BREAKPOINT_COMMANDS:
        assert rizin_sessions.check_console_command(cmd) is None, cmd
        assert rizin_sessions._console_moves_breakpoints(cmd) and rizin_sessions._console_spoils(cmd) is None, cmd
    for cmd in READING:
        assert rizin_sessions.check_console_command(cmd) is None, cmd
        assert rizin_sessions._console_spoils(cmd) is None, cmd
        assert not rizin_sessions._console_moves_breakpoints(cmd), cmd


def test_a_console_command_taints_before_it_runs(rz, monkeypatch):
    # what a command did before it failed is done, so the taint does not wait for its answer
    sid = _started(rz)
    session = rz.mgr.get(sid)
    monkeypatch.setattr(session._pipe, "console", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    with pytest.raises(ValueError):
        session.console("wx 90 @ 0x140001440")
    assert _state(rz, sid)["tainted"]


def test_a_breakpoint_changed_between_two_actions_taints_the_timeline(rz):
    # the breakpoints the timeline began with are the ones it ran under; a run stops at the ones there are
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert _record(rz, sid)["breakpoints"] == [0x1400014B7], "the set it began with, once for all of it"
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})  # set again: no change
    _run(rz, sid, "cont")
    assert _state(rz, sid) == {"actions": 2, "tainted": None}
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    assert _state(rz, sid)["tainted"] is None, "nothing has run under it yet"
    _run(rz, sid, "step")  # the change stood between two actions
    assert "breakpoint" in _state(rz, sid)["tainted"] and _state(rz, sid)["actions"] == 3
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})  # back where it began: it stays spoilt
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]


def test_a_breakpoint_that_is_put_back_before_the_next_action_changes_nothing(rz):
    sid = rz.session()
    for addr in ("0x1400014b7", "0x140001450"):
        rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": addr})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    _run(rz, sid, "step")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    assert _state(rz, sid) == {"actions": 3, "tainted": None}, "the run was replayable: it ran under the same set"
    # the same through the console, whose db is read back once it has run
    _console(rz, sid, "db @ 0x140001480")
    _console(rz, sid, "db- @ 0x140001480")
    _run(rz, sid, "step")
    assert _state(rz, sid) == {"actions": 4, "tainted": None}
    _console(rz, sid, "db @ 0x140001480")
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]


@pytest.mark.parametrize("action", ["run", "patch", "skip", "start"])
def test_every_kind_of_action_sees_a_breakpoint_that_changed_before_it(rz, monkeypatch, action):
    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 12:#x}")
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    assert _state(rz, sid)["tainted"] is None
    {"run": lambda: _run(rz, sid, "step"),
     "patch": lambda: _patch(rz, sid, addr="0x140001440", bytes="90"),
     "skip": lambda: _skip(rz, sid, ASSIST_AT + 12),
     "start": lambda: rz.send(f"/api/rizin/{sid}/emulation/start", {})}[action]()
    assert "breakpoint" in _state(rz, sid)["tainted"], action


def test_a_breakpoint_that_differs_now_is_said_by_the_offer_until_it_is_put_back(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    assert _offer(rz, sid) == {"actions": 1, "reason": None, "digests": 1}
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    offer = _offer(rz, sid)
    assert "breakpoint" in offer["reason"] and offer["digests"] == 1, "a replay would run under another set"
    assert _state(rz, sid)["tainted"] is None, "and it is not the record's: no action has run under it"
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    assert _offer(rz, sid) == {"actions": 1, "reason": None, "digests": 1}
    _console(rz, sid, "db- @ 0x1400014b7")
    assert "breakpoint" in _offer(rz, sid)["reason"], "a console db is read back too"


@pytest.mark.parametrize("error", ["value", "large"])
def test_a_breakpoint_that_cannot_be_read_back_after_a_console_db_counts_as_changed(rz, monkeypatch, error):
    import rizin_sessions

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    session = rz.mgr.get(sid)
    real = session._breakpoint_list
    boom = ValueError("x") if error == "value" else rizin_sessions.RizinTooLarge("big")
    monkeypatch.setattr(session, "_breakpoint_list", lambda pipe: (_ for _ in ()).throw(boom))
    _console(rz, sid, "db @ 0x140001480")  # the console answers: reading the set back is the timeline's own
    monkeypatch.setattr(session, "_breakpoint_list", real)
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"], "what the set is was not read, so it counts as changed"


@pytest.mark.parametrize("error", [OSError, BrokenPipeError])
def test_a_console_db_that_ran_and_then_failed_leaves_the_breakpoints_as_changed(rz, monkeypatch, error):
    # what a command did before it failed is done: the db removed the breakpoint, and the answer never came
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    session = rz.mgr.get(sid)
    real = session._pipe.console

    def runs_then_fails(text, *args, **kwargs):
        real(text, *args, **kwargs)
        raise error("the pipe broke")

    monkeypatch.setattr(session._pipe, "console", runs_then_fails)
    with pytest.raises(error):
        session.console("db- @ 0x1400014b7")
    monkeypatch.setattr(session._pipe, "console", real)
    assert rz.read(f"/api/rizin/{sid}/breakpoints") == [], "it really did remove it"
    assert "breakpoint" in _offer(rz, sid)["reason"]
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]


def test_a_console_db_that_changes_nothing_is_cleared_again_once_it_has_been_read_back(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _console(rz, sid, "db @ 0x1400014b7")  # already there
    assert rz.mgr.get(sid)._restore_bp_moved is False
    _run(rz, sid, "step")
    assert _state(rz, sid) == {"actions": 2, "tainted": None}


def test_a_standing_breakpoint_change_does_not_follow_a_timeline_into_the_next(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    assert "breakpoint" in _offer(rz, sid)["reason"]
    rz.remove(f"/api/rizin/{sid}/patch", {})  # gone, with the standing change
    assert "no longer kept" in _offer(rz, sid)["reason"], "after a discard, why it is gone"
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})  # begins over no breakpoint at all
    _run(rz, sid, "step")
    assert _state(rz, sid) == {"actions": 2, "tainted": None}
    assert _record(rz, sid)["breakpoints"] == []


def test_a_record_that_is_tainted_says_its_taint_before_a_breakpoint_that_stands_other(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    assert "register" in _offer(rz, sid)["reason"]


def test_the_breakpoints_are_compared_as_a_set_whatever_order_they_were_set_in(rz):
    sid = rz.session()
    for addr in ("0x1400014b7", "0x140001450", "0x140001480"):
        rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": addr})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert _record(rz, sid)["breakpoints"] == [0x140001450, 0x140001480, 0x1400014B7], "ascending, once each"
    for addr in ("0x140001480", "0x1400014b7", "0x140001450"):
        rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": addr})
    _run(rz, sid, "step")
    assert _state(rz, sid)["tainted"] is None, "the same three, set again"
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001480"})
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]


def test_clearing_a_breakpoint_the_timeline_began_with_taints_it(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]
    # all of them, with an empty body: the same
    sid = _another_file(rz, "again.exe", SAMPLE + b"1")
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert _state(rz, sid)["tainted"] is None
    rz.remove(f"/api/rizin/{sid}/breakpoints", {})
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]
    # clearing where there is none is no change
    sid = _another_file(rz, "none.exe", SAMPLE + b"2")
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.remove(f"/api/rizin/{sid}/breakpoints", {})
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    _run(rz, sid, "step")
    assert _state(rz, sid)["tainted"] is None


def test_a_breakpoint_that_rizin_kept_but_that_changed_the_set_spoils_the_timeline(rz, monkeypatch):
    import rizin_sessions

    sid = rz.session()
    for addr in ("0x140001450", "0x1400014b7"):
        rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": addr})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    session = rz.mgr.get(sid)
    real = session._breakpoint_list
    monkeypatch.setattr(session, "_breakpoint_list", lambda pipe: [{"addr": 0x140001450, "enabled": True}])
    with pytest.raises(rizin_sessions.RizinRefused):
        session.breakpoint_clear(0x140001450)  # rizin kept this one, and the other one went
    monkeypatch.setattr(session, "_breakpoint_list", real)
    _run(rz, sid, "step")
    assert "breakpoint" in _state(rz, sid)["tainted"]


def test_a_breakpoint_before_the_timeline_began_is_part_of_it_not_a_change(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001450"})
    assert _record(rz, sid) is None and _state(rz, sid)["tainted"] is None
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    assert _record(rz, sid)["breakpoints"] == [0x1400014B7] and _state(rz, sid)["tainted"] is None


def test_a_cache_that_held_writes_before_the_timeline_began_taints_it_from_the_start(rz):
    # a console wx before the first start is no run: run_digests would hash it as one, and no replay writes it
    sid = rz.session()
    _console(rz, sid, "e io.cache=true")
    _console(rz, sid, "wx 9090 @ 0x140001440")
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    offer = _state(rz, sid)
    assert offer["actions"] == 1 and offer["tainted"] and "cache" in offer["tainted"]
    # a patch of the session's own before the start is no such write: it is the project's, and replays at open
    sid = _another_file(rz, "clean.exe", SAMPLE + b"3")
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid) == {"actions": 1, "tainted": None}
    assert [a["kind"] for a in _record(rz, sid)["actions"]] == ["start"], "a patch before the start is not an action"


@pytest.mark.parametrize("which", ["_patch_list", "_breakpoint_list"])
@pytest.mark.parametrize("error", ["value", "large"])
def test_a_read_that_fails_when_the_timeline_begins_does_not_cost_the_start(rz, monkeypatch, which, error):
    import rizin_sessions

    sid = rz.session()
    session = rz.mgr.get(sid)
    boom = ValueError("x") if error == "value" else rizin_sessions.RizinTooLarge("big")

    def fails(*args, **kwargs):
        raise boom

    monkeypatch.setattr(session, which, fails)
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert state["pc"] == hex(ENTRY)
    offer = _state(rz, sid)
    assert offer["actions"] == 1 and offer["tainted"] and "did not say" in offer["tainted"]


def test_the_timeline_holds_the_counters_as_they_stand_when_it_begins(rz):
    sid = rz.session()
    session = rz.mgr.get(sid)
    session._assist_tick, session._assist_handle, session._assist_pseudo = 0x1234, 5, 7
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _record(rz, sid)["counters"] == {"tick": 0x1234, "handle": 5, "pseudo": 7}


def test_a_new_timeline_after_a_discard_holds_the_counters_of_its_own_start(rz, monkeypatch):
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = _started(rz, f"{ASSIST_AT + 12:#x}")
    _skip(rz, sid, ASSIST_AT + 12, value=_assist(rz, sid, ASSIST_AT + 12)["value"])
    moved = rz.mgr.get(sid)._assist_tick
    assert moved > rizin_emulation.TICK_START
    rz.remove(f"/api/rizin/{sid}/patch", {})  # nothing in the cache: nothing is taken out
    assert _record(rz, sid) is not None
    _patch(rz, sid, addr="0x140001440", bytes="90")
    rz.remove(f"/api/rizin/{sid}/patch", {})
    assert _record(rz, sid) is None
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _record(rz, sid)["counters"]["tick"] == moved, "the replay of this timeline begins where this one did"


def test_the_value_a_skip_records_is_cut_to_the_width_of_the_register(rz, monkeypatch):
    # the fake does not cut it; rizin does, which test_real_rizin_the_recorded_skip_value_is_what_was_applied pins
    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    sid = _started(rz, f"{ASSIST32_AT:#x}")
    _skip(rz, sid, ASSIST32_AT, value="0x100000041", stack_fix=4)
    assert _record(rz, sid)["actions"][-1]["value"] == 0x41


def test_a_64_bit_register_keeps_all_of_the_value_a_skip_records(rz):
    sid = _started(rz, f"{SLEEP_CALL:#x}")
    _skip(rz, sid, SLEEP_CALL, value="0x100000041")
    assert _record(rz, sid)["actions"][-1]["value"] == 0x100000041


def test_a_second_emulation_start_is_an_action_of_the_same_timeline(rz, monkeypatch):
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST_AT + 12:#x}"})
    first = _record(rz, sid)
    _skip(rz, sid, ASSIST_AT + 12, value=_assist(rz, sid, ASSIST_AT + 12)["value"])
    assert rz.mgr.get(sid)._assist_tick > rizin_emulation.TICK_START, "the skip moved the clock on"
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    record = _record(rz, sid)
    assert record is first, "the same timeline, not a new one"
    assert [a["kind"] for a in record["actions"]] == ["start", "skip", "start"]
    assert record["actions"][2] == {"kind": "start", "addr": 0x140001440}
    assert record["counters"] == {"tick": rizin_emulation.TICK_START, "handle": 0, "pseudo": 0}, \
        "the counters are those of the first start: the replay sets them back to it"
    assert record["breakpoints"] == [0x1400014B7]
    assert _state(rz, sid) == {"actions": 3, "tainted": None}
    # a start with no address is at the seek: it is the address that is recorded
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert record["actions"][3] == {"kind": "start", "addr": rz.mgr.get(sid).at}


def test_a_start_that_fails_is_no_action_and_no_timeline(rz):
    sid = rz.session()
    assert rz.post(f"/api/rizin/{sid}/emulation/start", {"addr": "zzz"}).status_code == 400
    assert _record(rz, sid) is None
    sid = _started(rz)
    assert rz.post(f"/api/rizin/{sid}/emulation/start", {"addr": "-1"}).status_code == 400
    assert len(_record(rz, sid)["actions"]) == 1


def test_taking_something_out_of_the_cache_discards_the_timeline(rz):
    import rizin_sessions

    for body in ({}, {"addr": "0x140001440"}):
        sid = _started_another(rz, f"discard{len(body)}.exe")
        _patch(rz, sid, addr="0x140001440", bytes="9090")
        _run(rz, sid, "step")
        assert _state(rz, sid)["actions"] == 3
        rz.remove(f"/api/rizin/{sid}/patch", body)
        assert _offer(rz, sid) == {"actions": 0, "reason": rizin_sessions._RESTORE_GONE, "digests": 0}, body
        assert "no longer kept" in _offer(rz, sid)["reason"]
        assert _record(rz, sid) is None
        # nothing more is written to what is gone, and later taints have nothing to spoil
        _run(rz, sid, "step")
        rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x1"})
        assert _record(rz, sid) is None and _state(rz, sid)["actions"] == 0


def test_taking_back_where_there_is_nothing_keeps_the_timeline(rz):
    sid = _started(rz)
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140009000"})  # no write there
    assert _state(rz, sid) == {"actions": 2, "tainted": None}
    sid = _another_file(rz, "empty.exe", SAMPLE + b"4")
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    rz.remove(f"/api/rizin/{sid}/patch", {})  # an empty cache stays empty
    assert _state(rz, sid) == {"actions": 1, "tainted": None}


def test_a_taint_and_a_discard_end_in_the_discard_and_a_new_start_begins_a_new_timeline(rz):
    import rizin_sessions

    sid = _started(rz)
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x1"})
    assert "register" in _state(rz, sid)["tainted"]
    rz.remove(f"/api/rizin/{sid}/patch", {})
    assert _state(rz, sid)["tainted"] == rizin_sessions._RESTORE_GONE, "the reason that is left is the discard"
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid) == {"actions": 1, "tainted": None}, "a new timeline, a clean one"
    assert session._restore_gone is None
    # and a discard of a timeline that never was says nothing
    sid = _another_file(rz, "nothing.exe", SAMPLE + b"5")
    _patch(rz, sid, addr="0x140001440", bytes="90")
    rz.remove(f"/api/rizin/{sid}/patch", {})
    assert _state(rz, sid) == {"actions": 0, "tainted": None}


def test_an_unpatch_that_fails_after_the_command_discards_the_timeline(rz, monkeypatch):
    # what the command took out is not known any more
    sid = _started(rz)
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    session = rz.mgr.get(sid)
    real, calls = session._patch_list, []

    def fails_the_second_read(pipe, ordered=False):
        calls.append(1)
        if len(calls) == 2:
            raise ValueError("boom")
        return real(pipe, ordered)

    monkeypatch.setattr(session, "_patch_list", fails_the_second_read)
    with pytest.raises(ValueError):
        session.unpatch(0x140001440)
    assert _record(rz, sid) is None and "no longer kept" in _state(rz, sid)["tainted"]


def test_an_unpatch_that_is_refused_after_it_took_something_out_discards_the_timeline(rz, monkeypatch):
    # rizin kept the row at the address, and took another one: the cache is not what the timeline made
    import rizin_sessions

    sid = _started(rz)
    _patch(rz, sid, addr="0x140001440", bytes="9090")
    _patch(rz, sid, addr="0x140001450", bytes="9090")
    session = rz.mgr.get(sid)
    real, calls = session._patch_list, []

    def keeps_a_row_at_the_address(pipe, ordered=False):
        calls.append(1)
        rows = real(pipe, ordered)
        if len(calls) == 2:
            rows = [r for r in rows if r["addr"] != 0x140001440] + [
                {"addr": 0x140001440, "size": 1, "before": "ff", "after": "cc", "mine": False, "over_run": False}]
        return rows

    monkeypatch.setattr(session, "_patch_list", keeps_a_row_at_the_address)
    with pytest.raises(rizin_sessions.RizinRefused):
        session.unpatch(0x140001440)
    assert _record(rz, sid) is None


def test_the_timeline_stops_growing_where_a_project_would_not_keep_it(rz, monkeypatch):
    import rizin_emulation

    monkeypatch.setattr(rizin_emulation, "RESTORE_MAX_ACTIONS", 4)
    sid = _started(rz)
    for _ in range(3):
        _run(rz, sid, "step")
    assert _state(rz, sid) == {"actions": 4, "tainted": None}, "four is the most it keeps"
    _run(rz, sid, "step")
    state = _state(rz, sid)
    assert state["actions"] == 4 and "dropped" in state["tainted"] and "4 actions" in state["tainted"]
    assert "longer than" not in state["tainted"], "four are kept: what taints is the fifth that is not"


def test_the_fake_takes_a_register_before_aei_and_keeps_it_through_aei_like_rizin(rz):
    # measured on rizin 0.9.1 (test_real_rizin_the_recorded_skip_value_is_what_was_applied): `ar eax=0x1234` is
    # accepted before aei, reads back, and is still there after aei, aeim and aepc. The fake used to refuse it.
    def held(sid, name="rax"):
        return int(_console(rz, sid, f"ar {name}")["output"].split("=")[1], 16)

    sid = rz.session()
    assert held(sid) == 0
    assert _console(rz, sid, "ar rax=0x1234")["output"] == ""
    assert held(sid) == 0x1234
    _console(rz, sid, "aepc 0x140001450")
    assert held(sid, "PC") == 0x140001450
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert held(sid) == 0x1234
    assert _word(next(r["value"] for r in rz.read(f"/api/rizin/{sid}/emulation")["registers"]
                      if r["name"] == "rax")) == 0x1234


# What a start does not undo: it closes every ESIL map, runs aei and aeim, and sets the PC (and aeim the stack
# pointer and the base pointer) -- measured on rizin 0.9.1 -- so a register other than those, and the registers
# and rows of a step, are still there when the run begins. (`aer` is no command of rizin 0.9.1: "Command 'aer'
# does not exist". It is classified like `ar` so that a build that has it is safe.)
SURVIVES_A_START = ["ar rax=0x1234", "ar rcx=0x5", "aer rax=0x1234", "aes", "aeso", "aess", "aesu 0x140001450"]
# What it does undo: arming, mapping and the PC.
GONE_AFTER_A_START = ["aei", "aei-", "aeim", "aeim 0x300000 0x100 mine", "aeim-", "aepc 0x140001450", "aeip"]


@pytest.mark.parametrize("arm", ["aei", "aeim"])
def test_the_fake_loses_the_pc_the_sp_and_the_bp_when_it_arms_but_keeps_the_rest(rz, arm):
    # measured on rizin 0.9.1 and written into fake_rizin's contract: `aepc 0x3; aei; ar PC` is 0, `aepc 0x3; aeim`
    # with no aei at all as well, `ar esp=0x1234; aei; aeim` leaves esp in the new stack and `ar ecx=…` stays
    def held(sid, name):
        return int(_console(rz, sid, f"ar {name}")["output"].split("=")[1], 16)

    sid = rz.session()
    for command in ("aepc 0x3", "ar rsp=0x1234", "ar rbp=0x1234", "ar rcx=0x1234"):
        _console(rz, sid, command)
    assert [held(sid, n) for n in ("PC", "rsp", "rbp", "rcx")] == [3, 0x1234, 0x1234, 0x1234]
    _console(rz, sid, arm)
    assert held(sid, "PC") == ENTRY
    if arm == "aeim":
        assert held(sid, "rsp") == held(sid, "rbp") == 0x178000, "in the middle of the stack it mapped"
    assert held(sid, "rcx") == 0x1234


@pytest.mark.parametrize("cmd", SURVIVES_A_START)
def test_a_console_command_before_the_first_start_that_a_start_does_not_undo_spoils_the_timeline(rz, cmd):
    sid = rz.session()
    _console(rz, sid, cmd)
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    state = _state(rz, sid)
    assert state["actions"] == 1 and state["tainted"] and "emulation" in state["tainted"], cmd
    # and it is said once: the next timeline begins from what is true then
    sid = _another_file(rz, f"{cmd[:3]}.exe", SAMPLE + cmd.encode())
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid)["tainted"] is None


@pytest.mark.parametrize("cmd", GONE_AFTER_A_START)
def test_a_console_command_before_the_first_start_that_a_start_undoes_spoils_nothing(rz, cmd):
    # the start gives the ESIL memory back, arms the VM again and sets the PC: a replay does the same
    sid = rz.session()
    _console(rz, sid, cmd)
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid) == {"actions": 1, "tainted": None}, cmd
    assert rz.mgr.get(sid)._restore_pending is None


@pytest.mark.parametrize("cmd", GONE_AFTER_A_START)
def test_but_in_the_middle_of_a_timeline_the_same_commands_still_spoil_it(rz, cmd):
    sid = _started(rz)
    _console(rz, sid, cmd)
    assert _state(rz, sid)["tainted"], cmd


@pytest.mark.parametrize("cmd", ["e asm.arch=x86", "e asm.syntax=intel", "e esil.timeout=9", "ahs 3 @ 0x140001440",
                                 "db @ 0x140001480"])
def test_a_setting_a_hint_or_a_breakpoint_before_the_first_start_is_part_of_where_it_began(rz, cmd):
    # the project keeps the settings, the hints and the breakpoints, so a replay begins with them
    sid = rz.session()
    _console(rz, sid, cmd)
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid) == {"actions": 1, "tainted": None}, cmd


def test_a_write_that_was_taken_out_again_before_the_first_start_spoils_nothing(rz):
    sid = rz.session()
    _console(rz, sid, "e io.cache=true")
    _console(rz, sid, "wx 9090 @ 0x140001440")
    _console(rz, sid, "wc-*")
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid) == {"actions": 1, "tainted": None}


def test_what_was_set_by_hand_before_a_start_spoils_that_timeline_only_and_comes_first(rz):
    sid = rz.session()
    _console(rz, sid, "e io.cache=true")
    _console(rz, sid, "wx 9090 @ 0x140001440")  # a foreign row, which would name the cache
    _console(rz, sid, "ar rax=0x5")
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert "emulation" in _state(rz, sid)["tainted"], "the register is the cause worth naming"
    assert rz.mgr.get(sid)._restore_pending is None
    _wrote(rz, sid)
    rz.remove(f"/api/rizin/{sid}/patch", {})  # discarded: the next start begins a new one, which is clean
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _state(rz, sid) == {"actions": 1, "tainted": None}


def test_a_register_set_by_hand_after_a_discard_spoils_the_next_timeline(rz):
    sid = _started(rz)
    _patch(rz, sid, addr="0x140001440", bytes="90")
    rz.remove(f"/api/rizin/{sid}/patch", {})
    assert _record(rz, sid) is None
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {})  # aei keeps the register
    assert "register" in _state(rz, sid)["tainted"]


@pytest.mark.parametrize("error", ["timeout", "died"])
def test_a_pipe_that_stops_while_the_timeline_begins_ends_the_session_and_is_not_swallowed(rz, monkeypatch, error):
    # RizinTimeout and RizinDied are Exceptions, and swallowing them here would let the start answer "done" on
    # a rizin that has been killed: the session has to end, as it does for any other command (_call)
    import rizin_sessions

    sid = rz.session()
    session = rz.mgr.get(sid)
    boom = rizin_sessions.RizinTimeout("slow") if error == "timeout" else rizin_sessions.RizinDied("gone")

    def stops(*args, **kwargs):
        raise boom

    monkeypatch.setattr(session, "_breakpoint_list", stops)
    with pytest.raises(type(boom)):
        session.emulation_start(0x140001440)
    assert session.closed
    assert session._restore is None


def test_a_rizin_restart_drops_the_timeline_and_says_why(sessions, sample, fake, tmp_path, monkeypatch):
    """_recover gives the session a rizin with an empty cache: the run's rows are gone, so the digests Task 4
    would make are none, while the record would go on claiming it can be replayed. The timeline goes, with a
    reason of its own, the way the project's own save (_saved_cache) leaves a project alone rather than
    strip it by guesswork over a cache that died. The next start begins a new one, on a cache that is true."""
    import rizin_sessions

    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    session = mgr.get(mgr.open(sample("restart.exe", b"MZ restart"), "tab")["session"])
    _wait_state(session, "done")
    session.emulation_start(0x140001440)
    session.emulation_run("step")
    session._pipe.cmd("wx 41424344 @ 0x140002200")  # what the run left
    assert _offered(session) == {"actions": 2, "reason": None, "digests": 1}

    session.analyze_full()  # its aar hangs, so rizin is killed and restarted
    _wait_state(session, "stopped")
    assert session._restore is None and session._restore_gone == rizin_sessions._RESTORE_RESTARTED
    # What the project holds is what is offered then (spec 3: a restart is treated as the open is, and the
    # restore is offered): the analysis step saved the timeline before it hung, with the digests of the cache that
    # was alive, and the new rizin's empty cache is the one a replay starts from. A session that never saved one
    # says what happened to its own.
    assert _offered(session) == {"actions": 2, "reason": None, "digests": 1}
    saved, session._restore_saved = session._restore_saved, None
    offer = session._restore_offer()
    assert offer["actions"] == 0 and offer["digests"] == 0
    assert offer["reason"] == rizin_sessions._RESTORE_RESTARTED and "restarted" in offer["reason"]
    session._restore_saved = saved
    session.emulation_start(0x140001440)
    assert session._restore_offer()["actions"] == 1 and session._restore["tainted"] is None
    assert session._restore_gone is None


def test_a_rizin_restart_forgets_what_the_old_rizin_was_told_by_hand(sessions, sample, fake, tmp_path, monkeypatch):
    # the new rizin's registers are its own: a register the old one was given does not spoil the next timeline
    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    session = mgr.get(mgr.open(sample("restart2.exe", b"MZ restart 2"), "tab")["session"])
    _wait_state(session, "done")
    session.emulation_start(0x140001440)
    session.emulation_run("step")
    session._pipe.cmd("wx 41424344 @ 0x140002200")
    session.unpatch()  # the timeline is gone ...
    assert session._restore is None
    session.emulation_register("rax", 5)  # ... and the register that is set now would spoil the next one
    assert session._restore_pending
    session.analyze_full()
    _wait_state(session, "stopped")
    assert session._restore_pending is None
    session.emulation_start(0x140001440)
    assert session._restore["tainted"] is None


def test_the_offer_says_how_many_ranges_the_record_would_prove_right_now(rz):
    import rizin_emulation

    sid = rz.session()
    assert _offer(rz, sid) == {"actions": 0, "reason": None, "digests": 0}
    mark = len(rz.commands())
    _offer(rz, sid)
    assert rz.commands()[mark:] == [], "with no timeline there is nothing to ask rizin"

    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert _offer(rz, sid) == {"actions": 1, "reason": rizin_emulation_reason("nothing"), "digests": 0}
    _wrote(rz, sid)
    assert _offer(rz, sid) == {"actions": 1, "reason": None, "digests": 1}
    _wrote(rz, sid, "0x140003000", "4142")
    _wrote(rz, sid, "0x140002202", "ff")  # over the first: one range still
    assert _offer(rz, sid) == {"actions": 1, "reason": None, "digests": 2}
    # and it is the number run_digests makes from the cache, which is what the save will write
    rows = rz.mgr.get(sid).patches_made()
    assert len(rizin_emulation.run_digests(rows, rizin_emulation.run_only_ranges(rows))) == 2
    # a patch over a run's byte does not take its range away from the proof
    _patch(rz, sid, addr="0x140002201", bytes="90")
    assert _offer(rz, sid)["digests"] == 2


def rizin_emulation_reason(which):
    import rizin_sessions

    return {"nothing": rizin_sessions._RESTORE_NOTHING}[which]


def test_the_offer_shows_the_proof_going_where_the_cache_lost_it(rz):
    # the cache emptied behind the timeline's back (what a restart did): 1 range becomes 0, and the offer says so
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    _wrote(rz, sid)
    assert _offer(rz, sid)["digests"] == 1
    rz.mgr.get(sid)._pipe.cmd("wc-*")
    offer = _offer(rz, sid)
    assert offer["digests"] == 0 and offer["reason"] == rizin_emulation_reason("nothing")


def test_the_offers_reason_is_the_records_taint_first_and_still_counts_the_ranges(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    _wrote(rz, sid)
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})
    offer = _offer(rz, sid)
    assert "register" in offer["reason"] and offer["digests"] == 1 and offer["actions"] == 1
    # the field the pane reads is the offer's; the record keeps its own
    assert _record(rz, sid)["tainted"] == offer["reason"]
    assert set(offer) == {"actions", "reason", "digests"}


def test_the_digests_are_made_from_the_rows_in_the_order_they_were_written(rz):
    # spec 5: by address the two rows below change places, and the digest would be of `aaeeccdd`, a plausible
    # SHA-256 that is nobody's bytes; run_digests cannot tell, so what feeds it is pinned here
    import hashlib

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    session = rz.mgr.get(sid)
    _wrote(rz, sid, "0x140002201", "ee")
    _wrote(rz, sid, "0x140002200", "aabbccdd")
    with _held(session) as pipe:
        digests = session._restore_digests(pipe)
    assert digests == [{"start": 0x140002200, "end": 0x140002203,
                        "sha256": hashlib.sha256(bytes.fromhex("aabbccdd")).hexdigest()}]


class _held:
    """The gate and the pipe of a session, the way a request holds them."""

    def __init__(self, session):
        self.session = session

    def __enter__(self):
        self.session._gate.enter("test", 1.0)
        return self.session._pipe

    def __exit__(self, *exc):
        self.session._gate.leave()


def test_a_tainted_record_with_no_range_to_prove_says_its_taint_not_that_there_is_nothing(rz):
    sid = _started(rz)
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})
    assert _offer(rz, sid) == {"actions": 1, "reason": _record(rz, sid)["tainted"], "digests": 0}
    assert "register" in _offer(rz, sid)["reason"]


def test_the_offer_waits_for_the_gate_like_any_view(rz):
    import threading
    import rizin_sessions

    sid = rz.session()
    session = rz.mgr.get(sid)
    session._gate.enter("test", 1.0)
    try:
        assert _offered(session) == {"actions": 0, "reason": None, "digests": 0}, \
            "with no timeline there is nothing to wait for"
    finally:
        session._gate.leave()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    session._gate.enter("test", 1.0)
    try:
        with pytest.raises(rizin_sessions.RizinBusy):
            session._restore_offer(wait=0.05)
    finally:
        session._gate.leave()
    # and it waits as long as it is told to, not for ever and not for nothing
    session._gate.enter("test", 1.0)
    threading.Timer(0.3, session._gate.leave).start()
    assert session._restore_offer(wait=5.0)["actions"] == 1


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
def test_real_rizin_the_recorded_skip_value_is_what_was_applied(tmp_path, monkeypatch):
    """What the timeline records against rizin 0.9.1 itself, on 32-bit code (a raw blob whose arch and bits
    are set after it is opened, as test_real_rizin_assists_a_32_bit_stdcall_call does).

    The skip's value is **what the register holds afterwards**, not what was asked: ``ar eax=<more than 32
    bits>`` is cut to the register's width (measured: 0x100000041 reads back as 0x41, and 2^64-1 as
    0xffffffff), so a record of the request would name a value no register ever had. Three more facts the
    fake models: ``dblj`` names the breakpoints the timeline begins with, a console ``wx`` before the first
    start is a write of the cache that is no run's and no patch's (so the timeline begins spoilt), and a run
    that ends at the time limit is ``timeout``.
    """
    import rizin_sessions

    # push 0x40; push 0x1000; push 0x200; push 0; call dword [0x100]  (VirtualAlloc, stdcall, 4 arguments)
    code = bytes.fromhex("6a40680010000068000200006a00" "ff1500010000" "90c3")
    alloc_call = 0xE
    blob = bytearray(0x200)
    blob[:len(code)] = code
    (tmp_path / "call32.bin").write_bytes(bytes(blob))
    (tmp_path / "loop32.bin").write_bytes(bytes.fromhex("ebfe") + bytes(62))  # jmp $
    (tmp_path / "nops32.bin").write_bytes(bytes.fromhex("90909090") + bytes(60))
    for name in ("mov32.bin", "mov32b.bin"):  # a file of its own for each session: the same file is the same session
        (tmp_path / name).write_bytes(bytes.fromhex("b905000000" "6a40") + bytes(60) + name.encode())  # mov ecx, 5; push
    monkeypatch.setattr(rizin_sessions, "ESIL_TIMEOUT", 1.0)
    monkeypatch.setattr(rizin_sessions, "ESIL_SETTINGS", tuple(
        "esil.timeout=1" if c.startswith("esil.timeout=") else c for c in rizin_sessions.ESIL_SETTINGS))
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))

    def opened(name):
        session = mgr.get(mgr.open(str(tmp_path / name), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.text("e asm.arch=x86")
        session.text("e asm.bits=32")
        session.arch, session.bits = "x86", 32
        return session

    try:
        session = opened("call32.bin")
        session.text("f sym.imp.KERNEL32.dll_VirtualAlloc @ 0x100")
        session.breakpoint_set(0x20)
        for asked in (0x41, 0x1_0000_0041, 2 ** 64 - 1):
            session.emulation_start(0)
            for _ in range(4):
                session.emulation_run("step")
            state = session.call_skip(alloc_call, asked, 16)
            held = _word(next(r["value"] for r in state["registers"] if r["name"] == "eax"))
            assert held == asked & 0xFFFFFFFF
            skip = session._restore["actions"][-1]
            assert skip == {"kind": "skip", "addr": alloc_call, "value": held, "fix": 16}, (hex(asked), skip)
        assert session._restore["breakpoints"] == [0x20], "dblj's address, the one the timeline began with"
        assert session._restore["tainted"] is None
        # the four pushes wrote into the emulation's stack, which is the run's too: one range to prove
        offer = session._restore_offer()
        assert _offered(session) == {"actions": 3 * (1 + 4 + 1), "reason": None, "digests": 1}, offer
        stack = session._emulation_stack_map
        assert [r["addr"] for r in session.patches()["patches"] if not r["mine"]] and stack
        session._pipe.cmd("wx 4142 @ 0x30")  # and what a run leaves elsewhere
        assert session._restore_offer()["digests"] == 2

        # a console write before the first start is a foreign row of the cache: the timeline begins spoilt
        session = opened("loop32.bin")
        session.text("e io.cache=true")
        session.console("wx 90 @ 0x30")
        assert [row["mine"] for row in session.patches()["patches"]] == [False]
        session.emulation_start(0)
        assert "cache" in session._restore_offer()["reason"]

        # and a run that ends at the time limit spoils one that began clean
        session.unpatch()
        assert session._restore_offer()["actions"] == 0, "taking it out of the cache dropped the timeline"
        session.emulation_start(0)
        assert session._restore["tainted"] is None
        assert session.emulation_run("cont")["stopped"] == "timeout"
        offer = session._restore_offer()
        assert offer["actions"] == 2 and "time limit" in offer["reason"]

        # a register set before the first start is read by the run: rizin takes `ar` before aei and keeps it
        # through aei, aeim and aepc and a step (the fake does the same), so the timeline begins spoilt
        session = opened("nops32.bin")
        session.console("ar eax=0x1234")
        assert "0x00001234" in session.console("ar eax")["output"], "taken before aei, no ESIL-not-initialized"
        state = session.emulation_start(0)
        session.emulation_run("step")
        state = session.emulation_state()
        assert _word(next(r["value"] for r in state["registers"] if r["name"] == "eax")) == 0x1234
        assert "emulation" in session._restore["tainted"]

        # what a start undoes, so that a pre-start command of that kind spoils nothing: arming and the PC (`aepc 3;
        # aei` and `aepc 3; aeim` both read PC 0), the stack pointer (aeim puts it in its stack), the ESIL maps
        # (the start closes them) -- and what it does not: a register and what a step left
        def held(session, name):  # the console answers in colour
            return int(re.search(r"0x[0-9a-f]+", session.console(f"ar {name}")["output"]).group(), 16)

        session = opened("mov32.bin")
        session.console("aepc 0x3")
        assert held(session, "PC") == 3, "taken before aei"
        session.console("aei")
        assert held(session, "PC") == 0, "aei put the PC at the seek"
        session.console("aepc 0x3")
        session.text("ar esp=0x1234")  # through a view: the console would taint, for the PC/SP/BP too (not told apart)
        session.console("aeim 0x300000 0x100 mine")
        before = [m["name"] for m in session.json("omlj")]
        assert "mem.mine" in before, before
        state = session.emulation_start(0)
        names = [m["name"] for m in session.json("omlj")]
        assert "mem.mine" not in names and any(n.startswith("mem.0x100000") for n in names), names
        assert state["pc"] == "0x0" and held(session, "esp") == 0x178000, "the start set both again"
        assert session._restore["tainted"] is None and session._restore_pending is None

        session = opened("mov32b.bin")
        session.console("e io.cache=true")
        session.console("aes")  # mov ecx, 5
        assert held(session, "ecx") == 5
        session.emulation_start(0)
        assert held(session, "ecx") == 5, "a step's register is still there after a start"
        assert "emulation" in session._restore["tainted"]
    finally:
        mgr.shutdown()


# --- The timeline in the project: the restore= line (webui/rizin_sessions.py) ----------------------

def _project_text(project):
    return project.read_text(encoding="utf-8", errors="surrogateescape")


def _restore_value(project):
    """The project's ``restore=`` line, or None where it has none."""
    return _project_namespace(_project_text(project), "/tdc").get("restore")


def _decrypted_and_patched(rz, name="pipesim.exe"):
    """A file opened, the emulation started, four bytes a run left (written on the pipe, as a run does: a
    console ``wx`` would spoil the timeline) and a patch of the session's own over the second of them -- the
    anti-VM check inside freshly decrypted code. Returns the path and the session ID."""
    path = rz.write(name)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140001440", "41424344")
    _patch(rz, sid, addr="0x140001441", bytes="90")
    return path, sid


def _the_timeline():
    """What _decrypted_and_patched leaves as the project's record."""
    import hashlib
    import rizin_emulation

    return {"counters": {"tick": rizin_emulation.TICK_START, "handle": 0, "pseudo": 0}, "breakpoints": [],
            "actions": [{"kind": "start", "addr": 0x140001440}, {"kind": "patch", "addr": 0x140001441, "data": "90"}],
            "digests": [{"start": 0x140001440, "end": 0x140001443,
                         "sha256": hashlib.sha256(bytes.fromhex("41424344")).hexdigest()}]}


def _saved_with_a_record(rz, name="pipesim.exe"):
    """_decrypted_and_patched and saved: the path, the session ID and the line the project holds."""
    path, sid = _decrypted_and_patched(rz, name)
    rz.mgr.get(sid).flush()
    line = _restore_value(rz.project())
    assert line, "the save wrote no record"
    return path, sid, line


def _mark_dirty(rz, sid):
    """A change the timeline knows nothing of, so that a save is asked for."""
    rz.send(f"/api/rizin/{sid}/comment", {"addr": "0x1400014b7", "text": "a save, please"})


def test_the_timeline_survives_a_save_and_comes_back_on_open(rz):
    import rizin_emulation
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    expected = _the_timeline()
    assert rizin_emulation.read_restore(line) == expected
    text = _project_text(rz.project())
    assert text.index("\npatches=140001441:90:r\n") < text.index("\nrestore=" + line), "after the patches"
    assert text.endswith("\nrestore=" + line + "\n")
    meta = rizin_sessions._read_project_meta(str(rz.project()))
    assert meta["restore"] == expected and meta["restore_refused"] is False
    assert (meta["level"], meta["mode"]) == ("aaa", "one") and meta["patches"] == [(0x140001441, "90", True)]
    rz.close(sid)

    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    session = rz.mgr.get(sid)
    assert session._restore_saved == expected, "it came back"
    assert "timeline" not in (rz.status(sid)["analysis"]["note"] or ""), "and says nothing: it is in order"
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    # a save of this session, which has done nothing to the emulation, carries it on as it was
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line


def test_a_project_from_before_the_record_reads_as_having_none(tmp_path):
    import rizin_sessions

    project = tmp_path / "old.rzdb"
    project.write_text("/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches=140001440:90\n")
    meta = rizin_sessions._read_project_meta(str(project))
    assert meta["restore"] is None and meta["restore_refused"] is False and meta["restore_dropped"] is False
    assert rizin_sessions._read_project_meta(str(tmp_path / "gone.rzdb"))["restore"] is None
    project.write_text("/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches=\nrestore=\n")
    meta = rizin_sessions._read_project_meta(str(project))
    assert meta["restore"] is None and meta["restore_refused"] is False, "an empty line is no line"
    assert meta["restore_dropped"] is False


def test_the_timeline_is_hashed_over_the_rows_in_the_order_they_were_written_when_it_is_saved(rz):
    # spec 5, at the file: by address the two rows swap places and the digest is of `aaeeccdd`, a plausible SHA-256
    # nobody's bytes are. run_digests cannot tell the two orders apart, so what the save feeds it is pinned here
    import hashlib

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    _wrote(rz, sid, "0x140002201", "ee")
    _wrote(rz, sid, "0x140002200", "aabbccdd")
    _mark_dirty(rz, sid)
    rz.mgr.get(sid).flush()
    import rizin_emulation

    record = rizin_emulation.read_restore(_restore_value(rz.project()))
    assert record["digests"] == [{"start": 0x140002200, "end": 0x140002203,
                                  "sha256": hashlib.sha256(bytes.fromhex("aabbccdd")).hexdigest()}]
    assert record["digests"][0]["sha256"] != hashlib.sha256(bytes.fromhex("aaeeccdd")).hexdigest()


def test_the_patches_win_the_budget_and_the_record_falls_away_whole(rz, monkeypatch):
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    session = rz.mgr.get(sid)
    patches = "140001441:90:r"
    chars = rizin_sessions.PROJECT_PATCH_CHARS
    # exactly the budget the two share: it fits ...
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len(patches) + len(line))
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line and "\npatches=" + patches + "\n" in _project_text(rz.project())
    assert "did not fit" not in (rz.status(sid)["analysis"]["note"] or "")
    # ... and one character less does not: the patches are whole, the record is not there at all, and the
    # session says so -- not a half of it that would replay to somewhere nobody named
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len(patches) + len(line) - 1)
    _mark_dirty(rz, sid)
    session.flush()
    text = _project_text(rz.project())
    assert "\npatches=" + patches + "\n" in text
    assert _restore_value(rz.project()) == rizin_sessions._RESTORE_DROPPED_MARK, "no half of it: only the marker"
    assert "start:" not in text
    note = rz.status(sid)["analysis"]["note"]
    assert "timeline" in note and "did not fit" in note and str(len(patches) + len(line) - 1) in note, note
    assert "with the patches" in note and "on its own" not in note, "it was the patches that took the room: " + note
    # the record would have fitted alone: the line is far under the whole budget the patches share it with
    assert len(line) <= chars
    # said once, however many saves follow
    _mark_dirty(rz, sid)
    session.flush()
    assert rz.status(sid)["analysis"]["note"].count("did not fit") == 1
    # and a save with room again puts it back, and the note that said it was gone goes
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", chars)
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line
    assert "did not fit" not in (rz.status(sid)["analysis"]["note"] or "")


def test_the_patches_alone_filling_the_budget_leave_the_record_only_its_marker(rz, monkeypatch):
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len("140001441:90:r"))
    _mark_dirty(rz, sid)
    rz.mgr.get(sid).flush()
    text = _project_text(rz.project())
    assert "\npatches=140001441:90:r\n" in text and _restore_value(rz.project()) == _marker(), \
        "the patches are whole, and the record that did not fit says so in the one thing that costs no room worth the name"


def test_a_waiting_patch_that_the_budget_cuts_is_still_listed_and_the_note_counts_it(rz, monkeypatch):
    # Task 1's residue, now that the record shares the budget: a waiting patch is the last the patches line
    # takes, so it is the first the budget cuts. It stays in the session's list (this session still holds it),
    # the note states the number and says it will not be there at the next open -- true, and said
    import rizin_sessions

    path, sid = _reopened_with_a_waiting_patch(rz)
    session = rz.mgr.get(sid)
    _patch(rz, sid, addr="0x140001460", bytes="41")
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len("140001460:41"))
    session.flush()
    assert _project_patches(rz) == "140001460:41"
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")]
    assert "1 patch did not fit into the project" in rz.status(sid)["analysis"]["note"]


@pytest.mark.parametrize("hostile", [
    "nonsense",
    "1;100000,0,0;;start:140001440;;",                     # a line cut where its terminator should be
    "1;100000,0,0;;start:140001440;;end;and then more",     # one that goes on past it
    "1;100000,0,0;;poke:140001440;;end",                    # a kind nobody knows
    "1;100000,0,0;;run:step;;end",                          # a timeline that does not begin with a start
    "1;100000,0,0;;start:zz;;end",                          # an address that is no number
    "1;100000,0,0;;start:140001440,patch:1:9;;end",         # bytes that are no bytes
    "1;100000,0,0;;start:140001440;1-2-ab;end",             # a hash that is no SHA-256
    "2;100000,0,0;;start:140001440;;end",                   # another version
    "1;100000,0,0;;" + ",".join(["start:1"] + ["run:step"] * 600) + ";;end",   # more than a record may hold
    "dropped;end", "Dropped", "dropped ", "dropped,dropped",
    "a" * (40 * 1024),                                      # more than the budget a save could have spent, and still in the tail
])
def test_a_hand_edited_record_is_refused_and_the_session_still_starts(rz, hostile):
    path, sid, line = _saved_with_a_record(rz)
    rz.close(sid)
    text = _project_text(rz.project())
    planted = text.replace("\nrestore=" + line + "\n", "\nrestore=" + hostile + "\n")
    assert planted != text
    rz.project().write_text(planted, encoding="utf-8", errors="surrogateescape")

    sid = rz.open(path)["session"]
    rz.wait_done(sid)  # the session starts, and finishes its analysis
    session = rz.mgr.get(sid)
    assert session._restore_saved is None, "None means no record"
    note = rz.status(sid)["analysis"]["note"]
    assert "timeline" in note and "not used" in note, note
    assert note.index("Held back") < note.index("timeline"), "the damage first, the convenience after: " + note
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140001441, "90")], "the patches are not touched"
    # nothing of it is carried into the next save: the nonsense is gone, the patches are not
    _mark_dirty(rz, sid)
    session.flush()
    text = _project_text(rz.project())
    assert "restore=" not in text and "\npatches=140001441:90:r\n" in text


def test_a_record_over_the_reading_cap_is_refused_without_being_parsed(rz, monkeypatch):
    # R-T2d: read_restore builds all its actions before the budget could apply, so the cap is in front of it
    import rizin_emulation
    import rizin_sessions

    seen = []
    real = rizin_emulation.read_restore
    monkeypatch.setattr(rizin_emulation, "read_restore", lambda value: seen.append(len(value)) or real(value))
    project = rz.project()
    project.parent.mkdir(parents=True, exist_ok=True)
    over = "1;0,0,0;;" + ",".join(["start:1"] * 4500) + ";;end"
    assert len(over) > rizin_sessions.PROJECT_PATCH_CHARS
    project.write_text(f"/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches=\nrestore={over}\n")
    meta = rizin_sessions._read_project_meta(str(project))
    assert meta["restore"] is None and meta["restore_refused"] is True and seen == []
    # the boundary itself: exactly the cap is read (and refused as what it is, no record), one more is not read
    seen.clear()
    for length, read in ((rizin_sessions.PROJECT_PATCH_CHARS, True), (rizin_sessions.PROJECT_PATCH_CHARS + 1, False)):
        project.write_text(f"/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches=\nrestore={'x' * length}\n")
        meta = rizin_sessions._read_project_meta(str(project))
        assert meta["restore"] is None and meta["restore_refused"] is True
        assert seen == ([length] if read else []), (length, seen)
        seen.clear()
    under = "1;0,0,0;;start:1;;end"
    project.write_text(f"/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches=\nrestore={under}\n")
    assert rizin_sessions._read_project_meta(str(project))["restore"]["actions"] == [{"kind": "start", "addr": 1}]
    assert seen == [len(under)]


def _hand_set_a_register(rz, sid):
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})


def _wrote_by_console(rz, sid):
    _console(rz, sid, "wx 90 @ 0x140002000")


def _moved_a_breakpoint(rz, sid):
    # taints nothing yet (it is a reason until an action follows), and the save asks the reason
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})


_SPOILS = {"register": _hand_set_a_register, "console write": _wrote_by_console,
           "standing breakpoint": _moved_a_breakpoint}


@pytest.mark.parametrize("spoil", sorted(_SPOILS))
def test_a_record_with_a_reason_is_not_written_and_does_not_erase_what_is_stored(rz, spoil):
    # R-T3a and R-T3f together: a timeline that cannot be offered is never written (read_restore has no notion
    # of taint, so it would come back clean), and it does not take the project's own line with it either
    path, sid, line = _saved_with_a_record(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")  # a new timeline's bytes: not the stored ones
    _SPOILS[spoil](rz, sid)
    assert session._restore_reason(), "the timeline cannot be offered"
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line, "the stored line, byte for byte"
    assert "\npatches=140001441:90:r\n" in _project_text(rz.project())


@pytest.mark.parametrize("spoil", sorted(_SPOILS))
def test_a_record_with_a_reason_and_nothing_stored_writes_no_line_at_all(rz, spoil):
    sid = rz.session()
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _SPOILS[spoil](rz, sid)
    assert session._restore_reason()
    _mark_dirty(rz, sid)
    session.flush()
    text = _project_text(rz.project())
    assert "restore=" not in text
    assert "\n/tdc\nlevel=aaa" in text and "\npatches=\n" in text, "a project was written, with no line of it"


def test_no_record_at_save_time_leaves_the_stored_one_alone(rz):
    # a session that never emulated, a timeline an unpatch took out of the cache, and the other way round:
    # none of them says anything about what the project holds, and none of them may erase it
    path, sid, line = _saved_with_a_record(rz)
    rz.close(sid)

    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    session = rz.mgr.get(sid)
    assert session._restore is None
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line, "a session that never emulated"

    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    session.unpatch()
    assert session._restore is None and session._restore_gone
    session.flush()
    assert _restore_value(rz.project()) == line, "after an unpatch"


def test_a_clean_record_replaces_the_stored_one(rz):
    import rizin_emulation

    path, sid, line = _saved_with_a_record(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001450"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _mark_dirty(rz, sid)
    rz.mgr.get(sid).flush()
    now = _restore_value(rz.project())
    assert now != line
    record = rizin_emulation.read_restore(now)
    assert record["actions"] == [{"kind": "start", "addr": 0x140001450}]
    assert [(d["start"], d["end"]) for d in record["digests"]] == [(0x140009000, 0x140009002)]


def test_a_timeline_with_nothing_of_a_run_to_prove_writes_nothing_and_keeps_what_is_stored(rz):
    # started, and the run left nothing in the cache: a record with no digest proves nothing, so it is not
    # the one that replaces a record that does
    path, sid, line = _saved_with_a_record(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _mark_dirty(rz, sid)
    rz.mgr.get(sid).flush()
    assert _restore_value(rz.project()) == line


def test_a_cache_the_digests_cannot_be_made_from_costs_the_record_and_not_the_save(rz, monkeypatch):
    # R-T2c: parse_cache guarantees the types of a row but not that its bytes are as many as its size
    import rizin_emulation

    path, sid, line = _saved_with_a_record(rz)
    rz.close(sid)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    real = rizin_emulation.parse_cache

    def short(text):
        rows = real(text)
        for row in rows:
            if row["addr"] == 0x140009000:
                row["after"] = "ff"  # one byte of the three it says
        return rows

    monkeypatch.setattr(rizin_emulation, "parse_cache", short)
    _mark_dirty(rz, sid)
    rz.mgr.get(sid).flush()
    text = _project_text(rz.project())
    assert "\n/tdc\nlevel=aaa" in text and "\npatches=140001441:90:r\n" in text, "the project was written"
    assert _restore_value(rz.project()) == line, "and what it held stays"


def test_the_record_and_the_waiting_patches_survive_a_rizin_restart(sessions, sample, fake, tmp_path, monkeypatch):
    # _recover gives the session a rizin with an empty cache and drops the live timeline (Task 3): the project's
    # line is not that rizin's to erase. R-T3f at the place a hung step puts it
    import rizin_sessions

    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    opened = mgr.open(sample("restart_record.exe", b"MZ restart record"), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    session.emulation_start(0x140001440)
    session._pipe.cmd("wx 41424344 @ 0x140001440")
    session.patch(0x140001441, "90")
    timers.fire()
    line = _restore_value(project)
    assert line and _project_patches_of(project) == "140001441:90:r"

    session.analyze_full()  # its aar hangs, so rizin is killed and restarted
    _wait_state(session, "stopped")
    assert session._restore is None and session._restore_gone == rizin_sessions._RESTORE_RESTARTED
    assert session._waiting == [(0x140001441, "90", True)]
    session.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert _restore_value(project) == line, "the record the project held is still there"
    assert _project_patches_of(project) == "140001441:90:r", "and so is the patch that waits"


def test_a_tainted_timeline_is_not_written_to_a_session_that_saves_it_first_either(rz):
    # the first save of a tainted timeline: nothing stored, nothing written -- and a later clean one is written
    sid = rz.session()
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _hand_set_a_register(rz, sid)
    _mark_dirty(rz, sid)
    session.flush()
    assert "restore=" not in _project_text(rz.project())
    session.unpatch()  # taken out: the timeline goes, and a new one can begin
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _mark_dirty(rz, sid)
    session.flush()
    assert "restore=" in _project_text(rz.project())


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not RZ_ASM, reason="rz-asm not installed")
def test_real_rizin_the_project_round_trips_the_record(tmp_path):
    """``Ps``, a reopen and ``Poo``: the record comes back unchanged and rizin still loads the project.

    Only the binary can show it: the line goes into a /tdc namespace that rizin's own ``Ps`` and ``Poo`` read
    around, and what rizin does with a ``;``, a ``:`` and a ``-`` in a value, and with a namespace it does not
    know, is its own. The record is made of a real decryption (the digest is the SHA-256 of what rizin's ESIL
    left), saved over a patch of the decrypted code, and read back by a session that has not run anything."""
    import hashlib
    import rizin_emulation
    import rizin_sessions

    blob = tmp_path / "decryptor.bin"
    stop = _decryptor_blob(blob)
    sha = hashlib.sha256(blob.read_bytes()).hexdigest()
    project = tmp_path / "projects" / (sha + ".rzdb")
    plain = bytes(b ^ 0xFF for b in blob.read_bytes()[0x1000:0x1040])
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        session.console("e asm.arch=x86")  # a raw blob is read for the host's arch (avr here)
        session.console("e asm.bits=64")
        session.emulation_start(0)
        assert session.emulation_run("until", stop)["pc"] == hex(stop)
        session.patch(0x1002, "9090")  # the check inside what was decrypted
        assert session.flush() is True
        saved = _project_text(project)
        line = _restore_value(project)
        expected = {"counters": {"tick": rizin_emulation.TICK_START, "handle": 0, "pseudo": 0}, "breakpoints": [],
                    "actions": [{"kind": "start", "addr": 0}, {"kind": "run", "run": "until", "addr": stop},
                                {"kind": "patch", "addr": 0x1002, "data": "9090"}],
                    "digests": [{"start": 0x1000, "end": 0x103F, "sha256": hashlib.sha256(plain).hexdigest()}]}
        assert rizin_emulation.read_restore(line) == expected
        assert "\npatches=1002:9090:r\n" in saved and saved.endswith("\nrestore=" + line + "\n")
        assert "\n/tdc\n" in saved and saved.count("\nrestore=") == 1
    finally:
        mgr.shutdown()

    # the real Poo: a new session loads the project (e prj.file says so), the record is the one that was saved,
    # and a save that does nothing to the emulation writes the same line again
    mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
    try:
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        assert session.text("e prj.file").strip() == str(project), "rizin loaded the project"
        assert not project.with_suffix(".rzdb.broken").exists()
        assert session._restore_saved == expected
        assert "timeline" not in (session.analysis["note"] or "")
        session.breakpoint_set(0x8000)
        assert session.flush() is True
        assert _restore_value(project) == line
        assert _project_text(project).count("\n/tdc\n") == 1
        # and once more over the file the second save wrote
        session.breakpoint_set(0x8001)
        assert session.flush() is True
        assert _restore_value(project) == line
    finally:
        mgr.shutdown()


def test_a_timeline_that_grows_and_is_then_spoiled_leaves_the_line_as_the_last_clean_save_made_it(rz):
    # what was saved is a copy: the actions the live timeline gains afterwards are not in it, and a spoiled
    # timeline does not rewrite it with half a growth and the digests of before
    path, sid, line = _saved_with_a_record(rz)
    session = rz.mgr.get(sid)
    _run(rz, sid, "step")
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _hand_set_a_register(rz, sid)
    assert len(session._restore["actions"]) == 3 and session._restore_reason()
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line
    assert len(session._restore_saved["actions"]) == 2


# --- Fix round 1: the marker, the save an emulation action asks for, one read of the cache --------------------

def _marker():
    import rizin_sessions

    return rizin_sessions._RESTORE_DROPPED_MARK


def test_a_record_that_had_to_be_dropped_leaves_a_marker_and_the_open_says_so(rz, monkeypatch):
    # spec 4 and 1: "beim Oeffnen, nicht erst, wenn es wehtut". A dropped timeline is invisible at the next open (the
    # user did not put it there and cannot see it gone), so the project says it
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    session = rz.mgr.get(sid)
    patches = "140001441:90:r"
    chars = rizin_sessions.PROJECT_PATCH_CHARS
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len(patches) + len(line) - 1)
    _mark_dirty(rz, sid)
    session.flush()
    text = _project_text(rz.project())
    assert text.endswith("\npatches=" + patches + "\nrestore=" + _marker() + "\n"), text[-120:]
    meta = rizin_sessions._read_project_meta(str(rz.project()))
    assert (meta["restore"], meta["restore_refused"], meta["restore_dropped"]) == (None, False, True)
    rz.close(sid)

    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", chars)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    session = rz.mgr.get(sid)
    note = rz.status(sid)["analysis"]["note"]
    assert "could not be kept" in note and "timeline" in note and "not used" not in note, note
    assert note.index("Held back") < note.index("timeline"), "after the damage, as the refusal is"
    assert session._restore_saved is None
    # a save that does nothing to the emulation says it again: the project must not forget it
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == _marker()
    # and a record that does fit takes the marker's place
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()).startswith("1;") and _marker() not in _project_text(rz.project())
    # the note said "the way is gone" about the project as it was: it is not true of the project that holds the record
    # again, and a user told to decrypt again would redo what the pane is about to offer
    assert "could not be kept" not in (rz.status(sid)["analysis"]["note"] or ""), rz.status(sid)["analysis"]["note"]
    assert session._restore_dropped_note is None
    # and a re-plan (Full analysis) does not bring it back out of the notes that outlive one
    session.analyze_full()
    _wait_state(session, "done", "stopped")
    assert "could not be kept" not in (rz.status(sid)["analysis"]["note"] or "")


def test_the_marker_is_written_whatever_the_patches_leave(rz, monkeypatch):
    # the patches have the budget first and are never cut for the record; the marker is a few characters over it at most. Where
    # the patches leave less than its own length it was suppressed with left_out 0, and the next open said nothing at all
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    session = rz.mgr.get(sid)
    patches = "140001441:90:r"
    for room in (len(_marker()), len(_marker()) - 1, 1, 0):
        monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len(patches) + room)
        _mark_dirty(rz, sid)
        session.flush()
        text = _project_text(rz.project())
        assert "\npatches=" + patches + "\n" in text, room
        assert _restore_value(rz.project()) == _marker(), room


def test_a_project_with_no_record_and_one_that_lost_it_are_told_apart(rz, tmp_path):
    import rizin_sessions

    project = tmp_path / "x.rzdb"
    for tail, expected in (("", (None, False, False)), ("restore=\n", (None, False, False)),
                           (f"restore={_marker()}\n", (None, False, True)),
                           ("restore=" + _marker() + "x\n", (None, True, False))):
        project.write_text("/\nversion=25\n\n/tdc\nlevel=aa\nmode=one\ndone=aa\npatches=\n" + tail)
        meta = rizin_sessions._read_project_meta(str(project))
        assert (meta["restore"], meta["restore_refused"], meta["restore_dropped"]) == expected, tail


def test_a_timeline_that_alone_is_over_the_budget_says_so_and_does_not_blame_the_patches(rz, monkeypatch):
    import rizin_sessions

    sid = rz.session()
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", 100)
    _mark_dirty(rz, sid)
    session.flush()
    note = rz.status(sid)["analysis"]["note"]
    assert "did not fit" in note and "on its own" in note and "with the patches" not in note, note
    assert _restore_value(rz.project()) == _marker()


def test_a_running_emulation_asks_for_a_save_like_every_other_change(sessions, sample, fake, tmp_path):
    # R-T4a: _dirty used to be false after a start and a run, so a session that only emulated and closed saved no record
    timers = Timers()
    mgr = sessions(timer=timers, big_file=1)
    opened = mgr.open(sample("emulates.exe", b"MZ emulates"), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    timers.fire()
    session.emulation_start(0x140001440)
    assert session._dirty and timers.pending, "a start asks for a save"
    timers.fire()
    session._pipe.cmd("wx 41424344 @ 0x140002200")  # what the run left
    session.emulation_run("step")
    assert session._dirty and timers.pending, "so does a run"
    timers.fire()
    assert _restore_value(project), "and the save wrote the record"
    # a timeline that cannot be offered has nothing new for a save to say: it does not ask for one
    session.emulation_register("rax", 5)
    timers.fire()
    made = len(timers.made)
    session.emulation_run("step")
    assert len(timers.made) == made and not session._dirty


def test_a_session_that_only_ran_the_emulation_and_closed_wrote_its_record(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140009000", "ffeedd")
    _run(rz, sid, "step")
    rz.close(sid)
    assert _restore_value(rz.project()).startswith("1;")


def test_a_save_reads_the_write_cache_once(rz):
    sid = rz.session()
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid, "0x140002201", "ee")
    _wrote(rz, sid, "0x140002200", "aabbccdd")
    _patch(rz, sid, addr="0x140002201", bytes="90")
    _mark_dirty(rz, sid)
    mark = len(rz.commands())
    assert session.flush() is True
    assert [c for c in rz.commands()[mark:] if c == "wcj"] == ["wcj"], rz.commands()[mark:]
    import hashlib
    import rizin_emulation

    record = rizin_emulation.read_restore(_restore_value(rz.project()))
    assert record["digests"][0]["sha256"] == hashlib.sha256(bytes.fromhex("aabbccdd")).hexdigest(), "still in write order"


def test_a_restart_keeps_the_record_the_session_holds_over_an_older_line_of_the_project(
        sessions, sample, fake, tmp_path, monkeypatch):
    # _recover boots rizin from the project, whose line can be older than what this session has saved since (or
    # planted): the session's own record is the newer one
    import rizin_emulation

    timers = Timers()
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    opened = mgr.open(sample("restart_newer.exe", b"MZ restart newer"), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    project = tmp_path / "projects" / (opened["file"]["sha256"] + ".rzdb")
    session.emulation_start(0x140001440)
    session._pipe.cmd("wx 41424344 @ 0x140001440")
    session.patch(0x140001441, "90")
    timers.fire()
    mine = session._restore_saved
    assert mine and _restore_value(project)
    older = rizin_emulation.restore_line(dict(mine, actions=[{"kind": "start", "addr": 0x1}]), 4096)[0]
    project.write_text(re.sub(r"(?m)^restore=.*$", "restore=" + older, _project_text(project)), encoding="utf-8")
    assert _restore_value(project) == older

    session.analyze_full()  # its aar hangs, so rizin is killed and restarted
    _wait_state(session, "stopped")
    assert session._restore_saved == mine, "not the project's older one"
    session.comment(0x1400014B7, "after the restart")
    timers.fire()
    assert rizin_emulation.read_restore(_restore_value(project)) == mine


def test_a_run_that_ended_at_the_time_limit_does_not_ask_for_a_save(sessions, sample, fake, tmp_path, monkeypatch):
    # tainted by this very action (not before it, as a hand-set register is): a save would write nothing new and cost a
    # Ps and a read of the cache, in the one case where rizin was blocked for the whole time limit already
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    timers = Timers()
    mgr = sessions(timer=timers, big_file=1)
    session = mgr.get(mgr.open(sample("runaway.exe", b"MZ runaway"), "tab")["session"])
    _wait_state(session, "done")
    session.emulation_start(0x140001440)
    timers.fire()
    assert not session._dirty and session._restore["tainted"] is None
    made = len(timers.made)
    assert session.emulation_run("cont")["stopped"] == "timeout"
    assert session._restore["tainted"] and "time limit" in session._restore["tainted"]
    assert len(session._restore["actions"]) == 2, "the run is on the timeline all the same"
    assert not session._dirty and len(timers.made) == made, "and asked for no save"


def test_the_blame_for_a_dropped_timeline_follows_the_cause_within_one_session(rz, monkeypatch):
    # first the patches took the room, then the timeline is over the budget on its own: the note says the second, and
    # says it once
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    session = rz.mgr.get(sid)
    patches = "140001441:90:r"
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len(patches) + len(line) - 1)
    _mark_dirty(rz, sid)
    session.flush()
    note = rz.status(sid)["analysis"]["note"]
    assert "with the patches" in note and "on its own" not in note, note
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len(line) - 1)
    _mark_dirty(rz, sid)
    session.flush()
    note = rz.status(sid)["analysis"]["note"]
    assert "on its own" in note and "with the patches" not in note, note
    assert note.count("did not fit") == 1


# --- Replaying the timeline (webui/rizin_sessions.py's restore_run, patch_waiting and drop_waiting) ---------------

ORDER_AT, ORDER_END, ORDER_TARGET = 0x140002A00, 0x140002A0E, 0x140002100  # fake_rizin.py: two stores that overlap
UNCOVERED = 0x140001500  # in .text, and no run writes there


def _decrypted_and_saved(rz, name="pipesim.exe", before=(), over=((0x140002003, "90"),), stub=(DECRYPT_AT, DECRYPT_END),
                         rows=None):
    """The work the replay exists for: a file opened, the patches in ``before`` made (no run has written under
    them yet, so they are applied at the open and are no action), the emulation started at the decryption stub and
    run to its end -- eight bytes of 0x41 at 0x140002000 -- and the patches in ``over`` made over what it left, the
    way an analyst puts a NOP over the anti-VM check inside decrypted code. Saved and closed. Returns the path and
    the project's record. ``rows``, a list, is given the cache as it stood, in the order the writes were made in."""
    path = rz.write(name)
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    for addr, data in before:
        _patch(rz, sid, addr=f"{addr:#x}", bytes=data)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{stub[0]:#x}"})
    _run(rz, sid, "until", addr=f"{stub[1]:#x}")
    for addr, data in over:
        _patch(rz, sid, addr=f"{addr:#x}", bytes=data)
    assert rz.mgr.get(sid).flush() is True
    line = _restore_value(rz.project())
    assert line, "the save wrote no record"
    if rows is not None:
        rows.extend(rz.mgr.get(sid).patches_made())
    rz.close(sid)
    return path, line


def _reopened(rz, path):
    """The file opened again: the session ID and the session. Nothing has run in it."""
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    return sid, rz.mgr.get(sid)


def _restore(rz, sid):
    return rz.post(f"/api/rizin/{sid}/restore", {})


def _the_saved_record(rz):
    import rizin_emulation

    return rizin_emulation.read_restore(_restore_value(rz.project()))


def _the_bytes(session, addr=0x140002000, size=8):
    return session.json(f"pxj {size} @ {addr:#x}")


def _the_replay(rz, mark):
    """The commands of a replay that change something, in the order they went to rizin."""
    return [c for c in rz.commands()[mark:] if c.split(" ")[0] in ("wc-*", "ara0", "aei", "aeim", "aepc", "aesu",
                                                                  "aec", "aes", "wx", "o-", "e")
            and not c.startswith("e ")]


def test_restoring_replays_the_timeline_and_applies_the_waiting_patches(rz, monkeypatch):
    # The whole use of the feature: the open held the patch back (it is over a run's bytes), one press runs the
    # decryption again, the patch is made at its place in it, and a patch the timeline does not make but a run's
    # bytes cover is written after it. What stays waiting is what no run covers.
    import rizin_emulation

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140002003, "90")]
    assert _patches(rz, sid) == [] and _the_bytes(session) == [0] * 8, "nothing is decrypted, nothing is patched"
    session._waiting += [(0x140002005, "cc", True), (UNCOVERED, "90", True)]
    assert _offer(rz, sid) == {"actions": 3, "reason": None, "digests": 1}, "a record in the project is offered"
    saved, spied = session._restore_saved, []
    session._schedule_save = lambda: spied.append(1)
    session._assist_tick = 0x500000  # where the counters stand now is not where the timeline began
    _console(rz, sid, "ar rax=0x5")  # a register somebody set by hand: the replay begins from rizin's own state
    assert session._restore_pending

    mark = len(rz.commands())
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True and answer["reason"] is None, answer
    assert _register(rz, sid, "rax") == 0 and session._restore_pending is None, "what was set by hand is wiped, and said no more"
    assert answer["applied"] == [0x140002005] and answer["state"]["running"] is True
    assert answer["state"]["pc"] == hex(DECRYPT_END)
    assert _the_replay(rz, mark) == ["wc-*", "ara0", "aei", "aeim", f"aepc {DECRYPT_AT:#x}", f"aesu {DECRYPT_END:#x}",
                                     "wx 90 @ 0x140002003", "wx cc @ 0x140002005"], \
        "wc-* first, then the timeline in the order it was made in -- the patch inside it, not after it -- then what waited"
    assert _the_bytes(session) == [0x41, 0x41, 0x41, 0x90, 0x41, 0xCC, 0x41, 0x41], "decrypted, and the checks are patched"
    rows = answer["patches"]["patches"]
    assert [(r["addr"], r["mine"], r["over_run"]) for r in rows if r["mine"]] == [(0x140002003, True, True),
                                                                                  (0x140002005, True, True)]
    assert sum(not r["mine"] for r in rows) == 8, "the run's own writes, once"
    assert [(w["addr"], w["after"]) for w in answer["patches"]["waiting"]] == [(UNCOVERED, "90")]
    assert rz.read(f"/api/rizin/{sid}/patches") == answer["patches"], "what the route answers is what GET says"
    assert session._assist_tick == rizin_emulation.TICK_START, "the counters began where the timeline did"

    # the replay is nobody's action: it recorded nothing of its own and left the project's record as it was. The
    # replayed timeline is the session's from here on -- a copy, with the one patch written after the proof as an action,
    # which asks for a save as a patch of the user's does (once; the replay's own actions asked for none)
    assert session._replaying is False and session._restore_saved is saved
    assert saved["actions"] == _the_saved_record(rz)["actions"] and len(saved["actions"]) == 3, "the project's record is not grown"
    assert session._restore == {"counters": saved["counters"], "breakpoints": [], "tainted": None,
                                "actions": saved["actions"] + [{"kind": "patch", "addr": 0x140002005, "data": "cc"}]}
    assert session._restore["actions"] is not saved["actions"] and spied == [1]
    del session._schedule_save  # the real scheduling again, and a save that is asked for
    _mark_dirty(rz, sid)
    assert session.flush() is True
    record = _the_saved_record(rz)
    assert record["actions"][:3] == saved["actions"] and record["actions"][3]["data"] == "cc", "the longer recipe is saved"
    assert record["digests"] == saved["digests"], "of the same bytes"


def test_restoring_refuses_when_the_cache_is_not_the_one_from_opening(rz):
    # Spec 6: the replay begins with wc-*, so it may run only where that takes nothing away that is not its own
    # to take: the cache holds the patches the open applied and nothing else, and no emulation runs. A refusal
    # touches nothing.
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(UNCOVERED, "9090")]

    def refused(*words):
        mark = len(rz.commands())
        response = _restore(rz, sid)
        assert response.status_code == 400, response.get_json()
        reason = response.get_json()["refused"]
        assert all(word in reason for word in words), reason
        assert _the_replay(rz, mark) == [], "a refusal sends nothing that changes anything"
        return reason

    # an emulation that runs
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    refused("emulation is running")
    assert session._restore is not None and len(session._restore["actions"]) == 1, "and its timeline is still there"
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    # a patch made since the open, which the replay would take away
    _patch(rz, sid, addr="0x140001600", bytes="90")
    refused("write cache holds more or other")
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140001600"})
    # a write of the console, which the replay would take away too
    session._pipe.cmd("wx aa @ 0x140002010")
    refused("write cache holds more or other")
    session._pipe.cmd("wc- 0x140002010 0x140002011")
    # one of the open's own patches taken back: the cache is not the open's either, and a replay would put it back
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": f"{UNCOVERED:#x}"})
    refused("write cache holds more or other")
    _patch(rz, sid, addr=f"{UNCOVERED:#x}", bytes="9090")
    answer = rz.ok(_restore(rz, sid))  # the cache is the open's again: it goes through
    assert answer["restored"] is True


def test_restoring_refuses_without_a_timeline_and_says_why(rz):
    sid = rz.session()
    response = _restore(rz, sid)
    assert response.status_code == 400 and "no timeline" in response.get_json()["refused"]
    assert _offer(rz, sid) == {"actions": 0, "reason": None, "digests": 0}


def test_restoring_refuses_when_the_breakpoints_are_not_the_ones_the_timeline_ran_under(rz):
    # P2: a run stops at a breakpoint. rizin keeps them in its own project, but nothing makes them the same at the
    # replay: the reason is said up front, because the SHA-256 would only say "other bytes" for what is "your
    # breakpoints are different"
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001490"})
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    _patch(rz, sid, addr="0x140002003", bytes="90")
    assert rz.mgr.get(sid).flush() is True
    assert _the_saved_record(rz)["breakpoints"] == [0x140001490]
    rz.close(sid)

    sid, session = _reopened(rz, path)
    session._pipe.cmd("db-*")  # the fake does not bring the project's breakpoints back: another set
    offer = rz.mgr.get(sid)._restore_offer()
    assert offer["actions"] == 3 and offer["reason"] is None, "the record is clean: it is the button that is refused"
    assert "breakpoints" in offer["refused"] and "0x140001490" in offer["refused"], offer
    mark = len(rz.commands())
    response = _restore(rz, sid)
    assert response.status_code == 400 and "0x140001490" in response.get_json()["refused"]
    assert "none now" in response.get_json()["refused"]
    assert _the_replay(rz, mark) == []
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001490"})
    assert _refused(rz, sid) is None
    assert rz.ok(_restore(rz, sid))["restored"] is True
    # the replayed timeline ran under that set, and says so: the same set again is no change, another one is
    assert session._restore["breakpoints"] == [0x140001490]
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x140001490"})
    _run(rz, sid, "step")
    assert session._restore["tainted"] is None and session._restore_reason() is None
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    _run(rz, sid, "step")
    assert "breakpoint" in session._restore["tainted"]


def _the_state_of_the_open(rz, sid, session, patches, tick=None):
    """What a replay that did not hold has to leave (Review Focus 4): the cache holds the patches of the open and
    nothing else, no emulation is mapped or running, the counters stand where they stood, and what waited waits."""
    import rizin_emulation

    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid)] == [(a, d, True) for a, d in patches]
    assert session._emulation is None and rz.post(f"/api/rizin/{sid}/emulation/run", {"kind": "step"}).status_code == 400
    assert not [m for m in session.json("omlj") if m["name"].startswith("mem.")], "the emulation's memory is given back"
    assert session._assist_tick == (rizin_emulation.TICK_START if tick is None else tick)
    assert session._replaying is False
    assert session._restore is None and session._restore_saved is not None, "the record is still the project's"


def test_a_replay_that_produces_other_bytes_applies_nothing_and_says_so(rz, monkeypatch):
    # Review Focus 4: without it the SHA-256 is decoration. The replay runs, its bytes are not the saved ones (the
    # run XORs with another key), and what is left is the state of the open -- the patch of the open still there, the
    # patches that waited still waiting, nothing of the run in the cache -- and the answer says what happened.
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    monkeypatch.setenv("FAKE_RIZIN_XOR_KEY", "0x42")
    sid, session = _reopened(rz, path)
    session._waiting.append((0x140002005, "cc", True))  # one the timeline does not make, which a run covers
    session._assist_tick = 0x500000
    saved = session._restore_saved
    mark = len(rz.commands())

    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and answer["state"] is None and answer["applied"] == []
    assert "other bytes" in answer["reason"] and "1 of 1 saved ranges" in answer["reason"], answer["reason"]
    assert "nothing was applied" in answer["reason"] and "stopped: step" in answer["reason"]
    _the_state_of_the_open(rz, sid, session, [(UNCOVERED, "9090")], tick=0x500000)
    assert [(w["addr"], w["after"]) for w in answer["patches"]["waiting"]] == [(0x140002003, "90"), (0x140002005, "cc")]
    assert answer["patches"] == rz.read(f"/api/rizin/{sid}/patches")
    assert not any(c.startswith("wx cc ") for c in rz.commands()[mark:]), "the waiting patch is written after the proof"
    assert session._restore_saved is saved and _the_bytes(session) == [0] * 8
    # and the cache is exactly what the open made it: the replay's own commands, then the undo's
    assert _the_replay(rz, mark)[-3:] == ["wc-*", "ara0", f"wx 9090 @ {UNCOVERED:#x}"]


def test_a_replay_that_fails_midway_keeps_the_patches_waiting(rz, monkeypatch):
    # a run that ends at esil.timeout is not repeatable, and a replay that waited it out again would be the minutes
    # the cap on the actions is there to prevent: it stops at that action and says which, the cache is the open's
    # again, and the patch that waited waits
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    sid, session = _reopened(rz, path)
    mark = len(rz.commands())
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False
    assert "action 2 of 3 (run until 0x140002838)" in answer["reason"] and "time limit" in answer["reason"], answer["reason"]
    assert "nothing was applied" in answer["reason"]
    _the_state_of_the_open(rz, sid, session, [(UNCOVERED, "9090")])
    assert [(w["addr"], w["after"]) for w in answer["patches"]["waiting"]] == [(0x140002003, "90")]
    assert not any(c.startswith("wx 90 @ 0x140002003") for c in rz.commands()[mark:]), "it never got as far as the patch"


def test_a_replay_whose_action_is_refused_says_what_the_run_said(rz):
    # an action the code refuses (here a skip where the PC stands on no call) is a failure too, with the refusal's
    # own words and the number of the action; the project's text is a number in it, never a word
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    record = session._restore_saved
    session._restore_saved = dict(record, actions=[record["actions"][0],
                                                   {"kind": "skip", "addr": 0x140001440, "value": 1, "fix": 0}])
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False
    assert "action 2 of 2 (skip the call at 0x140001440)" in answer["reason"], answer
    assert "the emulation's PC is at 0x140002800, not at 0x140001440" in answer["reason"], answer
    assert session._emulation is None and _patches(rz, sid) == []


def test_a_replay_that_cannot_go_on_for_another_reason_says_so_and_undoes_itself(rz, monkeypatch):
    # rizin answers something unexpected after the run: the same, one sentence, and the open's state
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    monkeypatch.setattr(session, "_restore_digests", lambda pipe, rows=None: (_ for _ in ()).throw(ValueError("boom")))
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and "could not go on (boom)" in answer["reason"], answer
    _the_state_of_the_open(rz, sid, session, [(UNCOVERED, "9090")])


def test_a_replay_that_cannot_put_the_open_back_names_the_patch_and_keeps_it(rz, monkeypatch):
    # the undo is all-or-named: a patch of the open that rizin does not take now is not silently gone, it is kept in
    # the project (the way a restart's lost patches are) and the reason names it
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    monkeypatch.setenv("FAKE_RIZIN_XOR_KEY", "0x42")
    sid, session = _reopened(rz, path)
    real = session._patch_write
    undoing = []

    def refuses_the_one_of_the_open(pipe, addr, data):
        if addr == UNCOVERED and undoing:
            raise rizin_sessions.RizinRefused(f"rizin wrote nothing at {addr:#x}")
        return real(pipe, addr, data)

    import rizin_sessions

    real_undo = session._restore_undo
    monkeypatch.setattr(session, "_restore_undo", lambda pipe, counters: (undoing.append(1), real_undo(pipe, counters))[1])
    monkeypatch.setattr(session, "_patch_write", refuses_the_one_of_the_open)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and "0x140001500 could not be written into the cache again" in answer["reason"]
    assert session._lost == [(UNCOVERED, "9090", False)] and session._replaying is False
    assert session._emulation is None and _patches(rz, sid) == []
    monkeypatch.setattr(session, "_patch_write", real)
    session._schedule_save()
    assert session.flush() is True
    assert "140001500:9090" in _project_text(rz.project()), "the project still holds it"


def test_a_patch_made_before_the_first_start_is_not_lost_by_the_replay(rz):
    # R-T3b: the replay's wc-* takes out every row, and a patch made before the first start is no action of the
    # timeline (it is applied at the open). It is written again -- and before the first action, because it was in the
    # cache when the run began: a patch over code the run executes changes what the run does
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")], over=[(0x140002003, "90")])
    assert [a["kind"] for a in _the_saved_record(rz)["actions"]] == ["start", "run", "patch"], "it is no action"
    sid, session = _reopened(rz, path)
    mark = len(rz.commands())
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True
    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid) if r["mine"]] == [
        (UNCOVERED, "9090", True), (0x140002003, "90", True)]
    replay = _the_replay(rz, mark)
    assert replay.count("wx 9090 @ 0x140001500") == 1, "once"
    assert replay.index("wx 9090 @ 0x140001500") < replay.index("aei"), "and before the first action"
    assert replay.count("wx 90 @ 0x140002003") == 1, "the one the timeline makes is made by the timeline, once"


def test_a_patch_made_before_the_start_and_the_same_one_made_over_the_run_are_both_back(rz):
    # the same address and bytes, once before the first start and once over the run's bytes: the open applies the
    # first and holds the second back, the timeline holds a patch action of the second -- so the one that is no
    # action must not be taken for it. The run XORs over the first (0x90 ^ 0x41 = 0xd1), which is what the proof is
    # made of: written after the start, or not at all, the digest is another one
    path, line = _decrypted_and_saved(rz, before=[(0x140002003, "90")], over=[(0x140002003, "90")])
    assert _the_saved_record(rz)["digests"][0]["sha256"] == hashlib.sha256(bytes([0x41] * 3 + [0xD1] + [0x41] * 4)).hexdigest()
    sid, session = _reopened(rz, path)
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(0x140002003, "90")]
    assert _waiting(rz, sid) == [] and session._waiting == [(0x140002003, "90", True)], \
        "the one over the run is held back, and the cache's twin of it hides it from the list"
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True, answer["reason"]
    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid) if r["mine"]] == [
        (0x140002003, "90", True), (0x140002003, "90", True)]
    assert _the_bytes(session)[3] == 0x90 and answer["patches"]["waiting"] == [] and session._waiting == []
    assert session._restore_saved is not None, "the replay's wc-* removed a patch the timeline makes: not a take-back"


def test_a_waiting_patch_the_timeline_does_not_make_is_written_though_the_cache_holds_its_twin(rz):
    # the same pair as above, but the project's timeline is an older one that lacks the patch over the run (a spoiled
    # save leaves the line as it was): the held patch is nobody's action, and the twin the open applied is no reason
    # to take it for one that is in the cache. It is written, over the run's bytes
    path, line = _decrypted_and_saved(rz, before=[(0x140002003, "90")], over=[(0x140002003, "90")])
    sid, session = _reopened(rz, path)
    record = session._restore_saved
    session._restore_saved = dict(record, actions=record["actions"][:2])
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True and answer["applied"] == [0x140002003], answer
    assert [(r["addr"], r["after"], r["over_run"]) for r in _patches(rz, sid) if r["mine"]] == [
        (0x140002003, "90", False), (0x140002003, "90", True)]
    assert session._waiting == []


def test_the_replay_hashes_the_cache_in_the_order_the_writes_were_made_in(rz):
    # R-T2a at the replay: two stores overlap (a byte, then four bytes over it), the later one wins. By address the
    # four come first and the byte after them, which is a plausible SHA-256 of bytes the run never left, and
    # run_digests cannot tell
    path, line = _decrypted_and_saved(rz, over=[], stub=(ORDER_AT, ORDER_END))
    right = hashlib.sha256(bytes.fromhex("41004141")).hexdigest()
    assert right != hashlib.sha256(bytes.fromhex("41414141")).hexdigest(), "and not what rows by address would make"
    assert [d["sha256"] for d in _the_saved_record(rz)["digests"]] == [right], "what the save made"
    sid, session = _reopened(rz, path)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True, answer["reason"]
    assert _the_bytes(session, ORDER_TARGET, 4) == [0x41, 0x00, 0x41, 0x41]


def test_the_replay_sets_the_value_the_skip_applied_and_the_counters_the_timeline_began_with(rz, monkeypatch):
    # the recorded value is the one that was applied (the user edited the clock to 0x1234), not the one the
    # assistant would offer now, and the counters begin where the timeline did, so a clock that rises rises the same
    import rizin_emulation

    monkeypatch.setenv("FAKE_RIZIN_ASSIST", "1")
    path = rz.write("pipesim.exe")
    sid = rz.open(path)["session"]
    rz.wait_done(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{ASSIST_AT + 12:#x}"})  # GetTickCount
    _skip(rz, sid, ASSIST_AT + 12, value="0x1234", stack_fix=0)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})  # a start is an action: registers stay
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    after = _register(rz, sid, "rax")
    assert after == 0x1234
    session = rz.mgr.get(sid)
    ticks = session._assist_tick
    assert ticks == rizin_emulation.TICK_START + rizin_emulation.TICK_STEP
    assert session.flush() is True
    assert [a["kind"] for a in _the_saved_record(rz)["actions"]] == ["start", "skip", "start", "run"]
    rz.close(sid)

    sid, session = _reopened(rz, path)
    session._assist_tick, session._assist_handle, session._assist_pseudo = 0x500000, 3, 4
    session._pipe.cmd("ar rax=0x7777")  # a register somebody set before: the replay begins from rizin's own state
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True, answer["reason"]
    assert _register(rz, sid, "rax") == 0x1234, "the applied value"
    assert (session._assist_tick, session._assist_handle, session._assist_pseudo) == (ticks, 0, 0)
    assert session._restore["counters"] == {"tick": rizin_emulation.TICK_START, "handle": 0, "pseudo": 0}, \
        "the timeline's own begin, not where the replay left them: a derivation from them starts there"
    assert answer["state"]["pc"] == hex(DECRYPT_END)


def test_a_timeline_of_the_session_is_replaced_by_the_replay_not_added_to(rz):
    # started and stopped by hand before the restore: the cache is still the open's, so it is let through, and the
    # live timeline (a start) describes a cache that was replaced -- it must not be saved with the digests of the
    # replayed run, nor grow by the replay's actions: it is the record that is the timeline afterwards, and nothing else
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    assert len(session._restore["actions"]) == 1
    spied = []
    session._schedule_save = lambda: spied.append(1)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True and answer["applied"] == []
    assert [a["kind"] for a in session._restore["actions"]] == ["start", "run", "patch"], "not a start of the hand's, nor six"
    assert spied == [], "the replay asked for no save, and nothing was written after the proof"
    del session._schedule_save
    _mark_dirty(rz, sid)
    session.flush()
    assert _restore_value(rz.project()) == line, "the project keeps the record it had"


def test_the_replayed_timeline_is_a_copy_that_grows_and_the_project_keeps_the_longer_recipe(rz):
    # the review's addition: the replay proved the cache is what the record describes, so what is done next is an
    # action after the last one, in its place. Not begun again (the run's own rows are not "foreign": it is not
    # tainted, and its counters are the record's), a copy (the project's record does not grow in place), and the
    # next open restores all of it
    import rizin_emulation

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    session._assist_tick = 0x500000  # begun again, the timeline would take the counters as they stand
    assert rz.ok(_restore(rz, sid))["restored"] is True
    saved, live = session._restore_saved, session._restore
    assert live is not saved and live["actions"] is not saved["actions"] and live["actions"] == saved["actions"]
    assert live["tainted"] is None and live["counters"] == saved["counters"]
    assert live["counters"]["tick"] == rizin_emulation.TICK_START
    assert _offer(rz, sid) == {"actions": 3, "reason": None, "digests": 1}
    _run(rz, sid, "step")
    _patch(rz, sid, addr="0x140001600", bytes="9090")
    assert len(live["actions"]) == 5 and len(saved["actions"]) == 3, "the copy grew, the project's did not"
    assert session._opened == [] and _restore(rz, sid).status_code == 400, "a second press is refused: the cache is the run's"
    assert session.flush() is True
    record = _the_saved_record(rz)
    assert [a["kind"] for a in record["actions"]] == ["start", "run", "patch", "run", "patch"]
    rz.close(sid)

    sid, session = _reopened(rz, path)
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(0x140001600, "9090")]
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True, answer["reason"]
    assert [(r["addr"], r["after"]) for r in answer["patches"]["patches"] if r["mine"]] == [
        (0x140001600, "9090"), (0x140002003, "90")]
    assert len(session._restore["actions"]) == 5


def test_a_replayed_record_that_is_at_the_cap_spoils_at_the_first_action_that_follows(rz, monkeypatch):
    import rizin_emulation

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    assert rz.ok(_restore(rz, sid))["restored"] is True
    monkeypatch.setattr(rizin_emulation, "RESTORE_MAX_ACTIONS", 3)
    _run(rz, sid, "step")
    assert len(session._restore["actions"]) == 3 and "dropped" in session._restore["tainted"]


def test_the_replay_does_not_throw_the_record_away_the_way_a_take_back_does(rz, monkeypatch):
    # Task 3: unpatch() discards the timeline. The replay's wc-* is not an unpatch: nothing about the record changes,
    # not its text, not the reason it is gone (there is none), and a second press is refused for the cache's reason
    import rizin_sessions

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    monkeypatch.setattr(session, "unpatch", lambda *args, **kwargs: pytest.fail("the replay is no take back"))
    discarded = []
    monkeypatch.setattr(session, "_restore_discard", lambda *args, **kwargs: discarded.append(1))
    assert rz.ok(_restore(rz, sid))["restored"] is True
    assert discarded == [] and session._restore_gone is None and session._restore_saved is not None
    # the moment a pane reads the offer again, right after the press: the timeline is the session's own and clean, and the
    # button is refused -- for the emulation that the replay left running, and then for the cache, which is the run's
    offer = session._restore_offer()
    assert offer["actions"] == 3 and offer["reason"] is None and offer["refused"] == rizin_sessions._RESTORE_RUNNING, offer
    response = _restore(rz, sid)
    assert response.status_code == 400 and response.get_json()["refused"] == offer["refused"]
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    offer = session._restore_offer()
    assert offer["refused"] == rizin_sessions._RESTORE_CACHE and "write cache holds more or other" in offer["refused"], offer
    response = _restore(rz, sid)
    assert response.status_code == 400 and response.get_json()["refused"] == offer["refused"]


def test_apply_now_is_refused_until_a_runs_bytes_cover_the_address(rz):
    # The user's decision: the way out appears when the patch makes sense again, and the **server** says when --
    # a patch written before a run's bytes are under it is the harm that held it back
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    url = f"/api/rizin/{sid}/patch"
    mark = len(rz.commands())
    refused = rz.post(url, {"addr": "0x140002003", "waiting": True})
    assert refused.status_code == 400 and "no run's bytes lie under 0x140002003" in refused.get_json()["refused"]
    other = rz.post(url, {"addr": "0x140002004", "waiting": True})
    assert other.status_code == 400 and "no patch waits at 0x140002004" in other.get_json()["refused"]
    assert rz.post(url, {"addr": "0x140002003", "waiting": True, "bytes": "90"}).status_code == 400
    assert rz.post(url, {"addr": "0x140002003", "waiting": True, "kind": "nop"}).status_code == 400
    assert rz.post(url, {"addr": "0x140002003", "waiting": "yes"}).status_code == 400
    assert not [c for c in rz.commands()[mark:] if c.startswith("wx")], "nothing was written into the file's bytes"
    assert [(w["addr"], w["after"]) for w in _waiting(rz, sid)] == [(0x140002003, "90")] and _patches(rz, sid) == []

    # the analyst decrypts by hand, and now the patch makes sense
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    for extra in ({"bytes": "cc"}, {"kind": "nop"}):  # now that it would be let through, it is still no way to say other bytes
        both = rz.post(url, {"addr": "0x140002003", "waiting": True, **extra})
        assert both.status_code == 400 and "takes no bytes and no kind" in both.get_json()["refused"]
    assert not [r for r in _patches(rz, sid) if r["mine"]], "and nothing was written"
    answer = rz.send(url, {"addr": "0x140002003", "waiting": True})
    assert [(r["addr"], r["after"], r["mine"], r["over_run"]) for r in answer["patches"] if r["mine"]] == [
        (0x140002003, "90", True, True)]
    assert answer["waiting"] == [] and session._waiting == []
    assert _the_bytes(session) == [0x41, 0x41, 0x41, 0x90, 0x41, 0x41, 0x41, 0x41]
    session.flush()
    assert "\npatches=140002003:90:r\n" in _project_text(rz.project())
    assert rz.post(url, {"addr": "0x140002003", "waiting": True}).status_code == 400, "it does not wait any more"


def test_apply_now_over_a_run_that_covers_only_part_of_the_patch_is_let_through(rz):
    # a patch of several bytes is over the run's bytes where any byte of it is: the address says where it begins
    path, line = _decrypted_and_saved(rz, over=[(0x140002006, "909090")])
    sid, session = _reopened(rz, path)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    answer = rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140002006", "waiting": True})
    assert [(r["addr"], r["after"]) for r in answer["patches"] if r["mine"]] == [(0x140002006, "909090")]


def test_dropping_a_waiting_patch_takes_it_out_of_the_project(rz):
    # exit one: the cross. It goes from the list and from the project, the cache is not touched, and the timeline
    # that makes the patch again goes with it -- a replay would put back what the user took out
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    url = f"/api/rizin/{sid}/patch"
    unnamed = rz.delete(url, {"waiting": True})
    assert unnamed.status_code == 400 and "named by its addr" in unnamed.get_json()["refused"]
    nothing = rz.delete(url, {"addr": "0x140002004", "waiting": True})
    assert nothing.status_code == 400 and "no patch waits at 0x140002004" in nothing.get_json()["refused"]
    assert rz.delete(url, {"addr": "0x140002003", "waiting": 1}).status_code == 400
    mark = len(rz.commands())
    answer = rz.remove(url, {"addr": "0x140002003", "waiting": True})
    assert answer["patches"] == [] and answer["waiting"] == [] and session._waiting == []
    assert answer["restore"]["actions"] == 0 and "taken out of the project" in answer["restore"]["reason"]
    assert not [c for c in rz.commands()[mark:] if c.startswith(("wc-", "wx"))], "the cache is not touched"
    assert session._restore_saved is None
    offer = _offer(rz, sid)
    assert offer["actions"] == 0 and "taken out of the project" in offer["reason"], offer
    assert _restore(rz, sid).status_code == 400
    assert session.flush() is True
    text = _project_text(rz.project())
    assert _project_patches(rz) == "" and "\nrestore=" not in text, "out of the project, and the timeline with it"
    rz.close(sid)
    sid, session = _reopened(rz, path)
    assert _waiting(rz, sid) == [] and session._restore_saved is None


def test_dropping_a_waiting_patch_the_timeline_does_not_make_keeps_the_timeline(rz):
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    session._waiting.append((UNCOVERED, "90", True))
    session._lost = [(UNCOVERED, "90", True), (0x140002003, "90", True)]  # the same patch a restart lost goes with it
    saved = session._restore_saved
    answer = rz.remove(f"/api/rizin/{sid}/patch", {"addr": f"{UNCOVERED:#x}", "waiting": True})
    assert [w["addr"] for w in answer["waiting"]] == [0x140002003]
    assert session._restore_saved is saved and session._restore_gone is None
    assert session._lost == [(0x140002003, "90", True)]
    assert _offer(rz, sid) == {"actions": 3, "reason": None, "digests": 1}
    assert session.flush() is True
    assert _restore_value(rz.project()) == line and "patches=140002003:90:r\n" in _project_text(rz.project())


def test_a_record_without_digests_proves_nothing_and_is_not_replayed(rz):
    import rizin_sessions

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    session._restore_saved = dict(session._restore_saved, digests=[])
    assert _refused(rz, sid) == rizin_sessions._RESTORE_NOTHING
    mark = len(rz.commands())
    assert _restore(rz, sid).status_code == 400
    assert _the_replay(rz, mark) == []


def test_the_three_routes_drop_the_copies_of_the_views_whatever_came_of_them(rz):
    # the replay changes the cache and the emulation, a waiting patch is written, and a refused request may have
    # got as far as a view of its own: the copies go for all three, on success and on refusal
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)

    def generation():
        return rz.tdc._rizin_cache.get(session, {"gen": 0})["gen"]

    for request in (lambda: rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140002003", "waiting": True}),  # refused
                    lambda: rz.delete(f"/api/rizin/{sid}/patch", {"addr": "0x140002003", "waiting": True}),  # drops it
                    lambda: _restore(rz, sid),  # refused: no timeline any more
                    ):
        before = generation()
        request()
        assert generation() > before
    path, line = _decrypted_and_saved(rz, name="other.exe")
    sid, session = _reopened(rz, path)
    before = generation()
    assert rz.ok(_restore(rz, sid))["restored"] is True
    assert generation() > before
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    session._waiting.append((0x140002004, "90", True))
    before = generation()
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140002004", "waiting": True})
    assert generation() > before


def test_a_restart_makes_the_cache_it_has_the_one_the_timeline_is_restored_into(sessions, sample, fake, tmp_path,
                                                                                monkeypatch):
    # a rizin that was restarted has an empty cache and the patches of the mirror in it, like the open: that is the
    # cache the restore is allowed to replace, and not the one the first rizin was opened with
    monkeypatch.setenv("FAKE_RIZIN_SLOW", "aar:60")
    timers = Timers()
    mgr = sessions(analysis_limit=1.0, step_grace=0.5, big_file=1, timer=timers)
    opened = mgr.open(sample("restart_restore.exe", b"MZ restart restore"), "tab")
    session = mgr.get(opened["session"])
    _wait_state(session, "done")
    session.emulation_start(DECRYPT_AT)
    session.emulation_run("until", DECRYPT_END)
    session.patch(0x140002003, "90")
    session.patch(0x140001600, "9090")  # over no run's bytes: written again by the restarted rizin, and a timeline action
    timers.fire()
    session.analyze_full()  # its aar hangs, so rizin is killed and restarted
    _wait_state(session, "stopped")
    assert session._opened == [(0x140001600, 2, "9090")] and session._waiting == [(0x140002003, "90", True)]
    assert session._restore is None and session._restore_saved is not None, "a restart is nobody's take-back"
    assert session._emulation is not None, "the old rizin's emulation is not this one's: a restart has none"
    answer = session.restore_run()
    assert answer["restored"] is True, answer["reason"]
    assert session.json("pxj 8 @ 0x140002000") == [0x41, 0x41, 0x41, 0x90, 0x41, 0x41, 0x41, 0x41]
    assert [(r["addr"], r["after"]) for r in answer["patches"]["patches"] if r["mine"]] == [
        (0x140001600, "9090"), (0x140002003, "90")]
    assert session._waiting == []
    assert session._restore_gone is None, "the cache the restart emptied is the one the replay has just rebuilt"


@pytest.mark.skipif(not REAL_RIZIN, reason="rizin not installed")
@pytest.mark.skipif(not RZ_ASM, reason="rz-asm not installed")
def test_real_rizin_a_replayed_timeline_gives_the_same_bytes(tmp_path):
    """The proof the whole feature rests on, against the binary: a real decryption (rizin's ESIL XORs 0x40 bytes), a
    patch over what it left and one made before the run, saved; then a **new** rizin replays the timeline and the
    bytes it reads at the decrypted range are the ones the first one read -- byte for byte, the SHA-256 the project
    holds is the one the replay makes, and a patch made before the first start is still there. Only the binary can
    show that ``ara0``, ``wc-*`` and a second ``aei`` do what the fake's model says they do.

    The second half is the promise of Review Focus 4: with a digest that is not the run's, the replay applies
    nothing and the cache is what the open made it (measured with ``wcj``), the emulation's maps are gone and the
    registers are zero."""
    import rizin_sessions

    blob = tmp_path / "decryptor.bin"
    stop = _decryptor_blob(blob)
    sha = hashlib.sha256(blob.read_bytes()).hexdigest()
    project = tmp_path / "projects" / (sha + ".rzdb")

    def opened():
        mgr = rizin_sessions.RizinSessions(exe=REAL_RIZIN, projects_dir=str(tmp_path / "projects"))
        session = mgr.get(mgr.open(str(blob), "tab")["session"])
        _wait_state(session, "done", timeout=60)
        return mgr, session

    mgr, session = opened()
    try:
        session.console("e asm.arch=x86")  # a raw blob is read for the host's arch (avr here)
        session.console("e asm.bits=64")
        session.patch(0x2000, "9090")  # before the first start: no action, applied at the open
        session.emulation_start(0)
        assert session.emulation_run("until", stop)["pc"] == hex(stop)
        session.patch(0x1002, "9090")  # the check inside what was decrypted
        first = session.json("pxj 64 @ 0x1000")
        assert first[0] == 0xF9 and first[2:4] == [0x90, 0x90]  # decrypted: stc, push rbp, and the patch
        assert session.flush() is True
    finally:
        mgr.shutdown()

    mgr, session = opened()
    try:
        assert [(w["addr"], w["after"]) for w in session.patches()["waiting"]] == [(0x1002, "9090")]
        assert session.json("pxj 64 @ 0x1000")[0] == 0x06, "encrypted again: the open held the patch back"
        assert session._restore_offer() == {"actions": 3, "reason": None, "digests": 1, "refused": None}
        answer = session.restore_run()
        assert answer["restored"] is True, answer["reason"]
        assert session.json("pxj 64 @ 0x1000") == first, "the same bytes, patch included"
        assert answer["state"]["pc"] == hex(stop) and answer["applied"] == []
        assert sorted(r["addr"] for r in answer["patches"]["patches"] if r["mine"]) == [0x1002, 0x2000]
        assert answer["patches"]["waiting"] == [] and session._restore["tainted"] is None
        assert len(session._restore["actions"]) == 3
    finally:
        mgr.shutdown()

    mgr, session = opened()
    try:
        session._restore_saved["digests"][0]["sha256"] = "0" * 64
        answer = session.restore_run()
        assert answer["restored"] is False and "other bytes" in answer["reason"], answer["reason"]
        rows = rizin_emulation_rows(session)
        assert [(r["addr"], r["after"]) for r in rows] == [(0x2000, "9090")], "the cache is the open's: wcj says so"
        assert session.json("pxj 64 @ 0x1000")[0] == 0x06 and session.json("pxj 2 @ 0x2000") == [0x90, 0x90]
        assert not [m for m in session.json("omlj") if m["name"].startswith("mem.")], "the emulation's maps are gone"
        # the registers are the reset's again: the decryptor's loop leaves rsi at 0x1040 (and rcx at 0, which would
        # say nothing), and aei keeps what a run left -- so only a reset that the undo really sent reads 0 here
        assert int(session.text("ar rsi").split("=")[-1].strip(), 16) == 0
        assert [(w["addr"], w["after"]) for w in answer["patches"]["waiting"]] == [(0x1002, "9090")]
    finally:
        mgr.shutdown()


def rizin_emulation_rows(session):
    import rizin_emulation

    return rizin_emulation.parse_cache(session._pipe.cmd("wcj"))


def test_the_replayed_cache_is_the_original_one_row_for_row(rz):
    # the open applies A, B and A' (the third is a patch action of the timeline that no run had written under) and
    # holds one back; the replay has to make them in the order the first session did -- two writes that overlap are
    # decided by it -- with the one that is no action before the start and the one that is an action at its place
    original = []
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090"), (UNCOVERED + 1, "cc")],
                                      over=[(0x140002003, "90"), (UNCOVERED, "9090")], rows=original)
    assert [(r["addr"], r["mine"]) for r in original][:2] == [(UNCOVERED, True), (UNCOVERED + 1, True)]
    sid, session = _reopened(rz, path)
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(UNCOVERED, "9090"), (UNCOVERED, "9090"),
                                                                    (UNCOVERED + 1, "cc")], "the open applied the three"
    saved = session._restore_saved
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True, answer["reason"]
    assert session._restore_saved is saved, "the replay's wc-* took a patch of the timeline out of the cache and is nobody's take-back"
    assert session.patches_made() == original, "the same rows, the same marks, in the same order"
    assert _the_bytes(session, UNCOVERED, 2) == [0x90, 0x90], "the later write wins over the byte they share"


def test_a_patch_a_restart_lost_stays_the_projects_whatever_the_replay_did(rz, monkeypatch):
    # the replay writes patches, and a patch write clears what a restarted rizin lost (the user is patching this
    # cache); the replay is nobody's patching, so what the project keeps stays kept -- when it holds and when not
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    session._lost = [(0x140001700, "aa", False)]
    assert rz.ok(_restore(rz, sid))["restored"] is True
    assert session._lost == [(0x140001700, "aa", False)]
    rz.close(sid)
    monkeypatch.setenv("FAKE_RIZIN_XOR_KEY", "0x42")
    sid, session = _reopened(rz, path)
    session._lost = [(0x140001700, "aa", False)]
    assert rz.ok(_restore(rz, sid))["restored"] is False
    assert session._lost == [(0x140001700, "aa", False)]


def test_a_waiting_patch_rizin_does_not_take_stays_waiting_and_the_restore_holds(rz, monkeypatch):
    # the proof is the run's; a patch written after it that rizin refuses does not undo it
    import rizin_sessions

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    session._waiting.append((0x140002005, "cc", True))
    real = session._patch_write

    def refuses(pipe, addr, data):
        if addr == 0x140002005:
            raise rizin_sessions.RizinRefused("rizin wrote nothing at 0x140002005")
        return real(pipe, addr, data)

    monkeypatch.setattr(session, "_patch_write", refuses)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True and answer["applied"] == []
    assert [(w["addr"], w["after"]) for w in answer["patches"]["waiting"]] == [(0x140002005, "cc")]
    assert session._waiting == [(0x140002005, "cc", True)]


def test_restoring_says_so_when_rizin_will_not_say_what_the_cache_or_the_breakpoints_hold(rz, monkeypatch):
    import rizin_sessions

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    monkeypatch.setattr(session, "_breakpoint_list", lambda pipe: (_ for _ in ()).throw(ValueError("dblj")))
    mark = len(rz.commands())
    response = _restore(rz, sid)
    assert response.status_code == 400 and response.get_json()["refused"] == rizin_sessions._RESTORE_CACHE_UNREAD
    assert _the_replay(rz, mark) == []


# --- Fix round 1 for the replay --------------------------------------------------------------------------------

def test_taking_back_a_patch_the_timeline_makes_drops_the_saved_timeline(rz):
    # Measured by the review: the patch is a timeline action over no run's bytes (the open applies it), the user takes
    # it back in a reopened session -- where there is no live timeline for unpatch to discard -- and the next replay
    # wrote it again and said "restored". The SHA-256 cannot tell: the patch lies outside the hashed ranges.
    path, line = _decrypted_and_saved(rz, over=[(0x140002003, "90"), (0x140001600, "9090")])
    sid, session = _reopened(rz, path)
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(0x140001600, "9090")]
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140001600"})
    assert session._restore_saved is None, "what replays the patch is not kept"
    assert "taken back" in session._restore_gone and "again" in session._restore_gone
    assert _offer(rz, sid)["actions"] == 0 and "taken back" in _offer(rz, sid)["reason"]
    assert session.flush() is True
    assert "\nrestore=" not in _project_text(rz.project())
    rz.close(sid)
    sid, session = _reopened(rz, path)
    assert session._restore_saved is None
    response = _restore(rz, sid)
    assert response.status_code == 400 and "no timeline" in response.get_json()["refused"]
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [], "and nothing put the patch back"


def test_taking_the_whole_cache_back_drops_a_saved_timeline_that_makes_a_patch(rz):
    path, line = _decrypted_and_saved(rz, over=[(0x140002003, "90"), (0x140001600, "9090")])
    sid, session = _reopened(rz, path)
    rz.remove(f"/api/rizin/{sid}/patch", {})
    assert session._restore_saved is None


def test_taking_back_a_patch_the_timeline_does_not_make_keeps_the_saved_timeline(rz):
    # a patch made before the first start is no action: nothing replays it, so nothing is lost with it
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    saved = session._restore_saved
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": f"{UNCOVERED:#x}"})
    assert session._restore_saved is saved and session._restore_gone is None
    # and a take-back where no row of the session's own goes (a run's bytes) is not a patch of the timeline either
    session._pipe.cmd("wx aa @ 0x140002010")
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140002010"})
    assert session._restore_saved is saved


def test_the_patches_of_the_open_are_written_in_the_order_they_were_made_in(rz):
    # Task 5's third step: two patches that overlap, neither of them an action of the timeline, so nothing but the
    # order of the open's list decides what the cache holds -- the later write wins over the byte they share
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090"), (UNCOVERED + 1, "cc")], over=[(0x140002003, "90")])
    sid, session = _reopened(rz, path)
    mark = len(rz.commands())
    assert rz.ok(_restore(rz, sid))["restored"] is True
    replay = _the_replay(rz, mark)
    assert replay[:4] == ["wc-*", "ara0", "wx 9090 @ 0x140001500", "wx cc @ 0x140001501"], replay
    assert _the_bytes(session, UNCOVERED, 2) == [0x90, 0xCC]


def test_the_gate_compares_the_bytes_of_the_cache_and_not_only_where_they_are(rz):
    # a write of the console of the same address and size as the open's patch, with other bytes
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    session._pipe.cmd(f"wc- {UNCOVERED:#x} {UNCOVERED + 1:#x}")
    session._pipe.cmd(f"wx abab @ {UNCOVERED:#x}")
    response = _restore(rz, sid)
    assert response.status_code == 400 and "write cache holds more or other" in response.get_json()["refused"]


def test_get_patches_carries_the_offer_and_reads_the_cache_once(rz):
    import rizin_sessions

    # The button's reader (spec 3): the offer rides the answer of GET /patches, which is asked for by the user and takes the
    # gate like a run. One wcj for all of it -- the list, the proof of a live timeline, the gate of a saved one.
    def reads(sid):
        mark = len(rz.commands())
        answer = rz.read(f"/api/rizin/{sid}/patches")
        return answer, rz.commands()[mark:].count("wcj"), rz.commands()[mark:].count("dblj")

    sid = rz.session()
    answer, wcj, dblj = reads(sid)
    assert answer == {"patches": [], "waiting": [], "restore": {"actions": 0, "reason": None, "digests": 0, "refused": _NO_RECORD}}
    assert (wcj, dblj) == (1, 0), "no timeline: nothing to ask the breakpoints for"

    path, line = _decrypted_and_saved(rz, name="saved.exe")
    sid, session = _reopened(rz, path)
    answer, wcj, dblj = reads(sid)
    assert answer["restore"] == {"actions": 3, "reason": None, "digests": 1, "refused": None} and (wcj, dblj) == (1, 1)
    assert answer["restore"] == session._restore_offer()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    answer, wcj, dblj = reads(sid)
    assert answer["restore"] == session._restore_offer() and answer["restore"]["actions"] == 2 and wcj == 1, "a live timeline"
    assert answer["restore"]["refused"] == rizin_sessions._RESTORE_RUNNING and answer["restore"]["reason"] is None
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    answer, wcj, dblj = reads(sid)
    assert answer["restore"]["refused"] == rizin_sessions._RESTORE_CACHE, "the cache is the run's: the button is refused"
    assert answer["restore"]["reason"] is None and (wcj, dblj) == (1, 1), "the live timeline would be saved, and that is the other field"


def test_a_reset_of_the_registers_that_rizin_did_not_take_is_said_and_not_taken_for_other_bytes(rz, monkeypatch):
    # ara0 answers nothing either way: it is read back (the PC is 0 after it). Here rizin ignores it and the PC is where
    # an earlier run left it -- the replay says so, and the undo, which has no digest to find it out, says it too
    path, line = _decrypted_and_saved(rz)
    monkeypatch.setenv("FAKE_RIZIN_ARA0_IGNORED", "1")
    sid, session = _reopened(rz, path)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    mark = len(rz.commands())
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and "did not reset the registers (the PC reads 0x140001440)" in answer["reason"], answer
    assert "other bytes" not in answer["reason"] and "nothing was applied" in answer["reason"]
    assert answer["reason"].endswith("-- and rizin did not reset the registers either: they are what the replay left")
    assert not [c for c in rz.commands()[mark:] if c.startswith(("aei", "aepc", "wx"))], "it never got to the first action"
    assert _patches(rz, sid) == [] and session._emulation is None


def test_a_replay_that_runs_out_of_time_stops_between_actions_and_undoes_itself(rz, monkeypatch):
    # spec 6: the cap on the actions is the lever against a restore that takes minutes; 500 runs of esil.timeout is not
    # one, so the replay has a budget of its own, checked before each action. Exactly the budget is still in time.
    import rizin_sessions

    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    budget = rizin_sessions.RESTORE_BUDGET
    ticks = iter([0, 0, budget / 2, budget + 1])  # the deadline, then before action 1, 2 and 3
    monkeypatch.setattr(rizin_sessions, "_replay_clock", lambda: next(ticks))
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False
    assert "before action 3 of 3 (patch at 0x140002003)" in answer["reason"] and f"{budget:g} seconds" in answer["reason"]
    assert "the 2 before it" in answer["reason"], "and it says how far it got"
    _the_state_of_the_open(rz, sid, session, [(UNCOVERED, "9090")])
    ticks = iter([0, 0, budget / 2, budget])
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True, answer["reason"]


def test_a_replay_whose_list_of_the_cache_cannot_be_made_is_still_a_restored_one(rz, monkeypatch):
    # the list after the replay is for the pane: a failure of it must not turn a replay that held into a 500
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    monkeypatch.setattr(session, "_patches_answer", lambda pipe, rows=None: (_ for _ in ()).throw(ValueError("wcj")))
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True and answer["patches"] is None and answer["reason"] is None
    assert _the_bytes(session)[3] == 0x90


def test_a_replay_that_rizin_dies_in_ends_the_session_and_leaves_no_flag_behind(rz, monkeypatch):
    # RizinDied passes by the replay's own failure paths (there is no rizin to undo it in): _call ends the session as it
    # does for any command, and what the replay set on the session is not left set
    import rizin_sessions

    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])  # its write clears what a restart lost, as any does
    sid, session = _reopened(rz, path)
    session._lost = [(0x140001700, "aa", False)]

    def dies(pipe, kind, command, addr):
        raise rizin_sessions.RizinDied("rizin is gone")

    monkeypatch.setattr(session, "_emulation_ran", dies)
    response = _restore(rz, sid)
    assert response.status_code == 404 and response.get_json()["error"] == "session ended"
    assert session.closed and session._replaying is False and session._lost == [(0x140001700, "aa", False)]
    assert rz.get(f"/api/rizin/{sid}/patches").status_code == 404


def test_what_each_route_reads_of_the_cache(rz):
    # R-T3h: ``wcj`` is 84 ms and 4 MB of JSON per MB cached, so every answer reads it as often as it must and no more.
    # The list, the offer and the gate share one read; a write adds the read its own check needs (_patch_write), and
    # the answer after it is the cache as it is then. The counts are: gate 1 + the patch of the open 1 + the patch
    # action 1 + the proof 1 + the answer 1 for a replay; read 1 + the write 1 + the answer 1 for apply-now.
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    session._waiting.append((0x140002005, "cc", True))

    def reads(do):
        mark = len(rz.commands())
        do()
        commands = rz.commands()[mark:]
        return commands.count("wcj"), commands.count("dblj")

    assert reads(lambda: rz.read(f"/api/rizin/{sid}/patches")) == (1, 1), "one read; the breakpoints for the project's timeline"
    assert reads(lambda: rz.post(f"/api/rizin/{sid}/patch", {"addr": "0x140002003", "waiting": True})) == (1, 0), "refused"
    assert reads(lambda: rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140002005", "waiting": True})) == (1, 1), \
        "nothing was written, so the read of the gate is the answer's"
    assert reads(lambda: rz.ok(_restore(rz, sid))) == (5, 1)
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    session._waiting.append((0x140002005, "cc", True))
    assert reads(lambda: rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140002005", "waiting": True})) == (3, 1), \
        "the offer of the adopted timeline asks the breakpoints once the emulation is stopped"


def test_taking_back_a_write_that_is_not_a_patch_of_the_session_keeps_the_saved_timeline(rz):
    # the rule is about the session's own patches: a run's row that happens to have the bytes of a patch action goes,
    # and the timeline is not what put it there
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    saved = session._restore_saved
    session._pipe.cmd("e io.cache=true")
    session._pipe.cmd("wx 90 @ 0x140002003")  # a foreign row with the address and bytes of the timeline's patch
    assert [r["mine"] for r in _patches(rz, sid)] == [False]
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140002003"})
    assert session._restore_saved is saved and session._restore_gone is None


def test_the_offer_of_a_project_with_patches_in_the_order_they_were_made_in_is_not_refused_for_the_order(rz):
    # the open's patches are written in the order the first session made them, which is not the order of their
    # addresses; the gate compares the cache in write order, and both the answer of GET /patches and the route do
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED + 1, "cc"), (UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    assert session._opened == [(UNCOVERED + 1, 1, "cc"), (UNCOVERED, 2, "9090")]
    assert rz.read(f"/api/rizin/{sid}/patches")["restore"] == {"actions": 3, "reason": None, "digests": 1, "refused": None}
    assert _refused(rz, sid) is None
    assert rz.ok(_restore(rz, sid))["restored"] is True
    assert _the_bytes(session, UNCOVERED, 2) == [0x90, 0x90], "the later write, the one over the byte they share"


def test_the_offer_counts_the_ranges_of_a_live_timeline_and_does_not_hash_them(rz, monkeypatch):
    import rizin_sessions

    # judged for round 2: the pane's own route pays no SHA-256 for a figure that is a count (measured, 2^20 one-byte rows:
    # 1.65 s with the hashing, and the hashing is a third of that); the save and the replay are what hash
    sid = rz.session()
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    session.flush()  # the save the start asked for hashes, as it should: not inside the window below
    monkeypatch.setattr(session, "_restore_digests", lambda *args, **kwargs: pytest.fail("the offer hashed"))
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert answer["restore"] == {"actions": 1, "reason": None, "digests": 1, "refused": rizin_sessions._RESTORE_RUNNING}


def test_a_replay_that_fails_after_it_became_the_timeline_is_not_the_timeline_any_more(rz, monkeypatch):
    # the step that follows the proof (reading the state) fails: the cache is the open's again, and the record that was
    # adopted for it is gone with the replay -- a timeline that outlived it would be recording over the wrong cache
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    real = session._emulation_read

    def fails_once_the_record_is_the_sessions(pipe):
        if session._restore is not None:
            raise ValueError("state")
        return real(pipe)

    monkeypatch.setattr(session, "_emulation_read", fails_once_the_record_is_the_sessions)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and "could not go on (state)" in answer["reason"]
    _the_state_of_the_open(rz, sid, session, [(UNCOVERED, "9090")])
    assert session._restore is None


def test_taking_back_a_patch_at_the_address_of_one_the_timeline_makes_but_with_other_bytes_keeps_it(rz):
    # the timeline replays bytes, not an address: another patch of the session's own at the same place is not the one
    # it would write again
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    saved = session._restore_saved
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    _patch(rz, sid, addr="0x140002003", bytes="cc")
    answer = rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140002003"})
    assert [(r["addr"], r["after"]) for r in answer["patches"] if r["mine"]] == []
    assert session._restore_saved is saved and session._restore_gone is not None, "the live timeline went, the project's did not"
    assert "taken back" not in session._restore_gone


def test_a_console_take_back_of_a_patch_the_timeline_makes_drops_the_saved_timeline_too(rz):
    # the second door to the defect of round 1: the console's wc- is no unpatch, and in a reopened session there is no live
    # timeline for the taint of "a console command wrote to the cache" to land on. The mirror is where it is seen, at the
    # next read of the cache, which a save, GET /patches and the gate all make
    import rizin_sessions

    for command in ("wc- 0x140001600 0x140001601", "wc-*"):
        path, line = _decrypted_and_saved(rz, name=f"console{len(command)}.exe", over=[(0x140002003, "90"), (0x140001600, "9090")])
        sid, session = _reopened(rz, path)
        assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(0x140001600, "9090")]
        saved = session._restore_saved
        _console(rz, sid, command)
        assert session._restore_saved is saved, "nothing has read the cache yet"
        answer = rz.read(f"/api/rizin/{sid}/patches")
        assert answer["patches"] == [] and session._restore_saved is None, command
        assert answer["restore"]["refused"] == rizin_sessions._RESTORE_PATCH_TAKEN_BACK and answer["restore"]["actions"] == 0
        assert session.flush() is True
        assert "\nrestore=" not in _project_text(rz.project())
        rz.close(sid)
        sid, session = _reopened(rz, path)
        assert session._restore_saved is None and _restore(rz, sid).status_code == 400
        assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [], "and nothing put the patch back"


def test_a_save_that_reads_the_cache_first_does_not_write_the_record_of_a_patch_the_console_took_back(rz):
    # no GET in between: the project is written from what the mirror says after the read the save makes
    path, line = _decrypted_and_saved(rz, over=[(0x140002003, "90"), (0x140001600, "9090")])
    sid, session = _reopened(rz, path)
    _console(rz, sid, "wc- 0x140001600 0x140001601")
    _mark_dirty(rz, sid)
    assert session.flush() is True
    text = _project_text(rz.project())
    assert "\nrestore=" not in text and "1600" not in _project_patches(rz), "neither the patch nor the way to it"


def test_a_write_that_never_reached_the_cache_is_no_take_back(rz):
    # an entry the mirror gained and the cache never held is not something that left it: the saved timeline, which
    # makes a patch at that very place, stays. (2^64-1 is where rizin writes nothing at all, measured.)
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    _patch(rz, sid, addr="0x140001600", bytes="9090")  # one the cache holds: the mirror is not empty beforehand
    last = 2 ** 64 - 1
    session._restore_saved = dict(session._restore_saved, actions=session._restore_saved["actions"] + [
        {"kind": "patch", "addr": last, "data": "90"}])
    saved = session._restore_saved
    response = rz.post(f"/api/rizin/{sid}/patch", {"addr": f"{last:#x}", "bytes": "90"})
    assert response.status_code == 400 and "rizin wrote nothing" in response.get_json()["refused"]
    rz.read(f"/api/rizin/{sid}/patches")
    assert session._restore_saved is saved and session._restore_gone is None


def test_the_offer_says_why_the_button_is_refused_in_every_shape_a_session_has(rz):
    # ``refused`` is the sentence POST /restore refuses with, whatever the session holds; ``reason`` stays the taint
    import rizin_sessions

    sid = rz.session()
    session = rz.mgr.get(sid)
    assert session._restore_offer() == {"actions": 0, "reason": None, "digests": 0, "refused": _NO_RECORD}
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    offer = session._restore_offer()
    assert offer == {"actions": 1, "reason": None, "digests": 1, "refused": _NO_RECORD}, "its own timeline, none in the project"
    assert _restore(rz, sid).json == {"refused": _NO_RECORD}
    session.unpatch()
    assert session._restore_offer() == {"actions": 0, "reason": rizin_sessions._RESTORE_GONE, "digests": 0,
                                       "refused": rizin_sessions._RESTORE_GONE}
    assert _restore(rz, sid).json == {"refused": rizin_sessions._RESTORE_GONE}
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x5"})
    offer = session._restore_offer()
    assert "register" in offer["reason"] and offer["refused"] == _NO_RECORD, "the taint and the button are two answers"


def test_the_budget_is_counted_from_the_first_command_and_not_from_the_first_action(rz, monkeypatch):
    # what is written before the first action (wc-*, the registers, the patches of the open) is time the replay spends
    # too: a clock that moves while a patch of the open is written has used the budget up before action 1
    import rizin_sessions

    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    now = [0.0]
    monkeypatch.setattr(rizin_sessions, "_replay_clock", lambda: now[0])
    real = session._patch_write

    def slow(pipe, addr, data):
        now[0] += rizin_sessions.RESTORE_BUDGET + 1
        return real(pipe, addr, data)

    monkeypatch.setattr(session, "_patch_write", slow)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and "before action 1 of 3" in answer["reason"] and "the 0 before it" in answer["reason"]


# --- Fix round 3 for the replay ----------------------------------------------------------------------------------

def test_a_restore_whose_record_went_in_the_read_of_its_own_gate_is_refused_and_touches_nothing(rz):
    # Measured by the review: "apply now" on a waiting patch (a patch action of the timeline by construction), then a
    # console wc- of it and of the run: the cache is the open's again, the breakpoints match, and the gate's read is
    # what notices the take-back and drops the record. The press then ran with no record, wiped the open's patch with its
    # wc-* and died on a TypeError the undo does not catch.
    import rizin_sessions

    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    sid, session = _reopened(rz, path)
    assert session._opened == [(UNCOVERED, 2, "9090")]
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    rz.send(f"/api/rizin/{sid}/patch", {"addr": "0x140002003", "waiting": True})
    rz.send(f"/api/rizin/{sid}/emulation/stop")
    _console(rz, sid, "wc- 0x140002000 0x140002010")  # the patch and the run's rows: the cache is the open's again
    saved = session._restore_saved
    assert saved is not None, "nothing has read the cache since the console"
    mark = len(rz.commands())

    response = _restore(rz, sid)
    assert response.status_code == 400 and response.get_json()["refused"] == rizin_sessions._RESTORE_PATCH_TAKEN_BACK
    assert _the_replay(rz, mark) == [], "a refusal sends nothing that changes anything"
    assert [(r["addr"], r["after"], r["mine"]) for r in _patches(rz, sid)] == [(UNCOVERED, "9090", True)], "the open's patch is still there"
    assert session._replaying is False and session._emulation is None and session._restore_saved is None
    _mark_dirty(rz, sid)
    assert session.flush() is True
    assert "140001500:9090" in _project_patches(rz), "and the next save writes it"
    assert "\nrestore=" not in _project_text(rz.project())


def test_taking_back_a_patch_the_timeline_does_not_make_keeps_the_record_while_another_it_does_make_stays(rz):
    # the cache holds a patch the timeline makes (A) and one it does not (B, made before the first start); B is taken back, and
    # A -- which is still there -- is no reason to drop the record. Only what went counts, not what is there
    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")], over=[(0x140002003, "90"), (0x140001600, "9090")])
    sid, session = _reopened(rz, path)
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(UNCOVERED, "9090"), (0x140001600, "9090")]
    saved = session._restore_saved
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": f"{UNCOVERED:#x}"})
    assert [(r["addr"], r["after"]) for r in _patches(rz, sid)] == [(0x140001600, "9090")]
    assert session._restore_saved is saved and session._restore_gone is None
    rz.remove(f"/api/rizin/{sid}/patch", {"addr": "0x140001600"})
    assert session._restore_saved is None, "and A going is"


def test_a_restart_that_could_not_read_the_cache_claims_nothing_and_drops_nothing(rz, monkeypatch):
    # _replay_patches' failure branch: the writes went, the read of what rizin holds did not. The mirror is emptied (a patch
    # nobody has seen in the cache is not the session's own, and a save would write it), and the project's record is not
    # touched by it
    import rizin_sessions

    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    saved = session._restore_saved
    real = session._patch_list
    monkeypatch.setattr(session, "_patch_list", lambda pipe, ordered=False: (_ for _ in ()).throw(ValueError("wcj")))
    note = session._replay_patches([(0x140001600, "9090", False)])
    assert "could not be applied" in note and session._mine == [] and session._mine_over == []
    monkeypatch.setattr(session, "_patch_list", real)
    rows = _patches(rz, sid)
    assert [(r["addr"], r["after"], r["mine"]) for r in rows] == [(0x140001600, "9090", False)], "written, and nobody's own"
    assert session._restore_saved is saved and session._restore_gone is None


def test_an_offer_does_not_state_a_count_over_a_row_that_holds_fewer_bytes_than_it_says(rz, monkeypatch):
    # parse_cache checks types and not sizes; the save skips such a timeline and the replay refuses it, and the count of
    # ranges that the offer would state for it is refused with the same sentence
    import rizin_emulation
    import rizin_sessions

    sid = rz.session()
    session = rz.mgr.get(sid)
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    real = rizin_emulation.parse_cache
    monkeypatch.setattr(rizin_emulation, "parse_cache", lambda text: [dict(row, size=8) for row in real(text)])
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert answer["restore"] == {"actions": 1, "reason": rizin_sessions._RESTORE_CACHE_UNREAD, "digests": 0, "refused": _NO_RECORD}


def test_the_offer_of_a_session_with_a_record_is_not_made_without_rizin(rz):
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    with pytest.raises(AssertionError):
        session._restore_offered(None, None)


# --- The branch fix wave ------------------------------------------------------------------------------------------

def test_a_timeline_that_is_not_kept_is_said_by_the_status_band_and_not_only_by_the_dock(rz, monkeypatch):
    # Spec 4 and Nachtrag 4: the Hinweisbox says why, as soon as it is true. The commonest spoiler is a decryption that
    # outlives esil.timeout; the analyst who reads the decrypted code and NOPs the check from the menu never opens the dock
    import rizin_sessions

    path, line = _decrypted_and_saved(rz, before=[(UNCOVERED, "9090")])
    monkeypatch.setenv("FAKE_RIZIN_ESIL_RUNAWAY", "1")
    sid, session = _reopened(rz, path)
    before = rz.status(sid)["analysis"]["note"]
    assert "The way to this state" not in before and "Held back" in before
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    assert "The way to this state" not in (rz.status(sid)["analysis"]["note"] or ""), "nothing is spoiled yet"
    assert _run(rz, sid, "cont")["stopped"] == "timeout"
    note = rz.status(sid)["analysis"]["note"]
    words = f"The way to this state is not kept in the project: {rizin_sessions._RESTORE_TIMEOUT}."
    assert words in note, note
    assert note.index("Held back") < note.index(words), "after the notes about the patches, which are the user's work"
    assert note.endswith(rizin_sessions._RESTORE_NOTICE_EARLIER), "and the project still holds the record it was opened with"
    assert note.count("The way to this state") == 1


def test_the_note_of_a_timeline_that_is_not_kept_is_said_while_it_is_true_and_has_no_second_sentence_without_a_record(rz):
    # computed, not stored: a breakpoint put back takes it away (spec 4's standing change), and with no record in the project
    # there is no earlier timeline to say anything of
    import rizin_sessions

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    rz.send(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    note = rz.status(sid)["analysis"]["note"]
    assert note == f"The way to this state is not kept in the project: {rizin_sessions._RESTORE_HAND_BREAKPOINT}.", note
    rz.remove(f"/api/rizin/{sid}/breakpoints", {"addr": "0x1400014b7"})
    assert "The way to this state" not in (rz.status(sid)["analysis"]["note"] or "")
    _hand_set_a_register(rz, sid)
    assert rizin_sessions._RESTORE_HAND_REGISTER in rz.status(sid)["analysis"]["note"]


def test_a_timeline_that_is_gone_is_said_by_the_status_band_too(rz):
    import rizin_sessions

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    _console(rz, sid, "wc-*")
    assert f"is not kept in the project: {rizin_sessions._RESTORE_GONE}." in rz.status(sid)["analysis"]["note"]


@pytest.mark.parametrize("command", ["wc- 0x1000 0x1001", "wc-*", "wc- 0x1000", "wc-"])
def test_a_console_take_back_is_a_take_back_and_not_a_write(command):
    import rizin_sessions

    assert rizin_sessions._console_spoils(command) == rizin_sessions._RESTORE_GONE
    assert rizin_sessions._console_spoils("wx 90 @ 0x1000") == rizin_sessions._RESTORE_HAND_WRITE
    assert rizin_sessions._console_spoils("wc") is None and rizin_sessions._console_spoils("wcj") is None


def test_a_console_take_back_taints_a_live_timeline_with_the_take_back_reason(rz):
    import rizin_sessions

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x140001440"})
    _wrote(rz, sid)
    _console(rz, sid, "wc- 0x140001440 0x140001441")
    assert _state(rz, sid)["tainted"] == rizin_sessions._RESTORE_GONE


def test_the_replay_hashes_overlapping_writes_in_write_order_and_the_address_ordered_proof_is_another_one(rz):
    # R-T2a where the digest decides whether the patch is applied. The run writes a byte and then four bytes over it (the shape
    # `wx ee @ 0x1101`, `wx aabbccdd @ 0x1100` has): the proof by address is a plausible SHA-256 of bytes the run never left,
    # and run_digests cannot tell, so the test has to
    import rizin_emulation

    path, line = _decrypted_and_saved(rz, over=[], stub=(ORDER_AT, ORDER_END))
    saved = _the_saved_record(rz)["digests"]
    sid, session = _reopened(rz, path)
    assert rz.ok(_restore(rz, sid))["restored"] is True
    rows = session.patches_made()
    by_write = rizin_emulation.run_digests(rows, rizin_emulation.run_only_ranges(rows))
    by_address = rizin_emulation.run_digests(sorted(rows, key=lambda row: row["addr"]), rizin_emulation.run_only_ranges(rows))
    assert by_write == saved, "the replay left what the save proved"
    assert by_address != saved and by_address[0]["sha256"] == hashlib.sha256(bytes.fromhex("41414141")).hexdigest()


def test_the_offer_of_a_live_timeline_counts_with_one_pass_and_neither_makes_the_ranges_nor_hashes(rz, monkeypatch):
    # the route's cost: the offer is asked on every read of GET /patches (after every run, start, stop and edit), with the gate
    # held. It does not make run_only_ranges and digest_ranges any more (five passes over the rows): one count
    import rizin_emulation

    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": f"{DECRYPT_AT:#x}"})
    _run(rz, sid, "until", addr=f"{DECRYPT_END:#x}")
    rz.mgr.get(sid).flush()
    for name in ("run_only_ranges", "digest_ranges", "run_digests"):
        monkeypatch.setattr(rizin_emulation, name, lambda *args, _name=name, **kwargs: pytest.fail(f"the offer made {_name}"))
    answer = rz.read(f"/api/rizin/{sid}/patches")
    assert answer["restore"]["digests"] == 1 and answer["restore"]["actions"] == 2


def test_the_offer_with_nothing_the_run_wrote_says_so_and_nothing_is_the_fallback_of_a_clean_timeline(rz):
    # reachable: a start, then a step over an instruction that writes no memory; the documented guarantee of GET /patches
    import rizin_sessions

    sid = _started(rz)
    _run(rz, sid, "step")
    answer = rz.read(f"/api/rizin/{sid}/patches")["restore"]
    assert answer["digests"] == 0 and answer["reason"] == rizin_sessions._RESTORE_NOTHING, answer
    assert "The way to this state" not in (rz.status(sid)["analysis"]["note"] or ""), "it needs the cache to know: the pane's block says it"


def test_a_replay_says_how_many_actions_of_the_record_it_ran_and_not_how_many_the_timeline_has_now(rz):
    # the block's `actions` is the timeline the session holds afterwards: the patch written after the proof is one more
    path, line = _decrypted_and_saved(rz)
    sid, session = _reopened(rz, path)
    session._waiting.append((0x140002005, "cc", True))
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is True and answer["replayed"] == 3
    assert answer["patches"]["restore"]["actions"] == 4, "which is why the count is not read from there"


def test_a_replay_that_did_not_hold_ran_no_action_of_the_record(rz, monkeypatch):
    path, line = _decrypted_and_saved(rz)
    monkeypatch.setenv("FAKE_RIZIN_XOR_KEY", "0x42")
    sid, session = _reopened(rz, path)
    answer = rz.ok(_restore(rz, sid))
    assert answer["restored"] is False and answer["replayed"] == 0


def test_a_project_with_no_room_for_the_marker_after_the_patches_still_says_the_record_was_lost(rz, monkeypatch):
    # measured by the review: 32 767 characters of patches left 1 of the 7 the marker needs, the marker was suppressed and
    # left_out was 0, so the next open said nothing of a record that was gone. The marker is written whatever is left
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    record = rizin_sessions.rizin_emulation.read_restore(line)
    src = rz.tmp / "src.rzdb"
    src.write_text("/\ntype=rizin\n", encoding="utf-8")
    dst = rz.tmp / "dst.rzdb"
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", 1000)
    patches = [(0x1000 + i, "90", False) for i in range(125)]
    line_of_patches, left = rizin_sessions._patches_line(patches)
    assert 1000 - len(line_of_patches) < len(rizin_sessions._RESTORE_DROPPED_MARK) and left == 0, \
        "a patches line that leaves fewer characters than the marker's own length, and cuts nothing"
    left_out, fitted, alone = rizin_sessions._sanitize_project(str(src), str(dst), "aaa", "one", ["aaa"], patches, (), record)
    text = dst.read_text(encoding="utf-8")
    assert (left_out, fitted) == (0, False)
    assert text.endswith("\nrestore=dropped\n") and "\npatches=" + line_of_patches + "\n" in text, text[-40:]
    meta = rizin_sessions._read_project_meta(str(dst))
    assert meta["restore_dropped"] is True and len(meta["patches"]) == 125, "the next open says it, and has every patch"


# --- The last fix ---------------------------------------------------------------------------------------------------

def test_the_band_does_not_say_the_project_holds_a_timeline_that_a_save_could_not_keep(rz, monkeypatch):
    # _restore_saved is set when a save is asked, not when it is written: after a record that did not fit it is the record the
    # session would keep, and the project holds the marker. The note says the way is not kept; it must not also say the button
    # replays an earlier timeline the project holds -- the first sentence is true and the second is not
    import rizin_sessions

    path, sid, line = _saved_with_a_record(rz)
    session = rz.mgr.get(sid)
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", len("140001441:90:r") + len(line) - 1)
    _mark_dirty(rz, sid)
    assert session.flush() is True
    assert _restore_value(rz.project()) == _marker() and session._restore_saved is not None
    _hand_set_a_register(rz, sid)
    note = rz.status(sid)["analysis"]["note"]
    assert "will not be there when the file is opened again" in note, note
    assert f"The way to this state is not kept in the project: {rizin_sessions._RESTORE_HAND_REGISTER}." in note, note
    assert rizin_sessions._RESTORE_NOTICE_EARLIER not in note, note
    # and where the project does hold the record, the sentence is true and is said (the earlier tests)
    monkeypatch.setattr(rizin_sessions, "PROJECT_PATCH_CHARS", 32 * 1024)
    session._restore = None
    session._restore_gone = rizin_sessions._RESTORE_GONE
    _mark_dirty(rz, sid)
    assert session.flush() is True
    assert session._restore_dropped_note is None and _restore_value(rz.project()).startswith("1;")
    assert rizin_sessions._RESTORE_NOTICE_EARLIER in rz.status(sid)["analysis"]["note"]


def test_the_band_and_the_pane_end_a_reason_with_the_same_pattern():
    # the band and the pane's own notice must be the same words, or the pane says it twice: one pattern, in both, and what it does
    import re
    import rizin_sessions

    with open(os.path.join(ROOT, "webui", "static", "js", "app.js"), encoding="utf-8") as fh:
        assert r"offer.reason.replace(/[.\s]+$/, '')" in fh.read()
    for text, words in (("a reason.", "a reason"), ("a reason. ", "a reason"), ("a reason...\n", "a reason"), ("a reason", "a reason"),
                        ("a. b.", "a. b"), ("", "")):
        assert rizin_sessions._reason_words(text) == words, repr(text)
    for reason in [v for k, v in vars(rizin_sessions).items() if k.startswith("_RESTORE_") and isinstance(v, str)]:
        assert rizin_sessions._reason_words(reason) == re.sub(r"[.\s]+$", "", reason)
