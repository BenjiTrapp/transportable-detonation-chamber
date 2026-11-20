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
    assert saved.rstrip().endswith("mode=one\ndone=aaa")

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

    @staticmethod
    def ok(response):
        assert response.status_code == 200, (response.status_code, response.get_json())
        return response.get_json()

    def read(self, url):
        return self.ok(self.get(url))

    def send(self, url, body=None):
        return self.ok(self.post(url, body))

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
    assert state["running"] is True and state["pc"] == 0x140001440
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
    assert commands[start + 1:start + 5] == ["e io.cache", "aei", "aeim", "aepc 0x140001440"]


def test_emulation_start_defaults_to_the_current_seek(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/seek", {"addr": "0x1400014b7"})
    assert rz.send(f"/api/rizin/{sid}/emulation/start", {})["pc"] == 0x1400014B7


def test_emulation_state_reads_the_stack_with_hints(rz, monkeypatch):
    import rizin_sessions

    monkeypatch.setenv("FAKE_RIZIN_STACK", "0x140001490")  # the address of sym.watchdog
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    state = rz.read(f"/api/rizin/{sid}/emulation")
    stack = state["stack"]
    assert len(stack) == rizin_sessions.RIZIN_STACK_ROWS
    assert stack[0]["value"] == 0x140001490 and stack[0]["hint"] == "sym.watchdog"
    assert stack[1]["hint"] is None
    sp = next(r["value"] for r in state["registers"] if r["name"] == "rsp")
    assert [row["addr"] for row in stack] == [sp + 8 * i for i in range(rizin_sessions.RIZIN_STACK_ROWS)]


def test_emulation_reads_a_32_bit_stack_in_4_byte_words(rz, monkeypatch):
    monkeypatch.setenv("FAKE_RIZIN_BITS", "32")
    monkeypatch.setenv("FAKE_RIZIN_STACK", "0x41424344,0x41")
    sid = rz.session()
    state = rz.send(f"/api/rizin/{sid}/emulation/start", {"addr": "0x401000"})
    assert state["bits"] == 32 and state["pc"] == 0x401000
    assert {r["name"] for r in state["registers"]} >= {"eax", "eip", "esp"}
    sp = next(r["value"] for r in state["registers"] if r["name"] == "esp")
    assert [(row["addr"], row["value"]) for row in state["stack"][:3]] == [(sp, 0x41424344), (sp + 4, 0x41),
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
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    assert rz.send(f"/api/rizin/{sid}/emulation/stop") == {"running": False}
    assert rz.commands()[-1] == "aeim-"
    r = rz.get(f"/api/rizin/{sid}/emulation")
    assert r.status_code == 400 and "not started" in r.get_json()["refused"]
    assert rz.send(f"/api/rizin/{sid}/emulation/stop") == {"running": False}  # stopping twice is no error
    # A new start begins afresh: nothing counts as changed against the run before
    assert rz.send(f"/api/rizin/{sid}/emulation/start", {})["changed"] == []


def test_a_register_can_be_set_and_only_a_known_one(rz):
    sid = rz.session()
    rz.send(f"/api/rizin/{sid}/emulation/start", {})
    state = rz.send(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "0x41"})
    assert next(r["value"] for r in state["registers"] if r["name"] == "rax") == 0x41
    assert any(c.startswith("ar rax=0x41") for c in rz.commands())
    assert state["changed"] == ["rax"]
    for name in ("rax; wci", "nope", "rax rbx", "", None, 7):
        r = rz.post(f"/api/rizin/{sid}/emulation/register", {"name": name, "value": "0x1"})
        assert r.status_code == 400 and "register" in r.get_json()["refused"], name
    assert not any(c.startswith(("ar rax;", "ar nope", "ar rax rbx", "ar =")) for c in rz.commands())
    r = rz.post(f"/api/rizin/{sid}/emulation/register", {"name": "rax", "value": "-1"})
    assert r.status_code == 400 and "value" in r.get_json()["refused"]


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
