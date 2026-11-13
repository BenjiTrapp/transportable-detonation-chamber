"""Rizin sessions for the RIZIN tab.

One opened file runs one ``rizin -q0`` process (rizin 0.9.1 from Cutter's
package). The web UI runs as SYSTEM without a login, so the file and the
console input are treated as hostile.

RizinPipe speaks rizin's pipe protocol: one NUL after start-up and one after
every answer. Two threads drain stdout and stderr, so every command has a
time limit; a command that runs over it gets rizin killed (RizinTimeout). An
answer to a view that is larger than VIEW_ANSWER_MAX is read to its end but
not kept (RizinTooLarge). On Windows every rizin runs in a job object that
ends it when the web UI's process ends, also when that is killed (_Job).

check_console_command is the console filter. Fail-closed: a command has to
start with one of the allowed families, and inside them every sub-command or
modifier is refused that runs a program, runs stored or nested commands,
reads or writes files, changes settings outside asm.*/analysis.*, waits for
input or opens an interactive view. The lists come from rizin 0.9.1's own
help (``?*``, ``@?``, ``@@?``, ``~?``) and its command sources. Nothing in the
console assembles, and the arch settings only take built-in disassemblers:
some assembler plugins hand their work to nasm or as.

RizinSessions keeps at most ``max_sessions`` sessions, one file per browser
tab. A file (by SHA-256) has one session at most: opening it in another tab
moves the session there, and opening it while its session still closes waits
for that session's last save, so two sessions never write the same project.
Of the OPENs of one tab the newest wins: an older one that ends later closes
its own session (SessionSuperseded). The injected ``clock`` drives idle time
and eviction; analysis times are real seconds, like the pipe's time limits.

The analysis: a file up to ``big_file`` runs ``aaa`` as one step, so the
result is exactly rizin's; a larger file runs ``aa``. Full analysis
(analyze_full) runs aaa's sub-steps one by one (see aaa_steps). Between two
of them the session holds off for ``step_gap`` seconds, and then as long as
requests use or wait for the pipe, ``step_gap_limit`` seconds after the step
at most: the tab stays usable between the steps. While an analysis runs,
renames and comments are refused (RizinBusy): a later step could change them.

Projects (``projects_dir/<sha256>.rzdb``) are written after a rename or a
comment only, ``save_delay`` seconds after the last one, and at the latest
when the session closes. They are loaded with ``Poo``, which keeps the file
rizin has open, so the same file under another path finds its project too.
``Poo`` also brings back the saved settings and hints; those that could run
a program or a command are set back afterwards (_make_safe). A project saved
while a Full analysis had not finished opens stopped: the button goes on.
"""

import base64
import collections
import ctypes
import hashlib
import json
import os
import queue
import re
import secrets
import subprocess
import tempfile
import threading
import time

RIZIN_EXE = os.environ.get("TDC_RIZIN", r"C:\tools\cutter\rizin.exe")
PROJECTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rizin_projects")
BIG_FILE = 20 * 1024 * 1024
START_TIMEOUT = 120.0
VIEW_TIMEOUT = 30.0
CONSOLE_TIMEOUT = 60.0
# rz-ghidra's pdgj (the DECOMPILER): under x64 emulation a big function takes long
DECOMPILE_TIMEOUT = 120.0
PROJECT_TIMEOUT = 300.0
STEP_GRACE = 120.0
# Full analysis: after a step, the next one waits STEP_GAP seconds, in which requests get the pipe, and
# then as long as requests use or wait for it, STEP_GAP_LIMIT seconds after the step at most.
STEP_GAP = 2.0
STEP_GAP_LIMIT = 10.0
SAVE_DELAY = 3.0
CONSOLE_LIMIT = 1024 * 1024
# The largest answer to a view that is kept: rizin's lists of a big dump (izj, flj) run to hundreds of MB
VIEW_ANSWER_MAX = 32 * 1024 * 1024
MAX_CONSOLE_COMMAND = 2000
MAX_COMMENT = 500
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.@$:-]{0,127}$")
_STDERR_KEEP = 256 * 1024
_MAX_MOVED = 256
_CREATE_NO_WINDOW = 0x08000000
_PROJECT_FAILED = "The saved project could not be loaded; it was kept as .rzdb.broken."
_FULL_NOTE = "Full analysis runs aaa's steps one by one; variables are analysed less than with aaa."
# How long close() waits for the pipe to write a pending save: longer than the longest command.
_FLUSH_WAIT = max(CONSOLE_TIMEOUT, DECOMPILE_TIMEOUT) + 5
# How long a request that closes a session waits; a save that needs longer goes on in the background.
_CLOSE_WAIT = 2.0
# Set at start-up. asm.debuginfo.file would make the disassembly read the source files that a sample's
# debug info names; with an empty cfg.editor no command can start an editor.
_START_SETTINGS = ("asm.debuginfo.file=false", "cfg.editor=")
# The hooks of rizin 0.9.1 (cmd.* in librz/core/cconfig.c) that run rizin commands on events.
_COMMAND_HOOKS = ("cmd.times", "cmd.bp", "cmd.onsyscall", "cmd.stack", "cmd.cprompt", "cmd.gprompt", "cmd.hit",
                  "cmd.open", "cmd.load", "cmd.prompt", "cmd.fcn.new", "cmd.fcn.delete", "cmd.fcn.rename",
                  "cmd.visual", "cmd.vprompt", "cmd.esil.step", "cmd.esil.stepout", "cmd.esil.mdev",
                  "cmd.esil.intr", "cmd.esil.trap", "cmd.esil.todo", "cmd.esil.ioer", "cmd.hexcursor")
# Set again after Poo, which restores every saved setting apart from a few scr.* and dir.* keys.
_LOAD_SETTINGS = ("scr.color=0", "scr.pager=", "scr.interactive=false", "asm.assembler=", *_START_SETTINGS,
                  *(hook + "=" for hook in _COMMAND_HOOKS))


class RizinTimeout(Exception):
    """rizin did not answer in time and was killed."""


class RizinTooLarge(Exception):
    """rizin's answer was larger than the limit of the command; it was read to its end, not kept."""


class RizinDied(Exception):
    """rizin is not running (any more)."""


class RizinBusy(Exception):
    """The session's pipe is held by an analysis step (or another request)."""

    def __init__(self, step):
        super().__init__(f"busy: {step}")
        self.step = step


class RizinRefused(Exception):
    """A console command or an input that is not allowed."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class SessionMoved(Exception):
    """The session moved to another browser tab."""


class SessionEnded(Exception):
    """The session is closed, timed out or unknown."""


class SessionSuperseded(SessionEnded):
    """A newer OPEN of the same browser tab came first; this OPEN's session was closed."""


# --- Console filter ---------------------------------------------------------

_FAMILIES = "apifCs/?xtbe"
# rizin-shell-parser's command-name scanner (is_mid_command), ASCII part. It
# drops a backslash and joins the next character ("a\gw" is "agw").
_NAME_RE = re.compile(r"[A-Za-z/?][A-Za-z0-9$?.+=/*&_%-]*")
_NAME_REGION_RE = re.compile(r"[^\s@~\"'(),`|>#:;]*")
_FORBIDDEN_CHARS = (
    ("!", "no shell commands"),
    ("|", "no pipes"),
    (">", "no redirection"),
    ("<", "no input redirection"),
    ("`", "no command substitution"),
)
_SHELL = "shell commands are not allowed"
_ASSEMBLE = "assembling is not available: rizin can hand it to an external assembler"
# Refused inside the allowed families, matched at the start of the command name.
_REFUSED = [(re.compile(pattern), reason) for pattern, reason in (
    (r"aa", "whole-program analysis runs from the Full analysis button"),
    (r"agw", "'agw' writes files"),
    (r"agl", "'agl' reads the source files that the debug info names"),
    (r"aep", "'aep' commands are not allowed"),
    (r"ael", "'ael' loads ESIL interrupt plugins from files"),
    (r"aek", "'aek' runs SDB queries"),
    (r"afco", "'afco' opens a file"),
    (r"arp[og]", "'arpo' and 'arpg' load files"),
    (r"ascii", _SHELL),
    (r"p=.*v$", "visual histograms are interactive"),
    (r"pa(?!de?$)", _ASSEMBLE),  # pa and pae assemble; pad and pade disassemble
    (r"pfo", "'pfo' loads a file"),
    (r"pfw", "'pfw' writes data"),
    (r"pm", "'pm' reads magic files"),
    (r"pxa", "'pxa' runs the stored formats (Cf) as commands"),
    (r"pkill|pwd", _SHELL),
    (r"idp", "'idp' commands load, download or extract PDB files"),
    (r"ik", "'ik' runs SDB queries"),
    (r"iO", "'iO' writes files"),
    (r"inittime", _SHELL),
    (r"flush|fortune", _SHELL),
    (r"CCe|Cve", "editing a comment opens an editor"),
    (r"sil", "'sil' (silhouette) talks to a server"),
    (r"sleep|sort|shell", _SHELL),
    (r"/F", "'/F' reads a file"),
    (r"/a(?![1Iacdefilmost])", _ASSEMBLE),  # /a, /aj, /aq; the other /a... search the disassembly
    (r"/m(?!b)", "'/m' reads magic files"),
    (r"\?\*\*", "interactive help search is not available"),
    (r"\?i", "'?i' waits for input"),
    (r"to", "'to' commands open files or an editor"),
    (r"tp[vx]", "'tpv' and 'tpx' run a type's format as a command"),
    (r"time", _SHELL),
    (r"bm", "'bm' changes the block size limit"),
)]
_EVAL_NAMES = {"e", "el", "elj", "elq", "ell", "elJ", "es", "et"}
_EVAL_REFUSED = [(re.compile(pattern), reason) for pattern, reason in (
    (r"ee", "'ee' opens an editor"),
    (r"e-", "'e-' resets the configuration"),
    (r"er", "'er' locks settings"),
    (r"echo|env|exit", _SHELL),
    (r"ec", "colour themes (ec) are not available"),
)]
# rizin 0.9.1 names the analysis settings analysis.*; anal.* is their older name.
_EVAL_SET_PREFIXES = ("asm.", "analysis.", "anal.")
_EVAL_SET_KEYS = {"bin.demangle"}
_EVAL_SET_REFUSED = {
    # With it, the disassembly reads the source files that a sample's debug info names.
    "asm.debuginfo.file": "it reads source files",
    "asm.assembler": "an assembler can run an external program",
}
_EVAL_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+")
# Names and numbers; no path separators, so arch, cpu or os cannot point into other folders.
_EVAL_VALUE_RE = re.compile(r"[A-Za-z0-9_.,+-]*|\?\??")
# The settings that pick the arch plugin (analysis.arch sets asm.arch too) and the arch hint (aha) take
# one of these: rizin 0.9.1's arch plugins that disassemble (librz/arch with every build option; `La`
# lists a build's own) and rz-ghidra's ghidra. Left out are x86.nasm, x86.as, arm.as and ppc.as, which
# hand assembling to nasm or as, and x86.nz, which only assembles.
_ARCH_KEYS = ("asm.arch", "analysis.arch", "anal.arch")
_SAFE_ARCHES = frozenset((
    "6502", "8051", "alpha", "amd29k", "arc", "arm", "avr", "bf", "c166", "cbpf", "chip8", "cil", "cr16", "cris",
    "dalvik", "dcpu16", "ebc", "gb", "ghidra", "h8300", "h8500", "hexagon", "hppa", "i4004", "i8080", "java",
    "lanai", "lh5801", "lm32", "loongarch", "luac", "m680x", "m68k", "malbolge", "mcore", "mcs96", "milstd1750",
    "mips", "msp430", "null", "or1k", "pic", "ppc", "propeller", "pyc", "riscv", "rl78", "rsp", "rx", "sh", "snes",
    "sparc", "spc700", "sysz", "tms320", "tricore", "v810", "v850", "vax", "wasm", "x86", "xap", "xcore", "xtensa",
    "z80"))
# The '@' forms of `@?` and `@@?` that only seek, iterate or replace the block
# in memory (@! for the block size has a '!'). Everything else is refused,
# among them @e: (settings), @a: and @b: (arch and bits), @f:
# (file), @k: (SDB), @o: (another fd), @@. (file), @@/ (nested search),
# @@c: and @@@c: (nested commands) and the debugger forms @@dbt*, @@t, @@dm,
# @@r and @@om.
_AT_ALLOWED = re.compile(r"@(?:@@=|@(?:=|C|b|i|f|F|s:)| |\(|B:|F:|i:|r:|s:|v:|x:)")
_AT_FORM_RE = re.compile(r"@+[^\s@]{0,3}")
_LINE_RANGE_RE = re.compile(r"[^.~{]*:-?\d*\.\.-?\d*")


def _show(text, size=40):
    """A fragment of the input for a refusal reason: printable ASCII, short."""
    return ascii(text[:size])[1:-1]


def check_console_command(text):
    """Return None if the console may run ``text``, otherwise a one-line reason."""
    if not isinstance(text, str):
        return "the command must be text"
    if len(text) > MAX_CONSOLE_COMMAND:
        return f"the command is longer than {MAX_CONSOLE_COMMAND} characters"
    if "\n" in text or "\r" in text:
        return "the command must be a single line"
    if "\0" in text:
        return "NUL characters are not allowed"
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        return "control characters are not allowed"
    for char, why in _FORBIDDEN_CHARS:
        if char in text:
            return f"'{char}' is not allowed: {why}"
    if "$(" in text:
        return "'$(' is not allowed: no command substitution"
    if "#!" in text:
        return "'#!' is not allowed: no interpreters"
    for statement in text.split(";"):
        reason = _check_statement(statement.strip(" "))
        if reason:
            return reason
    return None


def _check_statement(stmt):
    if not stmt:
        return None
    if stmt[0] not in _FAMILIES:
        return f"'{_show(stmt[0])}' commands are not allowed"
    # rizin joins quoted pieces into one argument, so a"gw" can reach it as agw (for one, inside a
    # format that Cf stores and pxa runs). The name is therefore read with the quotes removed.
    bare = stmt.replace('"', "").replace("'", "")
    quoted = bare != stmt
    if "\\" in _NAME_REGION_RE.match(bare).group():
        return "backslashes are not allowed in command names"
    name = _NAME_RE.match(bare).group()
    if len(name) > 32:
        return "unknown command"
    is_help = name.endswith("?")
    if not is_help:
        reason = _check_name(name)
        if reason:
            return reason
    if "\\" in stmt:
        return "backslash escapes are not allowed"
    reason = _check_at(stmt) or _check_grep(stmt) or _check_grep(bare)
    if reason:
        return reason
    if "$k{" in bare:
        return "SDB queries ($k{...}) are not allowed"
    if is_help:
        return None
    args = re.split(r"[@~]", bare[len(name):], maxsplit=1)[0]
    if name[0] == "e":
        return "quotes are not allowed in 'e' commands" if quoted else _check_eval(name, args)
    if name.startswith("aha") and name != "aha-":
        if quoted:
            return "quotes are not allowed in 'aha'"
        arch = args.split()[:1]
        if arch and arch[0] not in _SAFE_ARCHES and arch[0] != "0":
            return f"'{_show(arch[0])}' is not allowed as an arch hint: only rizin's built-in disassemblers"
    if name.startswith("ag"):
        if set(args.split()) & {"interactive", "v"}:
            return "interactive graphs are not available"
    return None


def _check_name(name):
    for pattern, reason in _REFUSED:
        if pattern.match(name):
            return reason
    if name[0] == "e" and name not in _EVAL_NAMES:
        for pattern, reason in _EVAL_REFUSED:
            if pattern.match(name):
                return reason
        return f"'{_show(name)}' is not allowed"
    return None


def _check_at(stmt):
    i = stmt.find("@")
    while i != -1:
        m = _AT_ALLOWED.match(stmt, i)
        if not m:
            return f"'{_show(_AT_FORM_RE.match(stmt, i).group())}' is not allowed"
        i = stmt.find("@", m.end())
    return None


def _check_grep(stmt):
    i = stmt.find("~")
    if i == -1:
        return None
    spec = stmt[i + 1:].strip()
    if ".." in spec and (_grep_pages(spec) or not _LINE_RANGE_RE.fullmatch(spec)):
        return "interactive grep views (~.. and ~...) are not available"
    return None


def _grep_pages(spec):
    """Whether rizin's grep opens its less or hud: the modifier loop of parse_grep_expression."""
    first = True
    while spec:
        c = spec[0]
        if c == ".":
            if spec.startswith(".."):
                return True
            spec = spec[1:]
        elif c == "{":
            if spec.startswith(("{:..", "{}..")):
                return True
            if spec[1:2] not in (":", "}"):
                return False  # a JSON path
            spec = spec[1:]
        elif c == "$":
            spec = spec[1:]
            spec = spec[1:] if spec.startswith("!") else spec
            spec = spec.lstrip("0123456789")
            spec = spec[2:] if spec.startswith(":") else spec
        elif c == "?":
            spec = spec[1:]
            if spec.startswith("?"):
                return False
            spec = spec[1:] if spec.startswith(".") else spec
        elif c in "&<^!" or (c == "+" and first):
            spec = spec[1:]
        else:
            return False
        first = False
    return False


def _check_eval(name, args):
    for token in args.split():
        if "=" not in token:
            if not _EVAL_KEY_RE.fullmatch(token):
                return f"'{_show(token)}' is not a setting"
            continue
        if name != "e":
            return f"'{_show(name)}' cannot set values"
        key, _, value = token.partition("=")
        if key not in _EVAL_SET_KEYS and not key.startswith(_EVAL_SET_PREFIXES):
            return f"only asm.*, analysis.* and bin.demangle can be set, not '{_show(key)}'"
        if key in _EVAL_SET_REFUSED:
            return f"'{key}' cannot be set: {_EVAL_SET_REFUSED[key]}"
        if not _EVAL_VALUE_RE.fullmatch(value) or ".." in value:
            return f"'{_show(value)}' is not allowed as a value"
        if key in _ARCH_KEYS and value not in _SAFE_ARCHES and value not in ("?", "??"):
            return f"'{_show(value)}' is not allowed for {key}: only rizin's built-in disassemblers"
    return None


_ANNOTATION_RE = re.compile(r"(?:afn|an|afvn|fr|CC|CC\+|CCu|Cv)$")
_REMOVAL_RE = re.compile(r"(?:CC-\*?|CCf-\*?|Cv-)$")


def _annotates(text):
    """Whether a console command renames or comments, after which the project is saved."""
    for statement in text.split(";"):
        statement = statement.strip(" ")
        m = _NAME_RE.match(statement)
        if not m:
            continue
        args = re.split(r"[@~]", statement[m.end():], maxsplit=1)[0].strip()
        if (_ANNOTATION_RE.match(m.group()) and args) or _REMOVAL_RE.match(m.group()):
            return True
    return False


def _temporary_seek(text):
    """The target of the last statement's ``@ <addr>``; the views (and rizin) go there."""
    found = re.findall(r"(?<!@)@ +([^@~]+)", text.split(";")[-1])
    return found[-1].strip() if found else None


# --- Pipe -------------------------------------------------------------------


def rizin_environment(exe):
    """The environment for starting `exe`: None (inherit), or one with SLEIGHHOME added.

    rz-ghidra finds its sleigh specs through SLEIGHHOME; the folder compiled into the Cutter package's
    core_ghidra.dll is the one it was built in. install-rizin.ps1 sets SLEIGHHOME machine-wide, but a
    process has it only if its parent picked it up (a scheduled task or service may run with an older
    environment), so a missing one is derived from the package layout next to rizin.exe.
    """
    if os.environ.get("SLEIGHHOME"):
        return None
    sleigh = os.path.join(os.path.dirname(os.path.abspath(exe)), "lib", "rizin", "plugins", "rz_ghidra_sleigh")
    if not os.path.isdir(sleigh):
        return None
    return dict(os.environ, SLEIGHHOME=sleigh)


class _JobBasicLimits(ctypes.Structure):
    """JOBOBJECT_BASIC_LIMIT_INFORMATION"""

    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32), ("SchedulingClass", ctypes.c_uint32)]


class _JobLimits(ctypes.Structure):
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION"""

    _fields_ = [("BasicLimitInformation", _JobBasicLimits), ("IoInfo", ctypes.c_uint64 * 6),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _Job:
    """A Windows job object that holds one rizin and ends it once the job's last handle closes.

    The web UI holds the only handle, so rizin ends with the web UI's process, also when that is
    killed: deploy-utm.py and install-webui.ps1 force-kill python, atexit does not run then, and
    Windows keeps child processes (a hung analysis step would run on for ever). The web UI's own task
    may run in a job already; jobs nest on Windows 8 and later.
    """

    _KILL_ON_JOB_CLOSE = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    _EXTENDED_LIMITS = 9  # JobObjectExtendedLimitInformation

    def __init__(self, proc, kernel32):
        self._kernel32 = kernel32
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(f"CreateJobObjectW failed ({_last_error()})")
        try:
            limits = _JobLimits()
            limits.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(ctypes.c_void_p(self.handle), self._EXTENDED_LIMITS,
                                                    ctypes.byref(limits), ctypes.sizeof(limits)):
                raise OSError(f"SetInformationJobObject failed ({_last_error()})")
            if not kernel32.AssignProcessToJobObject(ctypes.c_void_p(self.handle), ctypes.c_void_p(int(proc._handle))):
                raise OSError(f"AssignProcessToJobObject failed ({_last_error()})")
        except BaseException:
            self.close()
            raise

    def close(self):
        handle, self.handle = self.handle, None
        if handle:
            self._kernel32.CloseHandle(ctypes.c_void_p(handle))


def _last_error():
    return f"error {ctypes.get_last_error()}" if hasattr(ctypes, "get_last_error") else "no error code"


def _job_for(proc):
    """On Windows the _Job that ends ``proc`` with the web UI; None elsewhere, or if it cannot be made
    (logged: rizin then runs as before)."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        return _Job(proc, kernel32)
    except Exception as exc:
        print(f"[rizin] rizin (pid {proc.pid}) does not end with the web UI: no job object ({exc})")
        return None


class RizinPipe:
    """``rizin -q0`` on one file, with a time limit for every command."""

    def __init__(self, exe, path, extra_args=(), start_timeout=START_TIMEOUT):
        self.args = [exe, "-q0", "-N", "-e", "scr.interactive=false", "-e", "scr.pager=",
                     "-e", "scr.color=0", *extra_args, path]
        self._chunks = queue.Queue()
        self._buf = bytearray()
        self._err = bytearray()
        self._err_dropped = 0
        self._err_cond = threading.Condition()
        self._write_lock = threading.Lock()
        self._dead = False
        self._closed = False
        kwargs = {"creationflags": _CREATE_NO_WINDOW} if os.name == "nt" else {}
        self._proc = subprocess.Popen(self.args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, bufsize=0, cwd=tempfile.gettempdir(),
                                      env=rizin_environment(exe), **kwargs)
        # Kept while rizin runs: rizin ends with the web UI (see _Job)
        self._job = _job_for(self._proc)
        self._threads = [threading.Thread(target=self._pump_stdout, name="rizin-stdout", daemon=True),
                         threading.Thread(target=self._pump_stderr, name="rizin-stderr", daemon=True)]
        for thread in self._threads:
            thread.start()
        try:
            self._answer(time.monotonic() + start_timeout)
        except BaseException:
            self.close()
            raise

    @property
    def alive(self):
        return not self._dead and self._proc.poll() is None

    def cmd(self, text, timeout=VIEW_TIMEOUT, limit=None):
        """Run a command; an answer of more than ``limit`` bytes is read to its end and not kept (RizinTooLarge)."""
        self._send([text])
        data, cut = self._answer(time.monotonic() + timeout, limit)
        if cut:
            raise RizinTooLarge(f"rizin's answer to {text.split(' ', 1)[0]} is larger than {limit} bytes")
        return data.decode("utf-8", "replace")

    def cmdj(self, text, timeout=VIEW_TIMEOUT, limit=None):
        out = self.cmd(text, timeout, limit).strip()
        return json.loads(out) if out else None

    def console(self, text, timeout=CONSOLE_TIMEOUT, limit=CONSOLE_LIMIT):
        """Run a console command; returns (stdout, stderr, truncated).

        Its output may hold NUL bytes (``pr``), which would end the answer
        early, so an ``echo`` of a random marker ends it instead. stderr has
        no separators; there an unknown command named after a second marker
        shows the end.
        """
        nonce = "tdc" + secrets.token_hex(8)
        err_marker = "Z" + nonce
        err_start = self._stderr_total()
        self._send([text, "echo " + nonce, err_marker])
        deadline = time.monotonic() + timeout
        kept = bytearray()
        truncated = False
        while True:
            room = max(0, limit - len(kept))
            data, cut = self._answer(deadline, max(room, 64))
            if not cut and data.strip() == nonce.encode():
                break
            if len(data) > room:
                data, cut = data[:room], True
            kept += data
            truncated = truncated or cut
        self._answer(deadline, 0)
        return kept.decode("utf-8", "replace"), self._stderr_until(err_start, err_marker, 2.0), truncated

    def stderr_tail(self, size=2000):
        with self._err_cond:
            return bytes(self._err[-size:]).decode("utf-8", "replace")

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._proc.poll() is None and self._write_lock.acquire(timeout=0.5):
            try:
                self._proc.stdin.write(b"q!\n")
                self._proc.stdin.flush()
            except (OSError, ValueError):
                pass
            finally:
                self._write_lock.release()
        try:
            self._proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self._proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._kill()
        self._dead = True
        for thread in self._threads:
            thread.join(timeout=2)
        for stream in (self._proc.stdout, self._proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        job, self._job = self._job, None
        if job is not None:
            job.close()

    def _kill(self):
        if os.name == "nt" and self._proc.poll() is None:
            # taskkill /T walks the process tree from rizin, so it has to run before kill().
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(self._proc.pid)], capture_output=True,
                               timeout=10, creationflags=_CREATE_NO_WINDOW)
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            self._proc.kill()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self._dead = True

    def _send(self, lines):
        for line in lines:
            if "\n" in line or "\r" in line or "\0" in line:
                raise ValueError("a rizin command is a single line")
        if not self.alive:
            raise RizinDied("rizin is not running")
        data = "".join(line + "\n" for line in lines).encode("utf-8")
        try:
            with self._write_lock:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
        except (OSError, ValueError):
            self._dead = True
            raise RizinDied("rizin is not running") from None

    def _answer(self, deadline, limit=None):
        """Read up to the next NUL and keep at most ``limit`` bytes of it."""
        kept = bytearray()
        truncated = False
        while True:
            end = self._buf.find(b"\0")
            piece = self._buf[:end] if end != -1 else self._buf
            room = len(piece) if limit is None else max(0, limit - len(kept))
            kept += piece[:room]
            truncated = truncated or len(piece) > room
            if end != -1:
                del self._buf[:end + 1]
                return bytes(kept), truncated
            self._buf.clear()
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise queue.Empty
                chunk = self._chunks.get(timeout=remaining)
            except queue.Empty:
                self._kill()
                raise RizinTimeout("rizin did not answer in time") from None
            if chunk is None:
                self._dead = True
                self._chunks.put(None)
                self._threads[1].join(timeout=1)
                tail = self.stderr_tail(500).strip()
                raise RizinDied(tail.splitlines()[-1] if tail else "rizin stopped")
            self._buf += chunk

    def _pump_stdout(self):
        try:
            while True:
                data = self._proc.stdout.read(65536)
                if not data:
                    break
                self._chunks.put(data)
        except (OSError, ValueError):
            pass
        finally:
            self._chunks.put(None)

    def _pump_stderr(self):
        try:
            while True:
                data = self._proc.stderr.read(65536)
                if not data:
                    break
                with self._err_cond:
                    self._err += data
                    if len(self._err) > _STDERR_KEEP:
                        drop = len(self._err) - _STDERR_KEEP
                        del self._err[:drop]
                        self._err_dropped += drop
                    self._err_cond.notify_all()
        except (OSError, ValueError):
            pass
        finally:
            with self._err_cond:
                self._err_cond.notify_all()

    def _stderr_total(self):
        with self._err_cond:
            return self._err_dropped + len(self._err)

    def _stderr_until(self, start, marker, wait):
        deadline = time.monotonic() + wait
        with self._err_cond:
            while True:
                text = bytes(self._err[max(0, start - self._err_dropped):])
                at = text.find(marker.encode())
                if at != -1:
                    text = text[:text.rfind(b"\n", 0, at) + 1]
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._threads[1].is_alive():
                    break
                self._err_cond.wait(remaining)
        return text[:64 * 1024].decode("utf-8", "replace")


# --- Projects ---------------------------------------------------------------


def _rz_quote(path):
    # Inside rizin's single quotes only \' is an escape; backslashes stay as they are.
    if "'" in path or path.endswith("\\"):
        raise ValueError(f"this path cannot be passed to rizin: {path}")
    return "'" + path + "'"


def _sdb_unescape(value):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r", "t": "\t"}.get(m.group(1), m.group(1)), value)


def _sdb_escape(value):
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")


def _sanitize_project(src, dst, level, mode, done):
    """Copy a project written by ``Ps`` so that rizin 0.9.1 can load it again.

    Loading a variable that came from DWARF looks up its DWARF entry, which
    the newly opened file does not have, and rizin then crashes on ``aflj``.
    Such variables become plain ones; those without a resolved location
    (shown as "@ ...") are left out. The analysis progress goes into an extra
    ``/tdc`` namespace, which rizin ignores.
    """
    namespace = None
    with open(src, encoding="utf-8", errors="surrogateescape", newline="\n") as fin, \
            open(dst, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as fout:
        for line in fin:
            line = line.rstrip("\n")
            if line.startswith("/"):
                namespace = line
            elif namespace == "/core/analysis/functions" and '"DWARF"' in line and "=" in line:
                line = _plain_vars(line)
            fout.write(line + "\n")
        fout.write(f"\n/tdc\nlevel={level}\nmode={mode}\ndone={','.join(done)}\n")


def _plain_vars(line):
    key, value = line.split("=", 1)
    try:
        fcn = json.loads(_sdb_unescape(value))
    except ValueError:
        return line
    plain = []
    for var in fcn.get("vars") or []:
        if (var.get("storage") or {}).get("type") == "eval_pending":
            continue
        if var.get("origin") == "DWARF":
            var.pop("origin", None)
            var.pop("dw_var", None)
        plain.append(var)
    fcn["vars"] = plain
    return key + "=" + _sdb_escape(json.dumps(fcn, separators=(",", ":"), ensure_ascii=False))


def _read_project_meta(path):
    """The ``/tdc`` namespace that _sanitize_project appended."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 65536))
            tail = fh.read().decode("utf-8", "replace")
    except OSError:
        return {"level": None, "mode": None, "done": []}
    meta = {}
    at = tail.rfind("\n/tdc\n")
    if at != -1:
        for line in tail[at + 6:].splitlines():
            if line.startswith("/"):
                break
            key, _, value = line.partition("=")
            meta[key] = value
    return {"level": meta.get("level") if meta.get("level") in ("aa", "aaa") else None,
            "mode": meta.get("mode") if meta.get("mode") in ("one", "steps") else None,
            "done": [s for s in meta.get("done", "").split(",") if s in _ALL_STEPS]}


_HINT_LINE_RE = re.compile(r"\s*(0x[0-9a-fA-F]+) =>(.*)")


def _make_safe(pipe, arch):
    """Set back what a project brings with Poo that would run a program or a command.

    The settings come back as they were saved: an arch plugin or an assembler that hands its work to
    nasm or as, the command hooks (cmd.*), the pager, the editor. An arch hint switches asm.arch while
    the disassembly passes it, and an ESIL hint with "#!" runs a rizin command. ``arch`` is the one
    rizin chose for the file before Poo. False if the arch is not safe afterwards.
    """
    pipe.cmd("e " + " ".join(_LOAD_SETTINGS))
    if not _arch_is_safe(pipe) and arch in _SAFE_ARCHES:
        # rizin 0.9.1 keeps x86.nasm when asked for x86 (rz_asm_use compares the plugin's arch), so via null.
        pipe.cmd("e asm.arch=null")
        pipe.cmd("e asm.arch=" + arch)
    for line in pipe.cmd("ahl").splitlines():
        m = _HINT_LINE_RE.match(line)
        if not m:
            continue
        addr, hints = m.groups()
        hint_arch = re.search(r" arch='([^']*)'", hints)
        if hint_arch and hint_arch.group(1) not in _SAFE_ARCHES:
            pipe.cmd(f"aha- @ {addr}")
        if " esil='" in hints and "#!" in hints:
            pipe.cmd(f"ahe- @ {addr}")
    return _arch_is_safe(pipe)


def _arch_is_safe(pipe):
    return all(pipe.cmd("e " + key).strip() in _SAFE_ARCHES for key in ("asm.arch", "analysis.arch"))


# --- Sessions ---------------------------------------------------------------

_ALL_STEPS = ("aaa", "aa", "aalg", "aalos", "aac", "aap", "aar", "aalor", "aav", "aaef", "aan",
              "aaft", "Fa", "aanr", "aaC", "avrr")
_CALLS_STEPS = ("aac", "aar")  # aaa runs them with analysis.calls=true


def aaa_steps(arch, lang, bintype, autoname, apply_signature):
    """The sub-steps of rizin 0.9.1's ``aaa`` that rizin has a command for, in aaa's order.

    Full analysis runs them. Taken from rz_core_perform_auto_analysis and
    rz_core_analysis_everything (librz/core/canalysis.c), with their
    conditions. aaa also recovers local variables, integrates DWARF
    functions, recovers globals from symbols, resolves pointers into data
    sections and marks data-referenced bytes; rizin 0.9.1 has no command for
    those, so the steps leave them out.
    """
    apple = "mach" in bintype and any(a in arch for a in ("ppc", "arm", "x86"))
    x86 = arch.startswith("x86")
    steps = ["aa"]
    if lang.startswith("go"):
        steps.append("aalg")
    if apple:
        steps.append("aalos")
    steps.append("aac")
    if not x86:
        steps.append("aap")
    steps.append("aar")
    if apple:
        steps.append("aalor")
    if not x86 and arch != "hexagon":
        steps += ["aav", "aaef"]
    if autoname:
        steps.append("aan")
    steps.append("aaft")
    if apply_signature:
        steps.append("Fa")
    steps += ["aanr", "aaC", "avrr"]
    return steps


class _Gate:
    """One user of a session's pipe at a time; waiting requests go before the analysis.

    Between two steps of Full analysis (hold_off) requests get the pipe for a while; after that the next
    step goes first (``_due``), so requests that keep coming cannot hold it off for ever.
    """

    def __init__(self):
        self._cond = threading.Condition()
        self.holder = None
        self._waiting = 0
        self._due = False
        self.closed = False

    def enter(self, label, wait):
        with self._cond:
            if (self.holder is not None or self._due) and not self.closed:
                self._waiting += 1
                try:
                    free = self._cond.wait_for(lambda: self.closed or (self.holder is None and not self._due),
                                               timeout=wait)
                finally:
                    self._waiting -= 1
                    self._cond.notify_all()
                if not free and not self.closed:
                    raise RizinBusy(self.holder or "analysis")
            if self.closed:
                raise SessionEnded()
            self.holder = label

    def hold_off(self, gap, limit):
        """Between two analysis steps: ``gap`` seconds in which requests that come get the pipe, then as
        long as requests use or wait for it, until ``limit`` seconds in all. False if the gate closed."""
        end = time.monotonic() + max(gap, limit)
        with self._cond:
            self._cond.wait_for(lambda: self.closed, timeout=gap)
            self._cond.wait_for(lambda: self.closed or (self.holder is None and self._waiting == 0),
                                timeout=max(0.0, end - time.monotonic()))
            return not self.closed

    def enter_analysis(self, label, after_gap=False):
        """Take the pipe for an analysis step. Requests that wait go first, unless the step comes after
        hold_off: the gap gave them their turn, now they wait for the step."""
        with self._cond:
            if after_gap:
                self._due = True
            try:
                self._cond.wait_for(lambda: self.closed or (self.holder is None and (after_gap or self._waiting == 0)))
            finally:
                self._due = False
            if self.closed:
                return False
            self.holder = label
            return True

    def relabel(self, label):
        with self._cond:
            self.holder = label

    def unused_and(self, test):
        """Whether nobody holds the pipe and ``test()`` is true; nobody can take the pipe meanwhile."""
        with self._cond:
            return self.holder is None and not self.closed and test()

    def leave(self):
        with self._cond:
            self.holder = None
            self._cond.notify_all()

    def close(self):
        with self._cond:
            self.closed = True
            self._cond.notify_all()


class RizinSession:
    """One file in rizin: views, console, renames and comments, and the analysis in steps."""

    def __init__(self, sid, tab, path, sha256, size, exe=RIZIN_EXE, analysis_limit=600, step_grace=STEP_GRACE,
                 big_file=BIG_FILE, projects_dir=PROJECTS_DIR, clock=time.monotonic, save_delay=SAVE_DELAY,
                 timer=threading.Timer, step_gap=STEP_GAP, step_gap_limit=STEP_GAP_LIMIT):
        self.id = sid
        self.tab = tab
        self.path = path
        self.sha256 = sha256
        self.size = size
        self.last_used = clock()
        self.at = None
        self.function = None
        self.format = self.arch = self.bits = None
        self.level = "aa" if size > big_file else "aaa"
        # "one": aaa as one step; "steps": Full analysis, aaa's sub-steps one by one.
        self._mode = "one"
        self._exe = exe
        self._limit = analysis_limit
        self._grace = step_grace
        self._gap = step_gap
        self._gap_limit = max(step_gap, step_gap_limit)
        self._projects_dir = projects_dir
        self._project = os.path.join(projects_dir, sha256 + ".rzdb")
        _rz_quote(self._project + ".0.tmp")
        self._gate = _Gate()
        self._lock = threading.Lock()
        self._replace_lock = threading.Lock()
        self._save_seq = self._saved_seq = 0
        self._save_delay = save_delay
        self._make_timer = timer
        self._save_timer = None
        self._dirty = False
        self._save_lock = threading.Lock()
        self._closed = False
        self._closer = None
        # Set once the session has ended and its last save is written or dropped (wait_closed)
        self._gone = threading.Event()
        self._thread = None
        self._state, self._step, self._notes = "running", None, []
        self._run_started = self._run_finished = None
        self._pipe, contained, level, mode, note = self._boot()
        try:
            self._read_file_info()
            self._where(self._pipe)
        except BaseException:
            self._pipe.close()
            raise
        self._done = list(contained)
        self.level = level or self.level
        self._mode = mode or self._mode
        if note:
            self._notes.append(note)
        remaining = self._plan()
        if mode == "steps" and remaining:
            # The project was saved while a Full analysis had not finished (it stopped, or a step hung and
            # the session started again): its steps, the hung one too, run again from the button only.
            self._state = "stopped"
            self._notes.append(f"Full analysis did not finish; not run: {', '.join(remaining)}. "
                               f"Full analysis goes on with them.")
        else:
            self._start_analysis(restored=bool(contained))

    @property
    def closed(self):
        return self._closed

    @property
    def dead(self):
        """rizin stopped while nobody used the pipe (a step or a restart holds it while rizin is replaced)."""
        return self._gate.unused_and(lambda: not self._pipe.alive)

    @property
    def analysis(self):
        with self._lock:
            elapsed = 0.0
            if self._run_started is not None:
                end = self._run_finished if self._run_finished is not None else time.monotonic()
                elapsed = round(end - self._run_started, 1)
            # The session's own notes first (why the analysis stopped): the toolbar shows the start of the note
            notes = self._notes + ([_FULL_NOTE] if self._mode == "steps" else [])
            return {"state": self._state, "step": self._step, "done_steps": list(self._done),
                    "level": self.level, "elapsed": elapsed, "note": " ".join(notes) or None}

    def describe(self):
        return {"session": self.id,
                "file": {"path": self.path, "sha256": self.sha256, "size": self.size,
                         "format": self.format, "arch": self.arch, "bits": self.bits},
                "analysis": self.analysis}

    def status(self):
        """Analysis, seek and function without touching the pipe."""
        return {"analysis": self.analysis, "seek": self.at, "function": self.function}

    def json(self, cmd, wait=2.0, timeout=VIEW_TIMEOUT):
        """Run a JSON command built by the web UI. User input goes through console(). An answer over
        VIEW_ANSWER_MAX raises RizinTooLarge; the session goes on."""
        return self._call("view", wait, lambda pipe: pipe.cmdj(cmd, timeout, VIEW_ANSWER_MAX))

    def text(self, cmd, wait=2.0, timeout=VIEW_TIMEOUT):
        """Like json() for a command whose output is text."""
        return self._call("view", wait, lambda pipe: pipe.cmd(cmd, timeout, VIEW_ANSWER_MAX))

    def console(self, text, wait=2.0):
        reason = check_console_command(text)
        if reason:
            raise RizinRefused(reason)
        annotates = _annotates(text)
        if annotates:
            self._refuse_while_analysing()

        def run(pipe):
            if annotates:
                self._refuse_while_analysing()
            pipe.cmd("e scr.color=3")
            out, err, truncated = pipe.console(text)
            pipe.cmd("e scr.color=0")
            target = _temporary_seek(text)
            if target:
                pipe.cmd("s " + target)
            self._where(pipe)
            if err and out and not out.endswith("\n"):
                out += "\n"
            output = (out + err).replace("\r\n", "\n")
            if len(output) > CONSOLE_LIMIT:
                output, truncated = output[:CONSOLE_LIMIT], True
            # changed: the command renamed or commented, so the views show something else at the same place
            return {"output": output, "seek": self.at, "function": self.function, "truncated": truncated,
                    "changed": annotates}

        result = self._call("console", wait, run)
        if annotates:
            self._schedule_save()
        return result

    def seek(self, addr, wait=2.0):
        addr = _address(addr)

        def run(pipe):
            pipe.cmd(f"s {addr:#x}")
            self._where(pipe)
            return {"seek": self.at, "function": self.function}

        return self._call("seek", wait, run)

    def rename(self, addr, name, wait=2.0):
        """Rename the function at (or around) ``addr``."""
        addr = _address(addr)
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise RizinRefused("a name starts with a letter or '_' and has up to 128 of A-Z a-z 0-9 _ . @ $ : -")
        self._refuse_while_analysing()

        def run(pipe):
            self._refuse_while_analysing()
            found = pipe.cmd(f"afl. @ {addr:#x}").strip()
            if not found:
                raise RizinRefused(f"there is no function at {addr:#x}")
            # rizin 0.9.1's afn renames only at a function's start: the function around addr by its entry.
            entry = int(found.splitlines()[0].split(None, 1)[0], 16)
            # In single quotes the name's @ $ : stay text.
            pipe.cmd(f"afn {_rz_quote(name)} @ {entry:#x}")
            offset, _, new_name = pipe.cmd(f"afl. @ {entry:#x}").strip().splitlines()[0].partition(" ")
            self._where(pipe)
            return {"offset": int(offset, 16), "name": new_name.strip()}

        result = self._call("rename", wait, run)
        self._schedule_save()
        return result

    def comment(self, addr, text, wait=2.0):
        """Set (an empty ``text`` removes) the comment at ``addr``."""
        addr = _address(addr)
        if not isinstance(text, str) or "\n" in text or "\r" in text or "\0" in text:
            raise RizinRefused("a comment is a single line of text")
        if len(text) > MAX_COMMENT:
            raise RizinRefused(f"a comment has at most {MAX_COMMENT} characters")
        self._refuse_while_analysing()

        def run(pipe):
            self._refuse_while_analysing()
            pipe.cmd(f"CC- @ {addr:#x}")
            if text:
                # Base64 has no ; @ | ! or quotes, so the text cannot form a command.
                encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
                pipe.cmd(f"CCu base64:{encoded} @ {addr:#x}")
            return {"offset": addr, "comment": text}

        result = self._call("comment", wait, run)
        self._schedule_save()
        return result

    def analyze_full(self):
        """Full analysis: aaa's sub-steps that are not done yet, one by one (see aaa_steps).

        For a file over big_file, or after aaa had to be killed; a finished aaa
        already covers it. Pending renames and comments are saved first.
        """
        with self._lock:
            busy = self._closed or (self._thread is not None and self._thread.is_alive())
            covered = "aaa" in self._done
        if not busy and not covered:
            self.flush()
            with self._lock:
                self.level, self._mode = "aaa", "steps"
            if self._plan():
                self._start_analysis()
        return self.analysis

    def flush(self, wait=_FLUSH_WAIT):
        """Write the project now if a rename or comment is waiting for its save; True if it did.

        ``wait`` bounds the wait for a save that runs already and the wait for the pipe (None: no limit).
        A save that fails, whatever the error, leaves the change waiting for the next save.
        """
        if not self._save_lock.acquire(timeout=-1 if wait is None else wait):
            raise RizinBusy("save")
        try:
            with self._lock:
                if not self._dirty:
                    return False
                self._dirty = False
                timer, self._save_timer = self._save_timer, None
            if timer is not None:
                timer.cancel()
            try:
                self._finish_save(self._call("save", wait, self._project_snapshot))
            except BaseException:
                with self._lock:
                    self._dirty = not self._closed
                raise
            return True
        finally:
            self._save_lock.release()

    def close(self):
        """End the session; a save that is still pending is written first.

        The caller waits at most _CLOSE_WAIT. A save that needs longer (the pipe is busy, or a save
        runs already) goes on in the background, and the session ends once it is written or dropped.
        """
        with self._lock:
            if self._closed or self._closer is not None:
                if self._closer is None:
                    self._gone.set()  # it ended by itself (rizin stopped): nothing is left to write
                return
            closer = self._closer = threading.Thread(target=self._close_now, daemon=True,
                                                     name=f"rizin-close-{self.sha256[:12]}")
        closer.start()
        closer.join(timeout=_CLOSE_WAIT)

    def wait_closed(self, timeout):
        """Wait until close() has ended the session and its last save is written or dropped; True if so."""
        return self._gone.wait(timeout)

    def _close_now(self):
        try:
            try:
                self.flush()
            except Exception as exc:
                print(f"[rizin] {self.sha256[:12]}: a pending project save was dropped ({type(exc).__name__}: {exc})")
            finally:
                self._end()
            thread = self._thread
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=5)
        finally:
            self._gone.set()

    def _refuse_while_analysing(self):
        # A later step (Fa, for one) could rename the function again.
        with self._lock:
            if self._state == "running":
                raise RizinBusy(self._step or "analysis")

    def _schedule_save(self):
        """Save the project save_delay after the last rename or comment."""
        with self._lock:
            if self._closed:
                return
            self._dirty = True
            if self._save_timer is not None:
                self._save_timer.cancel()
            timer = self._save_timer = self._make_timer(self._save_delay, self._save_from_timer)
        timer.daemon = True
        timer.start()

    def _save_from_timer(self):
        try:
            self.flush(wait=None)
        except Exception as exc:
            # The change stays to be saved: by the next rename or comment, or when the session closes
            if not self._closed:
                print(f"[rizin] {self.sha256[:12]}: the project could not be saved ({type(exc).__name__}: {exc})")

    def _call(self, label, wait, fn):
        if self._closed:
            raise SessionEnded()
        self._gate.enter(label, wait)
        try:
            if self._closed:
                raise SessionEnded()
            try:
                return fn(self._pipe)
            except (RizinTimeout, RizinDied):
                if self._closed:
                    raise SessionEnded() from None
                self._end()
                raise
        finally:
            self._gate.leave()

    def _end(self):
        with self._lock:
            self._closed = True
            pipe = self._pipe
        self._gate.close()
        pipe.close()

    def _use(self, pipe):
        """Make a restarted rizin the session's pipe, unless the session ended meanwhile."""
        with self._lock:
            if not self._closed:
                self._pipe = pipe
                return True
        pipe.close()
        return False

    def _boot(self):
        """Start rizin and load the project; returns (pipe, steps in the project, level, mode, note)."""
        pipe = self._start_rizin()
        if not os.path.isfile(self._project):
            return pipe, [], None, None, None
        meta = _read_project_meta(self._project)
        try:
            arch = pipe.cmd("e asm.arch").strip()
            pipe.cmd("Poo " + _rz_quote(self._project), timeout=PROJECT_TIMEOUT)
            loaded = pipe.cmd("e prj.file").strip() == self._project
            if loaded:
                pipe.cmd("aflj~?")  # rizin 0.9.1 crashes here on a project it cannot use
                loaded = _make_safe(pipe, arch)
        except (RizinTimeout, RizinDied):
            loaded = False
        if loaded:
            return pipe, meta["done"], meta["level"], meta["mode"], None
        pipe.close()
        try:
            os.replace(self._project, self._project + ".broken")
        except OSError:
            pass
        return self._start_rizin(), [], None, None, _PROJECT_FAILED

    def _start_rizin(self):
        return RizinPipe(self._exe, self.path, [arg for setting in _START_SETTINGS for arg in ("-e", setting)])

    def _read_file_info(self):
        pipe = self._pipe
        try:
            info = pipe.cmdj("ij") or {}
        except ValueError:
            info = {}
        core, binfo = info.get("core") or {}, info.get("bin") or {}

        def setting(key):
            return pipe.cmd("e " + key).strip()

        arch = setting("asm.arch")
        self.format = core.get("format")
        self.arch = binfo.get("arch") or arch or None
        try:
            self.bits = int(binfo.get("bits") or setting("asm.bits"))
        except ValueError:
            self.bits = None
        self._steps = aaa_steps(arch, binfo.get("lang") or setting("bin.lang"), binfo.get("bintype") or "",
                                setting("analysis.autoname") == "true",
                                setting("analysis.apply.signature") == "true")

    def _plan(self):
        """The steps still to run: aaa as one step, aa (over big_file), or Full analysis's steps."""
        if "aaa" in self._done:
            return []
        if self.level == "aa":
            steps = ["aa"]
        elif self._mode == "steps":
            steps = self._steps
        else:
            steps = ["aaa"]
        return [s for s in steps if s not in self._done]

    def _start_analysis(self, restored=False):
        remaining = self._plan()
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._notes = [n for n in self._notes if n == _PROJECT_FAILED]
            if not remaining:
                self._state, self._step = "done", None
                if restored:
                    self._notes.append("Restored from the saved project.")
                return
            self._state, self._step = "running", None
            self._run_started, self._run_finished = time.monotonic(), None
            self._thread = threading.Thread(target=self._analyze, args=(remaining,), daemon=True,
                                            name=f"rizin-analysis-{self.sha256[:12]}")
            self._thread.start()

    def _analyze(self, steps):
        started = time.monotonic()
        # Full analysis: after each step a gap in which views and the console get the pipe (hold_off).
        # aaa and aa are one step each and have none.
        stepwise = self._mode == "steps"
        for i, step in enumerate(steps):
            if i and stepwise and not self._gate.hold_off(self._gap, self._gap_limit):
                return
            if i and time.monotonic() - started >= self._limit:
                self._finish("stopped", f"The analysis stopped after {self._limit:g} s; "
                                        f"not run: {', '.join(steps[i:])}.")
                return
            if not self._gate.enter_analysis(step, after_gap=bool(i and stepwise)):
                return
            snapshot = None
            try:
                with self._lock:
                    self._step = step
                try:
                    self._run_step(self._pipe, step)
                except (RizinTimeout, RizinDied) as exc:
                    if not self._closed:
                        self._recover(step, exc)
                    return
                with self._lock:
                    self._done.append(step)
                    self._step = None
                if i == len(steps) - 1:
                    self._finish("done", None)
                    snapshot = self._final_snapshot()
            finally:
                self._gate.leave()
            if snapshot:
                try:
                    self._finish_save(snapshot)
                except Exception as exc:
                    print(f"[rizin] {self.sha256[:12]}: the project could not be saved after the analysis ({exc})")

    def _final_snapshot(self):
        """Ps once the analysis is done, if there is a project (gate held); None if there is none or it failed.

        A failed save leaves the analysis done. After a Ps that timed out rizin is gone, so the session ends.
        """
        if not os.path.isfile(self._project):
            return None
        self._gate.relabel("save")
        try:
            return self._project_snapshot(self._pipe)
        except OSError as exc:
            print(f"[rizin] {self.sha256[:12]}: the project could not be saved after the analysis ({exc})")
        except (RizinTimeout, RizinDied) as exc:
            if not self._closed:
                print(f"[rizin] {self.sha256[:12]}: rizin stopped while it saved the project ({exc}); "
                      f"the session ends")
                self._end()
        return None

    def _run_step(self, pipe, step):
        timeout = self._limit + self._grace
        if step not in _CALLS_STEPS:
            pipe.cmd(step, timeout=timeout)
            return
        calls = pipe.cmd("e analysis.calls").strip() or "false"
        pipe.cmd("e analysis.calls=true")
        pipe.cmd(step, timeout=timeout)
        pipe.cmd("e analysis.calls=" + calls)

    def _recover(self, step, exc):
        """A step hung or crashed rizin: restart it and replay the finished steps (gate held)."""
        what = (f"did not finish within {self._limit + self._grace:g} s" if isinstance(exc, RizinTimeout)
                else "stopped rizin")
        self._gate.relabel("restart")
        with self._lock:
            self._step = "restart"
        self._pipe.close()
        replay = []
        try:
            pipe, contained, _, _, _ = self._boot()
            if not self._use(pipe):
                return
            if step == "aaa":
                # aaa is one step; the session goes on with aa, Full analysis can take it further.
                replay = [] if "aa" in contained else ["aa"]
                with self._lock:
                    self.level = "aa"
                    self._done = list(contained)
            else:
                replay = [s for s in self._done if s not in contained]
            for s in replay:
                self._gate.relabel(s)
                with self._lock:
                    self._step = s
                self._run_step(self._pipe, s)
                if step == "aaa":
                    with self._lock:
                        self._done.append(s)
            if self.at is not None:
                self._pipe.cmd(f"s {self.at:#x}")
            self._where(self._pipe)
        except (OSError, RizinTimeout, RizinDied) as err:
            if not self._closed:
                self._finish("failed", f"Step {step} {what}; rizin could not be restarted ({err}).")
            self._end()
            return
        if step == "aaa":
            self._finish("stopped", f"aaa {what}; rizin was restarted with aa. Full analysis runs aaa's steps "
                                    f"one by one.")
        else:
            self._finish("stopped", f"Step {step} {what}; rizin was restarted and replayed "
                                    f"{', '.join(replay) or 'no steps'}.")

    def _finish(self, state, note):
        with self._lock:
            self._state, self._step = state, None
            self._run_finished = time.monotonic()
            if note:
                self._notes.append(note)

    def _where(self, pipe):
        try:
            self.at = int(pipe.cmd("s").strip(), 16)
        except ValueError:
            self.at = None
        lines = pipe.cmd("afl.").strip().splitlines()
        parts = lines[0].split(None, 1) if lines else []
        self.function = parts[1].strip() if len(parts) == 2 else None

    def _project_snapshot(self, pipe):
        """``Ps`` to a temporary file (gate held); _finish_save then makes it the project."""
        self._save_seq += 1
        os.makedirs(self._projects_dir, exist_ok=True)
        tmp = f"{self._project}.{self._save_seq}.tmp"
        try:
            pipe.cmd("Ps " + _rz_quote(tmp), timeout=PROJECT_TIMEOUT)
        except BaseException:
            try:
                os.remove(tmp)  # what a killed Ps left behind
            except OSError:
                pass
            raise
        with self._lock:
            return self._save_seq, tmp, self.level, self._mode, list(self._done)

    def _finish_save(self, snapshot):
        seq, tmp, level, mode, done = snapshot
        part = f"{self._project}.{seq}.part"
        try:
            if not os.path.isfile(tmp):
                raise OSError(f"rizin did not write {tmp}")
            _sanitize_project(tmp, part, level, mode, done)
            with self._replace_lock:
                if seq > self._saved_seq:
                    os.replace(part, self._project)
                    self._saved_seq = seq
        finally:
            for leftover in (tmp, part):
                try:
                    os.remove(leftover)
                except OSError:
                    pass


def _address(addr):
    if isinstance(addr, bool) or not isinstance(addr, int) or not 0 <= addr < 2 ** 64:
        raise RizinRefused("an address is an integer from 0 to 2^64-1")
    return addr


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class RizinSessions:
    """All rizin sessions of the web UI. ``reap`` runs with every call."""

    def __init__(self, exe=RIZIN_EXE, max_sessions=3, idle_seconds=1800, analysis_limit=600,
                 big_file=BIG_FILE, projects_dir=PROJECTS_DIR, clock=time.monotonic, step_grace=STEP_GRACE,
                 save_delay=SAVE_DELAY, timer=threading.Timer, step_gap=STEP_GAP, step_gap_limit=STEP_GAP_LIMIT):
        self.exe = exe
        self.max_sessions = max_sessions
        self.idle_seconds = idle_seconds
        self.analysis_limit = analysis_limit
        self.big_file = big_file
        self.projects_dir = projects_dir
        self.clock = clock
        self.step_grace = step_grace
        self.save_delay = save_delay
        self.timer = timer
        self.step_gap = step_gap
        self.step_gap_limit = step_gap_limit
        self._lock = threading.Lock()
        self._sessions = {}
        self._moved = collections.OrderedDict()
        self._starting = {}
        # sha256 -> sessions out of the manager whose close (their last save) may still run
        self._closing = {}
        # tab -> the number of its newest OPEN that has not ended (of all OPENs, counted in _opens)
        self._tab_opens = {}
        self._opens = 0

    def open(self, path, tab):
        """Open ``path`` for the browser tab ``tab``; returns the session's describe().

        Of the OPENs of one tab the newest wins: one that a newer OPEN of the tab came after while it ran
        changes nothing in the tab and raises SessionSuperseded (a session it started is closed).
        """
        with self._lock:
            self._opens += 1
            ticket = self._tab_opens[tab] = self._opens
        try:
            return self._open(path, tab, ticket)
        finally:
            with self._lock:
                if self._tab_opens.get(tab) == ticket:
                    del self._tab_opens[tab]

    def _open(self, path, tab, ticket):
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        size = os.path.getsize(path)
        sha = _sha256(path)
        closing_until = None
        while True:
            to_close, session, closing, started, superseded = [], None, None, None, False
            with self._lock:
                to_close += self._reap_locked()
                superseded = self._tab_opens.get(tab) != ticket
                session = None if superseded else next((s for s in self._sessions.values() if s.sha256 == sha), None)
                if session is not None:
                    to_close += self._move_locked(session, tab)
                elif not superseded:
                    # A session of the file that still closes may still write its project: its save goes first,
                    # for _FLUSH_WAIT at most, so that this session loads it (and never writes over it)
                    closing = self._closing_locked(sha)
                    if closing is not None:
                        closing_until = closing_until or time.monotonic() + _FLUSH_WAIT
                        closing = closing if time.monotonic() < closing_until else None
                    started = None if closing is not None else self._starting.get(sha)
                    if closing is None and started is None:
                        self._starting[sha] = threading.Event()
                        to_close += self._free_tab_locked(tab) + self._evict_locked()
            self._close_all(to_close)
            if superseded:
                raise SessionSuperseded()
            if session is not None:
                return session.describe()
            if closing is not None:
                closing.wait_closed(max(0.0, closing_until - time.monotonic()))
            elif started is not None:
                started.wait(timeout=START_TIMEOUT + PROJECT_TIMEOUT)
            else:
                break
        try:
            session = RizinSession(secrets.token_hex(12), tab, path, sha, size, exe=self.exe,
                                   analysis_limit=self.analysis_limit, step_grace=self.step_grace,
                                   big_file=self.big_file, projects_dir=self.projects_dir, clock=self.clock,
                                   save_delay=self.save_delay, timer=self.timer, step_gap=self.step_gap,
                                   step_gap_limit=self.step_gap_limit)
        except BaseException:
            with self._lock:
                self._starting.pop(sha).set()
            raise
        with self._lock:
            self._starting.pop(sha).set()
            superseded = self._tab_opens.get(tab) != ticket
            if superseded:
                # A newer OPEN of the tab came meanwhile: the tab is that one's, this session goes
                to_close = self._retire_locked([session])
            else:
                to_close = self._free_tab_locked(tab)
                self._sessions[session.id] = session
                to_close += self._evict_locked()
        self._close_all(to_close)
        if superseded:
            raise SessionSuperseded()
        return session.describe()

    def get(self, sid):
        with self._lock:
            to_close = self._reap_locked()
            session = self._sessions.get(sid)
            if session is not None:
                session.last_used = self.clock()
            moved = sid in self._moved
        self._close_all(to_close)
        if session is not None:
            return session
        if moved:
            raise SessionMoved()
        raise SessionEnded()

    def close(self, sid):
        """End a session; an ID that moved to another tab leaves the session running."""
        with self._lock:
            to_close = self._reap_locked()
            session = self._sessions.pop(sid, None)
            to_close += self._retire_locked([session] if session else [])
        self._close_all(to_close)

    def reap(self):
        with self._lock:
            to_close = self._reap_locked()
        self._close_all(to_close)

    def shutdown(self):
        with self._lock:
            to_close = self._retire_locked(list(self._sessions.values()))
            self._sessions.clear()
        self._close_all(to_close)

    # These run under self._lock and return the sessions to close once it is released.

    def _reap_locked(self):
        now = self.clock()
        gone = [s for s in self._sessions.values()
                if s.closed or s.dead or now - s.last_used >= self.idle_seconds]
        for session in gone:
            del self._sessions[session.id]
        for sha in list(self._closing):
            self._closing_locked(sha)
        return self._retire_locked(gone)

    def _free_tab_locked(self, tab):
        old = [s for s in self._sessions.values() if s.tab == tab]
        for session in old:
            del self._sessions[session.id]
        return self._retire_locked(old)

    def _evict_locked(self):
        evicted = []
        while self._sessions and len(self._sessions) + len(self._starting) > self.max_sessions:
            oldest = min(self._sessions.values(), key=lambda s: s.last_used)
            del self._sessions[oldest.id]
            evicted.append(oldest)
        return self._retire_locked(evicted)

    def _retire_locked(self, sessions):
        """Sessions taken out of the manager, to be closed: until their last save is written, an OPEN of the
        same file waits for them (_closing_locked)."""
        for session in sessions:
            self._closing.setdefault(session.sha256, []).append(session)
        return sessions

    def _closing_locked(self, sha):
        """A session of the file sha that still closes, or None; the ones that have ended are let go."""
        left = [s for s in self._closing.pop(sha, []) if not s.wait_closed(0)]
        if left:
            self._closing[sha] = left
        return left[0] if left else None

    def _move_locked(self, session, tab):
        session.last_used = self.clock()
        if session.tab == tab:
            return []
        del self._sessions[session.id]
        to_close = self._free_tab_locked(tab)
        new_id = secrets.token_hex(12)
        self._moved[session.id] = new_id
        while len(self._moved) > _MAX_MOVED:
            self._moved.popitem(last=False)
        session.id, session.tab = new_id, tab
        self._sessions[new_id] = session
        return to_close

    @staticmethod
    def _close_all(sessions):
        for session in sessions:
            session.close()
