"""Rizin sessions for the RIZIN tab.

One opened file runs one ``rizin -q0`` process (rizin 0.9.1 from Cutter's
package). The web UI runs as SYSTEM without a login, so the file and the
console input are treated as hostile.

RizinPipe speaks rizin's pipe protocol: one NUL after start-up and one after
every answer. Two threads drain stdout and stderr, so every command has a
time limit; a command that runs over it gets rizin killed (RizinTimeout). An
answer larger than the command's limit is read to its end but not kept
(RizinTooLarge): the lists of strings, imports and flags keep at most
VIEW_ANSWER_MAX, a disassembly or a decompile of one function
FUNCTION_ANSWER_MAX, every other answer ANSWER_MAX, the backstop no
legitimate answer reaches. On Windows every rizin runs in a job object that
ends it when the web UI's process ends, also when that is killed (_Job).

check_console_command is the console filter. Fail-closed: a command has to
start with one of the allowed families, and inside them every sub-command or
modifier is refused that runs a program, runs stored or nested commands,
reads files, writes files (a write may only go to rizin's cache), changes
settings outside asm.*/analysis.*/esil.*, waits for input or opens an
interactive view. The lists come from rizin 0.9.1's own help (``?*``, ``@?``,
``@@?``, ``~?``) and its command sources. Nothing in the console assembles,
and the arch settings only take built-in disassemblers: some assembler
plugins hand their work to nasm or as.

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

Projects (``projects_dir/<sha256>.rzdb``) are written after a rename, a
comment, a patch or a breakpoint, ``save_delay`` seconds after the last one,
and at the latest when the session closes. They are loaded with ``Poo``,
which keeps the file rizin has open, so the same file under another path
finds its project too. ``Poo`` also brings back the saved settings, hints and
breakpoints; those that could run a program or a command are set back
afterwards (_make_safe), and a project that cannot be made safe is not used.
A project saved while a Full analysis had not finished opens stopped: the
button goes on. What rizin's own project does not hold -- the write cache,
measured -- goes into a ``/tdc`` namespace of its own and is written back
with ``wx`` when the file is opened again (_replay_patches).
"""

import base64
import collections
import contextlib
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

import rizin_emulation

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
# The emulation (ESIL) stops itself after ESIL_TIMEOUT seconds: measured with rizin 0.9.1, esil.timeout=3
# ended an endless `jmp $` after 3.02 s ("esil: timeout exceeded") and rizin went on. It stays well below
# CONSOLE_TIMEOUT, after which the pipe kills rizin and the session ends.
ESIL_TIMEOUT = 5.0
# The pipe's time limit for one run command: esil.timeout plus this, so a run that rizin bounds never trips
# it (past it the pipe kills rizin and the session ends). Every command a run sends is bounded by
# esil.timeout: aecc, aecs and aesuo are not, which is why to_call does not use them
# (rizin_emulation.STEP_COMMANDS) and why the console refuses all three (_REFUSED). There the limit is
# CONSOLE_TIMEOUT, so such a command would hold the session's gate for 60 s and then cost the session --
# measured, all three ran past 15 s on a `jmp $` with esil.timeout=2, while aesu, aecu, aecue, aesue,
# aess, aeso, aesou and aecb all stopped at the timeout.
ESIL_GRACE = 10.0
# The stack that aeim maps (rizin's own defaults): set by the server at each start, so a size the console
# set (esil.* is settable there) never becomes an allocation of gigabytes on the VM's 8 GB.
ESIL_STACK_ADDR = 0x100000
ESIL_STACK_SIZE = 0xF0000
# Set in one `e` at the start of an emulation. Without io.cache every write of the run is lost (px keeps
# the original bytes); with it the file on disk stays untouched. The traps stop the run at an invalid
# instruction, a jump into memory that does not execute and an invalid read or write, rather than
# emulating zeros there; romem stays off, so the run can decrypt in place. esil.verbose=1 makes an
# invalid read or write say "WARNING: core: TRAP": without it aec stops there without a word. Set again before
# each run (emulation_run): esil.exectrap takes effect only when it is set after aei.
# esil.nonull stops **nothing** in rizin 0.9.1: measured, a read and a write at address 0 are carried out
# silently and the run goes on to the timeout, exactly as with esil.nonull=false. It stays set because it
# is what rizin offers for the case and costs nothing; on a PE, where 0 is in no map, it is esil.iotrap
# that stops such an access ("WARNING: core: TRAP"), which is the right guard anyway (spec R75).
ESIL_SETTINGS = ("io.cache=true", f"esil.timeout={ESIL_TIMEOUT:g}", "esil.breakoninvalid=true",
                 "esil.exectrap=true", "esil.iotrap=true", "esil.nonull=true", "esil.verbose=1", "esil.romem=false",
                 f"esil.stack.addr={ESIL_STACK_ADDR:#x}", f"esil.stack.size={ESIL_STACK_SIZE:#x}")
# Stack words the emulation state reads from the stack pointer upwards (one pxj and an fd per word).
RIZIN_STACK_ROWS = 16
# Full analysis: after a step, the next one waits STEP_GAP seconds, in which requests get the pipe, and
# then as long as requests use or wait for it, STEP_GAP_LIMIT seconds after the step at most.
STEP_GAP = 2.0
STEP_GAP_LIMIT = 10.0
SAVE_DELAY = 3.0
# What the project's /tdc namespace may spend on its patches line. _read_project_meta reads the last
# 64 KB of a project, and a patch of MAX_PATCH_BYTES bytes is 4000 hex digits, so a few of them would push
# /tdc out of that tail and take level, mode and done with it -- a file that would then be analysed again
# from nothing. Patches past the budget are left out of the save and the session says how many
# (_finish_save), rather than costing the analysis progress in silence. The timeline of the emulation
# (``restore=``, _restore_record_for_save) is spent from the same budget, **after** the patches: what is left
# of it once the patches line is written is all it may have, and it is dropped whole when that is not enough.
PROJECT_PATCH_CHARS = 32 * 1024
# The widest range one re-analysis covers, and the most functions it rebuilds in it. Both are backstops
# on what a single request costs: the string search reads the range byte for byte (measured on rizin
# 0.9.1: 1 MB of random bytes in 0.2 s, 12 500 hits and about 1 MB of JSON), and every function of the
# range costs an af- and an af. A range a run decrypted is far smaller; a wider one is re-analysed in
# parts, which the start and end of the request allow.
MAX_REANALYZE_BYTES = 4 * 1024 * 1024
MAX_REANALYZE_FUNCTIONS = 256
# How far past the range the analysis may reach. rizin's analysis.limits truncates the function it cuts
# (measured: a 7-byte function at the range's start came out as 5 bytes with analysis.to at its 5th
# byte), and the function at the start is the one the analyst came for, so the limit gets one page of
# room -- the same distance that already counts as "the same range" when a run's writes are grouped
# (RUN_RANGE_GAP). It is a bound, not a licence: without the limits af walked 32 functions down a chain
# of calls, the last of them 0x2d00 bytes past the range (measured), and rizin's own cap on a function
# is 256 KB, 64 times this.
# A function reaching more than a page past the range is still truncated; docs/api.md says so.
REANALYZE_SLACK = 0x1000
CONSOLE_LIMIT = 1024 * 1024
# The largest answer that the lists of strings, imports and flags keep: their JSON of a big dump (izj,
# flj) runs to hundreds of MB, and the web UI filters and pages them from a copy of its own.
VIEW_ANSWER_MAX = 32 * 1024 * 1024
# The largest answer that a command covering one whole function keeps (pdfj, pdgj). Such an answer is
# decoded, parsed and turned into the view's own rows, which takes several times its size in the web UI
# (64 MB of pdfj measured at about 510 MB), so the backstop below would be far too much for one request
# on the VM's 8 GB. 64 MB is about 220 000 instructions in one function, while DISASSEMBLY shows 2000
# per page and rz-ghidra gives up long before that.
FUNCTION_ANSWER_MAX = 64 * 1024 * 1024
# The largest answer that every other command keeps: a backstop on the memory one answer can take in the
# web UI, far above what rizin answers to any of them. The function list reads afl's text (about 63 B per
# function, 80 times smaller than aflj's JSON) and is read row by row, a linear disassembly and a hexdump
# are bounded by the count the route asks for, and the lists of references (axtj, axfj, afxj) hold one
# line per reference, so nothing legitimate comes near it.
ANSWER_MAX = 256 * 1024 * 1024
MAX_CONSOLE_COMMAND = 2000
MAX_COMMENT = 500
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.@$:-]{0,127}$")
_STDERR_KEEP = 256 * 1024
# How much of stderr one command's answer keeps (RizinPipe.console): its first bytes, or its last ones for
# a run, whose reason for stopping comes after the warnings it floods stderr with.
_STDERR_PER_COMMAND = 64 * 1024
_MAX_MOVED = 256
_CREATE_NO_WINDOW = 0x08000000
_PROJECT_FAILED = "The saved project could not be loaded; it was kept as .rzdb.broken."
# What the session says about saved patches it could not apply, and about patches it could not save.
# Addresses the first note names before it says "...".
_NOTE_ADDRESSES = 5
_PATCHES_LOST = "{count} saved {patch} could not be applied to this file{where}."
# What a patch set over a run's bytes waits for, and the note that names it when the file is opened. The
# project keeps it, so does every save; it is written into the cache only when the bytes under it are a
# run's again, because a patch in the file's own (still encrypted) bytes is decrypted over by the next run.
_PATCH_WAITING_REASON = ("set over bytes an emulation run wrote; held back, because written into the file's own "
                         "bytes it would be decrypted over by the next run")
# Said as well where no map holds the address **now**. It is not "never": omlj at the open lists the file's
# maps only, and the ESIL stack's mem.* map arrives when the emulation starts (measured, rizin 0.9.1), so
# a patch in the stack's bytes can be held by a map later.
_PATCH_UNMAPPED_REASON = (" No map holds this address now: the file's maps do not cover it, but an emulation "
                          "maps memory of its own (its stack) when it starts, and the address may be in it then.")
_PATCHES_HELD = ("Held back, not applied: {count} saved {patch} over bytes an emulation run wrote ({where}). "
                 "The file's own bytes there are still encrypted, and a patch written into them would be "
                 "decrypted over by the next run.")
_PATCHES_DROPPED = ("{count} {patch} did not fit into the project ({chars} characters at most) and will "
                    "not come back when the file is opened again.")
# What the session says about the timeline of the emulation in the project: that a save could not keep it (it is
# not written in part: a timeline that ends where the budget did would replay to somewhere nobody named) -- either
# because the patches, which have the budget first, left too little, or because it is longer than the budget on its
# own --, that the one the project held was not used, and, at the open that follows a save that dropped it, that it
# was. A dropped patch is seen to be gone by the user who put it there; a dropped timeline is not, so the project
# keeps a marker (_RESTORE_DROPPED_MARK) in the place of its line, and the open says it (spec 1 and 4).
_RESTORE_DROPPED = ("The timeline of the emulation did not fit into the project (it shares {chars} characters "
                    "with the patches, and they come first) and was not saved: the way to the decrypted bytes "
                    "will not be there when the file is opened again.")
_RESTORE_TOO_LONG_ALONE = ("The timeline of the emulation did not fit into the project: on its own it is longer than "
                           "the {chars} characters a project keeps of it and the patches, so it was not saved and the "
                           "way to the decrypted bytes will not be there when the file is opened again.")
_RESTORE_REFUSED = ("The project's saved timeline of the emulation was not used: it is not exactly what this "
                    "version writes (edited, cut short, or from another version).")
_RESTORE_LOST_AT_OPEN = ("The project's timeline of the emulation could not be kept when the file was last saved (it "
                         "was too long for the room the project has): the way to the decrypted bytes is gone, and "
                         "decrypting again is the only way back.")
# What the project holds in the place of ``restore=``'s record when a save had to drop it. Not the shape of a record
# (they begin "1;"), so read_restore would refuse it, and _read_restore_line knows it for what it is. It is written
# only where the patches leave room for its own length: they have priority.
_RESTORE_DROPPED_MARK = "dropped"
# Why the timeline of an emulation session (RizinSession._restore) cannot be offered, or is gone. Said by the
# pane as they stand: a record that is tainted is never offered, whatever else is true of it.
_RESTORE_HAND_REGISTER = "a register was set by hand, which the timeline does not record"
_RESTORE_HAND_WRITE = "a console command wrote to the cache, which the timeline does not record"
_RESTORE_HAND_EMULATION = ("a console command set a register or stepped the emulation, which the timeline does "
                           "not record")
_RESTORE_HAND_SETUP = ("a console command armed the emulation, mapped its memory or set its PC, which the "
                       "timeline does not record")
_RESTORE_HAND_SETTING = ("a setting or a hint was changed while the timeline ran, and the timeline does not "
                         "record it")
_RESTORE_HAND_BREAKPOINT = "a breakpoint was changed, and a run stops at the breakpoints there are"
# What a project does not keep of the emulation **and a start does not undo**, so that a replay on a rizin of its
# own would not have it: a register and what a step left (measured on rizin 0.9.1: a start closes every ESIL map
# and runs aei, aeim and aepc, which put the PC at the seek and, with aeim, the stack and base pointer in its
# stack -- every other register is still there). Done by hand before the first start, it is held for the timeline
# that begins (_restore_pending). A write is caught by what the cache holds when the timeline begins, the
# settings, the hints and the breakpoints are in the project, and arming, mapping and the PC are done again by
# the start itself; _RESTORE_HAND_SETUP spoils a timeline in the middle of it, and nothing before it.
_RESTORE_BEFORE_START = (_RESTORE_HAND_REGISTER, _RESTORE_HAND_EMULATION)
_RESTORE_TIMEOUT = "a run ended at the time limit, a result that hangs on the clock and cannot be repeated"
_RESTORE_HALF = "an action failed half-way, after it had already changed the emulation or the cache"
_RESTORE_TOO_LONG = "an action was dropped: a project keeps {count} actions at most"
_RESTORE_UNREAD = "rizin did not say what the cache or the breakpoints held when the timeline began"
_RESTORE_FOREIGN = "the cache already held writes of its own when the timeline began, which no replay makes"
_RESTORE_GONE = ("something was taken out of the cache, so the way to the state it held is no longer "
                 "kept")
_RESTORE_RESTARTED = ("rizin was restarted, which emptied the cache the run had written to: the way to its "
                      "bytes can no longer be proven")
_RESTORE_NOTHING = "the run left nothing in the cache that a restore could bring back"
# Why the restore button refuses (RizinSession.restore_run), and what it says when a replay did not hold. The
# first group is said before anything was touched; the second after the replay was undone.
_RESTORE_NO_RECORD = "the project holds no timeline of the emulation to restore"
_RESTORE_RUNNING = ("the emulation is running: stop it first, because restoring starts it again from the "
                    "beginning of the timeline")
_RESTORE_CACHE = ("the write cache holds more or other than the patches the file was opened with (the timeline's "
                  "own run, a patch made since, or a write of the console), and replaying would take them away: "
                  "take back what was written since the file was opened, or open the file again")
_RESTORE_CACHE_UNREAD = "rizin did not say what the write cache holds"
_RESTORE_BREAKPOINTS = ("the breakpoints are not the ones the timeline ran under ({then} then, {now} now), and a run "
                        "stops at a breakpoint: a replay under another set would stop elsewhere and give other bytes")
_RESTORE_OTHER_BYTES = ("replaying the timeline left other bytes than the ones saved with it ({wrong} of {count} "
                        "saved ranges differ{more}{stopped}): nothing was applied, and the cache is as it was when "
                        "the file was opened")
_RESTORE_MIDWAY = ("the replay stopped at action {number} of {count} ({what}): {why}; nothing was applied, and the "
                   "cache is as it was when the file was opened")
_RESTORE_UNEXPECTED = "the replay could not go on ({why}); nothing was applied"
_RESTORE_STOPPED_AT_TIME_LIMIT = "it ended at the time limit, which a replay does not wait out again"
_RESTORE_NOT_PUT_BACK = (" -- the patches at {where} could not be written into the cache again and are kept in "
                         "the project, but not applied")
_RESTORE_WAITING_DROPPED = ("a patch the timeline makes was taken out of the project, and a replay would make it "
                            "again: the timeline is not kept")
_RESTORE_PATCH_TAKEN_BACK = ("a patch the timeline makes was taken back, and a replay would make it again: the "
                             "timeline is not kept")
_RESTORE_REGISTERS = ("rizin did not reset the registers ({pc}), so the replay would start from what an earlier run "
                      "left; nothing was applied")
_RESTORE_REGISTERS_UNDONE = " -- and rizin did not reset the registers either: they are what the replay left"
_RESTORE_OUT_OF_TIME = ("the replay stopped before action {number} of {count} ({what}): the {done} before it, "
                        "and what was written first, took the {budget:g} seconds a replay has; nothing was applied, "
                        "and the cache is as it was when the file was opened")
# How long one replay may take, from its first command (``wc-*``) to the last action, checked between the actions (so it is
# overshot by at most the action that was running: esil.timeout and its grace). What follows the last action is outside it:
# one ``wcj`` and the hashing for the proof, and the patches that waited, which are at most what 32 KB of project keep. Spec 6: the cap on the actions is the lever against a restore that takes minutes, and
# 500 runs of esil.timeout each is not that -- the request holds the gate like a console command, and has the time
# one has.
RESTORE_BUDGET = CONSOLE_TIMEOUT
_replay_clock = time.monotonic
_PATCH_NOT_WAITING = "no patch waits at {addr:#x}"
_PATCH_NOT_COVERED = ("no run's bytes lie under {addr:#x} (the cache holds none written by an emulation there), so "
                      "the patch would go into the file's own bytes and the next decryption would run over it: "
                      "run the decryption first, or take the patch out")
# The console commands that read what the emulation or the cache holds and change nothing of it; every
# other name of these families spoils the timeline (_console_spoils).
_SETUP_COMMANDS = frozenset(("aei", "aei-", "aeim", "aeim-", "aepc", "aeip"))
_READ_ONLY_COMMANDS = frozenset(("wc", "wcj", "ar", "arj", "ar*", "ar=", "arr", "arrj", "aer", "aerj", "aer*",
                                 "ahl", "dbl", "dblj", "dblq", "dbil"))
# While an analysis step holds rizin, a patch or a breakpoint goes through (it changes no bytes the step
# reads) but its project cannot be written yet, and the project is the only place it outlives the
# session. Said for as long as that is so (RizinSession.analysis), because closing the tab then loses it.
_WAITING_NOTE = ("A patch, a breakpoint or the timeline of the emulation is waiting to be saved; the project is "
                 "written when the analysis has finished.")
_FULL_NOTE = "Full analysis runs aaa's steps one by one; variables are analysed less than with aaa."
# What the status band says while the timeline of the emulation is not kept (spec 4: the Hinweisbox says why, and not
# only a dock the user may never open): the reason, as _restore_reason words it. Said while it is true, not stored, like
# the note above it: a breakpoint put back takes it away. The project may hold an earlier timeline all the same (a record
# that was clean when it was saved), and then the button of the pane still replays that one -- the second sentence.
_RESTORE_NOTICE = "The way to this state is not kept in the project: {reason}."
_RESTORE_NOTICE_EARLIER = " The project still holds an earlier timeline, which the restore button replays."
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


class _ReplayFailed(Exception):
    """A replay that did not hold, with the reason it says (RizinSession._restore_replay)."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


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

_FAMILIES = "apifCs/?xtbewd"
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
_DEBUG = "'d' commands are not allowed: emulation runs from the EMULATION tab"
# Refused inside the allowed families, matched at the start of the command name.
_REFUSED = [(re.compile(pattern), reason) for pattern, reason in (
    (r"aa", "whole-program analysis runs from the Full analysis button"),
    (r"agw", "'agw' writes files"),
    (r"agl", "'agl' reads the source files that the debug info names"),
    (r"aep(?!c$)", "'aep' commands are not allowed"),
    (r"ael", "'ael' loads ESIL interrupt plugins from files"),
    (r"aek", "'aek' runs SDB queries"),
    (r"aec[cs]|aesuo", "'aecc', 'aecs' and 'aesuo' ignore esil.timeout and run until rizin is killed: "
                       "TO CALL does this"),
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
    (r"wc[+i]|wcp", "'wc+', 'wci' and 'wcp...' commit the cache: they write into the file"),
    (r"w[aA]", _ASSEMBLE),
    (r"wu|wxf", "'wu' and 'wxf' read a file"),
    (r"wf[fs]", "'wff' and 'wfs' read a file or a socket"),
    (r"db[cCx]|dbi[cx]", "'dbc', 'dbC', 'dbx', 'dbic' and 'dbix' run rizin commands when a breakpoint hits"),
    (r"db[wW]", "'dbw' and 'dbW' set watchpoints, which hang rizin"),
)]
# The only `w` and `d` commands: writes that stay in the cache, and the breakpoint list. Any other name
# in these families is refused, the way `e` is.
_WRITE_NAMES = {
    "w", "wx", "wz", "wc", "wcj", "wc-", "wc-*",
    "wo", "wo2", "wo4", "wo8", "woa", "woA", "wod", "wol", "wom", "woo", "wor", "wos", "wox", "woe", "woD", "woE",
}
_BP_NAMES = {
    "db", "db-", "db-*", "db.", "dbl", "dblj", "dblq", "dbd", "dbe", "dbs", "dbn", "dbh",
    "dbi", "dbil", "dbi-", "dbie", "dbid", "dbis", "dbite", "dbitd", "dbits",
}
_EVAL_NAMES = {"e", "el", "elj", "elq", "ell", "elJ", "es", "et"}
_EVAL_REFUSED = [(re.compile(pattern), reason) for pattern, reason in (
    (r"ee", "'ee' opens an editor"),
    (r"e-", "'e-' resets the configuration"),
    (r"er", "'er' locks settings"),
    (r"echo|env|exit", _SHELL),
    (r"ec", "colour themes (ec) are not available"),
)]
# rizin 0.9.1 names the analysis settings analysis.*; anal.* is their older name.
_EVAL_SET_PREFIXES = ("asm.", "analysis.", "anal.", "esil.")
_EVAL_SET_KEYS = {"bin.demangle", "io.cache"}
_EVAL_SET_REFUSED = {
    # With it, the disassembly reads the source files that a sample's debug info names.
    "asm.debuginfo.file": "it reads source files",
    "asm.assembler": "an assembler can run an external program",
    "esil.mdev.range": "it is handled by a command hook",
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
    if name[0] == "w" and name not in _WRITE_NAMES:
        return f"'{_show(name)}' is not allowed: only writes that stay in the cache are available"
    if name[0] == "d" and name not in _BP_NAMES:
        return _DEBUG
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
            return f"only asm.*, analysis.*, esil.*, bin.demangle and io.cache can be set, not '{_show(key)}'"
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


def _console_statements(text):
    """The (name, arguments) of each statement of a console command, as the filter reads them: split at
    ``;``, quotes taken out, the name by ``_NAME_RE``; help (``name?``) and what has no name are left out."""
    for statement in text.split(";"):
        bare = statement.strip(" ").replace('"', "").replace("'", "")
        match = _NAME_RE.match(bare)
        if match and not match.group().endswith("?"):
            yield match.group(), re.split(r"[@~]", bare[match.end():], maxsplit=1)[0]


def _console_spoils(text):
    """Why a console command spoils the timeline of the emulation (RizinSession._restore), or None.

    The timeline holds what the emulation routes did and nothing else, so a console command that writes
    into the cache (every ``w`` but the two that list it), sets or drives the emulation (``ae*``: ``aeim``,
    ``aes``, ``aepc``; ``ar x=..``, ``aer x=..``), or **sets any setting** (``e <key>=<value>``) or a hint
    (``ah*``) is a change no replay makes. Any setting, not a list of the ones that matter: the list has to
    be kept (analysis.gp is ESIL's ``$gp`` on MIPS) and the ``=`` already says a set from a read. A name that
    is none of these reads, and spoils nothing: ``ar`` and ``ar rax`` show registers, ``wcj`` the cache.
    The filter has run already, so every statement is one it let through. A breakpoint is not in this: it
    spoils only if it stands between two actions (_console_moves_breakpoints).
    """
    for name, args in _console_statements(text):
        # A read-only name stays read-only without an ``=``. And a ``w`` name only without arguments: ``wc`` and ``wcj``
        # list the cache, but ``wc 0x1000`` and every other ``w`` with an argument takes an address, a hex string or a
        # file to write -- the argument is what makes it a write, and a list has none.
        if name in _READ_ONLY_COMMANDS and "=" not in args and (name[0] != "w" or not args.strip()):
            continue
        if name.startswith("wc-"):  # wc- and wc-* take writes out of the cache: no write of anybody's, a take-back
            return _RESTORE_GONE
        if name.startswith("w"):
            return _RESTORE_HAND_WRITE
        if name.startswith(("ae", "ar")):
            return _RESTORE_HAND_SETUP if name in _SETUP_COMMANDS else _RESTORE_HAND_EMULATION
        if name.startswith("ah") or (name == "e" and "=" in args):
            return _RESTORE_HAND_SETTING
    return None


def _console_moves_breakpoints(text):
    """Whether a console command may change the breakpoints (``db*`` but the lists)."""
    return any(name.startswith("db") and name not in _READ_ONLY_COMMANDS for name, _ in _console_statements(text))


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
        """Run a command; an answer of more than ``limit`` bytes (ANSWER_MAX by default) is read to its
        end and not kept (RizinTooLarge)."""
        limit = ANSWER_MAX if limit is None else limit
        self._send([text])
        data, cut = self._answer(time.monotonic() + timeout, limit)
        if cut:
            raise RizinTooLarge(f"rizin's answer to {text.split(' ', 1)[0]} is larger than {limit} bytes")
        return data.decode("utf-8", "replace")

    def cmdj(self, text, timeout=VIEW_TIMEOUT, limit=None):
        out = self.cmd(text, timeout, limit).strip()
        return json.loads(out) if out else None

    def console(self, text, timeout=CONSOLE_TIMEOUT, limit=CONSOLE_LIMIT, tail=False):
        """Run a console command; returns (stdout, stderr, truncated).

        stderr is cut to _STDERR_PER_COMMAND (64 KB): its first bytes, or with ``tail`` its last whole
        lines, which is where a command that floods stderr with warnings says why it stopped (an ESIL run).

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
        return kept.decode("utf-8", "replace"), self._stderr_until(err_start, err_marker, 2.0, tail), truncated

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

    def _stderr_until(self, start, marker, wait, tail=False):
        """What the command wrote to stderr, cut to _STDERR_PER_COMMAND: its first bytes, or with ``tail``
        its last ones.

        A tail begins from the first line boundary in it: a line cut in half matches nothing, and two things
        cut it. The slice itself starts anywhere, and the pipe's own buffer keeps only _STDERR_KEEP, so a
        command that wrote more than that has lost its first lines (``start`` is then before
        ``_err_dropped``) and what is left begins mid-line as well. The end needs no trim: with the marker
        found the text ends at a line boundary, and without it (the wait ran out) the unterminated last line
        is all there is of it.
        """
        deadline = time.monotonic() + wait
        with self._err_cond:
            while True:
                rolled = start < self._err_dropped
                text = bytes(self._err[max(0, start - self._err_dropped):])
                at = text.find(marker.encode())
                if at != -1:
                    text = text[:text.rfind(b"\n", 0, at) + 1]
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._threads[1].is_alive():
                    break
                self._err_cond.wait(remaining)
        if not tail:
            return text[:_STDERR_PER_COMMAND].decode("utf-8", "replace")
        if rolled or len(text) > _STDERR_PER_COMMAND:
            text = text[max(0, len(text) - _STDERR_PER_COMMAND):]
            text = text[text.find(b"\n") + 1:]  # no boundary at all: find gives -1, so the slice stays
        return text.decode("utf-8", "replace")


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


def _patch_words(count):
    """``count`` and the word for it, for the two notes about patches (_PATCHES_LOST, _PATCHES_DROPPED)."""
    return {"count": count, "patch": "patch" if count == 1 else "patches"}


def _named_addresses(addrs):
    """The addresses a note names, lowest first: the first _NOTE_ADDRESSES of them and "..." for the rest."""
    addrs = sorted(addrs)
    shown = ", ".join(f"{addr:#x}" for addr in addrs[:_NOTE_ADDRESSES])
    return shown + (", ..." if len(addrs) > _NOTE_ADDRESSES else "")


def _reason_words(reason):
    """A reason as the sentence that names it ends: without its closing stops and spaces. The pane (app.js,
    ``rizinEmuRestoreHtml``) ends the same reason with the same pattern, ``/[.\\s]+$/``, so that the sentence the band says
    and the one the dock would say are the same words and the dock can leave out the second one."""
    return re.sub(r"[.\s]+$", "", reason)


def _named_set(addrs):
    """A set of addresses for a sentence: "none", or _named_addresses."""
    return _named_addresses(addrs) if addrs else "none"


def _action_words(action):
    """An action of the timeline in a few words, for the reason a replay stopped at it. Numbers only: nothing of
    a project's text reaches a message."""
    kind = action["kind"]
    if kind == "start":
        return f"start at {action['addr']:#x}"
    if kind == "run":
        return f"run {action['run']}" + (f" {action['addr']:#x}" if action["run"] == "until" else "")
    if kind == "skip":
        return f"skip the call at {action['addr']:#x}"
    return f"patch at {action['addr']:#x}"


def _sanitize_project(src, dst, level, mode, done, patches, ranges=(), restore=None, restore_lost=False):
    """Copy a project written by ``Ps`` so that rizin 0.9.1 can load it again; (how many patches did not fit,
    whether ``restore`` did, whether it would have with the whole budget to itself).

    Loading a variable that came from DWARF looks up its DWARF entry, which
    the newly opened file does not have, and rizin then crashes on ``aflj``.
    Such variables become plain ones; those without a resolved location
    (shown as "@ ...") are left out. The analysis progress goes into an extra
    ``/tdc`` namespace, which rizin ignores.

    ``patches`` are the hand-made patches as (addr, after_hex, over_run), in the order rizin's write cache
    holds them, and they go into that namespace too: ``Ps`` saves the cache's bytes nowhere (measured, which
    is why they are kept here), and what a run wrote is no patch and is never passed in. Breakpoints
    need no line of their own: rizin's project holds them itself (/core/debug/breakpoints, measured).

    ``ranges`` are the addresses only an emulation run ever wrote (rizin_emulation.run_only_ranges);
    what the project says about them is dropped, see _run_only.

    ``restore`` is the timeline of the emulation (rizin_emulation.restore_line's record, digests and all) or
    None. It is written **after** the patches and spends what the patches line left of PROJECT_PATCH_CHARS;
    when that is not enough it is not written, whole -- the patches are the user's work and the timeline is
    the convenience (spec, section "Entscheidungen"). With no record there is no line at all, which is what
    a project from before the record is, and what _read_project_meta reads as none. A ``restore`` that is
    not a record the writer makes raises ValueError (_restore_record_for_save sees to it that it is one).

    A record that does not fit leaves ``_RESTORE_DROPPED_MARK`` in the line's place, so that the next open can say
    it was lost; ``restore_lost`` says the project already holds one (a save with no record of its own must not
    forget it). The marker is written whatever the patches leave: they come first for the budget, and the marker is
    a few characters over it at most.
    """
    namespace = None
    line_of_patches, left_out = _patches_line(patches)
    line_of_restore, fitted, alone = "", True, True
    room = PROJECT_PATCH_CHARS - len(line_of_patches)
    if restore is not None:
        # one build, against the whole budget: that it fits there is "alone", and that it is also no longer than
        # what the patches left is "fitted" -- the blame of the note needs both
        line_of_restore, alone = rizin_emulation.restore_line(restore, PROJECT_PATCH_CHARS)
        fitted = alone and len(line_of_restore) <= room
        if not fitted:
            line_of_restore = ""
    if not line_of_restore and (restore is not None or restore_lost):
        # whatever the patches left: they have the budget first, and the marker is seven characters over it at most, which the
        # 64 KB the project is read from has to spare -- a record that was lost and is not said at the next open is the silence it is for
        line_of_restore = _RESTORE_DROPPED_MARK
    with open(src, encoding="utf-8", errors="surrogateescape", newline="\n") as fin, \
            open(dst, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as fout:
        for line in fin:
            line = line.rstrip("\n")
            if line.startswith("/"):
                namespace = line
            elif ranges and _run_only(namespace, line, ranges):
                continue
            elif namespace == "/core/analysis/functions" and '"DWARF"' in line and "=" in line:
                line = _plain_vars(line)
            fout.write(line + "\n")
        fout.write(f"\n/tdc\nlevel={level}\nmode={mode}\ndone={','.join(done)}\n"
                   f"patches={line_of_patches}\n")
        if line_of_restore:
            fout.write(f"restore={line_of_restore}\n")
    return left_out, fitted, alone


# The flag spaces rizin's own analysis and search fill: a function's flag and the string search's hits.
# A flag of any other space at such an address (a symbol, a section, the emulator's register flags) is
# the file's or the emulation's and is left as it is.
_PROJECT_RUN_SPACES = ("functions", "search")
_PROJECT_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{1,16}")


def _run_only(namespace, line, ranges):
    """Whether this line of a project says something about bytes only an emulation run ever wrote.

    rizin's ``Ps`` keeps what a range re-analysis found -- measured: after an ``af`` over decrypted
    bytes the project holds the function in /core/analysis/functions, its name as a flag of the
    "functions" space and the search's hits as flags of the "search" space, and reopening the
    **untouched** sample with that project lists "0x00001000 1 12 fcn.00001000" while the bytes there
    disassemble as "invalid". Those bytes are gone with the write cache, so the project must not carry
    what was read from them.

    Dropped are a function whose entry address is in ``ranges`` and a flag of rizin's analysis or
    search spaces there. The rule needs nothing remembered between saves and corrects itself: an
    address a patch of this session covers is not in ``ranges`` (run_only_ranges takes it out), because
    those bytes do come back, so the function over them rightly stays. A basic block left in
    /core/analysis/blocks is not dropped: no view shows it, dropping one could break a function that
    begins outside the range, and a block without a function changes nothing rizin lists (measured).
    """
    key, sep, value = line.partition("=")
    if not sep:
        return False
    if namespace == "/core/analysis/functions":
        return bool(_PROJECT_ADDR_RE.fullmatch(key)) and rizin_emulation.in_ranges(int(key, 16), ranges)
    if namespace == "/core/flags/flags":
        try:
            flag = json.loads(_sdb_unescape(value))
        except ValueError:
            return False
        return (isinstance(flag, dict) and flag.get("space") in _PROJECT_RUN_SPACES
                and rizin_emulation.in_ranges(flag.get("offset"), ranges))
    return False


def _patches_line(patches):
    """The value of the ``patches=`` line ("<addr>:<hex>[:r],..."), and how many patches did not fit into
    PROJECT_PATCH_CHARS. The ones that fit are the first ones, so the list stays in the cache's order:
    replaying it in another order could put a different byte where two writes overlap.

    ``patches`` are (addr, after_hex, over_run). ``:r`` marks a patch set over bytes a run had written
    (see _read_patches); the budget counts the entry as it is written, mark included."""
    kept, used = [], 0
    for index, (addr, after, over_run) in enumerate(patches):
        entry = f"{addr:x}:{after}" + (":r" if over_run else "")
        if used + len(entry) + (1 if kept else 0) > PROJECT_PATCH_CHARS:
            return ",".join(kept), len(patches) - index
        used += len(entry) + (1 if kept else 0)
        kept.append(entry)
    return ",".join(kept), 0


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
        return {"level": None, "mode": None, "done": [], "patches": [], "restore": None, "restore_refused": False,
                "restore_dropped": False}
    meta = {}
    at = tail.rfind("\n/tdc\n")
    if at != -1:
        for line in tail[at + 6:].splitlines():
            if line.startswith("/"):
                break
            key, _, value = line.partition("=")
            meta[key] = value
    record, refused, dropped = _read_restore_line(meta.get("restore", ""))
    return {"level": meta.get("level") if meta.get("level") in ("aa", "aaa") else None,
            "mode": meta.get("mode") if meta.get("mode") in ("one", "steps") else None,
            "done": [s for s in meta.get("done", "").split(",") if s in _ALL_STEPS],
            "patches": _read_patches(meta.get("patches", "")),
            "restore": record, "restore_refused": refused, "restore_dropped": dropped}


# One patch of the /tdc namespace: the address in hex (up to 2^64-1) and the bytes it wrote, as the
# write cache reports them. Anything else -- a line from a newer version, a half-written one -- is left out.
# One ``addr:hex[:r]`` entry of the project's patches line. The hex is bounded only by the line's own
# budget (PROJECT_PATCH_CHARS), not by MAX_PATCH_BYTES: an entry that is too long to write is still
# read, so that _replay_patches can **name** it in the session's note instead of it disappearing. A
# project from a build whose bound was higher holds such entries (2001 to 2035 bytes could be written
# before the bound was corrected), and losing a patch without a word is what Task 6's note exists for.
# ``:r`` says the patch was set over bytes an emulation run had written. An entry without it comes from a
# project written before the mark existed, and it is read as not over a run -- which is how it was applied
# then, so such a project is not devalued by the mark.
_TDC_PATCH_RE = re.compile(r"([0-9a-f]{1,16}):((?:[0-9a-f]{2})+)(:r)?")


def _read_restore_line(text):
    """The ``restore=`` line as (record, refused, dropped): the record, or None; whether a line was there that is
    not one; and whether it is the marker a save left for a record it had to drop. No line (or an empty one) is
    no record and neither of the others.

    The line is hostile input (the project is a file a user can edit), so it passes the same cap as the
    patches line before anything parses it -- a save never writes more than PROJECT_PATCH_CHARS of it, so a
    longer one is not one -- and then ``read_restore``, which answers None for anything but exactly what
    ``restore_line`` writes. It builds every action of the line before it checks the count, so the cap is
    the only brake on what a long line costs."""
    if not text:
        return None, False, False
    if text == _RESTORE_DROPPED_MARK:
        return None, False, True
    record = None if len(text) > PROJECT_PATCH_CHARS else rizin_emulation.read_restore(text)
    return record, record is None, False


def _read_patches(text):
    """The ``patches=`` line as [(addr, after_hex, over_run)], dropping every entry that is not one.

    Read at most as much of the line as a save would have written (PROJECT_PATCH_CHARS), so that a
    project edited by hand cannot make the next boot send tens of thousands of ``wx`` commands. Where
    that slice cuts, its last entry goes: half of ``140001000:909090`` is ``140001000:9090``, which
    parses -- and would be applied as a different, shorter patch without a word about it.
    """
    read = text[:PROJECT_PATCH_CHARS]
    entries = read.split(",")
    if len(read) < len(text):
        entries.pop()
    found = []
    for entry in entries:
        shape = _TDC_PATCH_RE.fullmatch(entry)
        if shape:
            found.append((int(shape.group(1), 16), shape.group(2), shape.group(3) is not None))
    return found


_HINT_LINE_RE = re.compile(r"\s*(0x[0-9a-fA-F]+) =>(.*)")


def _make_safe(pipe, arch):
    """Set back what a project brings with Poo that would run a program or a command.

    The settings come back as they were saved: an arch plugin or an assembler that hands its work to
    nasm or as, the command hooks (cmd.*), the pager, the editor. An arch hint switches asm.arch while
    the disassembly passes it, and an ESIL hint with "#!" runs a rizin command. A breakpoint carries a
    command (``dbc``) and a condition (``dbC``) that rizin runs when it hits, and the project stores
    both verbatim (measured). ``arch`` is the one rizin chose for the file before Poo. False if the
    project is not safe afterwards.
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
    return _arch_is_safe(pipe) and _disarm_breakpoints(pipe)


def _disarm_breakpoints(pipe):
    """Take the command and the condition off every breakpoint the project brought back; False if that
    cannot be shown to have worked.

    Measured with rizin 0.9.1: ``dbc CC pwned`` puts the command into ``dblj``'s ``data``, ``dbC`` its
    expression into ``cond``, ``Ps`` writes both into /core/debug/breakpoints verbatim and ``Poo``
    brings them back -- a rizin command out of a file, in a web UI that runs as SYSTEM. The console
    cannot set one (dbc, dbC and dbx are refused there), so a project is the way in, which is what the
    cmd.* hooks and the "#!" hints above are reset for as well. ``dbc ""`` and ``dbC ""`` empty the two
    fields (measured; ``dbc`` without an argument leaves them as they are), and the list is read again
    afterwards: a project whose breakpoints cannot be shown to be harmless is not used at all, like one
    whose arch is not safe.
    """
    try:
        armed = [addr for addr, command in _breakpoint_commands(pipe) if command]
        for addr in armed:
            pipe.cmd(f'dbc "" @ {addr:#x}')
            pipe.cmd(f'dbC "" @ {addr:#x}')
        return not armed or not any(command for _, command in _breakpoint_commands(pipe))
    except ValueError:
        return False


def _breakpoint_commands(pipe):
    """(addr, what rizin would run) for every breakpoint of ``dblj``; ValueError for an answer in a
    shape nobody knows, which the caller treats as a project it cannot make safe."""
    found = pipe.cmdj("dblj")
    if found is None:
        return []
    if not isinstance(found, list):
        raise ValueError("dblj did not answer a list of breakpoints")
    rows = []
    for row in found:
        if not (isinstance(row, dict) and isinstance(row.get("addr"), int) and not isinstance(row["addr"], bool)):
            raise ValueError("dblj did not answer a list of breakpoints")
        rows.append((row["addr"], f"{row.get('data') or ''}{row.get('cond') or ''}"))
    return rows


def _arch_is_safe(pipe):
    return all(pipe.cmd("e " + key).strip() in _SAFE_ARCHES for key in ("asm.arch", "analysis.arch"))


# --- Sessions ---------------------------------------------------------------

def _first_line(text):
    """The first line of rizin's output that holds something, without its spaces, tabs and "\\r" around.

    Only "\\n" ends a line here: a function name may hold \\x85, U+2028 or U+2029, which str.splitlines()
    breaks at and str.strip() takes off, and rizin prints such a name as it is (see _rizin_functions in
    app.py, which reads afl's rows the same way).
    """
    for line in text.split("\n"):
        if line.strip(" \t\r"):
            return line.strip(" \t\r")
    return ""


def _afl_line(text):
    """The address and the name of rizin's ``afl.`` answer: ("0x…", name), both empty if it has neither.

    Split at the column separator only, never at arbitrary whitespace: str.split() would read a name's
    leading \\x85, U+2028, U+2029 or "\\r" as part of the separator, and the function list (afl's rows,
    see _rizin_functions in app.py) and a rename's answer keep such a character. Partitioning also means
    there is nothing to index, so a line without an address gives ("", ""), not an IndexError.
    """
    address, _, name = _first_line(text).partition(" ")
    return address, name.lstrip(" \t")


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
        self._waiters = 0
        self._due = False
        self.closed = False

    def enter(self, label, wait):
        with self._cond:
            if (self.holder is not None or self._due) and not self.closed:
                self._waiters += 1
                try:
                    free = self._cond.wait_for(lambda: self.closed or (self.holder is None and not self._due),
                                               timeout=wait)
                finally:
                    self._waiters -= 1
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
            self._cond.wait_for(lambda: self.closed or (self.holder is None and self._waiters == 0),
                                timeout=max(0.0, end - time.monotonic()))
            return not self.closed

    def enter_analysis(self, label, after_gap=False):
        """Take the pipe for an analysis step. Requests that wait go first, unless the step comes after
        hold_off: the gap gave them their turn, now they wait for the step."""
        with self._cond:
            if after_gap:
                self._due = True
            try:
                self._cond.wait_for(lambda: self.closed or (self.holder is None and (after_gap or self._waiters == 0)))
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
        self._dropped_noted = False
        self._run_started = self._run_finished = None
        # The emulation: the pipe it was started on (None: not started), the registers before and after
        # the last change (for "changed"), the file's byte order for the stack words and aeim's stack map
        # as (from, to, name).
        self._emulation = None
        self._emulation_before = self._emulation_after = None
        self._emulation_big_endian = False
        self._emulation_stack_map = None
        # Every range the ESIL VM has had memory in during this session, as (from, to): the stack of
        # each start and every buffer the assistant mapped. The write cache keeps a run's rows after
        # a stop, which unmaps the memory, so the live map list alone cannot tell afterwards that a
        # pushed word was no code -- and that is what the range of a re-analysis rests on (_run_range).
        self._emulation_ranges = []
        # The API assistant's own counters, which belong to the run: the clock it answers GetTickCount
        # and the performance counter with (it has to rise, or a timing check sees no time pass) and
        # how far each pseudo series has been used, so that two handles or two addresses can be told
        # apart. All three move only where a skip **applies** a value (R38): asking what a call could
        # answer must not change what it answers, because the run line asks on every step.
        self._assist_tick = rizin_emulation.TICK_START
        self._assist_handle = self._assist_pseudo = 0
        # This session's own writes through patch/patch_op, in the order it made them (rizin_emulation.
        # cache_entry). rizin has one write cache, which holds an emulation run's writes too and cannot
        # tell them apart; this mirror can, row by row (see patches). _lost: patches a restarted rizin
        # could not take back, which the project keeps all the same (see _saved_cache).
        self._mine = []
        # _mine's entries again, as over_run: whether each was set over bytes a run had written, as the
        # last read of the cache said (_patch_list). Kept beside the mirror because that is all there is
        # of it once a rizin has stopped, and _recover must tell the patches it may write from those it may not.
        self._mine_over = []
        self._lost = []
        # Patches held back (_replay_patches), as (addr, after_hex, True): in the project and not in the
        # cache, and every save keeps them as it keeps _lost.
        self._waiting = []
        # The timeline of this session's emulation, which a project can keep as the way to the bytes a run
        # decrypted (see _restore_start): None before the first start and after something was taken out of
        # the cache, then why (_restore_gone).
        self._restore = None
        self._restore_gone = None
        # What was done by hand to the emulation before the first start, for the timeline that begins
        # (_RESTORE_BEFORE_START), and whether the breakpoints stand other than the timeline began with.
        self._restore_pending = None
        self._restore_bp_moved = False
        # The record the project is to hold: the one it was opened with, and every clean one a save has asked
        # since. It is what a save writes when the timeline has nothing newer to say (_restore_record_for_save),
        # so a rizin that restarted, an unpatch or a session that never emulated leave the project's line
        # alone. With its digests, as the project holds it. Not the live timeline: that is ``_restore``, and the
        # digests of it are made when a save reads the cache.
        #
        # It is set when the save is **asked**, not when it is written, and so it can say something the project
        # does not hold for as long as a line did not fit (_finish_save then leaves the marker, and the next save
        # asks again, when the budget may allow it). That was chosen over setting it in _finish_save, which
        # would lose the retry for a session whose record was dropped and whose timeline is then gone, and it is
        # harmless to the replay: that runs on a reopened file, whose project holds a line or does not, and
        # the originating session's cache is not "nothing but the applied patches" (spec 6) for it to run in.
        # ``_restore_lost``: the project held the marker of a dropped record when it was opened. It matters until a
        # record is saved (then ``_restore_saved`` is set and a save writes that or, if it does not fit, the marker
        # again), so it is read at the open and never changed. The note the open made of it is retracted by
        # _note_restore when a record fits.
        self._restore_saved = None
        self._restore_lost = False
        self._restore_dropped_note = None
        # What the cache held when the file was opened, or when rizin was restarted (_opened: this session's own
        # writes as the mirror has them, in the order they were made in), and whether a timeline is being
        # replayed this moment (restore_run), which nothing may record.
        self._opened = []
        self._replaying = False
        # Notes that outlive a re-plan: what the session starts with (a project that could not be
        # loaded, patches that could not be applied) and the standing warning that patches did not fit
        # into the project. _start_analysis plans again and drops the notes of the run before it; these
        # are still true afterwards, and the budget warning is the only signal that what the pane calls
        # "kept with the project" is not all of it.
        self._kept_notes = []
        self._pipe, contained, level, mode, note, patches, saved_restore = self._boot()
        try:
            self._read_file_info()
            self._where(self._pipe)
            # Before the analysis and before the first view: the patched bytes are what rizin reads from
            # here on, so the first disassembly and the first hexdump already show them.
            patch_note = self._replay_patches(patches)
            self._opened = list(self._mine)
        except BaseException:
            self._pipe.close()
            raise
        self._done = list(contained)
        self.level = level or self.level
        self._mode = mode or self._mode
        self._restore_saved, restore_refused, self._restore_lost = saved_restore
        # in the order of what costs the user most: a project that could not be loaded, patches that were not
        # applied or are held back, a timeline that was not used or was lost
        for text in (note, patch_note, _RESTORE_REFUSED if restore_refused else None,
                     _RESTORE_LOST_AT_OPEN if self._restore_lost else None):
            if text:
                self._kept_notes.append(text)
        self._notes += self._kept_notes
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
            # Said while it is true, not stored: a patch or breakpoint made during an analysis step
            # cannot be written before the step lets go of the pipe, and the project is the only place
            # it would survive the session. The note goes as soon as the save is through.
            # After the notes of the open (the patches are the user's work, and what happened to them comes first) and
            # before the one that cannot wait. It needs no pipe: the record's own taint, and what a console did to it.
            lost = self._restore_reason()
            if lost:
                # The second sentence is a statement about the **project**, and ``_restore_saved`` is not one: it is set when a
                # save is asked, so after a record that did not fit it is the record the session would keep while the project
                # holds the marker (``_restore_dropped_note`` is set exactly then, and goes when a save fits it again)
                held = self._restore_saved is not None and self._restore_dropped_note is None
                notes = notes + [_RESTORE_NOTICE.format(reason=_reason_words(lost)) + (_RESTORE_NOTICE_EARLIER if held else "")]
            if self._dirty and self._state == "running":
                notes = notes + [_WAITING_NOTE]
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

    def json(self, cmd, wait=2.0, timeout=VIEW_TIMEOUT, limit=None):
        """Run a JSON command built by the web UI. User input goes through console(). An answer over
        ``limit`` (ANSWER_MAX by default; the list views pass VIEW_ANSWER_MAX, the views of one function
        FUNCTION_ANSWER_MAX) raises RizinTooLarge; the session goes on."""
        return self._call("view", wait, lambda pipe: pipe.cmdj(cmd, timeout, limit))

    def text(self, cmd, wait=2.0, timeout=VIEW_TIMEOUT, limit=None):
        """Like json() for a command whose output is text."""
        return self._call("view", wait, lambda pipe: pipe.cmd(cmd, timeout, limit))

    def console(self, text, wait=2.0):
        reason = check_console_command(text)
        if reason:
            raise RizinRefused(reason)
        annotates = _annotates(text)
        if annotates:
            self._refuse_while_analysing()
        spoils, moves = _console_spoils(text), _console_moves_breakpoints(text)

        def run(pipe):
            if annotates:
                self._refuse_while_analysing()
            if spoils:
                self._restore_taint(spoils)  # before it runs: what a command did before it failed is done
            if moves and self._restore is not None:
                self._restore_bp_moved = True  # likewise; what the set is is read back below, once it has run
            pipe.cmd("e scr.color=3")
            out, err, truncated = pipe.console(text)
            pipe.cmd("e scr.color=0")
            if moves:
                self._restore_observe(pipe)
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
            # rizin 0.9.1's afn renames only at a function's start: the function around addr by its entry.
            try:
                entry = int(_afl_line(pipe.cmd(f"afl. @ {addr:#x}"))[0], 16)
            except ValueError:
                raise RizinRefused(f"there is no function at {addr:#x}") from None
            # In single quotes the name's @ $ : stay text.
            pipe.cmd(f"afn {_rz_quote(name)} @ {entry:#x}")
            offset, new_name = _afl_line(pipe.cmd(f"afl. @ {entry:#x}"))
            self._where(pipe)
            return {"offset": int(offset, 16), "name": new_name}

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

    def emulation_start(self, addr=None, wait=2.0):
        """Start the emulation (ESIL) at ``addr``, the current seek if None: io.cache and the guards
        (ESIL_SETTINGS) in one ``e``, io.cache read back, then aei, aeim and aepc. Returns the state.

        A start while one runs gives the ESIL memory of the run before it back first
        (_emulation_unmap), so that the stack is mapped where ESIL_STACK_ADDR says and nothing of the
        last run is left mapped. Without that sweep rizin 0.9.1 maps a **second** stack at an address
        of its own once the assistant has mapped a buffer (measured: esp = 0x10078000 beside a live
        mem.0x100000_0xf0000), and the orphan stays for the session. The other registers keep their
        values: rizin's aei does not reset them (measured: rcx=0x1234 survived aeim-; aei; aeim).
        """
        if addr is not None:
            addr = _address(addr)
        return self._call("emulation", wait, lambda pipe: self._emulation_started(pipe, addr))

    def _emulation_started(self, pipe, addr):
        """The start itself (gate held): what emulation_start does, and what a replay does for a ``start``
        action. ``addr`` None is the current seek."""
        self._emulation = None
        pc = self.at if addr is None else addr
        if pc is None:
            raise RizinRefused("addr is missing: the session has no current address")
        pipe.cmd("e " + " ".join(ESIL_SETTINGS))
        self._require_io_cache(pipe)
        self._emulation_unmap(pipe)
        pipe.cmd("aei")
        pipe.cmd("aeim")
        pipe.cmd(f"aepc {pc:#x}")
        stack = rizin_emulation.stack_map(pipe.cmdj("omlj"), self._emulation_role(pipe, "SP"),
                                          ESIL_STACK_SIZE)
        if stack is None:
            raise RizinRefused("rizin could not map the emulation's stack (aeim)")
        self._emulation_stack_map = stack
        self._emulation_remember(stack[0], stack[1])
        self._emulation_big_endian = pipe.cmd("e cfg.bigendian").strip() == "true"
        self._emulation_before = self._emulation_after = None
        self._emulation = pipe
        self._restore_start(pipe, pc)  # before the read: a read that fails leaves the emulation started
        return self._emulation_read(pipe)

    def emulation_stop(self, wait=2.0):
        """Leave the emulation: its memory is unmapped (_emulation_unmap). The cache's writes stay
        (they are the patches)."""
        def run(pipe):
            if self._emulation is pipe:
                self._emulation_unmap(pipe)
            self._emulation = None
            return {"running": False}

        return self._call("emulation", wait, run)

    def _emulation_unmap(self, pipe):
        """Give the ESIL VM's memory back (gate held): the assistant's buffers first, the stack last.

        **Not** with rizin's own ``aeim-``, which cannot do it (all measured on 0.9.1): it drops the
        map it made last, and once an ``aeim <addr> <size> <name>`` has existed it can never name the
        stack map again -- it says "cannot deinitialize mem.0x10000000_0xf0000" and leaves the stack
        mapped, whether the buffers went first with ``om-``, with ``o-`` or not at all. A plain
        ``aeim`` then maps a *second* stack somewhere else and keeps the orphan.

        Closing the file descriptor of each of those maps (``o- <fd>``) removes the map **and** frees
        its memory (measured: ``ol`` loses the malloc:// entry, while ``om-`` keeps it), and a start
        after that maps the stack at esil.stack.addr again, exactly like a first one. Only descriptors
        that no map outside ``mem.*`` uses are closed, so the sample's own descriptor is never touched.
        """
        maps = pipe.cmdj("omlj")
        # the record is all that is left once these maps are closed, and a region the console mapped
        # (``aeim`` is allowed there) is in the map list but in no record yet (measured: a write into
        # one became "the range the run wrote" after a stop)
        for low, high in rizin_emulation.esil_ranges(maps):
            self._emulation_remember(low, high)
        for fd in rizin_emulation.esil_fds(maps):
            pipe.cmd(f"o- {fd}")
        self._emulation_stack_map = None

    def _emulation_remember(self, low, high):
        """Keep (low, high) as a range the ESIL VM had memory in; see _emulation_ranges. Each range is
        kept once, and nothing is ever taken out: a byte that was in the emulation's own memory is no
        byte of the file, whether or not the memory is still mapped."""
        if (low, high) not in self._emulation_ranges:
            self._emulation_ranges.append((low, high))

    # --- The timeline of the emulation --------------------------------------
    #
    # What the project can keep of a run is the way to its bytes (rizin_emulation: the timeline of a restorable
    # session). It is written here while the user works, by the methods that run the emulation, and only by
    # them: ``self._restore`` is None before the first start, or
    #
    #   {"counters": {"tick", "handle", "pseudo"},  the assistant's counters when the timeline began
    #    "breakpoints": [addr, ...],                the breakpoints it began with, for all of it
    #    "actions": [action, ...],                  as rizin_emulation describes them, in the order made
    #    "tainted": str | None}                     why it cannot be offered, the first reason there was
    #
    # which is a record without its digests (made at save time, while the cache is alive:
    # _restore_digests). Everything is done with the gate held, so the order of the actions is the order of
    # the requests. What the pane is told, and what a save has to ask, is _restore_reason: the record's own
    # taint, and a breakpoint that stands other than the timeline began with, which is not the record's.
    #
    # Recording is a side effect and never fails an action: it reads only where a timeline begins and where
    # a console db may have changed the breakpoints, and what it cannot read taints the timeline instead of
    # raising.

    def _restore_start(self, pipe, pc):
        """The emulation started at ``pc`` (gate held): the first start of the session begins the timeline,
        a later one is an action of it -- aei, aeim and aepc replay like any other. Not while a timeline is being
        replayed (restore_run): the replay is not an action of anybody's, and a start that began a timeline
        would record the replay as it goes."""
        if self._replaying:
            return
        if self._restore is None:
            self._restore = self._restore_begin(pipe)
            self._restore_gone = None
        self._restore_add({"kind": "start", "addr": pc})

    def _restore_begin(self, pipe):
        """A new timeline (gate held), at the state the replay will start from: the assistant's counters, the
        breakpoints, and tainted when something was done by hand to the emulation before (_restore_pending),
        or the cache already holds writes that no replay makes (a console ``wx`` before the start: they
        would be hashed as the run's).

        Only what a project could not make of a wrong answer is caught here: a ``ValueError`` or a
        ``RizinTooLarge`` of the two reads taints the timeline, and the start goes on. A ``RizinTimeout`` or a
        ``RizinDied`` is **not** caught on purpose: rizin has been killed or is gone, so the session ends
        (_call) as it does for every other command, and a start that answered "done" on a dead pipe would be
        the lie this guards against.

        **The read of the cache here has effects**: ``_patch_list`` rewrites the mirror of the session's own writes
        and is where a take-back is noticed, so it can drop ``_restore_saved`` (_restore_saved_without). It is a
        read of rizin and a step of the bookkeeping at once, and nothing may be put between it and the start that
        takes the record to be what it was."""
        pending, self._restore_pending, self._restore_bp_moved = self._restore_pending, None, False
        unread = foreign = False
        try:
            points = sorted({found["addr"] for found in self._breakpoint_list(pipe)})
            foreign = any(not row["mine"] for row in self._patch_list(pipe))
        except (ValueError, RizinTooLarge):
            points, unread = [], True
        return {"counters": {"tick": self._assist_tick, "handle": self._assist_handle,
                             "pseudo": self._assist_pseudo},
                "breakpoints": points, "actions": [],
                "tainted": pending or (_RESTORE_UNREAD if unread else _RESTORE_FOREIGN if foreign else None)}

    def _restore_add(self, action, timed_out=False):
        """Append ``action`` to the timeline (gate held), when there is one. A run that ended at the time
        limit is on it all the same -- and spoils it: its result hangs on the clock. So does a breakpoint
        that stood other than the timeline began with when the action ran (_restore_breakpoints)."""
        record = self._restore
        if record is None:
            return
        if self._restore_bp_moved:
            self._restore_taint(_RESTORE_HAND_BREAKPOINT)
        if len(record["actions"]) >= rizin_emulation.RESTORE_MAX_ACTIONS:
            self._restore_taint(_RESTORE_TOO_LONG.format(count=rizin_emulation.RESTORE_MAX_ACTIONS))
        else:
            record["actions"].append(action)
        if timed_out:
            self._restore_taint(_RESTORE_TIMEOUT)
        if record["tainted"] is None:
            # The record is a change of the project like a patch is: a session that only ran the emulation and
            # closed would otherwise write none. Debounced as every other (SAVE_DELAY), so single-stepping asks
            # once. A timeline that cannot be offered has nothing new for a save to say.
            self._schedule_save()

    def _restore_taint(self, reason):
        """Say that the timeline cannot be offered (gate held); the first reason stays. With no timeline
        there is nothing to spoil, except what a project does not keep of the emulation, which is held for
        the timeline that begins."""
        record = self._restore
        if record is None:
            if reason in _RESTORE_BEFORE_START and self._restore_pending is None:
                self._restore_pending = reason
        elif record["tainted"] is None:
            record["tainted"] = reason

    def _restore_discard(self, reason=_RESTORE_GONE):
        """Drop the timeline (gate held): bytes were taken out of the cache, so the actions no longer make
        the state it holds, and a recipe for a state that is gone is worse than none. A session that never had
        a timeline has nothing to lose, and says nothing."""
        if self._restore is not None:
            self._restore, self._restore_gone, self._restore_bp_moved = None, reason, False

    @contextlib.contextmanager
    def _restore_guard(self):
        """Around the part of an action that changes the emulation or the cache (gate held): one that fails
        in it has changed something the timeline will not name, so the timeline is spoiled and the failure
        goes on."""
        try:
            yield
        except BaseException:
            self._restore_taint(_RESTORE_HALF)
            raise

    def _restore_breakpoints(self, found):
        """``found`` are the breakpoints rizin holds now (gate held): whether they are other than the ones the
        timeline began with. That is not a taint yet: a breakpoint taken out and put back between two actions
        changes nothing, and a run is the only thing that stops at one. It becomes one when an action follows
        (_restore_add); until then it is only said (_restore_reason)."""
        record = self._restore
        if record is not None:
            self._restore_bp_moved = sorted({b["addr"] for b in found}) != record["breakpoints"]

    def _restore_observe(self, pipe):
        """Read the breakpoints back after a console ``db`` (gate held). A set that cannot be read counts as
        changed, until one is."""
        if self._restore is None:
            return
        try:
            self._restore_breakpoints(self._breakpoint_list(pipe))
        except (ValueError, RizinTooLarge):
            self._restore_bp_moved = True

    def _restore_reason(self):
        """Why the timeline is not to be offered now, or None (the record's own taint, then a breakpoint that
        stands other than it began with). After a discard, why it is gone. What the cache can prove is not
        in it: that needs rizin (_restore_offered)."""
        record = self._restore
        if record is None:
            return self._restore_gone
        return record["tainted"] or (_RESTORE_HAND_BREAKPOINT if self._restore_bp_moved else None)

    def _restore_digests(self, pipe, rows=None):
        """What the record would prove right now (gate held): the SHA-256 of what the run left in each range,
        read from the cache while it is alive (rizin_emulation.run_digests, over the rows in the order they
        were written). The save writes these, and an empty answer is the cache having nothing of a run.

        ``rows`` are the cache's rows **in write order** (``_patch_list(pipe, ordered=True)``) where the caller
        has read them already: the save does, and a second ``wcj`` of megabytes would be for nothing. Rows by
        address are not what this wants and run_digests cannot tell (spec 5): the one place that hands them over
        is _saved_cache, and tests/test_rizin.py pins what the save writes."""
        if rows is None:
            rows = self._patch_list(pipe, ordered=True)
        return rizin_emulation.run_digests(rows, rizin_emulation.run_only_ranges(rows))

    def _restore_offer(self, wait=2.0):
        """What the pane needs to offer the restore button, or to say why not: {"actions", "reason", "digests",
        "refused"}. GET /patches carries it as ``restore`` (_patches_answer, which is the production reader: this method is
        the same answer asked for by itself, for the tests, and is private for that). Two questions, two fields:

        ``reason`` is why the **timeline** cannot be offered -- the record's own taint, the thing spec 4's notice says:
        a hand-set register, a console write, a run that hit the time limit, a breakpoint that is not the one the
        timeline began with, a rizin that was restarted, something taken out of the cache, or that a restore would
        bring back nothing (no range for ``digests``). None where it can. It is the field the record's taint reaches the
        pane by, and nothing else carries it.

        ``refused`` is why **POST /restore would refuse now**, in the words it refuses with (_restore_refusal), or
        None where it would run: no timeline in the project, an emulation that runs (also the adopted timeline of a
        replay that has just held), a cache that is not the one from opening, other breakpoints than the timeline
        ran under. The button is enabled by ``refused`` being None and says ``refused`` when it is not. A session
        with no timeline of its own that holds the project's has no taint to report: its ``reason`` is None.

        ``actions`` and ``digests`` are not the same figures in the two cases:

        * A session that has run a timeline of its own (``_restore``) answers for **that**: ``digests`` is how
          many ranges the record would prove **right now**, from the cache as it is -- a timeline whose cache has
          lost the run's bytes says 0.
        * A session with none of its own that holds the project's (a file just opened, or a rizin that was
          restarted) answers for **that one**: what the record stores, which is what a replay will be held to.

        It asks rizin (one ``wcj``, and ``dblj`` where the project holds a record), so it waits for the gate like any
        view (RizinBusy); with no timeline of either kind it asks nothing and takes no gate."""
        if self._restore is None and self._restore_saved is None:
            return self._restore_offered(None, None)
        return self._call("emulation", wait,
                          lambda pipe: self._restore_offered(pipe, self._patch_list(pipe, ordered=True)))

    def _restore_offered(self, pipe, rows):
        """The restore offer (gate held when ``pipe`` is given): ``rows`` the cache **in write order**, read
        once by the caller, which is also what the answer of GET /patches is made from. Nothing in it hashes."""
        record, saved = self._restore, self._restore_saved  # after the caller's read of the cache: see _restore_refusal
        assert pipe is not None or (record is None and saved is None), "a timeline is asked about with rizin"
        refused = self._restore_refusal(pipe, rows, saved)
        if record is None and saved is None:
            return {"actions": 0, "reason": self._restore_gone, "digests": 0, "refused": refused}
        if record is None:
            return {"actions": len(saved["actions"]), "reason": None, "digests": len(saved["digests"]),
                    "refused": refused}
        # how many ranges the cache proves now: counted, not hashed (rizin_emulation.proved_range_count) -- the hashing is
        # for a save and a replay, and a read of the pane's own route would pay it for nothing. What the hashing would
        # have refused is refused here too: parse_cache checks the types of a row and not that ``after`` holds ``size``
        # bytes, and a count of ranges that the save skips and the replay refuses is not one to state
        try:
            digests = rizin_emulation.proved_range_count(rows)
        except ValueError:
            return {"actions": len(record["actions"]), "reason": _RESTORE_CACHE_UNREAD, "digests": 0, "refused": refused}
        return {"actions": len(record["actions"]), "digests": digests, "refused": refused,
                "reason": self._restore_reason() or (None if digests else _RESTORE_NOTHING)}

    def _restore_refusal(self, pipe, rows, saved):
        """Why restore_run would refuse now, or None (gate held when there is a record): the sentence it raises with.
        No record: why there is none; else _restore_blocked.

        Both come from what the caller passes: ``rows`` the cache **in write order**, read by the caller, and ``saved``
        the project's record **as the caller took it after that read**. The read is where a take-back is noticed
        (_patch_list drops the record), so a record taken before it can be one the read has just dropped -- and a
        refusal made over the dropped record would be a "go" for a press that has none. This function reads nothing
        that can change either, and asks ``self`` for neither."""
        if saved is None:
            return self._restore_gone or (_RESTORE_LOST_AT_OPEN if self._restore_lost else _RESTORE_NO_RECORD)
        return self._restore_blocked(pipe, saved, rows)

    # --- Replaying the timeline ---------------------------------------------
    #
    # restore_run plays the project's timeline (``_restore_saved``) back into the cache and proves it gave the
    # bytes the project says it did. The order, with the gate held for all of it:
    #
    #   1. refuse, touching nothing, unless the cache is the one from opening (_restore_blocked)
    #   2. ``wc-*`` -- not unpatch(), which would throw the timeline away -- and the registers to zero (``ara0``,
    #      read back: rizin 0.9.1's ``aei`` keeps what an earlier run left in them)
    #   3. the patches of the open that the timeline does not make (_restore_before_first_action)
    #   4. the assistant's counters to where the timeline began
    #   5. every action, in order, through the methods that did it the first time (_restore_do), inside
    #      RESTORE_BUDGET seconds
    #   6. the digests of the cache, in write order, against the ones saved
    #   7. the replayed timeline becomes the session's own (see below), then the patches that were held back and a
    #      run's bytes cover again are written
    #
    # and where 5 or 6 fail, ``wc-*`` and the patches of the open again (_restore_undo): the promise is that
    # nothing was applied, not that the cache is somewhere in between. Nothing in it records until 7: the live
    # timeline is dropped before 2 (it describes a cache that is being replaced) and ``_replaying`` keeps a start
    # from beginning one; nothing in it asks for a save either, because it calls the bodies of the actions and not
    # the methods that end in ``_schedule_save``.
    #
    # After 6 the cache **is** what the record describes -- the replay has just proved it -- so the record becomes
    # ``_restore``, a copy of it (``_restore_add`` appends, and ``_restore_saved`` is the project's, not to be
    # grown in place): whatever the user does next, a run, a skip or a patch, is an action after the last one, in
    # its place, which is what the timeline is for. It is **not** begun again (_restore_begin would see the run's
    # own rows as ``foreign`` and spoil it, and would take the counters as they stand now); ``_opened`` stays what
    # the open left, so a second press is refused (the cache is the run's). A record that is at
    # RESTORE_MAX_ACTIONS already spoils at the first action that follows, as any timeline does.

    def _restore_blocked(self, pipe, record, rows=None):
        """Why restore_run would refuse now, or None (gate held): spec 6, and the breakpoints.

        The cache has to be exactly what the open left (``_opened``, in the order it was written): anything
        else is something a ``wc-*`` would take away -- a patch made since, a console write, the bytes of a run.
        That is also what keeps ``_restore_saved``'s snapshot-time inaccuracy out of a replay: it can say
        something the project does not hold only in the session that wrote it, whose cache holds the run.
        The breakpoints have to be the ones the timeline ran under, because a run stops at a breakpoint and
        rizin keeps them where this does not reach: the replay would stop elsewhere and the digests would
        say "other bytes" for what is "other breakpoints".

        ``rows`` are the cache in write order where the caller has read them already (one ``wcj`` for an
        answer that needs the list and the gate), as _restore_digests takes them."""
        if not record["digests"]:
            return _RESTORE_NOTHING
        if self._emulation is pipe:  # a restarted rizin has none, whatever the one before it ran
            return _RESTORE_RUNNING
        try:
            if rows is None:
                rows = self._patch_list(pipe, ordered=True)
            points = sorted({found["addr"] for found in self._breakpoint_list(pipe)})
        except (ValueError, RizinTooLarge):
            return _RESTORE_CACHE_UNREAD
        if [(row["addr"], row["size"], row["after"]) for row in rows] != self._opened:
            return _RESTORE_CACHE
        if points != record["breakpoints"]:
            return _RESTORE_BREAKPOINTS.format(then=_named_set(record["breakpoints"]), now=_named_set(points))
        return None

    def restore_run(self, wait=2.0):
        """Replay the project's timeline of the emulation and prove it: {"restored", "reason", "state",
        "applied", "replayed", "patches"}. ``replayed`` is how many actions of the project's record ran (0 where the
        replay did not hold): the timeline the session holds afterwards is longer by the patches that were written
        after the proof (``applied``), and counting the replay from it would say more than was replayed.

        ``restored`` true: every action ran in the order it was made in, the SHA-256 of what the run left in
        each range is the one the project holds, and then the patches that were held back and a run's bytes
        cover again were written (``applied``: their addresses; the others stay waiting). ``state`` is the
        emulation as the replay leaves it, running, and the timeline is the session's own from here on.

        ``restored`` false: the replay did not hold -- an action was refused or ended at the time limit, the
        budget was used up, or it gave other bytes -- and **nothing was applied**: the cache is what the open
        left (``wc-*``, then the patches of the open again), the emulation is stopped, the counters are where they
        were, and the patches wait as they did. ``reason`` says why, as the run itself says it.

        ``patches`` is patches()'s answer afterwards, or None where rizin would not list the cache after it: the
        replay's result stands either way, and a request that failed over a list would tell the user nothing.

        Refused (RizinRefused, nothing touched) when there is no timeline, an emulation runs, the cache is not
        the one from opening or the breakpoints are not the ones the timeline ran under. It never runs on its
        own: it is one button press, and one request that holds the gate like a run -- RESTORE_MAX_ACTIONS bounds
        what a record holds, RESTORE_BUDGET how long this takes, and a run of it is bounded by ``esil.timeout``.
        """
        return self._call("emulation", wait, self._restore_replay)

    def _restore_replay(self, pipe):
        # The cache is read **first**: that read is where a take-back is noticed and the record dropped (_patch_list).
        # The record is taken after it and the refusal is made over that very record and those rows -- one observation,
        # so that a record the read dropped is a refusal and not a "go" with nothing to replay. Nothing between this
        # read and the first command of the replay reads the cache again (it holds the gate).
        rows = self._patch_list(pipe, ordered=True)
        record = self._restore_saved
        reason = self._restore_refusal(pipe, rows, record)
        if reason:
            raise RizinRefused(reason)
        counters, lost = (self._assist_tick, self._assist_handle, self._assist_pseudo), self._lost
        # the live timeline describes a cache that is about to be replaced, and a clean one that stayed would
        # be saved with the digests of the replayed run: it goes, and what it said of the breakpoints with it
        self._restore, self._restore_gone, self._restore_pending, self._restore_bp_moved = None, None, None, False
        self._replaying = True
        failed = state = applied = None
        try:
            try:
                state, applied = self._restore_play(pipe, record)
            except _ReplayFailed as err:
                failed = err.reason
            except (RizinRefused, ValueError, RizinTooLarge) as err:
                failed = _RESTORE_UNEXPECTED.format(why=getattr(err, "reason", None) or err)
            if failed is not None:
                note, missing = self._restore_undo(pipe, counters)
                failed += note
                lost = lost + missing
        finally:
            self._replaying = False
            self._lost = lost  # patches a restarted rizin could not take back are the project's, whatever happened here
        try:
            patches = self._patches_answer(pipe)
        except (ValueError, RizinTooLarge):
            patches = None
        return {"restored": failed is None, "reason": failed, "state": state, "applied": applied or [],
                "replayed": len(record["actions"]) if failed is None else 0, "patches": patches}

    def _restore_play(self, pipe, record):
        """Steps 2 to 7 (gate held): (the emulation's state, the addresses of the waiting patches written).
        Raises _ReplayFailed for an action that did not hold or bytes that are not the saved ones."""
        deadline = _replay_clock() + RESTORE_BUDGET
        pipe.cmd("wc-*")  # not unpatch(): that discards the timeline, and this is a replay of it
        self._mine, self._mine_over = [], []
        if not self._registers_reset(pipe):
            raise _ReplayFailed(_RESTORE_REGISTERS.format(pc=self._pc_words(pipe)))
        for addr, after in self._restore_before_first_action(record):
            self._patch_write(pipe, addr, bytes.fromhex(after))
        self._assist_tick, self._assist_handle, self._assist_pseudo = (
            record["counters"][name] for name in ("tick", "handle", "pseudo"))
        actions, stopped = record["actions"], None
        for number, action in enumerate(actions, 1):
            what = _action_words(action)
            if _replay_clock() > deadline:
                raise _ReplayFailed(_RESTORE_OUT_OF_TIME.format(number=number, count=len(actions), what=what,
                                                                done=number - 1, budget=RESTORE_BUDGET))
            try:
                answer = self._restore_do(pipe, action)
            except RizinRefused as err:
                raise _ReplayFailed(_RESTORE_MIDWAY.format(number=number, count=len(actions), what=what,
                                                           why=err.reason)) from None
            if answer.get("stopped") == "timeout":
                raise _ReplayFailed(_RESTORE_MIDWAY.format(number=number, count=len(actions), what=what,
                                                           why=_RESTORE_STOPPED_AT_TIME_LIMIT))
            stopped = answer.get("stopped", stopped)
        rows = self._patch_list(pipe, ordered=True)
        found = self._restore_digests(pipe, rows)  # in write order, as the save made them
        if found != record["digests"]:
            wrong = len([d for d in record["digests"] if d not in found])
            more = len(found) - (len(record["digests"]) - wrong)
            raise _ReplayFailed(_RESTORE_OTHER_BYTES.format(
                wrong=wrong, count=len(record["digests"]),
                more=f", and the replay left {more} more" if more else "",
                stopped=f"; the last run stopped: {stopped}" if stopped else ""))
        self._restore = {"counters": dict(record["counters"]), "breakpoints": list(record["breakpoints"]),
                         "actions": [dict(action) for action in record["actions"]], "tainted": None}
        state = self._emulation_read(pipe)
        return state, self._restore_apply_waiting(pipe, record, rows)

    def _registers_reset(self, pipe):
        """``ara0`` and a read back (gate held): whether the PC reads 0 afterwards, as it does after rizin's
        reset of the register arenas (measured on 0.9.1). ``ara0`` says nothing either way, so a rizin that did not
        take it would be found out as "other bytes" by the digest at best, and by nobody in the undo."""
        pipe.cmd("ara0")  # the registers a rizin that has not emulated has: aei keeps what an earlier run left
        return self._emulation_role(pipe, "PC") == 0

    def _pc_words(self, pipe):
        pc = self._emulation_role(pipe, "PC")
        return "the PC reads nothing" if pc is None else f"the PC reads {pc:#x}"

    def _restore_do(self, pipe, action):
        """One action of the timeline, through the body that did it the first time (gate held)."""
        kind = action["kind"]
        if kind == "start":
            return self._emulation_started(pipe, action["addr"])
        if kind == "run":
            return self._emulation_ran(pipe, action["run"], rizin_emulation.STEP_COMMANDS[action["run"]],
                                       action.get("addr"))
        if kind == "skip":
            return self._call_skipped(pipe, action["addr"], action["value"], action["fix"])
        if kind == "patch":
            return self._patch_write(pipe, action["addr"], bytes.fromhex(action["data"]))
        raise _ReplayFailed(f"the timeline holds an action of a kind this version does not replay: {kind}")

    def _restore_before_first_action(self, record):
        """The patches the open applied that the timeline does not make, as (addr, after_hex) in the order they
        were written: the ones made **before the first start**, which are no action (they are in the cache from
        the open, and the replay's ``wc-*`` takes them out with the rest).

        The timeline's own patch actions are in the open's list too, when they were not held back (a patch over
        bytes no run had written yet). Those the timeline makes again, at their place in it; so each one is
        taken out of the open's list, **from the end**: two entries that do not differ are the same patch, and the
        one that was written first is the one that was written before the start. What the open held back is not in
        the cache, so it does not stand for a patch action either (``self._waiting``): a patch made before the
        start at an address and with bytes that a later one over the run's bytes has too is still one of each."""
        made = collections.Counter((action["addr"], action["data"]) for action in record["actions"]
                                   if action["kind"] == "patch")
        made.subtract(collections.Counter((addr, after) for addr, after, _ in self._waiting))
        before = []
        for addr, _, after in reversed(self._opened):
            if made[(addr, after)] > 0:
                made[(addr, after)] -= 1
            else:
                before.append((addr, after))
        return before[::-1]

    def _restore_apply_waiting(self, pipe, record, rows):
        """The patches that were held back, written now that the timeline's run has left bytes under them (gate
        held): their addresses. What no run's bytes cover stays waiting, as does what rizin does not take. ``rows``
        are the cache in write order, as the digests were made from them: nothing was written since.

        They are actions of the timeline the session holds from here on (``_patch_write``), which asks for a save
        like a patch of the user's does: the project's patches line is the same, and its record is longer.

        A patch the timeline made again is no longer waiting and is not written twice -- counted as
        _restore_before_first_action counts it, per patch action and not by address and bytes: a twin that the
        open applied (a patch of the same bytes made before the start) is not the held one, and the cache's own
        twin of it (``_waiting_left``) would hide a patch the timeline does not make."""
        made = collections.Counter((action["addr"], action["data"]) for action in record["actions"]
                                   if action["kind"] == "patch")
        applied, still = [], []
        for patch in self._waiting:
            addr, after, _ = patch
            if made[(addr, after)] > 0:
                made[(addr, after)] -= 1
            elif rizin_emulation.run_covers(rows, addr, len(after) // 2):
                try:
                    self._patch_write(pipe, addr, bytes.fromhex(after))
                    applied.append(addr)
                    continue
                except RizinRefused:
                    still.append(patch)
            else:
                still.append(patch)
        self._waiting = still
        return applied

    def _restore_undo(self, pipe, counters):
        """The state of the open again (gate held), after a replay that did not hold: the emulation stopped, the
        cache emptied and the patches of the open written back, the counters where they were. Returns (the text
        to add to the reason, the patches that could not be written back as _lost entries): rizin took them at
        the open and does not take them now, and the project keeps them all the same."""
        self._restore = None  # the replayed timeline, if it got as far as being the session's: the cache is the open's again
        self._emulation_unmap(pipe)
        self._emulation = None
        pipe.cmd("wc-*")
        self._mine, self._mine_over = [], []
        reset = self._registers_reset(pipe)
        missing = []
        for addr, _, after in self._opened:
            try:
                self._patch_write(pipe, addr, bytes.fromhex(after))
            except RizinRefused:
                missing.append((addr, after, False))
        self._assist_tick, self._assist_handle, self._assist_pseudo = counters
        note = "" if reset else _RESTORE_REGISTERS_UNDONE
        if not missing:
            return note, []
        return note + _RESTORE_NOT_PUT_BACK.format(where=_named_addresses(addr for addr, _, _ in missing)), missing

    def emulation_state(self, wait=2.0):
        """The emulation's registers, PC, stack and the registers that changed (see _emulation_read)."""
        def run(pipe):
            self._require_emulation(pipe)
            return self._emulation_read(pipe)

        return self._call("emulation", wait, run)

    def emulation_register(self, name, value, wait=2.0):
        """Set the register ``name`` (one of those ``ar`` lists) to ``value``; returns the state."""
        if not isinstance(name, str):
            raise RizinRefused("a register name is text")
        value = _address(value)

        def run(pipe):
            self._require_emulation(pipe)
            # Only a name rizin listed itself goes into the command: those are [A-Za-z0-9_.] words.
            if name not in {r["name"] for r in rizin_emulation.parse_registers(pipe.cmd("ar"))}:
                raise RizinRefused(f"'{_show(name)}' is not a register of this emulation")
            self._restore_taint(_RESTORE_HAND_REGISTER)
            pipe.cmd(f"ar {name}={value:#x}")
            return self._emulation_read(pipe)

        return self._call("emulation", wait, run)

    def emulation_run(self, kind, addr=None, wait=2.0):
        """Run the emulation one of the ways in rizin_emulation.STEP_COMMANDS and return the state with
        ``stopped``: why it stopped (rizin_emulation.stop_reason; "trap" also when the PC is where nothing can
        execute, which rizin only says at the next step). ``addr`` is the address of "until".

        Before it runs, the settings of the start are set again (esil.* can be changed in the console, and
        esil.timeout=0 would make the run endless; set after aei, esil.exectrap takes effect, which at the
        start it does not), and io.cache and the stack are checked: a run that would write nothing, or into
        nothing, is refused.

        There is no step back: rizin 0.9.1's aesb restores no memory, and the step after it runs the
        instruction without moving the PC (a xor would be applied twice).

        A run's stderr is read from its end: esil.verbose=1 makes every int3 print a line (148 000 in a
        second), and the line that says why the run stopped comes last.
        """
        command = rizin_emulation.STEP_COMMANDS.get(kind) if isinstance(kind, str) else None
        if command is None:
            raise RizinRefused("kind must be one of " + ", ".join(rizin_emulation.STEP_COMMANDS))
        if kind == "until":
            if addr is None:
                raise RizinRefused("addr is missing: until runs to an address")
            addr = _address(addr)

        return self._call("emulation", wait, lambda pipe: self._emulation_ran(pipe, kind, command, addr))

    def _emulation_ran(self, pipe, kind, command, addr):
        """The run itself (gate held): what emulation_run does, and what a replay does for a ``run`` action."""
        maps = self._emulation_prepare(pipe)
        with self._restore_guard():
            if kind == "to_call":
                stopped = self._emulation_to_call(pipe)
            else:
                stopped = self._emulation_command(pipe, kind, command, addr)
        self._restore_add({"kind": "run", "run": kind, **({"addr": addr} if kind == "until" else {})},
                          timed_out=stopped == "timeout")
        return self._emulation_finish(pipe, stopped, maps)

    def _emulation_finish(self, pipe, stopped, maps):
        """The state after a run (gate held), with ``stopped``: why it stopped. A PC where nothing can
        execute is a trap even though rizin says so only at the next step."""
        state = self._emulation_read(pipe)
        pc = None if state["pc"] is None else int(state["pc"], 16)
        if stopped == "step" and pc is not None and not rizin_emulation.is_executable(pc, maps):
            stopped = "trap"
        state["stopped"] = stopped
        return state

    def _emulation_prepare(self, pipe):
        """What every run does before it runs (gate held): the settings of the start again, io.cache read
        back and the stack checked; ``omlj``'s maps, which the caller needs anyway.

        The settings go again because esil.* can be changed in the console (esil.timeout=0 would make
        the run endless) and because esil.exectrap takes effect only when it is set after aei. A run
        that would write nothing, or into nothing, is refused.
        """
        self._require_emulation(pipe)
        pipe.cmd("e " + " ".join(ESIL_SETTINGS))
        self._require_io_cache(pipe)
        maps = pipe.cmdj("omlj")
        if not self._emulation_stack_mapped(maps):
            raise RizinRefused("the emulation's stack is not mapped any more (aeim- in the console?): "
                               "start the emulation again")
        return maps

    def _emulation_command(self, pipe, kind, command, addr):
        """One run command (gate held); the reason it stopped."""
        if kind == "until":
            command += f" {addr:#x}"
        elif kind in ("over", "skip"):
            # aeso and aess do only what rizin's step logic lists as a call: through the import table
            # (call qword [rip+..]) they run into the callee, which is how the PC ends up in nothing
            pc = self._emulation_role(pipe, "PC")
            op = pc is not None and rizin_emulation.op_at(pipe.cmdj(f"pdj 1 @ {pc:#x}"), pc)
            if op and kind == "over" and rizin_emulation.over_call(op[0]):
                command = f"aesu {pc + op[1]:#x}"
            elif op and kind == "skip" and rizin_emulation.skip_call(op[0]):
                command = f"aepc {pc + op[1]:#x}"
        out, err, _ = pipe.console(command, timeout=ESIL_TIMEOUT + ESIL_GRACE, tail=True)
        return rizin_emulation.stop_reason(out, err)

    def _emulation_to_call(self, pipe):
        """Run to the next call, of any kind (gate held); the reason it stopped. One instruction first, like
        rizin's aecc, so a call the PC stands on is run. Then hop: look at the straight code ahead (pdj), run
        to a call in it and stop before it, or to the jump that ends it and take that. Every hop is an aesu,
        which rizin bounds by esil.timeout, and the whole is bounded by ESIL_TIMEOUT too."""
        deadline = time.monotonic() + ESIL_TIMEOUT
        timeout = ESIL_TIMEOUT + ESIL_GRACE
        out, err, _ = pipe.console("aes", timeout=timeout, tail=True)
        while True:
            stopped = rizin_emulation.stop_reason(out, err)
            if stopped != "step":
                return stopped
            if time.monotonic() > deadline:
                return "timeout"
            pc = self._emulation_role(pipe, "PC")
            if pc is None:
                return "step"
            where, target = rizin_emulation.next_call_stop(pipe.cmdj(f"pdj 16 @ {pc:#x}"), pc)
            if where == "call" and target == pc:
                return "step"
            if target != pc:
                out, err, _ = pipe.console(f"aesu {target:#x}", timeout=timeout, tail=True)
                if where == "call":
                    return rizin_emulation.stop_reason(out, err)
                continue
            # at the jump that ends the straight code, or at bytes rizin cannot decode (it says why)
            out, err, _ = pipe.console("aes", timeout=timeout, tail=True)

    def breakpoints(self, wait=2.0):
        """The breakpoints rizin holds, lowest address first: [{"addr": int, "enabled": bool}].

        They are rizin's own (``dblj``), not the emulation's: they can be set before it starts and they
        survive it, so none of the three asks for a running emulation. ``enabled`` is reported as rizin
        reports it, because a console ``dbd`` can set it; but rizin 0.9.1 stops a run at a disabled
        breakpoint all the same (``rz_bp_get_at`` looks at neither ``enabled`` nor ``valid``), so nothing
        here offers to change it: a breakpoint is set or it is removed.
        """
        return self._call("emulation", wait, self._breakpoint_list)

    def breakpoint_set(self, addr, wait=2.0):
        """Set a breakpoint at ``addr`` (``db @ addr``: rizin's db takes no address argument); returns
        {"breakpoints": the list}.

        One that is there already is left as it is, which is what rizin does too (it says "Breakpoint
        already set at this address." and keeps it), so setting one twice is no error. An address rizin
        leaves out of the list afterwards is refused rather than reported as set: on an arch whose
        breakpoints are wider than a byte another one can cover it (measured on arm64, where ``db``'s size
        is 4). An address outside every map is set: rizin warns and marks it ``valid: false``, and its runs
        stop there all the same (measured).
        """
        addr = _address(addr)

        def run(pipe):
            pipe.cmd(f"db @ {addr:#x}")
            found = self._breakpoint_list(pipe)
            if not any(b["addr"] == addr for b in found):
                raise RizinRefused(f"rizin set no breakpoint at {addr:#x}: another one may cover it already")
            self._restore_breakpoints(found)
            return {"breakpoints": found}

        result = self._call("emulation", wait, run)
        self._schedule_save()  # rizin's own project keeps the breakpoints; this makes one be written
        return result

    def breakpoint_clear(self, addr=None, wait=2.0):
        """Remove the breakpoint at ``addr`` (``db- @ addr``), or all of them when ``addr`` is None
        (``db-*``); returns {"breakpoints": the list}. One that is not there is no error: what was asked
        for is the state that is left."""
        if addr is not None:
            addr = _address(addr)

        def run(pipe):
            pipe.cmd("db-*" if addr is None else f"db- @ {addr:#x}")
            found = self._breakpoint_list(pipe)
            self._restore_breakpoints(found)  # also where it was kept: what is set is what runs stop at
            if addr is not None and any(b["addr"] == addr for b in found):
                raise RizinRefused(f"rizin kept the breakpoint at {addr:#x}")
            return {"breakpoints": found}

        result = self._call("emulation", wait, run)
        self._schedule_save()
        return result

    @staticmethod
    def _breakpoint_list(pipe):
        """``dblj``'s breakpoints as addr and enabled, lowest address first (gate held); rizin lists them in
        the order they were set. Its other fields (size, perm, hw, trace, valid, cond, data) belong to its
        debugger and say nothing about an ESIL run."""
        found = pipe.cmdj("dblj")
        if found is None:
            return []
        if not isinstance(found, list):
            raise ValueError("dblj did not answer a list of breakpoints")
        rows = [{"addr": b["addr"], "enabled": bool(b.get("enabled"))} for b in found
                if isinstance(b, dict) and isinstance(b.get("addr"), int) and not isinstance(b["addr"], bool)]
        return sorted(rows, key=lambda b: b["addr"])

    def patch(self, addr, data, wait=2.0):
        """Write ``data`` (bytes, or an even number of hex digits) at ``addr`` into rizin's write cache
        and return {"patches": the list}.

        The file on disk is never written: rizin runs without -w, and wci and wc+, which commit the
        cache, are refused everywhere. io.cache is switched on first (an analyst patches before ever
        stepping, so there need be no emulation) and read back: without it rizin loses the write and
        says so on stderr only, which cmd does not read, and px would go on showing the original bytes.
        """
        addr = _address(addr)
        try:
            data = rizin_emulation.hex_data(data)
        except ValueError as e:
            raise RizinRefused(str(e)) from None

        def run(pipe):
            return self._patch_write(pipe, addr, data)

        result = self._call("emulation", wait, run)
        self._schedule_save()
        return result

    def patch_op(self, addr, kind, wait=2.0):
        """Patch the instruction at ``addr`` one of rizin_emulation.PATCH_KINDS' ways (nop, flip, always,
        nocall): the bytes are computed from what ``pdj`` decoded there, nothing is assembled. Returns
        {"patches": the list}.

        x86 only: all four kinds are x86 encodings (0x90 is a nop here and nowhere else), so on another
        arch the kind is refused instead of writing bytes that mean something else.
        """
        addr = _address(addr)
        if not isinstance(kind, str) or kind not in rizin_emulation.PATCH_KINDS:
            raise RizinRefused("kind must be one of " + ", ".join(rizin_emulation.PATCH_KINDS))
        if self.arch != "x86":
            raise RizinRefused(f"the patch kinds write x86 bytes, and this file is "
                               f"{self.arch or 'of an arch rizin did not name'}: write the bytes by hand")

        def run(pipe):
            op = rizin_emulation.instruction_at(pipe.cmdj(f"pdj 1 @ {addr:#x}"), addr)
            if op is None:
                raise RizinRefused(f"rizin decoded no instruction at {addr:#x}")
            try:
                data = rizin_emulation.patch_bytes(kind, op)
            except ValueError as e:
                raise RizinRefused(str(e)) from None
            return self._patch_write(pipe, addr, data)

        result = self._call("emulation", wait, run)
        self._schedule_save()
        return result

    def patches(self, wait=2.0):
        """What rizin's write cache holds (``wcj``) and what waits: {"patches": [...], "waiting": [...]}.

        ``patches`` is the cache lowest address first: [{"addr", "size", "before", "after", "mine",
        "over_run"}].

        One row per write operation, not per byte: a two-byte ``wx`` is one row of size 2, and a second
        write over the same address is another row whose ``before`` is what the first one wrote
        (measured). ``mine`` is this session's own patch, row by row, as against what an emulation run
        or the console wrote into the same cache -- also where that write lies inside a range this
        session patched. ``over_run`` is a ``mine`` row set over bytes such a foreign write changed
        before it: rizin's ``before`` is then the run's byte and not the file's, so the pane marks the
        row and the export reads the file itself (see rizin_emulation.patch_rows). rizin's own ``idx``
        and ``written`` are left out: the index changes with every removal, and nothing here ever
        commits the cache, so ``written`` is always false.

        ``waiting`` is [{"addr", "after", "reason", "apply_now"}], lowest address first: the patches the project holds
        that were set over bytes a run had written and were **not** written into the cache when the
        file was opened (_replay_patches). They are not in ``patches`` and so not in an export, and a
        patch the cache holds since (the same address and bytes made again) is not waiting any more
        (_waiting_left). The reason says in addition where no map holds the address at the moment.
        ``apply_now`` is true where patch_waiting would write the entry now -- a row of the cache that is not this
        session's own overlaps a byte of it (rizin_emulation.run_covers, which does not care about the order of the
        rows) -- and it is made from the rows this answer is made from: no second read. The press is decided again
        on arrival. The cache is read first, because that read is what lets the mirror forget a write the console took out.

        ``restore`` is the offer (_restore_offered), {"actions", "reason", "digests", "refused"}, made from the same read of the
        cache: the reader of the restore button, which is asked for by the user and not on the poll. It costs
        nothing where the session holds no timeline (no breakpoint read either), and one ``dblj`` where it holds
        the project's. Read ``digests`` with what is asked: for a session's own timeline the ranges the cache
        proves **now**, for the project's the ranges the record **stores** (see _restore_offer).
        """
        return self._call("emulation", wait, self._patches_answer)

    def _patches_answer(self, pipe, rows=None):
        """patches()'s answer (gate held). ``rows`` are the cache **in write order** where the caller has read it
        already (the list is the same rows by address, and the offer and the gate need the order): one ``wcj``."""
        if rows is None:
            rows = self._patch_list(pipe, ordered=True)
        listed = sorted(rows, key=lambda row: row["addr"])
        waiting = sorted(self._waiting_left(self._own_patches()), key=lambda patch: patch[0])
        maps = None
        if waiting:
            try:
                maps = pipe.cmdj("omlj")
            except ValueError:
                pass  # what is mapped is not known, so the reason does not say
            except (RizinTimeout, RizinDied):
                # The read is for one sentence of prose and must not cost the answer: the rows above were
                # read before it. But rizin is gone (a timeout kills it), so the session ends as _call
                # ends one, and the next request is told so rather than finding a live-looking session.
                if not self._closed:
                    self._end()
        return {"patches": listed,
                "waiting": [{"addr": addr, "after": after,
                             "reason": _PATCH_WAITING_REASON + (
                                 _PATCH_UNMAPPED_REASON if isinstance(maps, list)
                                 and not rizin_emulation.maps_hold(addr, len(after) // 2, maps) else ""),
                             # whether patch_waiting would take it now: the same question over the same rows, asked
                             # once here, so that the pane draws "Apply now" from the answer and keeps no copy of it
                             "apply_now": rizin_emulation.run_covers(rows, addr, len(after) // 2)}
                            for addr, after, _ in waiting],
                "restore": self._restore_offered(pipe, rows)}

    def patch_waiting(self, addr, wait=2.0):
        """Apply the patches that wait at ``addr`` now: one of the two ways out of waiting (the other is
        drop_waiting). It is offered **only** where the bytes under the address are a run's again -- a row of the
        cache that is not this session's own covers it -- and the server decides, not the pane: a patch written
        before that is the harm that held it back, the file's still encrypted bytes with a patch in them and
        the next decryption XORing over it. Returns patches()'s answer; refused for an address where nothing waits
        and for one no run's bytes cover. It is a patch like any other afterwards, and a patch action of the
        timeline there is one."""
        addr = _address(addr)

        def run(pipe):
            rows = self._patch_list(pipe, ordered=True)  # what the console took out of the cache is not what waits
            mine = [patch for patch in self._waiting_left(self._own_patches()) if patch[0] == addr]
            if not mine:
                raise RizinRefused(_PATCH_NOT_WAITING.format(addr=addr))
            if not all(rizin_emulation.run_covers(rows, patch[0], len(patch[1]) // 2) for patch in mine):
                raise RizinRefused(_PATCH_NOT_COVERED.format(addr=addr))
            for patch in mine:
                self._patch_write(pipe, addr, bytes.fromhex(patch[1]))
                self._waiting = [kept for kept in self._waiting if kept != patch]
            return self._patches_answer(pipe)

        result = self._call("emulation", wait, run)
        self._schedule_save()
        return result

    def drop_waiting(self, addr, wait=2.0):
        """Take the patches that wait at ``addr`` out of the list and the project: the other way out. Returns
        patches()'s answer; refused where nothing waits. What is not in the cache is not touched, and a patch of
        the same bytes a restart lost (``_lost``) is the same patch and goes with it.

        A timeline that makes the patch again is dropped with it (_restore_saved): replaying it would put back
        what was taken out of the project."""
        addr = _address(addr)

        def run(pipe):
            rows = self._patch_list(pipe, ordered=True)
            mine = [patch for patch in self._waiting_left(self._own_patches()) if patch[0] == addr]
            if not mine:
                raise RizinRefused(_PATCH_NOT_WAITING.format(addr=addr))
            gone = {(patch[0], patch[1]) for patch in mine}
            self._waiting = [kept for kept in self._waiting if kept not in mine]
            self._lost = [kept for kept in self._lost if (kept[0], kept[1]) not in gone]
            saved = self._restore_saved
            if saved is not None and any(action["kind"] == "patch" and (action["addr"], action["data"]) in gone
                                         for action in saved["actions"]):
                self._restore_saved, self._restore_gone = None, _RESTORE_WAITING_DROPPED
            return self._patches_answer(pipe, rows)  # nothing was written: the read stands

        result = self._call("emulation", wait, run)
        self._schedule_save()
        return result

    def patches_made(self, wait=2.0):
        """``patches()`` in the order the writes were made, not by address: [{"addr", "size", "before",
        "after", "mine", "over_run"}]. Where two rows overlap the later one wins, which a list by
        address cannot say (a one-byte patch made after a longer one that starts a byte later is listed
        first, measured), so whoever applies the patches to a file needs this order."""
        return self._call("emulation", wait, lambda pipe: self._patch_list(pipe, ordered=True))

    def unpatch(self, addr=None, wait=2.0):
        """Take back every write that overlaps ``addr`` (``wc-``), or the whole cache (``wc-*``) when
        ``addr`` is None; returns {"patches": the list, "run_removed": the foreign rows that went}.
        Taking back where there is nothing is no error.

        rizin removes a write operation whole, so taking back one byte of a longer ``wx`` takes all of
        it, and two writes at one address go together (measured); the list says what is left.

        ``run_removed`` is the writes that were **not** this session's patches and went all the same,
        each as {"addr", "size"}: ``wc- <addr> <addr+1>`` removes every write that overlaps the
        address, so taking back a patch set over bytes an emulation run wrote takes the run's row with
        it -- up to a whole copied or decrypted stage (measured: a 4-byte run row and a 1-byte patch
        over it, and the range form emptied the cache). Those bytes are back only by running again, so
        the answer names them instead of letting the interface say only that one patch went.

        ``wc-*`` takes an emulation run's bytes with it, because rizin has one cache for both; the list
        says which of them are this session's own.
        """
        if addr is not None:
            addr = _address(addr)

        def run(pipe):
            self._lost = []
            held = self._patch_list(pipe)  # what the cache holds before the removal, to say what went
            try:
                if addr is None:
                    pipe.cmd("wc-*")  # the mirror forgets what went when the cache is read (_patch_list)
                else:
                    # The range, not the address: `wc- <addr>` with no second argument drops every write in
                    # a whole block (0x100 bytes) from there, the neighbours' included (measured).
                    pipe.cmd(f"wc- {addr:#x} {addr + 1:#x}")
                found = self._patch_list(pipe)
            except BaseException:
                self._restore_discard()  # what the command took out is not known
                raise
            went = rizin_emulation.rows_gone(held, found)
            if went:
                self._restore_discard()
            if addr is not None and any(r["addr"] <= addr < r["addr"] + r["size"] for r in found):
                raise RizinRefused(f"rizin kept the patch at {addr:#x}")
            gone = [{"addr": r["addr"], "size": r["size"]} for r in went if not r["mine"]]
            return {"patches": found, "run_removed": sorted(gone, key=lambda r: r["addr"])}

        result = self._call("emulation", wait, run)
        self._schedule_save()
        return result

    def _restore_saved_without(self, entries):
        """The project's timeline does not survive the take-back of a patch it makes (gate held): ``entries`` are this
        session's own writes, (addr, size, after_hex), that went out of the cache (_patch_list). The live timeline is
        dropped for any row that goes (_restore_discard), but the project's record is not the live one -- a reopened
        session has none -- and a replay of it would write the patch again, and say "restored": the patch lies outside
        the hashed ranges, so the SHA-256 cannot tell. The way a patch that waits is dropped (drop_waiting) has the
        same cause and the same answer. A patch of the open that the timeline does not make (one before the first
        start) costs it nothing."""
        saved = self._restore_saved
        if saved is None:
            return
        made = {(action["addr"], action["data"]) for action in saved["actions"] if action["kind"] == "patch"}
        if any((addr, after) in made for addr, _, after in entries):
            self._restore_saved, self._restore_gone = None, _RESTORE_PATCH_TAKEN_BACK
            self._schedule_save()  # the project holds the line, and a take-back by the console asked for nothing

    def _patch_write(self, pipe, addr, data):
        """``wx`` of ``data`` at ``addr`` through the cache (gate held); {"patches": the list}."""
        if self._emulation is not pipe:
            pipe.cmd("e io.cache=true")  # the emulation's start sets it too, but a patch needs no start
        self._require_io_cache(pipe, "the patch")
        with self._restore_guard():
            pipe.cmd(f"wx {data.hex()} @ {addr:#x}")
            self._mine.append(rizin_emulation.cache_entry(addr, data))
            self._lost = []  # the user is patching this cache: what a restart lost is not kept any more
            found = self._patch_list(pipe)
            if not any(r["addr"] <= addr < r["addr"] + r["size"] for r in found):
                raise RizinRefused(f"rizin wrote nothing at {addr:#x}")
        self._restore_add({"kind": "patch", "addr": addr, "data": data.hex()})
        return {"patches": found}

    def _patch_list(self, pipe, ordered=False):
        """The write cache as the patch list (gate held), and the mirror of this session's own writes
        kept honest: a write no row of the cache holds any more (a console ``wc-``, a rizin that was
        restarted) is dropped from it, so that a later write there is not taken for a patch.

        The rows are read in rizin's order, which is the order of the mirror, so that what each of this
        session's rows says about ``over_run`` can be kept beside the mirror's entries (``_mine_over``).

        **This is where a patch that left the cache is noticed**, whoever took it out (the take-back route, a console
        ``wc-``, a restart): an entry the last read **confirmed** and this one does not find is a take-back, and the
        project's timeline of the emulation does not survive that where it makes the patch
        (_restore_saved_without). The mirror is the one place all of them pass, and nothing about it needs the
        console to be watched. What the last read had not confirmed (an entry a write appended whose row never
        came, or one a restart's replay of the mirror could not write) was never in the cache, and is not a take-back;
        and the replay empties the mirror before it reads, so its own ``wc-*`` is nobody's."""
        confirmed = self._mine[:len(self._mine_over)]
        rows, self._mine = rizin_emulation.patch_rows(rizin_emulation.parse_cache(pipe.cmd("wcj")),
                                                      self._mine, True)
        self._mine_over = [row["over_run"] for row in rows if row["mine"]]
        left = collections.Counter(confirmed) - collections.Counter(self._mine)
        if left:
            self._restore_saved_without(left)
        return rows if ordered else sorted(rows, key=lambda row: row["addr"])

    def _waiting_left(self, kept):
        """The patches still waiting, given ``kept`` (this session's own writes, _own_patches): not those
        whose address and bytes a write of the cache holds -- that one is applied, and a waiting entry
        beside it would be one patch in two places. The same address with **other** bytes leaves it
        waiting: its own bytes are still not applied. The answer of patches() and the project's patches
        line (_saved_cache) both ask this, and the line leaves out a lost patch of the same address and
        bytes as one of them (``self._lost``), so the line holds no entry the answer does not show."""
        live = {(addr, after) for addr, after, _ in kept}
        return [patch for patch in self._waiting if (patch[0], patch[1]) not in live]

    def _own_patches(self):
        """This session's own writes as [(addr, after_hex, over_run)], in the order it made them.

        ``over_run`` is what the last read of the cache said (_patch_list); an entry the mirror gained
        since (a write whose read of the cache failed) has nothing yet and is False, which is a patch
        in the file's own bytes -- what a write by hand is until a run is known to lie under it."""
        over = self._mine_over + [False] * (len(self._mine) - len(self._mine_over))
        return [(addr, after, over_run) for (addr, _, after), over_run in zip(self._mine, over)]

    def run_range(self, wait=2.0):
        """The range an emulation run wrote, as (lowest address, highest address), both in it; None when
        the run wrote nothing.

        The run's writes are the rows of the write cache that are not this session's patches (``mine``),
        minus those in the ESIL VM's own memory: a word a call pushed is no code to analyse, and neither
        is a byte in a buffer the assistant mapped. What is left is grouped
        (rizin_emulation.write_cluster), and the group that holds the most bytes is the range -- a run
        that pushed a word here and decrypted a block there must not become one span of everything in
        between.
        """
        return self._call("emulation", wait, self._run_range)

    def reanalyze(self, start=None, end=None, wait=2.0):
        """Analyse the range ``start``..``end`` again, both addresses in it, and return
        {"start", "end", "functions", "strings"}: the range and what rizin now finds in it.

        Without a range, the one the run wrote (``run_range``); a run that wrote nothing is refused
        rather than analysed as an empty or invented range. HEX and DISASSEMBLY show a run's bytes by
        themselves (px reads through the cache), but FUNCTIONS and STRINGS do not: rizin builds those
        when it loads the file, from its sections. This is what makes the bytes a run decrypted readable
        as code -- and it belongs to the run: a ``wc-*`` or a new session takes it away with the bytes.
        """
        if (start is None) != (end is None):
            raise RizinRefused("a range takes start and end, or neither: then the run's own range is used")
        if start is not None:
            start, end = _address(start), _address(end)
            if end < start:
                raise RizinRefused(f"end ({end:#x}) is below start ({start:#x})")
            self._reanalyze_width(start, end)  # before the pipe is waited for

        def run(pipe):
            # A console `e io.cache=false` leaves wcj listing the run's rows while rizin reads the file
            # again (measured, Task 5), so af and /zj would analyse bytes the run never wrote.
            pipe.cmd("e io.cache=true")
            self._require_io_cache(pipe, "the bytes the run wrote")
            found = (start, end) if start is not None else self._run_range(pipe)
            if found is None:
                raise RizinRefused("the run wrote nothing to analyse")
            low, high = found
            self._reanalyze_width(low, high)  # a run can have decrypted more than one request covers
            return {"start": low, "end": high,
                    "functions": self._reanalyze_functions(pipe, low, high),
                    "strings": self._reanalyze_strings(pipe, low, high)}

        return self._call("emulation", wait, run)

    @staticmethod
    def _reanalyze_width(low, high):
        if high - low + 1 > MAX_REANALYZE_BYTES:
            raise RizinRefused(f"at most {MAX_REANALYZE_BYTES} bytes are analysed at once, and this "
                               f"range is {high - low + 1}: analyse it in parts")

    def _run_range(self, pipe):
        """The range the run wrote (gate held); see run_range.

        What is left out is every write inside the ESIL VM's own memory, from **both** sources: the
        maps ``omlj`` lists now (``mem.*``: the stack, the assistant's buffers and whatever a console
        ``aeim`` mapped) and every range this session's emulation has had memory in
        (_emulation_ranges). Both, because neither alone holds: the live list catches memory nobody
        recorded, but a stop gives it all back while the write cache keeps the rows -- and then the
        words a run pushed would become "the range the run wrote", so ``af`` and ``/zj`` would report
        stack words as decrypted functions and strings. The record catches that, and the sweep adds
        the live maps to it before closing them, so nothing falls between the two.
        """
        esil = rizin_emulation.esil_ranges(pipe.cmdj("omlj")) + self._emulation_ranges
        rows = [row for row in self._patch_list(pipe) if not row["mine"]
                and not rizin_emulation.overlaps_any(row["addr"], row["size"], esil)]
        return rizin_emulation.write_cluster(rows)

    def _reanalyze_functions(self, pipe, low, high):
        """``af`` over the range (gate held): how many functions begin in it afterwards.

        The functions that begin in the range go first (``af-``): rizin's af leaves a function that is
        there alone, so without that the stale function of the bytes the run overwrote would survive it
        (measured on 0.9.1: a 1-byte function at an address with 7 decrypted bytes under it stayed
        1 byte, and became 7 only after an ``af-`` there). Then one af per address, bounded to the range
        by ``analysis.limits``, because af follows the calls out of it -- measured, and with
        ``analysis.calls`` false as well: pointed into freshly decrypted bytes it made a function at the
        target of their call, and 32 of them down a chain. The limit gets REANALYZE_SLACK of room past
        the range, because analysis.to truncates the function it cuts (measured). The settings ride on
        the command (``@e:``), so nothing is left changed behind it.

        The count is read from the list again rather than from a difference: af may also make a function
        in the slack past the range, and the answer says how many begin *in* the range.
        """
        begins = self._reanalyze_begins(pipe, low, high)
        if len(begins) > MAX_REANALYZE_FUNCTIONS:
            raise RizinRefused(f"the range holds {len(begins)} functions, more than "
                               f"{MAX_REANALYZE_FUNCTIONS}: analyse it in parts")
        for addr in begins:
            pipe.cmd(f"af- @ {addr:#x}")
        limits = (f"@e:analysis.limits=true,analysis.from={low:#x},"
                  f"analysis.to={high + 1 + REANALYZE_SLACK:#x}")
        for addr in [low] + [addr for addr in begins if addr != low]:
            pipe.cmd(f"af @ {addr:#x} {limits}", timeout=CONSOLE_TIMEOUT)
        return len(self._reanalyze_begins(pipe, low, high))

    @staticmethod
    def _reanalyze_begins(pipe, low, high):
        """The addresses in low..high where ``afl`` says a function begins, lowest first (gate held)."""
        text = pipe.cmd("afl", timeout=CONSOLE_TIMEOUT, limit=FUNCTION_ANSWER_MAX)
        return sorted({addr for addr in rizin_emulation.function_entries(text) if low <= addr <= high})

    def _reanalyze_strings(self, pipe, low, high):
        """``/zj`` over the range (gate held): how many strings it found.

        rizin 0.9.1's /zj searches for a *pattern* and has no form that lists the strings of a range
        (measured: without one it refuses), so the pattern is a run of printable bytes. The range is
        search.from..search.to with search.in=range; the block (``@!``) does not bound the search
        (measured: it searched the whole file all the same). Every hit gets a flag of its own
        (hit.string.<encoding>.<n>, rizin's search.flags), which is how FLAGS and the console's Tab show
        what the run decrypted.
        """
        found = pipe.cmdj(f"/zj {rizin_emulation.STRING_PATTERN} r ascii "
                          f"@e:search.in=range,search.from={low:#x},search.to={high + 1:#x}",
                          timeout=CONSOLE_TIMEOUT, limit=VIEW_ANSWER_MAX)
        return rizin_emulation.string_hits(found)

    # --- The API-call assistant ---------------------------------------------

    def call_assist(self, addr, wait=2.0):
        """What a SKIP of the call at ``addr`` can answer: {"supported", "reason", "api", "ret_reg",
        "value", "stack_fix", "summary"}.

        ESIL emulates no Windows API: a step into a ``call qword [VirtualAlloc]`` runs into unmapped
        memory (measured). This names the API behind the call, offers a value for the return register
        and says in ``summary`` what SKIP would do with it. Every value is a proposal: call_skip takes
        the value and the stack correction from the request, so a client can change either (the tab edits
        only the value; it sends the stack correction as offered).

        It **changes nothing** (R38), not even the session's own clock or its pseudo-value series: the
        run line asks for this on every step, so two answers for the same call are the same answer, and
        the value cannot move between looking at it and applying it. The series move where a skip
        applies them.

        It needs no running emulation -- a call can be read before one starts -- but a value that only
        the VM has (a buffer's size from a register or the stack, the tick counter, memcpy's arguments)
        is then None and the summary says why.

        On an arch other than x86-32 and x86-64 the assistant switches itself off: ``supported`` false
        and a ``reason`` that names the arch. Emulation, breakpoints and patching keep working there;
        offering a guessed register would be the "the surface lies" anti-goal.
        """
        addr = _address(addr)

        def run(pipe):
            conv = rizin_emulation.convention(self.arch, self.bits, None)
            if conv is None:
                return self._assist_off()
            name = self._assist_call(pipe, addr)[1]
            api = rizin_emulation.lookup_api(name)
            conv = rizin_emulation.convention(self.arch, self.bits, api)
            if api is None:
                return dict(self._assist_answer(conv), api=name and _show(name, 120),
                            summary=self._assist_unknown(conv, name))
            plan = self._assist_plan(pipe, conv, api, pipe.cmdj("omlj"))
            fix = rizin_emulation.stack_fix(conv, api["args"])
            notes = [plan["note"]] + [write["note"] for write in plan["out"]]
            return dict(self._assist_answer(conv), api=api["name"], value=rizin_emulation.word(plan["value"]), stack_fix=fix,
                        summary=f"skip {api['name']}: {'; '.join(n for n in notes if n)}. "
                                f"{self._assist_stack_note(conv, api, fix)}")

        return self._call("emulation", wait, run)

    def call_skip(self, addr, value=None, stack_fix=0, wait=2.0):
        """Skip the call at ``addr`` and apply the answer; the state, with ``summary``: what was applied.

        ``value`` goes into the return register (None leaves it as it is), ``stack_fix`` is added to the
        stack pointer. Both come from the request, not from the table: a client may have changed
        them (the tab edits only ``value``; it sends ``stack_fix`` as offered). A memory API's buffer is mapped, a copying one really copies and the time and environment
        APIs write their out-parameter, all at the addresses the call's own arguments name.

        The order follows what rizin does: the buffer is mapped **first**, because ``aeim`` sets the PC
        and the stack and base pointer into the map it has just made (measured: the PC to the seek, SP
        and BP to the middle of the new map), so those three are read before it and written back after
        it. Then the call is skipped the way a SKIP run does -- which sets the PC itself for a call
        through the import table, because rizin's ``aess`` runs into that one (R18) -- then the return
        register, then the stack correction, then the copy and the out-parameters.

        This is also the only place where the run's clock and the pseudo-value series move on, so that
        asking what a call could answer never changes what it answers (R38).
        """
        addr = _address(addr)
        if value is not None:
            value = _address(value)
        if isinstance(stack_fix, bool) or not isinstance(stack_fix, int) or stack_fix < 0:
            raise RizinRefused("stack_fix must be a whole number of bytes, 0 or more")

        return self._call("emulation", wait, lambda pipe: self._call_skipped(pipe, addr, value, stack_fix))

    def _call_skipped(self, pipe, addr, value, stack_fix):
        """The skip itself (gate held): what call_skip does with a request that was checked, and what a replay
        does for a ``skip`` action."""
        maps = self._emulation_prepare(pipe)
        conv = rizin_emulation.convention(self.arch, self.bits, None)
        if conv is None:
            raise RizinRefused(self._assist_off()["reason"])
        pc = self._emulation_role(pipe, "PC")
        if pc != addr:
            raise RizinRefused(f"the emulation's PC is at {'nowhere' if pc is None else f'{pc:#x}'}, "
                               f"not at {addr:#x}: a skip applies to the call the PC stands on")
        api = rizin_emulation.lookup_api(self._assist_call(pipe, addr)[1])
        conv = rizin_emulation.convention(self.arch, self.bits, api)
        fix = self._assist_fix(pipe, conv, stack_fix)
        # planned before the skip: the arguments sit on the stack that the correction moves
        plan = self._assist_plan(pipe, conv, api, maps) if api else None
        notes = []
        with self._restore_guard():
            if plan is not None and plan["buffer"] and value is not None:
                notes.append(self._assist_map(pipe, maps, plan, value))
            stopped = self._emulation_command(pipe, "skip", rizin_emulation.STEP_COMMANDS["skip"], None)
            if value is not None:
                pipe.cmd(f"ar {conv['ret_reg']}={value:#x}")
                notes.insert(0, f"{conv['ret_reg']} = {value:#x}")
            if fix:
                # `ar SP=<value>` takes the role name, as `ar SP` does for reading (measured)
                sp = self._emulation_role(pipe, "SP")
                pipe.cmd(f"ar SP={sp + fix:#x}")
                notes.append(f"the stack pointer went up by {fix} bytes")
            if plan is not None:
                notes += self._assist_apply(pipe, plan)
                self._assist_advance(plan)
        # what the register holds: rizin cuts the value to its width (measured: eax=0x100000041 is 0x41)
        applied = None if value is None else value & ((1 << 8 * conv["word"]) - 1)
        self._restore_add({"kind": "skip", "addr": addr, "value": applied, "fix": fix},
                          timed_out=stopped == "timeout")
        state = self._emulation_finish(pipe, stopped, maps)
        state["summary"] = (f"skipped {api['name'] if api else 'the call'} at {addr:#x}: "
                            + ("; ".join(notes) if notes else "the PC is after the call, and nothing "
                                                              "else was changed"))
        return state

    def _assist_off(self):
        """The answer on an arch the assistant does not cover: it offers nothing and says so."""
        return {"supported": False,
                "reason": f"the assistant covers x86-64 and x86-32, and this file is "
                          f"{self.arch or 'of an arch rizin did not name'} at {self.bits or 'unknown'} bits",
                "api": None, "ret_reg": None, "value": None, "stack_fix": 0,
                "summary": "no value is offered here rather than a guessed one; emulation, breakpoints "
                           "and patching work on this file all the same"}

    @staticmethod
    def _assist_answer(conv):
        return {"supported": True, "reason": None, "api": None, "ret_reg": conv["ret_reg"],
                "value": None, "stack_fix": 0, "summary": ""}

    def _assist_unknown(self, conv, name):
        """What the summary says for a call the table does not know: the import is named, no value is
        offered, and at 32 bits that **the stack is not corrected**, because the argument count is the
        one thing a correction needs (R31). Both fields are there to be filled in by hand."""
        called = f"'{_show(name, 120)}'" if name else "the call's target"
        if conv["stack_args"]:
            return (f"the table does not know {called}, so no value is offered and the stack is not "
                    f"corrected: its argument count is unknown, and at 32 bits a stdcall callee would "
                    f"clear its arguments. Set the return register and the correction by hand")
        return (f"the table does not know {called}, so no value is offered; under win64 the caller "
                f"clears the stack, so nothing has to be corrected. Set {conv['ret_reg']} by hand")

    @staticmethod
    def _assist_stack_note(conv, api, fix):
        if fix:
            return (f"The stack pointer goes up by {fix} bytes, because a stdcall callee clears its "
                    f"{api['args']} arguments")
        if conv["stack_args"]:
            return "The stack is not corrected: a cdecl caller clears the arguments itself"
        return "The caller clears the stack under win64, so nothing is corrected"

    def _assist_call(self, pipe, addr):
        """(the op's type, the name of the call's target) at ``addr`` (gate held); refuses where rizin
        decoded no call there.

        The target: for a call through the import table rizin's ``ptr`` holds the table slot
        (``call qword [rip+..]``, type ircall at 64 bits, ``call dword [slot]``, type ucall at 32 --
        both measured), for a direct call ``jump`` holds the callee, and the flag at that address is the
        import's name (measured: ``fd.j`` gives [{"name": "sym.imp.KERNEL32.dll_Sleep", ...}]). The
        emulator's own register flags are left out, so a target that happens to be a register's value
        is not taken for a name. The name is hostile: it is looked up and shown, never sent to rizin.
        """
        op = rizin_emulation.instruction_at(pipe.cmdj(f"pdj 1 @ {addr:#x}"), addr)
        kind = op.get("type") if op else None
        if not rizin_emulation.is_call(kind):
            what = f"'{_show(str(kind))}'" if op else "nothing"
            raise RizinRefused(f"rizin decoded {what} at {addr:#x}, not a call: the assistant answers "
                               f"for a call whose target is an API")
        target = op.get("jump") if kind == "call" else op.get("ptr")
        if not isinstance(target, int) or isinstance(target, bool):
            return kind, None
        registers = {r["name"] for r in rizin_emulation.parse_registers(pipe.cmd("ar"))} \
            if self._emulation is pipe else set()
        return kind, rizin_emulation.flag_hint(pipe.cmdj(f"fd.j @ {target:#x}"), registers)

    def _assist_plan(self, pipe, conv, api, maps):
        """What this call can answer and what applying it would do (gate held), as one plan:

        ``value`` and ``note`` for the return register, ``buffer`` the bytes a memory API's buffer
        needs (0 for none), ``copy`` what a copying API would move, ``out`` the out-parameter writes
        with the words for each, and ``advance`` the series a skip would move on (R38: this reads, it
        never moves them).
        """
        plan = {"value": None, "note": "", "buffer": 0, "copy": None, "copy_note": "", "out": [],
                "advance": {}, "clock": self._assist_tick + rizin_emulation.TICK_STEP}
        answer, running = api["ret"], self._emulation is pipe
        if answer == "zero":
            plan.update(value=0, note=f"{conv['ret_reg']} = 0, the answer of a machine that is not "
                                      f"being watched")
        elif answer == "success":
            plan.update(value=1, note=f"{conv['ret_reg']} = 1, the call reports success")
        elif answer == "none":
            plan["note"] = "no register is set, because the call has no return value"
        elif answer == "handle":
            value, step = rizin_emulation.pseudo_value(maps, rizin_emulation.ASSIST_HANDLE,
                                                       self._assist_handle)
            if value is None:
                plan["note"] = "no value: this session's pseudo handles are used up; set one by hand"
            else:
                plan.update(value=value, advance={"handle": step},
                            note=f"{conv['ret_reg']} = {value:#x}, a pseudo handle that lies in no map "
                                 f"of this file, so nothing is ever read through it")
        elif not running:
            plan["note"] = ("no value yet: the emulation is not started, and this one is read from it "
                            "(the arguments of the call, or the run's own clock)")
        elif answer == "tick":
            plan.update(value=plan["clock"], advance={"tick": True},
                        note=f"{conv['ret_reg']} = {plan['clock']} ms, a clock that rises with every "
                             f"skip, so that a timing check sees time pass and no debugger")
        elif answer == "buffer":
            self._assist_buffer(pipe, conv, api, maps, plan)
        elif answer == "copy":
            self._assist_copy(pipe, conv, api, maps, plan)
        elif answer == "address":
            self._assist_address(pipe, conv, maps, plan)
        else:
            plan["note"] = f"no value: the table's answer '{_show(str(answer))}' is one this build " \
                           f"cannot build"
        if running:
            self._assist_out(pipe, conv, api, maps, plan)
        elif api.get("out"):
            plan["out"] = [{"addr": None, "data": None,
                            "note": "nothing is written to the call's out-parameters: the emulation is "
                                    "not started, so their pointers cannot be read"}]
        return plan

    def _assist_buffer(self, pipe, conv, api, maps, plan):
        """Plan a buffer for a memory API (gate held): the size the call asks for, rounded to pages, in
        memory that collides with neither the file's maps nor the stack nor a buffer an earlier call
        was given."""
        size = rizin_emulation.buffer_size(self._assist_arg(pipe, conv, api["size_arg"]))
        if size is None:
            plan["note"] = (f"no value: the size this call asks for (argument {api['size_arg'] + 1}) "
                            f"could not be read, or is above {rizin_emulation.ASSIST_BUFFER_MAX} bytes")
            return
        at = rizin_emulation.free_span(maps, size)
        if at is None:
            plan["note"] = f"no value: no free place for {size} bytes was found in the emulation's memory"
            return
        plan.update(value=at, buffer=size,
                    note=f"{conv['ret_reg']} = {at:#x}, a new buffer of {size} bytes that SKIP maps in "
                         f"the emulation's memory (aeim), so the code after it can really write into it")

    def _assist_copy(self, pipe, conv, api, maps, plan):
        """Plan the copy a copying API makes (gate held). Bounded to ASSIST_COPY_MAX bytes, and both
        ends have to lie in one map each: where nothing is mapped rizin reads 0xff, and copying that
        would put bytes nobody asked for into the file's memory while the summary claimed a step of an
        unpacking."""
        dst, src, size = (self._assist_arg(pipe, conv, i) for i in range(3))
        plan["value"] = dst
        if dst is None or src is None or size is None:
            plan["copy_note"] = "nothing is copied: the arguments of the call could not be read"
        elif not 0 < size <= rizin_emulation.ASSIST_COPY_MAX:
            plan["copy_note"] = (f"{size} bytes are not copied: at most "
                                 f"{rizin_emulation.ASSIST_COPY_MAX} bytes are moved at once")
        elif not (rizin_emulation.maps_hold(src, size, maps)
                  and rizin_emulation.maps_hold(dst, size, maps)):
            plan["copy_note"] = (f"{size} bytes are not copied: {src:#x} or {dst:#x} is not in one map "
                                 f"of the emulation, and rizin reads 0xff where nothing is mapped")
        else:
            plan["copy"] = (dst, src, size)
            plan["copy_note"] = f"{size} bytes are copied from {src:#x} to {dst:#x}"
        plan["note"] = (f"{conv['ret_reg']} = {dst:#x}, which is what the call returns, and "
                        if dst is not None else "") + plan["copy_note"]

    def _assist_address(self, pipe, conv, maps, plan):
        """Plan what GetProcAddress answers (gate held): the address the file's import table gives for
        the name the call asks for, else a pseudo address.

        The name is read from the argument's pointer (``pxj``), has to look like an export's name, and
        is compared with ``iij``'s names in Python -- it never goes into a command. A pseudo address is
        in no map, so a run that calls it stops with a trap instead of running on through nothing; the
        real export address does not exist in an ESIL run (the import slot holds an RVA: measured,
        [0x1400093a8:8]=0x96b8).
        """
        at = self._assist_arg(pipe, conv, 1)
        name = rizin_emulation.read_cstring(pipe.cmdj(f"pxj 64 @ {at:#x}")) if at is not None else None
        if name is not None:
            for entry in pipe.cmdj("iij", limit=VIEW_ANSWER_MAX) or []:
                if (isinstance(entry, dict) and entry.get("name") == name
                        and isinstance(entry.get("plt"), int) and not isinstance(entry["plt"], bool)):
                    plan.update(value=entry["plt"],
                                note=f"{conv['ret_reg']} = {entry['plt']:#x}, where this file imports "
                                     f"'{_show(name, 120)}'")
                    return
        value, step = rizin_emulation.pseudo_value(maps, rizin_emulation.ASSIST_PSEUDO,
                                                   self._assist_pseudo)
        asked = f"'{_show(name, 120)}'" if name else "the name"
        if value is None:
            plan["note"] = "no value: this session's pseudo addresses are used up; set one by hand"
            return
        plan.update(value=value, advance={"pseudo": step},
                    note=f"{conv['ret_reg']} = {value:#x}, a pseudo address in no map: {asked} is not "
                         f"an import of this file, and an ESIL run has no loaded module to take a real "
                         f"one from")

    def _assist_out(self, pipe, conv, api, maps, plan):
        """Plan the out-parameter writes of a row that has them (gate held): the pointer comes from the
        argument the row names, the bytes from rizin_emulation.out_bytes.

        Spec §4 asks for the **values** here, not only a return code: a QueryPerformanceCounter whose
        counter is never written lets a timing check see no time pass at all, and a GetComputerName
        that writes nothing answers no name. A pointer that is in no map writes nothing and says so,
        the way the buffer and the copy do -- and so does a text that the caller's own buffer has no
        room for (``out_room``): Windows writes no more than was asked for, and writing past a buffer
        inside a mapped page is still writing over something the sample owns.
        """
        room, text_note = self._assist_room(pipe, conv, api, maps), None
        for index, kind in api.get("out", ()):
            data, what = rizin_emulation.out_bytes(kind, api, plan["clock"])
            if data is None:
                continue
            if kind in rizin_emulation.OUT_TEXTS:
                text_note = self._assist_text_room(room, rizin_emulation.OUT_TEXTS[kind], what)
            if kind == "chars" and text_note is not None:
                # the length belongs to the name: where the name did not go, it does not either
                plan["out"].append({"addr": None, "data": None,
                                    "note": f"{what} is not written either"})
                continue
            if text_note is not None and kind in rizin_emulation.OUT_TEXTS:
                plan["out"].append({"addr": None, "data": None, "note": text_note})
                continue
            at = self._assist_arg(pipe, conv, index)
            if at is None:
                plan["out"].append({"addr": None, "data": None,
                                    "note": f"{what} is not written: argument {index + 1}, which holds "
                                            f"its pointer, could not be read"})
            elif not rizin_emulation.maps_hold(at, len(data), maps):
                plan["out"].append({"addr": at, "data": None,
                                    "note": f"{what} is not written: {at:#x} is not in one map of the "
                                            f"emulation"})
            else:
                plan["out"].append({"addr": at, "data": data,
                                    "note": f"{what} goes to {at:#x} ({len(data)} bytes)"})
                if kind in ("counter", "filetime"):
                    # the clock moves because this write used it, and only where it was really written
                    plan["advance"]["tick"] = True

    def _assist_room(self, pipe, conv, api, maps):
        """How many characters the call says its text buffer holds, or None where that cannot be read
        (gate held): ``out_room`` names the argument and whether it is the count itself or a pointer to
        it (GetComputerName and GetUserName pass a pointer, GetVolumeInformation the number)."""
        found = api.get("out_room")
        if not found:
            return None
        index, how = found
        value = self._assist_arg(pipe, conv, index)
        if value is None or how == "value":
            return value
        if not rizin_emulation.maps_hold(value, 4, maps):
            return None
        data = pipe.cmdj(f"pxj 4 @ {value:#x}")
        if not (isinstance(data, list) and len(data) == 4
                and all(isinstance(b, int) and 0 <= b < 256 for b in data)):
            raise ValueError("pxj did not answer a list of bytes")
        return int.from_bytes(bytes(data), "little")

    @staticmethod
    def _assist_text_room(room, text, what):
        """Why a text cannot go into the caller's buffer, or None when it fits: the name and its
        terminator have to fit in the characters the call said it had room for."""
        if room is None:
            return f"{what} is not written: the call does not say how much room its buffer has"
        if room < len(text) + 1:
            return (f"{what} is not written: the call's buffer holds {room} characters and the name "
                    f"needs {len(text) + 1} with its terminator")
        return None


    def _assist_apply(self, pipe, plan):
        """Write what the plan holds beside the register and the stack (gate held): the copy and the
        out-parameters; the words for the summary, including for what was *not* written."""
        notes = []
        if plan["copy"] is not None:
            dst, src, size = plan["copy"]
            self._assist_write(pipe, dst, self._assist_read(pipe, src, size))
            notes.append(f"{size} bytes were copied from {src:#x} to {dst:#x}")
        elif plan["copy_note"]:
            notes.append(plan["copy_note"])
        for write in plan["out"]:
            if write["data"] is not None:
                self._assist_write(pipe, write["addr"], write["data"])
            notes.append(write["note"])
        return notes

    def _assist_advance(self, plan):
        """Move the series this skip has applied on (R38: only here, never when a value is offered), so
        that the next clock reading is later and the next pseudo value is another one."""
        advance = plan["advance"]
        if advance.get("tick"):
            self._assist_tick = plan["clock"]
        if "handle" in advance:
            self._assist_handle = advance["handle"] + 1
        if "pseudo" in advance:
            self._assist_pseudo = advance["pseudo"] + 1

    @staticmethod
    def _assist_read(pipe, addr, size):
        """``size`` bytes from ``addr`` (gate held), read in ASSIST_READ_CHUNK pieces so that no one
        ``pxj`` answer has to hold a megabyte of JSON numbers."""
        data = bytearray()
        while len(data) < size:
            want = min(rizin_emulation.ASSIST_READ_CHUNK, size - len(data))
            found = pipe.cmdj(f"pxj {want} @ {addr + len(data):#x}")
            if not (isinstance(found, list) and len(found) == want
                    and all(isinstance(b, int) and 0 <= b < 256 for b in found)):
                raise ValueError("pxj did not answer a list of bytes")
            data += bytes(found)
        return bytes(data)

    @staticmethod
    def _assist_write(pipe, addr, data):
        """Write ``data`` at ``addr`` through the write cache (gate held), in ASSIST_WRITE_CHUNK pieces.

        The chunk is not tidiness: rizin 0.9.1 writes **nothing at all** for a ``wx`` whose command
        line passes about 4 KB and says so on stderr only, which ``cmd`` never reads (measured: 0x500
        bytes land, 0x7ff bytes do not). The bytes go through ``wx``, so they are the run's own, like
        every other byte a run writes: they stay out of the project and end with the session.
        """
        step = rizin_emulation.ASSIST_WRITE_CHUNK
        for at in range(0, len(data), step):
            pipe.cmd(f"wx {data[at:at + step].hex()} @ {addr + at:#x}")

    def _assist_arg(self, pipe, conv, index):
        """The ``index``-th argument of the call the PC stands on, or None (gate held).

        At 64 bits from rcx, rdx, r8, r9 (Microsoft x64); past the fourth nothing is read, because no
        row of the table needs it. At 32 bits from the stack -- and the word matters: the PC stands
        **on** the call, so the return address is not pushed yet and argument i is at [sp + 4*i], not
        at [sp + 4*(i+1)] (measured with rizin 0.9.1). Only inside the stack the start mapped: outside
        it rizin reads 0xff, and that is no argument.
        """
        if not conv["stack_args"]:
            names = conv["arg_regs"]
            if index >= len(names):
                return None
            found = rizin_emulation.parse_registers(pipe.cmd(f"ar {names[index]}"))
            return found[0]["value"] if found else None
        sp, stack, word = self._emulation_role(pipe, "SP"), self._emulation_stack_map, conv["word"]
        if sp is None or stack is None:
            return None
        at = sp + index * word
        if not (stack[0] <= at and at + word <= stack[1]):
            return None
        data = pipe.cmdj(f"pxj {word} @ {at:#x}")
        if not (isinstance(data, list) and len(data) == word
                and all(isinstance(b, int) and 0 <= b < 256 for b in data)):
            raise ValueError("pxj did not answer a list of bytes")
        return rizin_emulation.stack_words(data, word, self._emulation_big_endian)[0]

    def _assist_fix(self, pipe, conv, fix):
        """The stack correction the request asked for, checked (gate held).

        A whole number of words, at most ASSIST_MAX_ARGS of them, and only as far as the stack the
        start mapped reaches: a correction that moved the stack pointer out of it would leave every
        later state showing words that are no stack -- the hole the start's own stack check closed.
        """
        word, most = conv["word"], rizin_emulation.ASSIST_MAX_ARGS * conv["word"]
        if fix % word:
            raise RizinRefused(f"stack_fix must be a multiple of {word} bytes, this file's word")
        if fix > most:
            raise RizinRefused(f"stack_fix must be at most {rizin_emulation.ASSIST_MAX_ARGS} arguments "
                               f"({most} bytes)")
        if fix:
            sp, stack = self._emulation_role(pipe, "SP"), self._emulation_stack_map
            if sp is None or stack is None or not stack[0] <= sp + fix < stack[1]:
                raise RizinRefused(f"a correction of {fix} bytes would move the stack pointer out of the "
                                   f"emulation's stack: set it by hand, or start the emulation again")
        return fix

    def _assist_map(self, pipe, maps, plan, value):
        """Map the buffer a memory API answers with, at ``value`` (gate held); the summary's words.

        rizin's ``aeim`` moves the VM into the map it has just made -- the PC to the seek, the stack and
        base pointer to the middle of the new map, while the map made before stays (all measured) -- so
        the three registers are read first and written back afterwards. A buffer over something that is
        mapped already is **not** mapped: it would shadow the file's bytes or the stack.

        Then ``omf rwx`` for that map, because ``aeim`` maps **rw-** and with ``esil.exectrap`` set
        after ``aei`` -- which is how every run sets it -- the canonical unpacker (allocate, copy or
        decrypt, jump into the buffer) traps at the buffer's first instruction: "Trap, trying to execute
        on non-executable memory". Measured, and measured again with ``omf rwx``, which makes the same
        code run. The console cannot work around it (``o`` and ``om`` are refused, the guards are set
        again each run), and ``VirtualProtect`` answering success changes no permission. A real
        ``VirtualAlloc(PAGE_EXECUTE_READWRITE)`` is executable from the start too, and ``esil.exectrap``
        goes on guarding everything outside these buffers, which is what it is there for.

        The address, not the map's id: ``omf <flags>`` without one takes the map at the current offset,
        and ``@ <value>`` is that offset for one command (measured). Exactly one map covers ``value``
        at this point -- span_is_free said nothing was there, and the ``aeim`` just made one.
        """
        size = plan["buffer"]
        if not rizin_emulation.span_is_free(maps, value, size):
            return f"no memory was mapped at {value:#x}: something is mapped there already"
        before = {role: self._emulation_role(pipe, role) for role in ("PC", "SP", "BP")}
        pipe.cmd(f"aeim {value:#x} {size:#x} {rizin_emulation.ASSIST_MAP_NAME}")
        pipe.cmd(f"omf rwx @ {value:#x}")
        for role, was in before.items():
            if was is not None:
                pipe.cmd(f"ar {role}={was:#x}")
        self._emulation_remember(value, value + size)
        return f"a buffer of {size} bytes was mapped at {value:#x}"

    def _require_emulation(self, pipe):
        # A rizin that was restarted (a hung analysis step) has no emulation, whatever ran before.
        if self._emulation is not pipe:
            raise RizinRefused("the emulation is not started")

    @staticmethod
    def _require_io_cache(pipe, what="the emulation's writes"):
        if pipe.cmd("e io.cache").strip() != "true":
            raise RizinRefused(f"io.cache could not be switched on: {what} would be lost")

    def _emulation_read(self, pipe):
        """The state (gate held). ``changed``: the registers that differ from before the last change of
        any register, so reading the state again does not clear it."""
        registers = rizin_emulation.parse_registers(pipe.cmd("ar"))
        values = {r["name"]: r["value"] for r in registers}
        if values != self._emulation_after:
            self._emulation_before, self._emulation_after = self._emulation_after, values
        return {"running": True, "pc": rizin_emulation.word(self._emulation_role(pipe, "PC")),
                "registers": [{"name": r["name"], "value": rizin_emulation.word(r["value"])} for r in registers],
                "changed": rizin_emulation.changed_registers(self._emulation_before, registers),
                "stack": self._emulation_stack(pipe, self._emulation_role(pipe, "SP"), set(values)),
                "stopped": None, "arch": self.arch, "bits": self.bits}

    def _emulation_stack_mapped(self, maps):
        """Whether the stack that the start mapped is still among ``omlj``'s maps (aeim- in the console)."""
        stack = self._emulation_stack_map
        return isinstance(maps, list) and stack is not None and any(
            isinstance(m, dict) and (m.get("from"), m.get("to"), m.get("name")) == stack for m in maps)

    @staticmethod
    def _emulation_role(pipe, role):
        found = rizin_emulation.parse_registers(pipe.cmd("ar " + role))
        return found[0]["value"] if found else None

    def _emulation_stack(self, pipe, sp, registers):
        """Up to RIZIN_STACK_ROWS words from the stack pointer upwards, those inside the stack that the start
        mapped: addr, value and a hint. None at all when the stack pointer is not in that stack (it was
        unmapped, or the code moved the stack pointer elsewhere): rizin reads 0xff where nothing is mapped,
        which is no stack. Costs omlj and pxj, and for each distinct non-zero word in a map outside the stack
        afij, then fd.j if the word is in no function (measured: 5.8 ms for 16 words in a 1.4 KB function)."""
        size = {16: 2, 32: 4, 64: 8}.get(self.bits)
        if sp is None or size is None:
            return []
        maps = pipe.cmdj("omlj")
        stack = self._emulation_stack_map
        if not self._emulation_stack_mapped(maps):
            return []
        if not stack[0] <= sp < stack[1]:
            return []
        count = min(RIZIN_STACK_ROWS, (stack[1] - sp) // size)
        if not count:
            return []
        data = pipe.cmdj(f"pxj {count * size} @ {sp:#x}")
        if not isinstance(data, list) or not all(isinstance(b, int) and 0 <= b < 256 for b in data):
            raise ValueError("pxj did not answer a list of bytes")
        rows, known = [], {}
        for i, value in enumerate(rizin_emulation.stack_words(data, size, self._emulation_big_endian)):
            # A value inside the stack (a saved frame pointer, say) is no function or flag: not asked about.
            # One value that comes twice in the rows is asked about once.
            if stack[0] <= value < stack[1]:
                hint = None
            elif value in known:
                hint = known[value]
            else:
                hint = known[value] = self._emulation_hint(pipe, value, maps, registers)
            rows.append({"addr": rizin_emulation.word((sp + i * size) % 2 ** self.bits),
                         "value": rizin_emulation.word(value), "hint": hint})
        return rows

    @staticmethod
    def _emulation_hint(pipe, value, maps, registers):
        """The function the value points into, or a flag exactly at it that is not a register's; None
        for a value outside every map (fd would name the closest flag below, however far)."""
        if not value or not rizin_emulation.is_mapped(value, maps):
            return None
        hint = rizin_emulation.function_hint(value, pipe.cmdj(f"afij @ {value:#x}"))
        return hint or rizin_emulation.flag_hint(pipe.cmdj(f"fd.j @ {value:#x}"), registers)

    def analyze_full(self):
        """Full analysis: aaa's sub-steps that are not done yet, one by one (see aaa_steps).

        For a file over big_file, or after aaa had to be killed; a finished aaa
        already covers it. A rename, comment or patch that waits is saved first.
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
        """Write the project now if a change is waiting for its save; True if it did.

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
        """Save the project save_delay after the last rename, comment, patch or breakpoint."""
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
            # The change stays to be saved: by the next change, or when the session closes
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
        """Start rizin and load the project; returns (pipe, steps in the project, level, mode, note, patches,
        restore), restore being (the project's timeline or None, whether the project had a line that is none, whether
        it held the marker of a record a save had to drop)."""
        pipe = self._start_rizin()
        if not os.path.isfile(self._project):
            return pipe, [], None, None, None, [], (None, False, False)
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
            return (pipe, meta["done"], meta["level"], meta["mode"], None, meta["patches"],
                    (meta["restore"], meta["restore_refused"], meta["restore_dropped"]))
        pipe.close()
        try:
            os.replace(self._project, self._project + ".broken")
        except OSError:
            pass
        return self._start_rizin(), [], None, None, _PROJECT_FAILED, [], (None, False, False)

    def _replay_patches(self, patches):
        """Write the project's hand-made patches back into the cache (gate not held yet: the session is
        starting); a note naming those that were left out or held back, or None.

        ``patches`` are (addr, after_hex, over_run). A patch **over bytes a run wrote** is not written: this
        runs before any run, so it would land in the file's own, still encrypted bytes, and the next
        decryption would XOR over it instead of over the file's -- the patch gone and the decrypted bytes
        wrong, exactly where the analyst wanted to read. It goes into ``self._waiting``, the project keeps
        it, and the note names it. An entry without the mark comes from a project written before it and is
        applied as it always was.

        A project belongs to the file's SHA-256, so the bytes and the maps are the same ones the patches
        were made in -- except for a patch made into memory that only a running emulation had mapped
        (``aeim``'s stack): no map of ``omlj`` holds that address now, and it is a patch that never had
        a place in the file (the export says the same, design section 8). rizin would take such a write
        into its cache all the same (measured), so the check is the server's, and so is the one against
        a project somebody edited by hand. What rizin then does not report in ``wcj`` is left out as
        well, and the boot goes on either way: a project must not cost a session.
        """
        if not patches:
            return None
        # Decided by the entry alone, before rizin is asked anything: a patch that is held back needs no
        # command, so a rizin that fails over the others cannot take it with them. One too long to write
        # is not held but named below, with the others that cannot be applied.
        held, rest = [], []
        for patch in patches:
            over_run, long = patch[2], len(patch[1]) > 2 * rizin_emulation.MAX_PATCH_BYTES
            (held if over_run and not long else rest).append(patch)
        patches, held, known = rest, list(dict.fromkeys(held)), set(self._waiting)
        for patch in held:
            if patch not in known:
                known.add(patch)
                self._waiting.append(patch)
        # The note counts and names what **this** replay held back (the addresses it lists are that many),
        # not how much the waiting list grew by: a patch that waited already is held back once more by a
        # restart's replay of the mirror, and the user is told so.
        held_note = None
        if held:
            held_note = _PATCHES_HELD.format(where=_named_addresses(addr for addr, _, _ in held),
                                             **_patch_words(len(held)))
        if not patches:
            return held_note
        pipe = self._pipe
        skipped, planned = [], []
        try:
            pipe.cmd("e io.cache=true")
            cached = pipe.cmd("e io.cache").strip() == "true"
            maps = pipe.cmdj("omlj") if cached else None
            for addr, after, _ in patches:
                data = bytes.fromhex(after)
                # over the bound: one ``wx`` of it would pass what rizin reads of a command line and
                # land somewhere else (measured), so it is named in the note rather than written
                if (not cached or len(data) > rizin_emulation.MAX_PATCH_BYTES
                        or not rizin_emulation.maps_hold(addr, len(data), maps)):
                    skipped.append(addr)
                    continue
                entry = rizin_emulation.cache_entry(addr, data)
                planned.append(entry)
                self._mine.append(entry)
                pipe.cmd(f"wx {after} @ {addr:#x}")
            if planned:
                self._patch_list(pipe)  # keeps of the mirror what rizin's cache really holds
        except (ValueError, RizinTimeout, RizinDied):
            # The project decides how many commands this sends, so it must not be able to cost the
            # session: an answer in a shape nobody knows, or a rizin that stopped or hung over it,
            # leaves the file open without its patches and with a note saying so. Nothing is claimed as
            # this session's own either, so the next save does not write a patch that was never applied.
            self._mine, self._mine_over = [], []
            return " ".join(filter(None, [_PATCHES_LOST.format(where="", **_patch_words(len(patches))),
                                          held_note]))
        applied = collections.Counter(self._mine)
        for entry in planned:
            if applied[entry]:
                applied[entry] -= 1
            else:
                skipped.append(entry[0])
        if not skipped:
            return held_note
        lost_note = _PATCHES_LOST.format(where=f": {_named_addresses(skipped)}", **_patch_words(len(skipped)))
        return " ".join(filter(None, [lost_note, held_note]))

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
            self._notes = [n for n in self._notes if n in self._kept_notes]
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
        except (OSError, ValueError) as exc:
            # ValueError: the write cache the snapshot reads came back in a shape nobody knows. The save
            # is dropped, as an OSError drops it; the change stays and the next save takes it.
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
        """A step hung or crashed rizin: restart it and replay the finished steps and the patches (gate
        held).

        The restarted rizin has an empty write cache, so the hand-made patches have to go in again --
        and not only for this session: the mirror would be empty at the next save, which would write
        ``patches=`` over the ones the project holds. What goes back in is the session's own mirror, not
        the project's list: the mirror is what this rizin held (the project's can be older, and
        replaying it would bring back a patch the user has taken away since). What cannot be put back
        stays in ``self._lost``, which the next save keeps in the project rather than erasing.
        """
        what = (f"did not finish within {self._limit + self._grace:g} s" if isinstance(exc, RizinTimeout)
                else "stopped rizin")
        self._gate.relabel("restart")
        with self._lock:
            self._step = "restart"
        self._pipe.close()
        # The new rizin has an empty cache and registers of its own: what the timeline wrote is gone with the
        # old one, and a record that kept claiming it could be replayed would have no digest to be held to
        # (_saved_cache leaves a project alone over a cache that died, for the same reason). Said, and a start
        # that follows begins a timeline over a cache that is true.
        self._restore_discard(_RESTORE_RESTARTED)
        self._restore_pending = None
        replay, patch_note = [], None
        try:
            pipe, contained, _, _, _, _, _ = self._boot()
            if not self._use(pipe):
                return
            wanted, self._mine, self._mine_over = self._own_patches(), [], []
            patch_note = self._replay_patches(wanted)
            self._opened = list(self._mine)  # the cache a restore of the project's timeline starts from
            # what went back is a patch in the file's own bytes; a held-back one is in self._waiting
            back = {(addr, after, False) for addr, _, after in self._mine}
            held = set(self._waiting)
            self._lost = [patch for patch in wanted if patch not in back and patch not in held]
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
        if patch_note:
            self._finish("stopped", patch_note)

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
        self.function = _afl_line(pipe.cmd("afl."))[1] or None

    def _project_snapshot(self, pipe):
        """``Ps`` to a temporary file (gate held); _finish_save then makes it the project."""
        patches, ranges, rows = self._saved_cache(pipe)
        restore = self._restore_record_for_save(pipe, rows)
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
            return self._save_seq, tmp, self.level, self._mode, list(self._done), patches, ranges, restore, self._restore_lost

    def _saved_cache(self, pipe):
        """What the write cache says about the project (gate held): the patches to write into it, and
        the addresses only an emulation run ever wrote.

        The patches are this session's own writes as (addr, after_hex, over_run), in the order rizin's cache
        holds them; ``over_run`` is the mark the project keeps (see _read_patches). The cache is read back
        first, so the list is what rizin really holds *and* what this session wrote: a patch the console
        took back with ``wc-`` has left the mirror by then, and what an emulation run wrote was never in
        it. That is the whole point -- a run's bytes never stood in the file, and a project that baked
        them in would lose track of where bytes come from.

        ``self._lost`` are patches a restarted rizin could not take back (_recover): they are kept in
        the project, because a cache that died must not erase what the project already held. The next
        patch or take-back clears them -- from then on the live cache is the truth again.

        ``self._waiting`` are the patches held back over a run's bytes (_replay_patches). They are not in
        the cache and are kept in the project the same way, mark included, until they are taken out of it.

        The ranges are the other half of the same rule, for what rizin's own ``Ps`` keeps: what the
        project says about bytes that are gone with the cache is dropped (see _run_only). An empty cache
        gives no ranges, so a save after a lost cache leaves the project as it was rather than stripping
        it by guesswork.
        """
        rows = self._patch_list(pipe, ordered=True)  # one read for the whole save: the digests need this order
        kept = self._own_patches()
        waiting = self._waiting_left(kept)
        # one entry for one address and bytes, whichever mark: a patch that waits and one a restart lost are the
        # same patch, and the one the answer of patches() shows (the waiting one) is the one that stays
        known = {(addr, after) for addr, after, _ in kept + waiting}
        more = list(waiting)
        for patch in self._lost:
            if (patch[0], patch[1]) not in known:
                known.add((patch[0], patch[1]))
                more.append(patch)
        return kept + more, rizin_emulation.run_only_ranges(rows), rows

    def _restore_record_for_save(self, pipe, rows):
        """The timeline the project is to hold after this save, with its digests (gate held), or None for no
        record at all.

        A **clean** timeline that has something of a run to prove is the newest word there is: it becomes
        ``_restore_saved`` and replaces what the project held. In every other case the project's own line is
        what stays, and that is the point of the function being one: it returns the live timeline **only** when
        it can be offered (``_restore_reason``, not ``_restore["tainted"]``, which a standing breakpoint change
        does not set) and so a timeline with a reason cannot reach the file -- ``read_restore`` has no notion
        of taint, and one that was written would come back as a clean one. Nor does that erase anything: with
        no live timeline (a rizin that restarted, an unpatch, a session that never emulated) or a spoiled one
        the saved record is written again, as ``_saved_cache`` keeps ``_lost`` and ``_waiting`` over a cache
        that died.

        ``rows`` are the cache as _saved_cache read it, **in the order the writes were made in**. The digests are
        made from them in that order (_restore_digests): by address,
        two overlapping writes would swap, and the digest would be a plausible SHA-256 of bytes the run never
        left. A timeline the digests cannot be made for (a row of the cache that does not hold as many bytes
        as it says: ValueError) or that has none leaves the saved record as it is, and so does one that is
        not a record the writer makes: a project must not cost a session, nor a save."""
        record = self._restore
        if record is not None and not self._restore_reason():
            try:
                digests = self._restore_digests(pipe, rows)
                live = {"counters": dict(record["counters"]), "breakpoints": list(record["breakpoints"]),
                        "actions": [dict(action) for action in record["actions"]], "digests": digests}
                if digests:
                    rizin_emulation.restore_line(live, 0)  # raises ValueError for what is no record
                    self._restore_saved = live
            except ValueError as exc:
                print(f"[rizin] {self.sha256[:12]}: the timeline of the emulation was not saved ({exc})")
        return self._restore_saved

    def _finish_save(self, snapshot):
        seq, tmp, level, mode, done, patches, ranges, restore, lost = snapshot
        part = f"{self._project}.{seq}.part"
        try:
            if not os.path.isfile(tmp):
                raise OSError(f"rizin did not write {tmp}")
            left_out, fitted, alone = _sanitize_project(tmp, part, level, mode, done, patches, ranges, restore, lost)
            with self._replace_lock:
                if seq > self._saved_seq:
                    os.replace(part, self._project)
                    self._saved_seq = seq
            if left_out:
                self._note_dropped_patches(left_out)
            if restore is not None:
                self._note_restore(fitted, alone)
        finally:
            for leftover in (tmp, part):
                try:
                    os.remove(leftover)
                except OSError:
                    pass

    def _note_dropped_patches(self, count):
        """Say once that patches did not fit into the project: an analyst who patched must not find out
        at the next open that what was written is not all of it.

        It goes into the notes that outlive a re-plan as well: one Full analysis resets the notes, and
        without that the only signal that the pane's "kept with the project" is not true of every patch
        would disappear from a session where it still holds.
        """
        note = _PATCHES_DROPPED.format(chars=PROJECT_PATCH_CHARS, **_patch_words(count))
        print(f"[rizin] {self.sha256[:12]}: {note}")
        with self._lock:
            if self._dropped_noted or self._closed:
                return  # every save that follows would say it again
            self._dropped_noted = True
            self._kept_notes.append(note)
            self._notes.append(note)

    def _note_restore(self, fitted, fits_alone=True):
        """Say, once, that the timeline did not fit into the project (``fitted`` false), and take the note back
        when a later save has room for it again: the note is kept past a re-plan like the patches' one, and a
        warning that outlived its truth would be the other way to mislead. ``fits_alone`` says whom it is to
        blame: the patches, which have the budget first, or the timeline's own length."""
        with self._lock:
            if self._closed:
                return
            if fitted:
                # what the open said of the project it found ("the way is gone") is not true of one that holds the
                # record again, and it would send the user to decrypt what the pane is about to offer
                self._kept_notes = [n for n in self._kept_notes if n != _RESTORE_LOST_AT_OPEN]
                self._notes = [n for n in self._notes if n != _RESTORE_LOST_AT_OPEN]
            said = self._restore_dropped_note
            note = None if fitted else (_RESTORE_DROPPED if fits_alone else _RESTORE_TOO_LONG_ALONE).format(
                chars=PROJECT_PATCH_CHARS)
            if note == said:
                return  # every save that follows would say it again
            if said is not None:
                self._kept_notes = [n for n in self._kept_notes if n != said]
                self._notes = [n for n in self._notes if n != said]
            self._restore_dropped_note = note
            if note is None:
                return
            self._kept_notes.append(note)
            self._notes.append(note)
        print(f"[rizin] {self.sha256[:12]}: {note}")


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
