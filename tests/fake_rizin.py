#!/usr/bin/env python3
"""A stand-in for ``rizin -q0`` in the tests (CI has no rizin).

It speaks the pipe protocol: one NUL byte after start-up, then one command
per input line and a NUL after each answer. Answers are fixed and shaped like
rizin 0.9.1's output for tests/samples/pipesim.exe.

Environment:
  FAKE_RIZIN_LOG    every command received is appended as "<pid>\\t<command>";
                    the start-up line is "<pid>\\tSTART <argv as JSON>"
  FAKE_RIZIN_ENV_LOG  every start is appended as "<pid>\\t<START|VERSION|QC>\\t<SLEIGHHOME as JSON>"
                    (null when unset)
  FAKE_RIZIN_SLOW   "<command>:<seconds>[,...]": sleep before answering a
                    command whose first word matches (e.g. "aac:5,aaft:999")
  FAKE_RIZIN_FORMAT format reported by ``ij`` (default pe64)
  FAKE_RIZIN_NO_CODE  set: a file without functions (a text file, say)
  FAKE_RIZIN_NO_GHIDRA  set: rz-ghidra is missing (no ``pdgj``, not in ``Lc``)
  FAKE_RIZIN_CRASH  rizin dies on the command with this first word
  FAKE_RIZIN_FLAGS  this many more flags (str.extra_0000, ...) in ``flj``
  FAKE_RIZIN_STRINGS  this many more strings (text 0, ...) in ``izj``, after the others
  FAKE_RIZIN_FUNCTIONS  this many more functions (fcn.00000, ...) in ``afl``, ``aflj`` and ``flj``
  FAKE_RIZIN_AFL_NOISE  set: ``afl`` also prints a line that is no function row
  FAKE_RIZIN_BITS   32: an x86-32 file (``ij`` bits, the ESIL VM's registers); default 64
  FAKE_RIZIN_STACK  "<word>[,...]": the words ``aeim`` leaves at the stack pointer, upwards
  FAKE_RIZIN_NO_IO_CACHE  set: ``e io.cache=true`` does not take, ``e io.cache`` stays false
  FAKE_RIZIN_IO_CACHE_ONCE  set: only the first ``e io.cache=true`` takes (the console switched it off after)
  FAKE_RIZIN_ESIL_FLOOD  "<n>": a run that runs into esil.timeout first prints n lines of "WARNING: $ returned 0",
                    as every int3 does under esil.verbose=1 (148 000 a second measured), then the timeout line
  FAKE_RIZIN_NO_SP  set: ``ar SP`` answers nothing (a file whose profile has no SP role)
  FAKE_RIZIN_ESIL_RUNAWAY  set: ``aec`` and ``aesu`` run into esil.timeout (the warning on stderr, the PC where
                    it was)

Like rizin 0.9.1 it dies on ``aflj`` once a project with DWARF variable
origins has been loaded (see rizin_sessions._sanitize_project), and ``Poo``
brings back the settings (/core/config) and hints that a project holds.
``-v`` prints the version and ``-qc <cmd>`` runs one command, without a file.

The ESIL VM: ``aei`` arms it, ``aeim`` too and maps a stack (esil.stack.addr
and esil.stack.size, or its arguments) with the stack pointer in its middle
and the PC at the seek, ``aeim-`` unmaps it, ``aepc`` sets the PC. ``ar``
shows, reads (by name or the roles PC and SP) and sets the registers; before
``aei`` the register commands answer that ESIL is not initialized. ``pxj``
reads the stack, ``omlj`` lists it with the file's maps. ``fd`` describes the
closest flag below an address, ``fd.j`` lists the flags at it; like rizin's
aei, an armed VM has a flag per register at its value.

The write cache (``wx``, ``wcj``, ``wc-``, ``wc-*``; see write_cache) holds
the patches *and* what the emulation writes, as rizin's one cache does, and
every read of a byte goes through it. Without ``io.cache`` a write is lost.

Stepping moves the PC through the code model below: a call pushes its return address and goes to its target
(an indirect call goes to 0, where nothing is mapped: the callee is read from memory), a ret pops, a jmp
follows, a conditional jmp falls through (no flags). ``aes`` is one op, ``aeso`` runs a call to its return,
``aess`` skips a call (but not an indirect one, like rizin: ``aeso`` neither), ``aesu``/``aecu`` run to an
address, ``aecc`` to the next direct call (not before an indirect one), ``aec`` on. Like rizin 0.9.1 each
stops at a breakpoint (also a disabled one) with
"[ESIL] hit breakpoint at 0x..." on stdout, and a step at an address nothing is mapped at answers "Stopped
execution in an invalid instruction" on stderr and stays. ``db @ addr`` (the one it already has there stays,
with rizin's two ERROR lines; FAKE_RIZIN_BP_IGNORED sets none at all, as rizin does where another
breakpoint's width covers the address), ``db- @ addr``, ``db-*``, ``dbd``, ``dbe``, ``dblj``.

The views (afl, pdfj, afbj, pdj, axtj, axfj, afxj, izj, iij, flj, pxj, pdgj, ol.j, oml.j) answer
from one model of the code: entry0 calls sym.main, whose blocks branch, run
a long block, switch over two cases and leave by a tail call to
sym.watchdog. ``cmd @@= a b ...`` runs cmd at each address and, like rizin,
stops at an address ``pdj`` cannot read.
"""

import base64
import json
import os
import sys
import time

PID = os.getpid()
LOG = os.environ.get("FAKE_RIZIN_LOG")
SLOW = {}
for part in filter(None, os.environ.get("FAKE_RIZIN_SLOW", "").split(",")):
    name, _, seconds = part.rpartition(":")
    SLOW[name] = float(seconds)
CRASH = os.environ.get("FAKE_RIZIN_CRASH")
GHIDRA = not os.environ.get("FAKE_RIZIN_NO_GHIDRA")

FUNCTIONS = [] if os.environ.get("FAKE_RIZIN_NO_CODE") else [
    {"offset": 0x140001440, "name": "entry0", "size": 29, "nbbs": 1},
    {"offset": 0x140001490, "name": "sym.watchdog", "size": 38, "nbbs": 1},
    {"offset": 0x1400014B7, "name": "sym.main", "size": 1382, "nbbs": 30},
]
# A big dump: that many more functions, far from the ones above (a dump's thousands of fcn.*)
FUNCTIONS += [{"offset": 0x140010000 + i * 0x20, "name": f"fcn.{i:05d}", "size": 16, "nbbs": 1}
              for i in range(int(os.environ.get("FAKE_RIZIN_FUNCTIONS") or 0))]
SLEEP, PIPE, THREAD = 0x1400093A8, 0x1400093B0, 0x140009340
FLAGS = {"sym.imp.KERNEL32.dll_Sleep": SLEEP, "sym.imp.KERNEL32.dll_CreateNamedPipeA": PIPE,
         "str.child": 0x140005014}
BASE, MAPPED_END = 0x140000000, 0x14000A000
IMAGE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + bytes(range(256)) * 4
# The maps as "oml.j @ addr" shows them: parts of the opened file (fd 3, at delta) and a zero-filled part
# past .text's data (fd 4, like rizin's null:// maps); nothing else is mapped to the file
MAPS = [{"map": i + 1, "fd": fd, "delta": delta, "from": start, "to": end,
         "perm": "r-x" if ".text" in name else "r--", "name": name}
        for i, (fd, delta, start, end, name) in enumerate((
            (3, 0, BASE, BASE + 0x400, "fmap.header"),
            (3, 0x400, 0x140001000, 0x140003000, "fmap..text"),
            (4, 0, 0x140003000, 0x140004000, "mmap..text"),
            (3, 0x2400, 0x140005000, 0x140006000, "fmap..rdata"),
            (3, 0x3400, 0x140009000, MAPPED_END, "fmap..idata")))]


def _op(offset, size, text, kind, jump=None, fail=None, ptr=None, data=None):
    op = {"offset": offset, "size": size, "opcode": text, "disasm": text, "type": kind,
          "bytes": data if data else "90" * size}
    for key, value in (("jump", jump), ("fail", fail), ("ptr", ptr)):
        if value is not None:
            op[key] = value
    return op


def _block(*ops, cases=()):
    """A basic block: its ops; the last op's jump and fail are the block's edges."""
    return {"addr": ops[0]["offset"], "size": ops[-1]["offset"] + ops[-1]["size"] - ops[0]["offset"],
            "ops": list(ops), "cases": list(cases)}


def _long_block():
    ops = [_op(addr, 1, "nop", "nop") for addr in range(0x1400014CA, 0x1400015B9)]
    return _block(*ops, _op(0x1400015B9, 6, "call qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]", "ircall", ptr=PIPE),
                  _op(0x1400015BF, 3, "mov rsi, rax", "mov"),
                  _op(0x1400015C2, 5, "jmp 0x140001600", "jmp", jump=0x140001600))


BLOCKS = {
    0x140001440: [_block(_op(0x140001440, 4, "sub rsp, 0x28", "sub"),
                         _op(0x140001444, 5, "call sym.main", "call", jump=0x1400014B7, fail=0x140001449),
                         _op(0x140001449, 4, "add rsp, 0x28", "add"),
                         _op(0x14000144D, 1, "ret", "ret"))],
    0x140001490: [_block(_op(0x140001490, 4, "sub rsp, 0x28", "sub"),
                         _op(0x140001494, 5, "mov ecx, 0x3e8", "mov"),
                         _op(0x140001499, 6, "call qword [sym.imp.KERNEL32.dll_Sleep]", "ircall", ptr=SLEEP),
                         _op(0x14000149F, 4, "add rsp, 0x28", "add"),
                         _op(0x1400014A3, 1, "ret", "ret"))],
    0x1400014B7: [
        _block(_op(0x1400014B7, 2, "push r15", "rpush"),
               _op(0x1400014B9, 7, "sub rsp, 0x558", "sub"),
               _op(0x1400014C0, 5, "call dbg.__main", "call", jump=0x140001AF0, fail=0x1400014C5),
               _op(0x1400014C5, 3, "cmp ebx, 0x02", "cmp"),
               _op(0x1400014C8, 2, "jle 0x140001600", "cjmp", jump=0x140001600, fail=0x1400014CA)),
        _long_block(),
        _block(_op(0x140001600, 3, "cmp eax, 0x02", "cmp"),
               _op(0x140001603, 7, "jmp qword [rax*8 + 0x140005100]", "ijmp"),
               cases=(0x140001620, 0x140001630, 0x140001620)),
        _block(_op(0x140001620, 5, "mov ecx, 0x3e8", "mov"),
               _op(0x140001625, 6, "call qword [sym.imp.KERNEL32.dll_Sleep]", "ircall", ptr=SLEEP),
               _op(0x14000162B, 5, "jmp 0x140001640", "jmp", jump=0x140001640)),
        _block(_op(0x140001630, 5, "call sym.watchdog", "call", jump=0x140001490, fail=0x140001635),
               _op(0x140001635, 5, "jmp 0x140001640", "jmp", jump=0x140001640)),
        _block(_op(0x140001640, 2, "xor eax, eax", "xor"),
               _op(0x140001642, 7, "add rsp, 0x558", "add"),
               _op(0x140001649, 2, "pop r15", "pop"),
               _op(0x14000164B, 5, "jmp sym.watchdog", "jmp", jump=0x140001490)),
    ],
}
# Code outside every function: a check whose bytes are the real x86 encodings (each one checked with
# rz-asm -d -a x86 -b 64 at its address), so the patch kinds have an instruction to work on, and a thunk.
LOOSE_OPS = [_op(0x140003080, 3, "cmp eax, 0x01", "cmp", data="83f801"),
             _op(0x140003083, 2, "jz 0x140003090", "cjmp", jump=0x140003090, fail=0x140003085, data="740b"),
             _op(0x140003085, 6, "jnz 0x140003097", "cjmp", jump=0x140003097, fail=0x14000308B,
                 data="0f850c000000"),
             _op(0x14000308B, 5, "call sym.watchdog", "call", jump=0x140001490, fail=0x140003090,
                 data="e800e4ffff"),
             _op(0x140003098, 6, "jmp qword [sym.imp.KERNEL32.dll_CreateNamedPipeA]", "ijmp", ptr=PIPE),
             _op(0x14000309E, 1, "int3", "trap")]
XREFS = [{"from": src, "to": dst, "type": kind} for src, dst, kind in (
    (0x140001444, 0x1400014B7, "CALL"),
    (0x140001499, SLEEP, "CALL"),
    (0x1400014C0, 0x140001AF0, "CALL"),
    (0x1400015B9, PIPE, "CALL"),
    (0x140001603, 0x140005100, "DATA"),
    (0x140001625, SLEEP, "CALL"),
    (0x140001630, 0x140001490, "CALL"),
    (0x14000164B, 0x140001490, "CODE"),
    (0x140003098, PIPE, "CODE"),
)]
AGF = {"nodes": [{"id": 0, "title": "0x140001490", "offset": 0x140001490, "out_nodes": [],
                  "body": "sub rsp, 0x28\ncall qword [sym.imp.KERNEL32.dll_Sleep]\n"}]}
IZJ = [{"vaddr": vaddr, "paddr": vaddr - 0x140002600, "size": len(text) + 1, "length": len(text),
        "section": ".rdata", "type": "ascii", "string": text} for vaddr, text in (
    (0x140005000, "watchdog: giving up"),
    (0x140005014, "child"),
    (0x140005041, "\\\\.\\pipe\\msagent_%04x%02x"),
    (0x140005086, "parent: created %s"),
    (0x1400050A0, '<b>bold</b> & "quoted"'),
    (0x1400050C0, "Pipe closed"),
)]
IIJ = [{"ordinal": ordinal, "bind": "NONE", "type": "FUNC", "name": name, "libname": lib, "plt": plt}
       for ordinal, name, lib, plt in (
    (1, "CloseHandle", "KERNEL32.dll", 0x140009318),
    (4, "CreateNamedPipeA", "KERNEL32.dll", PIPE),
    (5, "CreateThread", "KERNEL32.dll", THREAD),
    (9, "Sleep", "KERNEL32.dll", SLEEP),
    (2, "strcmp", "msvcrt.dll", 0x1400094F0),
)]
# rz-ghidra's C for sym.main: (line, [(token, address)]) -> pdgj's code and offset annotations.
CODE = [
    ("int sym.main(int argc, char **argv)", []),
    ("{", []),
    ("    if (argc < 3) {", [("argc < 3", 0x1400014C5), ("if", 0x1400014C8)]),
    ('        s = "' + "\u00fc" * 40 + '"; Sleep(1000);', [("Sleep(1000)", 0x140001625)]),
    ("    }", []),
    ("    hPipe = CreateNamedPipeA(lpName);", [("hPipe =", 0x1400015BF), ("CreateNamedPipeA(lpName)", 0x1400015B9)]),
    ("    return 0;", [("return 0;", 0x140001640)]),
    ("}", []),
]

state = {"seek": 0x140001440, "names": {}, "comments": {}, "prj": "", "dwarf": False, "hints": {}, "bps": {},
         "cache": [],
         "config": {"asm.arch": "x86", "analysis.arch": "x86", "bin.lang": "c", "analysis.autoname": "false",
                    "analysis.apply.signature": "true", "analysis.calls": "false",
                    "scr.color": "0", "scr.pager": "", "scr.interactive": "false",
                    "io.cache": "false", "esil.romem": "false", "esil.breakoninvalid": "false", "esil.stack.addr": "0x100000",
                    "esil.stack.size": "0xf0000"}}

BITS = 32 if os.environ.get("FAKE_RIZIN_BITS") == "32" else 64
if BITS == 64:
    REG_NAMES = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)] + \
        ["rip", "rflags"]
    ROLES = {"PC": "rip", "SP": "rsp", "BP": "rbp"}
else:
    REG_NAMES = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"]
    ROLES = {"PC": "eip", "SP": "esp", "BP": "ebp"}
# The ESIL VM: regs is None until aei; stack is (addr, bytearray) while aeim's map is there.
esil = {"regs": None, "stack": None}
ESIL_CAP = 200000  # steps of one run: past it the fake's code has run into nothing it models
ESIL_INVALID = "ERROR: core: esil: Stopped execution in an invalid instruction (see e??esil.breakoninvalid)\n"


def log(text):
    if LOG:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{PID}\t{text}\n")


def log_env(mode):
    path = os.environ.get("FAKE_RIZIN_ENV_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{PID}\t{mode}\t{json.dumps(os.environ.get('SLEIGHHOME'))}\n")


def out(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    sys.stdout.buffer.write(data)


def err(text):
    sys.stderr.write(text)
    sys.stderr.flush()


def unquote(arg):
    # Only spaces and tabs around the argument: a name may start or end with \x85, U+2028 or U+2029,
    # which str.strip() would take off, and rizin 0.9.1 keeps those (checked with afn + afl).
    arg = arg.strip(" \t")
    if len(arg) >= 2 and arg[0] == arg[-1] == "'":
        return arg[1:-1].replace("\\'", "'")
    return arg


def number(expr):
    expr = expr.strip()
    for fn in FUNCTIONS:
        if expr in (fn["name"], name_of(fn)):
            return fn["offset"]
    if expr in FLAGS:
        return FLAGS[expr]
    try:
        return int(expr, 0)
    except ValueError:
        return None


def function_at(addr):
    for fn in FUNCTIONS:
        if fn["offset"] <= addr < fn["offset"] + fn["size"]:
            return fn
    return None


def name_of(fn):
    return state["names"].get(fn["offset"], fn["name"])


def function_ops(fn):
    """The ops of a function's blocks in address order, with fcn_addr/fcn_last and the comments set."""
    ops = [op for block in BLOCKS.get(fn["offset"], []) for op in block["ops"]]
    last = ops[-1]["offset"] if ops else fn["offset"]
    return [with_comment(dict(op, fcn_addr=fn["offset"], fcn_last=last)) for op in ops]


def with_comment(op):
    if op["offset"] in state["comments"]:
        op["comment"] = base64.b64encode(state["comments"][op["offset"]].encode("utf-8")).decode("ascii")
    return op


def linear(addr, count):
    """``pdj count``: the ops from addr on; bytes that start no op are 1-byte invalid ops; nothing unmapped."""
    known = {op["offset"]: op for fn in FUNCTIONS for op in function_ops(fn)}
    known.update((op["offset"], with_comment(dict(op, fcn_addr=0, fcn_last=0))) for op in LOOSE_OPS)
    ops = []
    while len(ops) < count and BASE <= addr < MAPPED_END:
        op = known.get(addr) or {"offset": addr, "size": 1, "opcode": "invalid", "disasm": "invalid",
                                 "bytes": f"{byte_at(addr):02x}", "type": "invalid", "fcn_addr": 0, "fcn_last": 0}
        ops.append(op)
        addr += op["size"]
    return ops


def byte_at(addr):
    for entry in reversed(state["cache"]):  # the cache sits above every map: the newest write wins
        if entry["addr"] <= addr < entry["addr"] + entry["size"]:
            return bytes.fromhex(entry["after"])[addr - entry["addr"]]
    stack = esil["stack"]
    if stack and stack[0] <= addr < stack[0] + len(stack[1]):
        return stack[1][addr - stack[0]]
    if not BASE <= addr < MAPPED_END:
        return 0xFF  # like rizin's io.unalloc
    i = addr - BASE
    return IMAGE[i] if i < len(IMAGE) else 0


def cache_write(addr, data, shown=None):
    """A write through rizin's write cache. Without io.cache it is lost, and rizin says so on stderr
    only (measured: "ERROR: Could not write hexpair '9090' at e"), which the server's cmd never reads:
    that is why the server sets io.cache and reads it back itself. UT64_MAX is refused outright
    (measured: rz_core_write_at asserts addr != UT64_MAX and writes nothing)."""
    if addr == 2 ** 64 - 1:
        err("WARNING: rz_core_write_at: assertion 'core && buf && addr != UT64_MAX' failed "
            "(line 153); returning false\n")
        err(f"ERROR: Could not write hexpair '{shown or data.hex()}' at {addr:x}\n")
        return
    if state["config"].get("io.cache") != "true":
        err(f"ERROR: Could not write hexpair '{shown or data.hex()}' at {addr:x}\n")
        return
    before = bytes(byte_at(addr + i) for i in range(len(data)))
    state["cache"].append({"addr": addr, "size": len(data), "before": before.hex(), "after": data.hex()})


def write_cache(word, rest, seek):
    """``wx <hex>``, ``wcj``, ``wc- [<from> [<to>]]`` and ``wc-*``, measured on rizin 0.9.1.

    One entry per write operation (a two-byte ``wx`` is one entry of size 2, four single-byte writes are
    four entries), and a second write over the same address is another entry whose "before" is what the
    first one wrote. ``wcj`` prints the entries comma separated **without** the brackets of an array,
    and nothing at all for an empty cache. ``wc-`` drops every entry that overlaps [from, to); without
    a ``to`` the range is one block (0x100) from ``from``, and without arguments it starts at the seek,
    so taking exactly one entry back needs an explicit range.
    """
    cache = state["cache"]
    if word == "wcj":
        return ",".join(json.dumps({"idx": i, "addr": e["addr"], "size": e["size"], "before": e["before"],
                                    "after": e["after"], "written": False})
                        for i, e in enumerate(cache)) + "\n"
    if word == "wc-*":
        del cache[:]
        return ""
    if word == "wc-":
        args = rest.split()
        start = number(args[0]) if args else seek
        if start is None:
            err(f"ERROR: core: Invalid address ({args[0]})\n")
            return ""
        end = number(args[1]) if len(args) > 1 else start + 0x100
        state["cache"] = [e for e in cache if e["addr"] + e["size"] <= start or e["addr"] >= end]
        return ""
    data = rest.strip()
    try:
        written = bytes.fromhex(data)
    except ValueError:
        written = b""
    if not written:
        err(f"ERROR: Could not write hexpair '{data}' at {seek:x}\n")
        return ""
    cache_write(seek, written, data)
    return ""


def esil_map_stack(args):
    """``aeim [addr [size [name]]]``: arm the VM, map the stack, SP and BP in its middle, PC at the seek."""
    if esil["regs"] is None:
        esil["regs"] = dict.fromkeys(REG_NAMES, 0)
    addr = number(args[0]) if args else int(state["config"]["esil.stack.addr"], 0)
    size = number(args[1]) if len(args) > 1 else int(state["config"]["esil.stack.size"], 0)
    memory = bytearray(size)
    sp = addr + size // 2
    word = BITS // 8
    for i, text in enumerate(filter(None, os.environ.get("FAKE_RIZIN_STACK", "").split(","))):
        value = int(text, 0) & (2 ** BITS - 1)
        memory[size // 2 + i * word:size // 2 + (i + 1) * word] = value.to_bytes(word, "little")
    name = f"mem.{args[2]}" if len(args) > 2 else f"mem.{addr:#x}_{size:#x}"  # like get_esil_stack_name
    esil["stack"] = (addr, memory, name)
    regs = esil["regs"]
    regs[ROLES["SP"]] = regs[ROLES["BP"]] = sp
    regs[ROLES["PC"]] = state["seek"]


def esil_mapped(addr):
    stack = esil["stack"]
    if stack and stack[0] <= addr < stack[0] + len(stack[1]):
        return True
    return any(m["from"] <= addr < m["to"] for m in MAPS)


def esil_executable(addr):
    stack = esil["stack"]
    if stack and stack[0] <= addr < stack[0] + len(stack[1]):
        return False  # aeim maps the stack rw-
    return any(m["from"] <= addr < m["to"] and "x" in m["perm"] for m in MAPS)


def esil_ops():
    ops = {op["offset"]: op for fn in FUNCTIONS for op in function_ops(fn)}
    ops.update((op["offset"], op) for op in LOOSE_OPS)
    return ops


def esil_push(value):
    regs, (base, memory, _name) = esil["regs"], esil["stack"]
    word = BITS // 8
    regs[ROLES["SP"]] = (regs[ROLES["SP"]] - word) % 2 ** BITS
    at = regs[ROLES["SP"]] - base
    if 0 <= at <= len(memory) - word:
        # like rizin: what the emulation writes goes through the write cache, the one the patches use too
        cache_write(regs[ROLES["SP"]], value.to_bytes(word, "little"))


def esil_pop():
    regs, (base, memory, _name) = esil["regs"], esil["stack"]
    word = BITS // 8
    sp = regs[ROLES["SP"]]
    at = sp - base
    value = int.from_bytes(bytes(byte_at(sp + i) for i in range(word)), "little") \
        if 0 <= at <= len(memory) - word else 0
    regs[ROLES["SP"]] = (sp + word) % 2 ** BITS
    return value


def esil_is_call(op):
    return op is not None and op["type"] in ("call", "ucall", "rcall", "ircall")


def esil_step_one(execute=True):
    """One instruction at the PC, as rizin's rz_core_esil_step does: "ok", "bp" (the new PC is a breakpoint:
    announced on stdout), "trap" (esil.exectrap: the PC is not in executable memory) or "invalid" (nothing is
    mapped at the PC and esil.breakoninvalid is on); both are announced on stderr and the PC stays."""
    regs = esil["regs"]
    pc = regs[ROLES["PC"]]
    if state["config"].get("esil.exectrap") == "true" and not esil_executable(pc):
        err("ERROR: core: esil: Trap, trying to execute on non-executable memory\n")
        return "trap"
    if not esil_mapped(pc):
        if state["config"].get("esil.breakoninvalid") == "true":
            err(ESIL_INVALID)
            return "invalid"
        regs[ROLES["PC"]] = pc + 1
        return "ok"
    op = esil_ops().get(pc)
    nxt = pc + (op["size"] if op else 1)
    kind = op["type"] if op else "nop"
    if kind == "call":
        esil_push(nxt)
        nxt = op["jump"]
    elif esil_is_call(op):
        esil_push(nxt)
        nxt = 0
    elif kind == "jmp":
        nxt = op["jump"]
    elif kind == "cjmp":
        nxt = op["fail"]
    elif kind == "ret":
        nxt = esil_pop()
    elif kind == "ijmp":
        nxt = 0
    regs[ROLES["PC"]] = nxt % 2 ** BITS
    return esil_stop_at_breakpoint()


def esil_stop_at_breakpoint():
    pc = esil["regs"][ROLES["PC"]]
    if pc in state["bps"]:  # rizin 0.9.1 does not look at "enabled": a disabled breakpoint still stops
        out(f"[ESIL] hit breakpoint at {pc:#x}\n")
        return "bp"
    return "ok"


def esil_run(until=None, stop_at_call=False, over=None):
    """aec, aecu, aesu, aecc, aeso's run: step until the PC is ``until`` (or at a call, or ``over``, the
    address after a call), a breakpoint or an invalid instruction stops it."""
    for _ in range(ESIL_CAP):
        result = esil_step_one()
        pc = esil["regs"][ROLES["PC"]]
        if result != "ok" or pc == until or pc == over:
            return
        if stop_at_call and (esil_ops().get(pc) or {}).get("type") in ("call", "ucall"):  # like aecc: not an ircall
            err(f"ERROR: call at {pc:#010x}\n")
            return
    err("WARNING: core: esil: timeout exceeded.\n")


def esil_timeout():
    """A run that ends at esil.timeout: the flood of warnings first (FAKE_RIZIN_ESIL_FLOOD), the timeout last."""
    for _ in range(int(os.environ.get("FAKE_RIZIN_ESIL_FLOOD") or 0)):
        err("WARNING: $ returned 0\n")
    err("WARNING: core: esil: timeout exceeded.\n")


def esil_command(word, rest, seek):
    """The ESIL step commands; None for a word that is none."""
    regs = esil["regs"]
    if word not in ("aes", "aeso", "aess", "aesu", "aecu", "aecc", "aec"):
        return None
    if regs is None:
        err("ERROR: ESIL is not initialized. Use `aei` first.\n")
        return ""
    pc = regs[ROLES["PC"]]
    op = esil_ops().get(pc)
    if word == "aes":
        for _ in range(int(rest) if rest.isdigit() else 1):
            if esil_step_one() != "ok":
                break
    elif word == "aeso":
        # rizin 0.9.1 steps over a plain "call" only: any other call (ircall) it steps into
        if op and op["type"] == "call" and esil_step_one() == "ok":
            esil_run(over=pc + op["size"])
        elif not op or op["type"] != "call":
            esil_step_one()
    elif word == "aess":
        # rizin 0.9.1 skips these (rz_core_esil_step's stepOver switch); an ircall it runs
        if op and op["type"] in ("call", "ucall", "rcall", "jmp", "cjmp", "ret"):
            regs[ROLES["PC"]] = pc + op["size"]  # not run
            esil_stop_at_breakpoint()
        else:
            esil_step_one()
    elif word in ("aesu", "aecu"):
        target = number(rest)
        if target is not None and os.environ.get("FAKE_RIZIN_ESIL_RUNAWAY"):
            esil_timeout()
        elif target is not None:
            esil_run(until=target)
    elif word == "aecc":
        esil_run(stop_at_call=True)
    elif os.environ.get("FAKE_RIZIN_ESIL_RUNAWAY"):  # aec
        esil_timeout()
    else:
        esil_run()
    return ""


def esil_breakpoints(word, seek):
    """``db @ addr`` and friends: rizin's db takes no address argument."""
    bps = state["bps"]
    if word == "dblj":
        return json.dumps([{"addr": addr, "size": 1, "perm": "--x", "hw": False, "trace": False,
                            "enabled": enabled, "valid": esil_mapped(addr), "data": "", "cond": ""}
                           for addr, enabled in sorted(bps.items())]) + "\n"
    if word == "db":
        if seek in bps or os.environ.get("FAKE_RIZIN_BP_IGNORED"):
            # rizin keeps the breakpoint it has there, disabled or not; FAKE_RIZIN_BP_IGNORED stands for
            # the address another breakpoint's width covers already, where rizin sets none at all
            err("ERROR: Breakpoint already set at this address.\n")
            err(f"ERROR: Cannot set breakpoint at {seek:#x}\n")
        else:
            bps[seek] = True
    elif word == "db-":
        if bps.pop(seek, None) is None:
            err(f"ERROR: Failed to delete breakpoint at {seek:#x}\n")
    elif word == "db-*":
        bps.clear()
    elif word in ("dbd", "dbe") and seek in bps:
        bps[seek] = word == "dbe"
    return ""



def esil_registers(rest):
    """``ar``, ``ar <name|PC|SP>``, ``ar <name>=<value>``, like rizin 0.9.1's ``name = 0x%016x`` lines."""
    regs = esil["regs"]
    if regs is None:
        err("ERROR: ESIL is not initialized. Use `aei` first.\n")
        return ""
    arg = rest.strip()
    if "=" in arg:
        name, _, value = arg.partition("=")
        name = ROLES.get(name.strip(), name.strip())
        if name not in regs or number(value) is None:
            err(f"ERROR: core: Unknown register {name}\n")
            return ""
        regs[name] = number(value) & (2 ** BITS - 1)
        return ""
    if not arg:
        return "".join(f"{name} = {value:#0{BITS // 4 + 2}x}\n" for name, value in regs.items())
    if arg == "SP" and os.environ.get("FAKE_RIZIN_NO_SP"):
        return ""
    name = ROLES.get(arg, arg)
    if name not in regs:
        err(f"ERROR: core: No such register '{arg}'\n")
        return ""
    return f"{name} = {regs[name]:#0{BITS // 4 + 2}x}\n\n"  # rizin ends the answer of a filter with an empty line


def all_flags():
    """(offset, name) of every flag; once the VM is armed, like rizin's aei, also a flag per register at
    its value (flagspace registers)."""
    flags = [(fn["offset"], name_of(fn)) for fn in FUNCTIONS] + [(a, n) for n, a in FLAGS.items()]
    if esil["regs"] is not None:
        flags += [(value, name) for name, value in esil["regs"].items()]
    return flags


def flag_describe(addr):
    """``fd``: the closest flag at or below addr, however far, as "name" or "name + delta"."""
    below = [(offset, name) for offset, name in all_flags() if offset <= addr]
    if not below:
        return ""
    offset, name = max(below)
    return f"{name}\n" if offset == addr else f"{name} + {addr - offset}\n"


def flags_at(addr):
    """``fd.j``: every flag exactly at addr (nothing at all where there is none)."""
    found = [{"name": name, "realname": name} for offset, name in all_flags() if offset == addr]
    return json.dumps(found) + "\n" if found else ""


def maps_json():
    """``omlj``: the file's maps and aeim's stack."""
    maps = list(MAPS)
    if esil["stack"]:
        addr, memory, name = esil["stack"]
        maps.append({"map": len(MAPS) + 1, "fd": 5, "delta": 0, "from": addr, "to": addr + len(memory),
                     "perm": "rw-", "name": name})
    return json.dumps(maps) + "\n"


def block_json(block):
    """A block as ``afbj`` shows it."""
    out = {"addr": block["addr"], "size": block["size"], "ninstr": len(block["ops"]), "traced": True}
    last = block["ops"][-1]
    if block["cases"]:
        out["switch_op"] = {"addr": last["offset"], "min_val": 0, "def_val": 0, "max_val": 0,
                            "cases": [{"addr": c, "jump": c, "value": i} for i, c in enumerate(block["cases"])]}
    elif last["type"] in ("jmp", "cjmp"):
        out["jump"] = last["jump"]
        if "fail" in last:
            out["fail"] = last["fail"]
    elif last["type"] not in ("ret", "ijmp"):
        out["jump"] = last["offset"] + last["size"]
    return out


def code_json():
    """``pdgj`` of sym.main: the code and its annotations at byte positions, as rizin prints them."""
    code, annotations = b"", [{"start": 0, "end": 3, "type": "syntax_highlight", "syntax_highlight": "datatype"}]
    for text, tokens in CODE:
        line = text.encode("utf-8")
        for token, addr in tokens:
            start = len(code) + line.index(token.encode("utf-8"))
            annotations.append({"start": start, "end": start + len(token.encode("utf-8")), "type": "offset",
                                "offset": addr})
        code += line + b"\n"
    return {"code": code.decode("utf-8"), "annotations": annotations}


def save_project(path):
    functions = {}
    for fn in FUNCTIONS:
        functions[hex(fn["offset"])] = {"name": name_of(fn), "vars": [
            {"name": "hDllHandle", "type": "HANDLE", "kind": "formal_parameter",
             "storage": {"type": "reg", "reg": "rcx"}, "origin": "DWARF", "dw_var": 16182},
            {"name": "pfunc", "type": "_PVFV *", "kind": "variable",
             "storage": {"type": "eval_pending", "eval_pending": 16221}, "origin": "DWARF",
             "dw_var": 16221}]}
    lines = ["/", "type=rizin rz-db project", "version=25", "", "/core", f"offset={state['seek']:#x}",
             "", "/core/analysis/functions"]
    lines += [f"{k}={json.dumps(v, separators=(',', ':'))}" for k, v in functions.items()]
    lines += ["", "/core/fake", "comments=" + json.dumps({hex(k): v for k, v in state["comments"].items()})]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def load_project(path):
    ns = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("/"):
                ns = line
            elif ns == "/core/analysis/functions" and "=" in line:
                key, value = line.split("=", 1)
                state["names"][int(key, 16)] = json.loads(value)["name"]
                if '"DWARF"' in value:
                    state["dwarf"] = True
            elif ns == "/core/fake" and line.startswith("comments="):
                state["comments"] = {int(k, 16): v for k, v in json.loads(line[9:]).items()}
            elif ns == "/core" and line.startswith("offset="):
                state["seek"] = int(line[7:], 16)
            elif ns == "/core/config" and "=" in line:  # like Poo: the saved settings come back
                key, value = line.split("=", 1)
                state["config"][key] = value
            elif ns == "/core/analysis/hints" and "=" in line:
                key, value = line.split("=", 1)
                state["hints"][int(key, 16)] = json.loads(value)
    state["prj"] = path


def answer(cmd):
    cmd, _, grep = cmd.partition("~")
    if grep == "?":
        return f"{len(answer(cmd).splitlines())}\n"
    if " @@= " in cmd:
        base, _, targets = cmd.partition(" @@= ")
        parts = []
        for target in targets.split():
            addr = number(target)
            if base.split(" ", 1)[0] == "pdj" and not linear(addr or 0, 1):
                break  # like rizin, the loop stops at an address it cannot read
            parts.append(answer(f"{base} @ {target}"))
        return "".join(parts)
    at = None
    if " @ " in cmd:
        cmd, _, at = cmd.rpartition(" @ ")
    # @! N: the block for the command (pdj decodes only the block, of 256 bytes unless set)
    cmd, _, block = cmd.partition(" @! ")
    seek = state["seek"] if at is None else number(at)
    if seek is None:
        err(f"ERROR: core: Invalid address ({at.strip()})\n")
        return ""
    word, _, rest = cmd.strip().partition(" ")
    if word in ("q", "q!"):
        sys.exit(0)
    if word == "ij":
        fmt = os.environ.get("FAKE_RIZIN_FORMAT", "pe64")
        return json.dumps({"core": {"file": sys.argv[-1], "size": os.path.getsize(sys.argv[-1]),
                                    "format": fmt},
                           "bin": {"arch": "x86", "bits": BITS, "bintype": "pe", "lang": "c"}}) + "\n"
    if word == "afl":
        # rizin 0.9.1: "<offset> <nbbs> <size>[ -> <realsz>]  <name>", by address; realsz where there are gaps
        lines = []
        if os.environ.get("FAKE_RIZIN_AFL_NOISE"):
            lines += ["WARN: a line that is no function row", "0x140001440 nbbs size name"]
        for fn in sorted(FUNCTIONS, key=lambda f: f["offset"]):
            real = f" -> {fn['size'] - 82}" if fn["nbbs"] > 1 else ""
            lines.append(f"{fn['offset']:#011x} {fn['nbbs']:4} {fn['size']:<4}{real:<7}  {name_of(fn)}")
        return "".join(line + "\n" for line in lines)
    if word == "aflj":
        if state["dwarf"]:
            os._exit(139)
        return json.dumps([dict(fn, name=name_of(fn)) for fn in FUNCTIONS]) + "\n"
    if word == "afl.":
        fn = function_at(seek)
        return f"{fn['offset']:#x} {name_of(fn)}\n" if fn else ""
    if word == "afij":
        fn = function_at(seek)
        return json.dumps([dict(fn, name=name_of(fn))] if fn else []) + "\n"
    if word in ("pdfj", "afbj", "afxj"):
        fn = function_at(seek)
        if not fn:
            err(f"ERROR: Cannot find function at {seek:#x}\n")
            return ""
        if word == "pdfj":
            return json.dumps({"name": name_of(fn), "size": fn["size"], "addr": fn["offset"],
                               "ops": function_ops(fn)}) + "\n"
        if word == "afbj":
            return json.dumps([block_json(b) for b in BLOCKS.get(fn["offset"], [])]) + "\n"
        return json.dumps([x for x in XREFS if function_at(x["from"]) is fn]) + "\n"
    if word == "pdj":
        ops = linear(seek, int(rest) if rest.isdigit() else 1)
        size = int(block) if block.isdigit() else 256
        inside = [op for op in ops if op["offset"] + op["size"] <= seek + size]
        if len(inside) < len(ops):
            # like rizin 0.9.1 past the block: a broken op (no address) in place of the next one
            ops = inside + [{"offset": 2 ** 64 - 1, "size": 0, "opcode": "invalid", "disasm": "invalid", "type": "null",
                             "fcn_addr": 0, "fcn_last": 0}] + ops[len(inside) + 1:]
        return json.dumps(ops) + "\n" if ops else ""
    if word == "agf" and rest == "json":
        return json.dumps(AGF) + "\n"
    if word in ("axtj", "axfj"):
        key = "to" if word == "axtj" else "from"
        return json.dumps([x for x in XREFS if x[key] == seek]) + "\n"
    if word in ("izj", "iij"):
        if word == "iij":
            return json.dumps(IIJ) + "\n"
        extra = int(os.environ.get("FAKE_RIZIN_STRINGS") or 0)
        texts = [(0x140006000 + i * 16, f"text {i}") for i in range(extra)]
        return json.dumps(IZJ + [{"vaddr": vaddr, "paddr": vaddr - 0x140002600, "size": len(text) + 1, "length": len(text),
                                  "section": ".data", "type": "ascii", "string": text} for vaddr, text in texts]) + "\n"
    if word == "flj":
        # The functions' flags (renamed with them) and the other flags, in no particular order, like rizin
        extra = int(os.environ.get("FAKE_RIZIN_FLAGS") or 0)
        flags = [(name_of(fn), fn["offset"], fn["size"]) for fn in FUNCTIONS]
        flags += [(name, addr, 8) for name, addr in FLAGS.items()]
        flags += [(f"str.extra_{i:04d}", 0x140007000 + i * 16, 16) for i in range(extra)]
        return json.dumps([{"name": name, "realname": name.split(".")[-1], "size": size, "offset": addr}
                           for name, addr, size in reversed(flags)]) + "\n"
    if word == "pxj":
        count = int(rest) if rest.isdigit() else 256
        return json.dumps([byte_at(seek + i) for i in range(count)]) + "\n"
    if word == "ol.j":
        return json.dumps({"raised": True, "fd": 3, "uri": sys.argv[-1], "from": 0, "writable": False,
                           "size": os.path.getsize(sys.argv[-1])}) + "\n"
    if word == "oml.j":
        found = next((m for m in MAPS if m["from"] <= seek < m["to"]), None)
        if found is None:
            err(f"ERROR: Cannot find any map at the current address {seek:x}\n")
            return ""
        return json.dumps(found) + "\n"
    if word == "Lc":
        plugins = ["java: Suite of java commands, type `java` for more info (v1.0, LGPL-3.0-only)"]
        if GHIDRA:
            plugins.append("ghidra: Ghidra integration (v0.9.1, LGPL3)")
        return "\n".join(plugins) + "\n"
    if word == "pdgj":
        if not GHIDRA:
            err("ERROR: Command 'pdgj' does not exist.\n")
            return ""
        fn = function_at(seek)
        if not fn or fn["offset"] != 0x1400014B7:
            err("No function at this offset\n")
            return ""
        return json.dumps(code_json()) + "\n"
    if word == "s":
        if rest:
            target = number(rest)
            if target is None:
                err(f"ERROR: Cannot seek to unknown address '{rest}'\n")
            else:
                state["seek"] = target
            return ""
        return f"{seek:#x}\n"
    if word == "e":
        tokens = rest.split()
        if tokens and all("=" in token for token in tokens):
            for token in tokens:
                key, _, value = token.partition("=")
                if key == "io.cache" and value == "true":
                    state["cache_sets"] = state.get("cache_sets", 0) + 1
                    if os.environ.get("FAKE_RIZIN_NO_IO_CACHE") or (
                            os.environ.get("FAKE_RIZIN_IO_CACHE_ONCE") and state["cache_sets"] > 1):
                        continue
                state["config"][key] = value
                if key in ("asm.arch", "analysis.arch"):  # like rizin, one sets the other
                    state["config"]["asm.arch"] = state["config"]["analysis.arch"] = value
            return ""
        key = rest.strip()
        if key == "prj.file":
            return state["prj"] + "\n"
        return state["config"].get(key, "") + "\n"
    if word == "ahl":
        return "".join(f" {addr:#x} =>" + "".join(f" {k}='{v}'" for k, v in hint.items()) + "\n"
                       for addr, hint in sorted(state["hints"].items()) if hint)
    if word in ("aha-", "ahe-"):
        state["hints"].get(seek, {}).pop("arch" if word == "aha-" else "esil", None)
        return ""
    if word == "echo":
        return rest + "\n"
    if word == "afn":
        fn = function_at(seek)
        if fn and fn["offset"] == seek:  # like rizin 0.9.1: only at the function's start, else nothing happens
            state["names"][fn["offset"]] = unquote(rest)
        return ""
    if word == "CC-":
        state["comments"].pop(seek, None)
        return ""
    if word == "CCu":
        state["comments"][seek] = base64.b64decode(rest.split(":", 1)[1]).decode("utf-8")
        return ""
    if word == "CC.":
        return state["comments"].get(seek, "") + ("\n" if seek in state["comments"] else "")
    if word == "Ps":
        save_project(unquote(rest))
        return ""
    if word == "Poo":
        load_project(unquote(rest))
        return ""
    if word == "pr":
        return b"MZ\x90\x00\x03\x00\x00\x00rest\n"
    if word == "x" and rest.isdigit():
        return "A" * int(rest)
    if word.startswith("Z") or word == "xyzzy":
        err(f"ERROR: Command '{word}' does not exist.\n")
        return ""
    if word in ("db", "db-", "db-*", "dbd", "dbe", "dblj"):
        if word not in ("dblj", "db-*") and at is None:
            err("ERROR: Wrong number of arguments passed to `db`, see its help with `db?`\n")
            return ""
        return esil_breakpoints(word, seek)
    if word in ("wx", "wcj", "wc-", "wc-*"):
        return write_cache(word, rest, seek)
    stepped = esil_command(word, rest, seek)
    if stepped is not None:
        return stepped
    if word == "aei":
        # like rizin's reinit: a new VM, the registers stay, the PC goes to the seek
        if esil["regs"] is None:
            esil["regs"] = dict.fromkeys(REG_NAMES, 0)
        esil["regs"][ROLES["PC"]] = seek
        return ""
    if word == "aeim":
        esil_map_stack(rest.split())
        return ""
    if word == "aeim-":
        esil["stack"] = None
        return ""
    if word == "aepc":
        if esil["regs"] is None:
            err("ERROR: ESIL is not initialized. Use `aei` first.\n")
        elif number(rest) is not None:
            esil["regs"][ROLES["PC"]] = number(rest)
        return ""
    if word == "ar":
        return esil_registers(rest)
    if word == "fd":
        return flag_describe(seek)
    if word == "fd.j":
        return flags_at(seek)
    if word == "omlj":
        return maps_json()
    if word.startswith("a") or word in ("Fa",):
        return ""
    if word == "pd":
        return f"fake disassembly at {seek:#x}\n"
    return f"fake output for: {cmd}\n"


def main():
    args = sys.argv[1:]
    if "-v" in args:
        log_env("VERSION")
        log("VERSION")
        print("rizin 0.9.1 @ linux-x86-64, package: fake")
        return
    if "-qc" in args:
        command = args[args.index("-qc") + 1]
        log_env("QC")
        log("QC " + command)
        out(answer(command))
        sys.stdout.flush()
        return
    log_env("START")
    log("START " + json.dumps(args))
    out(b"\0")
    sys.stdout.flush()
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline()
        if not line:
            return
        cmd = line.decode("utf-8", "replace").rstrip("\r\n")
        log(cmd)
        if CRASH and cmd.split(" ", 1)[0] == CRASH:
            os._exit(139)
        delay = SLOW.get(cmd.split(" ", 1)[0])
        if delay:
            time.sleep(delay)
        out(answer(cmd))
        out(b"\0")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
