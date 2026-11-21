"""Pure logic of the RIZIN tab's emulation: no pipe and no Flask, so it is testable on its own.

rizin_sessions runs the commands; what their answers mean is decided here, where a
wrong value would silently show a wrong register, stack word or pointer.
"""

import bisect
import json
import re

# One line of ``ar``: "rax = 0x0000000000000041" (rizin 0.9.1 pads the value to the register's width).
_REGISTER_LINE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_.]*) = (0x[0-9a-fA-F]+)\s*")


def parse_registers(text):
    """The registers of ``ar``'s answer, in its order: [{"name", "value"}]. Lines that are no register
    with a hex value (a blank line, a warning, a value rizin could not read) are left out."""
    registers = []
    for line in text.splitlines():
        m = _REGISTER_LINE.fullmatch(line)
        if m:
            registers.append({"name": m.group(1), "value": int(m.group(2), 16)})
    return registers


def changed_registers(before, registers):
    """The names of the registers whose value differs from ``before`` ({name: value}); none without one."""
    if before is None:
        return []
    return [r["name"] for r in registers if r["name"] in before and before[r["name"]] != r["value"]]


def stack_words(data, word_size, big_endian):
    """``pxj``'s bytes as words of ``word_size`` bytes in the file's byte order; a partial word is dropped."""
    order = "big" if big_endian else "little"
    return [int.from_bytes(bytes(data[i:i + word_size]), order)
            for i in range(0, len(data) - word_size + 1, word_size)]


def stack_map(maps, sp, size):
    """The map that aeim made for the emulation's stack: of ``omlj``'s maps the one of ``size`` bytes that
    holds the stack pointer and has aeim's name (mem.<addr>_<size>, rizin 0.9.1's get_esil_stack_name);
    (from, to, name), or None (also without a stack pointer: ``ar SP`` answered nothing)."""
    if sp is None:
        return None
    name = re.compile(r"mem\.0x[0-9a-f]+_0x%x" % size)
    for m in maps if isinstance(maps, list) else []:
        if (isinstance(m, dict) and isinstance(m.get("from"), int) and isinstance(m.get("to"), int)
                and isinstance(m.get("name"), str) and name.fullmatch(m["name"])
                and m["to"] - m["from"] == size and m["from"] <= sp < m["to"]):
            return m["from"], m["to"], m["name"]
    return None


def is_mapped(value, maps):
    """Whether ``value`` lies in one of ``omlj``'s maps (``to`` is the end, not in the map)."""
    if not isinstance(maps, list):
        return False
    return any(isinstance(m, dict) and isinstance(m.get("from"), int) and isinstance(m.get("to"), int)
               and m["from"] <= value < m["to"] for m in maps)


def maps_hold(addr, size, maps):
    """Whether one map of ``omlj`` holds all ``size`` bytes from ``addr``.

    One map, not "every byte is mapped somewhere": a range that starts in one map and ends in the next
    has no one place in the file, and both its ends can be mapped while the hole between them is not.
    """
    if not isinstance(maps, list) or size <= 0:
        return False
    return any(isinstance(m, dict) and isinstance(m.get("from"), int) and isinstance(m.get("to"), int)
               and m["from"] <= addr and addr + size <= m["to"] for m in maps)


def function_hint(value, functions):
    """``afij @ value``'s function as a hint for ``value``: its name at its entry, "name + delta" inside it
    (offset <= value < offset + size), None for none or a value outside the function it names."""
    for fn in functions if isinstance(functions, list) else []:
        if not isinstance(fn, dict):
            continue
        offset, size, name = fn.get("offset"), fn.get("size"), fn.get("name")
        if (isinstance(offset, int) and isinstance(size, int) and isinstance(name, str) and name
                and offset <= value < offset + size):
            return name if value == offset else f"{name} + {value - offset}"
    return None


def flag_hint(flags, registers):
    """The first of ``fd.j``'s flags at a value that is not one of the emulator's own register flags (aei
    sets a flag per register at its value, flagspace registers: their names are those of ``registers``)."""
    for flag in flags if isinstance(flags, list) else []:
        name = flag.get("name") if isinstance(flag, dict) else None
        if isinstance(name, str) and name and name not in registers:
            return name
    return None


# The run kinds and the rizin 0.9.1 command each one is built on ("until" takes an address: aesu <addr>).
# "to_call" is no single command: aecc and aesuo, which rizin offers for it, do not stop before a call through
# the import table (`call qword [rip+..]` is "ircall": they run into it) and ignore esil.timeout, because they
# step one instruction per rz_core_esil_step, whose timer starts again each time. to_call is built on aesu
# instead (see next_call_stop). aeso and aess handle only direct calls as well (see skip_call, over_call).
STEP_COMMANDS = {"step": "aes", "over": "aeso", "skip": "aess", "to_call": "aesu",
                 "cont": "aec", "until": "aesu"}

# What rizin 0.9.1 prints when a run stops, checked with the binary. stdout: "[ESIL] hit breakpoint at 0x14".
# stderr: "WARNING: core: esil: timeout exceeded." (esil.timeout); "ERROR: core: esil: Stopped execution in
# an invalid instruction (see e??esil.breakoninvalid)" (esil.breakoninvalid: bytes rizin cannot decode);
# "ERROR: core: esil: Trap, trying to execute on non-executable memory" (esil.exectrap, which takes effect
# only when it is set after aei); "WARNING: core: TRAP" (esil.iotrap on an invalid read or write: only with
# esil.verbose, else the run stops without a word); and from the sources "esil condition breakpoint!".
# Other ERROR lines are no stop: aecc's "ERROR: call at 0x..." is the goal reached.
_REASONS = (
    ("breakpoint", re.compile(r"\[ESIL\] hit breakpoint|esil condition breakpoint")),
    ("timeout", re.compile(r"esil: timeout exceeded")),
    ("invalid", re.compile(r"invalid instruction")),
    ("trap", re.compile(r"esil: Trap,|ESIL TRAP|core: TRAP")),
)


def stop_reason(output, stderr):
    """Why a run stopped, from what rizin printed: "breakpoint", "timeout", "invalid", "trap", else "step"
    (it did what it was asked: one step, or up to the address or call)."""
    text = f"{output}\n{stderr}"
    for reason, pattern in _REASONS:
        if pattern.search(text):
            return reason
    return "step"


def is_executable(value, maps):
    """Whether ``value`` lies in a map of ``omlj`` that can execute (perm has an x): where rizin's
    esil.exectrap lets the PC run. Stepping onto an address that is not leaves no message, only the next step."""
    if not isinstance(maps, list):
        return False
    return any(isinstance(m, dict) and isinstance(m.get("from"), int) and isinstance(m.get("to"), int)
               and isinstance(m.get("perm"), str) and "x" in m["perm"] and m["from"] <= value < m["to"] for m in maps)


def op_at(ops, pc):
    """The op at ``pc`` of ``pdj``'s answer as (type, size), None where rizin decoded none there."""
    first = ops[0] if isinstance(ops, list) and ops else None
    if (isinstance(first, dict) and first.get("offset") == pc and isinstance(first.get("type"), str)
            and isinstance(first.get("size"), int) and first["size"] > 0):
        return first["type"], first["size"]
    return None


def is_call(op_type):
    """call, ucall, rcall, ircall, icall, ccall...: rizin's types of an instruction that calls."""
    return isinstance(op_type, str) and op_type.endswith("call")


# What rizin's own commands handle. aess skips these (rz_core_esil_step's stepOver switch); an ircall (and an
# icall, a ccall) it runs. aeso steps over a plain "call" only; every other call it steps into.
_AESS_SKIPS = ("call", "ucall", "rcall")


def skip_call(op_type):
    """Whether the op is a call that aess does not skip (so the server sets the PC after it itself)."""
    return is_call(op_type) and op_type not in _AESS_SKIPS


def over_call(op_type):
    """Whether the op is a call that aeso does not step over (so the server runs to the address after it)."""
    return is_call(op_type) and op_type != "call"


def _ends_a_run(op_type):
    # an instruction after which the next one is not at the next address, or that stops the emulation
    return isinstance(op_type, str) and ("jmp" in op_type or "ret" in op_type
                                         or op_type in ("swi", "cswi", "trap", "ill", "invalid", "null"))


def next_call_stop(ops, pc):
    """Where the emulation runs to, looking for the next call, from ``pdj``'s ops at ``pc`` (the straight
    code up to its first jump, return or call): ("call", addr) a call that is next, ("branch", addr) a jump
    or return that ends the straight code, ("more", addr) the end of the ops, none of them yet."""
    end = pc
    for op in ops if isinstance(ops, list) else []:
        if not (isinstance(op, dict) and isinstance(op.get("offset"), int) and isinstance(op.get("size"), int)
                and op["size"] > 0 and op["offset"] == end):
            break
        if is_call(op.get("type")):
            return "call", op["offset"]
        if _ends_a_run(op.get("type")):
            return "branch", op["offset"]
        end = op["offset"] + op["size"]
    return "more", end


# --- Patching: the bytes, and the write cache's list ------------------------

MAX_PATCH_BYTES = 4096

# x86's conditional jumps and their opposites, for "flip". Both forms: 7x rel8 (two bytes) and 0f 8x rel32
# (six). In each pair the even opcode is the condition and the odd one its negation, which is why the table
# is built rather than written out; all 32 checked with rz-asm (-d -a x86 -b 64): 70 is "jo", 71 "jno",
# 74 "jz", 75 "jnz" ... 7f "jnle", and 0f80..0f8f the same conditions with a 32-bit displacement.
JUMP_PAIRS = {}
for _base, _prefix in ((0x70, ""), (0x80, "0f")):
    for _opcode in range(_base, _base + 0x10, 2):
        JUMP_PAIRS[f"{_prefix}{_opcode:02x}"] = f"{_prefix}{_opcode + 1:02x}"
        JUMP_PAIRS[f"{_prefix}{_opcode + 1:02x}"] = f"{_prefix}{_opcode:02x}"
del _base, _prefix, _opcode

PATCH_KINDS = ("nop", "flip", "always", "nocall")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")


def hex_data(value):
    """The bytes of a patch from a request: ``value`` is already bytes, or an even-length string of hex
    digits (nothing else, so a command cannot hide in it); at most MAX_PATCH_BYTES of them."""
    if isinstance(value, str) and len(value.strip()) > 2 * MAX_PATCH_BYTES:
        # the length first: a field of megabytes is refused before it is parsed
        raise ValueError(f"bytes must be at most {MAX_PATCH_BYTES} bytes")
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    elif isinstance(value, str) and _HEX_RE.fullmatch(value.strip()):
        data = bytes.fromhex(value.strip())
    else:
        raise ValueError("bytes must be an even number of hex digits, like 9090")
    if not data:
        raise ValueError("bytes must hold at least one byte")
    if len(data) > MAX_PATCH_BYTES:
        raise ValueError(f"bytes must be at most {MAX_PATCH_BYTES} bytes")
    return data


def instruction_at(ops, addr):
    """The op of ``pdj``'s answer that starts at ``addr``, None where rizin decoded none (past its block
    it answers an op whose address is none)."""
    for op in ops if isinstance(ops, list) else []:
        if (isinstance(op, dict) and op.get("offset") == addr and isinstance(op.get("size"), int)
                and op["size"] > 0):
            return op
    return None


def _mnemonic(op):
    """What to call the instruction in a refusal. rizin 0.9.1's pdj has no "mnemonic" (measured: it has
    "opcode" and "disasm"), so the first word of those stands in, and the type where there is neither."""
    for key in ("mnemonic", "opcode", "disasm"):
        text = op.get(key)
        if isinstance(text, str) and text.strip():
            return text.strip().split(" ")[0]
    kind = op.get("type")
    return kind if isinstance(kind, str) and kind else "that instruction"


def _conditional_jump(data):
    """(opcode, displacement) of a conditional jump in one of x86's two forms, 7x rel8 and 0f 8x rel32;
    None for anything else, among them a prefixed form, the rel16 form, loop and jrcxz, whose bytes this
    cannot rewrite without changing where the jump goes."""
    for width, length in ((1, 2), (2, 6)):
        opcode = data[:width].hex()
        if len(data) == length and opcode in JUMP_PAIRS:
            return opcode, data[width:]
    return None


def patch_bytes(kind, op):
    """The bytes one of the four patch kinds writes over the instruction ``op`` (one op as ``pdj`` gives
    it: size, bytes, type). x86 only, because a nop is 0x90 here and nowhere else.

    "nop" fills the instruction with nops, "nocall" does the same to a call, "flip" turns a conditional
    jump into its opposite (JUMP_PAIRS) and "always" into an unconditional one that goes to the same
    place: eb for the short form, e9 for the near one, which is a byte shorter, so its displacement
    counts from a byte earlier and goes up by one, with a nop filling the length.

    Raises ValueError, with a reason the route turns into a refusal, where the kind does not apply.
    """
    if kind not in PATCH_KINDS:
        raise ValueError("kind must be one of " + ", ".join(PATCH_KINDS))
    size = op.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or op.get("type") in ("invalid", "null"):
        raise ValueError("rizin decoded no instruction there")
    try:
        data = hex_data(op.get("bytes"))
    except ValueError:
        raise ValueError("rizin gave no bytes for the instruction there") from None
    if len(data) != size:
        raise ValueError("rizin's bytes for the instruction are not as long as it says")
    name = _mnemonic(op)
    if kind == "nop":
        return b"\x90" * size
    if kind == "nocall":
        if not is_call(op.get("type")):
            raise ValueError(f"'{name}' is no call")
        return b"\x90" * size
    found = _conditional_jump(data) if op.get("type") == "cjmp" else None
    if found is None:
        raise ValueError(f"'{name}' is no x86 conditional jump of the forms 7x rel8 or 0f 8x rel32")
    opcode, displacement = found
    if kind == "flip":
        return bytes.fromhex(JUMP_PAIRS[opcode]) + displacement
    if len(opcode) == 2:  # 7x rel8 -> eb rel8: the same length, so the same displacement
        return b"\xeb" + displacement
    moved = int.from_bytes(displacement, "little") + 1
    if moved == 2 ** 31:  # the one displacement where the byte saved turns the jump around
        raise ValueError(f"'{name}' jumps as far as a jump can: making it unconditional would move it")
    return b"\xe9" + (moved % 2 ** 32).to_bytes(4, "little") + b"\x90"


def parse_cache(text):
    """``wcj``'s write operations: [{"addr", "size", "before", "after"}], in rizin's order (a later write
    over the same address comes after the one it covers).

    rizin 0.9.1 prints one object per operation, comma separated and **without** the brackets of an array
    (measured), so the answer is not JSON as it stands; an empty cache prints nothing at all. Anything
    else raises ValueError, as a view does for a list rizin answered in a shape nobody knows.
    """
    text = text.strip()
    if not text:
        return []
    try:
        found = json.loads(text if text.startswith("[") else "[" + text + "]")
    except ValueError:
        raise ValueError("wcj did not answer the write cache") from None
    rows = []
    for row in found if isinstance(found, list) else []:
        if not (isinstance(row, dict) and isinstance(row.get("addr"), int) and not isinstance(row["addr"], bool)
                and isinstance(row.get("size"), int) and not isinstance(row["size"], bool)
                and isinstance(row.get("before"), str) and isinstance(row.get("after"), str)):
            raise ValueError("wcj did not answer the write cache")
        rows.append({"addr": row["addr"], "size": row["size"], "before": row["before"], "after": row["after"]})
    return rows


def cache_entry(addr, data):
    """One write of this session for the mirror ``patch_rows`` matches against: (addr, size, after) in
    the shape ``wcj`` reports it (rizin's hex is lower case, as bytes.hex() is)."""
    return addr, len(data), bytes(data).hex()


def patch_rows(rows, mine):
    """``parse_cache``'s rows as the patch list, and the mirror of this session's own writes as it
    stands afterwards: (rows lowest address first, the mirror entries the cache still holds).

    ``mine`` is this session's writes in the order it made them, each as ``cache_entry`` gives it.
    rizin's cache is append-only (a second write over the same address becomes another row *after* the
    rows made before it) and a removal drops whole rows and keeps the order of the rest, both measured.
    So the session's writes are a subsequence of ``rows``: each row is matched, in order, to the first
    mirror entry at or after the last match whose address, size and bytes are the same, and only a
    matched row is "mine". A row no mirror entry matches is foreign even where this session owns the
    address -- what an emulation run or a console ``wx`` wrote into a range this session patched. A
    mirror entry that no row matches any more was taken out of the cache and is dropped from the mirror.

    Two writes of the same bytes to the same address cannot be told apart; either of them exports and
    persists the same byte, which is why that case is left as it is.
    """
    places = {}
    for index, entry in enumerate(mine):
        places.setdefault(entry, []).append(index)
    marked, kept, at = [], [], 0
    for row in rows:
        spots = places.get((row["addr"], row["size"], row["after"]), ())
        where = bisect.bisect_left(spots, at)  # the first of those writes at or after the last match
        index = spots[where] if where < len(spots) else None
        if index is None:
            marked.append(dict(row, mine=False))
            continue
        marked.append(dict(row, mine=True))
        kept.append(mine[index])
        at = index + 1
    return sorted(marked, key=lambda row: row["addr"]), kept


# --- Re-analysing the range an emulation run decrypted ---------------------

# Writes no further apart than this belong to one range: a decryption loop writes byte by byte, and a
# run that touched two far-apart places must not turn into one enormous span to analyse and search.
RUN_RANGE_GAP = 0x1000
# The least length of a run of printable bytes that counts as a string, as rizin's own string finder
# uses. rizin 0.9.1's /zj is a *pattern* search (measured: without a pattern it refuses and prints its
# help), and it has no form that lists the strings of a range, so the pattern is the run itself. POSIX's
# class, not "[ -~]" or "[\x20-\x7e]", for three reasons that are all about rizin's own parser: no space,
# so it is one argument without quotes; no "~", which starts rizin's grep; and no backslash, which the
# console's filter refuses -- so the console can run the very same command (measured, all four forms).
STRING_MIN_LENGTH = 4
STRING_PATTERN = "[[:print:]]{%d,}" % STRING_MIN_LENGTH

# One row of ``afl``: "<offset> <nbbs> <size>[ -> <realsz>]  <name>" (rizin 0.9.1). Only the address is
# read here; the four columns are also what makes a row hard to forge with a function name that holds a
# line separator (\x85, U+2028, U+2029), which rizin prints as it is.
_AFL_ROW = re.compile(r"(?m)^[ \t]*(0x[0-9a-fA-F]{1,16})[ \t]+[0-9]{1,9}[ \t]+[0-9]{1,19}"
                      r"(?:[ \t]*->[ \t]*[0-9]{1,19})?[ \t]")


def write_cluster(rows, gap=RUN_RANGE_GAP):
    """The range of the writes that belong together, as (lowest address, highest address), both in it;
    None where there is no write at all.

    ``rows`` are cache rows ({"addr", "size"}), in any order. A write no more than ``gap`` bytes after
    the one before it belongs to the same range; a larger hole starts another one, and of those the
    range that holds the most written bytes wins (the lowest one where two hold the same). That is what
    keeps a run which pushed a word here and decrypted a block there from becoming one span of
    everything in between -- the block is the range, and it is the block that was decrypted.
    """
    spans = sorted((row["addr"], row["addr"] + row["size"] - 1, row["size"]) for row in rows
                   if isinstance(row.get("addr"), int) and isinstance(row.get("size"), int)
                   and row["size"] > 0)
    clusters = []
    for low, high, size in spans:
        if clusters and low - clusters[-1][1] <= gap:
            start, end, written = clusters[-1]
            clusters[-1] = (start, max(end, high), written + size)
        else:
            clusters.append((low, high, size))
    if not clusters:
        return None
    best = max(clusters, key=lambda cluster: (cluster[2], -cluster[0]))
    return best[0], best[1]


def function_entries(text):
    """The addresses where rizin's ``afl`` says a function begins, in its order; a line that is no row
    is left out.

    afl's text, not aflj: rizin 0.9.1 dies on aflj once a project with DWARF variable origins has been
    loaded, and its JSON of a function is about 80 times larger (see _rizin_functions in app.py).
    """
    return [int(row.group(1), 16) for row in _AFL_ROW.finditer(text)]


def written_ranges(rows):
    """The addresses ``rows`` wrote, merged into the fewest (low, high) ranges, both in them, lowest
    first: a decryption loop's thousands of one-byte rows become one range."""
    spans = sorted((row["addr"], row["addr"] + row["size"] - 1) for row in rows
                   if isinstance(row.get("addr"), int) and isinstance(row.get("size"), int)
                   and row["size"] > 0)
    merged = []
    for low, high in spans:
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged


def run_only_ranges(rows):
    """The addresses an emulation run wrote and no patch of this session covers, as ``written_ranges``
    gives them: the run's rows, minus every byte a ``mine`` row holds.

    What rests on those addresses belongs to the run and nothing else -- it is gone with the write cache,
    so nothing about it may go into the project. A byte a patch covers as well is **not** in them: that
    byte comes back when the file is opened again, so what rests on it may stay.
    """
    kept = []
    held = written_ranges([row for row in rows if row.get("mine")])
    for low, high in written_ranges([row for row in rows if not row.get("mine")]):
        at = low
        for hold_low, hold_high in held:
            if hold_high < at:
                continue
            if hold_low > high:
                break
            if hold_low > at:
                kept.append((at, hold_low - 1))
            at = max(at, hold_high + 1)
            if at > high:
                break
        if at <= high:
            kept.append((at, high))
    return kept


def in_ranges(addr, ranges):
    """Whether ``addr`` is in one of ``ranges`` as written_ranges gives them (lowest first, no overlap)."""
    if not isinstance(addr, int) or isinstance(addr, bool):
        return False
    at = bisect.bisect_right(ranges, (addr, 2 ** 64)) - 1  # the last range that starts at or below addr
    return at >= 0 and addr <= ranges[at][1]


def string_hits(found):
    """How many strings ``/zj`` found: its answer is [{"address", "size", "flag", "detail"}], an empty
    array for none (and nothing at all, which cmdj gives as None, for a command that printed none)."""
    if found is None:
        return 0
    if not isinstance(found, list):
        raise ValueError("/zj did not answer a list of string hits")
    for hit in found:
        if not (isinstance(hit, dict) and isinstance(hit.get("address"), int)
                and not isinstance(hit["address"], bool) and isinstance(hit.get("size"), int)
                and not isinstance(hit["size"], bool)):
            raise ValueError("/zj did not answer a list of string hits")
    return len(found)


# --- The API-call assistant ------------------------------------------------
#
# ESIL emulates no Windows API: a `call` into VirtualAlloc runs into unmapped memory (measured). The
# assistant names the API behind such a call, offers a value for the return register and knows what
# else a skip has to do -- a buffer to map, a copy to make, and at 32-bit stdcall the stack the callee
# would have cleared. Everything here is arithmetic over rizin's answers; rizin_sessions runs the
# commands.

# The one arch the assistant covers, as rizin names it (``bin.arch`` of ij, and the session's ``arch``).
ASSIST_ARCH = "x86"
# At most this many arguments a stack correction covers: the widest call in the table takes eight, and
# a correction that comes from a request is held to the same number (an unbounded one would move the
# stack pointer out of the stack and the state would show words that are no stack).
ASSIST_MAX_ARGS = 16
# Where the assistant's own memory goes. Clear of a PE's image (0x140000000 for a 64-bit one, 0x400000
# for a 32-bit one) and of the stack aeim maps (0x100000), and inside 32 bits, so that a 32-bit register
# can hold it. The address is searched for in omlj's maps rather than fixed (free_span): the file's
# maps, the stack and a buffer an earlier call was given are all in there, and the second VirtualAlloc
# of a run must not be handed the first one's memory.
ASSIST_ADDR = 0x50000000
ASSIST_STEP = 0x100000
ASSIST_TRIES = 64
# A buffer is the size the call asked for, rounded up to a page, between these two. The maximum bounds
# what one aeim allocates on the VM's 8 GB; an unpacker's allocation is far below it, and a size above
# it means the arguments were read wrong, so then nothing is offered.
ASSIST_BUFFER_MIN = 0x1000
ASSIST_BUFFER_MAX = 16 * 1024 * 1024
# A pseudo handle and a pseudo address: recognisable at a glance in a register or a stack word, and
# checked against ``omlj`` before they are offered (pseudo_value), so that they really are in no map --
# a run that calls or reads one then stops with a trap instead of running on through nothing. A dump of
# a live process can have maps anywhere, which is why the check is made and not assumed.
ASSIST_HANDLE = 0x6D000000
ASSIST_PSEUDO = 0x6E000000
ASSIST_SPACING = 0x10000
# How many values each of the two series has room for: 256 steps of 0x10000 fill the 0x1000000 between
# the two bases, so neither series can ever reach into the other's.
ASSIST_PSEUDO_TRIES = 0x100
# GetTickCount and friends: a machine that has been up for a while, and a step of one scheduler tick
# (GetTickCount's own resolution is about 15.6 ms), so that a timing check sees time pass without a
# jump that would look like a debugger. The clock moves when a skip **applies** a value, never when one
# is offered: a run line that asks for the offer on every step must not move it (R38).
TICK_START = 0x100000
TICK_STEP = 0x10
# The most bytes one copy of the assistant moves, and how much goes into one command.
#
# The cap is a cost bound, measured through the pipe against rizin 0.9.1: 64 KB take 0.18 s, 256 KB
# 0.73 s and 1 MB 2.96 s, so one request stays well inside the pipe's 30 s and in the order of an ESIL
# run's own esil.timeout. 1 MB covers the shape this is for -- an unpacker that memcpys a section into
# a fresh buffer.
#
# The chunk is **not** a tidiness choice: rizin 0.9.1 writes **nothing at all** for a ``wx`` whose
# command line passes about 4 KB, and says so on stderr only ("Cannot convert '4141...' to bin data"),
# which ``cmd`` never reads (measured: 0x500 bytes land, 0x7ff bytes do not). 0x400 bytes are 2048 hex
# digits, half of that wall.
ASSIST_COPY_MAX = 0x100000
ASSIST_WRITE_CHUNK = 0x400
# How many bytes one ``pxj`` reads: its answer is one JSON number per byte, so the read is chunked too.
ASSIST_READ_CHUNK = 0x10000
# The name aeim gives the assistant's buffers (``mem.assist`` in omlj).
ASSIST_MAP_NAME = "assist"
# What the environment group answers: unremarkable values, with no VM artefact in them (spec §4). Data,
# like the table itself, so they can be changed without a code change.
ASSIST_COMPUTER = "DESKTOP-7Q1M4KD"
ASSIST_USER = "dmartin"
ASSIST_VOLUME = "Windows"
ASSIST_SERIAL = 0x9C4E1A37
# The performance counter's frequency, as Windows 8 and later report it (10 MHz), and the FILETIME the
# run's clock counts from: 2026-01-01 00:00 UTC in 100 ns units since 1601 ((unix + 11644473600) * 1e7).
ASSIST_QPC_FREQUENCY = 10 * 1000 * 1000
ASSIST_FILETIME_BASE = 134116992000000000


# What a row of API_TABLE answers in the return register:
#   "buffer"   a freshly mapped buffer, its address in the return register; ``size_arg`` says which
#              argument is its size
#   "handle"   a recognisable pseudo handle (a module, a heap): nothing is ever read through it
#   "address"  the address the file knows for the name the call asks for, else a pseudo address
#   "copy"     the call really copies in the ESIL memory map and returns its destination
#   "tick"     a rising millisecond counter
#   "zero"     0: "not found", "not being watched"
#   "success"  1: the call reports success, and writes nothing to its out-parameters
#   "none"     the call has no return value; a skip only corrects the stack
ANSWERS = ("buffer", "handle", "address", "copy", "tick", "zero", "success", "none")

# What a row writes to an out-parameter, as (the argument that holds the pointer, what to write). The
# spec's answer for the time and environment groups is the **value**, not just a return code -- a
# QueryPerformanceCounter whose counter is never written lets a timing check see zero time pass, and a
# GetComputerName that writes nothing answers no name at all. The writes go through ``wx``, as a run's
# own writes do, and a pointer that is in no map writes nothing and says so.
#   "counter"    the performance counter, word-wide, from the run's clock (rising)
#   "frequency"  that counter's frequency (ASSIST_QPC_FREQUENCY), word-wide
#   "filetime"   the system time as a FILETIME, 8 bytes, from the same clock
#   "computer"   ASSIST_COMPUTER, NUL-terminated (UTF-16 for the ...W form of the call)
#   "user"       ASSIST_USER, the same way
#   "volume"     ASSIST_VOLUME, the same way
#   "chars"      how many characters the name before it has, as a 4-byte count: the in/out size that
#                GetComputerName and GetUserName take a pointer to
#   "serial"     ASSIST_SERIAL, 4 bytes
OUT_WRITES = ("counter", "frequency", "filetime", "computer", "user", "volume", "chars", "serial")

# The assistant's table: **data, not code**, so that it grows without a change here (the spec asks for
# that). Per row: the convention (which 64 bits ignores, where everything is Microsoft x64), how many
# arguments the call takes (the stack correction at 32-bit stdcall), what it answers, and for a buffer
# which argument is the size. The groups are the spec's: memory, memory protection, loader, anti-debug,
# time, environment, copying. The table answers like a clean, unobserved machine -- that is the
# anti-VM bypass, and it needs no patch.
API_TABLE = {
    # Memory
    "VirtualAlloc": {"conv": "stdcall", "args": 4, "ret": "buffer", "size_arg": 1},
    "VirtualAllocEx": {"conv": "stdcall", "args": 5, "ret": "buffer", "size_arg": 2},
    "HeapAlloc": {"conv": "stdcall", "args": 3, "ret": "buffer", "size_arg": 2},
    "HeapCreate": {"conv": "stdcall", "args": 3, "ret": "handle"},
    "LocalAlloc": {"conv": "stdcall", "args": 2, "ret": "buffer", "size_arg": 1},
    "GlobalAlloc": {"conv": "stdcall", "args": 2, "ret": "buffer", "size_arg": 1},
    "VirtualFree": {"conv": "stdcall", "args": 3, "ret": "success"},
    "HeapFree": {"conv": "stdcall", "args": 3, "ret": "success"},
    "malloc": {"conv": "cdecl", "args": 1, "ret": "buffer", "size_arg": 0},
    "free": {"conv": "cdecl", "args": 1, "ret": "none"},
    # Memory protection
    "VirtualProtect": {"conv": "stdcall", "args": 4, "ret": "success"},
    "VirtualProtectEx": {"conv": "stdcall", "args": 5, "ret": "success"},
    "FlushInstructionCache": {"conv": "stdcall", "args": 3, "ret": "success"},
    # Loader
    "LoadLibrary": {"conv": "stdcall", "args": 1, "ret": "handle"},
    "LoadLibraryEx": {"conv": "stdcall", "args": 3, "ret": "handle"},
    "GetModuleHandle": {"conv": "stdcall", "args": 1, "ret": "handle"},
    "GetModuleHandleEx": {"conv": "stdcall", "args": 3, "ret": "success"},
    "GetProcAddress": {"conv": "stdcall", "args": 2, "ret": "address"},
    # Anti-debug
    "IsDebuggerPresent": {"conv": "stdcall", "args": 0, "ret": "zero"},
    "CheckRemoteDebuggerPresent": {"conv": "stdcall", "args": 2, "ret": "zero"},
    "NtQueryInformationProcess": {"conv": "stdcall", "args": 5, "ret": "zero"},
    "OutputDebugString": {"conv": "stdcall", "args": 1, "ret": "none"},
    # Time
    "GetTickCount": {"conv": "stdcall", "args": 0, "ret": "tick"},
    "GetTickCount64": {"conv": "stdcall", "args": 0, "ret": "tick"},
    "timeGetTime": {"conv": "stdcall", "args": 0, "ret": "tick"},
    "QueryPerformanceCounter": {"conv": "stdcall", "args": 1, "ret": "success",
                                "out": ((0, "counter"),)},
    "QueryPerformanceFrequency": {"conv": "stdcall", "args": 1, "ret": "success",
                                  "out": ((0, "frequency"),)},
    "GetSystemTimeAsFileTime": {"conv": "stdcall", "args": 1, "ret": "none", "out": ((0, "filetime"),)},
    "Sleep": {"conv": "stdcall", "args": 1, "ret": "none"},
    # Environment
    "GetComputerName": {"conv": "stdcall", "args": 2, "ret": "success",
                        "out": ((0, "computer"), (1, "chars"))},
    "GetUserName": {"conv": "stdcall", "args": 2, "ret": "success", "out": ((0, "user"), (1, "chars"))},
    "GetVolumeInformation": {"conv": "stdcall", "args": 8, "ret": "success",
                             "out": ((1, "volume"), (3, "serial"))},
    "GetSystemInfo": {"conv": "stdcall", "args": 1, "ret": "none"},
    "GetEnvironmentVariable": {"conv": "stdcall", "args": 3, "ret": "zero"},
    # Copying
    "memcpy": {"conv": "cdecl", "args": 3, "ret": "copy", "size_arg": 2},
    "memmove": {"conv": "cdecl", "args": 3, "ret": "copy", "size_arg": 2},
    "RtlMoveMemory": {"conv": "stdcall", "args": 3, "ret": "copy", "size_arg": 2},
    "RtlCopyMemory": {"conv": "stdcall", "args": 3, "ret": "copy", "size_arg": 2},
}
_API_INDEX = {name.casefold(): dict(row, name=name) for name, row in API_TABLE.items()}
# What stands in front of the name of an import as a file gives it, and what a 32-bit build decorates it
# with: "sym.imp.KERNEL32.dll_Sleep" and "KERNEL32.dll_LoadLibraryW" (both measured on mingw builds),
# rizin's "sym._memcpy" for a CRT function, and stdcall's "_Sleep@4".
_API_PREFIX = re.compile(r"^(?:sym\.)?(?:imp\.)?")
_API_MODULE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}\.dll_", re.IGNORECASE)
_API_DECORATION = re.compile(r"@[0-9]{1,3}$")


def lookup_api(name):
    """The row of API_TABLE for the name of a call's target, with its own ``name`` and ``wide``, or None.

    The flag prefix, the module prefix, leading underscores and a stdcall decoration come off, and the
    ANSI/Unicode pair (``...A``/``...W``) is one row -- but only where the full name is not a row
    itself, so that a row whose own name ends in A or W would never be mangled. ``wide`` says that the
    call site was the ``...W`` form, which is where the encoding of an out-parameter's text comes from:
    the row cannot know it, the call can.
    """
    if not isinstance(name, str):
        return None
    key = _API_MODULE.sub("", _API_PREFIX.sub("", name.strip()))
    key = _API_DECORATION.sub("", key).lstrip("_").casefold()
    candidates = [(key, False)]
    if key[-1:] in ("a", "w"):
        candidates.append((key[:-1], key[-1:] == "w"))
    for candidate, wide in candidates:
        found = _API_INDEX.get(candidate)
        if found is not None:
            return dict(found, wide=wide)
    return None


def convention(arch, bits, api):
    """How the call at hand takes its arguments and gives its answer, or **None** where the assistant
    switches itself off: ``ret_reg``, ``arg_regs``, ``stack_args``, ``callee_pops``, ``word``, and
    ``conv``, the convention in force (None at 32 bits where the table does not know the call).

    None for anything but x86 at 32 or 64 bits (ARM, a dump of mixed code). There the assistant offers
    nothing and says so; emulation, breakpoints and patching keep working. Guessing a return register
    would be the "the surface lies" anti-goal.

    At 64 bits every Win32 and CRT call is Microsoft x64: the first four arguments in rcx, rdx, r8 and
    r9, the answer in rax, and the **caller** clears the stack. At 32 bits the arguments are on the
    stack, and the convention says who clears it: the Win32 API is stdcall, where the callee does (see
    stack_fix), while the CRT's memcpy and friends are cdecl, where the caller does. Without a row of
    the table nothing is known to clear, so ``callee_pops`` is false.
    """
    if arch != ASSIST_ARCH or bits not in (32, 64):
        return None
    if bits == 64:
        return {"conv": "win64", "ret_reg": "rax", "arg_regs": ("rcx", "rdx", "r8", "r9"),
                "stack_args": False, "callee_pops": False, "word": 8}
    conv = (api or {}).get("conv")
    return {"conv": conv, "ret_reg": "eax", "arg_regs": (), "stack_args": True,
            "callee_pops": conv == "stdcall", "word": 4}


def stack_fix(conv, args):
    """How many bytes to add to the stack pointer after a skipped call: the arguments the callee would
    have cleared, and 0 where the caller clears them.

    Review Focus 1: a 32-bit stdcall callee ends in ``ret <n>``, which takes its arguments off the
    stack. Skipping the call takes nothing off, so without this the stack stays that much too deep and
    every later step reads and writes beside the truth -- while the surface shows a stack that looks
    fine. win64 and cdecl are the other way round, and there nothing may be added.
    """
    if not isinstance(conv, dict) or not conv.get("callee_pops"):
        return 0
    if not isinstance(args, int) or isinstance(args, bool) or not 0 <= args <= ASSIST_MAX_ARGS:
        return 0
    return args * conv["word"]


def _map_rows(maps):
    return [m for m in maps if isinstance(m, dict) and isinstance(m.get("from"), int)
            and isinstance(m.get("to"), int)] if isinstance(maps, list) else []


def span_is_free(maps, addr, size):
    """Whether ``size`` bytes from ``addr`` lie in none of ``omlj``'s maps: there and only there may the
    assistant map a buffer, so that it covers neither the file nor the emulation's stack."""
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        return False
    return all(addr + size <= m["from"] or m["to"] <= addr for m in _map_rows(maps))


def free_span(maps, size, base=ASSIST_ADDR, step=ASSIST_STEP, tries=ASSIST_TRIES):
    """An address where ``size`` bytes collide with no map of ``omlj``, searched from ``base`` upwards
    in steps of ``step``; None when ``tries`` of them are all taken or the search would leave 32 bits
    (where a 32-bit register could not hold the answer)."""
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        return None
    for i in range(max(tries, 0)):
        addr = base + i * step
        if addr + size > 2 ** 32:
            return None
        if span_is_free(maps, addr, size):
            return addr
    return None


def buffer_size(value):
    """The size to map for a buffer the call asked for: ``value`` rounded up to a page, at least
    ASSIST_BUFFER_MIN; None for what is no size or is above ASSIST_BUFFER_MAX -- then nothing is
    offered and the summary says so, rather than gigabytes being mapped on a size read wrong."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= ASSIST_BUFFER_MAX:
        return None
    pages = (value + ASSIST_BUFFER_MIN - 1) // ASSIST_BUFFER_MIN
    return max(ASSIST_BUFFER_MIN, pages * ASSIST_BUFFER_MIN)


_EXPORT_NAME = re.compile(r"[A-Za-z0-9_@?$.]{1,64}")


def read_cstring(data):
    """The name at a pointer, from ``pxj``'s bytes: what stands before the first NUL, if that is a name
    a file may give an export (letters, digits and ``_ @ ? $ .``); None for anything else, a run of
    bytes without a NUL in reach among it.

    It is only ever compared with the file's own import names (GetProcAddress) and shown in the
    summary; nothing of it ever goes into a rizin command.
    """
    if not isinstance(data, list) or not all(isinstance(b, int) and 0 <= b < 256 for b in data):
        return None
    try:
        text = bytes(data[:data.index(0)]).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _EXPORT_NAME.fullmatch(text) else None


def pseudo_value(maps, base, index, spacing=ASSIST_SPACING, tries=ASSIST_PSEUDO_TRIES):
    """(the next value of a pseudo series, the step it came from): ``base`` plus ``index`` steps, moved
    on while a map of ``omlj`` holds it; (None, index) once the series is used up.

    The check is the point: these values are offered *because* they are in no map, so that a run which
    calls or reads one stops with a trap instead of running on through nothing. A dump of a live
    process -- a case the spec names -- can have maps anywhere, this region included, and then the
    series has to move or say that it is out of values.
    """
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        return None, 0
    for step in range(index, max(tries, 0)):
        value = base + step * spacing
        if not is_mapped(value, maps):
            return value, step
    return None, index


def esil_ranges(maps):
    """The ranges of the ESIL VM's own maps in ``omlj`` as (from, to), ``to`` not in them: those named
    the way ``aeim`` names its maps (``mem.…``, rizin's get_esil_stack_name) -- the stack and the
    buffers the assistant mapped. The file's maps are ``fmap.*``/``mmap.*`` and are not among them."""
    return [(m["from"], m["to"]) for m in _map_rows(maps)
            if str(m.get("name", "")).startswith("mem.")]


def overlaps_any(addr, size, ranges):
    """Whether ``size`` bytes from ``addr`` touch one of ``ranges`` as esil_ranges gives them."""
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        return False
    return any(addr < high and low < addr + size for low, high in ranges)


def esil_fds(maps):
    """The file descriptors of the ESIL VM's own memory in ``omlj``, the newest map first: those whose
    name is one ``aeim`` gives (``mem.…``, rizin's get_esil_stack_name), and of those only the ones no
    other map uses -- the file's maps are ``fmap.*``/``mmap.*``, and closing a descriptor the file is
    mapped through would close the sample.

    Closing them (``o- <fd>``) is how the emulation's memory is given back: rizin 0.9.1's own ``aeim-``
    can only ever drop the map it made last, and once an ``aeim <addr> <size> <name>`` has existed it
    can never name the stack map again (measured), while ``om-`` unmaps without freeing the memory.
    """
    rows = _map_rows(maps)
    theirs = {m.get("fd") for m in rows if not str(m.get("name", "")).startswith("mem.")}
    fds, seen = [], set()
    for m in rows:
        fd = m.get("fd")
        if (str(m.get("name", "")).startswith("mem.") and isinstance(fd, int)
                and not isinstance(fd, bool) and fd not in theirs and fd not in seen):
            seen.add(fd)
            fds.append(fd)
    return list(reversed(fds))


def out_bytes(kind, api, clock):
    """(the bytes an out-parameter write puts there, what to call them in the summary) for one entry of
    a row's ``out``, or (None, None) for a kind this build does not know.

    ``api`` is the row as ``lookup_api`` gives it (its ``wide`` decides whether a text goes as ANSI or
    as UTF-16), and ``clock`` is the run's millisecond clock. The values are the spec's answer for the
    time and environment groups: a counter that rises with the same clock the tick answers come from,
    so that two ways of measuring time agree, and names with no VM artefact in them.

    The counter and its frequency are 8 bytes whatever the file's word is: a LARGE_INTEGER is 64 bits
    on 32-bit Windows too, and writing only four of them would leave the high half as it was and the
    counter could read as an enormous number.
    """
    texts = {"computer": ASSIST_COMPUTER, "user": ASSIST_USER, "volume": ASSIST_VOLUME}
    if kind in texts:
        text = texts[kind]
        data = (text.encode("utf-16-le") + b"\0\0") if api.get("wide") else (text.encode("ascii") + b"\0")
        return data, f"'{text}'"
    if kind == "chars":
        written = next((texts[what] for _, what in api.get("out", ()) if what in texts), "")
        return len(written).to_bytes(4, "little"), f"its length ({len(written)} characters)"
    if kind == "counter":
        value = clock * (ASSIST_QPC_FREQUENCY // 1000)   # the same elapsed time as the tick clock
        return value.to_bytes(8, "little"), f"the performance counter ({value})"
    if kind == "frequency":
        return ASSIST_QPC_FREQUENCY.to_bytes(8, "little"), \
            f"its frequency ({ASSIST_QPC_FREQUENCY} Hz, as Windows 8 and later report)"
    if kind == "filetime":
        value = ASSIST_FILETIME_BASE + clock * 10000     # 100 ns units per millisecond
        return value.to_bytes(8, "little"), "the system time as a FILETIME"
    if kind == "serial":
        return ASSIST_SERIAL.to_bytes(4, "little"), f"a volume serial ({ASSIST_SERIAL:#x})"
    return None, None


