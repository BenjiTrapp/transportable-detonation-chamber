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
