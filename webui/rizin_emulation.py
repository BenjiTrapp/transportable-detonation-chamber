"""Pure logic of the RIZIN tab's emulation: no pipe and no Flask, so it is testable on its own.

rizin_sessions runs the commands; what their answers mean is decided here, where a
wrong value would silently show a wrong register, stack word or pointer.
"""

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
    (from, to, name), or None."""
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
