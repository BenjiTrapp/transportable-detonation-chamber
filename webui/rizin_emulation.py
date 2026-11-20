"""Pure logic of the RIZIN tab's emulation: no pipe and no Flask, so it is testable on its own.

rizin_sessions runs the commands; what their answers mean is decided here, where a
wrong value would silently show a wrong register, stack word or pointer.
"""

import re

# One line of ``ar``: "rax = 0x0000000000000041" (rizin 0.9.1 pads the value to the register's width).
_REGISTER_LINE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_.]*) = (0x[0-9a-fA-F]+)\s*")
# ``fd`` describes the closest flag below an address, however far below it is (and prints the distance as
# an int, which wraps past 2^31). A stack word that far past a flag is a number, not a pointer into it:
# 64 KiB is more than nearly any function or string, where return addresses and pointers point.
HINT_DISTANCE = 0x10000
_HINT_LINE = re.compile(r"(\S+)(?: \+ (-?[0-9]+))?")


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


def flag_hint(text):
    """The flag that ``fd``'s answer names for a stack word ("name" or "name + delta"), or None when it
    names none or one so far below that the word does not point into it (HINT_DISTANCE)."""
    lines = text.strip().splitlines()
    if not lines:
        return None
    m = _HINT_LINE.fullmatch(lines[0].strip())
    if not m:
        return None
    if m.group(2) is not None and not 0 < int(m.group(2)) < HINT_DISTANCE:
        return None
    return m.group(0)
