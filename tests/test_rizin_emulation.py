"""The emulation's pure logic (webui/rizin_emulation.py), without rizin."""

import rizin_emulation


def test_parse_registers_reads_ar_output():
    text = "rax = 0x0000000000000041\nrip = 0x0000000000401000\n"
    assert rizin_emulation.parse_registers(text) == [
        {"name": "rax", "value": 0x41}, {"name": "rip", "value": 0x401000}]


def test_parse_registers_skips_what_is_no_register_line():
    # `ar PC` prints a blank line after the register; a value rizin could not read is "ERROR"
    text = "\nrip = 0x0000000000401000\n\nxmm0 = ERROR\nWARN: something\n r8 = 0x10 \n"
    assert rizin_emulation.parse_registers(text) == [
        {"name": "rip", "value": 0x401000}, {"name": "r8", "value": 0x10}]


def test_stack_words_follow_the_word_size_and_byte_order():
    data = [0x90, 0x14, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x41, 0, 0, 0, 0, 0, 0, 0]
    assert rizin_emulation.stack_words(data, 8, big_endian=False) == [0x140001490, 0x41]
    assert rizin_emulation.stack_words(data, 4, big_endian=False) == [0x40001490, 0x1, 0x41, 0]
    assert rizin_emulation.stack_words(data[:4], 4, big_endian=True) == [0x90140040]
    assert rizin_emulation.stack_words(data[:7], 4, big_endian=False) == [0x40001490]  # no half word


STACK = {"map": 6, "fd": 5, "from": 0x100000, "to": 0x1F0000, "perm": "rw-", "name": "mem.0x100000_0xf0000"}
MAPS = [{"map": 1, "fd": 3, "from": 0x140000000, "to": 0x140000400, "perm": "r--", "name": "fmap.header"}, STACK]


def test_stack_map_is_the_one_aeim_made_around_the_stack_pointer():
    assert rizin_emulation.stack_map(MAPS, 0x178000, 0xF0000) == (0x100000, 0x1F0000, "mem.0x100000_0xf0000")
    assert rizin_emulation.stack_map(MAPS, 0x1F0000, 0xF0000) is None  # "to" is past the map
    assert rizin_emulation.stack_map(MAPS, 0x178000, 0x1000) is None  # another size: not ours
    renamed = [dict(STACK, name="mem.mystack")]  # a console aeim with a name of its own
    assert rizin_emulation.stack_map(renamed, 0x178000, 0xF0000) is None
    assert rizin_emulation.stack_map(None, 0x178000, 0xF0000) is None


def test_is_mapped_follows_the_maps():
    assert rizin_emulation.is_mapped(0x140000000, MAPS) and rizin_emulation.is_mapped(0x1EFFFF, MAPS)
    assert not rizin_emulation.is_mapped(0x140000400, MAPS) and not rizin_emulation.is_mapped(0x41, MAPS)
    assert not rizin_emulation.is_mapped(0x41, None)


def test_function_hint_names_only_the_function_the_value_is_in():
    entry0 = [{"offset": 0x140001440, "name": "entry0", "size": 29}]
    assert rizin_emulation.function_hint(0x140001440, entry0) == "entry0"
    assert rizin_emulation.function_hint(0x140001449, entry0) == "entry0 + 9"
    assert rizin_emulation.function_hint(0x14000145D, entry0) is None  # just past its end
    assert rizin_emulation.function_hint(0x140001400, entry0) is None
    assert rizin_emulation.function_hint(0x140001449, []) is None
    assert rizin_emulation.function_hint(0x140001449, None) is None


def test_flag_hint_leaves_out_the_register_flags():
    registers = {"rax", "rsp", "rbp", "rip"}
    assert rizin_emulation.flag_hint([{"name": "str.child"}], registers) == "str.child"
    assert rizin_emulation.flag_hint([{"name": "rsp"}, {"name": "rbp"}], registers) is None
    assert rizin_emulation.flag_hint([{"name": "rip"}, {"name": "entry0"}], registers) == "entry0"
    assert rizin_emulation.flag_hint(None, registers) is None
    assert rizin_emulation.flag_hint([{"name": ""}, "x"], registers) is None


def test_changed_registers_compares_with_the_state_before():
    before = {"rax": 1, "rbx": 2, "rip": 3}
    after = [{"name": "rax", "value": 1}, {"name": "rbx", "value": 5}, {"name": "rip", "value": 4}]
    assert rizin_emulation.changed_registers(before, after) == ["rbx", "rip"]
    assert rizin_emulation.changed_registers(None, after) == []


def test_stack_map_without_a_stack_pointer_is_none():
    # `ar SP` can answer nothing (no SP role): a missing stack, not a TypeError
    assert rizin_emulation.stack_map(MAPS, None, 0xF0000) is None


def test_step_commands_name_the_six_kinds_and_no_step_back():
    assert rizin_emulation.STEP_COMMANDS == {
        "step": "aes", "over": "aeso", "skip": "aess", "to_call": "aesu", "cont": "aec",
        "until": "aesu"}


def test_stop_reason_reads_rizins_own_words():
    assert rizin_emulation.stop_reason("[ESIL] hit breakpoint at 0x14", "") == "breakpoint"
    assert rizin_emulation.stop_reason("", "WARNING: core: esil: timeout exceeded.") == "timeout"
    assert rizin_emulation.stop_reason("", "ERROR: invalid instruction") == "invalid"
    assert rizin_emulation.stop_reason("", "") == "step"


def test_stop_reason_matches_what_rizin_0_9_1_printed():
    invalid = "ERROR: core: esil: Stopped execution in an invalid instruction (see e??esil.breakoninvalid)\n"
    assert rizin_emulation.stop_reason("rip = 0x9000\n", invalid) == "invalid"
    assert rizin_emulation.stop_reason("", "ERROR: core: esil: Trap, trying to execute on non-executable memory\n") == "trap"
    assert rizin_emulation.stop_reason("ESIL TRAP type 3 code 0x00000014 read error\n", "") == "trap"
    # aecc announces the call it stopped before as an ERROR line: that is the run's goal, not a failure
    assert rizin_emulation.stop_reason("", "ERROR: call at 0x0000001a\n") == "step"
    # other errors and warnings are no stop of the emulation
    assert rizin_emulation.stop_reason("", "ERROR: base addr should not be larger than the breakpoint address.\n") == "step"
    assert rizin_emulation.stop_reason("", "ERROR: cannot step back\n") == "step"
    # a conditional breakpoint
    assert rizin_emulation.stop_reason("", "WARNING: core: esil condition breakpoint!\n") == "breakpoint"


def test_stop_reason_names_the_io_trap_that_stops_without_a_word():
    # esil.iotrap on an invalid read or write ends aec with only this, and only with esil.verbose set
    assert rizin_emulation.stop_reason("rip = 0x48\n", "WARNING: core: TRAP\n") == "trap"


def test_is_executable_follows_the_perm_of_the_map():
    maps = [{"from": 0x1000, "to": 0x2000, "perm": "r-x", "name": "fmap..text"},
            {"from": 0x2000, "to": 0x3000, "perm": "rw-", "name": "mmap..data"}, STACK]
    assert rizin_emulation.is_executable(0x1000, maps) and rizin_emulation.is_executable(0x1FFF, maps)
    assert not rizin_emulation.is_executable(0x2000, maps)       # a map's end is not in it
    assert not rizin_emulation.is_executable(0x2800, maps)       # data
    assert not rizin_emulation.is_executable(0x100800, maps)     # the emulation's stack
    assert not rizin_emulation.is_executable(0x96B8, maps)       # nothing mapped: where an import call ends
    assert not rizin_emulation.is_executable(0x1000, None)


def test_op_at_reads_the_type_and_size_pdj_gave_for_that_address():
    ops = [{"offset": 0x140001499, "size": 6, "type": "ircall", "disasm": "call qword [x]"}]
    assert rizin_emulation.op_at(ops, 0x140001499) == ("ircall", 6)
    assert rizin_emulation.op_at(ops, 0x14000149A) is None      # another address
    assert rizin_emulation.op_at([], 0x1) is None and rizin_emulation.op_at(None, 0x1) is None
    assert rizin_emulation.op_at([{"offset": 1, "size": 0, "type": "invalid"}], 1) is None


def test_aess_and_aeso_handle_only_the_calls_rizin_lists():
    # measured with rizin 0.9.1 on `call qword [sym.imp.KERNEL32.dll_Sleep]` (type ircall): aess and aeso
    # both ran into the callee; at a direct call (type call) aess went from 0x1a to 0x1f
    assert not rizin_emulation.skip_call("call") and not rizin_emulation.skip_call("ucall")
    assert not rizin_emulation.skip_call("rcall") and not rizin_emulation.skip_call("mov")
    assert rizin_emulation.skip_call("ircall") and rizin_emulation.skip_call("icall")
    assert not rizin_emulation.over_call("call") and not rizin_emulation.over_call("jmp")
    assert rizin_emulation.over_call("ucall") and rizin_emulation.over_call("ircall")
    assert not rizin_emulation.skip_call(None) and not rizin_emulation.over_call(None)


def _op(offset, size, kind):
    return {"offset": offset, "size": size, "type": kind}


def test_next_call_stop_runs_to_a_call_to_a_branch_or_on():
    code = [_op(0x10, 4, "sub"), _op(0x14, 5, "mov"), _op(0x19, 6, "ircall"), _op(0x1F, 1, "nop")]
    assert rizin_emulation.next_call_stop(code, 0x10) == ("call", 0x19)
    # an indirect call through the import table counts: that is where aecc ran past
    assert rizin_emulation.next_call_stop(code[2:], 0x19) == ("call", 0x19)
    branch = [_op(0x10, 3, "cmp"), _op(0x13, 2, "cjmp"), _op(0x15, 6, "call")]
    assert rizin_emulation.next_call_stop(branch, 0x10) == ("branch", 0x13)
    for kind in ("jmp", "ujmp", "ret", "cret", "swi", "trap", "invalid"):
        assert rizin_emulation.next_call_stop([_op(0x10, 2, kind)], 0x10) == ("branch", 0x10), kind
    straight = [_op(0x10, 1, "nop"), _op(0x11, 1, "nop"), _op(0x12, 3, "mov")]
    assert rizin_emulation.next_call_stop(straight, 0x10) == ("more", 0x15)
    # nothing decoded, or a listing that does not follow on from the address: no step forward is claimed
    assert rizin_emulation.next_call_stop([], 0x10) == ("more", 0x10)
    assert rizin_emulation.next_call_stop(None, 0x10) == ("more", 0x10)
    assert rizin_emulation.next_call_stop([_op(0x10, 1, "nop"), _op(0x40, 1, "call")], 0x10) == ("more", 0x11)
