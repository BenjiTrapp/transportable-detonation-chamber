"""The emulation's pure logic (webui/rizin_emulation.py), without rizin."""

import pytest

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


def test_maps_hold_asks_for_one_map_that_holds_the_whole_patch():
    """What a saved patch is replayed against: one map has to hold all of it. Every byte "mapped
    somewhere" is not enough -- a range can start in one map, end in the next and have nothing in
    between, and a patch that is in two places at once has no one place in the file."""
    assert rizin_emulation.maps_hold(0x140000000, 0x400, MAPS)
    assert not rizin_emulation.maps_hold(0x140000000, 0x401, MAPS)  # one byte past the map's end
    assert not rizin_emulation.maps_hold(0xFFFFE, 4, MAPS)  # runs into the stack map from below
    neighbours = [{"map": 1, "from": 0x1000, "to": 0x2000, "perm": "r--", "name": "a"},
                  {"map": 2, "from": 0x3000, "to": 0x4000, "perm": "r--", "name": "b"}]
    # both ends mapped, the middle not: the endpoint check alone would let this through
    assert rizin_emulation.maps_hold(0x1FFF, 1, neighbours)
    assert rizin_emulation.maps_hold(0x3000, 1, neighbours)
    assert not rizin_emulation.maps_hold(0x1FFF, 0x1002, neighbours)
    assert not rizin_emulation.maps_hold(0x1000, 1, None) and not rizin_emulation.maps_hold(0x1000, 0, MAPS)


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


# --- Patching (the four kinds, the cache's list, the bytes from a hex field) ---

JZ_SHORT = {"size": 2, "bytes": "7410", "type": "cjmp", "mnemonic": "jz"}
# measured with rz-asm: 0f 84 2e120000 at 0 is "jz 0x1234" (6 bytes), e9 2f120000 is "jmp 0x1234" (5)
JZ_NEAR = {"size": 6, "bytes": "0f842e120000", "type": "cjmp", "mnemonic": "jz"}
CALL = {"size": 5, "bytes": "e8e18f0000", "type": "call", "mnemonic": "call"}


def test_patch_bytes_computes_the_four_kinds():
    jz = JZ_SHORT
    assert rizin_emulation.patch_bytes("nop", jz) == b"\x90\x90"
    assert rizin_emulation.patch_bytes("flip", jz) == b"\x75\x10"
    assert rizin_emulation.patch_bytes("always", jz) == b"\xeb\x10"
    call = CALL
    assert rizin_emulation.patch_bytes("nocall", call) == b"\x90" * 5
    with pytest.raises(ValueError):
        rizin_emulation.patch_bytes("flip", call)


def test_patch_bytes_keeps_the_target_of_a_near_conditional_jump():
    """e9 is one byte shorter than 0f 8x, and a jump's displacement counts from its end: keeping the
    displacement as it is would move the target by one byte, so it is raised by one and a nop fills up."""
    assert rizin_emulation.patch_bytes("flip", JZ_NEAR) == bytes.fromhex("0f852e120000")
    assert rizin_emulation.patch_bytes("always", JZ_NEAR) == bytes.fromhex("e92f12000090")
    assert rizin_emulation.patch_bytes("nop", JZ_NEAR) == b"\x90" * 6
    # a backwards jump: 0f 84 ffffffff lands on the byte after the instruction, e9 00000000 too
    back = dict(JZ_NEAR, bytes="0f84ffffffff")
    assert rizin_emulation.patch_bytes("always", back) == bytes.fromhex("e90000000090")
    # the one displacement where raising it by one would turn the jump around: refused, not written wrong
    with pytest.raises(ValueError):
        rizin_emulation.patch_bytes("always", dict(JZ_NEAR, bytes="0f84ffffff7f"))


def test_jump_pairs_name_each_conditional_jump_and_its_opposite():
    # all 32 checked with rz-asm (-d -a x86 -b 64): 70..7f is jo..jnle rel8, 0f80..0f8f the rel32 forms
    pairs = rizin_emulation.JUMP_PAIRS
    assert len(pairs) == 32
    for opcode, opposite in pairs.items():
        assert opposite != opcode and pairs[opposite] == opcode, opcode
    assert pairs["74"] == "75" and pairs["7f"] == "7e" and pairs["70"] == "71"
    assert pairs["0f84"] == "0f85" and pairs["0f8e"] == "0f8f"


def test_patch_bytes_refuses_what_it_cannot_encode():
    refused = (
        ("zap", JZ_SHORT),                                              # no such kind
        ("flip", CALL),                                                 # not a jump at all
        ("always", CALL),
        ("nocall", JZ_SHORT),                                           # not a call
        ("nop", dict(JZ_SHORT, size=3)),                                # bytes and size disagree
        ("nop", {"size": 0, "bytes": "", "type": "invalid"}),           # rizin decoded nothing
        ("nop", {"size": 1, "bytes": "ff", "type": "invalid"}),         # a byte that is no instruction
        ("nop", dict(JZ_SHORT, bytes="zz")),                            # no hex
        ("flip", {"size": 7, "bytes": "2e0f842e120000", "type": "cjmp"}),   # a prefixed near jump
        ("flip", {"size": 4, "bytes": "6674100f", "type": "cjmp"}),     # an operand-size prefix
        ("flip", {"size": 2, "bytes": "e2f0", "type": "cjmp", "mnemonic": "loop"}),
        ("always", {"size": 2, "bytes": "e3f0", "type": "cjmp", "mnemonic": "jrcxz"}),
    )
    for kind, op in refused:
        with pytest.raises(ValueError):
            rizin_emulation.patch_bytes(kind, op)
    # the reason names the instruction, so the route can pass it on
    with pytest.raises(ValueError, match="call"):
        rizin_emulation.patch_bytes("flip", CALL)


def test_parse_cache_reads_the_objects_wcj_prints_without_an_array():
    """rizin 0.9.1 prints one object per write operation, comma separated and *without* the [] of an
    array, so json.loads cannot read the answer as it stands (measured); an empty cache answers nothing."""
    text = ('{"idx":0,"addr":14,"size":2,"before":"8036","after":"9090","written":false},'
            '{"idx":1,"addr":1540088,"size":8,"before":"0000000000000000",'
            '"after":"1f00000000000000","written":false}\n')
    rows = [{"addr": 14, "size": 2, "before": "8036", "after": "9090"},
            {"addr": 1540088, "size": 8, "before": "0000000000000000", "after": "1f00000000000000"}]
    assert rizin_emulation.parse_cache(text) == rows
    assert rizin_emulation.parse_cache("[" + text.strip() + "]") == rows  # should rizin ever wrap them
    assert rizin_emulation.parse_cache("\n") == [] and rizin_emulation.parse_cache("") == []
    for bad in ("ERROR: something", '{"idx":0}', '{"addr":1,"size":1,"before":"0"}', "42",
                '{"addr":"x","size":1,"before":"0","after":"1"}'):
        with pytest.raises(ValueError):
            rizin_emulation.parse_cache(bad)


def _row(addr, size, after="90"):
    return {"addr": addr, "size": size, "before": "00" * size, "after": after}


def test_patch_rows_mark_only_what_this_session_wrote():
    rows = [_row(0x1000, 2, "9090"), _row(0x20, 1, "41"), _row(0x1000, 1, "cc"), _row(0x1001, 2, "4142")]
    mine = [rizin_emulation.cache_entry(0x1000, b"\x90\x90"), rizin_emulation.cache_entry(0x1000, b"\xcc")]
    marked, kept = rizin_emulation.patch_rows(rows, mine)
    # sorted by address, rizin's order kept where two writes sit at one address (the newer one last)
    assert [(r["addr"], r["after"], r["mine"]) for r in marked] == [
        (0x20, "41", False),            # a run's write elsewhere
        (0x1000, "9090", True),         # this session's patch
        (0x1000, "cc", True),           # and a write of this session over it
        (0x1001, "4142", False)]        # reaches past what this session wrote
    assert all(set(r) == {"addr", "size", "before", "after", "mine"} for r in marked)
    assert kept == mine
    assert [r["mine"] for r in rizin_emulation.patch_rows(rows, [])[0]] == [False] * 4


def test_patch_rows_do_not_claim_a_foreign_write_inside_a_patch():
    """The hole an address set cannot see: a run (or the console) writing into the range this session
    patched. Its row is another row of the cache, so it is matched against the mirror, not the range."""
    mine = [rizin_emulation.cache_entry(0x1000, bytes.fromhex("9090909090"))]
    rows = [_row(0x1000, 5, "9090909090"), _row(0x1002, 1, "41")]
    marked, kept = rizin_emulation.patch_rows(rows, mine)
    assert [(r["addr"], r["after"], r["mine"]) for r in marked] == [
        (0x1000, "9090909090", True), (0x1002, "41", False)]
    assert kept == mine
    # the same bytes at the same address: one row of the two counts as this session's, and it makes no
    # difference which, because either one exports and persists the same byte
    same = [_row(0x1000, 1, "90"), _row(0x1000, 1, "90")]
    marked, kept = rizin_emulation.patch_rows(same, [rizin_emulation.cache_entry(0x1000, b"\x90")])
    assert [r["mine"] for r in marked] == [True, False] and len(kept) == 1
    # a foreign write of the same length at the same address, made *before* this session's: the bytes
    # are part of what is matched, so the foreign row is not the one claimed
    mine = [rizin_emulation.cache_entry(0x1000, b"\x90")]
    marked, kept = rizin_emulation.patch_rows([_row(0x1000, 1, "41"), _row(0x1000, 1, "90")], mine)
    assert [(r["after"], r["mine"]) for r in marked] == [("41", False), ("90", True)]
    assert kept == mine


def test_patch_rows_drop_a_write_the_cache_no_longer_holds():
    """rizin's cache is append-only and a removal keeps the order of the rest (measured), so a write
    whose row is gone is dropped from the mirror -- the rows after it stay this session's."""
    mine = [rizin_emulation.cache_entry(0x10, b"\x11"), rizin_emulation.cache_entry(0x200, b"\x22"),
            rizin_emulation.cache_entry(0x400, b"\x33")]
    rows = [_row(0x10, 1, "11"), _row(0x400, 1, "33")]           # the middle one was taken back
    marked, kept = rizin_emulation.patch_rows(rows, mine)
    assert [(r["addr"], r["mine"]) for r in marked] == [(0x10, True), (0x400, True)]
    assert kept == [mine[0], mine[2]]
    # and with the whole cache gone (wc-*) nothing is left to claim
    assert rizin_emulation.patch_rows([], mine) == ([], [])


def test_cache_entry_is_the_write_in_the_shape_wcj_reports_it():
    assert rizin_emulation.cache_entry(0x1000, b"\x90\x90") == (0x1000, 2, "9090")
    assert rizin_emulation.cache_entry(0x20, bytearray(b"\x0f\x84")) == (0x20, 2, "0f84")


def test_hex_data_takes_an_even_number_of_hex_digits():
    assert rizin_emulation.hex_data("9090") == b"\x90\x90"
    assert rizin_emulation.hex_data("0F84") == b"\x0f\x84"
    assert rizin_emulation.hex_data(b"\x90") == b"\x90"
    assert len(rizin_emulation.hex_data("90" * rizin_emulation.MAX_PATCH_BYTES)) == 4096
    for value in ("9", "zz", "90 90", "", "0x90", "90" * 4097, b"", b"\x90" * 4097, None, 144, True):
        with pytest.raises(ValueError):
            rizin_emulation.hex_data(value)
    # the length is checked before the string is parsed, so a field of megabytes is refused by its size
    with pytest.raises(ValueError, match="at most"):
        rizin_emulation.hex_data("zz" * 500000)


def test_instruction_at_takes_the_op_pdj_decoded_there():
    ops = [{"offset": 0x1000, "size": 2, "bytes": "7410", "type": "cjmp"}]
    assert rizin_emulation.instruction_at(ops, 0x1000) is ops[0]
    assert rizin_emulation.instruction_at(ops, 0x1001) is None
    assert rizin_emulation.instruction_at([], 0x1000) is None
    assert rizin_emulation.instruction_at(None, 0x1000) is None
    # past its block rizin 0.9.1 answers a broken op whose address is not one
    assert rizin_emulation.instruction_at([{"offset": 2 ** 64 - 1, "size": 0, "type": "null"}], 0x1000) is None
