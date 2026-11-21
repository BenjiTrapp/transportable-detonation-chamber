"""The emulation's pure logic (webui/rizin_emulation.py), without rizin."""

import re

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


# --- Re-analysing the range a run decrypted ---------------------------------

def _written(addr, size):
    return {"addr": addr, "size": size, "before": "00" * size, "after": "41" * size}


def test_write_cluster_takes_the_writes_that_belong_together():
    """A decryption loop writes byte by byte: those rows are one range."""
    rows = [_written(0x1000 + i, 1) for i in range(8)]
    assert rizin_emulation.write_cluster(rows) == (0x1000, 0x1007)
    # rizin's order is the order the writes were made, not by address
    assert rizin_emulation.write_cluster(list(reversed(rows))) == (0x1000, 0x1007)
    # one write, and a write of several bytes: the last byte is the end
    assert rizin_emulation.write_cluster([_written(0x20, 1)]) == (0x20, 0x20)
    assert rizin_emulation.write_cluster([_written(0x20, 16)]) == (0x20, 0x2F)
    # overlapping writes (a byte written twice) do not reach past the range
    assert rizin_emulation.write_cluster([_written(0x20, 16), _written(0x24, 2)]) == (0x20, 0x2F)
    assert rizin_emulation.write_cluster([]) is None
    assert rizin_emulation.write_cluster([{"addr": 0x10, "size": 0}]) is None


def test_write_cluster_does_not_span_a_scattered_run():
    """Two writes far apart are not one enormous range: the cluster with the most bytes wins."""
    far = [_written(0x1000 + i, 1) for i in range(8)] + [_written(0x9000000, 1)]
    assert rizin_emulation.write_cluster(far) == (0x1000, 0x1007)
    # the other way round as well: the many bytes decide, not the order or the address
    assert rizin_emulation.write_cluster([_written(0x10, 1)] + [_written(0x9000000 + i, 1)
                                                               for i in range(8)]) == (0x9000000, 0x9000007)
    # a hole of at most RUN_RANGE_GAP keeps the writes together, a larger one splits them
    gap = rizin_emulation.RUN_RANGE_GAP
    assert rizin_emulation.write_cluster([_written(0x1000, 4), _written(0x1000 + 3 + gap, 4)]) == \
        (0x1000, 0x1006 + gap)
    assert rizin_emulation.write_cluster([_written(0x1000, 4), _written(0x1000 + 4 + gap, 8)]) == \
        (0x1004 + gap, 0x100B + gap)
    # two clusters of the same size: the lower one
    assert rizin_emulation.write_cluster([_written(0x900000, 2), _written(0x10, 2)]) == (0x10, 0x11)


def test_function_entries_read_the_addresses_of_afls_rows():
    text = ("0x140001440    1 29           entry0\n"
            "0x1400014b7   30 1382 -> 1300  sym.main\n"
            "WARN: a line that is no row\n"
            "0x140004000 1\n0x1 1 4\nxx 1 4 name\n")
    assert rizin_emulation.function_entries(text) == [0x140001440, 0x1400014B7]
    assert rizin_emulation.function_entries("") == []


def test_written_ranges_merge_what_a_decryption_loop_wrote():
    """A loop's thousands of one-byte rows are one range; what is not next to it is another."""
    rows = [_written(0x1000 + i, 1) for i in range(8)]
    assert rizin_emulation.written_ranges(rows) == [(0x1000, 0x1007)]
    assert rizin_emulation.written_ranges(list(reversed(rows))) == [(0x1000, 0x1007)]
    # touching and overlapping rows merge, a hole of one byte does not
    assert rizin_emulation.written_ranges([_written(0x10, 4), _written(0x14, 4)]) == [(0x10, 0x17)]
    assert rizin_emulation.written_ranges([_written(0x10, 4), _written(0x12, 1)]) == [(0x10, 0x13)]
    assert rizin_emulation.written_ranges([_written(0x10, 4), _written(0x15, 1)]) == [(0x10, 0x13),
                                                                                     (0x15, 0x15)]
    assert rizin_emulation.written_ranges([]) == []
    assert rizin_emulation.written_ranges([{"addr": 0x10, "size": 0}]) == []


def test_run_only_ranges_leave_out_what_a_patch_of_this_session_covers():
    """What the project may keep: a function or flag over bytes a patch holds comes back when the file
    is opened again, so only what *nothing but the run* wrote is dropped."""
    def row(addr, size, mine):
        return dict(_written(addr, size), mine=mine)

    rows = [row(0x1000, 8, False), row(0x1004, 2, True)]
    assert rizin_emulation.run_only_ranges(rows) == [(0x1000, 0x1003), (0x1006, 0x1007)]
    # a patch over the whole of it leaves nothing, one before or after it leaves all of it
    assert rizin_emulation.run_only_ranges([row(0x1000, 4, False), row(0x1000, 4, True)]) == []
    assert rizin_emulation.run_only_ranges([row(0x1000, 4, False), row(0x900, 4, True)]) == \
        [(0x1000, 0x1003)]
    # the ends, and two patches inside one run range
    assert rizin_emulation.run_only_ranges([row(0x1000, 4, False), row(0x1000, 1, True)]) == \
        [(0x1001, 0x1003)]
    assert rizin_emulation.run_only_ranges([row(0x1000, 4, False), row(0x1003, 1, True)]) == \
        [(0x1000, 0x1002)]
    assert rizin_emulation.run_only_ranges([row(0x1000, 9, False), row(0x1002, 1, True),
                                            row(0x1006, 1, True)]) == [(0x1000, 0x1001),
                                                                       (0x1003, 0x1005),
                                                                       (0x1007, 0x1008)]
    assert rizin_emulation.run_only_ranges([row(0x1000, 4, True)]) == []
    assert rizin_emulation.run_only_ranges([]) == []


def test_in_ranges_finds_the_range_an_address_is_in():
    ranges = [(0x10, 0x13), (0x1000, 0x1007), (0x9000000, 0x9000000)]
    assert [addr for addr in (0xF, 0x10, 0x13, 0x14, 0x1007, 0x1008, 0x9000000, 0x9000001)
            if rizin_emulation.in_ranges(addr, ranges)] == [0x10, 0x13, 0x1007, 0x9000000]
    assert rizin_emulation.in_ranges(0x10, []) is False
    for value in (None, "0x10", True, 1.5):
        assert rizin_emulation.in_ranges(value, ranges) is False


def test_string_hits_counts_what_the_search_answered():
    hits = [{"address": 0x1000, "size": 8, "flag": "hit.string.ascii.0", "detail": 8},
            {"address": 0x2000, "size": 4, "flag": "hit.string.ascii.1", "detail": 4}]
    assert rizin_emulation.string_hits(hits) == 2
    assert rizin_emulation.string_hits([]) == 0
    assert rizin_emulation.string_hits(None) == 0      # an empty answer, as cmdj gives it
    for found in ({"address": 1}, "none", [{"size": 8}], [{"address": "0x10", "size": 8}], [None]):
        with pytest.raises(ValueError, match="/zj"):
            rizin_emulation.string_hits(found)


def test_the_string_pattern_searches_for_printable_runs():
    """rizin 0.9.1's /zj takes a pattern, not a range to list the strings of (measured: without one it
    refuses), so the search is for a run of printable bytes of rizin's own least string length. POSIX's
    class is the one form of it that rizin's parser and the console's filter both take as it is."""
    from rizin_sessions import check_console_command

    assert rizin_emulation.STRING_MIN_LENGTH == 4
    assert rizin_emulation.STRING_PATTERN == "[[:print:]]{4,}"
    assert " " not in rizin_emulation.STRING_PATTERN, "one argument of /zj, without quoting"
    assert "~" not in rizin_emulation.STRING_PATTERN, "a '~' would start rizin's grep"
    assert check_console_command(f"/zj {rizin_emulation.STRING_PATTERN} r ascii") is None
    assert check_console_command(r"/zj [\x20-\x7e]{4,} r ascii") is not None, "a backslash is refused"
    # and the commands the re-analysis is built on pass the filter as they are, so none of this needed a
    # change to it -- while a whole-program analysis stays refused
    for allowed in ("af @ 0x1000", "af- @ 0x1000", "aflc"):
        assert check_console_command(allowed) is None, allowed
    assert check_console_command("aa") == "whole-program analysis runs from the Full analysis button"


# --- The API-call assistant (the table, the conventions, the stack fix) -----

def test_lookup_api_strips_prefixes_and_the_ansi_suffix():
    for name in ("sym.imp.KERNEL32.dll_VirtualAlloc", "VirtualAlloc", "sym.imp.LoadLibraryA",
                 "KERNEL32.dll_LoadLibraryW"):
        assert rizin_emulation.lookup_api(name) is not None, name
    assert rizin_emulation.lookup_api("sym.imp.nothing_like_this") is None
    # the row names itself, so a summary can say which API it is
    assert rizin_emulation.lookup_api("sym.imp.KERNEL32.dll_virtualalloc")["name"] == "VirtualAlloc"
    assert rizin_emulation.lookup_api("KERNEL32.dll_LoadLibraryW")["name"] == "LoadLibrary"
    # what rizin names an import on a 32-bit build: sym._memcpy, and stdcall's @<argument bytes>
    assert rizin_emulation.lookup_api("sym._memcpy")["name"] == "memcpy"
    assert rizin_emulation.lookup_api("sym.imp.KERNEL32.dll_Sleep@4")["name"] == "Sleep"
    # a name that is only a prefix, a name that merely starts with one of the table's, and no name
    for name in ("sym.imp.", "", "GetTickCount64_and_more", "myVirtualAlloc", None, 7, b"Sleep"):
        assert rizin_emulation.lookup_api(name) is None, name
    assert rizin_emulation.lookup_api("GetTickCount64")["ret"] == "tick"


def test_convention_picks_the_return_register_per_arch():
    assert rizin_emulation.convention("x86", 64, None)["ret_reg"] == "rax"
    assert rizin_emulation.convention("x86", 32, None)["ret_reg"] == "eax"
    assert rizin_emulation.convention("arm", 64, None) is None
    # the assistant covers x86-32 and x86-64 and nothing else: everywhere else it switches off
    for arch, bits in (("arm", 32), ("mips", 32), ("x86", 16), ("x86", None), (None, 64), ("X86", 64)):
        assert rizin_emulation.convention(arch, bits, None) is None, (arch, bits)
    win64 = rizin_emulation.convention("x86", 64, rizin_emulation.lookup_api("VirtualAlloc"))
    assert win64["arg_regs"] == ("rcx", "rdx", "r8", "r9") and win64["word"] == 8
    assert win64["stack_args"] is False and win64["callee_pops"] is False, "the caller clears the stack"
    std32 = rizin_emulation.convention("x86", 32, rizin_emulation.lookup_api("VirtualAlloc"))
    assert std32["stack_args"] is True and std32["callee_pops"] is True and std32["word"] == 4
    assert std32["arg_regs"] == ()
    # without a row of the table nothing is known to clear the stack, so nothing is cleared
    assert rizin_emulation.convention("x86", 32, None)["callee_pops"] is False


def test_stack_fix_only_applies_to_stdcall():
    # Review Focus 1: a 32-bit stdcall callee pops its arguments. Skipping the call with
    # aess pops nothing, so without this the stack stays too deep and every later step
    # computes on a corrupt stack.
    win64 = rizin_emulation.convention("x86", 64, rizin_emulation.lookup_api("VirtualAlloc"))
    std32 = rizin_emulation.convention("x86", 32, rizin_emulation.lookup_api("VirtualAlloc"))
    cdecl32 = rizin_emulation.convention("x86", 32, rizin_emulation.lookup_api("memcpy"))
    assert rizin_emulation.stack_fix(win64, 4) == 0
    assert rizin_emulation.stack_fix(std32, 4) == 16
    assert rizin_emulation.stack_fix(cdecl32, 3) == 0
    # a call without arguments corrects nothing, and no argument count is taken on trust
    assert rizin_emulation.stack_fix(std32, 0) == 0
    for args in (None, -1, True, 1.5, "4", rizin_emulation.ASSIST_MAX_ARGS + 1):
        assert rizin_emulation.stack_fix(std32, args) == 0, args
    assert rizin_emulation.stack_fix(None, 4) == 0


def test_the_api_table_is_data_in_one_shape():
    """The spec asks for a table that grows without a code change, so every row is a name and the same
    four fields, and every answer is one the assistant can actually build."""
    for name, api in rizin_emulation.API_TABLE.items():
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name), name
        assert set(api) <= {"conv", "args", "ret", "size_arg", "out"}, name
        assert api["conv"] in ("win64", "stdcall", "cdecl"), name
        assert isinstance(api["args"], int) and 0 <= api["args"] <= rizin_emulation.ASSIST_MAX_ARGS, name
        assert api["ret"] in rizin_emulation.ANSWERS, name
        if api["ret"] in ("buffer", "copy"):
            assert 0 <= api["size_arg"] < api["args"], name
        else:
            assert "size_arg" not in api, name
        for index, what in api.get("out", ()):
            # an out-parameter's pointer is one of the call's own arguments, and what goes there is
            # one of the kinds out_bytes can build
            assert 0 <= index < api["args"] and what in rizin_emulation.OUT_WRITES, name
            assert rizin_emulation.out_bytes(what, api, rizin_emulation.TICK_START)[0] is not None, name
        assert rizin_emulation.lookup_api(name)["name"] == name
    # the seven groups of the spec's table are in it
    for name in ("VirtualAlloc", "HeapAlloc", "malloc", "VirtualProtect", "LoadLibrary",
                 "GetModuleHandle", "GetProcAddress", "IsDebuggerPresent", "GetTickCount",
                 "GetComputerName", "GetUserName", "memcpy", "memmove", "RtlMoveMemory"):
        assert name in rizin_emulation.API_TABLE, name
    # the Win32 calls are stdcall (which 64 bits ignores) and the CRT ones cdecl
    assert rizin_emulation.API_TABLE["VirtualAlloc"]["conv"] == "stdcall"
    assert [rizin_emulation.API_TABLE[n]["conv"] for n in ("memcpy", "memmove", "malloc")] == ["cdecl"] * 3


def test_free_span_keeps_clear_of_the_file_and_the_stack():
    """A buffer the assistant hands out must collide with neither the file's maps nor the stack, and a
    second allocation must not be handed the first one's memory -- which is why it is searched for in
    omlj's maps rather than fixed."""
    base, step = rizin_emulation.ASSIST_ADDR, rizin_emulation.ASSIST_STEP
    assert rizin_emulation.free_span(MAPS, 0x1000) == base
    assert rizin_emulation.free_span([], 0x1000) == base
    assert rizin_emulation.free_span(None, 0x1000) == base
    taken = [{"from": base, "to": base + 0x1000, "perm": "rw-", "name": "mem.assist"}]
    assert rizin_emulation.free_span(taken, 0x1000) == base + step
    assert rizin_emulation.free_span(taken + [{"from": base + step, "to": base + 2 * step}],
                                     0x1000) == base + 2 * step
    # a span that reaches into the next map is no free span
    assert rizin_emulation.free_span([{"from": base + 0x800, "to": base + 0x900}], 0x1000) == base + step
    # nothing free in reach, and a size that is no size
    everything = [{"from": 0, "to": 2 ** 64 - 1}]
    assert rizin_emulation.free_span(everything, 0x1000) is None
    for size in (0, -1, None, True, 1.5, 2 ** 32):
        assert rizin_emulation.free_span(MAPS, size) is None, size
    assert rizin_emulation.span_is_free(MAPS, base, 0x1000) is True
    assert rizin_emulation.span_is_free(MAPS, 0x140000000, 1) is False      # the file
    assert rizin_emulation.span_is_free(MAPS, 0x1EFFFF, 1) is False         # the stack
    assert rizin_emulation.span_is_free(MAPS, 0x13FFFFFFF, 2) is False      # reaches into the file


def test_buffer_size_rounds_up_to_a_page_and_is_bounded():
    page, most = rizin_emulation.ASSIST_BUFFER_MIN, rizin_emulation.ASSIST_BUFFER_MAX
    assert rizin_emulation.buffer_size(1) == page and rizin_emulation.buffer_size(page) == page
    assert rizin_emulation.buffer_size(page + 1) == 2 * page
    assert rizin_emulation.buffer_size(most) == most
    # what is no size, and a size above the maximum: nothing is offered rather than gigabytes mapped
    for size in (0, -1, most + 1, 2 ** 64 - 1, None, True, 1.5, "0x1000"):
        assert rizin_emulation.buffer_size(size) is None, size


def test_read_cstring_takes_the_name_before_the_first_nul():
    assert rizin_emulation.read_cstring(list(b"Sleep\0rest")) == "Sleep"
    assert rizin_emulation.read_cstring(list(b"GetProcAddress")) is None, "no NUL in reach"
    # only what a file may name an export; nothing of it ever goes into a command
    for data in (b"", b"\0", b"a b\0", b"a;wci\0", b"\x80\x81\0", b"-" * 80 + b"\0"):
        assert rizin_emulation.read_cstring(list(data)) is None, data
    assert rizin_emulation.read_cstring("Sleep\0") is None and rizin_emulation.read_cstring(None) is None
    assert rizin_emulation.read_cstring([0x41, 300, 0]) is None, "pxj answers bytes"


def test_esil_ranges_and_fds_name_the_vms_own_memory():
    """R37: what the emulation's own memory is, told from the file's by the name aeim gives it. The
    ranges keep a run's pushed words out of the range a re-analysis takes (a pushed word is no code),
    and the descriptors are what a stop closes to give the memory back."""
    maps = [{"map": 1, "fd": 3, "from": 0x140000000, "to": 0x140000400, "perm": "r-x", "name": "fmap..text"},
            {"map": 2, "fd": 3, "from": 0x140001000, "to": 0x140002000, "perm": "r--", "name": "fmap..data"},
            {"map": 3, "fd": 4, "from": 0x100000, "to": 0x1F0000, "perm": "rw-", "name": "mem.0x100000_0xf0000"},
            {"map": 4, "fd": 5, "from": 0x50000000, "to": 0x50001000, "perm": "rw-", "name": "mem.assist"}]
    assert rizin_emulation.esil_ranges(maps) == [(0x100000, 0x1F0000), (0x50000000, 0x50001000)]
    assert rizin_emulation.esil_ranges([]) == [] and rizin_emulation.esil_ranges(None) == []
    # the newest map first, so a stop gives the assistant's buffers back before the stack
    assert rizin_emulation.esil_fds(maps) == [5, 4]
    # a descriptor the file is mapped through is never closed, whatever a map of it is called
    shared = maps + [{"map": 5, "fd": 5, "from": 0x200000, "to": 0x201000, "perm": "r--", "name": "fmap..x"}]
    assert rizin_emulation.esil_fds(shared) == [4]
    assert rizin_emulation.esil_fds([]) == [] and rizin_emulation.esil_fds(None) == []
    # one descriptor is named once, however many maps of it there are
    twice = maps + [{"map": 5, "fd": 5, "from": 0x51000000, "to": 0x51001000, "perm": "rw-",
                     "name": "mem.assist"}]
    assert rizin_emulation.esil_fds(twice) == [5, 4]


def test_overlaps_any_finds_a_write_inside_the_vms_memory():
    ranges = [(0x100000, 0x1F0000), (0x50000000, 0x50001000)]
    assert rizin_emulation.overlaps_any(0x178000, 8, ranges)
    assert rizin_emulation.overlaps_any(0x1EFFFF, 1, ranges)
    assert rizin_emulation.overlaps_any(0xFFFFC, 8, ranges), "reaches into the stack from below"
    assert not rizin_emulation.overlaps_any(0x1F0000, 8, ranges), "a range's end is not in it"
    assert not rizin_emulation.overlaps_any(0x140002000, 8, ranges)
    assert not rizin_emulation.overlaps_any(0x178000, 0, ranges) and not rizin_emulation.overlaps_any(
        0x178000, None, ranges)
    assert not rizin_emulation.overlaps_any(0x178000, 8, [])


def test_pseudo_value_is_bounded_and_really_in_no_map():
    """Important 4: these values are offered *because* nothing is mapped at them, so that a run which
    calls or reads one traps instead of running on through nothing. A dump can have maps anywhere."""
    base, step = rizin_emulation.ASSIST_HANDLE, rizin_emulation.ASSIST_SPACING
    assert rizin_emulation.pseudo_value([], base, 0) == (base, 0)
    assert rizin_emulation.pseudo_value(None, base, 3) == (base + 3 * step, 3)
    # a map over the first two values moves the series on, and says which step it used
    dump = [{"from": base, "to": base + 2 * step, "perm": "rw-", "name": "mmap.dump"}]
    assert rizin_emulation.pseudo_value(dump, base, 0) == (base + 2 * step, 2)
    # used up: nothing is offered rather than a value in someone else's map
    whole = [{"from": base, "to": base + rizin_emulation.ASSIST_PSEUDO_TRIES * step, "name": "mmap.dump"}]
    assert rizin_emulation.pseudo_value(whole, base, 0) == (None, 0)
    assert rizin_emulation.pseudo_value([], base, rizin_emulation.ASSIST_PSEUDO_TRIES) == (None, rizin_emulation.ASSIST_PSEUDO_TRIES)
    for index in (None, -1, True, 1.5):
        assert rizin_emulation.pseudo_value([], base, index) == (None, 0), index
    # the two series cannot reach into each other: 256 steps of 0x10000 fill the space between them
    assert base + rizin_emulation.ASSIST_PSEUDO_TRIES * step <= rizin_emulation.ASSIST_PSEUDO


def test_out_bytes_are_the_values_the_spec_asks_for():
    """Important 3: the time and environment groups answer with the **value**, not just a return code.
    A QueryPerformanceCounter whose counter is never written lets a timing check see no time pass."""
    api = rizin_emulation.lookup_api("QueryPerformanceCounter")
    data, what = rizin_emulation.out_bytes("counter", api, rizin_emulation.TICK_START)
    assert len(data) == 8 and "performance counter" in what
    # the same elapsed time as the tick clock: 10 MHz, so 10 000 counts per millisecond
    assert int.from_bytes(data, "little") == rizin_emulation.TICK_START * 10000
    later = rizin_emulation.out_bytes("counter", api, rizin_emulation.TICK_START + rizin_emulation.TICK_STEP)[0]
    assert int.from_bytes(later, "little") > int.from_bytes(data, "little")
    frequency = rizin_emulation.out_bytes("frequency", api, 0)[0]
    assert len(frequency) == 8 and int.from_bytes(frequency, "little") == rizin_emulation.ASSIST_QPC_FREQUENCY
    # a FILETIME is 100 ns units since 1601 and rises with the same clock
    stamp = rizin_emulation.out_bytes("filetime", api, rizin_emulation.TICK_START)[0]
    assert len(stamp) == 8 and int.from_bytes(stamp, "little") == \
        rizin_emulation.ASSIST_FILETIME_BASE + rizin_emulation.TICK_START * 10000

    # the ANSI and the Unicode form of a call write the name in their own encoding
    ansi = rizin_emulation.lookup_api("sym.imp.KERNEL32.dll_GetComputerNameA")
    wide = rizin_emulation.lookup_api("sym.imp.KERNEL32.dll_GetComputerNameW")
    assert ansi["wide"] is False and wide["wide"] is True
    assert rizin_emulation.out_bytes("computer", ansi, 0)[0] == \
        rizin_emulation.ASSIST_COMPUTER.encode("ascii") + b"\0"
    assert rizin_emulation.out_bytes("computer", wide, 0)[0] == \
        rizin_emulation.ASSIST_COMPUTER.encode("utf-16-le") + b"\0\0"
    # the in/out size that goes with the name is its length in characters, not in bytes
    assert rizin_emulation.out_bytes("chars", wide, 0)[0] == \
        len(rizin_emulation.ASSIST_COMPUTER).to_bytes(4, "little")
    assert rizin_emulation.out_bytes("user", ansi, 0)[0] == rizin_emulation.ASSIST_USER.encode("ascii") + b"\0"
    serial = rizin_emulation.out_bytes("serial", ansi, 0)[0]
    assert int.from_bytes(serial, "little") == rizin_emulation.ASSIST_SERIAL and len(serial) == 4
    # nothing of this names a VM
    for value in (rizin_emulation.ASSIST_COMPUTER, rizin_emulation.ASSIST_USER, rizin_emulation.ASSIST_VOLUME):
        assert not any(mark in value.lower() for mark in
                       ("vbox", "vmware", "virtual", "qemu", "xen", "sandbox", "malware", "sample")), value
    assert rizin_emulation.out_bytes("nothing_like_this", ansi, 0) == (None, None)


def test_the_copy_bound_and_the_write_chunk_follow_what_rizin_does():
    """R36: 4096 bytes made the common unpacker shape -- a section-sized memcpy -- copy nothing. The
    new bound is a cost bound (measured: 1 MB through the pipe in 2.96 s), and the chunk is what rizin
    needs: a `wx` whose command line passes about 4 KB writes **nothing** and says so on stderr only
    (measured: 0x500 bytes land, 0x7ff bytes do not)."""
    assert rizin_emulation.ASSIST_COPY_MAX == 0x100000
    assert rizin_emulation.ASSIST_COPY_MAX > rizin_emulation.MAX_PATCH_BYTES
    assert 2 * rizin_emulation.ASSIST_WRITE_CHUNK + 32 < 4096, "one wx stays inside rizin's command buffer"
    assert rizin_emulation.ASSIST_READ_CHUNK <= rizin_emulation.ASSIST_COPY_MAX
