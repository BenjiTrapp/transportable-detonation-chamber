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
