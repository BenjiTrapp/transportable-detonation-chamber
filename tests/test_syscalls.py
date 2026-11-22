"""NTSleuth syscall baseline: loading, validation, the lookup catalog, and measuring a process."""

import json
import os

import pytest

import memory_evidence
import syscall_baseline
import syscall_scan

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def _fixture(view):
    with open(os.path.join(SAMPLES, f"ntsleuth-26220.5770-{view}.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_parse_baseline_reads_numbers_and_stub_bytes():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    assert bl.build == "26220.5770"
    assert bl.view == "arm64"
    assert bl.syscalls["NtWriteVirtualMemory"].number == 0x3A
    assert bl.syscalls["NtWriteVirtualMemory"].module == "ntdll.dll"
    assert isinstance(bl.syscalls["NtWriteVirtualMemory"].stub_bytes, bytes)
    assert bl.by_number[("ntdll.dll", 0x3A)].name == "NtWriteVirtualMemory"


def test_parse_baseline_keeps_sal_annotations_in_order():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    params = bl.syscalls["NtWriteVirtualMemory"].parameters
    assert [p["name"] for p in params][:2] == ["ProcessHandle", "BaseAddress"]
    assert params[0]["sal_annotation"] == "_In_"


def test_find_baseline_matches_build_and_view(tmp_path):
    (tmp_path / "ntsleuth-26220.5770-arm64.json").write_text("{}")
    assert syscall_baseline.find_baseline(str(tmp_path), "26220.5770", "arm64")
    assert syscall_baseline.find_baseline(str(tmp_path), "26220.5770", "x64") is None
    assert syscall_baseline.find_baseline(str(tmp_path), "26100.1", "arm64") is None


def test_catalog_filters_by_name_and_module_and_pages():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    page = syscall_baseline.catalog(bl, query="virtual", module="ntdll.dll", limit=2)
    assert page["limit"] == 2 and len(page["items"]) == 2
    assert page["total"] >= 3
    assert all("Virtual" in i["name"] for i in page["items"])


def test_catalog_name_match_ignores_case_and_sorts_by_module_then_number():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    page = syscall_baseline.catalog(bl, query="NT")
    assert [i["number"] for i in page["items"]] == [0x18, 0x3A, 0x50, 0x1034]
    assert page["items"][-1]["module"] == "win32u.dll"
    assert syscall_baseline.catalog(bl, query="WRITEVIRTUAL")["total"] == 1


def test_catalog_pages_with_offset_and_reports_the_total():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    page = syscall_baseline.catalog(bl, offset=3, limit=2)
    assert page["total"] == 4 and page["offset"] == 3
    assert [i["name"] for i in page["items"]] == ["NtUserGetForegroundWindow"]
    assert syscall_baseline.catalog(bl, offset=99)["items"] == []


def test_entry_without_stub_bytes_is_skipped_not_fatal():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    assert "NtNoStub" not in bl.syscalls
    assert "NtNoStub" in bl.skipped
    assert len(bl.syscalls) >= 4


def test_truncated_json_raises_one_clear_error(tmp_path):
    p = tmp_path / "ntsleuth-26220.5770-arm64.json"
    p.write_text('{"syscalls": [{"name": "NtFoo"')
    with pytest.raises(syscall_baseline.BaselineError):
        syscall_baseline.load_baseline(str(p))


def test_entries_that_are_not_true_syscalls_are_skipped():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    assert "NtNotASyscall" not in bl.syscalls
    assert "NtNotASyscall" in bl.skipped


def _entry(**overrides):
    entry = {"name": "NtFoo", "module": "ntdll.dll", "syscall_number": 1, "rva": 16,
             "return_type": "NTSTATUS", "calling_convention": "__stdcall",
             "parameters": [], "stub_bytes": "0f05c3", "is_true_syscall": True}
    entry.update(overrides)
    return entry


@pytest.mark.parametrize("overrides", [
    {"stub_bytes": ""},
    {"stub_bytes": "zz"},
    {"stub_bytes": "abc"},
    {"stub_bytes": 7},
    {"syscall_number": "58"},
    {"syscall_number": True},
    {"syscall_number": None},
    {"rva": None},
    {"rva": -1},
    {"syscall_number": -1},
    {"module": ""},
])
def test_malformed_entry_is_skipped_and_the_rest_still_loads(overrides):
    payload = {"syscalls": [_entry(**overrides), _entry(name="NtBar", syscall_number=2)]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")
    assert list(bl.syscalls) == ["NtBar"]
    assert bl.skipped == ["NtFoo"]


def test_non_object_entry_is_skipped_without_a_name():
    bl = syscall_baseline.parse_baseline({"syscalls": ["junk", _entry()]}, "1.0", "x64")
    assert list(bl.syscalls) == ["NtFoo"]
    assert bl.skipped == ["#0"]


def test_missing_optional_fields_default():
    entry = _entry()
    for key in ("return_type", "calling_convention", "parameters"):
        del entry[key]
    sc = syscall_baseline.parse_baseline({"syscalls": [entry]}, "1.0", "x64").syscalls["NtFoo"]
    assert (sc.return_type, sc.calling_convention, sc.parameters) == ("", "", [])


def test_duplicate_name_keeps_the_first_entry_and_is_not_reported_as_skipped():
    payload = {"syscalls": [_entry(), _entry(syscall_number=2, rva=32)]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")
    assert bl.syscalls["NtFoo"].number == 1
    assert bl.skipped == []


def test_duplicate_number_under_another_name_is_skipped():
    payload = {"syscalls": [_entry(), _entry(name="NtBaz")]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")
    assert list(bl.syscalls) == ["NtFoo"]
    assert bl.by_number[("ntdll.dll", 1)].name == "NtFoo"
    assert bl.skipped == ["NtBaz"]


@pytest.mark.parametrize("bad_first", [True, False])
def test_a_name_is_never_in_syscalls_and_skipped_at_once(bad_first):
    bad, good = _entry(stub_bytes=""), _entry(syscall_number=2)
    payload = {"syscalls": [bad, good] if bad_first else [good, bad]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")
    assert "NtFoo" in bl.syscalls
    assert not set(bl.skipped) & set(bl.syscalls)


def test_the_fixtures_carry_ntsleuths_entry_schema():
    entry_keys = {"calling_convention", "is_true_syscall", "module", "name", "return_type",
                  "rva", "syscall_number", "stub_bytes", "parameters"}
    param_keys = {"name", "type", "sal_annotation", "is_const", "is_input", "is_optional",
                  "is_output", "is_pointer"}
    for view in ("arm64", "x64"):
        for entry in _fixture(view)["syscalls"]:
            assert set(entry) - {"stub_bytes"} == entry_keys - {"stub_bytes"}, entry["name"]
            assert isinstance(entry["rva"], int) and isinstance(entry["syscall_number"], int)
            assert all(set(p) == param_keys for p in entry["parameters"]), entry["name"]


def test_parameter_flags_survive_parsing():
    bl = syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64")
    last = bl.syscalls["NtWriteVirtualMemory"].parameters[-1]
    assert (last["is_output"], last["is_optional"], last["is_pointer"]) == (True, True, True)
    assert bl.syscalls["NtWriteVirtualMemory"].parameters[0]["is_input"] is True


def test_catalog_number_query_is_a_union_with_the_name_match():
    payload = {"syscalls": [
        _entry(name="NtAddAtom", syscall_number=0x11),
        _entry(name="NtWriteVirtualMemory", syscall_number=0x3A),
        _entry(name="NtOther", syscall_number=0xADD),
    ]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")

    def names(query):
        return [i["name"] for i in syscall_baseline.catalog(bl, query=query)["items"]]

    assert names("add") == ["NtAddAtom", "NtOther"]
    assert names("0x3a") == ["NtWriteVirtualMemory"]
    assert names("0X3A") == ["NtWriteVirtualMemory"]
    assert names("58") == ["NtWriteVirtualMemory"]
    assert names("3a") == ["NtWriteVirtualMemory"]
    assert names("0x3") == []


def test_catalog_clamps_negative_paging():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    page = syscall_baseline.catalog(bl, offset=-5, limit=-1)
    assert (page["offset"], page["limit"], page["items"]) == (0, 0, [])


def test_load_baseline_accepts_a_bare_list_and_the_syscalls_object(tmp_path):
    entries = _fixture("x64")["syscalls"]
    for label, payload in (("list", entries), ("object", {"syscalls": entries})):
        d = tmp_path / label
        d.mkdir()
        p = d / "ntsleuth-26220.5770-x64.json"
        p.write_text(json.dumps(payload))
        bl = syscall_baseline.load_baseline(str(p))
        assert bl.syscalls["NtWriteVirtualMemory"].number == 0x3A, label
        assert bl.skipped == ["NtNotASyscall", "NtNoStub"], label


@pytest.mark.parametrize("payload", [{}, {"syscalls": "x"}, {"syscalls": None}, "x", None, 7])
def test_payload_without_a_syscall_list_raises(payload):
    with pytest.raises(syscall_baseline.BaselineError):
        syscall_baseline.parse_baseline(payload, "1.0", "x64")


def test_load_baseline_reads_a_file_and_takes_build_and_view_from_its_name(tmp_path):
    p = tmp_path / "ntsleuth-26220.5770-x64.json"
    p.write_text(json.dumps(_fixture("x64")))
    bl = syscall_baseline.load_baseline(str(p))
    assert (bl.build, bl.view) == ("26220.5770", "x64")
    assert bl.syscalls["NtWriteVirtualMemory"].number == 0x3A


def test_load_baseline_rejects_unreadable_and_unnamed_files(tmp_path):
    with pytest.raises(syscall_baseline.BaselineError):
        syscall_baseline.load_baseline(str(tmp_path / "ntsleuth-1.0-x64.json"))
    other = tmp_path / "baseline.json"
    other.write_text(json.dumps(_fixture("x64")))
    with pytest.raises(syscall_baseline.BaselineError):
        syscall_baseline.load_baseline(str(other))


@pytest.mark.parametrize("label, payload", [
    ("bare empty list", []),
    ("empty syscalls object", {"syscalls": []}),
    ("every entry skipped", {"syscalls": [_entry(stub_bytes=""), _entry(name="NtBar", is_true_syscall=False)]}),
])
def test_load_baseline_rejects_a_payload_without_usable_syscalls(tmp_path, label, payload):
    p = tmp_path / "ntsleuth-26220.5770-x64.json"
    p.write_text(json.dumps(payload))
    with pytest.raises(syscall_baseline.BaselineError, match="no usable syscalls"):
        syscall_baseline.load_baseline(str(p))


@pytest.mark.parametrize("view", ["arm64", "x64"])
def test_fixture_stub_windows_are_32_bytes(view):
    bl = syscall_baseline.parse_baseline(_fixture(view), "26220.5770", view)
    assert {len(sc.stub_bytes) for sc in bl.syscalls.values()} == {32}


@pytest.mark.parametrize("build, view", [
    ("26220.5770", "../arm64"),
    ("26220.5770", "/etc/passwd"),
    ("26220.5770", "arm64/../x64"),
    ("26220.5770", "sparc"),
    ("26220.5770", ""),
    ("../26220", "arm64"),
    ("/tmp/x", "arm64"),
    ("26220.5770\\..", "arm64"),
    ("", "arm64"),
    ("26220.5770", "arm64\n"),
    ("26220.5770\n", "arm64"),
])
def test_find_baseline_refuses_unsafe_names_without_touching_the_filesystem(
        tmp_path, monkeypatch, build, view):
    (tmp_path / "ntsleuth-26220.5770-arm64.json").write_text("{}")

    def boom(*args, **kwargs):
        raise AssertionError("the filesystem was touched")

    monkeypatch.setattr(syscall_baseline.os.path, "isfile", boom)
    assert syscall_baseline.find_baseline(str(tmp_path), build, view) is None


def test_same_name_in_another_module_is_recorded_and_the_first_wins():
    payload = {"syscalls": [
        _entry(),
        _entry(module="win32u.dll", syscall_number=0x1001),
        _entry(name="NtBar", module="win32u.dll", syscall_number=0x1002),
    ]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")
    assert bl.syscalls["NtFoo"].module == "ntdll.dll"
    assert bl.shadowed == ["NtFoo"]
    assert ("win32u.dll", 0x1001) not in bl.by_number
    assert bl.skipped == []


def test_same_name_in_the_same_module_is_not_reported_as_shadowed():
    bl = syscall_baseline.parse_baseline({"syscalls": [_entry(), _entry(syscall_number=2)]}, "1.0", "x64")
    assert bl.shadowed == []


def test_a_baseline_file_name_with_a_trailing_newline_is_not_a_baseline_name(tmp_path):
    path = tmp_path / "ntsleuth-1.0-x64.json\n"
    path.write_text(json.dumps({"syscalls": [_entry()]}))
    with pytest.raises(syscall_baseline.BaselineError):
        syscall_baseline.load_baseline(str(path))


def test_a_name_shadowed_by_several_entries_is_recorded_once():
    payload = {"syscalls": [
        _entry(),
        _entry(module="win32u.dll", syscall_number=0x1001),
        _entry(module="win32u.dll", syscall_number=0x1002),
    ]}
    bl = syscall_baseline.parse_baseline(payload, "1.0", "x64")
    assert bl.shadowed == ["NtFoo"]


def _names(page):
    return [i["name"] for i in page["items"]]


def test_catalog_module_filter_alone_lists_that_module_in_number_order():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    page = syscall_baseline.catalog(bl, module="ntdll.dll")
    assert _names(page) == ["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory"]
    assert page["total"] == 3


def test_catalog_module_filter_selects_win32u():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    page = syscall_baseline.catalog(bl, module="win32u.dll")
    assert _names(page) == ["NtUserGetForegroundWindow"] and page["total"] == 1


def test_catalog_module_match_ignores_case_and_surrounding_space():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    assert syscall_baseline.catalog(bl, module=" NTDLL.DLL ")["total"] == 3
    assert syscall_baseline.catalog(bl, module="Win32U.dll")["total"] == 1


def test_catalog_number_query_combines_with_the_module_filter():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    assert _names(syscall_baseline.catalog(bl, query="0x3a", module="ntdll.dll")) == ["NtWriteVirtualMemory"]
    assert syscall_baseline.catalog(bl, query="0x3a", module="win32u.dll")["items"] == []
    assert _names(syscall_baseline.catalog(bl, query="0x1034", module="win32u.dll")) == ["NtUserGetForegroundWindow"]
    assert syscall_baseline.catalog(bl, query="0x1034", module="ntdll.dll")["items"] == []


def test_catalog_module_match_ignores_the_case_of_the_stored_module_too():
    bl = syscall_baseline.parse_baseline({"syscalls": [_entry(module="NTDLL.dll")]}, "1.0", "x64")
    assert syscall_baseline.catalog(bl, module="ntdll.dll")["total"] == 1


def test_prefix_length_stops_before_the_next_stub():
    bl = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")
    sc = bl.syscalls["NtWriteVirtualMemory"]
    assert syscall_baseline.stub_prefix_len(sc, "arm64") == 8


def test_x64_prefix_ends_after_the_syscall_instruction():
    bl = syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64")
    sc = bl.syscalls["NtWriteVirtualMemory"]
    n = syscall_baseline.stub_prefix_len(sc, "x64")
    assert sc.stub_bytes[n - 2:n] == b"\x0f\x05"
    assert n < 32


def test_x64_prefix_ignores_a_syscall_number_that_spells_0f05():
    sc = syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64").syscalls["NtWriteVirtualMemory"]
    sc.stub_bytes = bytes.fromhex("4c8bd1b80f050000") + sc.stub_bytes[8:]
    assert syscall_baseline.stub_prefix_len(sc, "x64") == 20


def test_x64_prefix_without_a_syscall_instruction_falls_back_to_the_whole_window():
    sc = syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64").syscalls["NtWriteVirtualMemory"]
    sc.stub_bytes = b"\x90" * 32
    assert syscall_baseline.stub_prefix_len(sc, "x64") == 32


def test_prefix_never_exceeds_the_stub_the_baseline_holds():
    sc = syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64").syscalls["NtWriteVirtualMemory"]
    sc.stub_bytes = sc.stub_bytes[:6]
    assert syscall_baseline.stub_prefix_len(sc, "arm64") == 6


def _sc(view, name="NtWriteVirtualMemory"):
    return syscall_baseline.parse_baseline(_fixture(view), "26220.5770", view).syscalls[name]


@pytest.mark.parametrize("live_hex,owner,state,pattern", [
    ("41 07 00 d4 c0 03 5f d6", None,        "intact",   None),
    ("05 00 00 14 c0 03 5f d6", "edr.dll",   "hooked",   "B"),
    ("05 00 00 14 c0 03 5f d6", "private",   "patched",  "B"),
    ("05 00 00 14 c0 03 5f d6", None,        "diverged", "B"),
    ("11 22 33 44 55 66 77 88", "private",   "patched",  None),
    ("50 00 00 58 00 02 1f d6", "edr.dll",   "hooked",   "LDR x16; BR x16"),
    ("01 18 00 d4 c0 03 5f d6", None,        "diverged", None),
])
def test_classify_arm64_states(live_hex, owner, state, pattern):
    out = syscall_baseline.classify_stub(
        _sc("arm64"), bytes.fromhex(live_hex.replace(" ", "")), "arm64", owner)
    assert out["state"] == state
    assert out["pattern"] == pattern


def test_classify_x64_hook_patterns():
    sc = _sc("x64")
    live = bytes.fromhex("e92b170080") + sc.stub_bytes[5:]
    out = syscall_baseline.classify_stub(sc, live, "x64", "private")
    assert (out["state"], out["pattern"]) == ("patched", "JMP rel32")
    live = bytes.fromhex("ff251a4c0300") + sc.stub_bytes[6:]
    out = syscall_baseline.classify_stub(sc, live, "x64", "edr.dll")
    assert (out["state"], out["pattern"]) == ("hooked", "JMP [rip]")
    out = syscall_baseline.classify_stub(sc, live, "x64", None)
    assert (out["state"], out["pattern"]) == ("diverged", "JMP [rip]")


@pytest.mark.parametrize("head_hex,pattern", [
    ("48b8" + "8877665544332211" + "ffe0", "MOV RAX; JMP RAX"),
    ("49bb" + "8877665544332211" + "41ffe3", "MOV R11; JMP R11"),
    ("68" + "44332211" + "c3", "PUSH; RET"),
])
def test_classify_x64_absolute_hook_patterns(head_hex, pattern):
    sc = _sc("x64")
    head = bytes.fromhex(head_hex)
    out = syscall_baseline.classify_stub(sc, head + sc.stub_bytes[len(head):], "x64", "edr.dll")
    assert (out["state"], out["pattern"]) == ("hooked", pattern)


def test_x64_garbage_over_the_stub_follows_the_owner_too():
    sc = _sc("x64")
    live = b"\x11\x22\x33\x44\x55\x66\x77\x88" + sc.stub_bytes[8:]
    states = {owner: syscall_baseline.classify_stub(sc, live, "x64", owner)["state"]
              for owner in ("private", "edr.dll", None)}
    assert states == {"private": "patched", "edr.dll": "hooked", None: "diverged"}


def test_a_changed_syscall_number_alone_is_reported():
    sc = _sc("x64")
    live = bytearray(sc.stub_bytes)
    live[4] = (sc.number + 1) & 0xFF
    out = syscall_baseline.classify_stub(sc, bytes(live), "x64", None)
    assert out["number_matches"] is False
    assert out["state"] == "diverged"


def test_a_changed_arm64_syscall_number_alone_is_reported():
    out = syscall_baseline.classify_stub(
        _sc("arm64"), bytes.fromhex("01 18 00 d4 c0 03 5f d6".replace(" ", "")), "arm64", None)
    assert out["number_matches"] is False


def test_an_untouched_stub_has_a_matching_number_and_no_target():
    for view in ("arm64", "x64"):
        sc = _sc(view)
        out = syscall_baseline.classify_stub(sc, sc.stub_bytes, view, "edr.dll")
        assert out["state"] == "intact"
        assert out["number_matches"] is True
        assert out["target_owner"] is None
        assert out["pattern"] is None


def test_a_hook_that_overwrites_the_number_does_not_claim_a_mismatch():
    sc = _sc("x64")
    live = bytes.fromhex("e92b170080") + sc.stub_bytes[5:]
    assert syscall_baseline.classify_stub(sc, live, "x64", "edr.dll")["number_matches"] is None


def test_win32u_numbers_are_checked_against_the_full_number():
    for view in ("arm64", "x64"):
        sc = _sc(view, "NtUserGetForegroundWindow")
        out = syscall_baseline.classify_stub(sc, sc.stub_bytes, view, None)
        assert (out["state"], out["number_matches"]) == ("intact", True)


def test_classify_reports_the_compared_bytes_and_the_owner():
    sc = _sc("arm64")
    live = bytes.fromhex("0500001411223344")
    out = syscall_baseline.classify_stub(sc, live + b"\xff" * 24, "arm64", "edr.dll")
    assert out["expected"] == "410700d4c0035fd6"
    assert out["actual"] == "0500001411223344"
    assert out["target_owner"] == "edr.dll"
    assert set(out) == {"state", "pattern", "target_owner", "expected", "actual", "number_matches"}


@pytest.mark.parametrize("view,head", [("arm64", "0500001400000000"), ("x64", "e92b170080")])
def test_a_jump_into_ntdll_itself_is_neither_hooked_nor_patched(view, head):
    sc = _sc(view)
    live = bytes.fromhex(head) + sc.stub_bytes[len(head) // 2:]
    out = syscall_baseline.classify_stub(sc, live, view, "ntdll.dll")
    assert out["state"] == "diverged"


def test_a_jump_into_the_stubs_own_module_is_diverged():
    sc = _sc("arm64", "NtUserGetForegroundWindow")
    live = bytes.fromhex("05 00 00 14 c0 03 5f d6".replace(" ", ""))
    assert syscall_baseline.classify_stub(sc, live, "arm64", "win32u.dll")["state"] == "diverged"
    assert syscall_baseline.classify_stub(sc, live, "arm64", "edr.dll")["state"] == "hooked"


def _words(*words):
    return b"".join(w.to_bytes(4, "little") for w in words)


def _adrp(rd, pages):
    imm = pages & 0x1FFFFF
    return 0x90000000 | (imm & 3) << 29 | (imm >> 2) << 5 | rd


def _add(rd, rn, imm12, shift12=False):
    return 0x91000000 | shift12 << 22 | imm12 << 10 | rn << 5 | rd


@pytest.mark.parametrize("live_hex,base,target", [
    ("e910000000", 0x1000, 0x1015),
    ("e9f6ffffff", 0x1000, 0xFFB),
    ("48b88877665544332211ffe0", 0x1000, 0x1122334455667788),
    ("49bb8877665544332211" "41ffe3", 0x1000, 0x1122334455667788),
    ("6844332211c3", 0x1000, 0x11223344),
    ("6800000080c3", 0x1000, 0xFFFFFFFF80000000),
])
def test_x64_jump_target_of_hooks_whose_target_is_in_the_bytes(live_hex, base, target):
    live = bytes.fromhex(live_hex) + b"\x90" * 8
    assert syscall_baseline.jump_target(live, base, "x64") == target


def test_x64_relative_results_wrap_at_64_bits_like_the_arm64_ones():
    top = 0xFFFFFFFFFFFFFFF0
    assert syscall_baseline.jump_target(bytes.fromhex("e920000000"), top, "x64") == 0x15
    assert syscall_baseline.jump_pointer(bytes.fromhex("ff2520000000"), top, "x64") == 0x16
    assert syscall_baseline.jump_target(_words(0x14000008), top, "arm64") == 0x10


@pytest.mark.parametrize("live", [
    bytes.fromhex("ff251a4c0300") + b"\x90" * 8,
    bytes.fromhex("4c8bd1b83a000000") + b"\x90" * 8,
    bytes.fromhex("e91000"),
    b"",
])
def test_x64_jump_target_is_none_when_it_is_not_in_the_bytes(live):
    assert syscall_baseline.jump_target(live, 0x1000, "x64") is None


@pytest.mark.parametrize("live,base,target", [
    (_words(0x14000005, 0xD65F03C0), 0x1000, 0x1014),
    (_words(0x17FFFFFF, 0xD65F03C0), 0x1000, 0xFFC),
    (_words(_adrp(16, 2), _add(16, 16, 0x123), 0xD61F0200), 0x50000FF0, 0x50002123),
    (_words(_adrp(16, -1), _add(16, 16, 0x7, shift12=True), 0xD61F0200), 0x50001000, 0x50007000),
])
def test_arm64_jump_target_of_hooks_whose_target_is_in_the_bytes(live, base, target):
    assert syscall_baseline.jump_target(live, base, "arm64") == target


@pytest.mark.parametrize("live", [
    _words(0x58000050, 0xD61F0200),
    _words(0xD4000741, 0xD65F03C0),
    _words(_adrp(16, 2), _add(16, 16, 0x123)),
    _words(_adrp(16, 2), _add(16, 16, 0x123), 0xD61F0220),
    _words(_adrp(16, 2), _add(17, 16, 0x123), 0xD61F0200),
    b"\x05\x00",
])
def test_arm64_jump_target_is_none_when_it_is_not_in_the_bytes(live):
    assert syscall_baseline.jump_target(live, 0x1000, "arm64") is None


def test_the_adrp_chain_needs_its_branch_to_count_as_a_hook():
    sc = _sc("arm64")
    chain = _words(_adrp(16, 2), _add(16, 16, 0x123), 0xD61F0200)
    assert syscall_baseline.classify_stub(sc, chain, "arm64", "edr.dll")["pattern"] == "ADRP; ADD; BR"
    assert syscall_baseline.classify_stub(sc, chain[:8], "arm64", "edr.dll")["pattern"] is None


def test_x86_has_a_prefix_length_but_no_hook_patterns():
    assert syscall_baseline.PREFIX_LEN["x86"] == 16
    assert syscall_baseline.jump_target(bytes.fromhex("e910000000"), 0x1000, "x86") is None


def test_all_zero_bytes_are_unreadable_not_patched():
    out = syscall_baseline.classify_stub(_sc("arm64"), b"\x00" * 8, "arm64", "private")
    assert out["state"] == "unreadable"


def test_no_bytes_at_all_is_unreadable():
    assert syscall_baseline.classify_stub(_sc("arm64"), None, "arm64", None)["state"] == "unreadable"


@pytest.mark.parametrize("view", ["arm64", "x64"])
def test_a_window_shorter_than_the_prefix_is_unreadable(view):
    sc = _sc(view)
    n = syscall_baseline.stub_prefix_len(sc, view)
    out = syscall_baseline.classify_stub(sc, sc.stub_bytes[:n - 1], view, "private")
    assert out["state"] == "unreadable"


def test_zero_bytes_beyond_the_prefix_do_not_make_a_stub_unreadable():
    sc = _sc("arm64")
    out = syscall_baseline.classify_stub(sc, sc.stub_bytes[:8] + b"\x00" * 24, "arm64", None)
    assert out["state"] == "intact"


def test_an_unreadable_stub_carries_no_verdict_details():
    out = syscall_baseline.classify_stub(_sc("arm64"), None, "arm64", "edr.dll")
    assert out["pattern"] is None
    assert out["target_owner"] is None
    assert out["number_matches"] is None
    assert out["actual"] is None
    assert out["expected"] == "410700d4c0035fd6"


def test_read_len_covers_the_longest_arm64_hook_the_prefix_does_not():
    assert syscall_baseline.READ_LEN == {"arm64": 16, "x64": 32, "x86": 16}
    assert syscall_baseline.READ_LEN["arm64"] >= 12 > syscall_baseline.PREFIX_LEN["arm64"]


@pytest.mark.parametrize("view", ["arm64", "x64"])
def test_a_longer_read_than_the_prefix_does_not_make_an_intact_stub_differ(view):
    sc = _sc(view)
    n = syscall_baseline.stub_prefix_len(sc, view)
    live = sc.stub_bytes[:n] + b"\xaa" * (syscall_baseline.READ_LEN[view] - n)
    out = syscall_baseline.classify_stub(sc, live, view, None)
    assert out["state"] == "intact"
    assert out["actual"] == out["expected"]


@pytest.mark.parametrize("live_hex,base,pointer", [
    ("ff25" "10000000", 0x1000, 0x1016),
    ("ff25" "faffffff", 0x1000, 0x1000),
    ("ff25" "00000000", 0x7FF800001000, 0x7FF800001006),
])
def test_x64_jump_pointer_is_the_rip_relative_address(live_hex, base, pointer):
    live = bytes.fromhex(live_hex) + b"\x90" * 8
    assert syscall_baseline.jump_pointer(live, base, "x64") == pointer
    assert syscall_baseline.jump_target(live, base, "x64") is None


@pytest.mark.parametrize("live,base,pointer", [
    (_words(0x58000050, 0xD61F0200), 0x1000, 0x1008),
    (_words(0x58FFFFF0, 0xD61F0200), 0x1000, 0xFFC),
])
def test_arm64_jump_pointer_is_the_literal_address(live, base, pointer):
    assert syscall_baseline.jump_pointer(live, base, "arm64") == pointer
    assert syscall_baseline.jump_target(live, base, "arm64") is None


@pytest.mark.parametrize("view,live", [
    ("x64", bytes.fromhex("e910000000") + b"\x90" * 8),
    ("x64", bytes.fromhex("48b88877665544332211ffe0")),
    ("x64", bytes.fromhex("4c8bd1b83a000000") + b"\x90" * 8),
    ("x64", bytes.fromhex("ff2510")),
    ("x64", b""),
    ("arm64", _words(0x14000005, 0xD65F03C0)),
    ("arm64", _words(0xD4000741, 0xD65F03C0)),
    ("arm64", _words(_adrp(16, 2), _add(16, 16, 0x123), 0xD61F0200)),
    ("arm64", _words(0x58000050, 0xD61F0220)),
    ("arm64", _words(0x58000051, 0xD61F0200)),
    ("arm64", _words(0x58000050)),
    ("arm64", b"\x05\x00"),
    ("x86", bytes.fromhex("ff2510000000")),
])
def test_jump_pointer_is_none_unless_the_hook_reads_its_target_from_memory(view, live):
    assert syscall_baseline.jump_pointer(live, 0x1000, view) is None


def test_the_indirect_hooks_are_named_by_classify():
    sc = _sc("x64")
    live = bytes.fromhex("ff251a4c0300") + sc.stub_bytes[6:]
    assert syscall_baseline.classify_stub(sc, live, "x64", "edr.dll")["state"] == "hooked"
    sc = _sc("arm64")
    live = _words(0x58000050, 0xD61F0200)
    out = syscall_baseline.classify_stub(sc, live, "arm64", "edr.dll")
    assert (out["state"], out["pattern"]) == ("hooked", "LDR x16; BR x16")


# --- measuring a process (syscall_scan) ---------------------------------------------------

_DEVICE = "\\Device\\HarddiskVolume3\\Windows\\System32\\"
_MODULE_BASES = {"ntdll.dll": 0x7FF810000000, "win32u.dll": 0x7FF820000000}
_IMAGE = syscall_scan.Region(syscall_scan.MEM_COMMIT, syscall_scan.MEM_IMAGE, None)
_PRIVATE = syscall_scan.Region(syscall_scan.MEM_COMMIT, syscall_scan.MEM_PRIVATE, None)


@pytest.fixture
def arm64_baseline():
    return syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64")


@pytest.fixture
def x64_baseline():
    return syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64")


@pytest.fixture
def gui_baseline(x64_baseline):
    # both fixtures carry a win32u stub; the x64 one keeps the other view measured too
    return x64_baseline


class FakeReader(syscall_scan.ProcessReader):
    """A process as a few byte ranges and memory regions.

    A read succeeds only when one range holds all of it, as ReadProcessMemory fails a
    partial copy. Regions are found by containment, the first that holds an address
    winning, as VirtualQueryEx answers for the region around an address."""

    def __init__(self, mods, ranges, regions=(), view="arm64", build="26220.5770", cut=None):
        self._m, self._ranges, self._regions = mods, ranges, list(regions)
        self._view, self._build, self._cut = view, build, cut
        self.reads = 0
        self.region_queries = 0

    def view(self):
        return self._view

    def build(self):
        return self._build

    def modules(self):
        return self._m

    def read(self, addr, size):
        self.reads += 1
        if self._cut is not None and addr + size > self._cut:
            return None
        for start, data in self._ranges:
            if start <= addr and addr + size <= start + len(data):
                return bytes(data[addr - start:addr - start + size])
        return None

    def region(self, addr):
        self.region_queries += 1
        for start, size, region in self._regions:
            if start <= addr < start + size:
                return region
        return None


def _owner_region(owner):
    if owner == "private":
        return _PRIVATE
    return _IMAGE._replace(path=_DEVICE + owner.upper())


def _reader_from(baseline, patched, drop=None, build=None, fail_after=None, view=None):
    """A process whose modules hold the baseline's stubs at their RVAs.

    `patched` maps a name to `(hex, owner)`: those bytes replace the stub, and the
    address its jump goes to belongs to `owner`. `fail_after=n`: memory past the first
    n stubs is gone, as when the process exits while the scan reads it."""
    view = view or baseline.view
    mods, ranges, regions = [], [], []
    for name, base in _MODULE_BASES.items():
        stubs = [sc for sc in baseline.syscalls.values() if sc.module == name]
        if not stubs or name == drop:
            continue
        image = bytearray(max(sc.rva for sc in stubs) + 0x1000)
        for sc in stubs:
            image[sc.rva:sc.rva + len(sc.stub_bytes)] = sc.stub_bytes
        mods.append({"name": name, "base": base, "size": len(image), "path": _DEVICE + name})
        ranges.append((base, image))
        regions.append((base, len(image), _IMAGE._replace(path=_DEVICE + name)))
    for name, (live_hex, owner) in patched.items():
        sc = baseline.syscalls[name]
        live = bytes.fromhex(live_hex)
        image = dict(ranges)[_MODULE_BASES[sc.module]]
        image[sc.rva:sc.rva + len(live)] = live
        target = syscall_baseline.jump_target(live, _MODULE_BASES[sc.module] + sc.rva, view)
        if owner is not None and target is not None:
            regions.insert(0, (target, 4, _owner_region(owner)))
    cut = None
    if fail_after is not None:
        addrs = sorted(_MODULE_BASES[sc.module] + sc.rva for sc in baseline.syscalls.values())
        cut = addrs[fail_after - 1] + syscall_baseline.READ_LEN[view]
    return FakeReader(mods, ranges, regions, view=view, build=build or baseline.build, cut=cut)


def test_measure_reports_intact_for_untouched_stubs(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={})
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["counts"]["intact"] == len(out["states"])
    assert out["deviations"] == []
    assert out["view"] == "arm64"


def test_measure_lists_a_patched_stub_with_its_owner(arm64_baseline):
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", "private")})
    out = syscall_scan.measure(arm64_baseline, reader)
    dev = [d for d in out["deviations"] if d["name"] == "NtWriteVirtualMemory"]
    assert dev and dev[0]["state"] == "patched"
    assert dev[0]["target_owner"] == "private"
    assert out["counts"]["patched"] == 1


def test_read_spans_batches_adjacent_stubs(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={})
    syscall_scan.measure(arm64_baseline, reader)
    assert reader.reads < len(arm64_baseline.syscalls)
    # the three ntdll stubs lie within a few hundred bytes of each other
    assert reader.reads == 1


def _flat_reader(*ranges):
    return FakeReader([], [(start, bytearray(data)) for start, data in ranges])


def test_read_spans_hands_each_item_its_own_bytes():
    reader = _flat_reader((0x1000, bytes(range(256))))
    out = syscall_scan.read_spans(reader, [("b", 0x1040), ("a", 0x1010)], lambda key: 4)
    assert out == {"a": bytes([0x10, 0x11, 0x12, 0x13]), "b": bytes([0x40, 0x41, 0x42, 0x43])}
    assert reader.reads == 1


def test_a_failed_span_is_retried_item_by_item():
    # the gap between the two ranges is not mapped, so the span across it fails
    reader = _flat_reader((0x1000, b"\x11" * 16), (0x1100, b"\x22" * 16))
    out = syscall_scan.read_spans(reader, [("a", 0x1000), ("b", 0x1100), ("c", 0x1200)],
                                  lambda key: 8)
    assert out == {"a": b"\x11" * 8, "b": b"\x22" * 8, "c": None}


def test_stubs_far_apart_are_not_read_as_one_span():
    reader = _flat_reader((0x1000, b"\x11" * 8), (0x1000 + 0x100000, b"\x22" * 8))
    out = syscall_scan.read_spans(reader, [("a", 0x1000), ("b", 0x101000)], lambda key: 8)
    assert out == {"a": b"\x11" * 8, "b": b"\x22" * 8}
    assert reader.reads == 2


def test_a_span_is_capped_in_size():
    step = 0x800
    reader = _flat_reader((0x1000, bytes(step * 64)))
    items = [(str(i), 0x1000 + i * step) for i in range(64)]
    out = syscall_scan.read_spans(reader, items, lambda key: 8)
    assert len(out) == 64
    assert 1 < reader.reads < 64


def test_read_spans_never_takes_a_short_read_for_bytes():
    class Short(FakeReader):
        def read(self, addr, size):
            data = super().read(addr, size)
            return data[:-1] if data else data
    reader = Short([], [(0x1000, bytearray(b"\x11" * 64))])
    assert syscall_scan.read_spans(reader, [("a", 0x1000)], lambda key: 8) == {"a": None}


def test_win32u_is_only_measured_when_asked(gui_baseline):
    reader = _reader_from(gui_baseline, patched={})
    assert all(s["module"] == "ntdll.dll" for s in
               syscall_scan.measure(gui_baseline, reader)["states"].values())
    both = syscall_scan.measure(gui_baseline, reader,
                                modules=("ntdll.dll", "win32u.dll"))
    assert any(s["module"] == "win32u.dll" for s in both["states"].values())


def test_a_module_the_process_never_loaded_is_noted_not_fatal(gui_baseline):
    reader = _reader_from(gui_baseline, patched={}, drop="win32u.dll")
    out = syscall_scan.measure(gui_baseline, reader,
                               modules=("ntdll.dll", "win32u.dll"))
    assert "win32u.dll" in out["note"]
    assert out["counts"]["intact"] > 0


def test_module_names_match_regardless_of_case(gui_baseline):
    reader = _reader_from(gui_baseline, patched={})
    for mod in reader.modules():
        mod["name"] = mod["name"].upper()
    out = syscall_scan.measure(gui_baseline, reader, modules=("NTDLL.DLL", "Win32u.dll"))
    assert {s["module"] for s in out["states"].values()} == {"ntdll.dll", "win32u.dll"}
    assert out["note"] == ""


def test_a_module_loaded_twice_is_noted_and_not_guessed(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={})
    ntdll = dict(reader.modules()[0], base=0x10000, path="\\Device\\X\\SysWOW64\\ntdll.dll")
    reader.modules().append(ntdll)
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["states"] == {}
    assert "ntdll.dll" in out["note"]
    assert out["partial"] is True


def test_a_process_without_ntdll_is_partial_never_clean(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={}, drop="ntdll.dll")
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["states"] == {} and out["deviations"] == []
    assert out["partial"] is True
    assert "ntdll.dll" in out["note"]


def test_measure_refuses_a_baseline_of_another_view(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={})
    with pytest.raises(syscall_scan.ScanRefused) as e:
        syscall_scan.measure(arm64_baseline, reader, view="x64")
    assert "view" in e.value.reason


def test_measure_refuses_a_baseline_of_another_build(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={}, build="26100.1")
    with pytest.raises(syscall_scan.ScanRefused) as e:
        syscall_scan.measure(arm64_baseline, reader)
    assert "build" in e.value.reason


@pytest.mark.parametrize("kwargs", [{"view": "x64"}, {"build": "26100.1"}])
def test_a_refused_scan_reads_nothing(arm64_baseline, kwargs):
    reader = _reader_from(arm64_baseline, patched={})
    with pytest.raises(syscall_scan.ScanRefused):
        syscall_scan.measure(arm64_baseline, reader, **kwargs)
    assert reader.reads == 0


def test_the_view_the_reader_reports_is_checked_too(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={}, view="x64")
    with pytest.raises(syscall_scan.ScanRefused, match="view"):
        syscall_scan.measure(arm64_baseline, reader)


@pytest.mark.parametrize("field", ["view", "build"])
def test_a_process_of_unknown_view_or_build_is_refused(arm64_baseline, field):
    reader = _reader_from(arm64_baseline, patched={})
    setattr(reader, "_" + field, None)
    with pytest.raises(syscall_scan.ScanRefused, match=field):
        syscall_scan.measure(arm64_baseline, reader)


def test_a_process_that_vanishes_midway_yields_a_partial_result(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={}, fail_after=2)
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["partial"] is True
    assert out["read_errors"] > 0
    assert out["counts"]["intact"] >= 1
    assert out["counts"]["patched"] == 0


def test_the_note_says_how_many_stubs_could_not_be_read(arm64_baseline):
    out = syscall_scan.measure(arm64_baseline, _reader_from(arm64_baseline, patched={}, fail_after=2))
    assert out["read_errors"] == 1 and out["counts"]["unreadable"] == 1
    assert "1 stub" in out["note"] and "partial" in out["note"]


def test_a_complete_scan_is_not_partial(arm64_baseline):
    out = syscall_scan.measure(arm64_baseline, _reader_from(arm64_baseline, patched={}))
    assert (out["partial"], out["read_errors"], out["note"]) == (False, 0, "")


@pytest.mark.parametrize("region, owner", [
    (_IMAGE._replace(path="\\Device\\HarddiskVolume3\\Windows\\System32\\NTDLL.DLL"), "ntdll.dll"),
    (_IMAGE._replace(path="\\Device\\HarddiskVolume3\\Program Files\\Edr\\EdrHook.dll"), "edrhook.dll"),
    (_PRIVATE, "private"),
    (_IMAGE, None),
    (_IMAGE._replace(path=""), None),
    (_IMAGE._replace(path="\\Device\\HarddiskVolume3\\"), None),
    (syscall_scan.Region(syscall_scan.MEM_COMMIT, syscall_scan.MEM_MAPPED, "\\Device\\X\\a.dat"), None),
    (_PRIVATE._replace(state=0x2000), None),
    (None, None),
])
def test_the_owner_is_a_lower_case_basename_private_or_none(region, owner):
    assert syscall_scan.owner_from_region(region) == owner


def test_a_jump_back_into_ntdll_named_by_its_device_path_is_diverged(arm64_baseline):
    # the target region names ntdll the way GetMappedFileNameW does, upper-case at that
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", "ntdll.dll")})
    s = syscall_scan.measure(arm64_baseline, reader)["states"]["NtWriteVirtualMemory"]
    assert (s["state"], s["target_owner"]) == ("diverged", "ntdll.dll")


def test_a_jump_into_ntdlls_own_image_is_diverged(arm64_baseline):
    # no region of its own: the target lies in the ntdll image the module list maps
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", None)})
    s = syscall_scan.measure(arm64_baseline, reader)["states"]["NtWriteVirtualMemory"]
    assert (s["state"], s["target_owner"]) == ("diverged", "ntdll.dll")


def test_a_jump_into_another_module_is_hooked(arm64_baseline):
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", "edr.dll")})
    s = syscall_scan.measure(arm64_baseline, reader)["states"]["NtWriteVirtualMemory"]
    assert (s["state"], s["target_owner"], s["pattern"]) == ("hooked", "edr.dll", "B")


_EDR_TARGET = 0x7FFA00001230


def _with_edr_at_target(reader):
    reader._regions.insert(0, (_EDR_TARGET & ~0xFFF, 0x1000, _owner_region("edrhook.dll")))
    return reader


def test_an_x64_jmp_rip_hook_is_followed_through_its_pointer(x64_baseline):
    sc = x64_baseline.syscalls["NtWriteVirtualMemory"]
    stub = _MODULE_BASES["ntdll.dll"] + sc.rva
    pointer = 0x7FF830000000
    disp = (pointer - (stub + 6)) & 0xFFFFFFFF
    assert disp < 0x80000000
    reader = _reader_from(x64_baseline, patched={
        "NtWriteVirtualMemory": ("ff25" + disp.to_bytes(4, "little").hex(), None)})
    reader._ranges.append((pointer, bytearray(_EDR_TARGET.to_bytes(8, "little"))))
    s = syscall_scan.measure(x64_baseline, _with_edr_at_target(reader))["states"]["NtWriteVirtualMemory"]
    assert (s["state"], s["pattern"], s["target_owner"]) == ("hooked", "JMP [rip]", "edrhook.dll")


def test_an_unreadable_pointer_leaves_the_owner_unresolved(x64_baseline):
    reader = _reader_from(x64_baseline, patched={"NtWriteVirtualMemory": ("ff2500001000", None)})
    s = syscall_scan.measure(x64_baseline, _with_edr_at_target(reader))["states"]["NtWriteVirtualMemory"]
    assert (s["state"], s["target_owner"]) == ("diverged", None)


def test_an_arm64_ldr_br_hook_is_followed_through_its_literal(arm64_baseline):
    live = _words(0x58000050, 0xD61F0200) + _EDR_TARGET.to_bytes(8, "little")
    reader = _reader_from(arm64_baseline, patched={"NtWriteVirtualMemory": (live.hex(), None)})
    s = syscall_scan.measure(arm64_baseline, _with_edr_at_target(reader))["states"]["NtWriteVirtualMemory"]
    assert (s["state"], s["pattern"], s["target_owner"]) == ("hooked", "LDR x16; BR x16", "edrhook.dll")


def test_the_owner_is_only_asked_for_a_stub_that_differs(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={})
    syscall_scan.measure(arm64_baseline, reader)
    assert reader.region_queries == 0
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", "private")})
    syscall_scan.measure(arm64_baseline, reader)
    assert reader.region_queries == 1


def test_a_state_names_its_syscall(arm64_baseline):
    out = syscall_scan.measure(arm64_baseline, _reader_from(arm64_baseline, patched={}))
    s = out["states"]["NtWriteVirtualMemory"]
    assert (s["name"], s["module"], s["number"], s["rva"]) == ("NtWriteVirtualMemory", "ntdll.dll", 0x3A, 652224)
    assert set(s) == {"state", "pattern", "target_owner", "expected", "actual", "number_matches",
                      "name", "module", "number", "rva"}


def test_counts_name_all_five_states(arm64_baseline):
    out = syscall_scan.measure(arm64_baseline, _reader_from(arm64_baseline, patched={}))
    assert out["counts"] == {"intact": 3, "hooked": 0, "patched": 0, "diverged": 0, "unreadable": 0}


def test_an_intact_stub_shaped_like_a_jump_costs_no_owner_lookup(x64_baseline):
    # a clean stub that itself begins with a jump still matches the baseline
    sc = x64_baseline.syscalls["NtWriteVirtualMemory"]
    sc.stub_bytes = bytes.fromhex("e910000000") + sc.stub_bytes[5:]
    reader = _reader_from(x64_baseline, patched={})
    out = syscall_scan.measure(x64_baseline, reader)
    assert out["states"]["NtWriteVirtualMemory"]["state"] == "intact"
    assert reader.region_queries == 0


def test_a_lone_unreadable_stub_costs_one_read():
    reader = _flat_reader()
    assert syscall_scan.read_spans(reader, [("a", 0x1000)], lambda key: 8) == {"a": None}
    assert reader.reads == 1


def test_the_win32_structures_have_the_64_bit_windows_layout():
    import ctypes
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip("the layout checked is the 64-bit one")
    mbi = syscall_scan.MEMORY_BASIC_INFORMATION
    assert ctypes.sizeof(mbi) == 48
    assert (mbi.RegionSize.offset, mbi.State.offset, mbi.Protect.offset, mbi.Type.offset) == (24, 32, 36, 40)
    mi = syscall_scan.MODULEINFO
    assert ctypes.sizeof(mi) == 24
    assert (mi.SizeOfImage.offset, mi.EntryPoint.offset) == (8, 16)


def test_the_scan_opens_the_process_for_reading_only():
    query, limited, vm_read = 0x0400, 0x1000, 0x0010
    assert syscall_scan.PROCESS_ACCESS == (query | vm_read, limited | vm_read)
    for mask in syscall_scan.PROCESS_ACCESS:
        assert mask & ~(query | limited | vm_read) == 0, hex(mask)
    with open(syscall_scan.__file__, encoding="utf-8") as fh:
        source = fh.read()
    for call in ("WriteProcessMemory", "VirtualProtectEx", "VirtualAllocEx", "DebugActiveProcess",
                 "DebugSetProcessKillOnExit", "CreateRemoteThread", "OpenThread", "SuspendThread",
                 "SetThreadContext", "NtSuspendProcess", "PROCESS_VM_WRITE", "PROCESS_VM_OPERATION",
                 "PROCESS_CREATE_THREAD", "PROCESS_SUSPEND_RESUME", "PROCESS_ALL_ACCESS",
                 "THREAD_"):
        assert call not in source, call


def test_the_win32_reader_is_only_built_on_windows():
    if os.name == "nt":
        pytest.skip("on Windows it opens a real process")
    with pytest.raises(OSError):
        syscall_scan.Win32Reader(os.getpid(), "x64", "1.0")


def test_a_zeroed_stub_makes_the_result_partial(arm64_baseline):
    # the read succeeds, but image pages are paged in on read: zeros there were written
    reader = _reader_from(arm64_baseline, patched={"NtWriteVirtualMemory": ("00" * 16, None)})
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["states"]["NtWriteVirtualMemory"]["state"] == "unreadable"
    assert out["read_errors"] == 0
    assert out["partial"] is True
    assert "1 stub" in out["note"] and "unreadable" in out["note"]


def test_a_failed_owner_lookup_is_counted_and_makes_the_result_partial(arm64_baseline):
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", "private")})
    reader._regions = []
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["states"]["NtWriteVirtualMemory"]["state"] == "diverged"
    assert out["owner_errors"] == 1
    assert out["partial"] is True
    assert "owner" in out["note"]


def test_an_unreadable_pointer_is_a_failed_owner_lookup(x64_baseline):
    reader = _reader_from(x64_baseline, patched={"NtWriteVirtualMemory": ("ff2500001000", None)})
    out = syscall_scan.measure(x64_baseline, reader)
    assert out["owner_errors"] == 1 and out["partial"] is True


def test_changed_bytes_without_a_jump_are_no_failed_lookup(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={"NtWriteVirtualMemory": ("1122334455667788", None)})
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["states"]["NtWriteVirtualMemory"]["state"] == "diverged"
    assert (out["owner_errors"], out["partial"], out["note"]) == (0, False, "")


def test_a_resolved_owner_is_no_failed_lookup(arm64_baseline):
    reader = _reader_from(arm64_baseline,
                          patched={"NtWriteVirtualMemory": ("0500001400000000", "edr.dll")})
    out = syscall_scan.measure(arm64_baseline, reader)
    assert (out["owner_errors"], out["partial"]) == (0, False)


def test_a_module_list_that_cannot_be_read_is_not_called_missing(arm64_baseline):
    reader = _reader_from(arm64_baseline, patched={})
    reader._m = None
    out = syscall_scan.measure(arm64_baseline, reader)
    assert out["states"] == {} and out["partial"] is True
    assert "could not be listed" in out["note"]
    assert "not loaded" not in out["note"]


# --- the hook allowlist -------------------------------------------------------------------

def _result_with(state="hooked", syscall="NtProtectVirtualMemory", owner="edr.dll",
                 process=None, build="26220.5770", view="arm64", **extra):
    """The slice of a `measure` result the allowlist reads, for one deviating stub."""
    entry = dict(name=syscall, module="ntdll.dll", state=state, target_owner=owner, **extra)
    if process is not None:
        # a scan result does not name its process; the list must not care if one did
        entry["process"] = process
    return {"build": build, "view": view, "states": {syscall: entry}, "deviations": [entry]}


_PAIR = ("26220.5770", "arm64")


def _e(syscall, owner, build=_PAIR[0], view=_PAIR[1]):
    return {"syscall": syscall, "owner": owner, "build": build, "view": view}


def _file(path, sets, version=1):
    path.write_text(json.dumps({"version": version, "sets": sets}))


def _allowlist(tmp_path, name="hooks.json"):
    return syscall_scan.HookAllowlist(str(tmp_path / name))


def _hooked_reader(baseline, owner="edr.dll"):
    return _reader_from(baseline,
                        patched={"NtProtectVirtualMemory": ("0500001400000000", owner)})


def _protect(out):
    return out["states"]["NtProtectVirtualMemory"]


def test_allowlist_marks_a_known_hook_without_hiding_it(arm64_baseline, tmp_path):
    reader = _hooked_reader(arm64_baseline)
    al = _allowlist(tmp_path)
    first = syscall_scan.measure(arm64_baseline, reader, allowlist=al)
    assert al.add_from(first) == 1
    second = syscall_scan.measure(arm64_baseline, reader, allowlist=al)
    dev = [d for d in second["deviations"] if d["name"] == "NtProtectVirtualMemory"]
    assert dev and dev[0]["state"] == "hooked"
    assert dev[0]["allowlisted"] is True
    assert second["counts"] == first["counts"]
    assert second["counts"]["hooked"] == 1


def test_a_hook_is_not_allowlisted_before_the_list_knows_it(arm64_baseline, tmp_path):
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline),
                               allowlist=_allowlist(tmp_path))
    assert _protect(out)["allowlisted"] is False


def test_every_state_dict_carries_the_flag_once_a_list_is_given(arm64_baseline, tmp_path):
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline),
                               allowlist=_allowlist(tmp_path))
    assert all(s["allowlisted"] is False for s in out["states"].values())


def test_allowlist_is_independent_of_the_process(tmp_path):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with(process="explorer.exe")) == 1
    assert al.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is True
    # the same hook seen in another process is the same entry
    assert al.add_from(_result_with(process="sample.exe")) == 0
    assert al.entries() == [_e("NtProtectVirtualMemory", "edr.dll")]


def test_a_hook_recorded_for_one_syscall_does_not_cover_another(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    assert al.knows("NtWriteVirtualMemory", "edr.dll", *_PAIR) is False
    assert al.knows("NtProtectVirtualMemory", "other.dll", *_PAIR) is False


def test_the_owner_is_matched_by_its_lower_case_basename(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with(owner="EDR.dll"))
    assert al.knows("NtProtectVirtualMemory", "edr.DLL", *_PAIR) is True


def test_allowlist_never_covers_a_patched_stub(tmp_path):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with(state="patched", owner="private")) == 0
    assert al.entries() == []


@pytest.mark.parametrize("state, owner", [
    ("patched", "edr.dll"),
    ("patched", "private"),
    ("diverged", "edr.dll"),
    ("diverged", None),
    ("unreadable", None),
    ("intact", None),
    ("hooked", "private"),
    ("hooked", None),
    ("hooked", ""),
])
def test_only_a_hook_owned_by_a_module_enters_the_list(tmp_path, state, owner):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with(state=state, owner=owner)) == 0
    assert al.entries() == []


def test_a_patched_stub_is_not_marked_even_if_the_list_names_its_pair(arm64_baseline, tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with(owner="edr.dll"))
    reader = _hooked_reader(arm64_baseline, owner="private")
    out = syscall_scan.measure(arm64_baseline, reader, allowlist=al)
    assert _protect(out)["state"] == "patched"
    assert _protect(out)["allowlisted"] is False


def test_add_from_reads_the_deviations_not_a_rescan(tmp_path):
    al = _allowlist(tmp_path)
    result = _result_with()
    result["states"] = {}
    assert al.add_from(result) == 1


def test_add_from_takes_several_hooks_and_skips_the_rest(tmp_path):
    al = _allowlist(tmp_path)
    result = _result_with()
    for name, state, owner in (("NtClose", "hooked", "edr.dll"), ("NtOpenFile", "patched", "private"),
                               ("NtCreateFile", "hooked", "av.dll")):
        result["deviations"].append(dict(name=name, state=state, target_owner=owner))
    assert al.add_from(result) == 3
    assert [(e["syscall"], e["owner"]) for e in al.entries()] == [
        ("NtClose", "edr.dll"), ("NtCreateFile", "av.dll"), ("NtProtectVirtualMemory", "edr.dll")]


def test_entries_come_back_in_a_stable_order(tmp_path):
    al = _allowlist(tmp_path)
    for name in ("NtZ", "NtA", "NtM"):
        al.add_from(_result_with(syscall=name))
    al.add_from(_result_with(syscall="NtA", owner="aa.dll"))
    first = al.entries()
    assert first == sorted(first, key=lambda e: (e["syscall"], e["owner"]))
    assert al.entries() == first


def test_entries_are_copies(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    al.entries()[0]["owner"] = "evil.dll"
    al.entries().clear()
    assert al.entries() == [_e("NtProtectVirtualMemory", "edr.dll")]


@pytest.mark.parametrize("build, view", [
    ("", "arm64"), ("26220.5770", None), (None, "arm64"), ("26220.5770", ""), (None, None),
])
def test_a_result_without_build_and_view_cannot_be_recorded(tmp_path, build, view):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with(build=build, view=view)) == 0
    assert al.entries() == []


def test_the_list_survives_a_restart(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    again = _allowlist(tmp_path)
    assert again.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is True
    assert again.entries() == al.entries()


def test_the_file_has_the_documented_format(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    al.add_from(_result_with(view="x64", syscall="NtClose", owner="av.dll"))
    with open(al.path) as f:
        assert json.load(f) == {"version": 1, "sets": {
            "26220.5770|arm64": [{"syscall": "NtProtectVirtualMemory", "owner": "edr.dll"}],
            "26220.5770|x64": [{"syscall": "NtClose", "owner": "av.dll"}]}}
    assert syscall_scan.KEY_VERSION == 1


def test_clear_empties_the_list_and_the_file(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    al.clear()
    assert al.entries() == [] and al.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is False
    assert _allowlist(tmp_path).entries() == []


def test_a_missing_file_is_an_empty_list(tmp_path):
    al = _allowlist(tmp_path, "sub/never.json")
    assert al.entries() == [] and al.problem is None


def test_save_creates_the_directory(tmp_path):
    al = _allowlist(tmp_path, "sub/hooks.json")
    al.add_from(_result_with())
    assert os.path.isfile(al.path)


def test_load_picks_up_what_another_writer_saved(tmp_path):
    a, b = _allowlist(tmp_path), _allowlist(tmp_path)
    a.add_from(_result_with())
    assert b.entries() == []
    b.load()
    assert b.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is True


def test_a_save_leaves_no_temp_file_behind(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    assert os.listdir(tmp_path) == ["hooks.json"]


def test_a_failed_swap_keeps_the_old_file_and_the_old_list(tmp_path, monkeypatch):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    before = open(al.path).read()

    def refuse(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(syscall_scan.os, "replace", refuse)
    with pytest.raises(OSError):
        al.add_from(_result_with(syscall="NtClose"))
    monkeypatch.undo()
    assert open(al.path).read() == before
    assert al.knows("NtClose", "edr.dll", *_PAIR) is False
    assert os.listdir(tmp_path) == ["hooks.json"]


def test_a_failed_clear_keeps_the_list(tmp_path, monkeypatch):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())

    def refuse(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(syscall_scan.os, "replace", refuse)
    with pytest.raises(OSError):
        al.clear()
    assert al.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is True


@pytest.mark.parametrize("text", ["{not json", "[]", '"x"', "7", "",
                                  '{"version": 1}', '{"version": 1, "sets": []}',
                                  '{"version": 1, "sets": null}',
                                  # the layout of one pair for the whole file, as it once was
                                  '{"version": 1, "build": "b", "view": "arm64", "entries": []}'])
def test_a_corrupt_file_is_kept_aside_and_reported(tmp_path, text):
    path = tmp_path / "hooks.json"
    path.write_text(text)
    al = syscall_scan.HookAllowlist(str(path))
    assert al.entries() == []
    assert al.problem and "hooks.json" in al.problem
    assert (tmp_path / "hooks.json.corrupt").read_text() == text
    assert not path.exists()


def test_a_file_of_another_version_is_ignored_and_reported_but_not_destroyed(tmp_path):
    path = tmp_path / "hooks.json"
    _file(path, {"26220.5770|arm64": [{"syscall": "NtClose", "owner": "edr.dll"}]}, version=2)
    text = path.read_text()
    al = syscall_scan.HookAllowlist(str(path))
    assert al.knows("NtClose", "edr.dll", *_PAIR) is False
    assert "version" in al.problem
    assert path.read_text() == text


def test_malformed_entries_are_skipped_not_applied(tmp_path):
    path = tmp_path / "hooks.json"
    _file(path, {"26220.5770|arm64": [
        {"syscall": "NtClose", "owner": "edr.dll"}, {"syscall": "NtOpenFile"},
        {"syscall": 3, "owner": "x.dll"}, "x", None,
        {"syscall": "NtCreateFile", "owner": "private"}, {"syscall": "", "owner": "x.dll"},
        {"syscall": "NtRead", "owner": ""}]})
    al = syscall_scan.HookAllowlist(str(path))
    assert al.entries() == [_e("NtClose", "edr.dll")]


@pytest.mark.parametrize("key", ["", "26220.5770", "|arm64", "26220.5770|", "|"])
def test_a_set_under_a_malformed_key_is_skipped(tmp_path, key):
    path = tmp_path / "hooks.json"
    _file(path, {key: [{"syscall": "NtClose", "owner": "edr.dll"}],
                 "26220.5770|arm64": [{"syscall": "NtOpenFile", "owner": "av.dll"}]})
    al = syscall_scan.HookAllowlist(str(path))
    assert al.entries() == [_e("NtOpenFile", "av.dll")]


def test_a_set_that_is_not_a_list_is_skipped(tmp_path):
    path = tmp_path / "hooks.json"
    _file(path, {"26220.5770|arm64": {"syscall": "NtClose", "owner": "edr.dll"},
                 "26220.5770|x64": [{"syscall": "NtOpenFile", "owner": "av.dll"}]})
    al = syscall_scan.HookAllowlist(str(path))
    assert al.entries() == [_e("NtOpenFile", "av.dll", view="x64")]


def test_a_list_without_a_set_for_this_build_is_refused_and_says_so(arm64_baseline, tmp_path):
    reader = _hooked_reader(arm64_baseline)
    al = _allowlist(tmp_path)
    al.add_from(_result_with(build="26100.1"))
    out = syscall_scan.measure(arm64_baseline, reader, allowlist=al)
    assert _protect(out)["state"] == "hooked"
    assert _protect(out)["allowlisted"] is False
    assert out["allowlist"]["applied"] is False
    assert out["allowlist"]["entries"] == 0
    assert "26220.5770" in out["allowlist"]["reason"] and "26100.1" in out["allowlist"]["reason"]
    assert out["allowlist"]["reason"] in out["note"]
    assert out["partial"] is False


def test_a_list_without_a_set_for_this_view_is_refused_and_says_so(arm64_baseline, tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with(view="x64"))
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline), allowlist=al)
    assert _protect(out)["allowlisted"] is False
    assert out["allowlist"]["applied"] is False
    assert "arm64" in out["allowlist"]["reason"] and "x64" in out["allowlist"]["reason"]


def test_a_list_that_matches_is_reported_as_applied(arm64_baseline, tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline), allowlist=al)
    assert out["allowlist"] == {"applied": True, "entries": 1, "reason": ""}
    assert "allowlist" not in out["note"]


def test_an_empty_list_has_nothing_to_refuse(arm64_baseline, tmp_path):
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline),
                               allowlist=_allowlist(tmp_path))
    assert out["allowlist"] == {"applied": True, "entries": 0, "reason": ""}
    assert out["note"] == ""


def test_a_scan_without_a_list_carries_no_flag(arm64_baseline):
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline))
    assert out["allowlist"] is None
    assert "allowlisted" not in _protect(out)


def test_a_list_that_could_not_be_loaded_is_not_applied_and_says_so(arm64_baseline, tmp_path):
    (tmp_path / "hooks.json").write_text("{broken")
    al = _allowlist(tmp_path)
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline), allowlist=al)
    assert out["allowlist"]["applied"] is False
    assert out["allowlist"]["reason"] == al.problem
    assert out["allowlist"]["reason"] in out["note"]


def test_recording_another_pair_leaves_the_sets_of_the_others_alone(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with(build="26100.1", syscall="NtClose"))
    assert al.add_from(_result_with()) == 1
    assert al.entries("26100.1", "arm64") == [_e("NtClose", "edr.dll", build="26100.1")]
    assert al.entries(*_PAIR) == [_e("NtProtectVirtualMemory", "edr.dll")]
    assert len(al.entries()) == 2
    assert _allowlist(tmp_path).entries() == al.entries()


def test_the_flagged_deviation_is_the_entry_of_the_state_map(arm64_baseline, tmp_path):
    al = _allowlist(tmp_path)
    reader = _hooked_reader(arm64_baseline)
    al.add_from(syscall_scan.measure(arm64_baseline, reader))
    out = syscall_scan.measure(arm64_baseline, reader, allowlist=al)
    assert [d["name"] for d in out["deviations"]] == ["NtProtectVirtualMemory"]
    assert out["deviations"][0] is out["states"]["NtProtectVirtualMemory"]


def test_a_result_without_hooks_changes_no_set(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with(build="26100.1"))
    assert al.add_from(_result_with(state="intact", owner=None)) == 0
    assert al.knows("NtProtectVirtualMemory", "edr.dll", "26100.1", "arm64") is True
    assert len(al.entries()) == 1


def test_only_a_hooked_stub_is_marked_even_if_a_file_names_its_pair(arm64_baseline, tmp_path):
    path = tmp_path / "hooks.json"
    _file(path, {"26220.5770|arm64": [{"syscall": "NtProtectVirtualMemory",
                                       "owner": "ntdll.dll"}]})
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline, owner="ntdll.dll"),
                               allowlist=syscall_scan.HookAllowlist(str(path)))
    assert _protect(out)["state"] == "diverged"
    assert _protect(out)["allowlisted"] is False


# one build, two views: the EDR hooks the native ARM64 ntdll and the emulated x64 one, and
# recording the clean host for one view must not cost the other its list

_X64 = (_PAIR[0], "x64")


def _both_views(tmp_path):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with()) == 1
    assert al.add_from(_result_with(view="x64", syscall="NtWriteVirtualMemory")) == 1
    return al


def test_recording_a_second_view_keeps_the_first(tmp_path):
    al = _both_views(tmp_path)
    assert al.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is True
    assert al.knows("NtWriteVirtualMemory", "edr.dll", *_X64) is True
    again = _allowlist(tmp_path)
    assert again.knows("NtProtectVirtualMemory", "edr.dll", *_PAIR) is True
    assert again.knows("NtWriteVirtualMemory", "edr.dll", *_X64) is True


def test_a_hook_of_one_view_is_not_known_for_the_other(tmp_path):
    al = _both_views(tmp_path)
    assert al.knows("NtProtectVirtualMemory", "edr.dll", *_X64) is False
    assert al.knows("NtWriteVirtualMemory", "edr.dll", *_PAIR) is False
    assert al.knows("NtProtectVirtualMemory", "edr.dll", "26100.1", "arm64") is False


def test_the_same_hook_in_two_views_is_two_entries(tmp_path):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with()) == 1
    assert al.add_from(_result_with(view="x64")) == 1
    assert al.add_from(_result_with(view="x64")) == 0
    assert len(al.entries()) == 2


def test_entries_bare_lists_every_set_in_a_stable_order(tmp_path):
    al = _both_views(tmp_path)
    al.add_from(_result_with(build="26100.1", syscall="NtClose"))
    got = al.entries()
    assert got == [_e("NtClose", "edr.dll", build="26100.1"),
                   _e("NtProtectVirtualMemory", "edr.dll"),
                   _e("NtWriteVirtualMemory", "edr.dll", view="x64")]
    assert al.entries() == got


def test_entries_given_a_pair_lists_that_set_only(tmp_path):
    al = _both_views(tmp_path)
    assert al.entries(*_X64) == [_e("NtWriteVirtualMemory", "edr.dll", view="x64")]
    assert al.entries("26100.1", "x64") == []


@pytest.mark.parametrize("call", [lambda al: al.entries("26220.5770"),
                                  lambda al: al.entries(view="x64"),
                                  lambda al: al.clear("26220.5770"),
                                  lambda al: al.clear(view="x64")])
def test_half_a_pair_is_a_mistake_not_a_wildcard(tmp_path, call):
    al = _both_views(tmp_path)
    with pytest.raises(ValueError):
        call(al)
    assert len(al.entries()) == 2


def test_clear_given_a_pair_clears_that_set_only(tmp_path):
    al = _both_views(tmp_path)
    al.clear(*_PAIR)
    assert al.entries(*_PAIR) == []
    assert al.knows("NtWriteVirtualMemory", "edr.dll", *_X64) is True
    again = _allowlist(tmp_path)
    assert again.entries() == [_e("NtWriteVirtualMemory", "edr.dll", view="x64")]
    with open(al.path) as f:
        assert list(json.load(f)["sets"]) == ["26220.5770|x64"]


def test_clear_of_a_pair_nobody_recorded_changes_nothing(tmp_path):
    al = _both_views(tmp_path)
    al.clear("26100.1", "arm64")
    assert len(al.entries()) == 2


def test_clear_bare_clears_every_set(tmp_path):
    al = _both_views(tmp_path)
    al.clear()
    assert al.entries() == []
    assert _allowlist(tmp_path).entries() == []


def test_a_view_that_would_break_the_key_is_not_recorded(tmp_path):
    al = _allowlist(tmp_path)
    assert al.add_from(_result_with(view="x|64")) == 0
    assert al.entries() == []


def test_a_build_with_the_separator_in_it_survives_a_restart(tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with(build="1|2"))
    assert _allowlist(tmp_path).entries() == [_e("NtProtectVirtualMemory", "edr.dll", build="1|2")]


def test_each_view_of_a_scan_finds_its_own_set(arm64_baseline, x64_baseline, tmp_path):
    arm = _hooked_reader(arm64_baseline)
    x64 = _reader_from(x64_baseline,
                       patched={"NtWriteVirtualMemory": ("e92b170080", "edr.dll")})
    al = _allowlist(tmp_path)
    al.add_from(syscall_scan.measure(arm64_baseline, arm))
    al.add_from(syscall_scan.measure(x64_baseline, x64))
    arm_out = syscall_scan.measure(arm64_baseline, arm, allowlist=al)
    x64_out = syscall_scan.measure(x64_baseline, x64, allowlist=al)
    assert arm_out["states"]["NtProtectVirtualMemory"]["allowlisted"] is True
    assert x64_out["states"]["NtWriteVirtualMemory"]["state"] == "hooked"
    assert x64_out["states"]["NtWriteVirtualMemory"]["allowlisted"] is True
    assert arm_out["allowlist"] == {"applied": True, "entries": 1, "reason": ""}
    assert x64_out["allowlist"] == {"applied": True, "entries": 1, "reason": ""}


def test_recording_the_x64_view_does_not_unsuppress_the_arm64_scan(arm64_baseline, x64_baseline,
                                                                    tmp_path):
    arm = _hooked_reader(arm64_baseline)
    x64 = _reader_from(x64_baseline,
                       patched={"NtWriteVirtualMemory": ("e92b170080", "edr.dll")})
    al = _allowlist(tmp_path)
    al.add_from(syscall_scan.measure(arm64_baseline, arm))
    al.add_from(syscall_scan.measure(x64_baseline, x64))
    out = syscall_scan.measure(arm64_baseline, arm, allowlist=al)
    assert out["states"]["NtProtectVirtualMemory"]["allowlisted"] is True


def test_the_set_count_in_the_result_is_that_of_the_scanned_pair(arm64_baseline, tmp_path):
    al = _allowlist(tmp_path)
    al.add_from(_result_with())
    al.add_from(_result_with(syscall="NtClose"))
    al.add_from(_result_with(view="x64", syscall="NtOpenFile"))
    out = syscall_scan.measure(arm64_baseline, _hooked_reader(arm64_baseline), allowlist=al)
    assert out["allowlist"]["entries"] == 2


# --- scoring in the evidence model --------------------------------------------------------

def test_a_patched_stub_reaches_suspicious_on_its_own():
    findings = memory_evidence.from_syscall_scan(
        _result_with(state="patched", syscall="NtWriteVirtualMemory", owner="private"),
        "sample.exe")
    scored = memory_evidence.score(findings)
    assert scored["score"] >= memory_evidence.VERDICT_SUSPICIOUS
    assert [f["kind"] for f in findings] == ["syscall_stub_patched"]
    assert scored["label"] == "SUSPICIOUS"


def test_an_allowlisted_hook_produces_no_finding():
    findings = memory_evidence.from_syscall_scan(
        _result_with(state="hooked", owner="edr.dll", allowlisted=True), "sample.exe")
    assert findings == []


def test_a_hook_that_is_not_allowlisted_produces_a_small_finding():
    findings = memory_evidence.from_syscall_scan(
        _result_with(state="hooked", owner="unknown.dll", allowlisted=False), "sample.exe")
    assert [f["kind"] for f in findings] == ["syscall_stub_hooked"]
    assert memory_evidence.score(findings)["score"] < memory_evidence.VERDICT_SUSPICIOUS


def test_a_hook_without_the_flag_counts_as_not_allowlisted():
    # a scan without an allowlist carries no flag at all
    findings = memory_evidence.from_syscall_scan(
        _result_with(state="hooked", owner="unknown.dll"), "sample.exe")
    assert [f["kind"] for f in findings] == ["syscall_stub_hooked"]


@pytest.mark.parametrize("state", ["intact", "diverged", "unreadable"])
def test_intact_diverged_and_unreadable_produce_no_findings(state):
    assert memory_evidence.from_syscall_scan(_result_with(state=state), "sample.exe") == []


def test_a_result_without_deviations_or_not_a_result_produces_no_findings():
    assert memory_evidence.from_syscall_scan({"deviations": []}, "sample.exe") == []
    assert memory_evidence.from_syscall_scan({}, "sample.exe") == []
    assert memory_evidence.from_syscall_scan(None, "sample.exe") == []


def test_a_partial_result_still_scores_the_stubs_it_did_read():
    result = _result_with(state="patched", owner="private")
    result["partial"] = True
    assert [f["kind"] for f in memory_evidence.from_syscall_scan(result, "sample.exe")] \
        == ["syscall_stub_patched"]


def test_none_of_the_new_kinds_is_baseline_exempt():
    for kind in ("syscall_stub_patched", "syscall_stub_hooked", "direct_syscall_stub"):
        assert not memory_evidence.KINDS[kind].get("baseline_exempt")


def test_a_repeated_scan_matches_the_same_finding_whatever_moved():
    first = _result_with(state="patched", owner="private", rva=0x1000, expected="aa",
                         actual="bb")
    second = _result_with(state="patched", owner="private", rva=0x2000, expected="cc",
                          actual="dd")
    key = lambda r: memory_evidence.from_syscall_scan(r, "sample.exe")[0]["key"]
    assert key(first) == key(second)


def test_the_key_names_the_syscall_the_owner_and_the_process():
    def key(process="sample.exe", **kw):
        return memory_evidence.from_syscall_scan(
            _result_with(state="hooked", **kw), process)[0]["key"]
    base = key(owner="a.dll")
    assert key(owner="b.dll") != base
    assert key(owner="a.dll", syscall="NtClose") != base
    assert key(owner="a.dll", process="other.exe") != base
    assert key(owner="A.DLL") == base


def test_a_known_finding_is_suppressed_by_the_host_baseline(tmp_path):
    # the new kinds take part in baseline suppression like every other source
    findings = memory_evidence.from_syscall_scan(
        _result_with(state="patched", owner="private"), "sample.exe")
    baseline = memory_evidence.MemoryBaseline(str(tmp_path / "baseline.json"))
    baseline.add(findings)
    scored = memory_evidence.score(findings, baseline)
    assert scored["score"] == 0 and scored["suppressed_count"] == 1


def test_a_stub_without_an_owner_still_scores_as_patched():
    result = _result_with(state="patched", owner=None)
    findings = memory_evidence.from_syscall_scan(result, "sample.exe")
    assert [f["kind"] for f in findings] == ["syscall_stub_patched"]


def test_syscall_findings_flow_through_collect():
    results = {"syscall_scan": _result_with(state="patched", owner="private")}
    findings = memory_evidence.collect(results, process="sample.exe")
    assert [f["kind"] for f in findings] == ["syscall_stub_patched"]
    assert findings[0]["process"] == "sample.exe"


def test_collect_ignores_a_missing_or_malformed_syscall_scan():
    assert memory_evidence.collect({}, process="sample.exe") == []
    assert memory_evidence.collect({"syscall_scan": None}, process="sample.exe") == []
    assert memory_evidence.collect({"syscall_scan": "x"}, process="sample.exe") == []
