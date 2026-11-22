"""NTSleuth syscall baseline: loading, validation, the lookup catalog, and measuring a process."""

import contextlib
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

import pytest

import memory_evidence
import syscall_baseline
import syscall_rules
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
                # VirtualQueryEx rounds down to the page and answers from there
                base = max(start, addr & ~0xFFF)
                return region._replace(base=base, size=start + size - base)
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


def test_the_verdict_model_does_not_depend_on_the_syscall_modules():
    # memory_evidence stays independent of any one scanner: it must import and score
    # with the scanner modules unavailable, and its literals must match theirs
    code = ("import sys; sys.modules['syscall_baseline'] = None; "
            "sys.modules['syscall_scan'] = None; import memory_evidence")
    webui = os.path.join(os.path.dirname(SAMPLES), "..", "webui")
    run = subprocess.run([sys.executable, "-c", code], cwd=webui,
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert (syscall_baseline.STATE_HOOKED, syscall_baseline.STATE_PATCHED) == ("hooked", "patched")


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


# --- the routes (app.py) ------------------------------------------------------------------

def test_status_says_what_is_installed(client, tdc, tmp_path):
    body = client.get("/api/syscalls/status").get_json()
    assert body["installed"] is False
    assert body["baselines"] == []


def test_baseline_route_pages_and_filters(client, tdc, fake_baseline_dir):
    body = client.get("/api/syscalls/baseline?view=arm64&query=virtual&limit=2").get_json()
    assert len(body["items"]) == 2 and body["total"] >= 3


def test_scan_refuses_without_a_matching_baseline(client, tdc):
    r = client.post("/api/syscalls/scan", json={"pid": 4812})
    assert r.status_code == 400
    assert "baseline" in r.get_json()["error"].lower()


def test_lookup_returns_parameters(client, tdc, fake_baseline_dir):
    body = client.get("/api/syscalls/NtWriteVirtualMemory?view=arm64").get_json()
    assert body["number"] == 0x3A
    assert body["parameters"][0]["sal_annotation"] == "_In_"


def test_unknown_syscall_is_404(client, tdc, fake_baseline_dir):
    r = client.get("/api/syscalls/NtNope?view=arm64")
    assert r.status_code == 404
    # a 404 that only says "no such route" is not the answer to this question
    assert "NtNope" in r.get_json()["error"]


def test_a_baseline_file_name_gives_its_build_and_view():
    assert syscall_baseline.parse_baseline_name("ntsleuth-26220.5770-arm64.json") == ("26220.5770", "arm64")
    for name in ("ntsleuth-26220.5770-x86.json", "ntsleuth-26220.5770-arm64.json.tmp", "graph-cache.json",
                 "ntsleuth-../x-arm64.json", "ntsleuth-26220.5770-arm64.json\n"):
        assert syscall_baseline.parse_baseline_name(name) is None, name


def test_describe_is_the_catalog_entry_of_one_syscall(arm64_baseline):
    sc = arm64_baseline.syscalls["NtWriteVirtualMemory"]
    page = syscall_baseline.catalog(arm64_baseline, query="NtWriteVirtualMemory")
    assert syscall_baseline.describe(sc) == page["items"][0]


def test_a_baseline_says_whether_it_was_extracted_with_symbols():
    # NTSleuth's own output carries no such key: a baseline is taken to hold its parameters unless it says not
    assert syscall_baseline.parse_baseline(_fixture("arm64"), "26220.5770", "arm64").symbols is True
    assert syscall_baseline.parse_baseline([], "26220.5770", "arm64").symbols is True
    marked = dict(_fixture("arm64"), symbols=False)
    assert syscall_baseline.parse_baseline(marked, "26220.5770", "arm64").symbols is False
    assert syscall_baseline.parse_baseline(dict(marked, symbols=True), "26220.5770", "arm64").symbols is True


def test_the_status_names_the_installed_binaries_and_the_current_baseline(client, tdc, fake_baseline_dir, tmp_path):
    ntsleuth = tmp_path / "ntsleuth"
    ntsleuth.mkdir()
    (ntsleuth / "ntsleuth-x64.exe").write_bytes(b"MZ")
    (fake_baseline_dir / "graph-cache.json").write_text("{}")             # not a baseline: left out
    body = client.get("/api/syscalls/status").get_json()
    assert body["installed"] is True
    assert body["executables"] == {"arm64": False, "x64": True}
    assert body["build"] == "26220.5770"
    assert [(b["build"], b["view"], b["current"], b["symbols"]) for b in body["baselines"]] == [
        ("26220.5770", "arm64", True, True), ("26220.5770", "x64", True, True)]
    assert "note" not in body["baselines"][0]


def test_the_status_marks_a_baseline_of_another_build_as_not_current(client, tdc, fake_baseline_dir, monkeypatch):
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    body = client.get("/api/syscalls/status").get_json()
    assert [b["current"] for b in body["baselines"]] == [False, False]


def test_the_status_reports_a_baseline_it_cannot_read(client, tdc, fake_baseline_dir):
    (fake_baseline_dir / "ntsleuth-26220.5770-arm64.json").write_text("{not json")
    arm64 = client.get("/api/syscalls/status").get_json()["baselines"][0]
    assert arm64["symbols"] is None and "cannot read" in arm64["error"]


@pytest.mark.parametrize("machine, view", [("x64", "x64"), ("ARM64", "arm64"), ("ARM64EC", "x64"),
                                           ("x86", "x86"), ("ARM", None), (None, None)])
def test_the_view_of_a_process_follows_its_image_not_the_host(tdc, monkeypatch, machine, view):
    monkeypatch.setattr(tdc, "_process_machine", lambda pid: machine)
    assert tdc._syscall_view_for_pid(4812) == view


@pytest.mark.parametrize("view", ["../x64", "X64", "x64 ", "arm64\n", "ntdll", "'", "a" * 5000])
def test_a_view_that_is_not_one_of_the_three_is_refused_before_anything_is_read(client, tdc, fake_baseline_dir, view):
    for path in ("/api/syscalls/baseline", "/api/syscalls/NtWriteVirtualMemory"):
        r = client.get(path, query_string={"view": view})
        assert r.status_code == 400, (path, view)
        assert "view must be one of" in r.get_json()["error"]


def test_a_view_without_a_baseline_says_so(client, tdc, fake_baseline_dir):
    r = client.get("/api/syscalls/baseline?view=x86")
    assert r.status_code == 503 and "x86 view" in r.get_json()["error"]


def test_the_catalog_page_is_bounded_and_says_which_baseline_it_is(client, tdc, fake_baseline_dir):
    body = client.get("/api/syscalls/baseline?view=x64&limit=99999&offset=-5").get_json()
    assert body["limit"] == tdc.SYSCALL_PAGE_MAX and body["offset"] == 0
    assert (body["build"], body["view"], body["symbols"]) == ("26220.5770", "x64", True)
    assert client.get("/api/syscalls/baseline?view=x64&limit=lots").status_code == 400


def test_a_lookup_names_the_stub_prefix_that_is_compared(client, tdc, fake_baseline_dir):
    body = client.get("/api/syscalls/NtWriteVirtualMemory?view=x64").get_json()
    assert body["prefix_len"] == syscall_baseline.stub_prefix_len(
        syscall_baseline.load_baseline(str(fake_baseline_dir / "ntsleuth-26220.5770-x64.json")).syscalls[
            "NtWriteVirtualMemory"], "x64")
    assert body["stub_hex"]


# --- the baseline of a new build is extracted in the background --------------------------

def test_a_build_change_triggers_a_fresh_extraction(client, tdc, monkeypatch,
                                                    fake_baseline_dir):
    calls = []
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    monkeypatch.setattr(tdc, "_extract_baseline",
                        lambda view, symbols, build: calls.append((view, symbols)) or True)
    assert tdc._get_syscall_baseline("arm64") is None
    tdc._syscall_extract_state["thread"].join(5)
    assert calls and calls[0][0] == "arm64"


def test_without_the_symbol_server_the_extraction_drops_symbols(client, tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_symbol_server_reachable", lambda: False)
    args = tdc._ntsleuth_args("arm64")
    assert "--no-symbols" in args


def test_with_the_symbol_server_the_extraction_keeps_them(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_symbol_server_reachable", lambda: True)
    assert "--no-symbols" not in tdc._ntsleuth_args("arm64")
    assert "--no-symbols" in tdc._ntsleuth_args("arm64", symbols=False)
    assert tdc._ntsleuth_args("x64")[0].endswith("ntsleuth-x64.exe")


def test_status_says_when_parameters_are_incomplete(client, tdc, monkeypatch,
                                                    degraded_baseline_dir):
    body = client.get("/api/syscalls/status").get_json()
    assert body["baselines"][0]["symbols"] is False
    assert "parameter" in body["baselines"][0]["note"].lower()


def test_the_catalog_says_when_its_parameters_are_incomplete(client, tdc, degraded_baseline_dir):
    assert client.get("/api/syscalls/baseline?view=arm64").get_json()["symbols"] is False


def test_a_request_does_not_wait_for_the_extraction_and_two_start_one(client, tdc, monkeypatch, fake_baseline_dir):
    started, release, calls = threading.Event(), threading.Event(), []

    def slow(view, symbols, build):
        calls.append(view)
        started.set()
        release.wait(10)
        return True

    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    monkeypatch.setattr(tdc, "_extract_baseline", slow)
    try:
        first = client.get("/api/syscalls/baseline?view=arm64")      # returns while NTSleuth "runs"
        assert started.wait(5)
        second = client.get("/api/syscalls/baseline?view=arm64")
        for r in (first, second):
            assert r.status_code == 503 and "baseline" in r.get_json()["error"]
        assert "background" in second.get_json()["error"]
        running = client.get("/api/syscalls/status").get_json()["extraction"]["running"]
        assert running == [{"build": "26300.1", "view": "arm64"}]
    finally:
        release.set()
    tdc._syscall_extract_state["thread"].join(5)
    assert calls == ["arm64"]


def test_two_views_are_extracted_one_after_the_other(tdc, monkeypatch):
    # NTSleuth writes to one output folder: a second run must not start inside the first
    inside, overlap, entered, release = [], [], threading.Event(), threading.Event()

    def slow(view, symbols, build):
        inside.append(view)
        overlap.append(len(inside))
        entered.set()
        release.wait(10)
        inside.remove(view)
        return True

    monkeypatch.setattr(tdc, "_extract_baseline", slow)
    assert tdc._start_baseline_extraction("26300.1", "arm64")
    first = tdc._syscall_extract_state["thread"]
    assert entered.wait(5)
    assert tdc._start_baseline_extraction("26300.1", "x64")
    second = tdc._syscall_extract_state["thread"]
    time.sleep(0.2)                  # long enough for the second to have entered, were it not held back
    assert inside == ["arm64"]
    release.set()
    first.join(5)
    second.join(5)
    assert overlap == [1, 1]


def test_a_failed_extraction_is_not_retried_at_once_and_says_why(client, tdc, monkeypatch, fake_baseline_dir):
    calls = []
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    monkeypatch.setattr(tdc, "_extract_baseline", lambda view, symbols, build: calls.append(view) or False)
    client.get("/api/syscalls/baseline?view=arm64")
    tdc._syscall_extract_state["thread"].join(5)
    again = client.get("/api/syscalls/baseline?view=arm64")
    assert calls == ["arm64"]
    assert "not installed" in again.get_json()["error"]
    failed = client.get("/api/syscalls/status").get_json()["extraction"]["failed"]
    assert failed[0]["build"] == "26300.1" and "not installed" in failed[0]["reason"]
    monkeypatch.setattr(tdc, "SYSCALL_EXTRACT_RETRY", 0)
    client.get("/api/syscalls/baseline?view=arm64")
    tdc._syscall_extract_state["thread"].join(5)
    assert calls == ["arm64", "arm64"]


def test_an_extraction_that_raises_is_a_failure_with_its_reason(client, tdc, monkeypatch, fake_baseline_dir):
    def boom(view, symbols, build):
        raise RuntimeError("NTSleuth exited with 3: bad")

    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    monkeypatch.setattr(tdc, "_extract_baseline", boom)
    client.get("/api/syscalls/baseline?view=arm64")
    tdc._syscall_extract_state["thread"].join(5)
    assert "exited with 3" in client.get("/api/syscalls/baseline?view=arm64").get_json()["error"]
    assert tdc._syscall_extract_state["running"] == set()


def test_an_x86_view_or_an_unknown_build_starts_no_extraction(tdc, monkeypatch):
    monkeypatch.setattr(tdc, "_extract_baseline", lambda view, symbols, build: pytest.fail("extracted"))
    monkeypatch.setattr(tdc, "_current_os_build", lambda: None)
    assert tdc._get_syscall_baseline("arm64") is None
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    assert tdc._get_syscall_baseline("x86") is None
    assert tdc._syscall_extract_state["thread"] is None


def _fake_ntsleuth(tdc, monkeypatch, tmp_path, payload, returncode=0):
    """NTSleuth as a program that writes `payload` to output/syscalls.json, as it does beside where it runs."""
    exe = pathlib.Path(tdc.NTSLEUTH_DIR) / "ntsleuth-arm64.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"MZ")
    runs = []

    def run(args, timeout=None, **kwargs):
        runs.append((args, kwargs))
        if payload is not None:
            out = pathlib.Path(kwargs["cwd"]) / "output" / "syscalls.json"
            out.parent.mkdir(exist_ok=True)
            out.write_text(json.dumps(payload))
        return subprocess.CompletedProcess(args, returncode, "", "boom\nlast line")

    monkeypatch.setattr(tdc, "_run_cmd", run)
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    return runs


def test_the_extraction_stores_a_baseline_the_web_ui_then_loads(tdc, monkeypatch, tmp_path):
    runs = _fake_ntsleuth(tdc, monkeypatch, tmp_path, _fixture("arm64"))
    assert tdc._extract_baseline("arm64", False, "26300.1") is True
    path = pathlib.Path(tdc.NTSLEUTH_BASELINE_DIR) / "ntsleuth-26300.1-arm64.json"
    stored = syscall_baseline.load_baseline(str(path))
    assert (stored.build, stored.view, stored.symbols) == ("26300.1", "arm64", False)
    assert "--no-symbols" in runs[0][0] and runs[0][1]["cwd"] == tdc.NTSLEUTH_DIR
    assert not list(path.parent.glob("*.tmp"))
    assert tdc._get_syscall_baseline("arm64").build == "26300.1"


def test_an_extraction_with_symbols_is_not_marked_degraded(tdc, monkeypatch, tmp_path):
    _fake_ntsleuth(tdc, monkeypatch, tmp_path, _fixture("arm64")["syscalls"])        # a bare list also loads
    assert tdc._extract_baseline("arm64", True, "26300.1") is True
    assert tdc._get_syscall_baseline("arm64").symbols is True


def test_an_extraction_without_ntsleuth_says_so_and_writes_nothing(tdc, tmp_path):
    assert tdc._extract_baseline("arm64", True, "26300.1") is False
    assert not os.path.exists(tdc.NTSLEUTH_BASELINE_DIR)


@pytest.mark.parametrize("payload, returncode, why", [
    (_fixture("arm64"), 3, "exited with 3: last line"),
    (None, 0, "no usable JSON"),
    ({"syscalls": []}, 0, "no usable syscall"),
    ({"syscalls": "x"}, 0, "neither a list"),
])
def test_a_failed_extraction_stores_no_baseline(tdc, monkeypatch, tmp_path, payload, returncode, why):
    _fake_ntsleuth(tdc, monkeypatch, tmp_path, payload, returncode)
    with pytest.raises(RuntimeError) as err:
        tdc._extract_baseline("arm64", True, "26300.1")
    assert why in str(err.value)
    assert not os.path.exists(tdc.NTSLEUTH_BASELINE_DIR)


def test_an_output_left_by_an_earlier_run_is_not_taken_for_this_ones(tdc, monkeypatch, tmp_path):
    _fake_ntsleuth(tdc, monkeypatch, tmp_path, None)
    stale = pathlib.Path(tdc.NTSLEUTH_DIR) / "output" / "syscalls.json"
    stale.parent.mkdir()
    stale.write_text(json.dumps(_fixture("arm64")))
    with pytest.raises(RuntimeError, match="no usable JSON"):
        tdc._extract_baseline("arm64", True, "26300.1")


def test_a_baseline_that_changed_on_disk_is_read_again(client, tdc, fake_baseline_dir):
    assert client.get("/api/syscalls/baseline?view=arm64").get_json()["total"] > 1
    path = fake_baseline_dir / "ntsleuth-26220.5770-arm64.json"
    document = _fixture("arm64")
    document["syscalls"] = document["syscalls"][:1]
    path.write_text(json.dumps(document))
    assert client.get("/api/syscalls/baseline?view=arm64").get_json()["total"] == 1


# --- measuring a process through the routes --------------------------------------------------

class _Target:
    """The process a scan request is about: what the web UI is told of it, and the reader it opens."""

    def __init__(self):
        self.view, self.reader, self.opened, self.history = "arm64", None, [], []


@pytest.fixture
def target(tdc, monkeypatch, fake_baseline_dir):
    t = _Target()

    def opening(pid, view, build):
        t.opened.append((pid, view, build))
        if isinstance(t.reader, Exception):
            raise t.reader
        return contextlib.nullcontext(t.reader)

    monkeypatch.setattr(tdc, "_syscall_view_for_pid", lambda pid: t.view)
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: "C:\\Samples\\sample.exe")
    monkeypatch.setattr(tdc, "_open_syscall_reader", opening)
    monkeypatch.setattr(tdc, "_record_scan",
                        lambda tool, name, result, status="ok": t.history.append((tool, name, result, status)))
    t.reader = _reader_from(syscall_baseline.load_baseline(str(fake_baseline_dir / "ntsleuth-26220.5770-arm64.json")),
                            patched={})
    return t


def _patched_reader(tdc, fake_baseline_dir, owner, view="arm64", name="NtWriteVirtualMemory", live="0500001400000000"):
    baseline = syscall_baseline.load_baseline(str(fake_baseline_dir / f"ntsleuth-26220.5770-{view}.json"))
    return _reader_from(baseline, patched={name: (live, owner)})


def test_a_scan_measures_the_process_and_scores_it(client, tdc, target, fake_baseline_dir):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "private")
    body = client.post("/api/syscalls/scan", json={"pid": 4812}).get_json()
    assert body["counts"]["patched"] == 1 and body["view"] == "arm64"
    assert body["tool"] == "Syscalls" and body["pid"] == 4812 and body["modules"] == ["ntdll.dll"]
    assert body["states"]["NtWriteVirtualMemory"]["state"] == "patched"
    assert [f["kind"] for f in body["evidence"]["findings"]] == ["syscall_stub_patched"]
    assert body["evidence"]["score"] > 0
    # the reader is opened for the view and the build the route resolved, not for what the reader derives
    assert target.opened == [(4812, "arm64", "26220.5770")]


def test_a_scan_goes_to_the_history_without_the_state_of_every_stub(client, tdc, target, fake_baseline_dir):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "private")
    client.post("/api/syscalls/scan", json={"pid": 4812})
    [(tool, name, result, status)] = target.history
    assert (tool, name, status) == ("Syscalls", "PID 4812", "ok")
    assert "states" not in result and result["counts"]["patched"] == 1 and result["evidence"]["score"] > 0


def test_a_scan_of_a_clean_process_scores_nothing(client, tdc, target):
    body = client.post("/api/syscalls/scan", json={"pid": 4812}).get_json()
    assert body["deviations"] == [] and body["evidence"]["score"] == 0 and body["evidence"]["label"] == "CLEAN"


def test_a_scan_takes_the_view_from_the_image_and_the_baseline_of_that_view(client, tdc, target, fake_baseline_dir):
    target.view = "x64"
    target.reader = _patched_reader(tdc, fake_baseline_dir, "private", view="x64", name="NtProtectVirtualMemory",
                                    live="e900000000" + "00" * 11)
    body = client.post("/api/syscalls/scan", json={"pid": 4812, "view": "arm64"}).get_json()
    assert body["view"] == "x64"                        # a view in the request is not a say in the matter
    assert target.opened[0][1] == "x64"


def test_a_scan_of_an_x86_process_has_no_baseline_to_use(client, tdc, target):
    target.view = "x86"
    r = client.post("/api/syscalls/scan", json={"pid": 4812})
    assert r.status_code == 400 and "x86 view" in r.get_json()["error"]
    assert target.opened == []


def test_a_scan_of_a_process_whose_architecture_is_unknown_is_refused_unread(client, tdc, target):
    target.view = None
    r = client.post("/api/syscalls/scan", json={"pid": 4812})
    assert r.status_code == 400 and "baseline" in r.get_json()["error"].lower()
    assert target.opened == []


@pytest.mark.parametrize("pid", ["abc", 0, -4, True, None, "", [4], 2 ** 40, "4812; calc"])
def test_a_scan_wants_a_pid(client, tdc, target, pid):
    r = client.post("/api/syscalls/scan", json={"pid": pid})
    assert r.status_code == 400 and "pid" in r.get_json()["error"]
    assert target.opened == []


def test_a_scan_with_a_body_that_is_not_an_object_is_a_400_not_a_crash(client, tdc, target):
    assert client.post("/api/syscalls/scan", json=[1, 2]).status_code == 400
    assert client.post("/api/syscalls/scan", data="x").status_code == 400


@pytest.mark.parametrize("modules, expected", [
    (None, ["ntdll.dll"]), (["win32u.dll"], ["win32u.dll"]), ("ntdll.dll, WIN32U.DLL", ["ntdll.dll", "win32u.dll"]),
    (["ntdll.dll", "NTDLL.dll"], ["ntdll.dll"])])
def test_a_scan_measures_the_modules_it_is_asked_for(client, tdc, target, modules, expected):
    body = client.post("/api/syscalls/scan", json={"pid": 4812, "modules": modules}).get_json()
    assert body["modules"] == expected
    assert {s["module"] for s in body["states"].values()} <= set(expected)


@pytest.mark.parametrize("modules", [["kernel32.dll"], ["ntdll.dll", "..\\x.dll"], 7, [7], {"a": 1}])
def test_a_scan_refuses_a_module_it_does_not_know(client, tdc, target, modules):
    r = client.post("/api/syscalls/scan", json={"pid": 4812, "modules": modules})
    assert r.status_code == 400 and "modules" in r.get_json()["error"]


def test_a_process_that_cannot_be_opened_is_a_400_naming_why(client, tdc, target):
    target.reader = PermissionError("Access is denied")
    r = client.post("/api/syscalls/scan", json={"pid": 4812})
    assert r.status_code == 400 and "cannot read process 4812" in r.get_json()["error"]
    assert not tdc._syscall_scan_running()


def test_a_scan_is_refused_when_the_build_of_the_system_is_not_the_baselines(client, tdc, target, monkeypatch):
    # the reader and measure compare the build the route resolved with the baseline's: a build that moved under a
    # running web UI is refused by the measurement, not by a second copy of the check here
    calls = iter(["26220.5770", "26300.1"])
    monkeypatch.setattr(tdc, "_current_os_build", lambda: next(calls))
    r = client.post("/api/syscalls/scan", json={"pid": 4812})
    assert r.status_code == 400 and "does not match the baseline build" in r.get_json()["error"]


class _Blocked(FakeReader):
    """A process whose module list never comes back until `release` is set."""

    def __init__(self, inner, release):
        super().__init__(inner._m, inner._ranges, inner._regions, view=inner._view, build=inner._build)
        self.release, self.entered = release, threading.Event()

    def modules(self):
        self.entered.set()
        self.release.wait(10)
        return self._m


def _until(predicate, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not predicate():
        time.sleep(0.01)
    return predicate()


def test_a_scan_that_hangs_is_a_504_and_is_still_counted_until_the_reader_returns(client, tdc, target, monkeypatch):
    release = threading.Event()
    target.reader = _Blocked(target.reader, release)
    monkeypatch.setattr(tdc, "SYSCALL_SCAN_TIMEOUT", 0.05)
    monkeypatch.setattr(tdc, "SYSCALL_SCAN_GRACE", 0.05)
    try:
        r = client.post("/api/syscalls/scan", json={"pid": 4812})
        assert r.status_code == 504 and "timed out" in r.get_json()["error"]
        assert target.reader.entered.is_set()
        assert tdc._syscall_scan_running() is True       # the thread still holds the process: no update under it
    finally:
        release.set()
    assert _until(lambda: not tdc._syscall_scan_running())
    assert target.history == []                          # nothing timed out is a result


def test_a_scan_that_runs_out_of_time_reads_no_more_and_is_a_504(client, tdc, target, monkeypatch):
    monkeypatch.setattr(tdc, "SYSCALL_SCAN_TIMEOUT", 0)
    r = client.post("/api/syscalls/scan", json={"pid": 4812})
    assert r.status_code == 504 and target.reader.reads == 0
    assert _until(lambda: not tdc._syscall_scan_running())


def test_no_scan_is_counted_once_it_is_done(client, tdc, target):
    assert tdc._syscall_scan_running() is False
    client.post("/api/syscalls/scan", json={"pid": 4812})
    assert tdc._syscall_scan_running() is False


def test_scans_of_two_processes_run_side_by_side(client, tdc, target, monkeypatch):
    # no scan locks another out: both readers are in `modules` at once
    release, inside = threading.Event(), []
    base = target.reader

    class Waiting(_Blocked):
        def modules(self):
            inside.append(1)
            return super().modules()

    readers = iter([Waiting(base, release), Waiting(base, release)])
    monkeypatch.setattr(tdc, "_open_syscall_reader", lambda pid, view, build: contextlib.nullcontext(next(readers)))
    answers = []
    threads = [threading.Thread(target=lambda: answers.append(
        tdc.app.test_client().post("/api/syscalls/scan", json={"pid": 4812}).status_code)) for _ in range(2)]
    for t in threads:
        t.start()
    assert _until(lambda: len(inside) == 2) and tdc._syscall_scan_running()
    release.set()
    for t in threads:
        t.join(5)
    assert answers == [200, 200]
    assert not tdc._syscall_scan_running()


def test_the_new_post_routes_are_behind_the_cross_site_check_and_the_maintenance_gate(client, tdc, target,
                                                                                      monkeypatch):
    writes = (("post", "/api/syscalls/scan", {"pid": 4812}), ("post", "/api/syscalls/stubs", {"pid": 4812}),
              ("post", "/api/syscalls/hook-baseline", {"pid": 4812}), ("delete", "/api/syscalls/hook-baseline", None))
    for method, path, body in writes:
        r = getattr(client, method)(path, json=body, headers={"Origin": "http://evil.example"})
        assert r.status_code == 403, path
    assert target.opened == []
    assert client.get("/api/syscalls/status", headers={"Host": "evil.example"}).status_code == 403

    class Busy:
        maintenance = True

    monkeypatch.setattr(tdc, "_update_manager", Busy())
    for method, path, body in writes:
        r = getattr(client, method)(path, json=body)
        assert r.status_code == 503 and r.get_json()["maintenance"] is True, path
    assert target.opened == []
    assert client.get("/api/syscalls/status").status_code == 200


# --- stubs outside ntdll through the route -------------------------------------------------

_X64_STUB_0x3A = bytes.fromhex("4c8bd1b8") + (0x3A).to_bytes(4, "little") + bytes.fromhex("f604250803fe7f017503" "0f05")
_PRIVATE_BASE = 0x1F0000


def _x64_space(data, protect=0x20, view="x64"):
    """An x64 process whose only private executable memory holds `data`."""
    free = syscall_scan.Region(0, 0, None, 0, 0, 0)
    private = syscall_scan.Region(syscall_scan.MEM_COMMIT, syscall_scan.MEM_PRIVATE, None, 0, 0, protect)
    size = (len(data) + 0xFFF) & ~0xFFF
    regions = [(0, _PRIVATE_BASE, free), (_PRIVATE_BASE, size, private),
               (_PRIVATE_BASE + size, syscall_scan._USER_SPACE_END - _PRIVATE_BASE - size, free)]
    return FakeReader([], [(_PRIVATE_BASE, bytearray(data.ljust(size, b"\0")))], regions, view=view)


def test_a_stub_in_a_process_is_found_and_the_search_says_how_far_it_went(client, tdc, target):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    r = client.post("/api/syscalls/stubs", json={"pid": 4812})
    body = r.get_json()
    assert r.status_code == 200 and body["mode"] == "process" and body["view"] == "x64"
    assert [h["syscall"] for h in body["hits"]] == ["NtWriteVirtualMemory"]
    assert body["hits"][0]["address"] == _PRIVATE_BASE + 0x40
    # StubScan's own attributes do not survive json.dumps: the route has to say them in keys
    assert (body["partial"], body["regions_searched"], body["note"]) == (False, 1, "")
    assert body["hits"][0]["import_present"] is None
    assert [f["kind"] for f in body["evidence"]["findings"]] == ["direct_syscall_stub"]
    # a hint, as no import table was expanded: it holds its weight only with a second source
    finding = body["evidence"]["findings"][0]
    assert finding["needs_corroboration"] is True and finding["factors"]["corroboration"] < 1


def test_a_search_that_could_not_read_all_says_partial(client, tdc, target):
    target.view = "x64"
    reader = _x64_space(_X64_STUB_0x3A)
    reader._cut = _PRIVATE_BASE                       # every read of that memory fails
    target.reader = reader
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert body["hits"] == [] and body["partial"] is True and "not read" in body["note"]


def test_a_stub_search_of_a_process_of_another_view_than_the_reader_is_refused(client, tdc, target):
    target.view = "x64"
    target.reader = _x64_space(_X64_STUB_0x3A, view="arm64")
    r = client.post("/api/syscalls/stubs", json={"pid": 4812})
    assert r.status_code == 400 and "does not match the baseline view" in r.get_json()["error"]


def test_a_stub_search_wants_a_pid_or_a_path_not_both_nor_neither(client, tdc, target):
    for body in ({}, {"pid": 4812, "path": "C:\\x"}, {"pid": "", "path": ""}):
        r = client.post("/api/syscalls/stubs", json=body)
        assert r.status_code == 400 and "pid or a path" in r.get_json()["error"]


@pytest.fixture
def sample_dir(tdc, monkeypatch, tmp_path):
    folder = tmp_path / "samples"
    folder.mkdir()
    monkeypatch.setattr(tdc, "_readable_roots", lambda: [str(folder)])
    return folder


def test_a_stub_in_a_file_is_found(client, tdc, target, sample_dir):
    path = sample_dir / "loader.bin"
    path.write_bytes(b"\x90" * 16 + _X64_STUB_0x3A + b"\xc3")
    r = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"})
    body = r.get_json()
    assert r.status_code == 200 and body["mode"] == "file" and body["process"] == "loader.bin"
    assert [(h["syscall"], h["offset"]) for h in body["hits"]] == [("NtWriteVirtualMemory", 16)]
    assert body["imports_read"] is False and body["hits"][0]["import_present"] is None
    assert body["partial"] is False and target.opened == []         # a file opens no process


def test_a_file_that_imports_the_function_says_so_but_never_that_it_does_not(client, tdc, target, sample_dir,
                                                                             monkeypatch):
    path = sample_dir / "loader.bin"
    path.write_bytes(_X64_STUB_0x3A)
    monkeypatch.setattr(tdc, "_pe_import_names", lambda data: {"NtWriteVirtualMemory"})
    hit = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()["hits"][0]
    assert hit["import_present"] is True
    # a table that was read and lacks the name is still no proof: only the expanded table can give that
    monkeypatch.setattr(tdc, "_pe_import_names", lambda data: {"CreateFileW"})
    hit = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()["hits"][0]
    assert hit["import_present"] is None


def _pe_importing(*names):
    """A minimal PE32+ whose import table lists `names` from one DLL."""
    import struct
    base, ilt, dll = 0x1000, 0x1040, 0x1080
    hints, at = b"", 0x10A0
    thunks = b""
    for name in names:
        thunks += struct.pack("<Q", at)
        entry = struct.pack("<H", 0) + name.encode() + b"\0"
        entry += b"\0" * (len(entry) % 2)
        hints, at = hints + entry, at + len(entry)
    section = bytearray(0x200)
    section[0:40] = struct.pack("<IIIII", ilt, 0, 0, dll, ilt) + bytes(20)
    section[0x40:0x40 + len(thunks)] = thunks
    section[0x80:0x80 + 10] = b"ntdll.dll\0"
    section[0xA0:0xA0 + len(hints)] = hints
    optional = struct.pack("<HBBIIIII", 0x20B, 14, 0, 0, 0x200, 0, 0, 0x1000)
    optional += struct.pack("<QIIHHHHHHIIIIHH", 0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0)
    optional += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    directories = bytearray(128)
    directories[8:16] = struct.pack("<II", base, 40)
    optional += bytes(directories)
    assert len(optional) == 0xF0
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    header = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0" + coff + optional
    header += struct.pack("<8sIIIIIIHHI", b".idata", 0x200, base, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)
    return header.ljust(0x200, b"\0") + bytes(section)


def test_the_imports_of_a_pe_are_read_and_a_file_that_is_none_is_unread(tdc):
    assert tdc._pe_import_names(_pe_importing("NtWriteVirtualMemory", "CreateFileW")) == {
        "NtWriteVirtualMemory", "CreateFileW"}
    assert tdc._pe_import_names(b"not a pe at all") is None
    assert tdc._pe_import_names(b"") is None
    assert tdc._pe_import_names(_pe_importing("NtClose")[:0x60]) is None


def test_a_pe_that_carries_a_stub_and_imports_it_says_so(client, tdc, target,
                                                                                         sample_dir):
    path = sample_dir / "loader.exe"
    path.write_bytes(_pe_importing("NtWriteVirtualMemory") + _X64_STUB_0x3A)
    body = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()
    assert body["imports_read"] is True and body["hits"][0]["import_present"] is True


@pytest.mark.parametrize("name", ["../outside.bin", "sub/../../outside.bin"])
def test_a_path_outside_the_readable_folders_is_refused(client, tdc, target, sample_dir, tmp_path, name):
    (tmp_path / "outside.bin").write_bytes(_X64_STUB_0x3A)
    r = client.post("/api/syscalls/stubs", json={"path": str(sample_dir / name), "view": "x64"})
    assert r.status_code == 403


def test_a_link_out_of_the_readable_folders_is_refused(client, tdc, target, sample_dir, tmp_path):
    (tmp_path / "outside.bin").write_bytes(_X64_STUB_0x3A)
    link = sample_dir / "link.bin"
    os.symlink(tmp_path / "outside.bin", link)
    assert client.post("/api/syscalls/stubs", json={"path": str(link), "view": "x64"}).status_code == 403


@pytest.mark.parametrize("path", ["\\\\host\\share\\x.bin", "relative.bin", "C:x.bin", "nul\0byte", 7])
def test_a_path_that_is_not_a_local_absolute_path_is_refused(client, tdc, target, sample_dir, path):
    assert client.post("/api/syscalls/stubs", json={"path": path, "view": "x64"}).status_code in (400, 403)


def test_a_file_search_wants_a_view_and_a_file_that_is_there_and_not_too_big(client, tdc, target, sample_dir,
                                                                           monkeypatch):
    path = sample_dir / "loader.bin"
    path.write_bytes(_X64_STUB_0x3A)
    assert client.post("/api/syscalls/stubs", json={"path": str(path)}).status_code == 400
    assert client.post("/api/syscalls/stubs", json={"path": str(path), "view": "../x"}).status_code == 400
    assert client.post("/api/syscalls/stubs", json={"path": str(sample_dir / "gone.bin"), "view": "x64"}
                       ).status_code == 400
    assert client.post("/api/syscalls/stubs", json={"path": str(sample_dir), "view": "x64"}).status_code == 400
    monkeypatch.setattr(tdc, "SYSCALL_FILE_MAX", 4)
    r = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"})
    assert r.status_code == 400 and "larger than" in r.get_json()["error"]


# --- the hook allowlist ---------------------------------------------------------------------

def test_there_is_one_allowlist_in_the_process(tdc):
    assert tdc._get_hook_allowlist() is tdc._get_hook_allowlist()
    seen = []
    threads = [threading.Thread(target=lambda: seen.append(tdc._get_hook_allowlist())) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(a is seen[0] for a in seen) and seen[0] is tdc._get_hook_allowlist()


def test_the_hook_list_starts_empty_and_says_where_it_lives(client, tdc):
    body = client.get("/api/syscalls/hook-baseline").get_json()
    assert body["entries"] == [] and body["problem"] is None and body["path"] == tdc.SYSCALL_HOOK_ALLOWLIST_FILE


def test_hooks_are_recorded_per_view_and_a_second_view_keeps_the_first(client, tdc, target, fake_baseline_dir):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll")
    first = client.post("/api/syscalls/hook-baseline", json={"pid": 4812}).get_json()
    assert (first["added"], first["entries"], first["view"], first["build"]) == (1, 1, "arm64", "26220.5770")
    target.view = "x64"
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll", view="x64", name="NtProtectVirtualMemory",
                                    live="e900000000" + "00" * 11)
    second = client.post("/api/syscalls/hook-baseline", json={"pid": 4812}).get_json()
    assert (second["added"], second["entries"], second["view"]) == (1, 1, "x64")
    entries = client.get("/api/syscalls/hook-baseline").get_json()["entries"]
    assert sorted((e["view"], e["syscall"], e["owner"]) for e in entries) == [
        ("arm64", "NtWriteVirtualMemory", "edr.dll"), ("x64", "NtProtectVirtualMemory", "edr.dll")]
    only = client.get("/api/syscalls/hook-baseline?build=26220.5770&view=x64").get_json()["entries"]
    assert [e["view"] for e in only] == ["x64"]
    with open(tdc.SYSCALL_HOOK_ALLOWLIST_FILE, encoding="utf-8") as fh:
        assert len(json.load(fh)["sets"]) == 2


def test_a_recorded_hook_is_known_to_the_next_scan_and_no_longer_scores(client, tdc, target, fake_baseline_dir):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll")
    before = client.post("/api/syscalls/scan", json={"pid": 4812}).get_json()
    assert before["states"]["NtWriteVirtualMemory"]["state"] == "hooked"
    assert before["evidence"]["score"] > 0
    client.post("/api/syscalls/hook-baseline", json={"pid": 4812})
    after = client.post("/api/syscalls/scan", json={"pid": 4812}).get_json()
    assert after["states"]["NtWriteVirtualMemory"]["allowlisted"] is True
    assert after["counts"]["hooked"] == 1                       # still seen, no longer a finding
    assert after["evidence"]["score"] == 0


def test_a_patch_is_never_recorded_as_a_known_hook(client, tdc, target, fake_baseline_dir):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "private")
    body = client.post("/api/syscalls/hook-baseline", json={"pid": 4812}).get_json()
    assert body["added"] == 0 and client.get("/api/syscalls/hook-baseline").get_json()["entries"] == []


def test_the_known_hooks_can_be_forgotten_for_one_view_or_all(client, tdc, target, fake_baseline_dir):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll")
    client.post("/api/syscalls/hook-baseline", json={"pid": 4812})
    target.view = "x64"
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll", view="x64", name="NtProtectVirtualMemory",
                                    live="e900000000" + "00" * 11)
    client.post("/api/syscalls/hook-baseline", json={"pid": 4812})
    assert client.delete("/api/syscalls/hook-baseline?build=26220.5770&view=arm64").get_json()["entries"] == 1
    assert [e["view"] for e in client.get("/api/syscalls/hook-baseline").get_json()["entries"]] == ["x64"]
    assert client.delete("/api/syscalls/hook-baseline").get_json() == {"ok": True, "entries": 0}


@pytest.mark.parametrize("query", ["build=26220.5770", "view=arm64", "build=&view=arm64", "build=1&view=", "build=1&view=../x"])
def test_one_of_build_and_view_alone_is_no_wildcard(client, tdc, target, fake_baseline_dir, query):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll")
    client.post("/api/syscalls/hook-baseline", json={"pid": 4812})
    assert client.delete("/api/syscalls/hook-baseline?" + query).status_code == 400
    assert client.get("/api/syscalls/hook-baseline?" + query).status_code == 400
    assert len(client.get("/api/syscalls/hook-baseline").get_json()["entries"]) == 1


def test_an_allowlist_that_cannot_be_written_is_a_500_and_stays_as_it_was(client, tdc, target, fake_baseline_dir,
                                                                          monkeypatch):
    target.reader = _patched_reader(tdc, fake_baseline_dir, "edr.dll")
    allowlist = tdc._get_hook_allowlist()
    monkeypatch.setattr(allowlist, "save", lambda: (_ for _ in ()).throw(OSError("disk full")))
    r = client.post("/api/syscalls/hook-baseline", json={"pid": 4812})
    assert r.status_code == 500 and "disk full" in r.get_json()["error"]
    assert allowlist.entries() == []


def test_a_scan_is_recorded_as_a_syscall_row_with_its_verdict(tdc):
    verdict = tdc._normalize_scan("Syscalls", {"evidence": {"label": "MALICIOUS", "score": 6.5}})
    assert verdict == ("detected", True, False, 6.5)
    clean = tdc._normalize_scan("Syscalls", {"evidence": {"label": "CLEAN", "score": 0}})
    assert clean[0] == "clean" and clean[2] is True


def test_the_symbol_server_is_reachable_when_a_connection_opens(app_module, monkeypatch):
    # not `tdc`: its stand-in for the probe is not what is under test
    import socket
    closed, asked = [], []

    class Connection:
        def close(self):
            closed.append(1)

    def connect(address, timeout=None):
        asked.append((address, timeout))
        return Connection()

    monkeypatch.setattr(socket, "create_connection", connect)
    assert app_module._symbol_server_reachable() is True and closed == [1]
    assert asked[0][0] == ("msdl.microsoft.com", 443) and asked[0][1] == app_module.SYMBOL_SERVER_WAIT

    def refuse(address, timeout=None):
        raise OSError("network is unreachable")

    monkeypatch.setattr(socket, "create_connection", refuse)
    assert app_module._symbol_server_reachable() is False


# --- review fixes: maintenance, the running extraction, the build of a job, a corrupt baseline ---

class _Maintenance:
    maintenance = True


def test_no_extraction_starts_while_the_tools_are_being_updated(client, tdc, monkeypatch, fake_baseline_dir):
    # a GET passes the maintenance gate; the extraction it would start must not, or an update could swap the
    # NTSleuth binary out from under it
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    monkeypatch.setattr(tdc, "_extract_baseline", lambda *a: pytest.fail("extracted during maintenance"))
    monkeypatch.setattr(tdc, "_update_manager", _Maintenance())
    for path in ("/api/syscalls/baseline?view=arm64", "/api/syscalls/NtClose?view=arm64"):
        r = client.get(path)
        assert r.status_code == 503 and "being updated" in r.get_json()["error"]
    assert tdc._syscall_extract_state["thread"] is None and not tdc._syscall_extracting()
    assert tdc._start_baseline_extraction("26300.1", "arm64") is False


def test_the_extraction_starts_once_the_update_is_over(client, tdc, monkeypatch, fake_baseline_dir):
    calls = []
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26300.1")
    monkeypatch.setattr(tdc, "_extract_baseline", lambda view, symbols, build: calls.append(view) or True)
    monkeypatch.setattr(tdc, "_update_manager", _Maintenance())
    client.get("/api/syscalls/baseline?view=arm64")
    monkeypatch.setattr(tdc, "_update_manager", type("Idle", (), {"maintenance": False})())
    client.get("/api/syscalls/baseline?view=arm64")
    tdc._syscall_extract_state["thread"].join(5)
    assert calls == ["arm64"]


def test_a_running_extraction_is_visible_to_the_update_preconditions(tdc, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def slow(view, symbols, build):
        started.set()
        release.wait(10)
        return True

    monkeypatch.setattr(tdc, "_extract_baseline", slow)
    assert tdc._syscall_extracting() is False
    assert tdc._start_baseline_extraction("26300.1", "arm64")
    try:
        assert started.wait(5) and tdc._syscall_extracting() is True
    finally:
        release.set()
    tdc._syscall_extract_state["thread"].join(5)
    assert tdc._syscall_extracting() is False


def test_the_job_extracts_the_build_it_is_keyed_by(tdc, monkeypatch):
    seen = []
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26400.9")        # moved since the job was started
    monkeypatch.setattr(tdc, "_extract_baseline", lambda view, symbols, build: seen.append(build) or True)
    assert tdc._start_baseline_extraction("26300.1", "arm64")
    tdc._syscall_extract_state["thread"].join(5)
    assert seen == ["26300.1"]


def test_the_extraction_files_the_baseline_under_the_build_it_was_asked_for(tdc, monkeypatch, tmp_path):
    _fake_ntsleuth(tdc, monkeypatch, tmp_path, _fixture("arm64"))
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26400.9")
    assert tdc._extract_baseline("arm64", True, "26300.1") is True
    stored = sorted(p.name for p in pathlib.Path(tdc.NTSLEUTH_BASELINE_DIR).iterdir())
    assert stored == ["ntsleuth-26300.1-arm64.json"]


def test_a_corrupt_baseline_is_parsed_once_not_on_every_request(client, tdc, fake_baseline_dir, monkeypatch):
    (fake_baseline_dir / "ntsleuth-26220.5770-arm64.json").write_text("{not json")
    parsed = []
    real = syscall_baseline.load_baseline
    monkeypatch.setattr(syscall_baseline, "load_baseline",
                        lambda path: (parsed.append(path) if "arm64" in path else None) or real(path))
    for _ in range(3):
        assert client.get("/api/syscalls/baseline?view=arm64").status_code == 503
        client.get("/api/syscalls/status")
    assert len(parsed) == 1
    # a file written again is looked at again
    document = _fixture("arm64")
    (fake_baseline_dir / "ntsleuth-26220.5770-arm64.json").write_text(json.dumps(document))
    assert client.get("/api/syscalls/baseline?view=arm64").status_code == 200
    assert len(parsed) == 2


def test_a_corrupt_baseline_says_it_is_not_replaced_by_itself(client, tdc, fake_baseline_dir, monkeypatch):
    path = fake_baseline_dir / "ntsleuth-26220.5770-arm64.json"
    path.write_text("{not json")
    monkeypatch.setattr(tdc, "_extract_baseline", lambda *a: pytest.fail("a corrupt file is not re-extracted"))
    error = client.get("/api/syscalls/baseline?view=arm64").get_json()["error"]
    assert "unusable" in error and "delete" in error and path.name in error
    entry = client.get("/api/syscalls/status").get_json()["baselines"][0]
    assert entry["symbols"] is None and "delete" in entry["note"] and "not replaced" in entry["note"]
    assert tdc._syscall_extract_state["thread"] is None


# --- rule drafts: a deviation or a stub hit becomes a rule the chamber can match next time ----------------

BUILD = "26220.5770"
_META_LINE = re.compile(r'^        [a-z_]+ += "[ -!#-\[\]-~]*"$')


def _hit(sample="evil.exe", **over):
    hit = {"syscall": "NtAllocateVirtualMemory", "number": 0x18, "module": "ntdll.dll", "offset": 0x1A40,
           "view": "x64", "pattern": "mov r10, rcx; mov eax, imm32; syscall",
           "stub_hex": "4c8bd1b8180000000f05", "import_present": None, "number_known": True, "sample": sample}
    hit.update(over)
    return hit


def _hit_payload(**over):
    body = {"hit": _hit(), "build": BUILD, "view": "x64", "source": "direct_syscall_stub"}
    body.update(over)
    return body


def _assert_well_formed(draft):
    """What a hot-reloaded YARA directory needs of every file in it: one rule, every meta string closed on its own
    line and free of quote and backslash, braces that pair, and a name that is an identifier."""
    text, name = draft["text"], draft["name"]
    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
    assert text.startswith(f"rule {name} {{\n") and text.endswith("\n}\n")
    assert text.count("{") == text.count("}")
    assert len(re.findall(r"^rule ", text, re.M)) == 1
    meta = text.split("    meta:\n")[1].split("\n\n")[0].split("\n")
    assert meta and all(_META_LINE.match(line) for line in meta), meta
    assert all(ch == "\n" or " " <= ch <= "~" for ch in text)
    assert syscall_rules.check_draft(draft) == (name, text)


def test_draft_names_the_syscall_build_and_view():
    d = syscall_rules.draft_yara(
        {"syscall": "NtAllocateVirtualMemory", "number": 0x18,
         "stub_hex": "4c8bd1b8180000000f05"},
        build="26220.5770", view="x64", source="direct_syscall_stub")
    assert "NtAllocateVirtualMemory" in d["name"]
    assert 'author      = "DetonationChamber"' in d["text"]
    assert "26220.5770" in d["text"] and "x64" in d["text"]
    assert "$stub = {" in d["text"]


def test_apply_writes_where_rustinel_reads(tmp_path):
    d = syscall_rules.draft_yara(_hit(), "26220.5770", "x64", "direct_syscall_stub")
    out = syscall_rules.apply_draft(d, str(tmp_path))
    assert out["status"] == "written"
    assert (tmp_path / (d["name"] + ".yar")).read_text().startswith("rule ")


def test_signatures_json_loads_and_clamps_weight(tmp_path):
    p = tmp_path / "s.json"
    p.write_text('[{"family":"X","pattern":"e9","match":"prefix","weight":99,"note":"n"},'
                 ' {"family":"Y","pattern":"(","match":"regex","weight":1,"note":"bad"}]')
    sigs = syscall_rules.load_signatures(str(p))
    assert len(sigs) == 1
    assert sigs[0]["weight"] <= syscall_rules.MAX_SIGNATURE_WEIGHT


def _draft(hit=None, **over):
    args = {"build": BUILD, "view": "x64", "source": "direct_syscall_stub"}
    args.update(over)
    return syscall_rules.draft_yara(hit or _hit(), **args)


def test_a_draft_has_the_house_form_and_says_where_it_came_from():
    d = _draft(now=datetime.datetime(2026, 11, 23, 10, 0, 0))
    _assert_well_formed(d)
    text = d["text"]
    assert d["target"] == d["name"] + ".yar" and d["kind"] == "yara"
    assert 'description = "Direct syscall stub for NtAllocateVirtualMemory (0x18) as numbered on Windows ' in text
    assert 'severity    = "medium"' in text
    assert 'tags        = "attack.defense_evasion,attack.t1106"' in text
    assert 'generated   = "2026-11-23T10:00:00Z by the Syscalls tab, source direct_syscall_stub"' in text
    assert 'os_build    = "26220.5770"' in text and 'os_view     = "x64"' in text
    assert "in evil.exe" in text and "offset 0x1A40" in text
    assert "$stub = { 4C 8B D1 B8 18 00 00 00 0F 05 }" in text
    assert text.rstrip().endswith("condition:\n        $stub\n}")


def test_a_draft_is_one_rule_per_syscall_build_view_and_stub():
    base = _draft()["name"]
    assert base == _draft(_hit(sample="another.exe"))["name"]
    assert base != _draft(build="26100.1")["name"]
    assert base != _draft(view="arm64", hit=_hit(stub_hex="01180000c0035fd6", view="arm64"))["name"]
    assert base != _draft(_hit(stub_hex="4c8bd1b8180000000f05" + "90"))["name"]
    assert base.startswith("TDC_DirectSyscall_NtAllocateVirtualMemory_x64_")


def test_the_rule_for_an_arm64_stub_carries_the_view():
    d = _draft(_hit(syscall="NtWriteVirtualMemory", number=0x3A, view="arm64", stub_hex="41070000c0035fd6"),
               view="arm64")
    _assert_well_formed(d)
    assert 'os_view     = "arm64"' in d["text"] and "_arm64_" in d["name"]
    assert "$stub = { 41 07 00 00 C0 03 5F D6 }" in d["text"]


def test_a_proven_bypass_is_high_and_anything_else_medium():
    assert 'severity    = "high"' in _draft(_hit(import_present=False))["text"]
    for present in (None, True):
        assert 'severity    = "medium"' in _draft(_hit(import_present=present))["text"]


def test_a_number_the_build_does_not_have_still_makes_a_rule_and_says_so():
    d = _draft(_hit(syscall=None, number=0x1234, number_known=False))
    _assert_well_formed(d)
    assert "Number0x1234" in d["name"]
    assert "which Windows 26220.5770 does not number" in d["text"]


@pytest.mark.parametrize("name", [
    'a"b', 'a\\b', "a\nb", "a*/b", 'x" or true //', "ä" * 300,
    "x\r\n    condition:\r\n        true\r\n}\r\nrule Evil { condition: true", '" } rule Evil { condition: true //',
    "a\x00b", "\u202eexe.txt", "$stub", "a{b}c", "/* c */", "x" * 10000, "\\\\?\\C:\\Users\\a\\b.exe",
], ids=lambda n: repr(n)[:24])
def test_a_sample_name_cannot_break_the_draft(name):
    d = syscall_rules.draft_yara(_hit(sample=name), "26220.5770", "x64", "direct_syscall_stub")
    _assert_well_formed(d)
    assert d["text"].count("{") == d["text"].count("}")
    assert "Evil" not in d["name"]
    note = re.search(r'note        = "(.*)"', d["text"]).group(1)
    assert len(note) < 400


def test_a_sample_name_is_capped_and_reduced_to_printable_ascii():
    d = _draft(_hit(sample='C:\\Users\\"x"\\' + "ä" * 300))
    sample = re.search(r" in (.*?)\. Matches", d["text"]).group(1)
    assert sample.startswith("C:_Users__x__") and len(sample) == syscall_rules.TEXT_MAX
    assert set(sample) <= set("C:_Usersx")
    assert "ä" not in d["text"] and "\\" not in d["text"]
    assert syscall_rules.clean("a" * 500) == "a" * 120
    assert syscall_rules.clean(None) == "" and syscall_rules.clean(b"\xff") == "b__xff_"


@pytest.mark.parametrize("over", [
    {"source": 'x"\n}\nrule Evil{'}, {"source": "s" * 5000}, {"source": None}, {"source": 7},
])
def test_the_source_label_cannot_break_the_draft_either(over):
    _assert_well_formed(_draft(**over))


@pytest.mark.parametrize("build", ['26220"5770', "26220\n.5770", "", "a" * 33, "26220.5770 ", None, 26220])
def test_a_build_that_is_not_a_build_is_refused(build):
    with pytest.raises(ValueError):
        _draft(build=build)


@pytest.mark.parametrize("view", ["", "arm", "x64\n", None, 64, "X64"])
def test_a_view_that_is_not_a_view_is_refused(view):
    with pytest.raises(ValueError):
        _draft(view=view)


@pytest.mark.parametrize("over", [
    {"syscall": 'Nt"Evil'}, {"syscall": "Nt Evil"}, {"syscall": "1Nt"}, {"syscall": "N" * 65}, {"syscall": 7},
    {"number": -1}, {"number": 2 ** 32}, {"number": "24"}, {"number": True}, {"number": None},
    {"offset": "0x10"}, {"offset": -4},
    {"stub_hex": None}, {"stub_hex": ""}, {"stub_hex": "4c8b"}, {"stub_hex": "zz" * 10}, {"stub_hex": "4c8bd1b8180000000f0"},
    {"stub_hex": "90" * 65}, {"stub_hex": 4}, {"stub_hex": "4c8bd1b8 180000000f05"},
])
def test_a_hit_that_cannot_make_a_rule_is_refused(over):
    with pytest.raises(ValueError):
        _draft(_hit(**over))


def test_a_hit_without_bytes_is_refused_not_drafted_empty():
    hit = _hit()
    del hit["stub_hex"]
    with pytest.raises(ValueError, match="no stub bytes"):
        _draft(hit)
    with pytest.raises(ValueError):
        _draft("4c8bd1b8")


def test_check_draft_takes_only_what_draft_yara_writes():
    d = _draft()
    assert syscall_rules.check_draft(d) == (d["name"], d["text"])
    evil_rule = d["text"] + d["text"].replace(d["name"], "TDC_DirectSyscall_Other")
    tampered = {
        "a second rule": evil_rule,
        "an include": 'include "C:/x.yar"\n' + d["text"],
        "a condition of its own": d["text"].replace("        $stub\n}", "        true\n}"),
        "a quote in a string": d["text"].replace('os_view     = "x64"', 'os_view     = "x64" "'),
        "a longer author": d["text"].replace('"DetonationChamber"', '"DetonationChamber2"'),
        "a hex string that is a regex": d["text"].replace("{ 4C", "{ [0-500] 4C"),
        "a missing newline": d["text"][:-1],
        "a trailing rule": d["text"] + "rule X { condition: true }\n",
        "a carriage return": d["text"].replace("\n", "\r\n"),
        "another name": d["text"].replace(d["name"], d["name"] + "x"),
        "huge": d["text"] + " " * 5000,
    }
    for why, text in tampered.items():
        with pytest.raises(ValueError):
            syscall_rules.check_draft({"name": d["name"], "text": text})
        assert why
    for bad_name in ("../x", "x" + d["name"], d["name"] + "/..", "", None, 4, "TDC_DirectSyscall_"):
        with pytest.raises(ValueError):
            syscall_rules.check_draft({"name": bad_name, "text": d["text"]})
    for bad in (None, [], "rule", {"name": d["name"]}, {"text": d["text"]}):
        with pytest.raises(ValueError):
            syscall_rules.check_draft(bad)
    # a name and a text that agree, in the exact form, and too long for libyara: 18 + 150 characters
    long_name = "TDC_DirectSyscall_" + "A" * 150
    with pytest.raises(ValueError):
        syscall_rules.check_draft({"name": long_name, "text": d["text"].replace(d["name"], long_name)})


def test_apply_writes_one_file_that_is_the_drafted_text_byte_for_byte(tmp_path):
    d = _draft()
    out = syscall_rules.apply_draft(d, str(tmp_path))
    assert out == {"status": "written", "name": d["name"], "path": str(tmp_path / (d["name"] + ".yar")),
                   "reload_seconds": 2}
    assert [p.name for p in tmp_path.iterdir()] == [d["name"] + ".yar"]
    assert (tmp_path / (d["name"] + ".yar")).read_bytes() == d["text"].encode("ascii")


def test_apply_leaves_a_rule_that_is_already_there_alone(tmp_path):
    d = _draft()
    (tmp_path / (d["name"] + ".yar")).write_text("rule mine { condition: true }\n")
    out = syscall_rules.apply_draft(d, str(tmp_path))
    assert out["status"] == "exists"
    assert (tmp_path / (d["name"] + ".yar")).read_text() == "rule mine { condition: true }\n"
    assert [p.name for p in tmp_path.iterdir()] == [d["name"] + ".yar"]


def test_apply_creates_its_own_directory_but_not_the_detection_install(tmp_path):
    out = syscall_rules.apply_draft(_draft(), str(tmp_path / "tdc"))
    assert out["status"] == "written" and (tmp_path / "tdc").is_dir()
    with pytest.raises(FileNotFoundError, match="not installed"):
        syscall_rules.apply_draft(_draft(), str(tmp_path / "absent" / "tdc"))
    assert not (tmp_path / "absent").exists()


def test_apply_refuses_a_draft_that_is_not_ours_before_it_writes(tmp_path):
    with pytest.raises(ValueError):
        syscall_rules.apply_draft({"name": _draft()["name"], "text": "rule x { condition: true }\n"}, str(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_a_failed_write_leaves_neither_the_rule_nor_a_temporary_file(tmp_path, monkeypatch):
    def refuse(src, dst):
        raise PermissionError("denied")
    monkeypatch.setattr(syscall_rules.os, "replace", refuse)
    with pytest.raises(PermissionError):
        syscall_rules.apply_draft(_draft(), str(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_the_temporary_file_is_not_a_rule_file(tmp_path, monkeypatch):
    seen = []
    real = syscall_rules.os.replace
    monkeypatch.setattr(syscall_rules.os, "replace", lambda s, d: seen.append(os.path.basename(s)) or real(s, d))
    syscall_rules.apply_draft(_draft(), str(tmp_path))
    assert seen and not seen[0].endswith((".yar", ".yara"))


# --- the catalog -------------------------------------------------------------------------------

def test_the_bundled_catalog_loads_whole_and_stays_under_malicious():
    sigs = syscall_rules.default_signatures()
    raw = json.load(open(syscall_rules.DEFAULT_SIGNATURES_PATH, encoding="utf-8"))
    assert len(sigs) == len(raw) > 0
    assert {s["view"] for s in sigs} == {"x64", "arm64"}
    assert {s["family"] for s in sigs} == {"Inline hook", "Stub patch"}
    assert all(0 <= s["weight"] <= syscall_rules.MAX_SIGNATURE_WEIGHT < memory_evidence.VERDICT_MALICIOUS
               for s in sigs)
    assert syscall_rules.MAX_SIGNATURE_WEIGHT == memory_evidence.VERDICT_MALICIOUS - 1.0
    assert syscall_rules.default_signatures() is sigs


def test_the_catalog_skips_what_it_cannot_use_and_says_so(tmp_path, capsys):
    p = tmp_path / "s.json"
    p.write_text(json.dumps([
        "text", {"family": "A", "pattern": "e9", "match": "prefix", "weight": 1, "note": "ok"},
        {"family": "B", "pattern": "e9", "match": "wildcard", "weight": 1},
        {"family": "C", "pattern": "", "match": "prefix", "weight": 1},
        {"family": "D", "pattern": "e9", "match": "prefix", "weight": "heavy"},
        {"family": "E", "pattern": "e9", "match": "prefix", "weight": True},
        {"family": "F", "pattern": "e9", "match": "prefix"},
        {"family": "G", "pattern": "e9", "match": "prefix", "weight": 1, "view": "mips"},
        {"family": "H", "pattern": "e9x", "match": "prefix", "weight": 1},
        {"family": "I", "pattern": "e", "match": "prefix", "weight": 1},
        {"family": "J", "pattern": "[", "match": "regex", "weight": 1},
        {"family": "K", "pattern": "^e9", "match": "regex", "weight": -5, "view": "x64"},
        {"pattern": "c3", "match": "exact", "weight": 2},
    ]))
    sigs = syscall_rules.load_signatures(str(p))
    assert [(s["family"], s["weight"], s.get("view")) for s in sigs] == [
        ("A", 1.0, None), ("K", 0.0, "x64"), ("unknown", 2.0, None)]
    out = capsys.readouterr().out
    assert out.count("skipping") == 10 and "clamped" in out


@pytest.mark.parametrize("content", ["{not json", '{"a": 1}', "null", ""])
def test_a_catalog_that_cannot_be_read_is_empty_not_fatal(tmp_path, content):
    p = tmp_path / "s.json"
    p.write_text(content)
    assert syscall_rules.load_signatures(str(p)) == []
    assert syscall_rules.load_signatures(str(tmp_path / "absent.json")) == []


# a hook of each shape, as bytes; `syscall_baseline` is what classifies them in a scan, so what it calls a hook
# the catalog must call one too
_HOOK_BYTES = {
    "x64": {
        "JMP rel32": "e9" "10000000",
        "JMP [rip]": "ff25" "20000000",
        "MOV RAX; JMP RAX": "48b8" "1122334455667788" "ffe0",
        "MOV R11; JMP R11": "49bb" "1122334455667788" "41ffe3",
        "PUSH; RET": "68" "11223344" "c3",
    },
    "arm64": {
        "B": "10000014",
        "LDR x16; BR x16": "50000058" "00021fd6",
        "ADRP; ADD; BR": "10000090" "10420091" "00021fd6",
    },
}


@pytest.mark.parametrize("view,name", [(v, n) for v, hooks in _HOOK_BYTES.items() for n in hooks])
def test_the_catalog_knows_every_hook_the_classifier_knows(view, name):
    live = _HOOK_BYTES[view][name] + "00" * 16
    assert syscall_baseline._find_hook(bytes.fromhex(live), 0, view)[0] == name
    found = syscall_rules.matching(live, view)
    assert [s["family"] for s in found] == ["Inline hook"], (name, found)


def test_a_view_keeps_its_patterns_to_itself():
    assert syscall_rules.matching("e9" + "00" * 8, "x64")
    assert not syscall_rules.matching("e9" + "00" * 8, "arm64")
    arm_b = "10000014" + "00" * 8
    assert syscall_rules.matching(arm_b, "arm64") and not syscall_rules.matching(arm_b, "x64")


@pytest.mark.parametrize("view,live", [
    ("x64", "c3" + "00" * 8), ("x64", "31c0c3" + "00" * 8), ("x64", "33c0c3"), ("x64", "b800000000c3"),
    ("arm64", "c0035fd6"), ("arm64", "00008052c0035fd6"), ("arm64", "000080d2c0035fd6"),
])
def test_the_catalog_knows_a_neutralised_stub(view, live):
    assert [s["family"] for s in syscall_rules.matching(live, view)] == ["Stub patch"]


@pytest.mark.parametrize("view,live", [
    ("x64", "4c8bd1b8180000000f05"), ("x64", "4c8bd1b8" + "00" * 20), ("arm64", "41070000c0035fd6"),
    ("arm64", "01180000c0035fd6"),
])
def test_an_intact_stub_matches_nothing(view, live):
    assert syscall_rules.matching(live, view) == []


def _dev(**over):
    dev = {"state": "patched", "pattern": None, "target_owner": "private", "expected": "4c8bd1b8180000000f05",
           "actual": "CC90909090000000000F", "number_matches": None, "name": "NtAllocateVirtualMemory",
           "module": "ntdll.dll", "number": 0x18, "rva": 0x1000, "allowlisted": False}
    dev.update(over)
    return dev


def test_a_signature_is_drafted_from_the_live_bytes_and_says_what_to_check():
    e = syscall_rules.draft_signature(_dev(), view="x64")
    assert e["family"] == "Stub patch" and e["match"] == "prefix" and e["pattern"] == "cc909090"
    assert e["view"] == "x64" and 0 < e["weight"] <= syscall_rules.MAX_SIGNATURE_WEIGHT
    assert "NtAllocateVirtualMemory" in e["note"] and "private" in e["note"] and "replace" in e["note"]


def test_a_drafted_signature_loads_back_through_the_loader(tmp_path):
    for dev in (_dev(), _dev(state="hooked", target_owner="edr.dll", actual="e91122334400"),
                _dev(state="diverged", number_matches=False)):
        entry = syscall_rules.draft_signature(dev, view="arm64")
        p = tmp_path / "s.json"
        p.write_text(json.dumps([entry]))
        assert syscall_rules.load_signatures(str(p)) == [entry]


def test_a_hooked_stub_is_an_inline_hook_and_weighs_less_than_a_patch():
    hooked = syscall_rules.draft_signature(_dev(state="hooked", target_owner="edr.dll"))
    patched = syscall_rules.draft_signature(_dev(state="patched"))
    assert hooked["family"] == "Inline hook" and "view" not in hooked
    assert hooked["weight"] < patched["weight"] <= syscall_rules.MAX_SIGNATURE_WEIGHT


def test_a_signature_says_when_the_number_differs():
    assert "number differs" in syscall_rules.draft_signature(_dev(number_matches=False))["note"]
    assert "number differs" not in syscall_rules.draft_signature(_dev(number_matches=True))["note"]


@pytest.mark.parametrize("dev,why", [
    (_dev(state="intact"), "only"), (_dev(state="unreadable", actual=None), "only"), (_dev(state="bogus"), "only"),
    (_dev(state="hooked", allowlisted=True), "known on this host"),
    (_dev(actual=None), "no bytes"), (_dev(actual=""), "no bytes"), (_dev(actual="zz"), "no bytes"),
    (_dev(actual="a" * 300), "no bytes"), ("x", "object"),
])
def test_a_deviation_that_is_no_detection_is_refused(dev, why):
    with pytest.raises(ValueError, match=why):
        syscall_rules.draft_signature(dev)


def test_a_module_name_from_a_sample_cannot_break_a_signature_note():
    e = syscall_rules.draft_signature(_dev(target_owner='evil"\n\\.dll' + "x" * 500, name='N"t', module="*/"))
    assert '"' not in e["note"] and "\n" not in e["note"] and "\\" not in e["note"] and "*/" not in e["note"]
    assert len(e["note"]) < 400


# --- the rule routes ----------------------------------------------------------------------------

@pytest.fixture
def rules_dir(tdc, monkeypatch, tmp_path):
    directory = tmp_path / "yara-combined" / "tdc"
    directory.parent.mkdir()
    monkeypatch.setattr(tdc, "YARA_RULES_DIR", str(directory))
    return directory


def _files(directory):
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


def test_rule_route_drafts_without_writing(client, tdc, tmp_path, monkeypatch):
    # the `tdc` fixture keeps its own logs in tmp_path, so the rules get a directory of their own
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setattr(tdc, "YARA_RULES_DIR", str(rules))
    body = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    assert "rule " in body["text"]
    assert list(rules.iterdir()) == []


def test_apply_route_writes_once(client, tdc, tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setattr(tdc, "YARA_RULES_DIR", str(rules))
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    assert client.post("/api/syscalls/rule/apply", json=draft).status_code == 200
    assert len(list(rules.iterdir())) == 1


def test_the_draft_route_makes_the_same_draft_the_module_does(client, rules_dir):
    r = client.post("/api/syscalls/rule", json=_hit_payload())
    assert r.status_code == 200
    body = r.get_json()
    _assert_well_formed(body)
    assert body["kind"] == "yara" and body["target"] == body["name"] + ".yar"
    assert 'os_build    = "26220.5770"' in body["text"] and 'os_view     = "x64"' in body["text"]
    assert "in evil.exe" in body["text"]
    assert _files(rules_dir) == []


def test_the_draft_route_does_not_even_create_the_directory(client, rules_dir):
    assert not rules_dir.exists()
    client.post("/api/syscalls/rule", json=_hit_payload())
    assert not rules_dir.exists()


def test_the_view_comes_from_the_request_or_the_hit_and_never_from_this_host(client, tdc, rules_dir, monkeypatch):
    monkeypatch.setattr(tdc, "_syscall_default_view", lambda: "arm64")
    body = _hit_payload()
    del body["view"]
    assert 'os_view     = "x64"' in client.post("/api/syscalls/rule", json=body).get_json()["text"]
    body["hit"] = {k: v for k, v in body["hit"].items() if k != "view"}
    r = client.post("/api/syscalls/rule", json=body)
    assert r.status_code == 400 and "view" in r.get_json()["error"]
    assert client.post("/api/syscalls/rule", json=_hit_payload(view="arm64")).status_code == 400


def test_the_build_defaults_to_this_systems_and_is_asked_for_when_unknown(client, tdc, rules_dir, monkeypatch):
    monkeypatch.setattr(tdc, "_current_os_build", lambda: "26100.4")
    body = _hit_payload()
    del body["build"]
    assert 'os_build    = "26100.4"' in client.post("/api/syscalls/rule", json=body).get_json()["text"]
    monkeypatch.setattr(tdc, "_current_os_build", lambda: None)
    r = client.post("/api/syscalls/rule", json=body)
    assert r.status_code == 400 and "build" in r.get_json()["error"]


@pytest.mark.parametrize("body,why", [
    ({}, "give a hit"),
    ({"hit": _hit(), "deviation": _dev(), "build": BUILD, "view": "x64"}, "give a hit"),
    ({"hit": "4c8b", "build": BUILD, "view": "x64"}, "object"),
    ({"hit": {k: v for k, v in _hit().items() if k != "stub_hex"}, "build": BUILD, "view": "x64"}, "stub bytes"),
    ({"hit": _hit(), "build": 'x"y', "view": "x64"}, "build"),
    ({"hit": _hit(syscall='N"t'), "build": BUILD, "view": "x64"}, "syscall"),
    ({"deviation": _dev(state="intact"), "view": "x64"}, "only"),
])
def test_the_draft_route_refuses_what_cannot_make_a_rule(client, rules_dir, body, why):
    r = client.post("/api/syscalls/rule", json=body)
    assert r.status_code == 400 and why in r.get_json()["error"]
    assert not rules_dir.exists()


def test_the_draft_route_takes_no_json_array_and_no_form_of_a_hit(client, rules_dir):
    assert client.post("/api/syscalls/rule", json=[1, 2]).status_code == 400
    assert client.post("/api/syscalls/rule", data={"hit": "x"}).status_code == 400


@pytest.mark.parametrize("name", ['a"b', "a\nb", "a*/b", 'x" or true //', "ä" * 300, "}\nrule Evil {condition: true"], ids=lambda n: repr(n)[:24])
def test_a_hostile_sample_name_through_the_routes_writes_a_sound_rule(client, rules_dir, name):
    draft = client.post("/api/syscalls/rule", json=_hit_payload(hit=_hit(sample=name))).get_json()
    _assert_well_formed(draft)
    assert client.post("/api/syscalls/rule/apply", json=draft).status_code == 200
    (written,) = rules_dir.iterdir()
    assert written.read_text() == draft["text"]
    _assert_well_formed({"name": written.stem, "text": written.read_text()})


def test_apply_route_reports_the_file_and_that_the_engine_reloads_by_itself(client, rules_dir):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    body = client.post("/api/syscalls/rule/apply", json=draft).get_json()
    assert body["status"] == "written" and body["reload_seconds"] == 2
    assert body["path"] == str(rules_dir / (draft["name"] + ".yar"))
    assert _files(rules_dir) == [draft["name"] + ".yar"]


def test_applying_twice_is_a_conflict_that_changes_nothing(client, rules_dir):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    assert client.post("/api/syscalls/rule/apply", json=draft).status_code == 200
    before = (rules_dir / (draft["name"] + ".yar")).read_bytes()
    again = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    r = client.post("/api/syscalls/rule/apply", json=again)
    assert r.status_code == 409 and r.get_json()["status"] == "exists"
    assert (rules_dir / (draft["name"] + ".yar")).read_bytes() == before
    assert len(_files(rules_dir)) == 1


@pytest.mark.parametrize("make", [
    lambda d: {**d, "text": d["text"] + d["text"]},
    lambda d: {**d, "text": 'include "C:/Windows/x.yar"\n' + d["text"]},
    lambda d: {**d, "text": d["text"].replace("$stub\n}", "true\n}")},
    lambda d: {**d, "name": "../../evil", "text": d["text"].replace(d["name"], "../../evil")},
    lambda d: {**d, "name": "TDC_DirectSyscall_x/../../evil"},
    lambda d: {"name": d["name"]}, lambda d: {"text": d["text"]}, lambda d: {},
    lambda d: {**d, "name": ["x"]},
])
def test_apply_route_refuses_a_draft_that_is_not_one_of_ours(client, rules_dir, make):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    r = client.post("/api/syscalls/rule/apply", json=make(draft))
    assert r.status_code == 400 and "error" in r.get_json()
    assert _files(rules_dir) == [] and not rules_dir.exists()


def test_apply_route_writes_nowhere_but_the_rules_directory(client, tdc, rules_dir, tmp_path):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    outside = tmp_path / "outside.yar"
    outside.write_text("untouched")
    rules_dir.mkdir()
    link = rules_dir / (draft["name"] + ".yar")
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("no symlinks here")
    r = client.post("/api/syscalls/rule/apply", json=draft)
    assert r.status_code == 403
    assert outside.read_text() == "untouched"


def test_the_rules_directory_is_the_one_writable_root_this_adds(tdc):
    assert tdc.YARA_RULES_DIR == r"C:\tools\detection-rules\yara-combined\tdc"


def test_apply_route_says_so_when_the_detection_rules_are_not_installed(client, tdc, tmp_path, monkeypatch):
    monkeypatch.setattr(tdc, "YARA_RULES_DIR", str(tmp_path / "absent" / "tdc"))
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    r = client.post("/api/syscalls/rule/apply", json=draft)
    assert r.status_code == 500 and "not installed" in r.get_json()["error"]
    assert not (tmp_path / "absent").exists()


def test_apply_route_reports_a_directory_it_cannot_write(client, tdc, rules_dir, monkeypatch):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()

    def refuse(draft, directory):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(tdc.syscall_rules, "apply_draft", refuse)
    r = client.post("/api/syscalls/rule/apply", json=draft)
    assert r.status_code == 500 and "Permission denied" in r.get_json()["error"]


def test_download_gives_the_drafted_text_as_a_file(client, rules_dir):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    r = client.get("/api/syscalls/rule/download", query_string={"name": draft["name"], "text": draft["text"]})
    assert r.status_code == 200
    assert r.data.decode() == draft["text"]
    assert r.headers["Content-Disposition"] == f'attachment; filename="{draft["name"]}.yar"'
    assert r.mimetype == "text/plain" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert _files(rules_dir) == [] and not rules_dir.exists()


@pytest.mark.parametrize("query", [
    {}, {"name": "TDC_DirectSyscall_x"}, {"text": "rule x { condition: true }"},
    {"name": "x\r\nSet-Cookie: a=b", "text": "x"}, {"name": 'TDC_DirectSyscall_x".yar', "text": "x"},
])
def test_download_hands_back_nothing_that_is_not_a_draft_of_ours(client, query):
    r = client.get("/api/syscalls/rule/download", query_string=query)
    assert r.status_code == 400 and "error" in r.get_json()
    assert "Content-Disposition" not in r.headers


def test_the_rule_routes_are_behind_the_cross_site_check_and_the_maintenance_gate(client, tdc, rules_dir,
                                                                                 monkeypatch):
    draft = client.post("/api/syscalls/rule", json=_hit_payload()).get_json()
    posts = (("/api/syscalls/rule", _hit_payload()), ("/api/syscalls/rule/apply", draft))
    for path, body in posts:
        assert client.post(path, json=body, headers={"Origin": "http://evil.example"}).status_code == 403, path
        assert client.post(path, json=body, headers={"Host": "evil.example"}).status_code == 403, path
    assert _files(rules_dir) == []

    class Busy:
        maintenance = True

    monkeypatch.setattr(tdc, "_update_manager", Busy())
    for path, body in posts:
        r = client.post(path, json=body)
        assert r.status_code == 503 and r.get_json()["maintenance"] is True, path
    assert _files(rules_dir) == []


def test_the_rule_routes_take_the_methods_they_name(client):
    assert client.get("/api/syscalls/rule/apply").status_code == 405
    assert client.post("/api/syscalls/rule/download").status_code == 405
    assert client.delete("/api/syscalls/rule/apply").status_code == 405


# a deviation, drafted into a signature

def test_a_deviation_is_drafted_into_a_signature_and_nothing_is_written(client, rules_dir, tdc):
    body = client.post("/api/syscalls/rule", json={"deviation": _dev(), "view": "x64"}).get_json()
    assert body["kind"] == "signature" and body["target"] == "webui/syscall_signatures.json"
    assert body["entry"]["view"] == "x64" and body["entry"]["pattern"] == "cc909090"
    assert json.loads(body["text"]) == body["entry"] and body["covered_by"] == []
    assert not rules_dir.exists() and not os.path.exists(tdc.SYSCALL_HOOK_ALLOWLIST_FILE)


def test_a_signature_says_which_entries_of_the_catalog_already_cover_it(client):
    dev = _dev(state="hooked", target_owner="edr.dll", actual="e9" + "11223344" + "00" * 4)
    body = client.post("/api/syscalls/rule", json={"deviation": dev, "view": "x64"}).get_json()
    assert [(c["family"], c["pattern"]) for c in body["covered_by"]] == [("Inline hook", "e9")]
    other = client.post("/api/syscalls/rule", json={"deviation": dev, "view": "arm64"}).get_json()
    assert other["covered_by"] == []


def test_a_signature_needs_its_view(client):
    r = client.post("/api/syscalls/rule", json={"deviation": _dev()})
    assert r.status_code == 400 and "view" in r.get_json()["error"]


def test_a_hook_this_host_knows_is_not_drafted_into_a_signature(client, tdc, fake_baseline_dir):
    allowlist = tdc._get_hook_allowlist()
    allowlist.add_from({"build": BUILD, "view": "x64", "deviations": [
        _dev(state="hooked", target_owner="edr.dll", name="NtAllocateVirtualMemory")]})
    dev = _dev(state="hooked", target_owner="edr.dll", actual="e911223344")
    r = client.post("/api/syscalls/rule", json={"deviation": dev, "view": "x64", "build": BUILD})
    assert r.status_code == 400 and "known on this host" in r.get_json()["error"]
    # the flag a browser sets for itself is not what decides
    r = client.post("/api/syscalls/rule", json={"deviation": {**dev, "allowlisted": False}, "view": "x64",
                                                "build": BUILD})
    assert r.status_code == 400
    # another build's list says nothing about this one
    r = client.post("/api/syscalls/rule", json={"deviation": dev, "view": "x64", "build": "26100.1"})
    assert r.status_code == 200


def test_a_signature_draft_cannot_be_applied_or_downloaded_as_a_rule(client, rules_dir):
    body = client.post("/api/syscalls/rule", json={"deviation": _dev(), "view": "x64"}).get_json()
    assert client.post("/api/syscalls/rule/apply", json=body).status_code == 400
    r = client.get("/api/syscalls/rule/download", query_string={"name": body.get("name"), "text": body["text"]})
    assert r.status_code == 400
    assert not rules_dir.exists()


def test_a_rule_route_does_not_swallow_the_catalog_name_route(client, fake_baseline_dir):
    assert client.get("/api/syscalls/NtAllocateVirtualMemory?view=arm64").status_code == 200
    assert client.get("/api/syscalls/rule").status_code == 404


@pytest.mark.skipif(shutil.which("yara") is None, reason="no yara binary here; CI has none")
@pytest.mark.parametrize("name", ['a"b', "a\nb", "a*/b", "ä" * 300, "}\nrule Evil {condition: true", "x" * 9000],
                         ids=lambda n: repr(n)[:24])
def test_the_real_yara_compiles_a_draft_and_finds_the_stub(tmp_path, name):
    d = _draft(_hit(sample=name))
    rule = tmp_path / (d["name"] + ".yar")
    rule.write_text(d["text"])
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\x90" * 40 + bytes.fromhex("4c8bd1b8180000000f05") + b"\x00" * 40)
    out = subprocess.run(["yara", "-m", str(rule), str(target)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith(d["name"] + " [") and 'os_view="x64"' in out.stdout
    other = tmp_path / "other.bin"
    other.write_bytes(b"MZ" + bytes.fromhex("4c8bd1b8190000000f05"))
    assert subprocess.run(["yara", str(rule), str(other)], capture_output=True, text=True).stdout == ""


@pytest.mark.parametrize("over", [{"view": {"a": 1}}, {"view": ["x64"]}, {"view": 64}, {"view": "mips"},
                                  {"build": ["26220.5770"]}, {"build": {"a": 1}}, {"build": 26220}])
def test_a_view_or_build_of_the_wrong_type_is_a_refusal_not_a_crash(client, rules_dir, over):
    for body in (_hit_payload(**over), {"deviation": _dev(state="hooked", actual="e911223344"), "view": "x64",
                                         "build": BUILD, **over}):
        r = client.post("/api/syscalls/rule", json=body)
        assert r.status_code == 400 and "error" in r.get_json()


# --- review fixes: the name libyara takes, the temporary file, what the catalog says of itself, the pin both ways --

def _forged(length):
    """A draft of the exact form with a name of `length` characters, as a forged request body would bring one."""
    d = _draft()
    name = "TDC_DirectSyscall_" + "A" * (length - len("TDC_DirectSyscall_"))
    return {"name": name, "text": d["text"].replace(d["name"], name)}


def test_the_name_of_a_rule_is_at_most_what_libyara_takes_and_the_generator_never_nears_it():
    assert syscall_rules.RULE_NAME_MAX == 128
    assert syscall_rules.check_draft(_forged(128))
    for length in (129, 150, 178):
        with pytest.raises(ValueError):
            syscall_rules.check_draft(_forged(length))
    # the longest the generator makes: a name of 64 characters, and the longest view
    longest = syscall_rules.draft_yara(_hit(syscall="N" * 64, view="arm64", stub_hex="41070000c0035fd6"),
                                       BUILD, "arm64", "s")
    assert len(longest["name"]) <= 128 and len(longest["name"]) == 18 + 64 + 1 + 5 + 1 + 8


def test_a_forged_apply_with_a_name_too_long_for_libyara_writes_nothing(client, rules_dir):
    r = client.post("/api/syscalls/rule/apply", json=_forged(150))
    assert r.status_code == 400
    assert not rules_dir.exists()


def test_a_link_planted_where_the_temporary_file_used_to_be_named_is_not_followed(tmp_path):
    d = _draft()
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    try:
        os.symlink(outside, tmp_path / ("." + d["name"] + ".tmp"))
    except (OSError, NotImplementedError):
        pytest.skip("no symlinks here")
    rules = tmp_path
    assert syscall_rules.apply_draft(d, str(rules))["status"] == "written"
    assert outside.read_text() == "untouched"
    assert (rules / (d["name"] + ".yar")).read_text() == d["text"]


def test_the_temporary_file_has_a_name_nobody_can_foresee_and_two_applies_do_not_share_it(tmp_path, monkeypatch):
    seen = []
    real = syscall_rules.os.replace
    monkeypatch.setattr(syscall_rules.os, "replace", lambda s, t: seen.append(os.path.basename(s)) or real(s, t))
    for i in range(2):
        d = _draft(_hit(stub_hex="4c8bd1b8180000000f05" + "90" * i))
        syscall_rules.apply_draft(d, str(tmp_path))
        assert seen[-1] != "." + d["name"] + ".tmp" and seen[-1].startswith(".") and seen[-1].endswith(".tmp")
    assert seen[0] != seen[1]


def test_the_signature_file_is_documented_as_advisory_where_it_cannot_say_so_itself():
    raw = open(syscall_rules.DEFAULT_SIGNATURES_PATH, encoding="utf-8").read()
    assert raw.lstrip().startswith("[")           # a bare array, as pipe_signatures.json is; JSON has no comment
    module, loader = (" ".join(t.split()) for t in (syscall_rules.__doc__, syscall_rules.load_signatures.__doc__))
    for text in (module, loader):
        assert "advisory" in text and "not the score" in text and "memory_evidence.KINDS" in text
    assert "in both directions" in module and "classify_stub" in module


# Neutralised stubs, as bytes. The classifier does not know them as a jump, only as a stub that is not the baseline's
_PATCH_BYTES = {
    "x64": ["c3", "31c0c3", "33c0c3", "b800000000c3"],
    "arm64": ["c0035fd6", "00008052c0035fd6", "000080d2c0035fd6"],
}


@pytest.mark.parametrize("view", ["x64", "arm64"])
def test_every_entry_of_the_catalog_is_one_the_code_recognises(view):
    """The pin in the other direction: each entry of this view must match an example the code itself classifies. An
    entry that is added without one, or one that matches only bytes the classifier calls intact, fails here."""
    baseline = syscall_baseline.parse_baseline(_fixture(view), BUILD, view)
    sc = baseline.syscalls["NtAllocateVirtualMemory"]
    read = syscall_baseline.READ_LEN[view]
    pad = "90" * read
    hooks = {n: h + "00" * 8 for n, h in _HOOK_BYTES[view].items()}
    patches = {f"patch {i}": b for i, b in enumerate(_PATCH_BYTES[view])}
    entries = [s for s in syscall_rules.default_signatures() if s.get("view") == view]
    assert entries
    for entry in entries:
        proof = []
        for label, live in {**hooks, **patches}.items():
            if not syscall_rules.matching(live, view, [entry]):
                continue
            data = bytes.fromhex((live + pad)[:2 * read])
            jump = syscall_baseline._find_hook(data, 0, view)
            # the scanner names an owner only for a jump it can follow; a patch has none
            owner = "edr.dll" if jump is not None else None
            state = syscall_baseline.classify_stub(sc, data, view, owner)["state"]
            if entry["family"] == "Inline hook":
                ok = jump is not None and jump[0] == label and state == "hooked"
            else:
                ok = jump is None and state == "diverged"
            proof.append((label, ok))
        assert proof, f"no example the code classifies matches {entry}"
        assert all(ok for _, ok in proof), (entry, proof)


def test_an_entry_of_the_catalog_without_a_code_backed_example_is_caught(tmp_path):
    """The check above has teeth: an entry for a form no example covers has no proof, and a patch pattern that
    matches the baseline's own intact stub would be classified intact."""
    view = "x64"
    baseline = syscall_baseline.parse_baseline(_fixture(view), BUILD, view)
    sc = baseline.syscalls["NtAllocateVirtualMemory"]
    stray = {"family": "Stub patch", "pattern": "4c8bd1b8", "match": "prefix", "weight": 3.0, "view": view}
    live = sc.stub_bytes[:syscall_baseline.READ_LEN[view]]
    assert syscall_rules.matching(live.hex(), view, [stray])
    assert syscall_baseline.classify_stub(sc, live, view, None)["state"] == "intact"
    unknown = {"family": "Inline hook", "pattern": "cd2e", "match": "prefix", "weight": 1.0, "view": view}
    assert not any(syscall_rules.matching(h + "00" * 8, view, [unknown]) for h in _HOOK_BYTES[view].values())


def test_a_hex_write_into_the_rules_directory_is_refused(client, tdc, rules_dir):
    rules_dir.mkdir()
    rule = rules_dir / "TDC_DirectSyscall_x.yar"
    rule.write_bytes(b"rule x { condition: true }\n")
    r = client.post("/api/file/hex/write", json={"path": str(rule), "offset": 0, "bytes": [0x52]})
    assert r.status_code == 403
    assert rule.read_bytes() == b"rule x { condition: true }\n"


@pytest.mark.skipif(shutil.which("yara") is None, reason="no yara binary here; CI has none")
def test_the_real_yara_takes_the_longest_name_check_draft_lets_through(tmp_path):
    forged = _forged(syscall_rules.RULE_NAME_MAX)
    rule = tmp_path / "long.yar"
    rule.write_text(syscall_rules.check_draft(forged)[1])
    assert subprocess.run(["yara", str(rule), str(rule)], capture_output=True, text=True).returncode == 0
    over = tmp_path / "over.yar"
    over.write_text(_forged(129)["text"])
    refused = subprocess.run(["yara", str(over), str(over)], capture_output=True, text=True)
    assert refused.returncode != 0 and "identifier too long" in refused.stderr
