"""NTSleuth syscall baseline: loading, validation and the lookup catalog."""

import json
import os

import pytest

import syscall_baseline

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
