"""The import graph of the system binaries, and the curated Win32 to Nt table under it."""

import json
import os
import re

import pytest

import memory_evidence
import syscall_baseline
import syscall_scan
import win32_to_nt
from test_syscalls import (_PRIVATE_BASE, _X64_STUB_0x3A, _fixture, _pe_importing, _x64_space,  # noqa: F401
                           sample_dir, target)


# --- the curated Win32 to Nt table --------------------------------------------------------

def test_the_table_maps_the_win32_entry_points_tdc_already_calls_suspicious():
    t = win32_to_nt.load_table()
    assert t.nt_for("VirtualAllocEx").nt == "NtAllocateVirtualMemory"
    assert t.nt_for("WriteProcessMemory").nt == "NtWriteVirtualMemory"
    assert t.nt_for("VirtualProtect").nt == "NtProtectVirtualMemory"
    assert t.nt_for("CreateRemoteThread").nt == "NtCreateThreadEx"
    assert t.nt_for("writeprocessmemory").nt == "NtWriteVirtualMemory"


NT_NAME = re.compile(r"Nt[A-Z][A-Za-z0-9]*")


def _suspicious_names(tdc_module):
    return {n.lower() for names in tdc_module.SUSPICIOUS_IMPORTS.values() for n in names}


def test_every_nt_name_has_the_shape_of_a_syscall_name():
    # "Nt" + CamelCase, no whitespace: a garbled row is caught without anyone reading it
    for entry in win32_to_nt.load_table().entries:
        assert NT_NAME.fullmatch(entry.nt), entry


def test_every_win32_name_is_one_tdc_already_calls_suspicious(app_module):
    # the table is not a Win32 dictionary: the function or its Nt counterpart is one TDC already flags
    suspicious = _suspicious_names(app_module)
    for entry in win32_to_nt.load_table().entries:
        assert entry.win32.lower() in suspicious or entry.nt.lower() in suspicious, entry


def test_a_zw_alias_entry_is_exactly_that_rename():
    table = win32_to_nt.load_table()
    aliases = [e for e in table.entries if e.source == "zw-alias"]
    assert aliases
    for entry in aliases:
        assert entry.win32.startswith("Zw") and entry.nt == "Nt" + entry.win32[2:], entry
    # and a mechanical rename is never filed as anything else
    for entry in table.entries:
        if entry.win32.startswith("Zw") and entry.nt == "Nt" + entry.win32[2:]:
            assert entry.source == "zw-alias", entry


def test_every_entry_names_a_source_from_the_vocabulary_and_no_win32_name_twice():
    # "documented" and "observed" carry the citation a human can check: the only real guard on a name
    entries = win32_to_nt.load_table().entries
    assert win32_to_nt.SOURCES == ("zw-alias", "documented", "observed")
    for entry in entries:
        assert entry.source in win32_to_nt.SOURCES, entry
        if entry.source != "zw-alias":
            assert entry.note.strip(), entry
    names = [e.win32.lower() for e in entries]
    assert len(names) == len(set(names))


def test_a_row_without_a_source_of_the_vocabulary_is_refused():
    with pytest.raises(win32_to_nt.TableError):
        win32_to_nt.parse_table({"version": 1, "entries": [
            {"win32": "VirtualAlloc", "nt": "NtAllocateVirtualMemory", "source": "guessed", "note": "x"}]})
    with pytest.raises(win32_to_nt.TableError):
        win32_to_nt.parse_table({"version": 1, "entries": [
            {"win32": "VirtualAlloc", "nt": "NtAllocateVirtualMemory", "source": "", "note": "x"}]})
    with pytest.raises(win32_to_nt.TableError):
        win32_to_nt.parse_table({"version": 2, "entries": []})


def test_the_table_is_read_once_and_held(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"version": 1, "entries": [
        {"win32": "VirtualAlloc", "nt": "NtAllocateVirtualMemory", "source": "zw-alias", "note": ""}]}))
    first = win32_to_nt.load_table(str(path))
    path.write_text("not json")
    assert win32_to_nt.load_table(str(path)) is first


def test_the_default_table_is_found_beside_the_module_from_any_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert win32_to_nt.load_table() is win32_to_nt.load_table(
        os.path.join(os.path.dirname(win32_to_nt.__file__), "win32_to_nt.json"))


def test_missing_from_lists_the_nt_names_a_set_of_syscalls_does_not_hold():
    table = win32_to_nt.load_table()
    held = {"NtAllocateVirtualMemory", "NtWriteVirtualMemory"}
    missing = table.missing_from(held)
    assert "NtCreateThreadEx" in missing and "NtProtectVirtualMemory" in missing
    assert not set(missing) & held
    assert len(missing) == len(set(missing))           # an Nt name several rows lead to is named once
    assert set(missing) == {e.nt for e in table.entries} - held


def test_missing_from_is_empty_for_a_set_that_holds_them_all():
    table = win32_to_nt.load_table()
    assert table.missing_from({e.nt for e in table.entries} | {"NtClose"}) == ()
    # any iterable of names: the keys of a baseline's syscalls are what the VM passes
    assert table.missing_from(dict.fromkeys(e.nt for e in table.entries)) == ()


# --- the table under the stub search: a proof, or a hint ------------------------------------

def _x64_stub(number):
    return bytes.fromhex("4c8bd1b8") + number.to_bytes(4, "little") + bytes.fromhex("0f05")


@pytest.fixture
def x64_baseline():
    """The x64 fixture, plus a syscall some row leads to (NtCreateThreadEx) and one no row does (NtCreateFile)."""
    bl = syscall_baseline.parse_baseline(_fixture("x64"), "26220.5770", "x64")
    for name, number in (("NtCreateThreadEx", 0xC1), ("NtCreateFile", 0x55)):
        sc = syscall_baseline.Syscall(name, "ntdll.dll", number, 0, "NTSTATUS", "", [], _x64_stub(number), True)
        bl.syscalls[name] = sc
        bl.by_number[("ntdll.dll", number)] = sc
    return bl


def _hit(baseline, name, imports):
    """The one hit of a stub for `name`, searched the way the web UI searches: the table applied to `imports`."""
    table = win32_to_nt.load_table()
    (hit,) = syscall_scan.find_stubs_in_bytes(
        _x64_stub(baseline.syscalls[name].number), baseline, imports,
        expanded_imports=table.expand(imports), covered=table.covered)
    return hit


def test_expand_keeps_none_as_none_and_adds_the_nt_name_of_a_hit():
    table = win32_to_nt.load_table()
    assert table.expand(None) is None
    assert table.expand(set()) == set()
    assert table.expand({"VirtualAllocEx", "GetLastError"}) == {
        "VirtualAllocEx", "GetLastError", "NtAllocateVirtualMemory"}
    assert table.expand({"zwunmapviewofsection"}) == {"zwunmapviewofsection", "NtUnmapViewOfSection"}
    # only a matched name adds anything: a miss must not sweep the table in, or nothing would ever be a proof
    assert table.expand({"GetLastError", "CreateService"}) == {"GetLastError", "CreateService"}


def test_a_sample_whose_api_the_table_does_not_know_is_a_hint_and_not_a_proven_bypass(x64_baseline):
    # imports {"CreateService"}: no row, so expand() adds nothing. For a stub of a syscall no row leads to, the
    # expansion cannot speak: an ordinary program reaching NtCreateFile through CreateFileW stays None, not False
    assert win32_to_nt.load_table().expand({"CreateService"}) == {"CreateService"}
    assert _hit(x64_baseline, "NtCreateFile", {"CreateService"})["import_present"] is None
    assert _hit(x64_baseline, "NtCreateFile", {"CreateFileW", "GetLastError"})["import_present"] is None
    assert _hit(x64_baseline, "NtUserGetForegroundWindow", {"GetForegroundWindow"})["import_present"] is None


def test_a_sample_that_imports_the_documented_win32_path_is_not_a_proven_bypass(x64_baseline):
    assert _hit(x64_baseline, "NtAllocateVirtualMemory", {"VirtualAllocEx"})["import_present"] is True
    assert _hit(x64_baseline, "NtCreateThreadEx", {"CreateThread"})["import_present"] is True
    assert _hit(x64_baseline, "NtCreateThreadEx", {"_beginthreadex"})["import_present"] is True


def test_a_sample_that_imports_nothing_of_the_path_is_a_proven_bypass(x64_baseline):
    hit = _hit(x64_baseline, "NtAllocateVirtualMemory", {"GetLastError"})
    assert hit["import_present"] is False
    (finding,) = memory_evidence.from_direct_stubs([hit], "s.exe")
    assert finding["needs_corroboration"] is False
    assert finding["base_weight"] == memory_evidence.KINDS["direct_syscall_stub"]["weight"]


def test_an_unknown_import_beside_does_not_shield_a_syscall_the_table_holds_every_known_path_to(x64_baseline):
    # CreateService has no row because it reaches no syscall of this process directly (it goes over RPC): it is
    # no path to NtCreateThreadEx, so a sample importing it and carrying that stub has gone around every path
    # the table knows
    assert _hit(x64_baseline, "NtCreateThreadEx", {"CreateService"})["import_present"] is False


def test_without_an_import_table_the_table_changes_nothing(x64_baseline):
    assert _hit(x64_baseline, "NtAllocateVirtualMemory", None)["import_present"] is None


# --- the table in the web UI: the stubs route and the detonation stage ------------------------

def _loader(sample_dir, *imports, name="loader.exe"):
    """A PE in the readable folders that imports `imports` and carries a stub for NtWriteVirtualMemory."""
    path = sample_dir / name
    path.write_bytes(_pe_importing(*imports) + _X64_STUB_0x3A)
    return path


def test_the_stubs_route_proves_a_bypass_for_a_file_that_does_not_import_the_path(client, tdc, target, sample_dir):
    path = _loader(sample_dir, "GetLastError")
    body = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()
    assert body["imports_read"] is True
    [hit] = body["hits"]
    assert (hit["syscall"], hit["import_present"]) == ("NtWriteVirtualMemory", False)
    [finding] = body["evidence"]["findings"]
    assert finding["needs_corroboration"] is False
    # the documented path imported: a hint, not a proof
    path = _loader(sample_dir, "WriteProcessMemory")
    body = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()
    assert body["hits"][0]["import_present"] is True
    assert body["evidence"]["findings"][0]["needs_corroboration"] is True


def test_the_stubs_route_proves_a_bypass_in_a_process_whose_image_does_not_import_the_path(
        client, tdc, target, sample_dir, monkeypatch):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    image = _loader(sample_dir, "GetLastError")
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: str(image))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert body["imports_read"] is True
    assert body["hits"][0]["import_present"] is False


def test_a_process_whose_image_cannot_be_read_keeps_import_present_unknown(client, tdc, target, monkeypatch):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    for image in ("", "C:\\Samples\\gone.exe"):
        monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid, image=image: image)
        body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
        assert body["imports_read"] is False
        assert body["hits"][0]["import_present"] is None
        assert body["evidence"]["findings"][0]["needs_corroboration"] is True


def test_the_detonation_stage_proves_a_bypass_for_the_sample_file(tdc, target, sample_dir):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    path = _loader(sample_dir, "GetLastError")
    result = tdc._run_syscall_stage(4812, str(path), [])
    stubs = result["stubs"]
    # the sample file's import table speaks for the process it became, too
    assert [h["import_present"] for h in stubs["process"]["hits"]] == [False]
    assert [h["import_present"] for h in stubs["file"]["hits"]] == [False]
    assert stubs["file"]["imports_read"] is True
    [finding] = [f for f in result["evidence"]["findings"] if f["kind"] == "direct_syscall_stub"]
    assert finding["needs_corroboration"] is False


def test_the_detonation_stage_without_a_sample_file_keeps_import_present_unknown(tdc, target):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    result = tdc._run_syscall_stage(4812, None, [])
    assert [h["import_present"] for h in result["stubs"]["process"]["hits"]] == [None]


def test_a_sample_file_that_is_no_pe_keeps_import_present_unknown(tdc, target, sample_dir):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 8)
    path = sample_dir / "loader.bin"
    path.write_bytes(_X64_STUB_0x3A)
    result = tdc._run_syscall_stage(4812, str(path), [])
    assert result["stubs"]["file"]["imports_read"] is False
    assert [h["import_present"] for h in result["stubs"]["file"]["hits"]] == [None]


def test_a_delay_loaded_import_counts_as_an_import(tdc, client, target, sample_dir):
    # the import table now speaks for an absence: a function the sample delay-loads is still a path it has
    assert tdc._pe_import_names(_pe_importing("WriteProcessMemory", delay=True)) == {"WriteProcessMemory"}
    path = sample_dir / "lazy.exe"
    path.write_bytes(_pe_importing("WriteProcessMemory", delay=True) + _X64_STUB_0x3A)
    body = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()
    assert body["hits"][0]["import_present"] is True
