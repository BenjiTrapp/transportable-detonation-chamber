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


def _boundary_tiers(entries, suspicious):
    """`(own, door, lexicon)`: rows that pass on their own (their win32 or nt is in SUSPICIOUS_IMPORTS), rows that
    are a further door to a syscall an own row covers, and rows that are neither."""
    own = [e for e in entries if e.win32.lower() in suspicious or e.nt.lower() in suspicious]
    covered = {e.nt for e in own}
    door = [e for e in entries if e not in own and e.nt in covered]
    lexicon = [e for e in entries if e not in own and e not in door]
    return own, door, lexicon


def test_every_row_is_inside_the_two_tier_boundary(app_module):
    # whether a syscall is covered at all is bounded by SUSPICIOUS_IMPORTS: a row whose own win32 or nt is there.
    # once it is covered, every door to it belongs in the table, suspicious or not: a missing door makes the
    # claim false. A row that is neither is a lexicon row, and the table is not a Win32 dictionary
    suspicious = _suspicious_names(app_module)
    own, door, lexicon = _boundary_tiers(win32_to_nt.load_table().entries, suspicious)
    assert lexicon == []
    assert door, "the second tier is in use"


def test_the_second_tier_never_covers_a_syscall_of_its_own(app_module):
    suspicious = _suspicious_names(app_module)
    table = win32_to_nt.load_table()
    own, _, _ = _boundary_tiers(table.entries, suspicious)
    assert table.covered == {e.nt for e in own}
    # a lexicon row is caught: a door to a syscall no own row covers
    stray = win32_to_nt.Entry("CreateFileW", "NtCreateFile", "documented", "x")
    assert _boundary_tiers(table.entries + (stray,), suspicious)[2] == [stray]


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


def test_every_entry_names_a_source_from_the_vocabulary_and_no_pair_twice():
    # "documented" and "observed" carry the citation a human can check: the only real guard on a name
    entries = win32_to_nt.load_table().entries
    assert win32_to_nt.SOURCES == ("zw-alias", "documented", "observed")
    for entry in entries:
        assert entry.source in win32_to_nt.SOURCES, entry
        if entry.source != "zw-alias":
            assert entry.note.strip(), entry
    pairs = [(e.win32.lower(), e.nt) for e in entries]
    assert len(pairs) == len(set(pairs))


def test_a_win32_name_may_lead_to_several_syscalls_and_expand_adds_them_all():
    # the shipped table has no such name today (see the door rule); the model keeps the seat for one
    row = {"win32": "SomeDoor", "source": "documented", "note": "x"}
    table = win32_to_nt.parse_table({"version": 1, "entries": [
        dict(row, nt="NtWriteVirtualMemory"), dict(row, win32="somedoor", nt="NtProtectVirtualMemory")]})
    assert [e.nt for e in table.entries_for("SOMEDOOR")] == ["NtWriteVirtualMemory", "NtProtectVirtualMemory"]
    assert table.nt_for("SomeDoor").nt == "NtWriteVirtualMemory"                # the first row is the headline
    assert table.entries_for("GetLastError") == ()
    assert table.expand({"SomeDoor"}) == {"SomeDoor", "NtWriteVirtualMemory", "NtProtectVirtualMemory"}
    assert table.covered == {"NtWriteVirtualMemory", "NtProtectVirtualMemory"}


def test_a_pair_twice_is_refused():
    row = {"win32": "VirtualAlloc", "nt": "NtAllocateVirtualMemory", "source": "documented", "note": "x"}
    with pytest.raises(win32_to_nt.TableError):
        win32_to_nt.parse_table({"version": 1, "entries": [row, dict(row, win32="virtualalloc")]})


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


def test_a_stub_for_a_syscall_no_row_leads_to_stays_unknown(x64_baseline):
    # the discriminator is the coverage of the stub's syscall: the table knows no door to NtCreateFile, so an
    # ordinary program reaching it through CreateFileW stays None, never a proven bypass
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


def test_a_sample_that_imports_no_door_to_a_covered_syscall_is_a_proven_bypass(x64_baseline):
    # the table knows the doors to NtCreateThreadEx and the sample takes none of them. CreateService having no
    # row of its own changes nothing: whether the sample's import has a row is never the question
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


def test_a_process_search_never_proves_a_bypass_even_when_its_image_imports_no_door(
        client, tdc, target, sample_dir, monkeypatch):
    # private executable memory belongs to nobody in particular: a hook engine's, a sandbox broker's or a
    # runtime's thunk is judged against an image table that is not its own, so process mode cannot prove
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    image = _loader(sample_dir, "_CorExeMain")
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: str(image))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert body["imports_read"] is True
    assert body["hits"][0]["import_present"] is None
    [finding] = body["evidence"]["findings"]
    assert finding["needs_corroboration"] is True and finding["may_corroborate"] is False


def test_a_process_whose_image_imports_the_function_says_imported_too(client, tdc, target, sample_dir,
                                                                       monkeypatch):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: str(_loader(sample_dir, "NtWriteVirtualMemory")))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert body["hits"][0]["import_present"] is True
    # a door alone is no import of the function in process mode: the raw table is all it uses
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: str(_loader(sample_dir, "WriteProcessMemory")))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert body["hits"][0]["import_present"] is None


def test_a_process_image_larger_than_the_cap_is_not_read(client, tdc, target, sample_dir, monkeypatch):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    image = _loader(sample_dir, "NtWriteVirtualMemory")
    monkeypatch.setattr(tdc, "_image_path_for_pid", lambda pid: str(image))
    monkeypatch.setattr(tdc, "SYSCALL_FILE_MAX", image.stat().st_size - 1)
    opened = []
    real_open = open
    monkeypatch.setattr("builtins.open", lambda f, *a, **k: opened.append(str(f)) or real_open(f, *a, **k))
    body = client.post("/api/syscalls/stubs", json={"pid": 4812}).get_json()
    assert body["imports_read"] is False and str(image) not in opened


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
    # the proof arrives through the file; the process copy is a hint, as its memory cannot be attributed
    assert [h["import_present"] for h in stubs["process"]["hits"]] == [None]
    assert [h["import_present"] for h in stubs["file"]["hits"]] == [False]
    assert stubs["file"]["imports_read"] is True
    [finding] = [f for f in result["evidence"]["findings"] if f["kind"] == "direct_syscall_stub"]
    assert finding["needs_corroboration"] is False and finding["copies"] == 2


def test_the_stage_searches_the_process_before_it_reads_the_sample_file(tdc, target, sample_dir, monkeypatch):
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 8)
    path = _loader(sample_dir, "GetLastError")
    order = []
    real_process, real_file = syscall_scan.find_stubs_in_process, tdc._syscall_stage_file
    monkeypatch.setattr(syscall_scan, "find_stubs_in_process",
                        lambda *a, **k: order.append("process") or real_process(*a, **k))
    monkeypatch.setattr(tdc, "_syscall_stage_file", lambda *a, **k: order.append("file") or real_file(*a, **k))
    tdc._run_syscall_stage(4812, str(path), [])
    assert order == ["process", "file"]


def _exported_stub_hit(client, sample_dir, exports, export_rva=None):
    path = sample_dir / "module.dll"
    path.write_bytes(_pe_importing(exports=exports, code=_X64_STUB_0x3A, export_rva=export_rva))
    body = client.post("/api/syscalls/stubs", json={"path": str(path), "view": "x64"}).get_json()
    [hit] = [h for h in body["hits"] if h["offset"] == 0x3C0]
    return hit


def test_a_module_that_exports_the_stub_under_its_own_name_holds_its_door(client, tdc, target, sample_dir):
    # a copy of ntdll: the stub is the body of the export of its own Nt or Zw name, the documented path itself
    assert _exported_stub_hit(client, sample_dir, ("NtWriteVirtualMemory",))["import_present"] is True
    assert _exported_stub_hit(client, sample_dir, ("ZwWriteVirtualMemory",))["import_present"] is True


def test_an_export_the_sample_wrote_for_itself_does_not_buy_off_the_proof(client, tdc, target, sample_dir):
    # the author writes the export table: a door name, or the Nt name pointing anywhere but at the stub, is free
    assert _exported_stub_hit(client, sample_dir, ("WriteProcessMemory",))["import_present"] is False
    assert _exported_stub_hit(client, sample_dir, ("CreateThread",))["import_present"] is False
    assert _exported_stub_hit(client, sample_dir, ("NtWriteVirtualMemory",), export_rva=0x1000)["import_present"] \
        is False
    assert _exported_stub_hit(client, sample_dir, ("NtAllocateVirtualMemory",))["import_present"] is False


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


# what Plan 1 said while the table did not exist; each became false the day it did, and none may come back
STALE_PHRASES = (
    "The import table is not passed",                       # app.py, _syscall_stage_file
    "`import_present` is None: a raw import table",         # app.py, api_syscalls_stubs
    "the sample imports the function is mostly not known",  # app.js, over renderSyscallStubs
    "that table is not part of this tab yet",               # app.js, the hint over the stub list
    "They are hints, not proof",                            # index.html, the info of the stub panel
    "not known to be complete for this function",           # app.js, the tooltip of "unknown"
    "until the Win32-to-Nt table exists",                   # docs/api.md
    "import table not checked",                             # memory_evidence.py, the detail of a hint
    "Every hit is a hint for now",                          # docs/memory.md, the table row
    "Every hit is for now a hint",                          # docs/memory.md, the section
    "which the chamber does not have yet",                  # docs/memory.md, the section
    "wartet daher auf Plan 2",                              # the spec, goal 7a
    "Solange die kuratierte Tabelle fehlt",                 # the spec, goal 7a
    "Plan 2 schaltet den Beleg frei",                       # the spec, goal 7a
)


def test_no_shipped_text_still_says_the_win32_to_nt_table_is_missing():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = [os.path.join(root, "webui", n) for n in sorted(os.listdir(os.path.join(root, "webui")))
             if n.endswith(".py")]
    paths += [os.path.join(root, *p.split("/")) for p in (
        "webui/static/js/app.js", "webui/templates/index.html", "docs/api.md", "docs/memory.md",
        "docs/superpowers/specs/2026-11-22-syscall-map-design.md")]
    found = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = " ".join(fh.read().split())
        found += [(os.path.relpath(path, root), phrase) for phrase in STALE_PHRASES if phrase in text]
    assert found == []


def test_the_stub_list_changed_and_so_did_its_asset_version():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "webui", "templates", "index.html"), encoding="utf-8") as fh:
        html = fh.read()
        assert "app.js?v=136" not in html and "app.js?v=137" not in html, "app.js changed, its version did not"


def test_an_expanded_import_set_without_its_coverage_is_refused(x64_baseline):
    # forgetting `covered` would bring back the false proof for every syscall no row leads to
    with pytest.raises(ValueError):
        syscall_scan.find_stubs_in_bytes(_x64_stub(0x55), x64_baseline, expanded_imports={"CreateFileW"})
    reader = _x64_space(_x64_stub(0x55))
    with pytest.raises(ValueError):
        syscall_scan.find_stubs_in_process(reader, x64_baseline, expanded_imports={"CreateFileW"})
    # coverage alone, or neither, is no mistake
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x55), x64_baseline, covered=frozenset())
    assert hit["import_present"] is None


# the doors to each covered syscall: APIs whose contract performs that syscall's operation on operands the caller
# supplies, not every API that reaches it on its way
DOORS = {
    "NtAllocateVirtualMemory": {"VirtualAlloc", "VirtualAllocEx", "VirtualAllocFromApp", "VirtualAllocExNuma"},
    "NtWriteVirtualMemory": {"WriteProcessMemory"},
    "NtProtectVirtualMemory": {"VirtualProtect", "VirtualProtectEx", "VirtualProtectFromApp"},
    "NtCreateThreadEx": {"CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx", "RtlCreateUserThread",
                         "_beginthreadex", "_beginthread", "DbgUiIssueRemoteBreakin", "DebugBreakProcess",
                         "SHCreateThread", "SHCreateThreadWithHandle"},
    "NtQueueApcThread": {"QueueUserAPC", "RtlQueueApcWow64Thread"},
    "NtSetContextThread": {"SetThreadContext", "RtlRemoteCall"},
    "NtUnmapViewOfSection": {"UnmapViewOfFile", "ZwUnmapViewOfSection", "FreeLibrary", "FreeLibraryAndExitThread",
                             "LdrUnloadDll"},
    "NtAdjustPrivilegesToken": {"AdjustTokenPrivileges", "RtlAdjustPrivilege"},
    "NtOpenProcessToken": {"OpenProcessToken"},
}


def test_every_door_the_audit_found_to_a_covered_syscall_is_in_the_table():
    table = win32_to_nt.load_table()
    assert set(DOORS) == set(table.covered)
    for nt, doors in DOORS.items():
        assert {e.win32 for e in table.entries if e.nt == nt} == doors, nt


def test_a_wrapper_that_reaches_the_ex_syscall_is_no_door_to_the_plain_one():
    # UnmapViewOfFileEx takes flags and VirtualAlloc2 extended parameters: they reach NtUnmapViewOfSectionEx and
    # NtAllocateVirtualMemoryEx, other syscalls, which the boundary keeps out of the table
    table = win32_to_nt.load_table()
    for name in ("UnmapViewOfFileEx", "UnmapViewOfFile2", "VirtualAlloc2", "QueueUserAPC2"):
        assert table.nt_for(name) is None, name


def test_an_api_that_reaches_a_covered_syscall_only_on_its_own_behalf_is_no_door():
    # the heap commits through NtAllocateVirtualMemory and the loader reprotects the import table, but the caller
    # names neither address, protection nor process: a door would erase the proof for nearly every program
    table = win32_to_nt.load_table()
    for name in ("HeapAlloc", "HeapCreate", "RtlAllocateHeap", "LocalAlloc", "GlobalAlloc", "malloc",
                 "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW", "LdrLoadDll",
                 "ImpersonateSelf", "RtlImpersonateSelf", "CheckTokenMembership"):
        assert table.entries_for(name) == (), name
    # one row each: what the caller directs, not what the implementation touches on the way
    assert [e.nt for e in table.entries_for("WriteProcessMemory")] == ["NtWriteVirtualMemory"]
    assert [e.nt for e in table.entries_for("RtlRemoteCall")] == ["NtSetContextThread"]
    assert [e.nt for e in table.entries_for("RtlAdjustPrivilege")] == ["NtAdjustPrivilegesToken"]


def test_the_internal_helpers_have_no_default_for_covered():
    # a future internal caller must name the coverage, not fall into the rule it replaced
    import inspect
    for fn in (syscall_scan._import_present, syscall_scan._scan_chunk):
        assert inspect.signature(fn).parameters["covered"].default is inspect.Parameter.empty, fn.__name__


def test_a_hint_without_an_answer_says_why_it_has_none(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x55), x64_baseline, {"CreateFileW"},
                                              expanded_imports={"CreateFileW"}, covered=frozenset())
    (finding,) = memory_evidence.from_direct_stubs([hit], "s.exe")
    assert "import table not checked" not in finding["detail"]
    assert "no curated door" in finding["detail"]


def test_a_finding_takes_its_address_from_the_first_copy_that_has_one(tdc, target, sample_dir):
    # the file's hits come first and carry an offset, not an address: the process copy still supplies one
    target.view = "x64"
    target.reader = _x64_space(b"\x90" * 0x40 + _X64_STUB_0x3A + b"\xc3")
    result = tdc._run_syscall_stage(4812, str(_loader(sample_dir, "GetLastError")), [])
    [finding] = [f for f in result["evidence"]["findings"] if f["kind"] == "direct_syscall_stub"]
    assert finding["address"] == _PRIVATE_BASE + 0x40
    assert finding["needs_corroboration"] is False


def test_the_detail_of_a_hint_does_not_attribute_what_it_says_cannot_be(x64_baseline):
    (hit,) = syscall_scan.find_stubs_in_bytes(_x64_stub(0x55), x64_baseline)
    (finding,) = memory_evidence.from_direct_stubs([hit], "s.exe")
    assert "carried by the sample" not in finding["detail"]
    assert "cannot be attributed" in finding["detail"]


def test_the_process_search_says_at_its_signature_who_may_pass_an_expanded_set():
    doc = syscall_scan.find_stubs_in_process.__doc__
    assert "every loaded module" in doc and "single image" in doc
