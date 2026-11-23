"""The import graph of the system binaries, and the curated Win32 to Nt table under it."""

import json
import os
import re

import pytest

import binary_graph
import memory_evidence
import syscall_baseline
import syscall_scan
import win32_to_nt
from conftest import make_pe
from test_syscalls import (_PRIVATE_BASE, _X64_STUB_0x3A, _fixture, _x64_space,  # noqa: F401
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
    path.write_bytes(make_pe(imports=(("ntdll.dll", imports),)) + _X64_STUB_0x3A)
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
    path.write_bytes(make_pe(exports=exports, code=_X64_STUB_0x3A, export_rva=export_rva))
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
    assert tdc._pe_import_names(make_pe(delay=(("ntdll.dll", ("WriteProcessMemory",)),))) == {"WriteProcessMemory"}
    path = sample_dir / "lazy.exe"
    path.write_bytes(make_pe(delay=(("ntdll.dll", ("WriteProcessMemory",)),)) + _X64_STUB_0x3A)
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


# --- one binary: what it imports, exports and forwards ------------------------------------

def test_the_test_pe_builder_produces_an_image_pefile_reads_back():
    # two import modules, an export, a forwarder, a named section and arm64 machine, all read back through pefile
    import pefile
    data = make_pe(imports=(("ntdll.dll", ("NtClose", 7)), ("KERNELBASE.dll", ("CreateFileW",))),
                   delay=(("user32.dll", ("MessageBoxW",)),),
                   exports=("OwnFunction",), forwarders=(("HeapAlloc", "NTDLL.RtlAllocateHeap"),),
                   code=_X64_STUB_0x3A, machine=0xAA64, sections=((".apiset", b"apiset-bytes"),))
    pe = pefile.PE(data=data)
    try:
        assert pe.FILE_HEADER.Machine == 0xAA64
        assert [(e.dll, [i.name or i.ordinal for i in e.imports]) for e in pe.DIRECTORY_ENTRY_IMPORT] == [
            (b"ntdll.dll", [b"NtClose", 7]), (b"KERNELBASE.dll", [b"CreateFileW"])]
        assert [(e.dll, [i.name for i in e.imports]) for e in pe.DIRECTORY_ENTRY_DELAY_IMPORT] == [
            (b"user32.dll", [b"MessageBoxW"])]
        symbols = {s.name: s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        assert set(symbols) == {b"OwnFunction", b"HeapAlloc"}
        assert symbols[b"OwnFunction"].forwarder is None and symbols[b"OwnFunction"].address == 0x11C0
        assert symbols[b"HeapAlloc"].forwarder == b"NTDLL.RtlAllocateHeap"
        apiset = [s for s in pe.sections if s.Name.rstrip(b"\0") == b".apiset"]
        assert [s.get_data()[:12] for s in apiset] == [b"apiset-bytes"]
        # the code still sits at RVA 0x11C0, file offset 0x3C0
        assert pe.get_offset_from_rva(0x11C0) == 0x3C0 and data[0x3C0:0x3C0 + len(_X64_STUB_0x3A)] == _X64_STUB_0x3A
    finally:
        pe.close()
    assert pefile.PE(data=make_pe()).FILE_HEADER.Machine == 0x8664


def test_the_builder_places_nameless_exports_at_their_ordinals_after_a_base():
    import pefile
    data = make_pe(exports=("Named",), forwarders=(("Fwd", "NTDLL.RtlFwd"),), ordinal_base=5,
                   nameless=((9, None), (12, "NTDLL.#8")), code=_X64_STUB_0x3A, dll=True)
    pe = pefile.PE(data=data)
    try:
        assert [(s.ordinal, s.name, s.forwarder) for s in pe.DIRECTORY_ENTRY_EXPORT.symbols] == [
            (5, b"Named", None), (6, b"Fwd", b"NTDLL.RtlFwd"), (9, None, None), (12, None, b"NTDLL.#8")]
        assert pe.DIRECTORY_ENTRY_EXPORT.struct.Base == 5
        assert pe.FILE_HEADER.Characteristics == 0x2022
    finally:
        pe.close()
    pe = pefile.PE(data=make_pe())
    try:
        assert pe.FILE_HEADER.Characteristics == 0x22          # the header every existing caller has had
    finally:
        pe.close()


def _binary(tmp_path, name="sample.dll", **pe):
    path = tmp_path / name
    path.write_bytes(make_pe(**pe))
    return binary_graph.extract_binary(str(path))


def test_imports_are_grouped_by_module_in_lower_case(tmp_path):
    info = _binary(tmp_path, "Sample.DLL", imports=(("NTDLL.dll", ("NtClose", "NtOpenFile")),
                                                    ("KernelBase.dll", ("CreateFileW",))),
                   delay=(("USER32.dll", ("MessageBoxW",)),), dll=True)
    assert info.name == "sample.dll" and info.kind == "dll"
    assert info.imports == {"ntdll.dll": ("NtClose", "NtOpenFile"), "kernelbase.dll": ("CreateFileW",),
                            "user32.dll": ("MessageBoxW",)}
    assert _binary(tmp_path, "tool.exe").kind == "exe"


def test_exports_this_image_defines_itself_are_listed_without_the_forwarders(tmp_path):
    info = _binary(tmp_path, exports=("CreateFileW", "CloseHandle"),
                   forwarders=(("HeapAlloc", "NTDLL.RtlAllocateHeap"),))
    assert info.exports == ("CreateFileW", "CloseHandle")
    assert set(info.forwarders) == {"HeapAlloc"}
    assert _binary(tmp_path, imports=(("ntdll.dll", ("NtClose",)),)).exports == ()


def test_a_forwarder_is_kept_as_the_raw_string_it_names(tmp_path):
    info = _binary(tmp_path, forwarders=(("WriteProcessMemory", "api-ms-win-core-memory-l1-1-0.WriteProcessMemory"),
                                         ("HeapAlloc", "NTDLL.RtlAllocateHeap")))
    assert info.forwarders == {"WriteProcessMemory": "api-ms-win-core-memory-l1-1-0.WriteProcessMemory",
                               "HeapAlloc": "NTDLL.RtlAllocateHeap"}
    assert info.exports == ()


def test_an_import_by_ordinal_is_named_hash_number(tmp_path):
    info = _binary(tmp_path, imports=(("ws2_32.dll", (115, "connect")),))
    assert info.imports == {"ws2_32.dll": ("#115", "connect")}


def test_the_machine_of_an_arm64_image_is_arm64_and_of_an_amd64_image_x64(tmp_path):
    assert _binary(tmp_path, machine=0xAA64).machine == "arm64"
    assert _binary(tmp_path, machine=0x8664).machine == "x64"
    assert _binary(tmp_path, machine=0x14C).machine == "x86"
    assert _binary(tmp_path, machine=0x1C4).machine == "other"


def test_a_nameless_export_is_its_ordinal_and_every_named_export_has_its_ordinal(tmp_path):
    info = _binary(tmp_path, exports=("RtlAllocateHeap", "NtClose"), forwarders=(("HeapAlloc", "NTDLL.#8"),),
                   ordinal_base=8, nameless=((20, None), (21, "NTDLL.#9")))
    assert info.exports == ("RtlAllocateHeap", "NtClose", "#20")
    assert info.forwarders == {"HeapAlloc": "NTDLL.#8", "#21": "NTDLL.#9"}
    # a forwarder naming "#8", or an import by ordinal, is turned into a name through this
    assert info.ordinal_names == {8: "RtlAllocateHeap", 9: "NtClose", 10: "HeapAlloc"}


def test_the_kind_is_what_the_header_says_and_the_extension_only_when_it_cannot(tmp_path, monkeypatch):
    assert _binary(tmp_path, "renamed.exe", dll=True).kind == "dll"
    assert _binary(tmp_path, "renamed.dll", dll=False).kind == "exe"
    # the header always carries the flag; the extension is the fallback for a header that yields no characteristics
    monkeypatch.setattr(binary_graph, "_is_dll", lambda pe: None)
    assert _binary(tmp_path, "tool.exe", dll=True).kind == "exe"
    assert _binary(tmp_path, "lib.DLL", dll=False).kind == "dll"


# --- a directory of them ------------------------------------------------------------------

def test_the_tree_holds_every_pe_of_the_directory_and_names_the_others_as_skipped(tmp_path):
    (tmp_path / "kernel32.dll").write_bytes(make_pe(forwarders=(("HeapAlloc", "NTDLL.RtlAllocateHeap"),)))
    (tmp_path / "notepad.exe").write_bytes(make_pe(imports=(("kernel32.dll", ("HeapAlloc",)),)))
    (tmp_path / "readme.dll").write_bytes(b"this is no PE")
    (tmp_path / "notes.txt").write_bytes(make_pe())            # only .dll and .exe are read
    (tmp_path / "en-US.dll").mkdir()                           # a directory, whatever its name
    (tmp_path / "en-US.dll" / "inner.dll").write_bytes(make_pe())
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["kernel32.dll", "notepad.exe"]
    assert binaries[0].forwarders == {"HeapAlloc": "NTDLL.RtlAllocateHeap"}
    assert [name for name, _ in skipped] == ["readme.dll"]


def test_a_name_that_differs_only_in_case_is_one_binary(tmp_path, monkeypatch):
    (tmp_path / "KERNEL32.DLL").write_bytes(make_pe(exports=("CreateFileW",), dll=True))
    (tmp_path / "kernel32.dll").write_bytes(make_pe(exports=("CreateFileW",), dll=True))   # the same file where case folds
    (tmp_path / "Notepad.Exe").write_bytes(make_pe())
    # both spellings listed, as a case-sensitive file system lists them, on every platform the suite runs on
    real_listdir = os.listdir
    monkeypatch.setattr(os, "listdir", lambda d: sorted(set(real_listdir(d)) | {"KERNEL32.DLL", "kernel32.dll"}))
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["kernel32.dll", "notepad.exe"]
    assert [b.kind for b in binaries] == ["dll", "exe"]
    # the second spelling is named, never silently dropped
    assert skipped == [("kernel32.dll", "the same name as kernel32.dll in another case")]


# --- a broken file among 4,000 -------------------------------------------------------------

def test_a_file_that_is_not_a_pe_is_skipped_with_a_reason_and_the_others_still_extract(tmp_path):
    (tmp_path / "a.dll").write_bytes(make_pe(exports=("A",)))
    (tmp_path / "b.dll").write_bytes(b"MZ but nothing after it")
    (tmp_path / "c.exe").write_bytes(b"")
    (tmp_path / "d.dll").write_bytes(make_pe(exports=("D",)))
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["a.dll", "d.dll"]
    assert [name for name, _ in skipped] == ["b.dll", "c.exe"]
    for _, reason in skipped:
        assert reason.startswith("not a PE: ") and "Error" not in reason and len(reason) < 120, reason
    with pytest.raises(binary_graph.ExtractError, match="^not a PE"):
        binary_graph.extract_binary(str(tmp_path / "b.dll"))


def test_a_file_that_cannot_be_opened_is_skipped_with_a_reason(tmp_path, monkeypatch):
    (tmp_path / "locked.dll").write_bytes(make_pe())
    (tmp_path / "fine.dll").write_bytes(make_pe())
    real_open = open

    def refusing_open(file, *args, **kwargs):
        if str(file).endswith("locked.dll"):
            raise PermissionError(13, "Permission denied")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", refusing_open)
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["fine.dll"]
    assert skipped == [("locked.dll", "cannot be opened: Permission denied")]
    # and a directory that cannot be listed is one skipped entry, not an exception
    assert binary_graph.extract_tree(str(tmp_path / "gone")) == (
        [], [(str(tmp_path / "gone"), "cannot be listed: No such file or directory")])


def test_a_pe_truncated_after_its_headers_is_skipped_and_does_not_raise(tmp_path):
    whole = make_pe(imports=(("ntdll.dll", ("NtClose",)),), exports=("A",))
    (tmp_path / "cut.dll").write_bytes(whole[:0x200])          # the headers, and not one byte of the section
    (tmp_path / "half.dll").write_bytes(whole[:0x300])
    (tmp_path / "whole.dll").write_bytes(whole)
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["whole.dll"]
    assert [name for name, _ in skipped] == ["cut.dll", "half.dll"]
    # pefile reads the headers and refuses the directory: the reason names which, never pefile's wording of it,
    # which may change with any release
    assert [reason for _, reason in skipped] == ["unreadable import directory"] * 2


def test_a_parse_that_warned_and_still_produced_entries_is_kept_and_marked_partial(tmp_path):
    # pefile gives up on an export table after 120 nameless exports at one address, and keeps what it read so far
    whole = _binary(tmp_path, "whole.dll", exports=("A",), nameless=tuple((n, None) for n in range(2, 12)))
    assert whole.partial is False and len(whole.exports) == 11
    cut = _binary(tmp_path, "cut.dll", exports=("A",), nameless=tuple((n, None) for n in range(2, 132)))
    assert cut.partial is True
    assert cut.exports[0] == "A" and 1 < len(cut.exports) < 131        # kept, with fewer exports than it has
    # a warning only about the headers, not from a directory the record is read from, is no partial parse
    short = make_pe(imports=(("ntdll.dll", ("NtClose",)),))
    (tmp_path / "short.dll").write_bytes(short[:-1])
    assert binary_graph.extract_binary(str(tmp_path / "short.dll")).partial is False


def test_without_pefile_every_file_is_skipped_and_nothing_escapes(tmp_path, monkeypatch):
    import sys
    (tmp_path / "a.dll").write_bytes(make_pe())
    monkeypatch.setitem(sys.modules, "pefile", None)             # `import pefile` raises ImportError
    assert binary_graph.extract_tree(str(tmp_path)) == ([], [("a.dll", "cannot be parsed: pefile is not available")])


def test_a_section_one_byte_past_the_end_of_the_file_is_read_as_pefile_reads_it(tmp_path):
    # pefile warns ("SizeOfRawData is larger than file") and reads every directory: no reason to lose the binary
    whole = make_pe(imports=(("ntdll.dll", ("NtClose",)),), exports=("A",),
                    forwarders=(("HeapAlloc", "NTDLL.RtlAllocateHeap"),))
    (tmp_path / "short.dll").write_bytes(whole[:-1])
    info = binary_graph.extract_binary(str(tmp_path / "short.dll"))
    assert info.imports == {"ntdll.dll": ("NtClose",)}
    assert info.exports == ("A",) and info.forwarders == {"HeapAlloc": "NTDLL.RtlAllocateHeap"}


def test_a_directory_pefile_cannot_read_skips_only_when_it_is_one_the_record_needs(tmp_path):
    # an unrelated section cut short is no reason: only the import, delay-load and export directories count
    whole = make_pe(imports=(("ntdll.dll", ("NtClose",)),), sections=((".rsrc", b"r" * 0x400),))
    (tmp_path / "rsrc.dll").write_bytes(whole[:-0x300])
    assert binary_graph.extract_binary(str(tmp_path / "rsrc.dll")).imports == {"ntdll.dll": ("NtClose",)}
    cut = make_pe(delay=(("user32.dll", ("MessageBoxW",)),))[:0x200]
    (tmp_path / "lazy.dll").write_bytes(cut)
    with pytest.raises(binary_graph.ExtractError, match="^unreadable delay-load directory$"):
        binary_graph.extract_binary(str(tmp_path / "lazy.dll"))
    cut = make_pe(exports=("A",))[:0x200]
    (tmp_path / "exp.dll").write_bytes(cut)
    with pytest.raises(binary_graph.ExtractError, match="^unreadable export directory$"):
        binary_graph.extract_binary(str(tmp_path / "exp.dll"))


def test_a_file_larger_than_the_cap_is_skipped_unread(tmp_path, monkeypatch):
    (tmp_path / "huge.dll").write_bytes(make_pe())
    monkeypatch.setattr(binary_graph, "MAX_BINARY_SIZE", 0x200)
    assert binary_graph.extract_tree(str(tmp_path)) == ([], [("huge.dll", "larger than 512 bytes")])


def test_no_exception_of_the_parser_escapes_the_tree(tmp_path, monkeypatch):
    (tmp_path / "odd.dll").write_bytes(make_pe(machine=0x1C4))
    (tmp_path / "fine.dll").write_bytes(make_pe())
    real = binary_graph._exports

    def exports(pe):
        if pe.FILE_HEADER.Machine == 0x1C4:
            raise ValueError("unpack requires a buffer of 4 bytes")
        return real(pe)

    monkeypatch.setattr(binary_graph, "_exports", exports)
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["fine.dll"]
    assert skipped == [("odd.dll", "malformed: ValueError")]
