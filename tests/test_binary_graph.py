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
    assert skipped == [("kernel32.dll", "the same name in another case")]


# --- a broken file among 4,000 -------------------------------------------------------------

def test_a_file_that_is_not_a_pe_is_skipped_with_a_reason_and_the_others_still_extract(tmp_path):
    (tmp_path / "a.dll").write_bytes(make_pe(exports=("A",)))
    (tmp_path / "b.dll").write_bytes(b"MZ but nothing after it")
    (tmp_path / "c.exe").write_bytes(b"")
    (tmp_path / "d.dll").write_bytes(make_pe(exports=("D",)))
    binaries, skipped = binary_graph.extract_tree(str(tmp_path))
    assert [b.name for b in binaries] == ["a.dll", "d.dll"]
    assert [name for name, _ in skipped] == ["b.dll", "c.exe"]
    assert skipped == [("b.dll", "not a PE"), ("c.exe", "empty file")]
    with pytest.raises(binary_graph.ExtractError, match="^not a PE$"):
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
    assert skipped == [("locked.dll", "cannot be opened")]
    # and a directory that cannot be listed is one skipped entry, not an exception
    assert binary_graph.extract_tree(str(tmp_path / "gone")) == (
        [], [(str(tmp_path / "gone"), "cannot be listed")])


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
    assert binary_graph.extract_tree(str(tmp_path)) == ([], [("a.dll", "pefile is not available")])


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
    assert binary_graph.extract_tree(str(tmp_path)) == ([], [("huge.dll", "larger than the size cap")])


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
    assert skipped == [("odd.dll", "malformed")]


def test_every_skip_reason_is_a_fixed_string_of_the_vocabulary():
    # Task 10 counts and groups the reasons: one whose wording drifts with pefile, the OS or its locale cannot be
    # counted. The file name is in the pair; the library's own message is for whoever opens that one file by hand
    import ast
    import inspect
    assert len(set(binary_graph.REASONS)) == len(binary_graph.REASONS)
    tree = ast.parse(inspect.getsource(binary_graph))
    raised = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and getattr(node.func, "id", None) == "ExtractError"]
    assert raised
    for call in raised:
        (arg,) = call.args
        if isinstance(arg, ast.Name):                               # a refused directory: its row of DIRECTORIES
            assert arg.id == "reason", ast.dump(arg)
            continue
        assert isinstance(arg, ast.Constant) and arg.value in binary_graph.REASONS, ast.dump(arg)
    assert {reason for _, _, reason in binary_graph.DIRECTORIES} <= set(binary_graph.REASONS)
    tree_fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "extract_tree")
    assert not [n for n in ast.walk(tree_fn) if isinstance(n, ast.JoinedStr)]
    literals = {n.value for n in ast.walk(tree_fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    literals.discard(ast.get_docstring(tree_fn, clean=False))
    assert {"cannot be listed", "the same name in another case"} <= literals <= set(binary_graph.REASONS) | {
        ".dll", ".exe"}


# --- the ApiSetMap: api-ms-win-* names, which no file on disk carries ---------------------------

_API_SET_HEADER, _API_SET_ENTRY, _API_SET_VALUE = 28, 24, 20     # bytes; the entries start right behind the header


def _api_set_map(mapping, version=6):
    """A version-6 ApiSetMap: alias -> hosts. A host is a module name, or an (importing module, host) pair.

    Header (u32 x 7): Version, Size, Flags, Count, EntryOffset, HashOffset, HashFactor.
    Entry  (u32 x 6, from EntryOffset): Flags, NameOffset, NameLength, HashedLength, ValueOffset, ValueCount.
    Value  (u32 x 5, from the entry's ValueOffset): Flags, NameOffset, NameLength, ValueOffset, ValueLength.
    Every offset counts from the base of the map, every name is UTF-16LE and every length is in bytes. Behind the
    header come the entries, then the hash table (8 bytes an entry, never read), then the value arrays, then the
    names; entry i sits at _API_SET_HEADER + _API_SET_ENTRY * i."""
    import struct
    n = len(mapping)
    hash_at = _API_SET_HEADER + _API_SET_ENTRY * n
    values_at = hash_at + 8 * n
    names_at = values_at + _API_SET_VALUE * sum(len(hosts) for hosts in mapping.values())
    names = bytearray()

    def name(text):
        raw = text.encode("utf-16-le")
        offset = names_at + len(names)
        names.extend(raw)
        return offset, len(raw)

    entries, values, hashes = b"", b"", b""
    for index, (alias, hosts) in enumerate(mapping.items()):
        alias_at, alias_len = name(alias)
        entries += struct.pack("<6I", 0, alias_at, alias_len, alias_len - 2 * len("-1-0"),
                               values_at + len(values), len(hosts))
        hashes += struct.pack("<2I", 0, index)
        for host in hosts:
            importer, module = host if isinstance(host, tuple) else ("", host)
            (importer_at, importer_len), (module_at, module_len) = name(importer), name(module)
            values += struct.pack("<5I", 0, importer_at, importer_len, module_at, module_len)
    size = names_at + len(names)
    return struct.pack("<7I", version, size, 0, n, _API_SET_HEADER, hash_at, 31) + entries + hashes + values + bytes(names)


def test_an_api_set_alias_resolves_to_its_host_modules_in_order():
    data = _api_set_map({"api-ms-win-core-memory-l1-1-0": ("kernelbase.dll", "kernel32.dll")})
    assert binary_graph.parse_api_set_map(data)["api-ms-win-core-memory-l1-1-0"] == ("kernelbase.dll", "kernel32.dll")


def test_the_packer_lays_the_map_out_as_the_version_6_table_says():
    # the packer is what every other test of the map stands on: pin its bytes once, field by field
    import struct
    data = _api_set_map({"api-x-1-0": ("a.dll",), "api-y-1-0": ("b.dll", "c.dll")})
    assert struct.unpack_from("<7I", data) == (6, len(data), 0, 2, 28, 28 + 2 * 24, 31)
    flags, name_at, name_len, hashed_len, value_at, value_count = struct.unpack_from("<6I", data, 28 + 24)
    assert (flags, name_len, hashed_len, value_count) == (0, 2 * len("api-y-1-0"), 2 * len("api-y"), 2)
    assert data[name_at:name_at + name_len].decode("utf-16-le") == "api-y-1-0"
    _, _, _, host_at, host_len = struct.unpack_from("<5I", data, value_at + 20)
    assert data[host_at:host_at + host_len].decode("utf-16-le") == "c.dll"


def test_several_aliases_and_a_host_that_is_the_same_for_all_come_back_whole():
    mapping = {"api-ms-win-core-file-l1-1-0": ("kernelbase.dll",), "api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",),
               "ext-ms-win-gdi-dc-l1-1-0": ("gdi32full.dll", "win32u.dll")}
    assert binary_graph.parse_api_set_map(_api_set_map(mapping)) == mapping


def test_the_name_an_importer_is_matched_by_does_not_become_a_host():
    data = _api_set_map({"api-ms-win-x-l1-1-0": (("kernel32.dll", "kernelbase.dll"), "ntdll.dll")})
    assert binary_graph.parse_api_set_map(data) == {"api-ms-win-x-l1-1-0": ("kernelbase.dll", "ntdll.dll")}


def _schema_dll(tmp_path, data, section=".apiset", name="apisetschema.dll"):
    path = tmp_path / name
    path.write_bytes(make_pe(dll=True, sections=((section, data),)))
    return str(path)


def test_the_map_is_read_from_the_apiset_section_of_the_schema_dll(tmp_path):
    mapping = {"api-ms-win-core-memory-l1-1-0": ("kernelbase.dll", "kernel32.dll"),
               "api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",)}
    assert binary_graph.load_api_set_map(_schema_dll(tmp_path, _api_set_map(mapping))) == mapping
    assert binary_graph.API_SET_SCHEMA_PATH == r"C:\Windows\System32\apisetschema.dll"


def test_an_alias_is_stored_without_its_dll_suffix_and_in_lower_case():
    data = _api_set_map({"API-MS-Win-Core-Memory-L1-1-0.DLL": ("KernelBase.dll",), "api-ms-win-core-heap-l1-1-0": ("kernelbase.dll",)})
    parsed = binary_graph.parse_api_set_map(data)
    assert set(parsed) == {"api-ms-win-core-memory-l1-1-0", "api-ms-win-core-heap-l1-1-0"}
    assert parsed["api-ms-win-core-memory-l1-1-0"] == ("KernelBase.dll",)          # a host is what the map says


def _patched(data, at, *values):
    import struct
    out = bytearray(data)
    struct.pack_into(f"<{len(values)}I", out, at, *values)
    return bytes(out)


_ENTRY_0 = _API_SET_HEADER                                      # where the packer puts the first entry
_ENTRY_1 = _API_SET_HEADER + _API_SET_ENTRY
_VALUES = _API_SET_HEADER + 2 * (_API_SET_ENTRY + 8)           # past two entries and their hash rows: the value arrays


def _two_aliases():
    return _api_set_map({"api-first-l1-1-0": ("kernelbase.dll",), "api-second-l1-1-0": ("ntdll.dll", "kernel32.dll")})


@pytest.mark.parametrize("what, at, values", [
    ("a name before the map", _ENTRY_0 + 4, (0xFFFFFFF0,)),
    ("a name that begins inside the map and ends outside it", _ENTRY_0 + 8, (0x7FFFFFFF,)),
    ("a name length past the end", _ENTRY_0 + 4, (10_000, 4)),
    ("a value array outside the map", _ENTRY_0 + 16, (0xFFFFFFFF, 1)),
    ("more values than fit in the map", _ENTRY_0 + 20, (0x10000000,)),
    ("a value array that begins in the map and runs out of it", _ENTRY_0 + 20, (400,)),
    ("a name length that is not whole UTF-16 characters", _ENTRY_0 + 8, (7,)),
    ("an entry with no value at all", _ENTRY_0 + 20, (0,)),
    ("a host past the end of the map", _VALUES + 12, (0xFFFFFF00, 8)),
])
def test_an_entry_whose_offsets_point_outside_the_map_is_dropped_and_the_rest_survives(what, at, values):
    data = _patched(_two_aliases(), at, *values)
    parsed = binary_graph.parse_api_set_map(data)
    assert parsed.get("api-second-l1-1-0") == ("ntdll.dll", "kernel32.dll"), what
    assert "api-first-l1-1-0" not in parsed, what


def test_a_value_with_a_bad_host_takes_its_whole_entry_with_it_rather_than_shortening_the_chain():
    # the loader tries the hosts in order: an entry without its first host would resolve to the wrong module
    data = _two_aliases()
    data = _patched(data, _VALUES + _API_SET_VALUE + 12, 0xFFFFFF00, 8)      # the second value of the second entry
    parsed = binary_graph.parse_api_set_map(data)
    assert "api-second-l1-1-0" not in parsed and parsed["api-first-l1-1-0"] == ("kernelbase.dll",)


def test_an_importer_name_that_points_outside_the_map_drops_its_entry_too():
    data = _two_aliases()
    parsed = binary_graph.parse_api_set_map(_patched(data, _VALUES + 4, 0xFFFFFF00, 8))
    assert set(parsed) == {"api-second-l1-1-0"}


def test_an_entry_count_larger_than_the_map_can_hold_reads_what_is_there_and_does_not_hang():
    import time
    data = _patched(_two_aliases(), 12, 0xFFFFFFFF)                     # Count
    started = time.monotonic()
    parsed = binary_graph.parse_api_set_map(data)
    assert time.monotonic() - started < 1
    assert parsed["api-second-l1-1-0"] == ("ntdll.dll", "kernel32.dll")


def test_an_entry_table_that_starts_outside_the_map_gives_an_empty_map():
    assert binary_graph.parse_api_set_map(_patched(_two_aliases(), 16, 0xFFFFFFFF)) == {}


def test_a_name_that_is_not_valid_utf16_or_is_empty_drops_its_entry():
    data = _api_set_map({"api-first-l1-1-0": ("kernelbase.dll",), "api-second-l1-1-0": ("ntdll.dll",),
                         "api-third-l1-1-0": ("kernel32.dll",)})
    import struct
    name_at = struct.unpack_from("<I", data, _ENTRY_0 + 4)[0]
    broken = bytearray(data)
    broken[name_at:name_at + 2] = b"\x00\xd8"                           # a lone high surrogate
    assert set(binary_graph.parse_api_set_map(bytes(broken))) == {"api-second-l1-1-0", "api-third-l1-1-0"}
    assert set(binary_graph.parse_api_set_map(_patched(data, _ENTRY_1 + 8, 0))) == {"api-first-l1-1-0", "api-third-l1-1-0"}


def test_an_empty_host_is_not_a_host():
    data = _api_set_map({"ext-ms-win-gone-l1-1-0": ("",), "api-ms-win-part-l1-1-0": ("", "kernelbase.dll")})
    assert binary_graph.parse_api_set_map(data) == {"api-ms-win-part-l1-1-0": ("kernelbase.dll",)}


def test_an_alias_named_twice_keeps_the_first():
    data = _api_set_map({"api-a-l1-1-0": ("one.dll",), "API-A-L1-1-0.dll": ("two.dll",)})
    assert binary_graph.parse_api_set_map(data) == {"api-a-l1-1-0": ("one.dll",)}


@pytest.mark.parametrize("version", [0, 1, 2, 3, 4, 5, 7, 0xFFFFFFFF])
def test_an_unknown_api_set_version_gives_an_empty_map_instead_of_raising(version):
    assert binary_graph.parse_api_set_map(_api_set_map({"api-a-l1-1-0": ("one.dll",)}, version=version)) == {}


@pytest.mark.parametrize("data", [b"", b"\x06", b"\x06\x00\x00\x00", bytes(27), bytes(28), b"MZ" + bytes(100)])
def test_bytes_too_short_or_empty_to_be_a_map_give_an_empty_map(data):
    assert binary_graph.parse_api_set_map(data) == {}


def test_a_map_cut_off_in_the_middle_keeps_the_aliases_before_the_cut():
    data = _api_set_map({"api-first-l1-1-0": ("kernelbase.dll",), "api-second-l1-1-0": ("ntdll.dll",)})
    for cut in range(len(data)):
        parsed = binary_graph.parse_api_set_map(data[:cut])               # never raises, whatever the cut
        assert set(parsed) <= {"api-first-l1-1-0", "api-second-l1-1-0"}
    assert binary_graph.parse_api_set_map(data[:-2]) == {"api-first-l1-1-0": ("kernelbase.dll",)}


def test_every_single_byte_of_the_map_overwritten_never_raises():
    data = _api_set_map({"api-first-l1-1-0": ("kernelbase.dll",), "api-second-l1-1-0": ("ntdll.dll", "kernel32.dll")})
    for at in range(len(data)):
        for byte in (0x00, 0xFF, 0x80, 0x01):
            result = binary_graph.parse_api_set_map(data[:at] + bytes([byte]) + data[at + 1:])
            assert isinstance(result, dict)
            assert all(isinstance(hosts, tuple) and hosts for hosts in result.values())


def test_a_missing_schema_dll_gives_an_empty_map(tmp_path):
    assert binary_graph.load_api_set_map(str(tmp_path / "apisetschema.dll")) == {}
    assert binary_graph.load_api_set_map(str(tmp_path)) == {}                      # a directory is not a file either


def test_a_schema_dll_without_an_apiset_section_gives_an_empty_map(tmp_path):
    path = tmp_path / "apisetschema.dll"
    path.write_bytes(make_pe(dll=True, imports=(("ntdll.dll", ("NtClose",)),)))
    assert binary_graph.load_api_set_map(str(path)) == {}
    assert binary_graph.load_api_set_map(_schema_dll(tmp_path, _api_set_map({"api-a-l1-1-0": ("one.dll",)}), section=".rdata")) == {}


def test_a_schema_dll_that_is_not_a_pe_or_is_empty_gives_an_empty_map(tmp_path):
    for content in (b"", b"not a pe at all", b"MZ" + bytes(20)):
        (tmp_path / "apisetschema.dll").write_bytes(content)
        assert binary_graph.load_api_set_map(str(tmp_path / "apisetschema.dll")) == {}


def test_a_schema_dll_whose_apiset_section_is_not_a_map_gives_an_empty_map(tmp_path):
    assert binary_graph.load_api_set_map(_schema_dll(tmp_path, b"garbage" * 40)) == {}
    assert binary_graph.load_api_set_map(_schema_dll(tmp_path, _api_set_map({"a-l1-1-0": ("x.dll",)}, version=4))) == {}


def test_a_schema_dll_without_pefile_gives_an_empty_map(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name == "pefile":
            raise ImportError(name)
        return real(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", refuse)
    assert binary_graph.load_api_set_map(_schema_dll(tmp_path, _api_set_map({"a-l1-1-0": ("x.dll",)}))) == {}


def test_a_schema_dll_that_is_larger_than_the_cap_is_not_read(tmp_path, monkeypatch):
    path = _schema_dll(tmp_path, _api_set_map({"a-l1-1-0": ("x.dll",)}))
    monkeypatch.setattr(binary_graph, "MAX_BINARY_SIZE", 100)
    assert binary_graph.load_api_set_map(path) == {}


def test_the_schema_dll_is_closed_whatever_its_map_looks_like(tmp_path, monkeypatch):
    import pefile
    closed = []
    real_close = pefile.PE.close
    monkeypatch.setattr(pefile.PE, "close", lambda self: (closed.append(1), real_close(self))[1])
    binary_graph.load_api_set_map(_schema_dll(tmp_path, b"garbage" * 40))
    binary_graph.load_api_set_map(_schema_dll(tmp_path, _api_set_map({"a-l1-1-0": ("x.dll",)})))
    assert len(closed) == 2
